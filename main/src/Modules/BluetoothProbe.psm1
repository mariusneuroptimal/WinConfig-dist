# Bluetooth.psm1 - Bluetooth diagnostics & telemetry core
#
# Note: the PERF-001 lazy-import tripwire that used to guard this module was
# removed when the project was reframed as the Bluetooth Flight Recorder.
# Bluetooth is now the application's core feature, not an optional tab, so
# eager-loading at startup is correct. The bypass env var
# $env:WINCONFIG_TEST_HARNESS is still honored elsewhere for unrelated
# test-only branching, but no longer gates this import.

# Import DiagnosticResult type constants
$script:DiagnosticsTypesPath = Join-Path $PSScriptRoot "DiagnosticTypes.psm1"
if (Test-Path $script:DiagnosticsTypesPath) {
    Import-Module $script:DiagnosticsTypesPath -Force -ErrorAction SilentlyContinue
}

# Import ExecutionIntent for mutation guards (must be loaded by caller first)
# This module enforces the non-mutating diagnostic contract
$ExecutionIntentModule = Get-Module -Name ExecutionIntent
if (-not $ExecutionIntentModule) {
    # Try to import from known location
    $intentPath = Join-Path $PSScriptRoot "ExecutionIntent.psm1"
    if (Test-Path $intentPath) {
        Import-Module $intentPath -Force -ErrorAction SilentlyContinue
    }
}

# Script-scoped state for caching
$script:BluetoothDiagnosticsCache = $null
$script:LastDiagnosticsTime = $null
$script:CacheTTLSeconds = 30

# Script-scoped state for probe execution (DIAG-EXEC-001 P0 guards)
# ProbeInProgress is an integer (0/1) for use with [Interlocked]::CompareExchange.
# Acquisition is atomic; treat as $true when -ne 0.
$script:ProbeInProgress = 0
$script:ProbeCancellationRequested = $false
$script:ProbeMediaPlayer = $null
$script:ProbeHardTimeoutSeconds = 5  # Grace period beyond requested duration

# Bluetooth event classifier (F2 + log-channel-agnostic refinement).
#
# Keys are "$ProviderName/$Id" tuples. Different Windows builds put the
# disconnect signal in different channels — Win10 used BthUSB/Operational,
# modern Win11 puts it in Bthmini/Operational, server builds may use yet
# another. Provider+Id keys keep these unambiguous and let one table cover
# the whole fleet.
#
# Conservative by design: only entries verified against real captured events
# live here. Unknown keys return 'Unknown' from Get-BluetoothEventClass and
# are surfaced in diagnostic output via the UnknownEventKeys field so field
# operators can refine the map without code changes.
#
# Localized Message text MUST NOT drive disconnect / verdict logic. Ever.
$script:BluetoothEventClassByKey = @{
    # Pending field verification. Populate via the bthmini-events collection
    # script in docs (or by capturing Get-WinEvent output on a known-good
    # machine after enabling Microsoft-Windows-Bluetooth-Bthmini/Operational).
    # Example shape (commented out; do NOT uncomment without verifying the Id
    # actually corresponds to a disconnect on your target build):
    #
    # 'Microsoft-Windows-Bluetooth-Bthmini/<verified-id>' = 'Disconnected'
}

# Cached enabled-log-channel enumeration. Populated lazily by
# Get-BluetoothOperationalLogNames so we don't hit wevtutil/Get-WinEvent
# -ListLog on every Get-BluetoothEventLogHints call.
$script:BluetoothOperationalLogsCache = $null
$script:BluetoothOperationalLogsCacheTime = $null
$script:BluetoothOperationalLogsCacheTTLSeconds = 300  # 5 min; channels rarely flip

#region Private Helper Functions

# Transport/service node exclusion patterns (CRITICAL: must never surface as adapter or actionable device)
$script:TransportExclusionPatterns = @(
    '*Transport*',
    '*AVRCP*',
    '*A2DP*',
    '*Hands-Free*Audio Gateway*',
    '*LE Generic Attribute Service*',
    '*Service Discovery Service*',
    '*Bluetooth Device (RFCOMM Protocol TDI)*',
    'Microsoft Bluetooth Enumerator',
    'Microsoft Bluetooth LE Enumerator',
    '*Generic Attribute Profile*',
    '*GATT Server*',
    '*Remote Control*'
)

function Test-IsTransportOrServiceNode {
    <#
    .SYNOPSIS
        Checks if a device name matches transport/service node exclusion patterns.
    #>
    [CmdletBinding()]
    param(
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    foreach ($pattern in $script:TransportExclusionPatterns) {
        if ($Name -like $pattern) {
            return $true
        }
    }
    return $false
}

function Test-BluetoothTransportInstanceId {
    <#
    .SYNOPSIS
        Structural test for whether a PnP InstanceId represents a Bluetooth transport.
    .DESCRIPTION
        F3 helper. Destructive operations (endpoint removal, ghost cleanup) must NEVER
        decide based on FriendlyName matches like 'BT', 'Headset', 'Bluetooth' — those
        false-positive on USB headsets and dock devices. The InstanceId enumerator
        prefix is the authoritative transport proof.

        Accepts: BTHENUM\... (any case, leading anchored or after a backslash boundary).
        Rejects: any InstanceId without a BTHENUM\ segment.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    param(
        [string]$InstanceId
    )

    if ([string]::IsNullOrWhiteSpace($InstanceId)) {
        return $false
    }

    return $InstanceId -match '(?i)(^|\\)BTHENUM\\'
}

function Clear-BluetoothDiagnosticsCache {
    <#
    .SYNOPSIS
        Invalidates the Bluetooth diagnostics cache.
    .DESCRIPTION
        F7 helper. Mutating tools (service reset, adapter reset, endpoint cleanup,
        ghost COM cleanup, device disable/remove) must call this after any actual
        change to system state, so the next Get-BluetoothDiagnostics call returns
        fresh state instead of pre-mutation cache (TTL is 30s — long enough to
        confuse the user who just clicked "Reset" and re-renders the dashboard).

        Safe to call when there is no cache. Does NOT clear in dry-run / no-op paths.
    #>
    [CmdletBinding()]
    param()

    $script:BluetoothDiagnosticsCache = $null
    $script:LastDiagnosticsTime = $null
}

function Get-BluetoothEventClass {
    <#
    .SYNOPSIS
        Classifies a Bluetooth event by stable (Provider, Id) tuple, not localized Message.
    .DESCRIPTION
        F2 helper, refined for log-channel-agnostic operation. Different Windows
        builds put the disconnect signal in different channels (BthUSB on Win10,
        Bthmini on modern Win11, etc.). Keying by ProviderName alone is too
        coarse; keying by Id alone collides across providers. The Provider/Id
        tuple is the smallest unambiguous unit.

        Returns one of: 'Connected', 'Disconnected', 'Unknown'.

        Conservative by design: an unknown key returns 'Unknown' rather than
        guessing from Message text. Callers should surface the unknown key so
        the classifier table can be refined from field data.
    .PARAMETER Event
        A WinEvent-shaped object (must expose .Id; .ProviderName is required
        for matching but missing-provider events return 'Unknown' safely).
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Event
    )

    if ($null -eq $Event) { return 'Unknown' }

    $rawId = $null
    try { $rawId = $Event.Id } catch { $rawId = $null }
    if ($null -eq $rawId) { return 'Unknown' }

    $id = 0
    if (-not [int]::TryParse([string]$rawId, [ref]$id)) { return 'Unknown' }

    $provider = $null
    try { $provider = $Event.ProviderName } catch { $provider = $null }
    if ([string]::IsNullOrWhiteSpace($provider)) { return 'Unknown' }

    $key = "$provider/$id"
    if ($script:BluetoothEventClassByKey.ContainsKey($key)) {
        return [string]$script:BluetoothEventClassByKey[$key]
    }
    return 'Unknown'
}

function Get-BluetoothOperationalLogNames {
    <#
    .SYNOPSIS
        Returns names of enabled Bluetooth-* /Operational log channels on this host.
    .DESCRIPTION
        B2 helper. Different Windows builds expose different BT log channels
        (BthUSB on Win10, Bthmini on modern Win11, BthLEPrepairing, MTPEnum,
        Policy, etc.). Hardcoding one channel produces silent dead spots when
        it doesn't exist on the target build. This helper enumerates whichever
        are present AND enabled.

        Result is cached for 5 minutes (channels rarely flip during a session).
        Pass -Refresh to force re-enumeration.
    .PARAMETER Refresh
        Bypass the cache and re-enumerate.
    .OUTPUTS
        [string[]] log channel names. Empty array if none are enabled.
    #>
    [CmdletBinding()]
    param(
        [switch]$Refresh
    )

    $now = Get-Date
    if (-not $Refresh -and $null -ne $script:BluetoothOperationalLogsCache -and
        $null -ne $script:BluetoothOperationalLogsCacheTime -and
        ($now - $script:BluetoothOperationalLogsCacheTime).TotalSeconds -lt $script:BluetoothOperationalLogsCacheTTLSeconds) {
        return $script:BluetoothOperationalLogsCache
    }

    $names = @()
    try {
        $logs = Get-WinEvent -ListLog 'Microsoft-Windows-Bluetooth-*' -ErrorAction SilentlyContinue
        foreach ($l in $logs) {
            if ($l.IsEnabled -and $l.LogName -match '/Operational$') {
                $names += $l.LogName
            }
        }
    } catch {
        # Permission failure or no matching channels — return empty.
    }

    $script:BluetoothOperationalLogsCache = $names
    $script:BluetoothOperationalLogsCacheTime = $now
    return $names
}

function Invoke-PnpDeviceRemovalWithVerification {
    <#
    .SYNOPSIS
        Removes a PnP device via pnputil and verifies removal by re-querying.
    .DESCRIPTION
        F4 helper. Captures $LASTEXITCODE (authoritative; locale-independent),
        records pnputil output, then re-queries the device by InstanceId. The
        device is only considered Removed when the command reports success AND
        a follow-up Get-PnpDevice cannot find it.

        Returns a structured object with all evidence the caller needs to put
        in ledger/result.
    .PARAMETER InstanceId
        The PnP InstanceId to remove.
    .PARAMETER Class
        Optional PnP class to scope the verification query (e.g. 'AudioEndpoint').
        When omitted, the verification query searches without class restriction.
    .OUTPUTS
        [pscustomobject] with:
            Status        : 'Removed' | 'StillPresent' | 'Failed'
            ExitCode      : pnputil exit code
            CommandOk     : $true when exit code 0 or output matches success token
            StillPresent  : $true when post-removal query found the device
            Output        : raw pnputil text
            InstanceId    : echoed input
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId,

        [string]$Class
    )

    $pnpOutput = pnputil /remove-device "$InstanceId" 2>&1
    $exitCode = $LASTEXITCODE
    $pnpText = ($pnpOutput | Out-String).Trim()

    # Exit code is authoritative on all locales; the success-token check only
    # rescues hosts where pnputil somehow returns non-zero for an actual success.
    $commandReportedSuccess = ($exitCode -eq 0) -or ($pnpText -match '(?i)successfully|removed')

    $queryParams = @{ ErrorAction = 'SilentlyContinue' }
    if ($PSBoundParameters.ContainsKey('Class') -and -not [string]::IsNullOrWhiteSpace($Class)) {
        $queryParams['Class'] = $Class
    }
    $stillPresent = $null -ne (Get-PnpDevice @queryParams |
        Where-Object { $_.InstanceId -eq $InstanceId } |
        Select-Object -First 1)

    $status = if ($commandReportedSuccess -and -not $stillPresent) {
        'Removed'
    } elseif ($stillPresent) {
        'StillPresent'
    } else {
        'Failed'
    }

    return [pscustomobject]@{
        Status       = $status
        ExitCode     = $exitCode
        CommandOk    = $commandReportedSuccess
        StillPresent = $stillPresent
        Output       = $pnpText
        InstanceId   = $InstanceId
    }
}

#region WinRT Bluetooth Enumeration (PERF-001 compliant - types loaded inside function)

function Initialize-WinRTTypes {
    <#
    .SYNOPSIS
        Loads WinRT types for Bluetooth enumeration. Called INSIDE functions, not at module scope.
    .DESCRIPTION
        PERF-001: This must NEVER be called at module import time.
        It's designed to be called lazily when Bluetooth tab is first accessed.
    #>
    [CmdletBinding()]
    param()

    if ($script:WinRTInitialized) { return $true }

    try {
        # Load WinRT interop assembly
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop

        # Helper to await WinRT async operations
        $script:AwaitMethod = [WindowsRuntimeSystemExtensions].GetMember('GetAwaiter').
            Where({ $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' },'First')

        $script:WinRTInitialized = $true
        return $true
    }
    catch {
        $script:WinRTInitialized = $false
        return $false
    }
}

function Await-WinRTAsync {
    <#
    .SYNOPSIS
        Awaits a WinRT IAsyncOperation and returns the result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AsyncOp,
        [int]$TimeoutMs = 5000
    )

    try {
        $awaiter = $script:AwaitMethod.Invoke($null, @($AsyncOp))
        $start = [DateTime]::Now
        while (-not $awaiter.IsCompleted) {
            if (([DateTime]::Now - $start).TotalMilliseconds -gt $TimeoutMs) {
                throw "WinRT async operation timed out after ${TimeoutMs}ms"
            }
            [System.Threading.Thread]::Sleep(50)
        }
        return $awaiter.GetResult()
    }
    catch {
        return $null
    }
}

function Get-BluetoothDevicesWinRT {
    <#
    .SYNOPSIS
        Enumerates paired Bluetooth devices using WinRT APIs (transport truth).
    .DESCRIPTION
        Uses Windows.Devices.Enumeration.DeviceInformation.FindAllAsync to get
        paired Bluetooth devices, then resolves connection status via
        Windows.Devices.Bluetooth.BluetoothDevice.FromIdAsync.

        This is the AUTHORITATIVE source for Bluetooth device presence.
        Does NOT rely on audio endpoints or name patterns.

        PERF-001: WinRT types are loaded inside this function, not at module scope.
    .OUTPUTS
        PSCustomObject[] with:
        - Name: Device friendly name
        - DeviceId: WinRT device ID
        - Address: Bluetooth MAC address (if available)
        - IsPaired: Always true (we query paired devices)
        - IsConnected: Live connection status from BluetoothDevice
        - ClassOfDevice: Major/minor class (Audio/Video detection)
        - LastSeen: Last connection time (if available from properties)
        - Presence: Connected | Remembered (NOT "Paired" - that's misleading)
    #>
    [CmdletBinding()]
    param()

    $devices = @()

    try {
        # Initialize WinRT (lazy, PERF-001 compliant)
        if (-not (Initialize-WinRTTypes)) {
            Write-Verbose "WinRT initialization failed, falling back to PnP"
            return @()
        }

        # AQS query for paired Bluetooth devices
        $btSelector = "System.Devices.Aep.ProtocolId:=""{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"" AND System.Devices.Aep.IsPaired:=System.StructuredQueryType.Boolean#True"

        # Request additional properties
        $requestedProps = [System.Collections.Generic.List[string]]::new()
        $requestedProps.Add("System.Devices.Aep.DeviceAddress")
        $requestedProps.Add("System.Devices.Aep.IsConnected")
        $requestedProps.Add("System.Devices.Aep.Bluetooth.Le.IsConnectable")
        $requestedProps.Add("System.Devices.Aep.SignalStrength")

        # Get DeviceInformation type
        $deviceInfoType = [Type]::GetType("Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType=WindowsRuntime")

        if (-not $deviceInfoType) {
            # Fallback: try loading via Add-Type with WinRT reference
            $null = [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType=WindowsRuntime]
            $deviceInfoType = [Windows.Devices.Enumeration.DeviceInformation]
        }

        # FindAllAsync with selector and properties
        $findAllMethod = $deviceInfoType.GetMethod('FindAllAsync', @([string], [System.Collections.Generic.IEnumerable[string]]))
        $asyncOp = $findAllMethod.Invoke($null, @($btSelector, $requestedProps))

        $deviceInfoCollection = Await-WinRTAsync -AsyncOp $asyncOp -TimeoutMs 10000

        if (-not $deviceInfoCollection) {
            Write-Verbose "No devices returned from WinRT enumeration"
            return @()
        }

        # Get BluetoothDevice type for connection status resolution
        $btDeviceType = $null
        try {
            $null = [Windows.Devices.Bluetooth.BluetoothDevice, Windows.Devices.Bluetooth, ContentType=WindowsRuntime]
            $btDeviceType = [Windows.Devices.Bluetooth.BluetoothDevice]
        }
        catch {
            Write-Verbose "Could not load BluetoothDevice type"
        }

        foreach ($devInfo in $deviceInfoCollection) {
            try {
                $name = $devInfo.Name
                $deviceId = $devInfo.Id

                # Skip transport/service nodes
                if (Test-IsTransportOrServiceNode -Name $name) { continue }
                if ($name -match "^Microsoft|Enumerator|^Generic") { continue }

                # Extract properties
                $props = $devInfo.Properties
                $address = $null
                $isConnectedProp = $false
                $signalStrength = $null

                if ($props) {
                    if ($props.ContainsKey("System.Devices.Aep.DeviceAddress")) {
                        $address = $props["System.Devices.Aep.DeviceAddress"]
                    }
                    if ($props.ContainsKey("System.Devices.Aep.IsConnected")) {
                        $isConnectedProp = $props["System.Devices.Aep.IsConnected"] -eq $true
                    }
                    if ($props.ContainsKey("System.Devices.Aep.SignalStrength")) {
                        $signalStrength = $props["System.Devices.Aep.SignalStrength"]
                    }
                }

                # Resolve live connection status via BluetoothDevice.FromIdAsync
                $isConnected = $isConnectedProp
                $classOfDevice = $null

                if ($btDeviceType) {
                    try {
                        $fromIdMethod = $btDeviceType.GetMethod('FromIdAsync', @([string]))
                        $btAsyncOp = $fromIdMethod.Invoke($null, @($deviceId))
                        $btDevice = Await-WinRTAsync -AsyncOp $btAsyncOp -TimeoutMs 3000

                        if ($btDevice) {
                            # Connection status from BluetoothDevice is authoritative
                            $connStatus = $btDevice.ConnectionStatus
                            $isConnected = $connStatus -eq [Windows.Devices.Bluetooth.BluetoothConnectionStatus]::Connected

                            # Class of Device (for audio detection)
                            $cod = $btDevice.ClassOfDevice
                            if ($cod) {
                                $classOfDevice = @{
                                    MajorClass = $cod.MajorClass.ToString()
                                    MinorClass = $cod.MinorClass.ToString()
                                    RawValue = $cod.RawValue
                                }
                            }
                        }
                    }
                    catch {
                        # Keep property-based connection status
                    }
                }

                # Presence: Connected if live connection, otherwise Remembered (NOT "Paired")
                # "Paired" is misleading - all these devices are paired, but that doesn't mean present
                $presence = if ($isConnected) { "Connected" } else { "Remembered" }

                # Detect if audio device from ClassOfDevice
                $isAudioDevice = $false
                if ($classOfDevice) {
                    # Major class 4 = Audio/Video
                    $isAudioDevice = $classOfDevice.MajorClass -eq "AudioVideoHandsfree" -or
                                     $classOfDevice.MajorClass -eq "AudioVideoHeadphones" -or
                                     $classOfDevice.MajorClass -eq "AudioVideoPortableAudio" -or
                                     $classOfDevice.MajorClass -match "Audio"
                }

                # Fallback: detect by name patterns (known BT audio brands)
                if (-not $isAudioDevice) {
                    $isAudioDevice = $name -match "AirPods|Galaxy Buds|WH-1000|WF-1000|Jabra|Bose|JBL|Beats|Dime|Kanto|ORA|Soundcore|Skullcandy|Sennheiser|Sony|Headphone|Headset|Speaker|Earbuds"
                }

                $devices += [PSCustomObject]@{
                    Name = $name
                    DeviceId = $deviceId
                    Address = $address
                    IsPaired = $true
                    IsConnected = $isConnected
                    ClassOfDevice = $classOfDevice
                    SignalStrength = $signalStrength
                    IsAudioDevice = $isAudioDevice
                    Presence = $presence
                    Source = "WinRT"
                }
            }
            catch {
                # Skip problematic devices
                continue
            }
        }
    }
    catch {
        Write-Verbose "WinRT enumeration failed: $_"
    }

    return $devices
}

function Get-BluetoothDevicesEnriched {
    <#
    .SYNOPSIS
        Returns Bluetooth devices with PnP enrichment (driver, PM, COM residue).
    .DESCRIPTION
        Combines WinRT enumeration (authoritative for pairing/connection) with
        PnP properties (driver version, power management, COM ports).

        This is the PRIMARY function for the Bluetooth dashboard.
    .OUTPUTS
        PSCustomObject[] with all WinRT properties plus:
        - InstanceId: PnP instance ID
        - DriverVersion: Driver version string
        - PowerManagementEnabled: PM status
        - GhostCOMPorts: Count of orphaned COM ports for this device
        - Activity: Active | Idle | Inactive
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeNonAudio
    )

    # Get WinRT devices (authoritative for connection status)
    $winrtDevices = Get-BluetoothDevicesWinRT

    if (-not $winrtDevices -or $winrtDevices.Count -eq 0) {
        # Fallback to PnP-only enumeration
        return Get-BluetoothAudioDevices
    }

    # Get PnP devices for enrichment
    $pnpDevices = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue)
    $pnpByName = @{}
    foreach ($pnp in $pnpDevices) {
        $key = $pnp.FriendlyName -replace '\s*(Stereo|Hands-Free|HFP|A2DP|Audio)$', ''
        $key = $key.Trim()
        if ($key -and -not $pnpByName.ContainsKey($key)) {
            $pnpByName[$key] = $pnp
        }
    }

    # Get COM ports for residue detection
    $comPorts = @()
    try {
        if (Get-Command Get-BluetoothCOMPorts -ErrorAction SilentlyContinue) {
            $comData = Get-BluetoothCOMPorts
            if ($comData -and -not $comData.Error) {
                $comPorts = $comData.GhostPorts
            }
        }
    }
    catch { }

    # Get default playback for Activity detection
    $defaultPlayback = $null
    try {
        # Try AudioDeviceCmdlets first (most accurate)
        if (Get-Command Get-AudioDevice -ErrorAction SilentlyContinue) {
            $defaultPlayback = Get-AudioDevice -Playback | Where-Object { $_.Default } | Select-Object -First 1
        }
    }
    catch { }

    if (-not $defaultPlayback) {
        # Fallback to registry
        try {
            $regPath = "HKCU:\Software\Microsoft\Multimedia\Sound Mapper"
            if (Test-Path $regPath) {
                $playbackName = (Get-ItemProperty -Path $regPath -Name "Playback" -ErrorAction SilentlyContinue).Playback
                if ($playbackName) {
                    $defaultPlayback = [PSCustomObject]@{ Name = $playbackName }
                }
            }
        }
        catch { }
    }

    # Enrich WinRT devices with PnP data
    $enriched = @()

    foreach ($dev in $winrtDevices) {
        # Filter to audio devices unless IncludeNonAudio
        if (-not $IncludeNonAudio -and -not $dev.IsAudioDevice) {
            continue
        }

        # Find matching PnP device
        $pnp = $pnpByName[$dev.Name]
        if (-not $pnp) {
            # Try partial match
            foreach ($key in $pnpByName.Keys) {
                if ($dev.Name -like "*$key*" -or $key -like "*$($dev.Name)*") {
                    $pnp = $pnpByName[$key]
                    break
                }
            }
        }

        # Get driver info from PnP
        $driverVersion = $null
        $pmEnabled = $null
        $instanceId = $null

        if ($pnp) {
            $instanceId = $pnp.InstanceId

            try {
                $driverInfo = Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceID='$($pnp.InstanceId -replace '\\','\\\\')'" -ErrorAction SilentlyContinue
                if ($driverInfo) {
                    $driverVersion = $driverInfo.DriverVersion
                }
            }
            catch { }

            # Power management check
            try {
                $pmStatus = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root/WMI -ErrorAction SilentlyContinue |
                    Where-Object { $_.InstanceName -match [regex]::Escape($pnp.InstanceId) }
                if ($pmStatus) {
                    $pmEnabled = $pmStatus.Enable
                }
            }
            catch { }
        }

        # Count ghost COM ports for this device
        $ghostCOMCount = 0
        if ($comPorts -and $dev.Address) {
            $ghostCOMCount = @($comPorts | Where-Object { $_.DeviceAddress -eq $dev.Address }).Count
        }

        # Determine Activity based on default playback
        $activity = "Inactive"
        if ($dev.IsConnected) {
            $activity = "Idle"  # Connected but not routing

            if ($defaultPlayback -and $defaultPlayback.Name) {
                if ($defaultPlayback.Name -match [regex]::Escape($dev.Name) -or
                    $dev.Name -match [regex]::Escape($defaultPlayback.Name)) {
                    $activity = "Active"
                }
            }
        }

        $enriched += [PSCustomObject]@{
            Name = $dev.Name
            DeviceId = $dev.DeviceId
            InstanceId = $instanceId
            Address = $dev.Address
            IsConnected = $dev.IsConnected
            IsPaired = $dev.IsPaired
            ClassOfDevice = $dev.ClassOfDevice
            IsAudioDevice = $dev.IsAudioDevice
            Presence = $dev.Presence
            Activity = $activity
            DriverVersion = $driverVersion
            PowerManagement = $pmEnabled
            GhostCOMCount = $ghostCOMCount
            SignalStrength = $dev.SignalStrength
            Source = "WinRT+PnP"
        }
    }

    return $enriched
}

#endregion WinRT Bluetooth Enumeration

function Get-BluetoothAdapterInfo {
    <#
    .SYNOPSIS
        Collects Bluetooth adapter information via PnP and CIM.
    .DESCRIPTION
        Returns info about the Bluetooth radio/controller (Intel/Realtek/USB dongle).
        CRITICAL: Excludes transport nodes (A2DP/AVRCP/HFP) from adapter selection.
    #>
    [CmdletBinding()]
    param()

    try {
        # Get all Bluetooth class devices
        $allBtDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue

        # Filter for actual radio/controller - prefer devices that:
        # 1. Are NOT transport/service nodes
        # 2. Match common radio patterns (Intel, Realtek, Qualcomm, USB, etc.)
        # 3. Have Class = Bluetooth
        $btAdapter = $allBtDevices | Where-Object {
            $_.Class -eq "Bluetooth" -and
            -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName) -and
            $_.FriendlyName -notmatch "Microsoft Bluetooth|Enumerator|LE$" -and
            # Prefer actual radio names
            ($_.FriendlyName -match "Intel|Realtek|Qualcomm|Broadcom|MediaTek|USB|Wireless Bluetooth|Radio" -or
             $_.InstanceId -match "^USB\\|^PCI\\|^ACPI\\")
        } | Select-Object -First 1

        # Fallback: any non-transport Bluetooth device with OK status
        if (-not $btAdapter) {
            $btAdapter = $allBtDevices | Where-Object {
                $_.Status -eq 'OK' -and
                -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName) -and
                $_.FriendlyName -notmatch "Microsoft Bluetooth|Enumerator"
            } | Select-Object -First 1
        }

        # Last fallback: any OK Bluetooth device (but still exclude transport nodes)
        if (-not $btAdapter) {
            $btAdapter = $allBtDevices | Where-Object {
                $_.Status -eq 'OK' -and
                -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName)
            } | Select-Object -First 1
        }

        if (-not $btAdapter) {
            return @{
                Present = $false
                Enabled = $false
                Status = "NotFound"
                FriendlyName = $null
                InstanceId = $null
                DriverInfo = $null
                Error = "No Bluetooth adapter found"
            }
        }

        # Get driver info
        $driverInfo = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.DeviceID -eq $btAdapter.InstanceId } |
            Select-Object -First 1

        # Check power management setting ("Allow the computer to turn off this device to save power")
        # F5: prior code double-escaped the InstanceId — `.Replace('\','\\')` doubled
        # backslashes, then [regex]::Escape doubled them AGAIN, producing a regex
        # that never matched the WMI InstanceName. Result: PowerManagementEnabled
        # was always $null, silently breaking buffer-underrun risk inputs.
        # WMI MSPower_DeviceEnable.InstanceName usually has a `_0`/`_1` suffix
        # appended to the raw device InstanceId — a -like prefix match handles
        # that without any regex escaping.
        $powerMgmtEnabled = $null
        try {
            $instanceIdPrefix = $btAdapter.InstanceId
            $powerSettings = Get-CimInstance -Namespace root\WMI -ClassName MSPower_DeviceEnable -ErrorAction SilentlyContinue |
                Where-Object { $_.InstanceName -like "$instanceIdPrefix*" } |
                Select-Object -First 1
            if ($powerSettings) {
                $powerMgmtEnabled = $powerSettings.Enable
            }
        } catch { }

        return @{
            Present = $true
            Enabled = $btAdapter.Status -eq 'OK'
            Status = $btAdapter.Status
            FriendlyName = $btAdapter.FriendlyName
            InstanceId = $btAdapter.InstanceId
            DriverInfo = @{
                Version = $driverInfo.DriverVersion
                Date = $driverInfo.DriverDate
                Manufacturer = $driverInfo.Manufacturer
                ProviderName = $driverInfo.DriverProviderName
            }
            PowerManagementEnabled = $powerMgmtEnabled  # $true, $false, or $null
        }
    }
    catch {
        return @{
            Present = $false
            Enabled = $false
            Status = "Error"
            FriendlyName = $null
            InstanceId = $null
            DriverInfo = $null
            Error = $_.Exception.Message
        }
    }
}

function Get-BluetoothServiceStates {
    <#
    .SYNOPSIS
        Collects status of Bluetooth and audio-related services.
    #>
    [CmdletBinding()]
    param()

    $services = @(
        @{ Name = "bthserv"; DisplayName = "Bluetooth Support Service" }
        @{ Name = "BTAGService"; DisplayName = "Bluetooth Audio Gateway" }
        @{ Name = "Audiosrv"; DisplayName = "Windows Audio" }
        @{ Name = "AudioEndpointBuilder"; DisplayName = "Windows Audio Endpoint Builder" }
    )

    $results = @{}
    foreach ($svc in $services) {
        $svcObj = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        $results[$svc.Name] = @{
            DisplayName = $svc.DisplayName
            Status = if ($svcObj) { $svcObj.Status.ToString() } else { "NotFound" }
            StartType = if ($svcObj) { $svcObj.StartType.ToString() } else { "Unknown" }
            Running = ($null -ne $svcObj) -and ($svcObj.Status -eq 'Running')
        }
    }

    # Check for per-user Bluetooth service
    $btUserSvc = Get-Service -Name "BluetoothUserService_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($btUserSvc) {
        $results["BluetoothUserService"] = @{
            DisplayName = "Bluetooth User Support Service"
            Status = $btUserSvc.Status.ToString()
            StartType = $btUserSvc.StartType.ToString()
            Running = $btUserSvc.Status -eq 'Running'
            ActualName = $btUserSvc.Name
        }
    }

    return $results
}

function Get-BluetoothPairedAudioDevices {
    <#
    .SYNOPSIS
        Enumerates Bluetooth audio devices (paired and connected).
    #>
    [CmdletBinding()]
    param()

    $devices = @()

    try {
        # Get audio endpoints that appear to be Bluetooth
        $audioEndpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FriendlyName -match "Bluetooth|BT|Hands-Free|Headset|Speaker|Headphone|AirPods|Buds|WH-|WF-|Jabra|Bose|Sony|JBL|Beats" -or
                $_.InstanceId -match "BTHENUM|BTH"
            }

        foreach ($dev in $audioEndpoints) {
            $isHFP = $dev.FriendlyName -match "Hands-Free|HFP|AG Audio|Headset"
            $isA2DP = $dev.FriendlyName -match "Stereo|A2DP|Speaker|Headphone" -or (-not $isHFP -and $dev.FriendlyName -notmatch "Hands-Free")

            $devices += @{
                Name = $dev.FriendlyName
                InstanceId = $dev.InstanceId
                Status = $dev.Status
                IsConnected = $dev.Status -eq 'OK'
                IsHFP = $isHFP
                IsA2DP = $isA2DP
                Class = $dev.Class
            }
        }
    }
    catch {
        # Silent fail - return empty array
    }

    return $devices
}

function Get-BluetoothAudioDevices {
    <#
    .SYNOPSIS
        Returns Bluetooth audio devices using transport-first detection.
    .DESCRIPTION
        TRANSPORT TRUTH FIRST: Enumerates from Bluetooth PnP devices, NOT audio endpoints.
        This prevents false positives (internal speakers shown as BT) and false negatives
        (real BT devices hidden because not routing audio).

        Detection model:
        1. Start from Bluetooth transport devices (Class Bluetooth, BTHENUM)
        2. Filter to devices with audio service UUIDs (A2DP/HFP/HSP)
        3. Correlate audio endpoints TO those devices (not the reverse)
        4. Hard-exclude internal audio (HDAUDIO, INTELAUDIO, SWD\MMDEVAPI)

        Uses a two-axis state model:
        - Presence: Connected | Paired | Remembered | Ghost
        - Activity: Active (audio route) | Idle (connected, no route) | Inactive

        CRITICAL: A device must satisfy transport proof to be listed.
        Audio capability alone is NOT sufficient.
    .OUTPUTS
        PSCustomObject[] with properties:
        - Name: User-friendly device name
        - InstanceId: PnP device instance ID
        - Status: PnP status (OK, Error, Unknown)
        - Presence: Connected | Paired | Remembered | Ghost
        - Activity: Active | Idle | Inactive
        - IsAudioDevice: $true (all returned devices are audio)
        - DeviceKind: Headphones, Earbuds, Speaker, or Unknown
        - SupportsA2DP: $true/$false/$null
        - SupportsHFP: $true/$false/$null
        - IsDefaultPlayback: $true/$false/$null
        - Notes: Array of detection notes
    #>
    [CmdletBinding()]
    param()

    $devices = @()

    try {
        # === STEP 1: Get default playback for activity detection ===
        $defaultPlaybackName = $null
        try {
            $regPath = "HKCU:\Software\Microsoft\Multimedia\Sound Mapper"
            if (Test-Path $regPath) {
                $defaultPlaybackName = (Get-ItemProperty -Path $regPath -Name "Playback" -ErrorAction SilentlyContinue).Playback
            }
        } catch { }

        # === STEP 2: TRANSPORT TRUTH - Enumerate Bluetooth devices first ===
        # Source of truth: Class Bluetooth (PnP), not audio endpoints
        $btDevices = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue)

        # === STEP 3: Get BTHENUM audio endpoints (transport-verified) ===
        # CRITICAL: Only endpoints with BTHENUM enumerator are Bluetooth transport
        # Do NOT filter by name patterns - names lie (Surface Omnisonic matches "Speaker")
        $btAudioEndpoints = @(Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue | Where-Object {
            # Transport gate: MUST have BTHENUM in InstanceId
            $_.InstanceId -match 'BTHENUM'
        })

        # === STEP 4: Build profile map from VERIFIED Bluetooth endpoints only ===
        $deviceProfiles = @{}
        foreach ($endpoint in $btAudioEndpoints) {
            # Extract base device name (remove profile suffixes)
            $baseName = $endpoint.FriendlyName -replace '\s*(Stereo|Hands-Free AG Audio|Hands-Free|HFP|A2DP|Audio)$', '' -replace '\s+$', ''
            $baseName = $baseName.Trim()

            if (-not $baseName) { continue }

            if (-not $deviceProfiles.ContainsKey($baseName)) {
                $deviceProfiles[$baseName] = @{
                    HasA2DP = $false
                    HasHFP = $false
                    Endpoints = @()
                    HasActiveEndpoint = $false
                }
            }

            # Detect profiles from endpoint names
            if ($endpoint.FriendlyName -match "Stereo|A2DP") {
                $deviceProfiles[$baseName].HasA2DP = $true
            }
            if ($endpoint.FriendlyName -match "Hands-Free|HFP|AG Audio") {
                $deviceProfiles[$baseName].HasHFP = $true
            }

            # Track if any endpoint is active (Status = OK)
            if ($endpoint.Status -eq 'OK') {
                $deviceProfiles[$baseName].HasActiveEndpoint = $true
            }

            $deviceProfiles[$baseName].Endpoints += $endpoint
        }

        # === STEP 5: Process Bluetooth class devices ===
        $seenDevices = @{}

        foreach ($dev in $btDevices) {
            # Skip transport/service nodes (A2DP Transport, AVRCP, etc.)
            if (Test-IsTransportOrServiceNode -Name $dev.FriendlyName) {
                continue
            }

            # Skip system/enumerator devices
            if ($dev.FriendlyName -match "^Microsoft Bluetooth|Enumerator|Generic|Radio") {
                continue
            }

            # === TRANSPORT GATE: Verify this is a real Bluetooth device ===
            # Must have BTHENUM or BTH in InstanceId, or be in Class Bluetooth
            $hasBluetoothTransport = $dev.InstanceId -match 'BTHENUM|BTH\\' -or $dev.Class -eq 'Bluetooth'

            # Hard exclusions: Never show internal/native audio as Bluetooth
            $isExcluded = $dev.InstanceId -match 'HDAUDIO|INTELAUDIO|SWD\\MMDEVAPI|USB\\VID_|PCI\\'
            if ($isExcluded) { continue }

            # Extract base name for profile lookup
            $baseName = $dev.FriendlyName -replace '\s*(Stereo|Hands-Free AG Audio|Hands-Free|HFP|A2DP|Audio)$', '' -replace '\s+$', ''
            $baseName = $baseName.Trim()

            # Check if device has audio profiles (from BTHENUM endpoints)
            $profiles = $deviceProfiles[$baseName]
            $hasAudioProfiles = $profiles -and ($profiles.HasA2DP -or $profiles.HasHFP -or $profiles.Endpoints.Count -gt 0)

            # Device is audio if it has BTHENUM audio endpoints OR matches known audio device patterns
            # BUT only if it passes the transport gate
            $isAudioDevice = $false
            $deviceKind = "Unknown"

            if ($hasAudioProfiles) {
                $isAudioDevice = $true
            }
            elseif ($hasBluetoothTransport) {
                # Check known audio brand/model patterns (only for transport-verified devices)
                # These are Bluetooth-specific brands that don't make internal speakers
                if ($dev.FriendlyName -match "AirPods|Galaxy Buds|WH-1000|WF-1000|Jabra|Bose (QC|NC|Sport)|JBL (Flip|Charge|Xtreme|Tune|Live)|Beats|Dime|Kanto|ORA|Soundcore|Anker|Tozo|Skullcandy|Sennheiser (Momentum|HD 4|CX)|Bang & Olufsen|B&O|Marshall (Major|Minor|Emberton)|Sony (WH-|WF-|SRS-)|Echo Buds") {
                    $isAudioDevice = $true
                }
            }

            if (-not $isAudioDevice) { continue }

            # Classify device kind (for UI icons)
            if ($dev.FriendlyName -match "AirPods|Buds|Earbuds|WF-|Tozo|Echo Buds") {
                $deviceKind = "Earbuds"
            }
            elseif ($dev.FriendlyName -match "Headphone|Headset|WH-|Jabra|Over-Ear|Momentum|HD 4") {
                $deviceKind = "Headphones"
            }
            elseif ($dev.FriendlyName -match "Flip|Charge|Xtreme|Boom|Kanto|ORA|Dime|Emberton|SRS-|Soundbar|Pill") {
                $deviceKind = "Speaker"
            }

            # Avoid duplicates
            $normalizedName = $baseName
            if ($seenDevices.ContainsKey($normalizedName)) { continue }
            $seenDevices[$normalizedName] = $true

            # === TWO-AXIS STATE MODEL ===
            # Presence: Connected (BT stack reports present) | Paired | Remembered | Ghost
            # Activity: Active (audio routing) | Idle (connected, no route) | Inactive

            $presence = "Remembered"  # Default until proven present
            $activity = "Inactive"

            # Presence detection: Use PnP Present flag + active endpoints
            # BT devices with Present=True AND active endpoint = Connected
            # BT devices with Present=True but no endpoint = Paired (connected at stack, not routing)
            # BT devices with Present=False = Remembered (cache only)
            $hasActiveEndpoint = $profiles -and $profiles.HasActiveEndpoint

            if ($dev.Present -and $hasActiveEndpoint) {
                $presence = "Connected"
            }
            elseif ($dev.Present) {
                # Device is present at Bluetooth stack but not routing audio
                $presence = "Paired"
            }
            else {
                $presence = "Remembered"
            }

            # A2DP/HFP support
            $supportsA2DP = if ($profiles) { $profiles.HasA2DP } else { $null }
            $supportsHFP = if ($profiles) { $profiles.HasHFP } else { $null }

            # Check if default playback (for Activity)
            $isDefaultPlayback = $false
            if ($defaultPlaybackName -and $normalizedName) {
                $isDefaultPlayback = $defaultPlaybackName -match [regex]::Escape($normalizedName)
            }

            # Activity: Based on presence and audio routing
            if ($presence -eq "Connected") {
                $activity = if ($isDefaultPlayback) { "Active" } else { "Idle" }
            }
            elseif ($presence -eq "Paired") {
                $activity = "Idle"  # Connected at stack, not routing
            }
            else {
                $activity = "Inactive"  # Not present
            }

            $devices += [PSCustomObject]@{
                Name = $normalizedName
                InstanceId = $dev.InstanceId
                Status = $dev.Status
                Presence = $presence
                Activity = $activity
                IsAudioDevice = $true
                DeviceKind = $deviceKind
                SupportsA2DP = $supportsA2DP
                SupportsHFP = $supportsHFP
                IsDefaultPlayback = $isDefaultPlayback
                Notes = @("Transport-verified", "Two-axis state")
            }
        }

        # === STEP 6: Add devices found via BTHENUM endpoints not in Class Bluetooth ===
        # Some BT audio devices only appear as audio endpoints, not in Bluetooth class
        # But they MUST have BTHENUM transport proof
        foreach ($baseName in $deviceProfiles.Keys) {
            $normalizedName = $baseName.Trim()
            if ($seenDevices.ContainsKey($normalizedName)) { continue }
            if (Test-IsTransportOrServiceNode -Name $normalizedName) { continue }

            $profiles = $deviceProfiles[$baseName]
            $primaryEndpoint = $profiles.Endpoints | Where-Object { $_.Status -eq 'OK' } | Select-Object -First 1
            if (-not $primaryEndpoint) {
                $primaryEndpoint = $profiles.Endpoints | Select-Object -First 1
            }
            if (-not $primaryEndpoint) { continue }

            # TRANSPORT GATE: Already verified in Step 3 (only BTHENUM endpoints in $deviceProfiles)

            # Classify device kind
            $deviceKind = "Unknown"
            if ($normalizedName -match "AirPods|Buds|Earbuds|WF-") {
                $deviceKind = "Earbuds"
            }
            elseif ($normalizedName -match "Headphone|Headset|WH-|Jabra") {
                $deviceKind = "Headphones"
            }
            elseif ($normalizedName -match "Flip|Charge|Xtreme|Boom|Kanto|ORA|Dime|Speaker") {
                $deviceKind = "Speaker"
            }

            # Presence/Activity
            $presence = if ($primaryEndpoint.Status -eq 'OK') { "Connected" } else { "Remembered" }

            $isDefaultPlayback = $false
            if ($defaultPlaybackName -and $normalizedName) {
                $isDefaultPlayback = $defaultPlaybackName -match [regex]::Escape($normalizedName)
            }

            $activity = "Inactive"
            if ($presence -eq "Connected") {
                $activity = if ($isDefaultPlayback) { "Active" } else { "Idle" }
            }

            $seenDevices[$normalizedName] = $true

            $devices += [PSCustomObject]@{
                Name = $normalizedName
                InstanceId = $primaryEndpoint.InstanceId
                Status = $primaryEndpoint.Status
                Presence = $presence
                Activity = $activity
                IsAudioDevice = $true
                DeviceKind = $deviceKind
                SupportsA2DP = $profiles.HasA2DP
                SupportsHFP = $profiles.HasHFP
                IsDefaultPlayback = $isDefaultPlayback
                Notes = @("BTHENUM endpoint", "Two-axis state")
            }
        }
    }
    catch {
        # Silent fail - return empty array
    }

    return $devices
}

function Get-DefaultPlaybackDevice {
    <#
    .SYNOPSIS
        Gets the current default Windows playback device (best-effort, registry-based).
    .DESCRIPTION
        Uses legacy Sound Mapper registry which may not reflect real-time changes.
        Does not use CoreAudio/MMDevice APIs. Results should be treated as indicative only.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        RegistryDevice = $null
        IsBluetooth = $false
        IsHFP = $false
        DetectionMethod = "Registry (best-effort)"
    }

    try {
        # Try Sound Mapper registry - legacy method, may lag behind actual default
        $regPath = "HKCU:\Software\Microsoft\Multimedia\Sound Mapper"
        if (Test-Path $regPath) {
            $playback = (Get-ItemProperty -Path $regPath -Name "Playback" -ErrorAction SilentlyContinue).Playback
            if ($playback) {
                $result.RegistryDevice = $playback
                $result.IsBluetooth = $playback -match "Bluetooth|BT|Hands-Free|Headset|AirPods|Buds"
                $result.IsHFP = $playback -match "Hands-Free|HFP|AG Audio"
            }
        }
    }
    catch {
        # Silent fail - detection method remains best-effort
    }

    return $result
}

function Get-KodiAudioSettings {
    <#
    .SYNOPSIS
        Parses Kodi audio settings from guisettings.xml.
    #>
    [CmdletBinding()]
    param()

    $guiSettingsPath = Join-Path $env:APPDATA "Kodi\userdata\guisettings.xml"

    if (-not (Test-Path $guiSettingsPath)) {
        return @{
            Found = $false
            Path = $guiSettingsPath
            Error = "guisettings.xml not found"
        }
    }

    try {
        [xml]$xml = Get-Content $guiSettingsPath -Raw -ErrorAction Stop
        $audioSettings = $xml.settings.setting | Where-Object { $_.id -match "^audiooutput\." }

        # Parse key settings
        $audioDevice = ($audioSettings | Where-Object { $_.id -eq "audiooutput.audiodevice" }).'#text'
        $passthroughDevice = ($audioSettings | Where-Object { $_.id -eq "audiooutput.passthroughdevice" }).'#text'
        $passthrough = ($audioSettings | Where-Object { $_.id -eq "audiooutput.passthrough" }).'#text' -eq 'true'
        $channels = ($audioSettings | Where-Object { $_.id -eq "audiooutput.channels" }).'#text'
        $guiSoundMode = ($audioSettings | Where-Object { $_.id -eq "audiooutput.guisoundmode" }).'#text'
        $streamSilence = ($audioSettings | Where-Object { $_.id -eq "audiooutput.streamsilence" }).'#text'

        # Parse audio quality/warbling-relevant settings (P0/P1/P2 tests)
        $sampleRateRaw = ($audioSettings | Where-Object { $_.id -eq "audiooutput.samplerate" }).'#text'
        $processQuality = ($audioSettings | Where-Object { $_.id -eq "audiooutput.processquality" }).'#text'
        $bufferSize = ($audioSettings | Where-Object { $_.id -eq "audiooutput.buffersize" }).'#text'

        # Parse sample rate to integer (Kodi stores as Hz, e.g., "48000")
        $sampleRate = $null
        if ($sampleRateRaw -match '^\d+$') {
            $sampleRate = [int]$sampleRateRaw
        }

        # Detect audio mode
        $isWASAPI = $audioDevice -match "WASAPI:"
        $isDirectSound = $audioDevice -match "DirectSound:" -or (-not $isWASAPI -and $audioDevice -ne "default")
        $isBluetooth = $audioDevice -match "Bluetooth|BT|Hands-Free|Headset|AirPods|Buds"
        $isDefault = $audioDevice -eq "default" -or [string]::IsNullOrEmpty($audioDevice)

        return @{
            Found = $true
            Path = $guiSettingsPath
            AudioDevice = $audioDevice
            PassthroughDevice = $passthroughDevice
            PassthroughEnabled = $passthrough
            Channels = $channels
            GUISoundMode = $guiSoundMode
            StreamSilence = $streamSilence
            IsWASAPI = $isWASAPI
            IsDirectSound = $isDirectSound
            IsBluetooth = $isBluetooth
            IsDefault = $isDefault
            # Audio quality/warbling-relevant settings
            SampleRate = $sampleRate          # Hz as integer, or $null if not set
            ProcessQuality = $processQuality  # "high", "medium", "low", or $null
            BufferSize = $bufferSize          # Buffer size setting, or $null
            RawSettings = $audioSettings | ForEach-Object { @{ Id = $_.id; Value = $_.'#text' } }
        }
    }
    catch {
        return @{
            Found = $true
            Path = $guiSettingsPath
            Error = "Failed to parse: $($_.Exception.Message)"
        }
    }
}

function Get-WindowsDefaultSampleRate {
    <#
    .SYNOPSIS
        Retrieves the sample rate of the Windows default playback device (best-effort).
    .DESCRIPTION
        Enumerates MMDevices registry and reads PKEY_AudioEngine_DeviceFormat blob
        to parse nSamplesPerSec from the WAVEFORMATEX structure.
        Returns $null on any failure (graceful degradation).
    #>
    [CmdletBinding()]
    param()

    try {
        $mmDevicesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
        if (-not (Test-Path $mmDevicesPath)) {
            return $null
        }

        # PKEY_AudioEngine_DeviceFormat property key
        $deviceFormatPropKey = "{f19f8f14-0001-4a49-a000-0000f0000037},0"

        # Find the active/default endpoint - look for endpoint with Role:0 (default multimedia)
        # or fall back to first endpoint with DeviceState=1 (active)
        $endpoints = Get-ChildItem $mmDevicesPath -ErrorAction SilentlyContinue

        foreach ($endpoint in $endpoints) {
            $propsPath = Join-Path $endpoint.PSPath "Properties"
            if (-not (Test-Path $propsPath)) { continue }

            # Check if this endpoint is active (DeviceState = 1)
            $deviceStateProp = "{a45c254e-df1c-4efd-8020-67d146a850e0},2"  # PKEY_Device_DeviceDesc... actually DeviceState
            try {
                # Check DeviceState in main endpoint key
                $endpointProps = Get-ItemProperty -Path $endpoint.PSPath -ErrorAction SilentlyContinue
                # DeviceState 1 = Active
                if ($endpointProps -and $endpointProps.DeviceState -eq 1) {
                    # Read DeviceFormat blob
                    $props = Get-ItemProperty -Path $propsPath -ErrorAction SilentlyContinue
                    $formatBlob = $props.$deviceFormatPropKey

                    if ($formatBlob -and $formatBlob.Length -ge 8) {
                        # WAVEFORMATEX: nSamplesPerSec is at offset 4, 4 bytes (little-endian DWORD)
                        $sampleRate = [BitConverter]::ToUInt32($formatBlob, 4)
                        if ($sampleRate -ge 8000 -and $sampleRate -le 192000) {
                            return $sampleRate
                        }
                    }
                }
            }
            catch {
                # Continue to next endpoint
            }
        }

        return $null
    }
    catch {
        return $null
    }
}

function Get-AudioSampleRates {
    <#
    .SYNOPSIS
        Compares Kodi and Windows sample rates for mismatch detection (P0 test).
    .DESCRIPTION
        Gets Kodi's configured sample rate from guisettings.xml and Windows default
        playback device sample rate from PKEY_AudioEngine_DeviceFormat registry blob.
        A mismatch (e.g., 48kHz vs 44.1kHz) is a strong signal for "sparkling" audio.
    .PARAMETER KodiSettings
        The KodiSettings hashtable from Get-KodiAudioSettings.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$KodiSettings
    )

    $result = @{
        KodiSampleRate = $null
        WindowsSampleRate = $null
        Mismatch = $false
        DetectionMethod = "registry-best-effort"
    }

    # Get Kodi sample rate
    if ($KodiSettings -and $KodiSettings.Found -and $KodiSettings.SampleRate) {
        $result.KodiSampleRate = $KodiSettings.SampleRate
    }

    # Get Windows sample rate
    $result.WindowsSampleRate = Get-WindowsDefaultSampleRate

    # Detect mismatch (only if both are known)
    if ($result.KodiSampleRate -and $result.WindowsSampleRate) {
        # Common mismatch: 48000 vs 44100
        $result.Mismatch = $result.KodiSampleRate -ne $result.WindowsSampleRate
    }

    return $result
}

function Test-HFPHijackRisk {
    <#
    .SYNOPSIS
        Detects risk of HFP (Hands-Free Profile) hijacking Bluetooth audio (P1 test).
    .DESCRIPTION
        Checks if a Bluetooth mic endpoint exists and if HFP profile activation
        events were detected in recent event logs. This indicates another app
        (Teams, Zoom, etc.) may have activated call mode, degrading audio quality.
    .PARAMETER PairedDevices
        Array of paired Bluetooth devices from Get-BluetoothPairedAudioDevices.
    .PARAMETER EventLogHints
        Event log hints from Get-BluetoothEventLogHints.
    .PARAMETER KodiSettings
        Kodi settings from Get-KodiAudioSettings.
    #>
    [CmdletBinding()]
    param(
        [array]$PairedDevices,
        [hashtable]$EventLogHints,
        [hashtable]$KodiSettings
    )

    $result = @{
        MicEndpointPresent = $false
        HFPActivationDetected = $false
        KodiExpectsA2DP = $false
        HijackRisk = $false
    }

    # Check for Bluetooth mic (HFP) endpoint
    if ($PairedDevices) {
        $hfpDevices = $PairedDevices | Where-Object { $_.IsHFP -and $_.IsConnected }
        $result.MicEndpointPresent = ($hfpDevices.Count -gt 0)
    }

    # Check event logs for HFP/call mode activation patterns
    if ($EventLogHints -and $EventLogHints.Hints) {
        $hfpPatterns = $EventLogHints.Hints | Where-Object {
            $_.Message -match "Hands-Free|HFP|SCO|call mode|voice|telephony|microphone activated"
        }
        $result.HFPActivationDetected = ($hfpPatterns.Count -gt 0)
    }

    # Check if Kodi expects A2DP stereo (Bluetooth selected but not explicitly HFP)
    if ($KodiSettings -and $KodiSettings.Found -and $KodiSettings.IsBluetooth) {
        # Kodi using Bluetooth but not explicitly a Hands-Free device
        $kodiUsingHFP = $KodiSettings.AudioDevice -match "Hands-Free|HFP|AG Audio"
        $result.KodiExpectsA2DP = -not $kodiUsingHFP
    }

    # Determine hijack risk:
    # Risk exists if mic endpoint is present AND (HFP activation detected OR Kodi expects A2DP but HFP exists)
    $result.HijackRisk = $result.MicEndpointPresent -and ($result.HFPActivationDetected -or $result.KodiExpectsA2DP)

    return $result
}

function Get-PowerPlanInfo {
    <#
    .SYNOPSIS
        Detects the active Windows power plan (best-effort).
    .DESCRIPTION
        Uses powercfg to get the active scheme. Returns plan name and whether
        it's Power Saver mode (relevant for buffer underrun risk heuristic).
    #>
    [CmdletBinding()]
    param()

    $result = @{
        ActivePlan = "Unknown"
        PlanGuid = $null
        IsPowerSaver = $false
        DetectionMethod = "powercfg"
    }

    try {
        $output = powercfg /getactivescheme 2>&1
        if ($output -match "GUID:\s*([0-9a-f-]+)\s*\(([^)]+)\)") {
            $result.PlanGuid = $Matches[1]
            $result.ActivePlan = $Matches[2].Trim()
            $result.IsPowerSaver = $result.ActivePlan -match "Power saver|Economizador|Risparmio energia|Économie d'énergie"
        }
    }
    catch {
        # Silent fail - return Unknown
    }

    return $result
}

function Test-BufferUnderrunRisk {
    <#
    .SYNOPSIS
        Evaluates buffer underrun risk for Bluetooth audio (P2 test).
    .DESCRIPTION
        Combines signals: Bluetooth audio active + Kodi high process quality +
        Power Saver mode = potential for intermittent crackling/warble under load.
        Only flags risk if ALL THREE signals are present.
    .PARAMETER KodiSettings
        Kodi settings from Get-KodiAudioSettings.
    .PARAMETER DefaultPlayback
        Default playback info from Get-DefaultPlaybackDevice.
    .PARAMETER PowerPlanInfo
        Power plan info from Get-PowerPlanInfo.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$KodiSettings,
        [hashtable]$DefaultPlayback,
        [hashtable]$PowerPlanInfo
    )

    $result = @{
        BluetoothAudio = $false
        KodiProcessQuality = $null
        PowerPlan = $null
        IsPowerSaver = $false
        UnderrunRisk = $false
    }

    # Check if Bluetooth is the active playback path
    if ($DefaultPlayback -and $DefaultPlayback.IsBluetooth) {
        $result.BluetoothAudio = $true
    }
    # Also check Kodi settings as secondary signal
    if ($KodiSettings -and $KodiSettings.Found -and $KodiSettings.IsBluetooth) {
        $result.BluetoothAudio = $true
    }

    # Get Kodi process quality
    if ($KodiSettings -and $KodiSettings.Found -and $KodiSettings.ProcessQuality) {
        $result.KodiProcessQuality = $KodiSettings.ProcessQuality
    }

    # Get power plan
    if ($PowerPlanInfo) {
        $result.PowerPlan = $PowerPlanInfo.ActivePlan
        $result.IsPowerSaver = $PowerPlanInfo.IsPowerSaver
    }

    # Underrun risk: ALL THREE signals must be present
    # - Bluetooth audio active
    # - Kodi process quality is "high" (case-insensitive)
    # - Power plan is Power Saver
    $highProcessQuality = $result.KodiProcessQuality -and ($result.KodiProcessQuality -match "^high$")
    $result.UnderrunRisk = $result.BluetoothAudio -and $highProcessQuality -and $result.IsPowerSaver

    return $result
}

function Get-BluetoothEventLogHints {
    <#
    .SYNOPSIS
        Collects recent Bluetooth-related event log entries (last 60 minutes).
        Returns both summary stats and a timeline of classified events.
    #>
    [CmdletBinding()]
    param()

    $cutoffTime = (Get-Date).AddMinutes(-60)
    $hints = @()
    $timeline = @()  # NirSoft-inspired: timestamped event timeline
    $unknownEventKeys = @()  # B-refinement: surface unknown "Provider/Id" keys for classifier refinement
    $logsAccessible = @{
        # Backward-compat: BthUSB key retained so consumers that look it up still work.
        # The new per-channel map below carries the authoritative truth.
        BthUSB = $false
        System = $false
    }
    $channelStates = @{}  # per-channel: $true if read returned events, $false otherwise

    # F2: Disconnect/connect classification now lives in Get-BluetoothEventClass,
    # which uses stable (Provider, Id) tuples only. The local Get-EventType
    # retained below is purely cosmetic — used to label the human-readable
    # Timeline view — and is NEVER consulted for verdict-critical counts
    # (DisconnectEvents, FrequentDisconnects). Localized Message text MUST NOT
    # drive verdict logic.
    function Get-EventType {
        param([string]$Message, [string]$Level)
        # Cosmetic timeline label only; defaults to Level if no English keyword hits.
        if ($Message -match "connect(?:ed|ion).*establish|paired|link.*up") { return "Connected" }
        if ($Message -match "disconnect|removed|lost|link.*down") { return "Disconnected" }
        if ($Message -match "hands.?free|HFP|SCO.*connect|call.*mode") { return "Profile: HFP" }
        if ($Message -match "A2DP|stereo|media.*audio") { return "Profile: A2DP" }
        if ($Message -match "reset|restart") { return "Adapter Reset" }
        if ($Level -eq "Error") { return "Error" }
        if ($Level -eq "Warning") { return "Warning" }
        return "Info"
    }

    # B-refinement: enumerate every enabled Bluetooth-* /Operational channel
    # at runtime. Different Windows builds expose different channels:
    #   - Win10                     → BthUSB/Operational
    #   - modern Win11              → Bthmini/Operational (disabled by default)
    #   - Pre-pairing/Policy/MTPEnum etc. → enabled, mostly off-topic
    # Hardcoding any single channel produces a silent dead spot on builds
    # where it doesn't exist.
    $btChannels = @(Get-BluetoothOperationalLogNames)
    if (-not $btChannels -or $btChannels.Count -eq 0) {
        # No enabled BT operational channels at all — surface explicitly.
        $channelStates['(none)'] = $false
    }

    foreach ($channelName in $btChannels) {
        try {
            $channelEvents = Get-WinEvent -LogName $channelName -MaxEvents 50 -ErrorAction Stop |
                Where-Object { $_.TimeCreated -gt $cutoffTime }

            $channelStates[$channelName] = $true

            # Backward-compat: keep the BthUSB key in logsAccessible truthy when
            # the legacy channel is among the enabled set.
            if ($channelName -eq 'Microsoft-Windows-Bluetooth-BthUSB/Operational') {
                $logsAccessible.BthUSB = $true
            }

            foreach ($evt in $channelEvents) {
                $eventType = Get-EventType -Message $evt.Message -Level $evt.LevelDisplayName
                $stableClass = Get-BluetoothEventClass -Event $evt
                $isRelevant = $evt.LevelDisplayName -in @("Error", "Warning") -or
                              ($stableClass -in @('Connected', 'Disconnected'))

                if ($isRelevant) {
                    $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                    $hints += @{
                        Source = $channelName
                        Time = $evt.TimeCreated
                        Level = $evt.LevelDisplayName
                        Id = $evt.Id
                        ProviderName = $evt.ProviderName
                        StableClass = $stableClass
                        Message = $msgSnippet
                    }

                    $timeline += @{
                        Time = $evt.TimeCreated
                        Type = $eventType
                        StableClass = $stableClass
                        EventId = $evt.Id
                        ProviderName = $evt.ProviderName
                        Device = ""
                        Source = "Driver"
                        Summary = $msgSnippet.Substring(0, [Math]::Min(80, $msgSnippet.Length))
                    }
                }

                # Surface unknown (Provider, Id) so field operators can refine the
                # classifier table. Skip events with no provider name (cannot key).
                if ($stableClass -eq 'Unknown' -and $null -ne $evt.Id -and -not [string]::IsNullOrWhiteSpace($evt.ProviderName)) {
                    $key = "$($evt.ProviderName)/$($evt.Id)"
                    if ($unknownEventKeys -notcontains $key) {
                        $unknownEventKeys += $key
                    }
                }
            }
        }
        catch {
            # Channel disabled, empty, or permission-denied — record and move on.
            $channelStates[$channelName] = $false
        }
    }

    # System log for audio/BT related
    try {
        $sysEvents = Get-WinEvent -LogName "System" -MaxEvents 100 -ErrorAction Stop |
            Where-Object {
                $_.TimeCreated -gt $cutoffTime -and
                ($_.ProviderName -match "Bluetooth|Audio|BTHUSB" -or $_.Message -match "Bluetooth|audio endpoint")
            }

        $logsAccessible.System = $true

        foreach ($evt in $sysEvents) {
            $eventType = Get-EventType -Message $evt.Message -Level $evt.LevelDisplayName
            $stableClass = Get-BluetoothEventClass -Event $evt
            # System log relevance still uses level + lightweight provider text since the
            # System log spans many providers; the classifier table is keyed to BthUSB.
            $isRelevant = $evt.LevelDisplayName -in @("Error", "Warning") -or
                          ($stableClass -in @('Connected', 'Disconnected'))

            if ($isRelevant) {
                $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                $hints += @{
                    Source = "System"
                    Time = $evt.TimeCreated
                    Level = $evt.LevelDisplayName
                    Id = $evt.Id
                    ProviderName = $evt.ProviderName
                    StableClass = $stableClass
                    Message = $msgSnippet
                }

                # Add to timeline
                $timeline += @{
                    Time = $evt.TimeCreated
                    Type = $eventType
                    StableClass = $stableClass
                    EventId = $evt.Id
                    Device = ""
                    Source = if ($evt.ProviderName) { $evt.ProviderName } else { "System" }
                    Summary = $msgSnippet.Substring(0, [Math]::Min(80, $msgSnippet.Length))
                }
            }
        }
    }
    catch {
        # Silent fail - log access issues are not diagnostic concerns
        $logsAccessible.System = $false
    }

    # Sort timeline by time descending (most recent first)
    $timeline = $timeline | Sort-Object Time -Descending

    # F2: DisconnectEvents counts only events with StableClass == 'Disconnected'.
    # English Message regex is NEVER used here — that was the prior bug class.
    $disconnectCount = ($hints | Where-Object { $_.StableClass -eq 'Disconnected' }).Count
    $profileSwitchCount = ($timeline | Where-Object { $_.Type -match "^Profile:" }).Count

    return @{
        Count = $hints.Count
        HasErrors = ($hints | Where-Object { $_.Level -eq "Error" }).Count -gt 0
        HasWarnings = ($hints | Where-Object { $_.Level -eq "Warning" }).Count -gt 0
        DisconnectEvents = $disconnectCount
        ProfileSwitches = $profileSwitchCount
        FrequentDisconnects = $disconnectCount -ge 3
        LogsAccessible = $logsAccessible
        ChannelStates = $channelStates       # per-BT-channel read state (B-refinement)
        UnknownEventKeys = $unknownEventKeys # "$Provider/$Id" tuples awaiting classification
        UnknownEventIds = @($unknownEventKeys | ForEach-Object {
            $parts = $_ -split '/', 2
            if ($parts.Count -eq 2) { [int]$parts[1] } else { $null }
        } | Where-Object { $null -ne $_ } | Select-Object -Unique)  # backward-compat
        Timeline = $timeline
        Hints = $hints | Sort-Object Time -Descending | Select-Object -First 10
    }
}

#endregion

#region Public Functions

function Get-BluetoothDiagnostics {
    <#
    .SYNOPSIS
        Collects comprehensive Bluetooth audio diagnostics.
    .DESCRIPTION
        Gathers adapter info, service states, paired devices, default playback,
        Kodi settings, and event log hints. Computes verdict and findings.
    .PARAMETER BypassCache
        If specified, bypasses the 30-second cache and collects fresh data.
    .OUTPUTS
        Hashtable with all diagnostic information, verdict, and findings.
    #>
    [CmdletBinding()]
    param(
        [switch]$BypassCache
    )

    # Check cache
    if (-not $BypassCache -and $script:BluetoothDiagnosticsCache -and
        ((Get-Date) - $script:LastDiagnosticsTime).TotalSeconds -lt $script:CacheTTLSeconds) {
        return $script:BluetoothDiagnosticsCache
    }

    # Get Bluetooth audio devices (user-facing, filtered)
    $audioDevices = @(Get-BluetoothAudioDevices)
    # Cap list to 8 devices for UI performance
    $audioDevicesCapped = if ($audioDevices.Count -gt 8) {
        $overflow = $audioDevices.Count - 8
        $capped = $audioDevices | Select-Object -First 8
        # Add note about overflow
        $capped | ForEach-Object { $_.Notes += "+$overflow more devices not shown" }
        $capped
    } else {
        $audioDevices
    }

    $diagnostics = [ordered]@{
        Timestamp = Get-Date
        Adapter = Get-BluetoothAdapterInfo
        Services = Get-BluetoothServiceStates
        PairedDevices = @(Get-BluetoothPairedAudioDevices)
        BluetoothAudioDevices = $audioDevicesCapped
        DefaultPlayback = Get-DefaultPlaybackDevice
        KodiSettings = Get-KodiAudioSettings
        EventLogHints = Get-BluetoothEventLogHints
        # Audio warbling diagnostic data (P0/P1/P2 tests)
        PowerPlan = Get-PowerPlanInfo
        SampleRates = $null  # Computed below after KodiSettings
        HFPHijackRisk = $null  # Computed below after EventLogHints
        BufferUnderrunRisk = $null  # Computed below after PowerPlan
        Verdict = $null
        Findings = @()
    }

    # Compute warbling-related diagnostics (depend on base data)
    $diagnostics.SampleRates = Get-AudioSampleRates -KodiSettings $diagnostics.KodiSettings
    $diagnostics.HFPHijackRisk = Test-HFPHijackRisk `
        -PairedDevices $diagnostics.PairedDevices `
        -EventLogHints $diagnostics.EventLogHints `
        -KodiSettings $diagnostics.KodiSettings
    $diagnostics.BufferUnderrunRisk = Test-BufferUnderrunRisk `
        -KodiSettings $diagnostics.KodiSettings `
        -DefaultPlayback $diagnostics.DefaultPlayback `
        -PowerPlanInfo $diagnostics.PowerPlan

    # Compute verdict
    $diagnostics.Verdict = Get-BluetoothVerdict -Diagnostics $diagnostics

    # Compute findings
    $diagnostics.Findings = @(Get-BluetoothFindings -Diagnostics $diagnostics -Verdict $diagnostics.Verdict)

    # Cache results
    $script:BluetoothDiagnosticsCache = $diagnostics
    $script:LastDiagnosticsTime = Get-Date

    return $diagnostics
}

function Get-BluetoothVerdict {
    <#
    .SYNOPSIS
        Pure classifier - computes READY/DEGRADED/UNSUITABLE verdict.
    .PARAMETER Diagnostics
        The diagnostics hashtable from Get-BluetoothDiagnostics.
    .OUTPUTS
        Hashtable with Status, Confidence, Summary, and Reasons.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Diagnostics
    )

    $reasons = @()
    $confidence = "High"

    # === UNSUITABLE Conditions ===

    # No BT adapter
    if (-not $Diagnostics.Adapter.Present) {
        return @{
            Status = "UNSUITABLE"
            Confidence = "High"
            Summary = "No Bluetooth adapter found on this system"
            Reasons = @("NO_ADAPTER")
        }
    }

    # BT adapter disabled
    if (-not $Diagnostics.Adapter.Enabled) {
        return @{
            Status = "UNSUITABLE"
            Confidence = "High"
            Summary = "Bluetooth adapter is disabled or has an error"
            Reasons = @("ADAPTER_DISABLED")
        }
    }

    # Core audio services check
    # Note: On modern Windows (10/11), Audiosrv may be stopped while audio still works.
    # AudioEndpointBuilder is the critical service - if it's running, audio generally works.
    # Audiosrv starts on-demand when needed.
    $audioSrv = $Diagnostics.Services["Audiosrv"]
    $aepBuilder = $Diagnostics.Services["AudioEndpointBuilder"]

    # Only UNSUITABLE if AudioEndpointBuilder is dead (critical service)
    if ($aepBuilder -and -not $aepBuilder.Running) {
        return @{
            Status = "UNSUITABLE"
            Confidence = "High"
            Summary = "Audio Endpoint Builder service is not running"
            Reasons = @("ENDPOINT_BUILDER_DEAD")
        }
    }

    # Audiosrv stopped is only UNSUITABLE if AudioEndpointBuilder is also stopped
    # Otherwise it's not a problem (Audiosrv starts on-demand on modern Windows)
    if ($audioSrv -and -not $audioSrv.Running -and $aepBuilder -and -not $aepBuilder.Running) {
        return @{
            Status = "UNSUITABLE"
            Confidence = "High"
            Summary = "Windows Audio services are not running"
            Reasons = @("AUDIO_SERVICE_DEAD")
        }
    }

    # Kodi passthrough with Bluetooth
    $kodi = $Diagnostics.KodiSettings
    if ($kodi.Found -and $kodi.PassthroughEnabled -and $kodi.IsBluetooth) {
        return @{
            Status = "UNSUITABLE"
            Confidence = "High"
            Summary = "Kodi passthrough is enabled but incompatible with Bluetooth audio"
            Reasons = @("PASSTHROUGH_BT_CONFLICT")
        }
    }

    # === DEGRADED Conditions ===

    # HFP/Hands-Free active (poor audio quality)
    $hfpActive = $Diagnostics.PairedDevices | Where-Object { $_.IsHFP -and $_.IsConnected }
    if ($hfpActive) {
        $reasons += "HFP_ACTIVE"
    }

    # Default playback is HFP
    if ($Diagnostics.DefaultPlayback.IsHFP) {
        $reasons += "DEFAULT_IS_HFP"
    }

    # WASAPI + Bluetooth (risk of exclusive mode issues)
    if ($kodi.Found -and $kodi.IsWASAPI -and $kodi.IsBluetooth) {
        $reasons += "WASAPI_BT_RISK"
    }

    # Frequent disconnects in event log
    if ($Diagnostics.EventLogHints.FrequentDisconnects) {
        $reasons += "FREQUENT_DISCONNECTS"
        $confidence = "Med"
    }

    # Ghost/stale endpoints
    $ghostEndpoints = $Diagnostics.PairedDevices | Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' }
    if ($ghostEndpoints.Count -gt 0) {
        $reasons += "GHOST_ENDPOINTS"
    }

    # Bluetooth service not running
    $bthserv = $Diagnostics.Services["bthserv"]
    if ($bthserv -and -not $bthserv.Running) {
        $reasons += "BTHSERV_STOPPED"
    }

    # BTAGService not running (if it exists)
    $btag = $Diagnostics.Services["BTAGService"]
    if ($btag -and $btag.Status -ne "NotFound" -and -not $btag.Running) {
        $reasons += "BTAG_STOPPED"
    }

    # Event log errors
    if ($Diagnostics.EventLogHints.HasErrors) {
        $reasons += "EVENT_LOG_ERRORS"
        if ($confidence -eq "High") { $confidence = "Med" }
    }

    # === P0/P1/P2 Warbling Diagnostics (only if Bluetooth is active playback) ===
    $btActive = $Diagnostics.DefaultPlayback.IsBluetooth -or ($kodi.Found -and $kodi.IsBluetooth)

    # P0: Sample rate mismatch (highest signal for "sparkling")
    if ($btActive -and $Diagnostics.SampleRates -and $Diagnostics.SampleRates.Mismatch) {
        $reasons += "SAMPLERATE_MISMATCH"
    }

    # P1: HFP hijack risk (call mode activation)
    if ($btActive -and $Diagnostics.HFPHijackRisk -and $Diagnostics.HFPHijackRisk.HijackRisk) {
        $reasons += "HFP_HIJACK_RISK"
    }

    # P2: Buffer underrun risk (only if all three signals present - checked in Test-BufferUnderrunRisk)
    if ($Diagnostics.BufferUnderrunRisk -and $Diagnostics.BufferUnderrunRisk.UnderrunRisk) {
        $reasons += "BUFFER_UNDERRUN_RISK"
        if ($confidence -eq "High") { $confidence = "Med" }  # Heuristic, not hard diagnosis
    }

    if ($reasons.Count -gt 0) {
        $summaryParts = @()
        if ($reasons -contains "SAMPLERATE_MISMATCH") {
            $summaryParts += "sample rate mismatch (resampling artifacts likely)"
        }
        if ($reasons -contains "HFP_HIJACK_RISK") {
            $summaryParts += "call mode may be active"
        }
        if ($reasons -contains "BUFFER_UNDERRUN_RISK") {
            $summaryParts += "buffer underrun risk (Power Saver + high processing)"
        }
        if ($reasons -contains "HFP_ACTIVE" -or $reasons -contains "DEFAULT_IS_HFP") {
            $summaryParts += "Hands-Free profile active (reduced audio quality)"
        }
        if ($reasons -contains "WASAPI_BT_RISK") {
            $summaryParts += "Kodi WASAPI mode may conflict with Bluetooth"
        }
        if ($reasons -contains "FREQUENT_DISCONNECTS") {
            $summaryParts += "frequent disconnects detected"
        }
        if ($reasons -contains "BTHSERV_STOPPED" -or $reasons -contains "BTAG_STOPPED") {
            $summaryParts += "Bluetooth services not running"
        }

        $summary = if ($summaryParts.Count -gt 0) {
            "Bluetooth audio degraded: " + ($summaryParts -join "; ")
        } else {
            "Bluetooth audio has minor issues"
        }

        return @{
            Status = "DEGRADED"
            Confidence = $confidence
            Summary = $summary
            Reasons = $reasons
        }
    }

    # === READY ===
    return @{
        Status = "READY"
        Confidence = "High"
        Summary = "Bluetooth audio appears ready for use"
        Reasons = @()
    }
}

function Get-BluetoothFindings {
    <#
    .SYNOPSIS
        Generates curated top findings (max 3) with single action hints.
    .PARAMETER Diagnostics
        The diagnostics hashtable.
    .PARAMETER Verdict
        The verdict hashtable.
    .OUTPUTS
        Array of finding hashtables.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Diagnostics,

        [Parameter(Mandatory)]
        [hashtable]$Verdict
    )

    $findings = @()

    # Build findings based on verdict reasons
    foreach ($reason in $Verdict.Reasons) {
        $finding = switch ($reason) {
            "NO_ADAPTER" {
                @{
                    Id = "NO_ADAPTER"
                    Title = "No Bluetooth Adapter"
                    Result = "FAIL"
                    AppliesTo = "Hardware"
                    Evidence = @("No Bluetooth radio detected on this system")
                    ActionHint = "Verify Bluetooth hardware is installed or enable in BIOS"
                }
            }
            "ADAPTER_DISABLED" {
                @{
                    Id = "ADAPTER_DISABLED"
                    Title = "Bluetooth Adapter Disabled"
                    Result = "FAIL"
                    AppliesTo = "Hardware"
                    Evidence = @("Bluetooth adapter status: $($Diagnostics.Adapter.Status)")
                    ActionHint = "Enable Bluetooth in Windows Settings or Device Manager"
                }
            }
            "AUDIO_SERVICE_DEAD" {
                @{
                    Id = "AUDIO_SERVICE_DEAD"
                    Title = "Windows Audio Service Stopped"
                    Result = "FAIL"
                    AppliesTo = "Audio"
                    Evidence = @("Audiosrv service is not running")
                    ActionHint = "Restart Windows Audio service"
                }
            }
            "PASSTHROUGH_BT_CONFLICT" {
                @{
                    Id = "PASSTHROUGH_BT_CONFLICT"
                    Title = "Passthrough Incompatible with Bluetooth"
                    Result = "FAIL"
                    AppliesTo = "Kodi Audio"
                    Evidence = @("Kodi passthrough enabled", "Bluetooth device selected", "Bitstream audio requires digital connection")
                    ActionHint = "Disable Kodi passthrough or switch to wired audio output"
                }
            }
            "HFP_ACTIVE" {
                $hfpDevice = $Diagnostics.PairedDevices | Where-Object { $_.IsHFP -and $_.IsConnected } | Select-Object -First 1
                @{
                    Id = "HFP_ACTIVE"
                    Title = "Hands-Free Profile Active"
                    Result = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @("Device: $($hfpDevice.Name)", "HFP provides mono 8kHz audio", "Stereo A2DP profile preferred")
                    ActionHint = "Switch to Stereo output in Windows Sound settings"
                }
            }
            "DEFAULT_IS_HFP" {
                @{
                    Id = "DEFAULT_IS_HFP"
                    Title = "Default Playback is Hands-Free"
                    Result = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @("Default device: $($Diagnostics.DefaultPlayback.RegistryDevice)", "HFP mode has reduced audio quality")
                    ActionHint = "Set Stereo variant as default in Sound settings"
                }
            }
            "WASAPI_BT_RISK" {
                @{
                    Id = "WASAPI_BT_RISK"
                    Title = "WASAPI Mode with Bluetooth"
                    Result = "WARN"
                    AppliesTo = "Stability"
                    Evidence = @("Kodi using WASAPI output", "Bluetooth device active", "Exclusive mode may cause audio dropouts")
                    ActionHint = "Change Kodi to DirectSound: Default output"
                }
            }
            "FREQUENT_DISCONNECTS" {
                @{
                    Id = "FREQUENT_DISCONNECTS"
                    Title = "Frequent Bluetooth Disconnects"
                    Result = "WARN"
                    AppliesTo = "Stability"
                    Evidence = @("$($Diagnostics.EventLogHints.DisconnectEvents) disconnect events in last 60 min", "May indicate interference or driver issues")
                    ActionHint = "Move closer to source or update Bluetooth driver"
                }
            }
            "GHOST_ENDPOINTS" {
                $ghostCount = ($Diagnostics.PairedDevices | Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' }).Count
                @{
                    Id = "GHOST_ENDPOINTS"
                    Title = "Stale Audio Endpoints"
                    Result = "WARN"
                    AppliesTo = "Device Routing"
                    Evidence = @("$ghostCount disconnected Bluetooth audio endpoint(s)", "May cause routing confusion")
                    ActionHint = "Use 'Remove Stale BT Audio Endpoints' to clean up"
                }
            }
            "BTHSERV_STOPPED" {
                @{
                    Id = "BTHSERV_STOPPED"
                    Title = "Bluetooth Service Stopped"
                    Result = "WARN"
                    AppliesTo = "Connectivity"
                    Evidence = @("Bluetooth Support Service (bthserv) not running")
                    ActionHint = "Use 'Restart Bluetooth + Audio Services' button"
                }
            }
            "BTAG_STOPPED" {
                @{
                    Id = "BTAG_STOPPED"
                    Title = "Bluetooth Audio Gateway Stopped"
                    Result = "WARN"
                    AppliesTo = "Audio Routing"
                    Evidence = @("BTAGService not running", "May affect audio device discovery")
                    ActionHint = "Use 'Restart Bluetooth + Audio Services' button"
                }
            }
            "EVENT_LOG_ERRORS" {
                @{
                    Id = "EVENT_LOG_ERRORS"
                    Title = "Bluetooth Errors in Event Log"
                    Result = "WARN"
                    AppliesTo = "Diagnostics"
                    Evidence = @("$($Diagnostics.EventLogHints.Count) relevant events in last 60 min", "Check Advanced Details for specifics")
                    ActionHint = $null
                }
            }
            # === P0/P1/P2 Warbling Diagnostics ===
            "SAMPLERATE_MISMATCH" {
                $sr = $Diagnostics.SampleRates
                @{
                    Id = "SAMPLERATE_MISMATCH"
                    Title = "Audio Sample Rate Mismatch"
                    Result = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @(
                        "Kodi: $($sr.KodiSampleRate) Hz",
                        "Windows: $($sr.WindowsSampleRate) Hz (DeviceFormat, best-effort)",
                        "Resampling artifacts likely"
                    )
                    ActionHint = "Set Windows playback device to $($sr.KodiSampleRate) Hz to match Kodi"
                }
            }
            "HFP_HIJACK_RISK" {
                @{
                    Id = "HFP_HIJACK_RISK"
                    Title = "Bluetooth Call Mode Likely Active"
                    Result = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @(
                        "Bluetooth mic endpoint present",
                        "HFP profile activation detected",
                        "Bluetooth call mode likely active (Hands-Free route)"
                    )
                    ActionHint = "Close other audio apps and reconnect the Bluetooth device"
                }
            }
            "BUFFER_UNDERRUN_RISK" {
                $bur = $Diagnostics.BufferUnderrunRisk
                @{
                    Id = "BUFFER_UNDERRUN_RISK"
                    Title = "Audio Buffer Underrun Risk"
                    Result = "WARN"
                    AppliesTo = "Stability"
                    Evidence = @(
                        "Bluetooth audio active",
                        "Kodi process quality: $($bur.KodiProcessQuality)",
                        "Power plan: $($bur.PowerPlan)"
                    )
                    ActionHint = "Switch Windows power plan to High Performance and retry"
                }
            }
            default { $null }
        }

        if ($finding) {
            $findings += $finding
        }
    }

    # Add Kodi mismatch findings if applicable
    $kodi = $Diagnostics.KodiSettings
    if ($kodi.Found -and -not $kodi.IsDefault -and $Diagnostics.DefaultPlayback.RegistryDevice) {
        # Check if Kodi device differs from Windows default
        $kodiDeviceName = $kodi.AudioDevice -replace "^(WASAPI:|DirectSound:)", ""
        $winDefault = $Diagnostics.DefaultPlayback.RegistryDevice
        if ($kodiDeviceName -and $winDefault -and $kodiDeviceName -notmatch [regex]::Escape($winDefault)) {
            $findings += @{
                Id = "AUDIO_SINK_MISMATCH"
                Title = "Kodi Output Differs from Windows Default"
                Result = "WARN"
                AppliesTo = "Device Routing"
                Evidence = @("Kodi: $kodiDeviceName", "Windows: $winDefault", "Audio may play on unexpected device")
                ActionHint = "Set Kodi output to 'Default' or match Windows setting"
            }
        }
    }

    # Return max 3 findings, prioritized by severity
    $severityOrder = @{ "FAIL" = 0; "WARN" = 1; "INFO" = 2 }
    return $findings | Sort-Object { $severityOrder[$_.Severity] } | Select-Object -First 3
}

function Invoke-BluetoothProbe {
    <#
    .SYNOPSIS
        30-second active probe to detect Bluetooth audio stability issues.
    .DESCRIPTION
        Plays a bundled 1s silent WAV in a loop while monitoring for device
        changes, re-enumerations, and disconnect events.

        Implements DIAG-EXEC-001 P0 guards:
        - Single-flight enforcement (rejects if probe already running)
        - Timeout watchdog (hard timeout = duration + grace period)
        - Cancellation support (check Stop-BluetoothProbe)
    .PARAMETER DurationSeconds
        Duration of the probe in seconds (default 30).
    .OUTPUTS
        Hashtable with Result, TerminalState, Confidence, Events, and metrics.
        TerminalState is exactly one of: ProbeCompleted, ProbeFailed, ProbeCancelled, ProbeTimedOut, ProbeRejected
    #>
    [CmdletBinding()]
    param(
        [int]$DurationSeconds = 30
    )

    # === P0: Single-flight enforcement (F1: atomic CompareExchange) ===
    # Acquire the flag atomically; if it was already 1, another probe is running
    # and we reject this call without ever entering the body. Two concurrent
    # callers can no longer both pass the gate.
    if ([System.Threading.Interlocked]::CompareExchange([ref]$script:ProbeInProgress, 1, 0) -ne 0) {
        return @{
            Result = "REJECTED"
            TerminalState = "ProbeRejected"
            Confidence = "High"
            Reason = "PROBE_ALREADY_RUNNING"
            StartTime = Get-Date
            EndTime = Get-Date
            Events = @()
            DeviceChanges = 0
            Disconnects = 0
            Completed = $false
            Error = "Another probe is already in progress"
        }
    }

    $probeResult = @{
        Result = "PASS"
        TerminalState = $null  # Must be set before return
        Confidence = "Med"
        StartTime = Get-Date
        EndTime = $null
        Events = @()
        DeviceChanges = 0
        Disconnects = 0
        Completed = $false
        Error = $null
        TimedOut = $false
        Cancelled = $false
        UnknownEventKeys = @()  # F2 + B-refinement: surface unknown "Provider/Id" tuples
    }

    # Find silent WAV - check assets folder relative to module
    $moduleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $silentWavPath = Join-Path $moduleRoot "assets\silence-1s.wav"

    if (-not (Test-Path $silentWavPath)) {
        # F1: release the single-flight flag we just acquired — otherwise the
        # next probe call rejects forever until module reload.
        [System.Threading.Interlocked]::Exchange([ref]$script:ProbeInProgress, 0) | Out-Null
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeFailed"
        $probeResult.Error = "Silent WAV file not found: $silentWavPath"
        $probeResult.Confidence = "Low"
        $probeResult.EndTime = Get-Date
        return $probeResult
    }

    # === P0: Reset cancellation flag (acquire already happened above) ===
    $script:ProbeCancellationRequested = $false

    try {
        # Create Windows Media Player COM object
        $script:ProbeMediaPlayer = New-Object -ComObject WMPlayer.OCX.7

        # Baseline device state
        $baselineDevices = @(Get-BluetoothPairedAudioDevices)

        # B-refinement: enumerate enabled Bluetooth-* /Operational channels once
        # for the duration of the probe instead of hardcoding BthUSB (which
        # doesn't exist on modern Win11). Empty array is fine — the probe will
        # still detect device-list changes via WinRT enumeration.
        $probeBtChannels = @(Get-BluetoothOperationalLogNames)

        # Start playback
        $script:ProbeMediaPlayer.settings.autoStart = $true
        $script:ProbeMediaPlayer.settings.setMode("loop", $true)
        $script:ProbeMediaPlayer.URL = $silentWavPath

        # === P0: Calculate hard timeout (duration + grace period) ===
        $softEndTime = ($probeResult.StartTime).AddSeconds($DurationSeconds)
        $hardEndTime = ($probeResult.StartTime).AddSeconds($DurationSeconds + $script:ProbeHardTimeoutSeconds)
        $checkInterval = 2

        # Monitor loop
        while ((Get-Date) -lt $softEndTime) {
            Start-Sleep -Seconds $checkInterval

            # === P0: Check cancellation ===
            if ($script:ProbeCancellationRequested) {
                $probeResult.Cancelled = $true
                $probeResult.Events += @{
                    Time = Get-Date
                    Type = "CANCELLED"
                    Detail = "Probe cancelled by request"
                }
                break
            }

            # === P0: Check hard timeout (watchdog) ===
            if ((Get-Date) -gt $hardEndTime) {
                $probeResult.TimedOut = $true
                $probeResult.Events += @{
                    Time = Get-Date
                    Type = "TIMEOUT"
                    Detail = "Probe exceeded hard timeout of $($DurationSeconds + $script:ProbeHardTimeoutSeconds)s"
                }
                break
            }

            # Check for device changes
            $currentDevices = @(Get-BluetoothPairedAudioDevices)
            $deviceDiff = Compare-Object -ReferenceObject $baselineDevices -DifferenceObject $currentDevices -Property InstanceId -ErrorAction SilentlyContinue

            if ($deviceDiff) {
                $probeResult.DeviceChanges++
                $probeResult.Events += @{
                    Time = Get-Date
                    Type = "DEVICE_CHANGE"
                    Detail = "Bluetooth audio device list changed during playback"
                }
                $baselineDevices = $currentDevices
            }

            # Check for new BT events across every enabled BT-* operational channel.
            # F2 + B-refinement: classify by stable (Provider, Id) tuple
            # (locale-independent, channel-agnostic). Unknown keys are surfaced
            # in $probeResult.UnknownEventKeys so the classifier table can be
            # refined from field data — but they are NEVER counted as
            # disconnects just because their message text contains an English word.
            foreach ($channelName in $probeBtChannels) {
                try {
                    $newEvents = Get-WinEvent -LogName $channelName -MaxEvents 10 -ErrorAction SilentlyContinue |
                        Where-Object { $_.TimeCreated -gt $probeResult.StartTime }

                    foreach ($evt in $newEvents) {
                        $class = Get-BluetoothEventClass -Event $evt
                        if ($class -eq 'Disconnected') {
                            $probeResult.Disconnects++
                            $probeResult.Events += @{
                                Time = $evt.TimeCreated
                                Type = "DISCONNECT"
                                EventId = $evt.Id
                                ProviderName = $evt.ProviderName
                                Source = $channelName
                                Detail = ($evt.Message -split "`n")[0]
                            }
                        } elseif ($class -eq 'Unknown' -and $null -ne $evt.Id -and -not [string]::IsNullOrWhiteSpace($evt.ProviderName)) {
                            $key = "$($evt.ProviderName)/$($evt.Id)"
                            if ($probeResult.UnknownEventKeys -notcontains $key) {
                                $probeResult.UnknownEventKeys += $key
                            }
                        }
                    }
                }
                catch {
                    # Channel may not be accessible — continue with next
                }
            }
        }

        # Mark completed if we exited normally (not cancelled/timed out)
        if (-not $probeResult.Cancelled -and -not $probeResult.TimedOut) {
            $probeResult.Completed = $true
        }
    }
    catch {
        $probeResult.Error = $_.Exception.Message
        $probeResult.Events += @{
            Time = Get-Date
            Type = "ERROR"
            Detail = $_.Exception.Message
        }
    }
    finally {
        # === P0: Guaranteed cleanup ===
        if ($null -ne $script:ProbeMediaPlayer) {
            try {
                $script:ProbeMediaPlayer.controls.stop()
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($script:ProbeMediaPlayer) | Out-Null
            }
            catch {
                # Best effort cleanup - COM object may already be disposed
            }
            $script:ProbeMediaPlayer = $null
        }

        # === F1: Clear single-flight flag atomically ===
        [System.Threading.Interlocked]::Exchange([ref]$script:ProbeInProgress, 0) | Out-Null
    }

    $probeResult.EndTime = Get-Date

    # === Evaluate result and set terminal state ===
    # Terminal state must be exactly one of: ProbeCompleted, ProbeFailed, ProbeCancelled, ProbeTimedOut

    if ($probeResult.Cancelled) {
        $probeResult.Result = "CANCELLED"
        $probeResult.TerminalState = "ProbeCancelled"
        $probeResult.Confidence = "High"
    }
    elseif ($probeResult.TimedOut) {
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeTimedOut"
        $probeResult.Confidence = "Low"
    }
    elseif ($probeResult.Disconnects -gt 0) {
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeCompleted"
        $probeResult.Confidence = "High"
    }
    elseif ($probeResult.DeviceChanges -gt 1) {
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeCompleted"
        $probeResult.Confidence = "Med"
    }
    elseif ($probeResult.Error) {
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeFailed"
        $probeResult.Confidence = "Low"
    }
    elseif ($probeResult.Completed) {
        $probeResult.TerminalState = "ProbeCompleted"
        $probeResult.Confidence = "High"
    }
    else {
        # Defensive fallback - should never reach here
        $probeResult.TerminalState = "ProbeFailed"
        $probeResult.Confidence = "Low"
    }

    return $probeResult
}

function Stop-BluetoothProbe {
    <#
    .SYNOPSIS
        Requests cancellation of a running Bluetooth probe.
    .DESCRIPTION
        Sets the cancellation flag that the probe monitors. The probe will
        exit cleanly on its next check interval (within ~2 seconds).

        Implements DIAG-EXEC-001 P0 cancellation semantics.
    .OUTPUTS
        Hashtable with Success and Message.
    #>
    [CmdletBinding()]
    param()

    # F1: ProbeInProgress is now an integer (0/1); compare explicitly.
    if ($script:ProbeInProgress -eq 0) {
        return @{
            Success = $false
            Message = "No probe is currently running"
        }
    }

    $script:ProbeCancellationRequested = $true

    # Also attempt to stop media player immediately
    if ($null -ne $script:ProbeMediaPlayer) {
        try {
            $script:ProbeMediaPlayer.controls.stop()
        }
        catch {
            # Best effort - probe loop will handle cleanup
        }
    }

    return @{
        Success = $true
        Message = "Cancellation requested; probe will stop within 2 seconds"
    }
}

function Test-BluetoothProbeInProgress {
    <#
    .SYNOPSIS
        Returns whether a Bluetooth probe is currently running.
    .DESCRIPTION
        Use this to check probe state before attempting operations that
        conflict with the probe (per DIAG-EXEC-001 cross-diagnostic guard).
    .OUTPUTS
        Boolean indicating if probe is in progress.
    #>
    [CmdletBinding()]
    param()

    # F1: underlying flag is now an integer for atomic CompareExchange.
    # Preserve the boolean output contract for existing callers.
    return ($script:ProbeInProgress -ne 0)
}

function Get-ServiceResetOutcome {
    <#
    .SYNOPSIS
        Pure classifier for service reset results. F6 helper.
    .DESCRIPTION
        Given the post-restart state of each touched service plus the list of
        required services, returns the terminal-state classification used by
        Invoke-BluetoothServiceReset. Extracted so the success/partial/failed
        decision is unit-testable without bypassing the execution-intent guard
        or invoking Start-Service in the test harness.
    .PARAMETER ServiceStatuses
        Hashtable mapping service name -> final status string
        (e.g. 'Running', 'Stopped', 'Error', 'NotFound').
    .PARAMETER RequiredServices
        Service names that must end up Running for the reset to be "Completed".
        A required service in 'NotFound' state is treated as benign (the service
        simply doesn't exist on this Windows build); any other non-Running
        terminal status counts as failure.
    .OUTPUTS
        [pscustomobject] with TerminalState, Success, ServicesRestarted,
        ServicesFailed, RequiredServicesFailed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ServiceStatuses,

        [Parameter(Mandatory)]
        [string[]]$RequiredServices
    )

    $running = @()
    $failed = @()
    $reqFailed = @()

    foreach ($name in $ServiceStatuses.Keys) {
        if ([string]$ServiceStatuses[$name] -eq 'Running') {
            $running += $name
        } elseif ([string]$ServiceStatuses[$name] -ne 'NotFound') {
            $failed += $name
        }
    }

    foreach ($req in $RequiredServices) {
        if (-not $ServiceStatuses.ContainsKey($req)) {
            # Required service wasn't even attempted -> treat as failure.
            $reqFailed += $req
            continue
        }
        $status = [string]$ServiceStatuses[$req]
        if ($status -eq 'NotFound') { continue }  # benign on this build
        if ($status -ne 'Running') {
            $reqFailed += $req
        }
    }

    $anyRestarted = $running.Count -gt 0
    $requiredFailed = $reqFailed.Count -gt 0

    $terminal = if (-not $requiredFailed -and $anyRestarted) {
        'ResetCompleted'
    } elseif ($requiredFailed -and $anyRestarted) {
        'ResetPartial'
    } else {
        'ResetFailed'
    }

    return [pscustomobject]@{
        TerminalState          = $terminal
        Success                = ($terminal -eq 'ResetCompleted')
        ServicesRestarted      = $running
        ServicesFailed         = $failed
        RequiredServicesFailed = $reqFailed
    }
}

function Invoke-BluetoothServiceReset {
    <#
    .SYNOPSIS
        Restarts Bluetooth and audio services (requires admin).
    .DESCRIPTION
        Stops and restarts bthserv, BTAGService, Audiosrv, and AudioEndpointBuilder.
        This is a Tier 1 safe reset with minimal disruption.

        Implements DIAG-EXEC-001 P1 guards:
        - Cross-diagnostic guard (blocked during probe)
        - Terminal state logging
    .OUTPUTS
        Hashtable with Success, TerminalState, Message, Details, and ServicesRestarted.
        TerminalState is one of: ResetCompleted, ResetPartial, ResetFailed, ResetRejected
    #>
    [CmdletBinding()]
    param()

    # === P0: Execution intent guard (MUST be first) ===
    try {
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
    } catch {
        return @{
            Success = $false
            Blocked = $true
            Reason = 'ExecutionIntent'
            TerminalState = "ResetRejected"
            Message = $_.Exception.Message
        }
    }

    # === P0: Dry-run mode (only after intent is valid) ===
    if (Test-IsDryRunMode) {
        Write-Warning "[DRY-RUN] Invoke-BluetoothServiceReset would execute"
        return New-DryRunRefusal `
            -ToolId "bluetooth-service-restart" `
            -ToolName "Invoke-BluetoothServiceReset" `
            -FailureCode "LEGACY_DRYRUN_ADAPTER" `
            -FailureReason "Legacy tool does not support structured Dry Run yet. Use the UI Dry Run button for plan-based execution."
    }

    $result = @{
        Success = $false
        TerminalState = $null  # Must be set before return
        Message = ""
        Details = @()
        ServicesRestarted = @()       # service names that ended up Running
        ServicesFailed = @()          # service names that did NOT end up Running
        RequiredServicesFailed = @()  # subset of ServicesFailed that are mandatory
        ServiceStatuses = @{}         # per-service final status (string)
        RequiresAdmin = $true
    }

    # === P1: Cross-diagnostic guard ===
    if ($script:ProbeInProgress -ne 0) {
        $result.TerminalState = "ResetRejected"
        $result.Message = "Reset blocked: Bluetooth probe is currently running"
        $result.Details += "Use Stop-BluetoothProbe to cancel the probe first"
        return $result
    }

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.TerminalState = "ResetFailed"
        $result.Message = "This operation requires administrator privileges"
        return $result
    }

    # F6: classify services. The bthserv stack is what "Bluetooth reset" must
    # actually restart for the tool's promise to hold. Audio services are
    # tracked for diagnostic completeness but are not required for the Bluetooth
    # support layer per se — they're optional in this context.
    # AudioEndpointBuilder is required only when this function is later extended
    # to claim audio-path repair; currently kept optional to match historical
    # call-site contracts (the audio-service-restart tool covers that path).
    $requiredServices = @("bthserv")
    $optionalServices = @("BTAGService", "Audiosrv", "AudioEndpointBuilder")

    $servicesToRestart = $requiredServices + $optionalServices

    # Also find per-user Bluetooth services (multiple may exist under RDP / Fast User Switching)
    $btUserSvcs = @(Get-Service -Name "BluetoothUserService_*" -ErrorAction SilentlyContinue)
    foreach ($u in $btUserSvcs) {
        if ($servicesToRestart -notcontains $u.Name) {
            $servicesToRestart += $u.Name
            # Per-user BT service is part of the BT support stack: treat as required-when-present.
            $requiredServices += $u.Name
        }
    }

    $waitTimeout = [TimeSpan]::FromSeconds(10)

    foreach ($svcName in $servicesToRestart) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) {
                $result.Details += "Service '$svcName' not found - skipped"
                $result.ServiceStatuses[$svcName] = 'NotFound'
                continue
            }

            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
            }

            Start-Service -Name $svcName -ErrorAction Stop

            # F6: verify the service actually reached Running, not just that the
            # Start command returned. WaitForStatus throws on timeout, which we catch.
            try {
                $svc.WaitForStatus('Running', $waitTimeout)
            } catch {
                # Fall through; the final status query below will record the truth.
            }

            $final = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            $finalStatus = if ($final) { [string]$final.Status } else { 'Unknown' }
            $result.ServiceStatuses[$svcName] = $finalStatus

            if ($finalStatus -eq 'Running') {
                $result.ServicesRestarted += $svcName
                $result.Details += "Restarted: $svcName"
            } else {
                $result.ServicesFailed += $svcName
                $result.Details += "Did not reach Running for '$svcName' (final status: $finalStatus)"
            }
        }
        catch {
            $result.ServicesFailed += $svcName
            $result.ServiceStatuses[$svcName] = 'Error'
            $result.Details += "Failed to restart '$svcName': $($_.Exception.Message)"
        }
    }

    # F6: defer classification to the pure helper so the decision logic is
    # unit-testable without bypassing the execution-intent guard.
    $outcome = Get-ServiceResetOutcome -ServiceStatuses $result.ServiceStatuses -RequiredServices $requiredServices
    $result.Success = $outcome.Success
    $result.TerminalState = $outcome.TerminalState
    $result.RequiredServicesFailed = @($outcome.RequiredServicesFailed)

    $anyRestarted = $result.ServicesRestarted.Count -gt 0
    $result.Message = switch ($outcome.TerminalState) {
        'ResetCompleted' { "Restarted $($result.ServicesRestarted.Count) service(s)" }
        'ResetPartial'   { "Partial: required service(s) failed: $($outcome.RequiredServicesFailed -join ', ')" }
        default          {
            if ($outcome.RequiredServicesFailed.Count -gt 0) {
                "Required service(s) failed: $($outcome.RequiredServicesFailed -join ', ')"
            } else {
                "Failed to restart any services"
            }
        }
    }

    # F7: invalidate diagnostics cache when state actually changed.
    if ($anyRestarted) {
        Clear-BluetoothDiagnosticsCache
    }

    return $result
}

function Invoke-BluetoothEndpointCleanup {
    <#
    .SYNOPSIS
        Removes stale/disconnected Bluetooth audio endpoints (requires admin).
    .DESCRIPTION
        Only removes endpoints that are:
        - Status != OK (disconnected/error)
        - Appear to be Bluetooth (InstanceId contains BTHENUM/BTH or name matches BT patterns)
        - NOT the current default playback device
        This is a Tier 2 operation that may require device re-pairing.

        Implements DIAG-EXEC-001 P1 guards:
        - Cross-diagnostic guard (blocked during probe)
        - Terminal state logging
    .OUTPUTS
        Hashtable with Success, TerminalState, Message, Details, and RemovedDevices.
        TerminalState is one of: CleanupCompleted, CleanupFailed, CleanupRejected
    #>
    [CmdletBinding()]
    param()

    # === P0: Execution intent guard (MUST be first) ===
    try {
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
    } catch {
        return @{
            Success = $false
            Blocked = $true
            Reason = 'ExecutionIntent'
            TerminalState = "CleanupRejected"
            Message = $_.Exception.Message
        }
    }

    # === P0: Dry-run mode (only after intent is valid) ===
    if (Test-IsDryRunMode) {
        Write-Warning "[DRY-RUN] Invoke-BluetoothEndpointCleanup would execute"
        return New-DryRunRefusal `
            -ToolId "bluetooth-diagnostics" `
            -ToolName "Invoke-BluetoothEndpointCleanup" `
            -FailureCode "LEGACY_DRYRUN_ADAPTER" `
            -FailureReason "Legacy tool does not support structured Dry Run yet. Use the UI Dry Run button for plan-based execution."
    }

    $result = @{
        Success = $false
        TerminalState = $null  # Must be set before return
        Message = ""
        Details = @()
        RemovedDevices = @()
        SkippedDevices = @()
        RequiresAdmin = $true
    }

    # === P1: Cross-diagnostic guard ===
    if ($script:ProbeInProgress -ne 0) {
        $result.TerminalState = "CleanupRejected"
        $result.Message = "Cleanup blocked: Bluetooth probe is currently running"
        $result.Details += "Use Stop-BluetoothProbe to cancel the probe first"
        return $result
    }

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.TerminalState = "CleanupFailed"
        $result.Message = "This operation requires administrator privileges"
        return $result
    }

    # Get current default playback device name (best-effort) for protection
    $defaultPlaybackName = $null
    try {
        $regPath = "HKCU:\Software\Microsoft\Multimedia\Sound Mapper"
        if (Test-Path $regPath) {
            $defaultPlaybackName = (Get-ItemProperty -Path $regPath -Name "Playback" -ErrorAction SilentlyContinue).Playback
        }
    }
    catch {
        # Silent fail - continue without this protection
    }

    # Also get all currently connected (Status=OK) endpoints to protect them
    $connectedEndpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'OK' } |
        ForEach-Object { $_.InstanceId }

    # F3: Anchor to BTHENUM transport ONLY. FriendlyName-based selection is unsafe
    # (matches USB headsets, dock devices, anything with 'BT' in its name).
    # F3: Status restricted to Error/Unknown — never Status='OK' (connected) and
    # never the broad set of transient PnP statuses caught by `-ne 'OK'`.
    $staleEndpoints = @(Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-BluetoothTransportInstanceId -InstanceId $_.InstanceId) -and
            ($_.Status -in @('Error', 'Unknown'))
        })

    # Add stillFailed tracker for F4 post-removal verification
    $result.StillPresentDevices = @()

    if (-not $staleEndpoints -or $staleEndpoints.Count -eq 0) {
        $result.Success = $true
        $result.TerminalState = "CleanupCompleted"
        $result.Message = "No stale Bluetooth audio endpoints found"
        # F7: nothing was changed; do NOT invalidate cache.
        return $result
    }

    foreach ($endpoint in $staleEndpoints) {
        # Safety check 1: Never remove if name matches default playback (best-effort overlap guard)
        if ($defaultPlaybackName -and $endpoint.FriendlyName -and $endpoint.FriendlyName -match [regex]::Escape($defaultPlaybackName)) {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (matches default): $($endpoint.FriendlyName)"
            continue
        }

        # Safety check 2: Defensive — re-confirm status hasn't flipped to OK during the loop
        if ($endpoint.Status -eq 'OK') {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (connected): $($endpoint.FriendlyName)"
            continue
        }

        # Safety check 3: Never remove if InstanceId is in connected list (race window guard)
        if ($connectedEndpoints -contains $endpoint.InstanceId) {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (active): $($endpoint.FriendlyName)"
            continue
        }

        try {
            $result.Details += "Removing: $($endpoint.FriendlyName) [InstanceId: $($endpoint.InstanceId), Status: $($endpoint.Status)]"

            # F4: capture exit code and re-query to confirm actual removal.
            $removal = Invoke-PnpDeviceRemovalWithVerification -InstanceId $endpoint.InstanceId -Class 'AudioEndpoint'

            switch ($removal.Status) {
                'Removed' {
                    $result.RemovedDevices += $endpoint.FriendlyName
                    $result.Details += "Removed: $($endpoint.FriendlyName) (exit=$($removal.ExitCode))"
                }
                'StillPresent' {
                    $result.StillPresentDevices += $endpoint.FriendlyName
                    $result.Details += "Removal command reported success but device is still present: $($endpoint.FriendlyName) (exit=$($removal.ExitCode))"
                }
                default {
                    $result.Details += "Failed to remove '$($endpoint.FriendlyName)' (exit=$($removal.ExitCode)): $($removal.Output)"
                }
            }
        }
        catch {
            $result.Details += "Failed to remove '$($endpoint.FriendlyName)': $($_.Exception.Message)"
        }
    }

    # F4: success is "we actually removed at least one device". Skipped-only and
    # still-present-only outcomes are not successes; the user clicked Cleanup to
    # change state, not to be told the state is unchanged.
    $actuallyRemoved = $result.RemovedDevices.Count -gt 0
    $result.Success = $actuallyRemoved
    $result.Message = if ($actuallyRemoved) {
        $msg = "Removed $($result.RemovedDevices.Count) stale endpoint(s)"
        if ($result.StillPresentDevices.Count -gt 0) {
            $msg += "; $($result.StillPresentDevices.Count) still present"
        }
        $msg
    } elseif ($result.StillPresentDevices.Count -gt 0) {
        "Removal commands returned but device(s) still present - try again or reboot"
    } elseif ($result.SkippedDevices.Count -gt 0) {
        "All endpoints skipped (protected or active)"
    } else {
        "No endpoints removed"
    }

    # === P1: Set terminal state ===
    $result.TerminalState = if ($actuallyRemoved) { "CleanupCompleted" } else { "CleanupFailed" }

    # F7: invalidate the diagnostics cache only when we actually changed state.
    if ($actuallyRemoved) {
        Clear-BluetoothDiagnosticsCache
    }

    return $result
}

function Invoke-BluetoothAdapterReset {
    <#
    .SYNOPSIS
        Resets the Bluetooth adapter by disabling and re-enabling it (requires admin).
    .DESCRIPTION
        This is a Tier 3 operation that may require a reboot and will disconnect
        all paired devices. Use as a last resort.

        Implements DIAG-EXEC-001 P1 guards:
        - Cross-diagnostic guard (blocked during probe)
        - Terminal state logging
    .OUTPUTS
        Hashtable with Success, TerminalState, Message, Details, and RebootRequired.
        TerminalState is one of: ResetCompleted, ResetFailed, ResetRejected
    #>
    [CmdletBinding()]
    param()

    # === P0: Execution intent guard (MUST be first) ===
    try {
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
    } catch {
        return @{
            Success = $false
            Blocked = $true
            Reason = 'ExecutionIntent'
            TerminalState = "ResetRejected"
            Message = $_.Exception.Message
        }
    }

    # === P0: Dry-run mode (only after intent is valid) ===
    if (Test-IsDryRunMode) {
        Write-Warning "[DRY-RUN] Invoke-BluetoothAdapterReset would execute"
        return New-DryRunRefusal `
            -ToolId "bluetooth-driver-reinstall" `
            -ToolName "Invoke-BluetoothAdapterReset" `
            -FailureCode "LEGACY_DRYRUN_ADAPTER" `
            -FailureReason "Legacy tool does not support structured Dry Run yet. Use the UI Dry Run button for plan-based execution."
    }

    $result = @{
        Success = $false
        TerminalState = $null  # Must be set before return
        Message = ""
        Details = @()
        RebootRequired = $false
        RequiresAdmin = $true
    }

    # === P1: Cross-diagnostic guard ===
    if ($script:ProbeInProgress -ne 0) {
        $result.TerminalState = "ResetRejected"
        $result.Message = "Reset blocked: Bluetooth probe is currently running"
        $result.Details += "Use Stop-BluetoothProbe to cancel the probe first"
        return $result
    }

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.TerminalState = "ResetFailed"
        $result.Message = "This operation requires administrator privileges"
        return $result
    }

    try {
        # Find the primary Bluetooth adapter (exclude transport nodes)
        $btAdapter = Get-PnpDevice -Class Bluetooth -ErrorAction Stop |
            Where-Object {
                $_.Status -eq 'OK' -and
                -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName) -and
                $_.FriendlyName -notmatch "Enumerator|LE$"
            } |
            Select-Object -First 1

        if (-not $btAdapter) {
            # Fallback: any OK Bluetooth device that isn't a transport node
            $btAdapter = Get-PnpDevice -Class Bluetooth -ErrorAction Stop |
                Where-Object {
                    $_.Status -eq 'OK' -and
                    -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName)
                } |
                Select-Object -First 1
        }

        if (-not $btAdapter) {
            $result.TerminalState = "ResetFailed"
            $result.Message = "No active Bluetooth adapter found to reset"
            return $result
        }

        $result.Details += "Target adapter: $($btAdapter.FriendlyName)"
        $result.Details += "InstanceId: $($btAdapter.InstanceId)"

        # Disable adapter
        Disable-PnpDevice -InstanceId $btAdapter.InstanceId -Confirm:$false -ErrorAction Stop
        $result.Details += "Adapter disabled at $(Get-Date -Format 'HH:mm:ss')"

        Start-Sleep -Seconds 2

        # Re-enable adapter
        Enable-PnpDevice -InstanceId $btAdapter.InstanceId -Confirm:$false -ErrorAction Stop
        $result.Details += "Adapter re-enabled"

        Start-Sleep -Seconds 1

        # Check if adapter came back
        $adapterCheck = Get-PnpDevice -InstanceId $btAdapter.InstanceId -ErrorAction SilentlyContinue
        if ($adapterCheck.Status -eq 'OK') {
            $result.Success = $true
            $result.TerminalState = "ResetCompleted"
            $result.Message = "Bluetooth adapter reset successfully"
        }
        else {
            $result.Success = $true
            $result.TerminalState = "ResetCompleted"
            $result.RebootRequired = $true
            $result.Message = "Adapter reset completed but may require reboot"
            $result.Details += "Adapter status after reset: $($adapterCheck.Status)"
        }

        # F7: PnP device state actually changed; invalidate the cache.
        Clear-BluetoothDiagnosticsCache
    }
    catch {
        $result.TerminalState = "ResetFailed"
        $result.Message = "Failed to reset adapter: $($_.Exception.Message)"
        $result.Details += $_.Exception.Message
        $result.RebootRequired = $true
        # F7: Disable may have succeeded before Enable failed — assume state changed.
        Clear-BluetoothDiagnosticsCache
    }

    return $result
}

function Invoke-BluetoothAudioDeviceDisable {
    <#
    .SYNOPSIS
        Disables a specific Bluetooth audio device (requires admin).
    .DESCRIPTION
        Disables a Bluetooth audio device using Disable-PnpDevice.
        Implements safety guards:
        - Blocked if device is current default playback
        - Blocked if probe is running (cross-diagnostic guard)
        - Requires admin privileges
    .PARAMETER InstanceId
        The PnP InstanceId of the device to disable.
    .PARAMETER Name
        The friendly name of the device (for logging).
    .PARAMETER IsDefaultPlayback
        If true, the operation will be blocked to prevent disabling the active playback device.
    .OUTPUTS
        Hashtable with Success, TerminalState, Message, Details, and Target.
        TerminalState is one of: DisableCompleted, DisableFailed, DisableBlocked, ActionRejected
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [Nullable[bool]]$IsDefaultPlayback
    )

    # === P0: Execution intent guard (MUST be first) ===
    try {
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
    } catch {
        return @{
            Success = $false
            Blocked = $true
            Reason = 'ExecutionIntent'
            TerminalState = "ActionRejected"
            Message = $_.Exception.Message
        }
    }

    # === P0: Dry-run mode (only after intent is valid) ===
    if (Test-IsDryRunMode) {
        Write-Warning "[DRY-RUN] Invoke-BluetoothAudioDeviceDisable would execute on '$Name'"
        return New-DryRunRefusal `
            -ToolId "bluetooth-diagnostics" `
            -ToolName "Invoke-BluetoothAudioDeviceDisable" `
            -FailureCode "LEGACY_DRYRUN_ADAPTER" `
            -FailureReason "Legacy tool does not support structured Dry Run yet. Use the UI Dry Run button for plan-based execution."
    }

    $result = @{
        Success = $false
        TerminalState = $null
        Message = ""
        Details = @()
        Target = @{
            Name = $Name
            InstanceId = $InstanceId
        }
        RequiresAdmin = $true
    }

    # === Cross-diagnostic guard ===
    if ($script:ProbeInProgress -ne 0) {
        $result.TerminalState = "ActionRejected"
        $result.Message = "Action blocked: Bluetooth probe is currently running"
        $result.Details += "Stop the probe before changing device state"
        return $result
    }

    # === Default playback guard ===
    if ($IsDefaultPlayback -eq $true) {
        $result.TerminalState = "DisableBlocked"
        $result.Message = "Disable blocked: device is current default playback"
        $result.Details += "Cannot disable the active playback device"
        $result.Details += "Change the default playback device first"
        return $result
    }

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.TerminalState = "DisableFailed"
        $result.Message = "This operation requires administrator privileges"
        return $result
    }

    try {
        $result.Details += "Disabling device: $Name"
        $result.Details += "InstanceId: $InstanceId"

        # Disable the device
        Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop
        $result.Details += "Disable-PnpDevice executed"

        # Verify device status
        Start-Sleep -Milliseconds 500
        $deviceCheck = Get-PnpDevice -InstanceId $InstanceId -ErrorAction SilentlyContinue

        if ($deviceCheck -and $deviceCheck.Status -ne 'OK') {
            $result.Success = $true
            $result.TerminalState = "DisableCompleted"
            $result.Message = "Device disabled successfully"
            $result.Details += "Device status after disable: $($deviceCheck.Status)"
        }
        else {
            $result.Success = $true
            $result.TerminalState = "DisableCompleted"
            $result.Message = "Disable command executed (verify in Device Manager)"
            $result.Details += "Device may require reconnection to reflect new state"
        }
        # F7: PnP state mutated; invalidate diagnostics cache.
        Clear-BluetoothDiagnosticsCache
    }
    catch {
        $result.TerminalState = "DisableFailed"
        $result.Message = "Failed to disable device: $($_.Exception.Message)"
        $result.Details += $_.Exception.Message
    }

    return $result
}

function Invoke-BluetoothAudioDeviceRemove {
    <#
    .SYNOPSIS
        Removes (unpairs) a Bluetooth audio device (requires admin).
    .DESCRIPTION
        Removes a Bluetooth audio device using Remove-PnpDevice or pnputil.
        This will unpair the device and may require re-pairing.
        Implements safety guards:
        - Blocked if probe is running (cross-diagnostic guard)
        - Requires admin privileges
        - UI should show confirmation dialog before calling this function
    .PARAMETER InstanceId
        The PnP InstanceId of the device to remove.
    .PARAMETER Name
        The friendly name of the device (for logging).
    .OUTPUTS
        Hashtable with Success, TerminalState, Message, Details, and Target.
        TerminalState is one of: RemoveCompleted, RemoveFailed, ActionRejected
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId,

        [Parameter()]
        [string]$Name
    )

    # === P0: Execution intent guard (MUST be first) ===
    try {
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
    } catch {
        return @{
            Success = $false
            Blocked = $true
            Reason = 'ExecutionIntent'
            TerminalState = "ActionRejected"
            Message = $_.Exception.Message
        }
    }

    # === P0: Dry-run mode (only after intent is valid) ===
    if (Test-IsDryRunMode) {
        Write-Warning "[DRY-RUN] Invoke-BluetoothAudioDeviceRemove would execute on '$Name'"
        return New-DryRunRefusal `
            -ToolId "bluetooth-diagnostics" `
            -ToolName "Invoke-BluetoothAudioDeviceRemove" `
            -FailureCode "LEGACY_DRYRUN_ADAPTER" `
            -FailureReason "Legacy tool does not support structured Dry Run yet. Use the UI Dry Run button for plan-based execution."
    }

    $result = @{
        Success = $false
        TerminalState = $null
        Message = ""
        Details = @()
        Target = @{
            Name = $Name
            InstanceId = $InstanceId
        }
        RequiresAdmin = $true
    }

    # === Cross-diagnostic guard ===
    if ($script:ProbeInProgress -ne 0) {
        $result.TerminalState = "ActionRejected"
        $result.Message = "Action blocked: Bluetooth probe is currently running"
        $result.Details += "Stop the probe before changing device state"
        return $result
    }

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.TerminalState = "RemoveFailed"
        $result.Message = "This operation requires administrator privileges"
        return $result
    }

    try {
        $result.Details += "Removing device: $Name"
        $result.Details += "InstanceId: $InstanceId"
        $result.Details += "Re-pairing may be required after removal"

        # Try Remove-PnpDevice first (preferred method)
        $removePnpAvailable = Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue

        if ($removePnpAvailable) {
            try {
                Remove-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop
                # F4: verify removal — Remove-PnpDevice can succeed-then-fail silently.
                $stillPresent = $null -ne (Get-PnpDevice -InstanceId $InstanceId -ErrorAction SilentlyContinue)
                if (-not $stillPresent) {
                    $result.Success = $true
                    $result.TerminalState = "RemoveCompleted"
                    $result.Message = "Device removed successfully"
                    $result.Details += "Remove-PnpDevice executed and verified"
                    # F7
                    Clear-BluetoothDiagnosticsCache
                    return $result
                }
                $result.Details += "Remove-PnpDevice returned but device is still present; trying pnputil"
            }
            catch {
                $result.Details += "Remove-PnpDevice failed: $($_.Exception.Message)"
                # Fall through to pnputil
            }
        }

        # Fallback to pnputil — use the verified-removal helper (F4).
        $removal = Invoke-PnpDeviceRemovalWithVerification -InstanceId $InstanceId

        switch ($removal.Status) {
            'Removed' {
                $result.Success = $true
                $result.TerminalState = "RemoveCompleted"
                $result.Message = "Device removed successfully"
                $result.Details += "pnputil /remove-device completed (exit=$($removal.ExitCode))"
                # F7
                Clear-BluetoothDiagnosticsCache
            }
            'StillPresent' {
                $result.TerminalState = "RemoveFailed"
                $result.Message = "Removal command returned but device is still present"
                $result.Details += "pnputil exit=$($removal.ExitCode); output: $($removal.Output)"
                $result.Details += "Try removing the device via Windows Bluetooth Settings instead"
            }
            default {
                $result.TerminalState = "RemoveFailed"
                $result.Message = "Device removal may not be supported on this system"
                $result.Details += "pnputil exit=$($removal.ExitCode); output: $($removal.Output)"
                $result.Details += "Try removing the device via Windows Bluetooth Settings instead"
            }
        }
    }
    catch {
        $result.TerminalState = "RemoveFailed"
        $result.Message = "Failed to remove device: $($_.Exception.Message)"
        $result.Details += $_.Exception.Message
    }

    return $result
}

#endregion

#region Bluetooth COM Port Detection

function Get-BluetoothCOMPorts {
    <#
    .SYNOPSIS
        Enumerates Bluetooth-associated COM ports, including ghost/orphaned entries.
    .DESCRIPTION
        Returns all COM ports where Enumerator = Bluetooth OR FriendlyName indicates
        Bluetooth serial (SPP) connection. This exposes "state accretion" - the
        accumulation of orphaned COM port registrations that degrade Bluetooth reliability.

        Ghost COM ports are non-present devices still registered in Windows, often
        causing pairing failures and connectivity issues.
    .OUTPUTS
        Array of objects with: COMPort, DeviceName, InstanceId, Status (Present/Ghost),
        Driver, AssociatedDevice, IsGhost
    #>
    [CmdletBinding()]
    param()

    $result = @{
        COMPorts = @()
        GhostCount = 0
        PresentCount = 0
        Error = $null
    }

    try {
        # Get all COM/LPT ports including non-present (ghost) devices
        # -PresentOnly:$false includes devices that are registered but not currently present
        $allPorts = @()

        # Method 1: Get-PnpDevice with Ports class
        try {
            # Present devices
            $presentPorts = Get-PnpDevice -Class Ports -Status OK -ErrorAction SilentlyContinue
            # All devices (including non-present) - requires different approach
            $allPortDevices = Get-PnpDevice -Class Ports -ErrorAction SilentlyContinue
            $allPorts += $allPortDevices
        } catch { }

        # Method 2: Query registry for additional ghost ports that PnpDevice might miss
        try {
            $serialCommKey = "HKLM:\SYSTEM\CurrentControlSet\Enum"
            $btEnumPath = Join-Path $serialCommKey "BTHENUM"
            if (Test-Path $btEnumPath) {
                $btDevices = Get-ChildItem -Path $btEnumPath -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -match "^\d+$" -or $_.GetValueNames() -contains "FriendlyName" }
            }
        } catch { }

        # Filter for Bluetooth-associated COM ports
        $btCOMPorts = @()

        foreach ($port in $allPorts) {
            $isBluetooth = $false
            $friendlyName = $port.FriendlyName
            $instanceId = $port.InstanceId

            # Check 1: Enumerator is Bluetooth (BTHENUM)
            if ($instanceId -match "^BTHENUM\\") {
                $isBluetooth = $true
            }

            # Check 2: FriendlyName indicates Bluetooth serial
            if ($friendlyName -match "Standard Serial over Bluetooth|Bluetooth Serial|SPP|Bluetooth.*COM") {
                $isBluetooth = $true
            }

            # Check 3: Instance ID contains Bluetooth-related GUID or pattern
            if ($instanceId -match "BTHENUM|RFCOMM|SerialPort") {
                $isBluetooth = $true
            }

            if (-not $isBluetooth) { continue }

            # Extract COM port number from FriendlyName (e.g., "Standard Serial over Bluetooth link (COM7)")
            $comNumber = $null
            if ($friendlyName -match '\((COM\d+)\)') {
                $comNumber = $Matches[1]
            } elseif ($friendlyName -match '(COM\d+)') {
                $comNumber = $Matches[1]
            }

            # Determine presence status
            $isPresent = $port.Status -eq 'OK'
            $isGhost = -not $isPresent

            # Try to resolve associated Bluetooth device name from InstanceId
            # BTHENUM format: BTHENUM\{guid}_LOCALMFG&xxxx\{address_stuff}
            $associatedDevice = $null
            if ($instanceId -match "BTHENUM\\.*\\([0-9A-Fa-f]{12})") {
                $btAddress = $Matches[1]
                # Format as XX:XX:XX:XX:XX:XX for display
                $formattedAddr = ($btAddress -replace '(.{2})', '$1:').TrimEnd(':')
                $associatedDevice = "BT: $formattedAddr"

                # Try to find the actual device name from paired devices
                try {
                    $pairedDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
                        Where-Object { $_.InstanceId -match $btAddress }
                    if ($pairedDevices) {
                        $associatedDevice = ($pairedDevices | Select-Object -First 1).FriendlyName
                    }
                } catch { }
            }

            # Get driver info
            $driverVersion = $null
            try {
                $driverInfo = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                    Where-Object { $_.DeviceID -eq $instanceId } |
                    Select-Object -First 1
                if ($driverInfo) {
                    $driverVersion = $driverInfo.DriverVersion
                }
            } catch { }

            # Clean device name for display
            $displayName = $friendlyName
            if ($displayName -match "^Standard Serial over Bluetooth link") {
                $displayName = if ($associatedDevice) { "$associatedDevice SPP" } else { "BT Serial Port" }
            }

            $btCOMPorts += [PSCustomObject]@{
                COMPort = $comNumber
                DeviceName = $displayName
                FriendlyName = $friendlyName
                InstanceId = $instanceId
                Status = if ($isPresent) { "Present" } else { "Ghost" }
                IsGhost = $isGhost
                IsPresent = $isPresent
                Driver = $driverVersion
                AssociatedDevice = $associatedDevice
                PnpStatus = $port.Status
            }

            if ($isGhost) {
                $result.GhostCount++
            } else {
                $result.PresentCount++
            }
        }

        # Sort: Present first, then by COM port number
        $result.COMPorts = $btCOMPorts | Sort-Object @{Expression={$_.IsGhost}}, @{Expression={
            if ($_.COMPort -match '\d+') { [int]($_.COMPort -replace '\D') } else { 999 }
        }}

    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Invoke-RevealHiddenBluetoothDevices {
    <#
    .SYNOPSIS
        Opens Device Manager with hidden (non-present) devices visible.
    .DESCRIPTION
        Sets DEVMGR_SHOW_NONPRESENT_DEVICES=1 and launches devmgmt.msc.
        This is a SAFE read-only action that reveals ghost devices for manual inspection.
        Does not modify or delete anything.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        Message = ""
        Details = @()
    }

    try {
        # Set environment variable to show non-present devices
        $env:DEVMGR_SHOW_NONPRESENT_DEVICES = "1"
        $result.Details += "Set DEVMGR_SHOW_NONPRESENT_DEVICES=1"

        # Launch Device Manager
        Start-Process "devmgmt.msc" -ErrorAction Stop
        $result.Details += "Launched Device Manager"

        $result.Success = $true
        $result.Message = "Device Manager opened with hidden devices visible. Look for grayed-out entries under 'Ports (COM & LPT)' and 'Bluetooth'."
        $result.Details += "To see ghost devices: View > Show hidden devices (if not already checked)"
        $result.Details += "Ghost devices appear grayed out"

    } catch {
        $result.Message = "Failed to open Device Manager: $($_.Exception.Message)"
        $result.Details += $_.Exception.Message
    }

    return $result
}

function Invoke-BluetoothGhostCOMCleanup {
    <#
    .SYNOPSIS
        Removes ghost (non-present) Bluetooth COM port registrations.
    .DESCRIPTION
        GUARDED DESTRUCTIVE ACTION - Removes orphaned Bluetooth serial device
        registrations that Windows retains after device removal.

        Preconditions enforced:
        - Admin privileges required
        - No active Bluetooth probe running
        - Only removes: Non-present devices, Bluetooth-enumerated, Serial/SPP class

        Never touches:
        - Present/active devices
        - USB CDC devices
        - Physical COM hardware
        - Non-Bluetooth serial ports
    .PARAMETER Force
        Skip confirmation prompt (still requires admin).
    .PARAMETER WhatIf
        Preview which devices would be removed without making changes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Force,
        [switch]$WhatIf
    )

    $result = @{
        Success = $false
        RemovedCount = 0
        SkippedCount = 0
        FailedCount = 0
        Message = ""
        Details = @()
        RemovedDevices = @()
        FailedDevices = @()
    }

    # Precondition 1: Admin check
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.Message = "This operation requires administrator privileges"
        $result.Details += "Run as Administrator to remove ghost COM ports"
        return $result
    }

    # Precondition 2: No active probe
    if ($script:ProbeInProgress -ne 0) {
        $result.Message = "Cannot remove devices while Bluetooth probe is running"
        $result.Details += "Wait for probe to complete or cancel it first"
        return $result
    }

    # Get Bluetooth COM ports
    $btPorts = Get-BluetoothCOMPorts

    if ($btPorts.Error) {
        $result.Message = "Failed to enumerate COM ports: $($btPorts.Error)"
        return $result
    }

    # Filter to only ghost/non-present devices
    $ghostPorts = $btPorts.COMPorts | Where-Object { $_.IsGhost -eq $true }

    if ($ghostPorts.Count -eq 0) {
        $result.Success = $true
        $result.Message = "No ghost Bluetooth COM ports found"
        return $result
    }

    $result.Details += "Found $($ghostPorts.Count) ghost Bluetooth COM port(s)"

    if ($WhatIf) {
        # Return canonical WinConfig.DryRunResult with structured plan steps
        $steps = @()
        foreach ($port in $ghostPorts) {
            $steps += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost COM port: $($port.COMPort)" -Detail $port.DeviceName).Summary
        }
        return [PSCustomObject]@{
            PSTypeName    = 'WinConfig.DryRunResult'
            OperationId   = $null
            ToolId        = 'bluetooth-diagnostics'
            Executed      = $false
            Outcome       = 'Skipped'
            FailureCode   = $null
            FailureReason = $null
            Summary       = "[DRY RUN] Would remove $($ghostPorts.Count) ghost COM port(s)"
            Plan          = @{ Steps = $steps; AffectedResources = @($ghostPorts | ForEach-Object { "COMPort:$($_.COMPort)" }) }
            SideEffects   = @()
        }
    }

    # Process each ghost device
    foreach ($port in $ghostPorts) {
        $deviceDesc = "$($port.COMPort) - $($port.DeviceName)"
        $result.Details += "Processing: $deviceDesc"

        # Safety: Verify it's still a ghost (not reconnected since enumeration)
        try {
            $currentStatus = Get-PnpDevice -InstanceId $port.InstanceId -ErrorAction SilentlyContinue
            if ($currentStatus -and $currentStatus.Status -eq 'OK') {
                $result.Details += "SKIPPED: $deviceDesc (device now present)"
                $result.SkippedCount++
                continue
            }
        } catch { }

        # Safety: Verify it's Bluetooth-enumerated
        if ($port.InstanceId -notmatch "^BTHENUM\\") {
            $result.Details += "SKIPPED: $deviceDesc (not BTHENUM)"
            $result.SkippedCount++
            continue
        }

        # Attempt removal
        try {
            # Try pnputil first (works best for ghost devices)
            $pnpResult = pnputil /remove-device $port.InstanceId 2>&1
            $pnpResultStr = $pnpResult -join "`n"

            if ($LASTEXITCODE -eq 0 -or $pnpResultStr -match "successfully|removed") {
                $result.Details += "REMOVED: $deviceDesc"
                $result.RemovedCount++
                $result.RemovedDevices += $deviceDesc
            } else {
                # Fallback to Remove-PnpDevice
                try {
                    Remove-PnpDevice -InstanceId $port.InstanceId -Confirm:$false -ErrorAction Stop
                    $result.Details += "REMOVED: $deviceDesc (via Remove-PnpDevice)"
                    $result.RemovedCount++
                    $result.RemovedDevices += $deviceDesc
                } catch {
                    $result.Details += "FAILED: $deviceDesc - $($_.Exception.Message)"
                    $result.FailedCount++
                    $result.FailedDevices += $deviceDesc
                }
            }
        } catch {
            $result.Details += "FAILED: $deviceDesc - $($_.Exception.Message)"
            $result.FailedCount++
            $result.FailedDevices += $deviceDesc
        }
    }

    # Summary
    if ($result.RemovedCount -gt 0) {
        $result.Success = $true
        $result.Message = "Removed $($result.RemovedCount) ghost COM port(s)"
        if ($result.FailedCount -gt 0) {
            $result.Message += " ($($result.FailedCount) failed)"
        }
        # F7: actual mutations occurred; invalidate diagnostics cache.
        Clear-BluetoothDiagnosticsCache
    } elseif ($result.SkippedCount -gt 0 -and $result.FailedCount -eq 0) {
        $result.Success = $true
        $result.Message = "No removable ghost COM ports (all skipped for safety)"
        # No mutation — skip cache invalidation.
    } else {
        $result.Message = "Failed to remove ghost COM ports"
    }

    return $result
}

#endregion

#region Flight Recorder Snapshots (read-only)
# These collectors are the building blocks for Bluetooth Flight Recorder session
# capture. They MUST NOT mutate state. On privileged-query failure they record
# the failure into the returned object instead of throwing — the Flight Recorder
# treats failures as evidence, not crashes.

function Get-BluetoothComPortPortName {
    <#
    .SYNOPSIS
        Extracts a COM port name (e.g. "COM3") from a Windows friendly name or
        device name string, or $null when no recognizable port token is present.
    .DESCRIPTION
        Used by Get-BluetoothComPortSnapshot AND by Find-TargetBluetoothComPort
        so the same parsing surface is reachable from tests without standing up
        a live PnP enumeration. Accepted shapes:
            "Standard Serial over Bluetooth link (COM3)"
            "Bluetooth Serial Port (COM12)"
            "COM7"            (bare token)
        Anything else returns $null.
    .OUTPUTS
        [string] like 'COM3' or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text -match '\((COM\d+)\)') { return $Matches[1].ToUpperInvariant() }
    if ($Text -match '(?<![A-Za-z0-9])(COM\d+)(?![A-Za-z0-9])') { return $Matches[1].ToUpperInvariant() }
    return $null
}

function Get-BluetoothComPortSnapshot {
    <#
    .SYNOPSIS
        Captures Bluetooth-associated serial/COM-port PnP entries as a structured
        snapshot. Read-only.
    .DESCRIPTION
        Enumerates the Windows "Ports" device class plus any PnP entry whose
        InstanceId or FriendlyName carries Bluetooth-serial markers (BTHENUM,
        RFCOMM, "Bluetooth Serial", "Standard Serial over Bluetooth"). The
        intent is to expose the RFCOMM/SPP COM-port surface LabVIEW expects:
        missing ports, ghost ports, and ports renumbered between baseline and
        final all show up here.

        Failures are recorded into the snapshot's Failures array — never thrown
        — so the Flight Recorder can persist them as evidence on hosts where
        Get-PnpDevice is unavailable or denied.
    .OUTPUTS
        PSCustomObject (PSTypeName WinConfig.FlightRecorder.ComPortSnapshot) with:
            CapturedAt   : [DateTime]
            Count        : [int] total port entries captured
            Ports        : [PSCustomObject[]] one per port, with at minimum
                InstanceId, FriendlyName, DeviceName, Class, Status, Problem,
                Present, PortName ('COM3' or $null), ParentBluetoothInstanceId,
                AssociatedBluetoothMac (12 hex uppercase or $null), Source
            Failures     : [PSCustomObject[]] (query, reason)
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $failures = @()
    $ports = @()

    # Helper: try to read the parent InstanceId via Get-PnpDeviceProperty.
    # Falls back to $null on any failure (older OS, permission denied, missing
    # property). This is best-effort enrichment, not a hard requirement.
    $getParent = {
        param([string]$InstanceId)
        if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $null }
        try {
            $prop = Get-PnpDeviceProperty -InstanceId $InstanceId `
                -KeyName 'DEVPKEY_Device_Parent' -ErrorAction Stop
            if ($prop -and $prop.Data) { return [string]$prop.Data }
        } catch { }
        return $null
    }

    $candidates = @()
    try {
        $candidates += Get-PnpDevice -Class Ports -ErrorAction Stop
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice -Class Ports'; Reason = $_.Exception.Message }
    }
    # Catch any Bluetooth-tagged entries that aren't class Ports (e.g. RFCOMM
    # service nodes that expose a PortName via friendly text).
    try {
        $extra = Get-PnpDevice -ErrorAction Stop | Where-Object {
            $_.InstanceId -match '^BTHENUM\\' -and (
                ($_.FriendlyName -match 'Standard Serial over Bluetooth|Bluetooth Serial|SPP|\(COM\d+\)') -or
                ($_.Service -match 'RFCOMM|Serenum')
            )
        }
        foreach ($e in $extra) {
            if ($candidates | Where-Object { $_.InstanceId -eq $e.InstanceId }) { continue }
            $candidates += $e
        }
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice | BTHENUM serial filter'; Reason = $_.Exception.Message }
    }

    foreach ($c in $candidates) {
        $instanceId = [string]$c.InstanceId
        $friendly   = [string]$c.FriendlyName
        $deviceName = $null
        try { $deviceName = [string]$c.Name } catch { $deviceName = $null }

        # Filter: keep only entries that are Bluetooth-flavored. Non-BT serial
        # ports (USB UARTs, FTDI, etc.) would otherwise pollute the snapshot.
        $isBt =
            ($instanceId -match '^BTHENUM\\') -or
            ($instanceId -match '^BTHLE') -or
            ($friendly   -match 'Bluetooth|SPP|RFCOMM') -or
            (([string]$c.Service) -match 'BTHENUM|RFCOMM')
        if (-not $isBt) { continue }

        $portName = Get-BluetoothComPortPortName -Text $friendly
        if (-not $portName) { $portName = Get-BluetoothComPortPortName -Text $deviceName }

        $mac = $null
        if (Get-Command Get-MacFromPnpInstanceId -ErrorAction SilentlyContinue) {
            $mac = Get-MacFromPnpInstanceId -InstanceId $instanceId
        } else {
            # Inline fallback mirrors TargetDeviceWatch normalization so this
            # module remains usable when TargetDeviceWatch isn't loaded yet.
            if ($instanceId -match 'Dev_([0-9A-Fa-f]{12})') { $mac = $Matches[1].ToUpperInvariant() }
            elseif ($instanceId -match '&([0-9A-Fa-f]{12})&') { $mac = $Matches[1].ToUpperInvariant() }
        }

        $parentId = & $getParent $instanceId
        # Only retain the parent when it's a Bluetooth-tree node, so callers
        # can rely on this field for correlation without re-checking.
        $parentBt = $null
        if ($parentId -and ($parentId -match '^BTHENUM\\' -or $parentId -match '^BTHLE')) {
            $parentBt = $parentId
        }
        if (-not $mac -and $parentId) {
            if ($parentId -match 'Dev_([0-9A-Fa-f]{12})')  { $mac = $Matches[1].ToUpperInvariant() }
            elseif ($parentId -match '&([0-9A-Fa-f]{12})&') { $mac = $Matches[1].ToUpperInvariant() }
        }

        $present = $true
        try { $present = [bool]$c.Present } catch { $present = ($c.Status -eq 'OK') }

        $ports += [pscustomobject]@{
            Source                    = if ($c.Class -eq 'Ports') { 'Class:Ports' } else { 'InstanceId:BTHENUM' }
            InstanceId                = $instanceId
            FriendlyName              = $friendly
            DeviceName                = $deviceName
            Class                     = [string]$c.Class
            Status                    = [string]$c.Status
            Problem                   = $c.Problem
            Present                   = $present
            PortName                  = $portName
            ParentBluetoothInstanceId = $parentBt
            AssociatedBluetoothMac    = $mac
        }
    }

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.ComPortSnapshot'
        CapturedAt = $now
        Count      = $ports.Count
        Ports      = $ports
        Failures   = $failures
    }
}

function Get-BluetoothServiceSurfaceSnapshot {
    <#
    .SYNOPSIS
        Captures the Bluetooth service/profile surface exposed by Windows.
    .DESCRIPTION
        For each Bluetooth-tree PnP entry (BTHENUM, BTHLEDevice, BTHLE), records
        the surface attributes that determine whether downstream consumers like
        LabVIEW can find a usable RFCOMM/SPP channel:
            - InstanceId, FriendlyName, Class
            - Service (the kernel service name, e.g. BthAvrcpTg, RFCOMM, BthLEEnum)
            - Status / Present / Problem
            - AssociatedBluetoothMac if extractable

        Prefers Get-PnpDevice (structured) over text parsing. The aggregate
        Summary counts surfaces by Service so the diff can highlight when a
        service disappears between baseline and final without enumerating every
        instance.

        Read-only. Failures recorded as evidence, never thrown.
    .OUTPUTS
        PSCustomObject (PSTypeName WinConfig.FlightRecorder.ServiceSurfaceSnapshot) with:
            CapturedAt : [DateTime]
            Count      : [int]
            Surfaces   : [PSCustomObject[]]
            Summary    : [PSCustomObject] with ByService (hashtable) + TotalPresent
            Failures   : [PSCustomObject[]]
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $failures = @()
    $surfaces = @()

    try {
        $btTree = Get-PnpDevice -ErrorAction Stop | Where-Object {
            $_.InstanceId -match '^BTHENUM\\' -or
            $_.InstanceId -match '^BTHLEDevice\\' -or
            $_.InstanceId -match '^BTHLE\\'
        }
        foreach ($d in $btTree) {
            $mac = $null
            if ($d.InstanceId -match 'Dev_([0-9A-Fa-f]{12})')  { $mac = $Matches[1].ToUpperInvariant() }
            elseif ($d.InstanceId -match '&([0-9A-Fa-f]{12})&') { $mac = $Matches[1].ToUpperInvariant() }

            $present = $true
            try { $present = [bool]$d.Present } catch { $present = ($d.Status -eq 'OK') }

            $surfaces += [pscustomobject]@{
                Source                 = if ($d.InstanceId -match '^BTHLE') { 'Tree:BTHLE' } else { 'Tree:BTHENUM' }
                InstanceId             = $d.InstanceId
                FriendlyName           = $d.FriendlyName
                Class                  = [string]$d.Class
                Service                = [string]$d.Service
                Status                 = [string]$d.Status
                Problem                = $d.Problem
                Present                = $present
                AssociatedBluetoothMac = $mac
            }
        }
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice | Bluetooth tree filter'; Reason = $_.Exception.Message }
    }

    # Aggregate by Service for the diff layer.
    $byService = @{}
    foreach ($s in $surfaces) {
        $key = if ([string]::IsNullOrWhiteSpace($s.Service)) { '(none)' } else { $s.Service }
        if (-not $byService.ContainsKey($key)) {
            $byService[$key] = [pscustomobject]@{ Service = $key; Total = 0; Present = 0 }
        }
        $byService[$key].Total += 1
        if ($s.Present) { $byService[$key].Present += 1 }
    }
    $totalPresent = @($surfaces | Where-Object { $_.Present }).Count

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.ServiceSurfaceSnapshot'
        CapturedAt = $now
        Count      = $surfaces.Count
        Surfaces   = $surfaces
        Summary    = [pscustomobject]@{
            ByService    = $byService
            TotalPresent = $totalPresent
        }
        Failures   = $failures
    }
}

function Get-BluetoothPnpSnapshot {
    <#
    .SYNOPSIS
        Captures the current Bluetooth PnP device set as a structured snapshot.
    .DESCRIPTION
        Enumerates all Bluetooth-class and BTHENUM-instance-id PnP devices and
        returns them as PSCustomObjects suitable for diffing across two captures.
        Read-only — never calls pnputil, Remove-PnpDevice, or any mutating cmdlet.
    .OUTPUTS
        PSCustomObject with:
            CapturedAt : [DateTime]
            Devices    : [PSCustomObject[]] (one entry per device)
            Failures   : [PSCustomObject[]] (errors recorded as evidence)
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $failures = @()
    $devices = @()

    try {
        $btClass = Get-PnpDevice -Class Bluetooth -ErrorAction Stop
        foreach ($d in $btClass) {
            $devices += [pscustomobject]@{
                Source       = 'Class:Bluetooth'
                InstanceId   = $d.InstanceId
                FriendlyName = $d.FriendlyName
                Class        = $d.Class
                Status       = $d.Status
                Manufacturer = $d.Manufacturer
                Service      = $d.Service
                Present      = $d.Present
                Problem      = $d.Problem
            }
        }
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice -Class Bluetooth'; Reason = $_.Exception.Message }
    }

    try {
        $bthEnum = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match '^BTHENUM\\' }
        foreach ($d in $bthEnum) {
            # Avoid duplicates when a device is already in Class:Bluetooth set.
            if ($devices | Where-Object { $_.InstanceId -eq $d.InstanceId }) { continue }
            $devices += [pscustomobject]@{
                Source       = 'InstanceId:BTHENUM'
                InstanceId   = $d.InstanceId
                FriendlyName = $d.FriendlyName
                Class        = $d.Class
                Status       = $d.Status
                Manufacturer = $d.Manufacturer
                Service      = $d.Service
                Present      = $d.Present
                Problem      = $d.Problem
            }
        }
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice | BTHENUM filter'; Reason = $_.Exception.Message }
    }

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.PnpSnapshot'
        CapturedAt = $now
        Count      = $devices.Count
        Devices    = $devices
        Failures   = $failures
    }
}

function Get-BluetoothAdapterSnapshot {
    <#
    .SYNOPSIS
        Captures Bluetooth adapter information as a timestamped snapshot.
    .DESCRIPTION
        Wraps Get-BluetoothAdapterInfo with a CapturedAt stamp so the Flight
        Recorder can diff adapter state across two captures.
    .OUTPUTS
        PSCustomObject with CapturedAt + Adapter sub-object.
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $adapter = $null
    $failure = $null
    try {
        $adapter = Get-BluetoothAdapterInfo
    } catch {
        $failure = $_.Exception.Message
    }

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.AdapterSnapshot'
        CapturedAt = $now
        Adapter    = $adapter
        Failure    = $failure
    }
}

function Get-BluetoothServiceSnapshot {
    <#
    .SYNOPSIS
        Captures Bluetooth and audio service states as a timestamped snapshot.
    .OUTPUTS
        PSCustomObject with CapturedAt + Services hashtable.
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $services = $null
    $failure = $null
    try {
        $services = Get-BluetoothServiceStates
    } catch {
        $failure = $_.Exception.Message
    }

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.ServiceSnapshot'
        CapturedAt = $now
        Services   = $services
        Failure    = $failure
    }
}

function Get-BluetoothEventLogInventory {
    <#
    .SYNOPSIS
        Enumerates Bluetooth-related event logs available on this host.
    .DESCRIPTION
        Lists every Microsoft-Windows-Bluetooth-* channel plus the small set of
        system channels we care about (System, Kernel-PnP). For each, records
        whether it's enabled, current record count, and last write time. Read-only.
    .OUTPUTS
        PSCustomObject with CapturedAt + Logs (array) + Failures (array).
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $logs = @()
    $failures = @()

    $patterns = @(
        'Microsoft-Windows-Bluetooth-*'
    )
    $extraNames = @(
        'System',
        'Microsoft-Windows-Kernel-PnP/Configuration',
        'Microsoft-Windows-Kernel-PnP/Device Management'
    )

    foreach ($p in $patterns) {
        try {
            $matched = Get-WinEvent -ListLog $p -ErrorAction Stop
            foreach ($l in $matched) {
                $logs += [pscustomobject]@{
                    Name          = $l.LogName
                    IsEnabled     = $l.IsEnabled
                    LogMode       = $l.LogMode.ToString()
                    RecordCount   = $l.RecordCount
                    LastWriteTime = $l.LastWriteTime
                    LogFilePath   = $l.LogFilePath
                }
            }
        } catch {
            $failures += [pscustomobject]@{ Log = $p; Reason = $_.Exception.Message }
        }
    }

    foreach ($n in $extraNames) {
        try {
            $l = Get-WinEvent -ListLog $n -ErrorAction Stop | Select-Object -First 1
            if ($l) {
                $logs += [pscustomobject]@{
                    Name          = $l.LogName
                    IsEnabled     = $l.IsEnabled
                    LogMode       = $l.LogMode.ToString()
                    RecordCount   = $l.RecordCount
                    LastWriteTime = $l.LastWriteTime
                    LogFilePath   = $l.LogFilePath
                }
            }
        } catch {
            $failures += [pscustomobject]@{ Log = $n; Reason = $_.Exception.Message }
        }
    }

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.EventLogInventory'
        CapturedAt = $now
        Count      = $logs.Count
        Logs       = $logs
        Failures   = $failures
    }
}

function Get-BluetoothRecentEvents {
    <#
    .SYNOPSIS
        Captures recent Bluetooth/PnP/System events since a given time.
    .DESCRIPTION
        Queries every enabled Bluetooth-* /Operational channel plus the System
        log filtered to Bluetooth/Audio/BTHUSB providers. Read-only.

        Failures (permission denied, channel disabled) are recorded as evidence
        instead of throwing — a non-admin user still gets a usable snapshot.
    .PARAMETER Since
        Earliest event time to include. Defaults to one hour ago.
    .PARAMETER MaxEventsPerLog
        Cap on events pulled from each log to bound output size. Default 500.
    .OUTPUTS
        PSCustomObject with CapturedAt + Since + Events + Failures.
    #>
    [CmdletBinding()]
    param(
        [datetime]$Since = (Get-Date).AddHours(-1),
        [int]$MaxEventsPerLog = 500
    )

    $now = Get-Date
    $events = @()
    $failures = @()

    # Bluetooth operational channels (whichever are enabled on this build).
    $btChannels = @()
    try {
        $btChannels = @(Get-BluetoothOperationalLogNames)
    } catch {
        $failures += [pscustomobject]@{ Log = '(enumerate BT channels)'; Reason = $_.Exception.Message }
    }

    foreach ($ch in $btChannels) {
        try {
            $rows = Get-WinEvent -FilterHashtable @{
                LogName   = $ch
                StartTime = $Since
            } -MaxEvents $MaxEventsPerLog -ErrorAction Stop

            foreach ($r in $rows) {
                $msg = $r.Message
                if ($msg -and $msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' }
                $events += [pscustomobject]@{
                    TimeCreated  = $r.TimeCreated
                    LogName      = $r.LogName
                    ProviderName = $r.ProviderName
                    Id           = $r.Id
                    Level        = $r.LevelDisplayName
                    StableClass  = Get-BluetoothEventClass -Event $r
                    Message      = $msg
                }
            }
        } catch {
            # FilterHashtable throws "no events matched" as an error — treat as empty, not failure.
            if ($_.Exception.Message -notmatch 'No events were found') {
                $failures += [pscustomobject]@{ Log = $ch; Reason = $_.Exception.Message }
            }
        }
    }

    # System log filtered to Bluetooth/Audio providers.
    try {
        $sysRows = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            StartTime    = $Since
            ProviderName = @('BTHUSB', 'BTHPORT', 'Microsoft-Windows-Bluetooth-BthUSB', 'Microsoft-Windows-Audio', 'Microsoft-Windows-Bluetooth-Bthmini')
        } -MaxEvents $MaxEventsPerLog -ErrorAction Stop

        foreach ($r in $sysRows) {
            $msg = $r.Message
            if ($msg -and $msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' }
            $events += [pscustomobject]@{
                TimeCreated  = $r.TimeCreated
                LogName      = $r.LogName
                ProviderName = $r.ProviderName
                Id           = $r.Id
                Level        = $r.LevelDisplayName
                StableClass  = Get-BluetoothEventClass -Event $r
                Message      = $msg
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $failures += [pscustomobject]@{ Log = 'System (BT/Audio filter)'; Reason = $_.Exception.Message }
        }
    }

    $events = @($events | Sort-Object TimeCreated)

    return [pscustomobject]@{
        PSTypeName = 'WinConfig.FlightRecorder.RecentEvents'
        CapturedAt = $now
        Since      = $Since
        Count      = $events.Count
        Events     = $events
        Failures   = $failures
    }
}

function Compare-BluetoothSnapshot {
    <#
    .SYNOPSIS
        Produces a structured diff between two Flight Recorder snapshots.
    .DESCRIPTION
        Diffs are computed per snapshot type. Inputs may be PnpSnapshot,
        AdapterSnapshot, or ServiceSnapshot — auto-detected by PSTypeName.
        Returns Added/Removed/Changed for PnP devices; ChangedFields for
        adapter; per-service before/after for services.
    .PARAMETER Before
        Baseline snapshot.
    .PARAMETER After
        Final snapshot. Must match the type of Before.
    .OUTPUTS
        PSCustomObject describing the diff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Before,
        [Parameter(Mandatory)] $After
    )

    $beforeType = if ($Before.PSObject.TypeNames) { $Before.PSObject.TypeNames | Select-Object -First 1 } else { 'Unknown' }
    $afterType  = if ($After.PSObject.TypeNames) { $After.PSObject.TypeNames | Select-Object -First 1 } else { 'Unknown' }

    if ($beforeType -ne $afterType) {
        return [pscustomobject]@{
            PSTypeName = 'WinConfig.FlightRecorder.SnapshotDiff'
            Kind       = 'TypeMismatch'
            Reason     = "Before=$beforeType vs After=$afterType"
        }
    }

    switch ($beforeType) {
        'WinConfig.FlightRecorder.PnpSnapshot' {
            $beforeMap = @{}
            foreach ($d in $Before.Devices) { $beforeMap[$d.InstanceId] = $d }
            $afterMap = @{}
            foreach ($d in $After.Devices)  { $afterMap[$d.InstanceId]  = $d }

            $added   = @()
            $removed = @()
            $changed = @()

            foreach ($k in $afterMap.Keys) {
                if (-not $beforeMap.ContainsKey($k)) {
                    $added += $afterMap[$k]
                } else {
                    $b = $beforeMap[$k]; $a = $afterMap[$k]
                    $delta = @()
                    foreach ($field in 'Status', 'Present', 'Problem', 'Service') {
                        if ($b.$field -ne $a.$field) {
                            $delta += [pscustomobject]@{ Field = $field; Before = $b.$field; After = $a.$field }
                        }
                    }
                    if ($delta.Count -gt 0) {
                        $changed += [pscustomobject]@{
                            InstanceId   = $k
                            FriendlyName = $a.FriendlyName
                            Changes      = $delta
                        }
                    }
                }
            }
            foreach ($k in $beforeMap.Keys) {
                if (-not $afterMap.ContainsKey($k)) { $removed += $beforeMap[$k] }
            }

            return [pscustomobject]@{
                PSTypeName = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind       = 'PnpDiff'
                BeforeAt   = $Before.CapturedAt
                AfterAt    = $After.CapturedAt
                Added      = $added
                Removed    = $removed
                Changed    = $changed
                Summary    = "Added=$($added.Count) Removed=$($removed.Count) Changed=$($changed.Count)"
            }
        }

        'WinConfig.FlightRecorder.AdapterSnapshot' {
            $delta = @()
            $b = $Before.Adapter
            $a = $After.Adapter
            if ($b -and $a) {
                foreach ($field in 'Present', 'Enabled', 'Status', 'FriendlyName', 'InstanceId', 'PowerManagementEnabled') {
                    if ($b.$field -ne $a.$field) {
                        $delta += [pscustomobject]@{ Field = $field; Before = $b.$field; After = $a.$field }
                    }
                }
            }
            return [pscustomobject]@{
                PSTypeName  = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind        = 'AdapterDiff'
                BeforeAt    = $Before.CapturedAt
                AfterAt     = $After.CapturedAt
                Changed     = ($delta.Count -gt 0)
                ChangedFields = $delta
            }
        }

        'WinConfig.FlightRecorder.ComPortSnapshot' {
            $beforeMap = @{}
            foreach ($p in $Before.Ports) { $beforeMap[$p.InstanceId] = $p }
            $afterMap = @{}
            foreach ($p in $After.Ports)  { $afterMap[$p.InstanceId]  = $p }

            $added   = @()
            $removed = @()
            $changed = @()
            $renumbered = @()

            foreach ($k in $afterMap.Keys) {
                if (-not $beforeMap.ContainsKey($k)) {
                    $added += $afterMap[$k]
                } else {
                    $b = $beforeMap[$k]; $a = $afterMap[$k]
                    $delta = @()
                    foreach ($field in 'Status', 'Present', 'Problem', 'PortName') {
                        if ($b.$field -ne $a.$field) {
                            $delta += [pscustomobject]@{ Field = $field; Before = $b.$field; After = $a.$field }
                        }
                    }
                    if ($delta.Count -gt 0) {
                        $changed += [pscustomobject]@{
                            InstanceId   = $k
                            FriendlyName = $a.FriendlyName
                            PortName     = $a.PortName
                            Changes      = $delta
                        }
                        # A port whose number changed without changing identity is the
                        # canonical LabVIEW-failure symptom -- surface it explicitly so
                        # the diff is searchable.
                        if ($b.PortName -and $a.PortName -and ($b.PortName -ne $a.PortName)) {
                            $renumbered += [pscustomobject]@{
                                InstanceId      = $k
                                FriendlyName    = $a.FriendlyName
                                BeforePortName  = $b.PortName
                                AfterPortName   = $a.PortName
                            }
                        }
                    }
                }
            }
            foreach ($k in $beforeMap.Keys) {
                if (-not $afterMap.ContainsKey($k)) { $removed += $beforeMap[$k] }
            }

            return [pscustomobject]@{
                PSTypeName  = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind        = 'ComPortDiff'
                BeforeAt    = $Before.CapturedAt
                AfterAt     = $After.CapturedAt
                Added       = $added
                Removed     = $removed
                Changed     = $changed
                Renumbered  = $renumbered
                Summary     = "Added=$($added.Count) Removed=$($removed.Count) Changed=$($changed.Count) Renumbered=$($renumbered.Count)"
            }
        }

        'WinConfig.FlightRecorder.ServiceSurfaceSnapshot' {
            $beforeMap = @{}
            foreach ($s in $Before.Surfaces) { $beforeMap[$s.InstanceId] = $s }
            $afterMap = @{}
            foreach ($s in $After.Surfaces)  { $afterMap[$s.InstanceId]  = $s }

            $added   = @()
            $removed = @()
            $changed = @()

            foreach ($k in $afterMap.Keys) {
                if (-not $beforeMap.ContainsKey($k)) {
                    $added += $afterMap[$k]
                } else {
                    $b = $beforeMap[$k]; $a = $afterMap[$k]
                    $delta = @()
                    foreach ($field in 'Status', 'Present', 'Problem', 'Service') {
                        if ($b.$field -ne $a.$field) {
                            $delta += [pscustomobject]@{ Field = $field; Before = $b.$field; After = $a.$field }
                        }
                    }
                    if ($delta.Count -gt 0) {
                        $changed += [pscustomobject]@{
                            InstanceId = $k
                            Service    = $a.Service
                            Changes    = $delta
                        }
                    }
                }
            }
            foreach ($k in $beforeMap.Keys) {
                if (-not $afterMap.ContainsKey($k)) { $removed += $beforeMap[$k] }
            }

            return [pscustomobject]@{
                PSTypeName = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind       = 'ServiceSurfaceDiff'
                BeforeAt   = $Before.CapturedAt
                AfterAt    = $After.CapturedAt
                Added      = $added
                Removed    = $removed
                Changed    = $changed
                Summary    = "Added=$($added.Count) Removed=$($removed.Count) Changed=$($changed.Count)"
            }
        }

        'WinConfig.FlightRecorder.ServiceSnapshot' {
            $delta = @()
            $bsvc = $Before.Services
            $asvc = $After.Services
            if ($bsvc -and $asvc) {
                $allKeys = @($bsvc.Keys + $asvc.Keys | Sort-Object -Unique)
                foreach ($k in $allKeys) {
                    $b = $bsvc[$k]; $a = $asvc[$k]
                    if ($null -eq $b -or $null -eq $a) {
                        $delta += [pscustomobject]@{ Service = $k; Before = $b; After = $a; Change = 'AppearedOrDisappeared' }
                        continue
                    }
                    if ($b.Status -ne $a.Status -or $b.Running -ne $a.Running) {
                        $delta += [pscustomobject]@{
                            Service       = $k
                            BeforeStatus  = $b.Status
                            AfterStatus   = $a.Status
                            BeforeRunning = $b.Running
                            AfterRunning  = $a.Running
                            Change        = 'StatusChanged'
                        }
                    }
                }
            }
            return [pscustomobject]@{
                PSTypeName = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind       = 'ServiceDiff'
                BeforeAt   = $Before.CapturedAt
                AfterAt    = $After.CapturedAt
                Changed    = ($delta.Count -gt 0)
                Services   = $delta
            }
        }

        default {
            return [pscustomobject]@{
                PSTypeName = 'WinConfig.FlightRecorder.SnapshotDiff'
                Kind       = 'Unsupported'
                Reason     = "No diff strategy for type: $beforeType"
            }
        }
    }
}

#endregion

#region WinConfig Integration

function Invoke-BluetoothDiagnosticsAndRecord {
    <#
    .SYNOPSIS
        Runs Bluetooth diagnostics and emits structured Action entries via a callback.
    .DESCRIPTION
        Collects a fresh diagnostic snapshot, classifies the verdict and findings,
        then calls $RecordAction once per Action entry using the schema defined in
        docs/WINCONFIG_INTEGRATION_CONTRACT.md.

        The probe has no direct dependency on WinConfig modules — the caller
        provides the callback, keeping this module independently testable.
    .PARAMETER RecordAction
        Scriptblock called for each Action entry. Receives a single [hashtable]
        argument with keys: Action, Category, Result, Tier, Summary, Evidence.
        Errors inside the callback are silently swallowed so probe output is
        never lost due to a ledger failure.
    .PARAMETER TimeoutSeconds
        Hard deadline for the data-collection phase. If Get-BluetoothDiagnostics does
        not complete within this window, the job is killed and Status=Timeout is returned.
        The callback is never invoked on timeout. Default: 180 seconds.
    .PARAMETER DiagnosticsFixture
        For testing only. When provided, skips the background-job data-collection phase
        and uses this hashtable as the diagnostics result directly. Must match the shape
        returned by Get-BluetoothDiagnostics (Adapter, Verdict, Findings, Services).
    .OUTPUTS
        Hashtable: Status, VerdictStatus, FindingCount, DurationMs, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$RecordAction,

        [int]$TimeoutSeconds = 180,

        [hashtable]$DiagnosticsFixture = $null
    )

    # Finding Id → Tier, per WINCONFIG_INTEGRATION_CONTRACT.md
    $findingTierMap = @{
        NO_ADAPTER              = 5
        ADAPTER_DISABLED        = 5
        AUDIO_SERVICE_DEAD      = 5
        ENDPOINT_BUILDER_DEAD   = 5
        PASSTHROUGH_BT_CONFLICT = 5
        HFP_ACTIVE              = 3
        DEFAULT_IS_HFP          = 3
        SAMPLERATE_MISMATCH     = 4
        HFP_HIJACK_RISK         = 4
        BUFFER_UNDERRUN_RISK    = 3
        FREQUENT_DISCONNECTS    = 4
        GHOST_ENDPOINTS         = 2
        BTHSERV_STOPPED         = 3
        BTAG_STOPPED            = 2
        EVENT_LOG_ERRORS        = 2
        WASAPI_BT_RISK          = 2
        AUDIO_SINK_MISMATCH     = 2
    }

    $startTime   = Get-Date
    $diagnostics = $null

    if ($DiagnosticsFixture) {
        # Test-injection path: use provided fixture, skip background job
        $diagnostics = $DiagnosticsFixture
    } else {
        # Phase 6 hardening: run data collection in a background job so a hung WMI/CIM
        # query or event-log scan can be killed by Wait-Job -Timeout rather than freezing
        # the caller indefinitely. The callback is invoked in the main thread after the
        # job completes, so it can safely cross the runspace boundary.
        $modulePath = $MyInvocation.MyCommand.Module.Path
        $btJob = Start-Job -ScriptBlock {
            param($ModulePath)
            Import-Module $ModulePath -Force -ErrorAction Stop
            Get-BluetoothDiagnostics -BypassCache
        } -ArgumentList $modulePath

        $jobDone = $btJob | Wait-Job -Timeout $TimeoutSeconds

        if (-not $jobDone) {
            $btJob | Remove-Job -Force
            return @{
                Status        = 'Timeout'
                VerdictStatus = $null
                FindingCount  = 0
                DurationMs    = [int]((Get-Date) - $startTime).TotalMilliseconds
                Error         = "Probe timed out after $TimeoutSeconds seconds"
            }
        }

        try {
            $diagnostics = Receive-Job $btJob -ErrorAction Stop
        } catch {
            Remove-Job $btJob -Force
            return @{
                Status        = 'Failed'
                VerdictStatus = $null
                FindingCount  = 0
                DurationMs    = [int]((Get-Date) - $startTime).TotalMilliseconds
                Error         = $_.Exception.Message
            }
        }
        Remove-Job $btJob -Force
    }

    if (-not $diagnostics -or -not $diagnostics.Verdict) {
        return @{
            Status        = 'Failed'
            VerdictStatus = $null
            FindingCount  = 0
            DurationMs    = [int]((Get-Date) - $startTime).TotalMilliseconds
            Error         = 'Diagnostics collection returned no verdict'
        }
    }

    $verdict  = $diagnostics.Verdict
    $findings = @($diagnostics.Findings | Where-Object { $_ })

    $summaryResult = switch ($verdict.Status) {
        'READY'      { 'PASS' }
        'DEGRADED'   { 'WARN' }
        'UNSUITABLE' { 'FAIL' }
        default      { 'FAIL' }
    }
    $summaryTier = switch ($verdict.Status) {
        'READY'      { 1 }
        'DEGRADED'   { 3 }
        'UNSUITABLE' { 5 }
        default      { 5 }
    }

    # Safe evidence: enum/boolean/count values only — no device names, paths, or identifiers.
    # See WINCONFIG_INTEGRATION_CONTRACT.md § Evidence Contract for the full PII safety rationale.
    $bthserv    = $diagnostics.Services['bthserv']
    $aepBuilder = $diagnostics.Services['AudioEndpointBuilder']
    $findingIds = @($findings | ForEach-Object { $_.Id })

    $summaryEvidence = @{
        VerdictStatus     = $verdict.Status
        VerdictConfidence = $verdict.Confidence
        FindingCount      = $findingIds.Count
        FindingIds        = $findingIds
        AdapterPresent    = [bool]($diagnostics.Adapter.Present)
        ServicesHealthy   = [bool](
            ($bthserv   -and $bthserv.Running)   -and
            ($aepBuilder -and $aepBuilder.Running)
        )
        DisconnectCount   = -1  # -1 = real-time probe not run; use Invoke-BluetoothProbe for live data
    }

    try {
        & $RecordAction @{
            Action   = 'Bluetooth Diagnostics Complete'
            Category = 'Bluetooth'
            Result   = $summaryResult
            Tier     = $summaryTier
            Summary  = $verdict.Summary
            Evidence = $summaryEvidence
        }
    }
    catch { }

    # Emit individual finding entries (WARN/FAIL only, max 5)
    $emitted = 0
    foreach ($finding in $findings) {
        if ($finding.Result -notin @('FAIL', 'WARN')) { continue }
        if ($emitted -ge 5) { break }

        $tier = if ($findingTierMap.ContainsKey($finding.Id)) { $findingTierMap[$finding.Id] } else { 2 }

        try {
            & $RecordAction @{
                Action   = 'Bluetooth Finding Detected'
                Category = 'Bluetooth'
                Result   = $finding.Result
                Tier     = $tier
                Summary  = $finding.Title
                Evidence = @{
                    FindingId = $finding.Id
                    AppliesTo = $finding.AppliesTo
                }
            }
        }
        catch { }

        $emitted++
    }

    $status = if ($verdict.Status -eq 'UNSUITABLE' -and $verdict.Reasons -contains 'NO_ADAPTER') {
        'NoAdapter'
    } else {
        'Success'
    }

    return @{
        Status        = $status
        VerdictStatus = $verdict.Status
        FindingCount  = $findingIds.Count
        DurationMs    = [int]((Get-Date) - $startTime).TotalMilliseconds
        Error         = $null
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Get-BluetoothDiagnostics',
    'Get-BluetoothVerdict',
    'Get-BluetoothFindings',
    'Invoke-BluetoothDiagnosticsAndRecord',
    'Invoke-BluetoothProbe',
    'Stop-BluetoothProbe',
    'Test-BluetoothProbeInProgress',
    'Invoke-BluetoothServiceReset',
    'Invoke-BluetoothEndpointCleanup',
    'Invoke-BluetoothAdapterReset',
    # Phase 2: Audio device actions
    'Get-BluetoothAudioDevices',
    'Invoke-BluetoothAudioDeviceDisable',
    'Invoke-BluetoothAudioDeviceRemove',
    # P0/P1/P2 Warbling diagnostic helpers (exported for testing)
    'Get-AudioSampleRates',
    'Get-PowerPlanInfo',
    'Test-HFPHijackRisk',
    'Test-BufferUnderrunRisk',
    # Tools tab individual checks (Phase 4)
    'Get-BluetoothAdapterInfo',
    'Get-BluetoothServiceStates',
    'Get-BluetoothPairedAudioDevices',
    # Dashboard snapshot helpers
    'Get-DefaultPlaybackDevice',
    'Get-KodiAudioSettings',
    'Get-BluetoothEventLogHints',
    # Bluetooth COM port detection (state accretion)
    'Get-BluetoothCOMPorts',
    'Invoke-RevealHiddenBluetoothDevices',
    'Invoke-BluetoothGhostCOMCleanup',
    # Audit critical-fix helpers (exported for unit tests + downstream tooling)
    'Test-BluetoothTransportInstanceId',
    'Clear-BluetoothDiagnosticsCache',
    'Get-BluetoothEventClass',
    'Invoke-PnpDeviceRemovalWithVerification',
    'Get-ServiceResetOutcome',
    'Get-BluetoothOperationalLogNames',
    # Flight Recorder snapshots (read-only collectors)
    'Get-BluetoothPnpSnapshot',
    'Get-BluetoothAdapterSnapshot',
    'Get-BluetoothServiceSnapshot',
    'Get-BluetoothComPortSnapshot',
    'Get-BluetoothComPortPortName',
    'Get-BluetoothServiceSurfaceSnapshot',
    'Get-BluetoothEventLogInventory',
    'Get-BluetoothRecentEvents',
    'Compare-BluetoothSnapshot'
)

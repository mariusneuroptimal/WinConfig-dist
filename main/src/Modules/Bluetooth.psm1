throw "PERF-001 TRIPWIRE: Bluetooth.psm1 imported unexpectedly"
# Bluetooth.psm1 - Bluetooth audio diagnostics for WinConfig
# Provides diagnostics, service control, and Kodi audio path analysis

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
$script:ProbeInProgress = $false
$script:ProbeCancellationRequested = $false
$script:ProbeMediaPlayer = $null
$script:ProbeHardTimeoutSeconds = 5  # Grace period beyond requested duration

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
        $powerMgmtEnabled = $null
        try {
            $powerSettings = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root/WMI -ErrorAction SilentlyContinue |
                Where-Object { $_.InstanceName -match [regex]::Escape($btAdapter.InstanceId.Replace('\', '\\')) }
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
    $logsAccessible = @{
        BthUSB = $false
        System = $false
    }

    # Helper to classify event type
    function Get-EventType {
        param([string]$Message, [string]$Level)
        if ($Message -match "connect(?:ed|ion).*establish|paired|link.*up") { return "Connected" }
        if ($Message -match "disconnect|removed|lost|link.*down") { return "Disconnected" }
        if ($Message -match "hands.?free|HFP|SCO.*connect|call.*mode") { return "Profile: HFP" }
        if ($Message -match "A2DP|stereo|media.*audio") { return "Profile: A2DP" }
        if ($Message -match "reset|restart") { return "Adapter Reset" }
        if ($Level -eq "Error") { return "Error" }
        if ($Level -eq "Warning") { return "Warning" }
        return "Info"
    }

    # BthUSB operational log - may be disabled or not present on some systems (normal)
    try {
        $btEvents = Get-WinEvent -LogName "Microsoft-Windows-Bluetooth-BthUSB/Operational" -MaxEvents 50 -ErrorAction Stop |
            Where-Object { $_.TimeCreated -gt $cutoffTime }

        $logsAccessible.BthUSB = $true

        foreach ($evt in $btEvents) {
            $eventType = Get-EventType -Message $evt.Message -Level $evt.LevelDisplayName
            $isRelevant = $evt.LevelDisplayName -in @("Error", "Warning") -or
                          $evt.Message -match "disconnect|removed|failed|reset|connect|HFP|A2DP|hands.?free"

            if ($isRelevant) {
                $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                $hints += @{
                    Source = "BthUSB"
                    Time = $evt.TimeCreated
                    Level = $evt.LevelDisplayName
                    Id = $evt.Id
                    Message = $msgSnippet
                }

                # Add to timeline
                $timeline += @{
                    Time = $evt.TimeCreated
                    Type = $eventType
                    Device = ""  # BthUSB events don't always have device name
                    Source = "Driver"
                    Summary = $msgSnippet.Substring(0, [Math]::Min(80, $msgSnippet.Length))
                }
            }
        }
    }
    catch {
        # Log may not exist or be disabled - this is normal on many systems
        # Do NOT treat this as a warning condition
        $logsAccessible.BthUSB = $false
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
            $isRelevant = $evt.LevelDisplayName -in @("Error", "Warning") -or
                          $evt.Message -match "disconnect|connect|endpoint"

            if ($isRelevant) {
                $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                $hints += @{
                    Source = "System"
                    Time = $evt.TimeCreated
                    Level = $evt.LevelDisplayName
                    Id = $evt.Id
                    ProviderName = $evt.ProviderName
                    Message = $msgSnippet
                }

                # Add to timeline
                $timeline += @{
                    Time = $evt.TimeCreated
                    Type = $eventType
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

    # Count specific event types
    $disconnectCount = ($hints | Where-Object { $_.Message -match "disconnect|removed|lost" }).Count
    $profileSwitchCount = ($timeline | Where-Object { $_.Type -match "^Profile:" }).Count

    return @{
        Count = $hints.Count
        HasErrors = ($hints | Where-Object { $_.Level -eq "Error" }).Count -gt 0
        HasWarnings = ($hints | Where-Object { $_.Level -eq "Warning" }).Count -gt 0
        DisconnectEvents = $disconnectCount
        ProfileSwitches = $profileSwitchCount
        FrequentDisconnects = $disconnectCount -ge 3
        LogsAccessible = $logsAccessible
        Timeline = $timeline  # NirSoft-inspired: full event timeline
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

    # === P0: Single-flight enforcement ===
    if ($script:ProbeInProgress) {
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
    }

    # Find silent WAV - check assets folder relative to module
    $moduleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $silentWavPath = Join-Path $moduleRoot "assets\silence-1s.wav"

    if (-not (Test-Path $silentWavPath)) {
        $probeResult.Result = $DiagnosticResult.FAIL
        $probeResult.TerminalState = "ProbeFailed"
        $probeResult.Error = "Silent WAV file not found: $silentWavPath"
        $probeResult.Confidence = "Low"
        $probeResult.EndTime = Get-Date
        return $probeResult
    }

    # === P0: Set probe in progress and reset cancellation flag ===
    $script:ProbeInProgress = $true
    $script:ProbeCancellationRequested = $false

    try {
        # Create Windows Media Player COM object
        $script:ProbeMediaPlayer = New-Object -ComObject WMPlayer.OCX.7

        # Baseline device state
        $baselineDevices = @(Get-BluetoothPairedAudioDevices)
        $baselineEventCount = (Get-WinEvent -LogName "Microsoft-Windows-Bluetooth-BthUSB/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId

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

            # Check for new BT events
            try {
                $newEvents = Get-WinEvent -LogName "Microsoft-Windows-Bluetooth-BthUSB/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue |
                    Where-Object { $_.TimeCreated -gt $probeResult.StartTime }

                foreach ($evt in $newEvents) {
                    if ($evt.Message -match "disconnect|removed|failed") {
                        $probeResult.Disconnects++
                        $probeResult.Events += @{
                            Time = $evt.TimeCreated
                            Type = "DISCONNECT"
                            Detail = ($evt.Message -split "`n")[0]
                        }
                    }
                }
            }
            catch {
                # Event log may not be accessible - continue
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

        # === P0: Clear single-flight flag ===
        $script:ProbeInProgress = $false
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

    if (-not $script:ProbeInProgress) {
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

    return $script:ProbeInProgress
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
        ServicesRestarted = @()
        RequiresAdmin = $true
    }

    # === P1: Cross-diagnostic guard ===
    if ($script:ProbeInProgress) {
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

    $servicesToRestart = @("bthserv", "BTAGService", "Audiosrv", "AudioEndpointBuilder")

    # Also find per-user Bluetooth service
    $btUserSvc = Get-Service -Name "BluetoothUserService_*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($btUserSvc) {
        $servicesToRestart += $btUserSvc.Name
    }

    foreach ($svcName in $servicesToRestart) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) {
                $result.Details += "Service '$svcName' not found - skipped"
                continue
            }

            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
            }

            Start-Service -Name $svcName -ErrorAction Stop
            $result.ServicesRestarted += $svcName
            $result.Details += "Restarted: $svcName"
        }
        catch {
            $result.Details += "Failed to restart '$svcName': $($_.Exception.Message)"
        }
    }

    $result.Success = $result.ServicesRestarted.Count -gt 0
    $result.Message = if ($result.Success) {
        "Restarted $($result.ServicesRestarted.Count) service(s)"
    } else {
        "Failed to restart any services"
    }

    # === P1: Set terminal state ===
    $result.TerminalState = if ($result.Success) { "ResetCompleted" } else { "ResetFailed" }

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
    if ($script:ProbeInProgress) {
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

    # Find stale BT audio endpoints
    $staleEndpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -ne 'OK' -and
            ($_.InstanceId -match "BTHENUM|BTH" -or $_.FriendlyName -match "Bluetooth|BT|Hands-Free|Headset")
        }

    if (-not $staleEndpoints) {
        $result.Success = $true
        $result.TerminalState = "CleanupCompleted"
        $result.Message = "No stale Bluetooth audio endpoints found"
        return $result
    }

    foreach ($endpoint in $staleEndpoints) {
        # Safety check 1: Never remove if name matches default playback
        if ($defaultPlaybackName -and $endpoint.FriendlyName -and $endpoint.FriendlyName -match [regex]::Escape($defaultPlaybackName)) {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (matches default): $($endpoint.FriendlyName)"
            continue
        }

        # Safety check 2: Never remove if somehow marked as OK (double-check)
        if ($endpoint.Status -eq 'OK') {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (connected): $($endpoint.FriendlyName)"
            continue
        }

        # Safety check 3: Never remove if InstanceId is in connected list
        if ($connectedEndpoints -contains $endpoint.InstanceId) {
            $result.SkippedDevices += $endpoint.FriendlyName
            $result.Details += "Skipped (active): $($endpoint.FriendlyName)"
            continue
        }

        try {
            # Log what we're about to remove
            $result.Details += "Removing: $($endpoint.FriendlyName) [InstanceId: $($endpoint.InstanceId), Status: $($endpoint.Status)]"

            # Remove the device (this uninstalls the driver instance)
            $pnpResult = pnputil /remove-device $endpoint.InstanceId 2>&1
            $result.RemovedDevices += $endpoint.FriendlyName
            $result.Details += "Removed: $($endpoint.FriendlyName)"
        }
        catch {
            $result.Details += "Failed to remove '$($endpoint.FriendlyName)': $($_.Exception.Message)"
        }
    }

    $result.Success = $result.RemovedDevices.Count -gt 0 -or $result.SkippedDevices.Count -gt 0
    $result.Message = if ($result.RemovedDevices.Count -gt 0) {
        "Removed $($result.RemovedDevices.Count) stale endpoint(s)"
    } elseif ($result.SkippedDevices.Count -gt 0) {
        "All endpoints skipped (protected or active)"
    } else {
        "No endpoints removed"
    }

    # === P1: Set terminal state ===
    $result.TerminalState = if ($result.Success) { "CleanupCompleted" } else { "CleanupFailed" }

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
    if ($script:ProbeInProgress) {
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
    }
    catch {
        $result.TerminalState = "ResetFailed"
        $result.Message = "Failed to reset adapter: $($_.Exception.Message)"
        $result.Details += $_.Exception.Message
        $result.RebootRequired = $true
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
    if ($script:ProbeInProgress) {
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
    if ($script:ProbeInProgress) {
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
                $result.Success = $true
                $result.TerminalState = "RemoveCompleted"
                $result.Message = "Device removed successfully"
                $result.Details += "Remove-PnpDevice executed successfully"
                return $result
            }
            catch {
                $result.Details += "Remove-PnpDevice failed: $($_.Exception.Message)"
                # Fall through to pnputil
            }
        }

        # Fallback to pnputil
        $pnpResult = pnputil /remove-device $InstanceId 2>&1
        $pnpResultStr = $pnpResult -join "`n"

        if ($LASTEXITCODE -eq 0 -or $pnpResultStr -match "successfully") {
            $result.Success = $true
            $result.TerminalState = "RemoveCompleted"
            $result.Message = "Device removed successfully"
            $result.Details += "pnputil /remove-device completed"
        }
        else {
            $result.TerminalState = "RemoveFailed"
            $result.Message = "Device removal may not be supported on this system"
            $result.Details += "pnputil output: $pnpResultStr"
            $result.Details += "Try removing the device via Windows Bluetooth Settings instead"
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
    if ($script:ProbeInProgress) {
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
    } elseif ($result.SkippedCount -gt 0 -and $result.FailedCount -eq 0) {
        $result.Success = $true
        $result.Message = "No removable ghost COM ports (all skipped for safety)"
    } else {
        $result.Message = "Failed to remove ghost COM ports"
    }

    return $result
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Get-BluetoothDiagnostics',
    'Get-BluetoothVerdict',
    'Get-BluetoothFindings',
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
    'Invoke-BluetoothGhostCOMCleanup'
)

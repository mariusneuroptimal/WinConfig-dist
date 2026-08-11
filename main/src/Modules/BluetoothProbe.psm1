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

        # AsTask, NOT GetAwaiter. Both are generic extension methods, but
        # GetAwaiter cannot be late-bound: Invoke() on it throws "Late bound
        # operations cannot be performed on types or methods for which
        # ContainsGenericParameters is true", because PowerShell has no way to
        # supply the type argument. AsTask can be closed explicitly with
        # MakeGenericMethod, which is why every caller passes -ResultType.
        #
        # This mattered: the previous GetAwaiter form threw on EVERY call, the
        # throw was swallowed, and Await-WinRTAsync returned $null. WinRT
        # Bluetooth enumeration therefore reported zero devices on every box,
        # silently, and the IsConnected/Presence/ClassOfDevice enrichment built
        # on it never ran.
        $script:AsTaskMethod = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        })[0]
        if (-not $script:AsTaskMethod) { throw 'AsTask(IAsyncOperation<T>) not found' }

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
        Awaits a WinRT IAsyncOperation and returns the result, or $null.
    .PARAMETER AsyncOp
        The IAsyncOperation. Under PowerShell 5.1 this arrives as a bare
        System.__ComObject, which is why the result type cannot be inferred and
        must be supplied.
    .PARAMETER ResultType
        The T of IAsyncOperation<T>. Required: it closes the generic AsTask
        method. Passing the wrong type surfaces as a marshalling failure, i.e.
        $null, not as silently wrong data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AsyncOp,
        [Parameter(Mandatory)][type]$ResultType,
        [int]$TimeoutMs = 5000
    )

    if (-not $AsyncOp) { return $null }
    if (-not $script:AsTaskMethod) {
        if (-not (Initialize-WinRTTypes)) { return $null }
    }

    try {
        $task = $script:AsTaskMethod.MakeGenericMethod($ResultType).Invoke($null, @($AsyncOp))

        # Apartment matters. On MTA (background jobs) Task.Wait behaves normally
        # and the timeout is real.
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            if (-not $task.Wait($TimeoutMs)) { return $null }
            return $task.Result
        }

        # On STA -- which is what the GUI runs on -- a blocking Task.Wait cannot
        # observe completion at all: the WinRT continuation needs the COM message
        # pump, and the pump is not running while the thread is blocked. Measured:
        # Wait(10000), AsyncWaitHandle.WaitOne(10000) and IsCompleted polling ALL
        # report "not finished" on an operation that has in fact completed.
        # Reading .Result does complete, so that is what we use here, and the
        # $TimeoutMs is advisory on this path.
        #
        # This is only safe because every call site uses a fast API: the paired
        # device enumeration below measures ~34ms and FromIdAsync ~10ms per
        # device. It is specifically NOT safe for DeviceInformation AEP queries,
        # which block for a fixed 30s -- see Get-BluetoothDevicesWinRT.
        return $task.Result
    }
    catch {
        Write-Verbose "WinRT await failed for [$($ResultType.Name)]: $($_.Exception.Message)"
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

        # Get DeviceInformation type
        $deviceInfoType = [Type]::GetType("Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType=WindowsRuntime")

        if (-not $deviceInfoType) {
            # Fallback: try loading via Add-Type with WinRT reference
            $null = [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType=WindowsRuntime]
            $deviceInfoType = [Windows.Devices.Enumeration.DeviceInformation]
        }

        # BluetoothDevice.GetDeviceSelector(), NOT a hand-written AQS query over
        # System.Devices.Aep.*. Both return the same paired devices here, but
        # they are not equivalent in practice:
        #
        #   GetDeviceSelector()  DeviceInterface kind        ~34ms
        #   AEP AQS filter       AssociationEndpoint kind    ~30s, every time
        #
        # The AEP form also requires the three-argument FindAllAsync overload
        # (the one- and two-argument ones default to DeviceInterface, against
        # which an AEP filter silently matches nothing) and its whole reason for
        # existing was to request System.Devices.Aep.IsConnected -- which cannot
        # be read anyway, because DeviceInformation.Properties is an
        # IMapView<string,object> that PowerShell 5.1 surfaces as an opaque
        # System.__ComObject. So the slow path bought nothing. Connection status
        # comes from BluetoothDevice.ConnectionStatus below instead, which is
        # authoritative and costs ~10ms per device.
        $btDeviceTypeForSelector = [Windows.Devices.Bluetooth.BluetoothDevice, Windows.Devices.Bluetooth, ContentType=WindowsRuntime]
        $btSelector = $btDeviceTypeForSelector::GetDeviceSelector()

        # [type[]] cast is required: without it PowerShell binds @(...) as
        # Object[] and resolves GetMethod(string, BindingFlags) instead of
        # GetMethod(string, Type[]), returning $null.
        $findAllMethod = $deviceInfoType.GetMethod('FindAllAsync', [type[]]@([string]))
        if (-not $findAllMethod) {
            Write-Verbose "FindAllAsync(String) not found"
            return @()
        }
        $asyncOp = $findAllMethod.Invoke($null, @($btSelector))

        $deviceInfoCollection = Await-WinRTAsync -AsyncOp $asyncOp `
            -ResultType ([Windows.Devices.Enumeration.DeviceInformationCollection]) -TimeoutMs 10000

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

                # Extract properties. DeviceInformation.Properties is an
                # IMapView<string,object>, which PowerShell 5.1 surfaces as a
                # bare System.__ComObject: ContainsKey/indexing are not
                # projected, Keys enumerates empty, and indexing throws. So this
                # is best-effort only and MUST NOT be the source of truth --
                # BluetoothDevice.ConnectionStatus below is, and it is read for
                # every device rather than only as a fallback.
                $address = $null
                $isConnectedProp = $false
                $signalStrength = $null

                try {
                    $props = $devInfo.Properties
                    if ($props -and $props.ContainsKey("System.Devices.Aep.DeviceAddress")) {
                        $address = $props["System.Devices.Aep.DeviceAddress"]
                    }
                    if ($props -and $props.ContainsKey("System.Devices.Aep.IsConnected")) {
                        $isConnectedProp = $props["System.Devices.Aep.IsConnected"] -eq $true
                    }
                    if ($props -and $props.ContainsKey("System.Devices.Aep.SignalStrength")) {
                        $signalStrength = $props["System.Devices.Aep.SignalStrength"]
                    }
                } catch {
                    Write-Verbose "AEP property map not readable for '$name' (expected on PS 5.1)"
                }

                # Resolve live connection status via BluetoothDevice.FromIdAsync
                $isConnected = $isConnectedProp
                $classOfDevice = $null

                if ($btDeviceType) {
                    try {
                        $fromIdMethod = $btDeviceType.GetMethod('FromIdAsync', [type[]]@([string]))
                        $btAsyncOp = $fromIdMethod.Invoke($null, @($deviceId))
                        $btDevice = Await-WinRTAsync -AsyncOp $btAsyncOp `
                            -ResultType ([Windows.Devices.Bluetooth.BluetoothDevice]) -TimeoutMs 3000

                        if ($btDevice) {
                            # Connection status from BluetoothDevice is authoritative
                            $connStatus = $btDevice.ConnectionStatus
                            $isConnected = $connStatus -eq [Windows.Devices.Bluetooth.BluetoothConnectionStatus]::Connected

                            # The only reliable MAC source here: the AEP property
                            # map that would otherwise carry it is not readable
                            # from PS 5.1. Formatted to match the colon-separated
                            # form used everywhere else in this module.
                            if (-not $address -and $btDevice.BluetoothAddress) {
                                $hex = '{0:X12}' -f $btDevice.BluetoothAddress
                                $address = ($hex -replace '(.{2})(?!$)', '$1:')
                            }

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

function Get-BluetoothInquiryScan {
    <#
    .SYNOPSIS
        Runs a real BR/EDR inquiry and reports UNPAIRED classic devices the box
        can currently see.
    .DESCRIPTION
        Answers the field question nothing else could: "can this box see the Arc
        at all?" Get-BluetoothDevicesWinRT enumerates PAIRED devices only, so
        before this there was no way to distinguish a headset the host cannot
        discover from one that is simply not paired yet.

        GetDeviceSelectorFromPairingState($false) carries IssueInquiry:=True, so
        this drives an actual radio inquiry rather than reading a cache. That is
        why it costs tens of seconds and why it is not on any automatic path.

        MUST RUN ON MTA, AND REFUSES ON STA BY DEFAULT. Await-WinRTAsync falls
        back to reading .Result on STA, where the timeout is only advisory --
        safe for the ~34ms paired enumeration it was written for, not for this:
        a DeviceInformation AEP query blocks for a fixed ~30s and would freeze
        the GUI message pump for the whole inquiry. powershell.exe defaults to
        STA on 5.1, so an operator must launch `powershell -MTA` explicitly.

        POWER-CYCLE THE DEVICE IMMEDIATELY BEFORE SCANNING. An Arc idles itself
        off and then answers no inquiry at all. Observed 2026-08-06: Arc 000013
        was heard exactly once, at 10:42:51, and not by either of two later
        scans - an idle timeout, not a discovery fault. Scanning a sleeping
        headset measures nothing, and a zero result is reported here as
        inconclusive for exactly that reason.

        A DEVICE THIS FINDS GETS A REGISTRY RECORD. Windows writes a
        BTHPORT\Parameters\Devices\<mac> subkey for a device it has merely seen.
        That is a sighting, not a pairing; Test-BluetoothOrphanPairingRecord
        classifies it as such so this scan does not manufacture orphan findings.
    .PARAMETER TimeoutMs
        Ceiling on the inquiry. The radio's own inquiry window dominates.
    .PARAMETER NameLike
        Wildcard filter applied to the results. Does not shorten the scan; the
        inquiry runs to completion either way.
    .PARAMETER Force
        Run on STA anyway, accepting a blocked message pump for the duration.
    .OUTPUTS
        [hashtable] Ran, Refused, Reason, Apartment, DurationMs, Count, Devices,
        Summary
    #>
    [CmdletBinding()]
    param(
        [int]$TimeoutMs = 60000,
        [string]$NameLike,
        [switch]$Force
    )

    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState().ToString()
    $result = @{
        Ran        = $false
        Refused    = $false
        Reason     = $null
        Apartment  = $apartment
        DurationMs = 0
        Count      = 0
        Devices    = @()
        Summary    = $null
    }

    if ($apartment -eq 'STA' -and -not $Force) {
        $result.Refused = $true
        $result.Reason  = "Refused: this thread is STA. A Bluetooth inquiry blocks for tens of seconds and on STA the await falls back to reading .Result, where the timeout is advisory and the COM message pump stalls for the whole scan. Re-run from 'powershell -MTA', or pass -Force to accept a frozen pump."
        $result.Summary = $result.Reason
        return $result
    }

    $collection = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $null = [Windows.Devices.Bluetooth.BluetoothDevice, Windows.Devices.Bluetooth, ContentType=WindowsRuntime]
        $null = [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType=WindowsRuntime]
        if (-not (Initialize-WinRTTypes)) {
            $result.Reason  = 'WinRT initialization failed'
            $result.Summary = $result.Reason
            return $result
        }

        # $false = UNPAIRED.
        $selector = [Windows.Devices.Bluetooth.BluetoothDevice]::GetDeviceSelectorFromPairingState($false)

        # [type[]] cast required, as in Get-BluetoothDevicesWinRT: without it
        # PowerShell resolves GetMethod(string, BindingFlags) and returns $null.
        $findAll = [Windows.Devices.Enumeration.DeviceInformation].GetMethod('FindAllAsync', [type[]]@([string]))
        if (-not $findAll) {
            $result.Reason  = 'FindAllAsync(String) not found'
            $result.Summary = $result.Reason
            return $result
        }

        $op = $findAll.Invoke($null, @($selector))
        $collection = Await-WinRTAsync -AsyncOp $op `
            -ResultType ([Windows.Devices.Enumeration.DeviceInformationCollection]) `
            -TimeoutMs $TimeoutMs
        $result.Ran = $true
    } catch {
        $result.Reason = $_.Exception.Message
    } finally {
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds
    }

    if (-not $result.Ran) {
        $result.Summary = "Inquiry scan failed: $($result.Reason)"
        return $result
    }
    if ($null -eq $collection) {
        $result.Reason  = "The await returned nothing after $($result.DurationMs)ms"
        $result.Summary = "Inquiry scan produced no result: $($result.Reason). This is a scan failure, NOT evidence that no device is in range."
        return $result
    }

    $found = @()
    foreach ($d in $collection) {
        # AEP ids carry both MACs: Bluetooth#Bluetooth<radio>-<device>. The
        # device half is the one after the hyphen.
        $address = $null
        $m = [regex]::Match([string]$d.Id, '-((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$')
        if ($m.Success) { $address = $m.Groups[1].Value.ToUpper() }

        $found += [PSCustomObject]@{
            Name      = $d.Name
            Id        = $d.Id
            Address   = $address
            Kind      = [string]$d.Kind
            IsEnabled = $d.IsEnabled
        }
    }
    if ($NameLike) { $found = @($found | Where-Object { $_.Name -like $NameLike }) }

    $result.Devices = @($found)
    $result.Count   = @($found).Count

    $secs = [math]::Round($result.DurationMs / 1000, 1)
    if ($result.Count -gt 0) {
        $names = ($found | ForEach-Object { if ($_.Name) { $_.Name } else { '(unnamed)' } }) -join ', '
        $result.Summary = "$($result.Count) unpaired device(s) seen in a ${secs}s inquiry: $names. The radio can discover devices, so a headset missing from this list was not answering."
    } elseif ($NameLike) {
        $result.Summary = "No unpaired device matching '$NameLike' was seen in a ${secs}s inquiry. INCONCLUSIVE on its own: an Arc that has idled itself off answers no inquiry at all. Power-cycle the headset and scan again before treating this as a discovery fault."
    } else {
        $result.Summary = "No unpaired device was seen in a ${secs}s inquiry. INCONCLUSIVE on its own - it cannot separate 'nothing in range' from 'the radio is not inquiring'. Power-cycle the target and re-scan; if a known-good device is also invisible, the fault is host-side."
    }
    return $result
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

    # Return max 3 findings, prioritized by severity (FAIL before WARN before INFO).
    # Findings carry a `Result` field (not `Severity`); the prior code indexed by the
    # non-existent `$_.Severity`, so the key was always $null. A hashtable null-index
    # throws "Index operation failed; the array index evaluated to null", which under the
    # app's $ErrorActionPreference='Stop' aborted the whole diagnostics run — but only when
    # $findings was non-empty (Sort-Object evaluates the key per item). That is exactly why
    # the baseline pass (READY, 0 findings) succeeded while the final pass (post-session
    # churn -> findings) crashed. Index by [string]$_.Result + ContainsKey so the key is
    # never $null and an unexpected Result can never throw.
    $severityOrder = @{ "FAIL" = 0; "WARN" = 1; "INFO" = 2 }
    return $findings | Sort-Object {
        $key = [string]$_.Result
        if ($severityOrder.ContainsKey($key)) { $severityOrder[$key] } else { 99 }
    } | Select-Object -First 3
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

    # Tracked outside the try so the catch can roll back a half-finished reset.
    $targetInstanceId = $null
    $adapterDisabled = $false

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
        $targetInstanceId = $btAdapter.InstanceId

        # Disable adapter
        Disable-PnpDevice -InstanceId $targetInstanceId -Confirm:$false -ErrorAction Stop
        $adapterDisabled = $true
        $result.Details += "Adapter disabled at $(Get-Date -Format 'HH:mm:ss')"

        Start-Sleep -Seconds 2

        # Re-enable adapter
        Enable-PnpDevice -InstanceId $targetInstanceId -Confirm:$false -ErrorAction Stop
        $adapterDisabled = $false
        $result.Details += "Adapter re-enabled"

        Start-Sleep -Seconds 1

        # Check if adapter came back
        $adapterCheck = Get-PnpDevice -InstanceId $targetInstanceId -ErrorAction SilentlyContinue
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

        # Rollback. If the disable landed and the enable did not, the radio is
        # left in CM_PROB_DISABLED, and Windows does not merely grey out the
        # Bluetooth toggle in that state - it removes it from Settings and Quick
        # Settings entirely. An operator sees "Bluetooth is gone", with no
        # in-Settings way back. Recovery is mandatory here, not best effort.
        if ($adapterDisabled -and $targetInstanceId) {
            $result.Details += "Disable succeeded but enable did not; rolling back"
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    Enable-PnpDevice -InstanceId $targetInstanceId -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $rollbackState = Get-PnpDevice -InstanceId $targetInstanceId -ErrorAction SilentlyContinue
                    if ($rollbackState -and $rollbackState.Status -eq 'OK') {
                        $adapterDisabled = $false
                        $result.Details += "Rollback succeeded on attempt ${attempt}; adapter re-enabled"
                        break
                    }
                    $result.Details += "Rollback attempt ${attempt}: adapter status is '$($rollbackState.Status)'"
                }
                catch {
                    $result.Details += "Rollback attempt ${attempt} failed: $($_.Exception.Message)"
                }
                Start-Sleep -Seconds 2
            }
        }

        # Rollback itself can fail. Say so loudly and hand over the exact
        # recovery command rather than reporting a generic reset failure.
        if ($adapterDisabled) {
            $result.TerminalState = "ResetFailedAdapterDisabled"
            $result.Message = "Reset failed and the Bluetooth adapter is STILL DISABLED. " +
                "Windows will not show a Bluetooth toggle until it is re-enabled. " +
                "Recover in Device Manager (Bluetooth > adapter > Enable device), or run as admin: " +
                "Enable-PnpDevice -InstanceId '$targetInstanceId' -Confirm:`$false"
            $result.Details += "ADAPTER LEFT DISABLED - manual recovery required"
        }

        # F7: Disable may have succeeded before Enable failed - assume state changed.
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

            # DEVPKEY_Device_BusReportedDeviceDesc - the per-channel name the
            # DEVICE reports (e.g. "NEUROPTIMAL COMMAND" / "NEUROPTIMAL DATA").
            # FriendlyName is the generic "Standard Serial over Bluetooth link
            # (COMx)" for every SPP channel, so this is the ONLY field that
            # distinguishes the command port from the data port. Applications
            # select the control port on it; without it captured, a bundle
            # cannot show whether port selection was correct.
            $busReportedDesc = $null
            try {
                $busReportedDesc = (Get-PnpDeviceProperty -InstanceId $instanceId `
                    -KeyName '{540b947e-8b40-45bc-a8a2-6a0b894cbda2} 4' `
                    -ErrorAction SilentlyContinue).Data
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
                BusReportedDeviceDesc = $busReportedDesc
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

function Initialize-SerialSymlinkApi {
    <#
    .SYNOPSIS
        Loads the QueryDosDevice P/Invoke used to resolve \GLOBAL??\COMx
        symlinks. Idempotent.
    .OUTPUTS
        [bool] $true if the API is available, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:SerialSymlinkApiAvailable) { return $true }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'WinConfigSerialSymlink').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinConfigSerialSymlink {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

    // Returns the device object the DOS name points at, or "ERR:<win32>" when
    // the symlink does not exist. Callers MUST treat "ERR:" as data, not as an
    // exception - an absent COMx symlink is the exact fault this detects.
    public static string Resolve(string dosName) {
        var sb = new StringBuilder(4096);
        uint n = QueryDosDevice(dosName, sb, 4096);
        if (n == 0) { return "ERR:" + Marshal.GetLastWin32Error(); }
        return sb.ToString();
    }
}
'@ -ErrorAction Stop
        }
        $script:SerialSymlinkApiAvailable = $true
        return $true
    } catch {
        return $false
    }
}

function Get-BluetoothSerialPortIntegrity {
    <#
    .SYNOPSIS
        Cross-checks the three layers that must agree before a Bluetooth COM
        port can be opened: SERIALCOMM registrations, the Object Manager
        symlink, and PnP presence.
    .DESCRIPTION
        Ghost enumeration (Get-BluetoothCOMPorts) only sees non-present PnP
        nodes. A machine can have ZERO ghosts and still be unable to open any
        Bluetooth COM port, because the fault lives a layer below:

            PnP / Device Manager            COM5, COM6 Present, Status OK
            HKLM\HARDWARE\DEVICEMAP\
              SERIALCOMM                    12 entries for 4 COM names
            \GLOBAL??\COMx (QueryDosDevice) symlink ABSENT (win32err 2)

        In that state CreateFile returns ERROR_FILE_NOT_FOUND and the calling
        app reports something like "Control Port 'COM6' is not valid" - which
        reads as a configuration problem even though port selection was
        correct. Observed on MMEVOLD_06 2026-07-27 (NeurOptimal Arc): three
        \Device\BthModemNN objects registered per COM name, all four symlinks
        destroyed, every open failing.

        HKLM\HARDWARE is a VOLATILE hive rebuilt from scratch at every boot,
        so a collision there was necessarily created during the current boot
        session - the Bluetooth serial driver re-registers COM names across
        sleep/resume without tearing down the previous generation, and the
        symlink is lost in the collision. A reboot clears it. Unpair/re-pair
        does NOT - it just mints another colliding generation.

        Read-only. Makes no changes.
    .OUTPUTS
        [hashtable] Healthy, CollisionCount, MissingSymlinkCount, Entries,
        Findings, Summary, Recommendation, ApiAvailable, Error
    #>
    [CmdletBinding()]
    param()

    $registrations = @()
    $symlinkMap    = @{}
    $symlinksValid = $false
    $collectError  = $null

    try {
        # --- Layer 2: SERIALCOMM registrations -------------------------------
        $serialCommPath = 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM'
        if (Test-Path $serialCommPath) {
            $raw = Get-ItemProperty -Path $serialCommPath -ErrorAction Stop
            foreach ($p in $raw.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                $registrations += [PSCustomObject]@{
                    DeviceObject = $p.Name
                    ComName      = [string]$p.Value
                }
            }
        }

        # --- Layer 3: Object Manager symlinks --------------------------------
        # The 'C:' control resolve is mandatory. Without it a broken P/Invoke
        # is indistinguishable from a machine with every symlink destroyed,
        # and we would report a catastrophic false positive.
        if (Initialize-SerialSymlinkApi) {
            $control = [WinConfigSerialSymlink]::Resolve('C:')
            if ($control -and $control -notlike 'ERR:*') {
                $symlinksValid = $true
                foreach ($name in @($registrations | Select-Object -ExpandProperty ComName -Unique)) {
                    $symlinkMap[$name] = [WinConfigSerialSymlink]::Resolve($name)
                }
            }
        }
    } catch {
        $collectError = $_.Exception.Message
    }

    $verdict = Test-BluetoothSerialPortIntegrity -Registrations $registrations `
                   -SymlinkMap $symlinkMap -SymlinksValid:$symlinksValid
    $verdict.Error = $collectError
    if ($collectError) {
        $verdict.Summary = "Serial port integrity check failed: $collectError"
    }

    # Boot/resume context, so the "re-registers on resume" hypothesis is carried
    # as a number in every capture rather than re-argued from memory each time.
    # Never allowed to fail the integrity check itself.
    $verdict.PowerContext = $null
    $verdict.Correlation  = $null
    try {
        $power = Get-BluetoothPowerCycleContext
        $verdict.PowerContext = $power
        $verdict.Correlation  = Get-SerialRegistrationCorrelation `
            -EntryCount $verdict.EntryCount -ComNameCount $verdict.ComNameCount `
            -ResumeCount $power.ResumeCount
    } catch { }

    return $verdict
}

function Test-BluetoothSerialPortIntegrity {
    <#
    .SYNOPSIS
        Pure verdict function for Bluetooth serial port integrity. Correlates
        SERIALCOMM registrations against resolved COMx symlinks.
    .DESCRIPTION
        Split out from Get-BluetoothSerialPortIntegrity so the detection logic
        can be tested against captured broken-state data without needing a
        machine in that state. Takes no live dependencies.

        Three defects are reported, all of which make a port unopenable or about
        to become so:
          COLLISION      one COM name claimed by several device objects
          SYMLINK ABSENT the COM name has no \GLOBAL??\ entry at all
          SYMLINK STALE  the entry resolves, but to a device object that is no
                         longer registered for that name
    .PARAMETER Registrations
        Array of objects with DeviceObject + ComName, as read from
        HKLM\HARDWARE\DEVICEMAP\SERIALCOMM.
    .PARAMETER SymlinkMap
        Hashtable of ComName -> resolved device object, or "ERR:<win32>" when
        QueryDosDevice failed for that name.
    .PARAMETER SymlinksValid
        $false when the symlink layer could not be read at all (P/Invoke
        unavailable or the control probe failed). Symlink findings are then
        suppressed rather than reported as absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Registrations,
        [hashtable]$SymlinkMap = @{},
        [switch]$SymlinksValid
    )

    $result = @{
        Healthy              = $true
        CollisionCount       = 0
        MissingSymlinkCount  = 0
        DanglingSymlinkCount = 0
        ComNameCount         = 0
        EntryCount           = $Registrations.Count
        Entries              = @()
        Findings             = @()
        Summary              = $null
        Recommendation       = $null
        SymlinksChecked      = [bool]$SymlinksValid
        Error                = $null
    }

    if ($Registrations.Count -eq 0) {
        $result.Summary = "No serial port registrations found"
        return $result
    }

    $comNames = @($Registrations | Select-Object -ExpandProperty ComName -Unique)
    $result.ComNameCount = $comNames.Count

    foreach ($name in $comNames) {
        $owners  = @($Registrations | Where-Object { $_.ComName -eq $name })
        $symlink = if ($SymlinksValid -and $SymlinkMap.ContainsKey($name)) { $SymlinkMap[$name] } else { $null }
        $symlinkOk = if ($SymlinksValid) { [bool]($symlink -and $symlink -notlike 'ERR:*') } else { $null }

        $deviceObjects = @($owners | Select-Object -ExpandProperty DeviceObject)

        # A symlink that RESOLVES is not necessarily a symlink that resolves to
        # the right place. \GLOBAL??\COM6 -> \Device\BthModem3 while SERIALCOMM
        # currently registers COM6 to BthModem7 means every open reaches a stale
        # device object: CreateFile succeeds or times out against something the
        # driver has already abandoned. Symptomatically that is ERROR_SEM_TIMEOUT,
        # i.e. it is indistinguishable from FI-012 fault 2 (device not answering)
        # unless this comparison is made -- and the remedy is the opposite one
        # (reboot, not a radio toggle). Only meaningful when the symlink layer was
        # actually read AND the name resolved; otherwise $null, not $false.
        $targetRegistered = $null
        if ($symlinkOk) {
            $targetRegistered = [bool]@($deviceObjects | Where-Object {
                $_ -and $symlink -and ($_.Trim() -ieq $symlink.Trim())
            }).Count
        }

        if ($owners.Count -gt 1)                 { $result.CollisionCount++ }
        if ($SymlinksValid -and -not $symlinkOk) { $result.MissingSymlinkCount++ }
        if ($targetRegistered -eq $false)        { $result.DanglingSymlinkCount++ }

        $result.Entries += [PSCustomObject]@{
            ComName                 = $name
            OwnerCount              = $owners.Count
            DeviceObjects           = $deviceObjects
            IsBluetooth             = [bool]@($owners | Where-Object { $_.DeviceObject -match 'BthModem|RFCOMM|BTHMODEM' }).Count
            Symlink                 = $symlink
            SymlinkOk               = $symlinkOk
            SymlinkTargetRegistered = $targetRegistered
            Collision               = ($owners.Count -gt 1)
        }
    }

    foreach ($e in ($result.Entries | Where-Object { $_.Collision })) {
        $result.Healthy = $false
        $result.Findings += "COLLISION: $($e.ComName) claimed by $($e.OwnerCount) device objects ($($e.DeviceObjects -join ', '))"
    }
    foreach ($e in ($result.Entries | Where-Object { $_.SymlinkOk -eq $false })) {
        $result.Healthy = $false
        $result.Findings += "SYMLINK ABSENT: $($e.ComName) is registered but \GLOBAL??\$($e.ComName) does not resolve ($($e.Symlink)) - CreateFile returns ERROR_FILE_NOT_FOUND and the app reports the port as invalid"
    }
    foreach ($e in ($result.Entries | Where-Object { $_.SymlinkTargetRegistered -eq $false })) {
        $result.Healthy = $false
        $result.Findings += "SYMLINK STALE: $($e.ComName) resolves to $($e.Symlink), which is NOT among the $($e.OwnerCount) device object(s) currently registered for it ($($e.DeviceObjects -join ', ')) - opens reach an abandoned device object and time out (ERROR_SEM_TIMEOUT), which looks exactly like a device that is not answering. It is not: the serial stack is stale and the fix is a reboot, NOT a radio toggle."
    }
    if (-not $result.SymlinksChecked) {
        $result.Findings += "NOTE: symlink layer not readable - collision findings only"
    }

    if (-not $result.Healthy) {
        $result.Summary = "$($result.EntryCount) SERIALCOMM entries for $($result.ComNameCount) COM name(s); $($result.CollisionCount) collided, $($result.MissingSymlinkCount) symlink(s) absent, $($result.DanglingSymlinkCount) symlink(s) stale"
        $result.Recommendation = "REBOOT - do not unpair. HKLM\HARDWARE is volatile and rebuilt at boot, which clears the duplicate registrations and restores the COM symlinks. Unpairing/re-pairing does not fix this and adds another colliding generation."
    } else {
        $result.Summary = "$($result.EntryCount) SERIALCOMM entries for $($result.ComNameCount) COM name(s); no collisions, all symlinks resolve to a registered device object"
    }

    return $result
}

function Initialize-RegistryKeyTimeApi {
    <#
    .SYNOPSIS
        Loads the RegQueryInfoKey P/Invoke used to read a registry key's
        last-write time. Idempotent.
    .DESCRIPTION
        PowerShell exposes no last-write time for a registry key, yet that one
        value is what separates "this pairing record was just written by a
        successful pair" from "this is a stale record an unpair left behind".
        See Get-BluetoothOrphanPairingRecord for why the distinction decides the
        diagnosis.
    .OUTPUTS
        [bool] $true if the API is available, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:RegistryKeyTimeApiAvailable) { return $true }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'WinConfigRegKeyTime').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
public static class WinConfigRegKeyTime {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKey(
        IntPtr hKey, IntPtr cls, IntPtr clsLen, IntPtr reserved,
        IntPtr subKeys, IntPtr maxSubKeyLen, IntPtr maxClassLen,
        IntPtr values, IntPtr maxValueNameLen, IntPtr maxValueLen,
        IntPtr securityDescriptor, out long lastWriteTime);

    // Returns a DateTime, or null when the key cannot be interrogated. Never
    // throws - an unreadable timestamp must degrade the report, not fail it.
    public static object Get(string subKeyPath) {
        RegistryKey key = null;
        try {
            key = Registry.LocalMachine.OpenSubKey(subKeyPath);
            if (key == null) { return null; }
            long ft;
            int rc = RegQueryInfoKey(key.Handle.DangerousGetHandle(),
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
            if (rc != 0) { return null; }
            return DateTime.FromFileTime(ft);
        } catch {
            return null;
        } finally {
            if (key != null) { key.Close(); }
        }
    }
}
'@ -ErrorAction Stop
        }
        $script:RegistryKeyTimeApiAvailable = $true
        return $true
    } catch {
        return $false
    }
}

function Test-BluetoothOrphanPairingRecord {
    <#
    .SYNOPSIS
        Pure verdict function. Correlates BTHPORT pairing records against PnP
        device nodes and reports classic records that exist in the registry but
        have no device node anywhere. Evidence about a named target device, not
        a fleet health verdict.
    .DESCRIPTION
        Split out from Get-BluetoothOrphanPairingRecord so the detection logic
        can be tested against captured data without needing a machine in the
        broken state. Takes no live dependencies.

        FI-014. A device removal deletes the PnP nodes but can leave
        HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\<mac>
        behind, so the registry says the device is known while Windows shows it
        as not paired and no DEV_ node, SPP node or COM port exists.

        A NODELESS RECORD IS ORDINARY REMOVAL RESIDUE, NOT A FAULT. Measured on
        the dev box 2026-08-06: removing the headset in NO.exe's own device
        panel left a nodeless record (n=2), and the CONTROL - removing it
        through Windows Settings instead - left the same residue. Both routes
        go through DeviceAssociationService, so this is what a removal does on
        this box and stack, not something an application did wrong. Anyone who
        has ever removed a Bluetooth device has such a record. Reporting that
        as unhealthy marks a healthy box broken.

        So the verdict is SCOPED. Without -TargetMac/-TargetName this function
        reports nodeless classic records as State='Residue' and stays
        Healthy - it is describing the box, and it cannot know which device the
        operator expects to be paired. Given a target, a nodeless record for
        THAT device is State='Orphan' and turns the verdict unhealthy, because
        that is the actual FI-014 incident shape: someone believes a device is
        paired and it has no node.

        WHAT THIS CHECK DOES AND DOES NOT CLAIM. The record-with-no-node state
        is measured and real. That the record CAUSES the blockage is not: on
        2026-08-06 a re-pair was run against an orphan of fully known
        provenance - minted 10 minutes earlier by a device removal - with the
        record deliberately LEFT IN PLACE, and a plain Windows Settings pair
        restored all four nodes on the first attempt. An orphan record alone is
        therefore NOT sufficient to block pairing. The 2026-07-30 blockage was
        real (zero BTHENUM entries measured across a whole boot session), but
        the missing ingredient is still unknown - candidates are record age,
        the SYSTEM-only Parameters\Keys\<adapter>\<mac> link key, and adapter
        stack state. So report the record, recommend pairing FIRST, and treat
        deleting it as the fallback rather than the fix.

        Detection still runs BEFORE the FI-012 triage tree, because neither
        FI-012 remedy clears a non-volatile registry record: a reboot does not
        (HKLM\SYSTEM survives it) and a radio toggle does not either.

        LOW ENERGY DEVICES ARE NOT ORPHANS. An LE device only materialises
        BTHLEDEVICE/BTHLE nodes while it is connected, so a remembered LE device
        that is merely out of range legitimately has a record and no node.
        Observed on the dev box 2026-07-30: a paired iPhone (7880363030a5) had
        no node and was perfectly healthy. Classic devices behave the opposite
        way - they keep their BTHENUM DEV_ node whether connected or not, which
        the same capture confirms: the Satechi keyboard read Connected=False and
        still had a Status OK DEV_ node. So a classic record with zero nodes is
        a real defect; an LE record with zero nodes is merely dormant.

        NEITHER IS AN INQUIRY SIGHTING. Windows writes a Devices\<mac> subkey
        for a device it has merely SEEN during an inquiry, with no pairing of
        any kind. That record blocks nothing and needs no action, but the old
        logic counted it as an orphan: a 30s scan run on the dev box 2026-08-06
        created one and OrphanCount immediately read 2. Measured against the two
        Arc records live on that box the same day:

                          sighting (8c1f6471000d)   pairing (8c1f64710013)
          Name              ABSENT                    "NeurOptimal Arc - 000019"
          LastConnected     0                         nonzero FILETIME
          LastSeen          nonzero                   nonzero
          COD               0                         0
          FriendlyName      0x00                      0x00
          subkeys           ServicesFor<radio> only   + CachedServices,
                                                        DynamicCachedServices

        So Name and LastConnected are the discriminators and they agree. COD and
        FriendlyName are NOT - both read identically on the two records, even
        though a .reg export of the pairing taken hours earlier had COD 0x080710
        (Windows rewrites it), which is exactly the trap of trusting one value.
        Requiring BOTH signals keeps a real pairing with an unreadable Name on
        the orphan side, where a false positive is the cheaper mistake.
    .PARAMETER Records
        Array of objects with Mac (12 hex chars, no separators), Name,
        IsLowEnergy, and optionally LastWrite, HasName and EverConnected, as
        read from BTHPORT. A record that omits HasName/EverConnected is treated
        as a real pairing.
    .PARAMETER PnpInstanceIds
        Every PnP instance ID on the box, including non-present devices. Must be
        the unfiltered set: filtering to present devices would report every
        powered-off classic device as an orphan.
    .PARAMETER TargetMac
        The device the operator expects to be paired, as a MAC in any
        separator style. Only a nodeless record for this device is treated as
        a fault; everything else nodeless stays Residue.
    .PARAMETER TargetName
        Same, matched against the record Name instead. A pattern containing
        *, ? or [ is used verbatim as a -like pattern; anything else is matched
        as a substring, so -TargetName 'Arc' finds 'NeurOptimal Arc - 000019'.
    .OUTPUTS
        [hashtable] Healthy, Scoped, TargetMac, TargetName, TargetState,
        OrphanCount, ResidueCount, DormantCount, SightingCount, RecordCount,
        Records, Findings, Summary, Recommendation, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Records,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$PnpInstanceIds,
        [string]$TargetMac,
        [string]$TargetName
    )

    # Normalise the target once. A MAC arrives in any separator style; a name
    # without wildcard characters is matched as a substring so a tech can pass
    # the word they know rather than the exact registry Name.
    $targetHex   = ''
    if ($TargetMac) { $targetHex = (([string]$TargetMac) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() }
    $namePattern = ''
    if ($TargetName) {
        $namePattern = if ($TargetName -match '[\*\?\[]') { $TargetName } else { "*$TargetName*" }
    }
    $scoped = [bool]($targetHex -or $namePattern)

    $result = @{
        Healthy        = $true
        Scoped         = $scoped
        TargetMac      = $(if ($targetHex) { $targetHex } else { $null })
        TargetName     = $(if ($TargetName) { $TargetName } else { $null })
        TargetState    = $(if ($scoped) { 'NoRecord' } else { $null })
        OrphanCount    = 0
        ResidueCount   = 0
        DormantCount   = 0
        SightingCount  = 0
        RecordCount    = $Records.Count
        Records        = @()
        Findings       = @()
        Summary        = $null
        Recommendation = $null
        Error          = $null
    }

    if ($Records.Count -eq 0) {
        $result.Summary = "No Bluetooth pairing records found"
        return $result
    }

    foreach ($rec in $Records) {
        $mac = ([string]$rec.Mac) -replace '[^0-9A-Fa-f]', ''

        # Instance IDs carry the MAC uppercase and unseparated, in several
        # shapes: BTHENUM\DEV_<mac>\..., BTHLE\DEV_<mac>\..., and the service
        # children BTHENUM\{guid}_VID&..\7&<radio>&0&<mac>_C0000000N. A
        # substring match covers all of them. The radio instance fragment is
        # only 8 hex characters so it cannot collide with a 12-character MAC.
        $nodes = @()
        if ($mac) {
            $nodes = @($PnpInstanceIds | Where-Object { $_ -and ([string]$_) -like "*$mac*" })
        }

        $isLe    = [bool]$rec.IsLowEnergy
        $hasNode = ($nodes.Count -gt 0)

        # Both signals must say "never bonded" before we dismiss a record.
        # -eq $false rather than -not: a record that carries neither property is
        # an older capture, and must keep its original Orphan reading.
        $neverNamed     = ($rec.HasName -eq $false)
        $neverConnected = ($rec.EverConnected -eq $false)
        $isSighting     = ($neverNamed -and $neverConnected)

        # A record is the operator's target if either signal names it. Matching
        # on the record we are already walking keeps MAC and name scoping in
        # one place, so a caller can pass whichever identifier they have.
        $isTarget = $false
        if ($scoped) {
            if ($targetHex -and $mac.ToUpperInvariant() -eq $targetHex) { $isTarget = $true }
            if (-not $isTarget -and $namePattern -and (([string]$rec.Name) -like $namePattern)) { $isTarget = $true }
        }

        # Orphan is reserved for the scoped target. Every other nodeless classic
        # record is Residue: measured, reported, and not a fault, because the
        # Settings-removal control produces exactly the same thing.
        $state = if ($hasNode)   { 'Paired' }
                 elseif ($isLe)  { 'Dormant' }
                 elseif ($isSighting) { 'Sighting' }
                 elseif ($isTarget)   { 'Orphan' }
                 else            { 'Residue' }

        if ($state -eq 'Orphan')   { $result.OrphanCount++ }
        if ($state -eq 'Residue')  { $result.ResidueCount++ }
        if ($state -eq 'Dormant')  { $result.DormantCount++ }
        if ($state -eq 'Sighting') { $result.SightingCount++ }

        if ($isTarget -and ($result.TargetState -eq 'NoRecord' -or $state -eq 'Orphan')) {
            $result.TargetState = $state
        }

        $result.Records += [PSCustomObject]@{
            Mac           = $mac
            Name          = $rec.Name
            IsLowEnergy   = $isLe
            NodeCount     = $nodes.Count
            Nodes         = $nodes
            LastWrite     = $rec.LastWrite
            HasName       = $rec.HasName
            EverConnected = $rec.EverConnected
            IsTarget      = $isTarget
            State         = $state
        }
    }

    foreach ($r in @($result.Records | Where-Object { $_.State -eq 'Orphan' })) {
        $result.Healthy = $false
        $stamp = if ($r.LastWrite) { " Record last written $($r.LastWrite)." } else { '' }
        $result.Findings += "ORPHAN PAIRING RECORD: '$($r.Name)' ($($r.Mac)) has a BTHPORT record but NO PnP device node.$stamp Windows will show it as not paired, and there are no SPP nodes and no COM port. Reboot and radio toggle leave the record untouched. A record on its own does NOT always block pairing - one was re-paired successfully with the record left in place - so try pairing before deleting anything."
    }

    $benign = ''
    if ($result.DormantCount -gt 0)  { $benign += "; $($result.DormantCount) dormant LE record(s), which is normal" }
    if ($result.SightingCount -gt 0) { $benign += "; $($result.SightingCount) inquiry sighting(s) - devices this box merely saw, never paired with, which block nothing" }

    $residue = ''
    if ($result.ResidueCount -gt 0) {
        $names = @($result.Records | Where-Object { $_.State -eq 'Residue' } |
            ForEach-Object { "'$($_.Name)' ($($_.Mac))" }) -join ', '
        $residue = "; $($result.ResidueCount) classic record(s) with no current device node - $names - which is the ordinary residue of removing a device and needs no action unless one of them is the device you are trying to pair"
    }

    if (-not $result.Healthy) {
        $result.Summary = "$($result.RecordCount) pairing record(s); the target device has a BTHPORT record but no device node$benign$residue"
        $result.Recommendation = "TRY PAIRING FIRST: power-cycle the headset, close NO.exe, and pair through Windows Settings. An orphan record does not always block pairing - one was re-paired successfully with the record left in place. ONLY IF that fails, DELETE the orphaned record(s) under HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices, then toggle the Bluetooth radio and pair again; BUILTIN\Administrators has FullControl on those keys, so this needs elevation but not SYSTEM, and export the key first. Do NOT reboot or toggle the radio expecting either to clear the record - neither touches a non-volatile registry key."
    } elseif ($scoped) {
        $who = if ($TargetName) { "'$TargetName'" } else { $targetHex }
        $lead = switch ($result.TargetState) {
            'Paired'   { "target $who has a device node" }
            'Dormant'  { "target $who is a remembered LE device with no node, which is normal for LE" }
            'Sighting' { "target $who was only ever seen in an inquiry, never paired with this box" }
            default    { "no BTHPORT pairing record for target $who" }
        }
        $result.Summary = "$($result.RecordCount) pairing record(s); $lead$benign$residue"
    } elseif ($result.ResidueCount -gt 0) {
        # No target was named, so there is nothing to call a fault. Say what is
        # there and say what would make it matter.
        $result.Summary = "$($result.RecordCount) pairing record(s); no target device given, so nothing here is a fault$benign$residue"
    } else {
        $result.Summary = "$($result.RecordCount) pairing record(s); every classic record has a device node$benign"
    }

    return $result
}

function Get-BluetoothOrphanPairingRecord {
    <#
    .SYNOPSIS
        Detects FI-014: BTHPORT pairing records that have no corresponding PnP
        device node. Such a record marks the FI-014 no-node state and can
        accompany a failed re-pair; it is not proven to cause one. Pass
        -TargetMac/-TargetName to get a verdict rather than an inventory.
    .DESCRIPTION
        Reads every subkey of
        HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices and
        cross-checks each MAC against the unfiltered PnP device list. See
        Test-BluetoothOrphanPairingRecord for the fault mechanism, for why LE
        records are exempt, and for why an unscoped run reports Residue and
        stays Healthy.

        The per-record LastWrite timestamp is best-effort and worth having: a
        child key's timestamp moves when its VALUES change, a parent's only when
        a subkey is added or removed. On the dev box 2026-07-30 the child read
        "written today" while the parent read "yesterday", which proved the
        subkey was a pre-existing orphan being rewritten rather than a fresh
        pairing - the single observation that identified the fault.

        Requires elevation to read the Devices subtree. Read-only; makes no
        changes.
    .PARAMETER TargetMac
        The device the operator expects to be paired. See
        Test-BluetoothOrphanPairingRecord.
    .PARAMETER TargetName
        Same, matched against the record Name. Substring unless it carries a
        wildcard character.
    .OUTPUTS
        [hashtable] As Test-BluetoothOrphanPairingRecord, plus ParentLastWrite.
    #>
    [CmdletBinding()]
    param(
        [string]$TargetMac,
        [string]$TargetName
    )

    $devicesPath = 'SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
    $records      = @()
    $instanceIds  = @()
    $parentWrite  = $null
    $collectError = $null

    $haveTimeApi = Initialize-RegistryKeyTimeApi

    try {
        if ($haveTimeApi) { $parentWrite = [WinConfigRegKeyTime]::Get($devicesPath) }

        $hive = "HKLM:\$devicesPath"
        if (Test-Path $hive) {
            foreach ($key in @(Get-ChildItem $hive -ErrorAction Stop)) {
                $mac   = $key.PSChildName
                $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue

                $valueNames = @()
                if ($props) {
                    $valueNames = @($props.PSObject.Properties |
                        Where-Object { $_.Name -notlike 'PS*' } |
                        Select-Object -ExpandProperty Name)
                }

                # Name is REG_BINARY UTF8 with a trailing NUL on most stacks, but
                # a plain string on some. Handle both rather than printing a byte
                # array into a finding.
                $name = $null
                if ($props) {
                    $name = $props.Name
                    if ($name -is [byte[]]) {
                        $name = [Text.Encoding]::UTF8.GetString($name).Trim([char]0)
                    }
                }
                $hasName = ($valueNames -contains 'Name') -and -not [string]::IsNullOrWhiteSpace([string]$name)
                if (-not $name) { $name = "(unnamed $mac)" }

                # LastConnected is REG_QWORD (hex(b) in a .reg export), so it
                # arrives as an int64; tolerate a REG_BINARY FILETIME anyway.
                # Zero means this box has never completed a connection to the
                # device, which together with a missing Name is the inquiry
                # sighting signature - see Test-BluetoothOrphanPairingRecord.
                $lastConn = 0L
                if ($props -and ($valueNames -contains 'LastConnected')) {
                    $raw = $props.LastConnected
                    if ($raw -is [byte[]]) {
                        if ($raw.Count -ge 8) { $lastConn = [BitConverter]::ToInt64($raw, 0) }
                    } else {
                        $lastConn = [int64]($raw -as [int64])
                    }
                }

                # LE pairings carry LE-specific values. Classic ones do not.
                $isLe = [bool]@($valueNames | Where-Object {
                    $_ -in @('LEName', 'LEAddressType', 'LEAppearance', 'LocalEvaldIoCapLE', 'LeContainerId')
                }).Count

                $records += [PSCustomObject]@{
                    Mac           = $mac
                    Name          = [string]$name
                    IsLowEnergy   = $isLe
                    HasName       = $hasName
                    EverConnected = ($lastConn -ne 0)
                    LastWrite     = $(if ($haveTimeApi) { [WinConfigRegKeyTime]::Get("$devicesPath\$mac") } else { $null })
                }
            }
        }

        # Unfiltered on purpose. Get-PnpDevice with no -Status returns present
        # and non-present nodes alike; narrowing to present would report every
        # powered-off classic device as an orphan.
        $instanceIds = @(Get-PnpDevice -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InstanceId)
    } catch {
        $collectError = $_.Exception.Message
    }

    $verdict = Test-BluetoothOrphanPairingRecord -Records $records -PnpInstanceIds $instanceIds `
        -TargetMac $TargetMac -TargetName $TargetName
    $verdict.ParentLastWrite = $parentWrite
    $verdict.Error = $collectError
    if ($collectError) {
        $verdict.Summary = "Orphan pairing record check failed: $collectError"
    }

    return $verdict
}

function Select-BluetoothSessionTarget {
    <#
    .SYNOPSIS
        Pure. Picks THE headset a recording is about, or refuses to pick.
    .DESCRIPTION
        Field bug (capture 8E39860E4AF2, 2026-08-07): the operator ran a clean
        37-minute session on Arc 000013 while the recorder watched Arc 000019 --
        powered off, in a drawer -- for the entire recording. It reported two
        problems and "this session did NOT end clean". Every statement in that
        capture was true of 019 and none of it was about the session.

        Cause: the recorder took `$pnp.Devices | Where FriendlyName -match
        'NeurOptimal' | Select -First 1`. With two Arcs paired, first-match wins
        over an unordered enumeration and the operator is never told a choice
        was made. A second selector (the FI-012 fingerprint) ran its own
        name-regex over the WinRT device list and picked the OTHER Arc, so one
        capture disagreed with itself about which headset it described.

        This is deliberately NOT a stable sort. A stable sort still silently
        chooses, and choosing wrong is the failure being fixed -- it just makes
        the wrong choice reproducible. Automatic selection requires POSITIVE
        EVIDENCE that exactly one candidate is the session device:

          exactly one candidate                  -> Automatic  (nothing to confuse)
          exactly one holds a COM port           -> Automatic  (the session device)
          anything else                          -> AmbiguousRequiresChoice

        A held COM port is the evidence used because it is the only signal that
        means "a process is talking to this headset right now". WinRT
        IsConnected is NOT used and must not be: SPP devices hold no profile
        open, so a healthy idle Arc reads Disconnected, and during the FI-012
        field case IsConnected read False while both ports opened fine. Ranking
        on it would reintroduce this bug with a confident-looking tie-break.

        Never silently narrows: every candidate and its evidence is returned
        whatever the outcome, so a capture records the choice that was available
        and not merely the one that was taken.
    .PARAMETER Candidates
        Objects carrying Mac, Name, and the per-candidate evidence:
        Present, HeldPorts, ComPorts, HasPairingRecord. The caller gathers these
        (it is I/O); this function only decides.
    .PARAMETER ExplicitMac
        An operator-chosen MAC. Wins over everything -- an explicit choice is
        not second-guessed, and it is recorded as Explicit so a reader can tell
        a human decision from an inference.
    .PARAMETER HeldPortEvidenceAvailable
        Whether anything actually LOOKED at the candidates' COM ports. Defaults
        to $true, which is every pre-existing caller and the shipped behaviour.

        It exists because with the active port-open probe disabled
        (ActivePortOpenProbeEnabled = $false) the caller cannot gather held
        ports at all, and passes $null for every candidate. Without this
        parameter the tie-breaker below would read those nulls as "no candidate
        is holding a port" and fall through to AmbiguousRequiresChoice with the
        summary "NONE is holding a COM port" -- a confident statement about
        hardware nobody examined, on the screen the operator uses to decide
        which headset the recording is about.

        Selection stays DETERMINISTIC either way: a single candidate is still
        automatic (it needs no tie-breaker), an explicit choice still wins, and
        anything else asks. What changes is only that the ambiguity says why.
    .OUTPUTS
        [pscustomobject] Mac, Name, Mode, Reason, Candidates, IsResolved,
        RequiresOperatorChoice, Summary, HeldPortEvidenceAvailable.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][array]$Candidates = @(),
        [string]$ExplicitMac,
        [bool]$HeldPortEvidenceAvailable = $true
    )

    $norm = { param($m) ([string]$m -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() }

    $cands = @($Candidates | Where-Object { $_ } | ForEach-Object {
        [pscustomobject]@{
            Mac              = & $norm $_.Mac
            Name             = [string]$_.Name
            Present          = [bool]$_.Present
            # $null survives as $null when no sensor looked. Collapsing it to
            # @() here would erase the distinction one layer below the decision
            # that depends on it.
            # Leading comma -- `$(if (..) { @() })` is $null, not an empty array,
            # and here that would turn an examined-and-idle candidate into an
            # unexamined one.
            HeldPorts        = $(if ($HeldPortEvidenceAvailable) { ,@($_.HeldPorts | Where-Object { $_ }) } else { $null })
            ComPorts         = @($_.ComPorts  | Where-Object { $_ })
            HasPairingRecord = [bool]$_.HasPairingRecord
        }
    })

    $result = [pscustomobject]@{
        PSTypeName             = 'WinConfig.FlightRecorder.SessionTarget'
        Mac                    = $null
        Name                   = $null
        Mode                   = 'None'
        Reason                 = $null
        Candidates             = $cands
        CandidateCount         = $cands.Count
        IsResolved             = $false
        RequiresOperatorChoice = $false
        Summary                = $null
        # Recorded on the result, not only consumed, so a capture says whether
        # the tie-breaker was even available rather than leaving a reader to
        # infer it from an absent field.
        HeldPortEvidenceAvailable = [bool]$HeldPortEvidenceAvailable
    }

    # An explicit choice is a decision, not a hypothesis. Honour it even if the
    # device looks idle -- an operator about to power a headset on knows
    # something the evidence cannot show yet.
    $explicit = & $norm $ExplicitMac
    if ($explicit) {
        $match = @($cands | Where-Object { $_.Mac -eq $explicit })[0]
        $result.Mac        = $explicit
        $result.Name       = if ($match) { $match.Name } else { $null }
        $result.Mode       = 'Explicit'
        $result.Reason     = 'OperatorSelected'
        $result.IsResolved = $true
        $result.Summary    = "Target chosen by the operator: $(if ($result.Name) { "'$($result.Name)' " })$explicit"
        return $result
    }

    if ($cands.Count -eq 0) {
        $result.Reason  = 'NoCandidates'
        $result.Summary = 'No NeurOptimal headset found on this box, so no target could be selected.'
        return $result
    }

    if ($cands.Count -eq 1) {
        $result.Mac        = $cands[0].Mac
        $result.Name       = $cands[0].Name
        $result.Mode       = 'Automatic'
        $result.Reason     = 'SingleCandidate'
        $result.IsResolved = [bool]$cands[0].Mac
        $result.Summary    = "Target '$($cands[0].Name)' ($($cands[0].Mac)) -- the only NeurOptimal headset on this box."
        if (-not $result.IsResolved) {
            $result.Reason  = 'SingleCandidateNoMac'
            $result.Summary = "Found '$($cands[0].Name)' but could not read its MAC address, so the target cannot be pinned."
        }
        return $result
    }

    # More than one. Only a held COM port earns an automatic choice -- and only
    # if a held COM port was actually LOOKED FOR. With the active port-open
    # probe disabled this evidence does not exist, so the tie-breaker is skipped
    # outright rather than evaluated over nulls: an unexamined candidate must
    # never be ranked below an equally unexamined one on the strength of a set
    # that was never populated.
    $active = @(if ($HeldPortEvidenceAvailable) { $cands | Where-Object { @($_.HeldPorts).Count -gt 0 } })
    if ($HeldPortEvidenceAvailable -and $active.Count -eq 1 -and $active[0].Mac) {
        $result.Mac        = $active[0].Mac
        $result.Name       = $active[0].Name
        $result.Mode       = 'Automatic'
        $result.Reason     = 'SoleActiveComPort'
        $result.IsResolved = $true
        $result.Summary    = "$($cands.Count) NeurOptimal headsets are paired; selected '$($active[0].Name)' ($($active[0].Mac)) because it is the only one whose COM port ($($active[0].HeldPorts -join ', ')) is currently held by a process."
        return $result
    }

    $result.Mode                   = 'AmbiguousRequiresChoice'
    $result.RequiresOperatorChoice = $true
    $names = @($cands | ForEach-Object { "'$($_.Name)' ($($_.Mac))" }) -join ', '
    $result.Reason =
        if (-not $HeldPortEvidenceAvailable) { 'NoHeldPortEvidence' }
        elseif ($active.Count -gt 1)         { 'MultipleActive' }
        else                                 { 'NoActiveCandidate' }
    $result.Summary =
        if (-not $HeldPortEvidenceAvailable) {
            # Says what was NOT done, and does not say the ports are free.
            "$($cands.Count) NeurOptimal headsets are paired ($names) and the active port-open probe is DISABLED for this recording, so nothing checked which of them is holding a COM port. That check is the only evidence this recorder uses to choose automatically, so the choice has to be yours. This is not a report that the ports are free."
        } elseif ($active.Count -gt 1) {
            "$($cands.Count) NeurOptimal headsets are paired and $($active.Count) of them are holding COM ports ($names). The recording cannot tell which one this session is about -- choose it, or the capture will describe the wrong headset."
        } else {
            "$($cands.Count) NeurOptimal headsets are paired and NONE is holding a COM port ($names). Nothing distinguishes them, so the recording cannot tell which one this session is about. Power on and connect the headset you are about to use, or choose it explicitly."
        }
    return $result
}

function Resolve-BluetoothTargetMac {
    <#
    .SYNOPSIS
        Picks the MAC to scope a target-context check to, preferring the live
        PnP node and falling back to the BTHPORT pairing record.

        ⛔ NOT A MULTI-DEVICE SESSION RESOLVER. Use Select-BluetoothSessionTarget
        to decide WHICH headset a recording is about; use this only to scope a
        check once that decision has been made. Two reasons it cannot do the
        session job: it trusts the PnpMac it is handed without validating it
        against anything, and when it does fall back it deliberately ranks the
        NODELESS record first -- the device most interesting for FI-014, which is
        precisely the device NOT in a live clinical session.
    .DESCRIPTION
        The Flight Recorder resolves its target from the PnP device list, which
        works right up to the moment it matters: FI-014's whole signature is a
        device with a pairing record and NO PnP node, so the PnP lookup returns
        nothing precisely when the orphan check has something to say. Scoping on
        the PnP MAC alone would leave every real FI-014 capture unscoped, and an
        unscoped scan is Healthy by construction.

        So when PnP has no MAC, fall back to the pairing records themselves and
        match on name. A nodeless candidate is preferred over one with nodes -
        that is the device in trouble - and ties break on the most recently
        written record.

        ⚠️ A SIGHTING CANNOT BE RESOLVED BY NAME. Windows writes no Name value
        for a device it has merely seen in an inquiry, so a never-paired headset
        has a record whose Name this function can never match. Verified live
        2026-08-07: Arc 000013's sighting record 8c1f6471000d resolves to
        NoRecord by name and to Sighting by MAC. If the caller knows the MAC
        from elsewhere - an operator typed it, or an inquiry scan found it -
        pass it as PnpMac; there is no name-based route to that record.
    .PARAMETER PnpMac
        MAC read from the PnP instance id, when the device has a node.
    .PARAMETER Records
        Records array from Get-BluetoothOrphanPairingRecord, carrying Mac, Name,
        State and LastWrite.
    .PARAMETER NamePattern
        Regex matched against the record Name. Defaults to the NeurOptimal
        headset family.
    .OUTPUTS
        [hashtable] Mac, Source (PnpNode|PairingRecord|None), Candidates,
        Summary
    #>
    [CmdletBinding()]
    param(
        [string]$PnpMac,
        [array]$Records = @(),
        [string]$NamePattern = 'NeurOptimal|Arc'
    )

    $result = @{
        Mac        = $null
        Source     = 'None'
        Candidates = @()
        Summary    = $null
    }

    $hex = ([string]$PnpMac) -replace '[^0-9A-Fa-f]', ''
    if ($hex) {
        $result.Mac     = $hex.ToUpperInvariant()
        $result.Source  = 'PnpNode'
        $result.Summary = "Target resolved from its live PnP node ($($result.Mac))"
        return $result
    }

    # No node. This is the FI-014 shape, so look in the records themselves.
    $named = @($Records | Where-Object {
        $_ -and $_.Name -and ([string]$_.Name) -match $NamePattern
    })
    $result.Candidates = @($named | ForEach-Object {
        [PSCustomObject]@{ Mac = $_.Mac; Name = $_.Name; State = $_.State; LastWrite = $_.LastWrite }
    })

    if ($named.Count -eq 0) {
        $result.Summary = "No PnP node and no pairing record matching '$NamePattern'. Nothing to scope to - the check will run unscoped and report an inventory only. A never-paired device is expected to land here: its record carries no Name."
        return $result
    }

    # The nodeless one is the interesting one; among equals, the freshest.
    $ranked = @($named | Sort-Object `
        @{ Expression = { if ($_.State -eq 'Paired') { 1 } else { 0 } } }, `
        @{ Expression = { $_.LastWrite }; Descending = $true })

    $pick = $ranked[0]
    $result.Mac    = ([string]$pick.Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $result.Source = 'PairingRecord'
    $extra = if ($named.Count -gt 1) { " ($($named.Count) records matched; picked the nodeless/most recent)" } else { '' }
    $result.Summary = "Target has no PnP node; resolved from its BTHPORT pairing record '$($pick.Name)' ($($result.Mac))$extra"

    return $result
}

function Get-BluetoothPowerCycleContext {
    <#
    .SYNOPSIS
        Boot time and the number of sleep/resume transitions since that boot.
    .DESCRIPTION
        FI-012's causal claim is that the Bluetooth serial driver re-registers
        its COM names on resume without tearing down the previous generation,
        so each resume leaves another SERIALCOMM entry behind and eventually
        the \GLOBAL??\COMx symlink is lost in the collision.

        That is currently a STORY, told from one box. It only becomes evidence
        if the resume count is captured next to the collision count on every
        run: if excess registrations track resumes across the fleet, the claim
        holds; if a box collides at zero resumes, the trigger is something else
        and the reboot advice needs a different rationale. HKLM\HARDWARE is
        volatile, so both numbers are scoped to the same boot session and are
        directly comparable.

        Read-only. Returns nulls rather than throwing when the event log is
        unreadable (non-admin, cleared log, rolled over).
    .OUTPUTS
        [hashtable] Available, LastBootTime, UptimeHours, ResumeCount,
        SleepCount, EventsRead, Error
    #>
    [CmdletBinding()]
    param()

    $ctx = @{
        Available    = $false
        LastBootTime = $null
        UptimeHours  = $null
        ResumeCount  = $null
        SleepCount   = $null
        EventsRead   = $false
        Error        = $null
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os -and $os.LastBootUpTime) {
            $ctx.LastBootTime = $os.LastBootUpTime
            $ctx.UptimeHours  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
            $ctx.Available    = $true
        }
    } catch {
        $ctx.Error = $_.Exception.Message
        return $ctx
    }

    # Kernel-Power 107 = resume from sleep/hibernate, 42 = entering sleep. Scoped
    # to the current boot because that is the window SERIALCOMM covers. A failure
    # here leaves the counts $null (unknown), which is NOT the same as 0 and must
    # not be reported as "no resumes" -- the correlation below treats them apart.
    try {
        $filter = @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Power'
            StartTime    = $ctx.LastBootTime
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                    Where-Object { $_.Id -in @(42, 107) })
        $ctx.ResumeCount = @($events | Where-Object { $_.Id -eq 107 }).Count
        $ctx.SleepCount  = @($events | Where-Object { $_.Id -eq 42  }).Count
        $ctx.EventsRead  = $true
    } catch {
        # No matching events is thrown as an error by Get-WinEvent, not returned
        # as an empty set. That case is a real zero, not an unknown.
        if ($_.Exception.Message -match 'No events were found') {
            $ctx.ResumeCount = 0
            $ctx.SleepCount  = 0
            $ctx.EventsRead  = $true
        } else {
            $ctx.Error = $_.Exception.Message
        }
    }

    return $ctx
}

function Get-SerialRegistrationCorrelation {
    <#
    .SYNOPSIS
        Pure. Tests the FI-012 causal hypothesis against one box's numbers.
    .DESCRIPTION
        SERIALCOMM holds one entry per registration made during the current boot.
        A clean box has exactly one per COM name. Every extra generation is an
        un-torn-down re-registration, and the hypothesis says each of those comes
        from a resume.

        Assessment values -- deliberately NOT called a Verdict, which in this
        codebase means a DiagnosticResult (PASS/WARN/FAIL/NOT_RUN) governed by
        the DCTC contract. This is a hypothesis test, not a diagnostic verdict:
          Consistent    excess generations <= resumes; hypothesis survives
          Unexplained   excess generations > resumes; something ELSE is
                        re-registering COM names, and reboot-only advice is
                        treating a symptom
          Clean         no excess generations
          Unknown       resume count unavailable (non-admin, cleared log)
    .PARAMETER EntryCount
        Total SERIALCOMM entries.
    .PARAMETER ComNameCount
        Distinct COM names among them.
    .PARAMETER ResumeCount
        Kernel-Power 107 events since boot, or $null when unknown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$EntryCount,
        [Parameter(Mandatory)][int]$ComNameCount,
        [System.Nullable[int]]$ResumeCount
    )

    $result = @{
        Assessment         = 'Unknown'
        ExcessGenerations  = $null
        GenerationsPerName = $null
        ResumeCount        = $ResumeCount
        Summary            = $null
    }

    if ($ComNameCount -le 0) {
        $result.Summary = 'No COM names registered; nothing to correlate'
        return $result
    }

    # Round UP: 5 entries over 2 names means some name is on its third
    # generation, and rounding down would hide it.
    $perName = [math]::Ceiling($EntryCount / [double]$ComNameCount)
    $excess  = [math]::Max(0, $perName - 1)
    $result.GenerationsPerName = $perName
    $result.ExcessGenerations  = $excess

    if ($excess -eq 0) {
        $result.Assessment = 'Clean'
        $result.Summary = "1 registration per COM name; no stale generations"
        return $result
    }

    if ($null -eq $ResumeCount) {
        $result.Summary = "$excess excess registration generation(s) per COM name; resume count unavailable, so the sleep/resume hypothesis could not be tested"
        return $result
    }

    if ($excess -le $ResumeCount) {
        $result.Assessment = 'Consistent'
        $result.Summary = "$excess excess registration generation(s) per COM name against $ResumeCount resume(s) since boot - consistent with the driver re-registering on resume without tearing down the previous generation"
    } else {
        $result.Assessment = 'Unexplained'
        $result.Summary = "$excess excess registration generation(s) per COM name but only $ResumeCount resume(s) since boot - sleep/resume does NOT account for these registrations; something else is re-registering COM names on this box"
    }

    return $result
}

function Get-BluetoothRadioState {
    <#
    .SYNOPSIS
        Reads the Bluetooth radio on/off state via WinRT.
    .DESCRIPTION
        FI-012 fault 2's remedy is a radio toggle, so whether the radio was ON
        at collection time is part of the evidence: "device not answering" means
        something different on a box whose radio is off, and telling an operator
        to toggle a radio that is already off wastes a field visit.

        Read-only -- reads Radio.State, never calls SetStateAsync.
    .OUTPUTS
        [hashtable] Available, BluetoothOn (nullable bool), Radios, Adapter, Error
    #>
    [CmdletBinding()]
    param([int]$TimeoutMs = 5000)

    $result = @{
        Available   = $false
        BluetoothOn = $null
        Radios      = @()
        Adapter     = $null
        Error       = $null
    }

    # PnP first, because it answers when WinRT cannot. A radio sitting in
    # CM_PROB_DISABLED is dropped from Radio.GetRadiosAsync() enumeration
    # altogether, so WinRT alone describes it exactly the way it describes a
    # box with no Bluetooth hardware at all. That is also the one state in
    # which Windows removes the Bluetooth toggle from Settings rather than
    # greying it out, so the operator reports "Bluetooth disappeared" and the
    # probe would have agreed with them instead of naming the cause.
    $result.Adapter = Get-BluetoothRadioPnpState
    if ($result.Adapter.Disabled) {
        $result.BluetoothOn = $false
        $result.Error = "Bluetooth adapter '$($result.Adapter.FriendlyName)' is DISABLED " +
            "(CM_PROB_DISABLED). Windows hides the Bluetooth toggle entirely in this state, " +
            "so this is not missing hardware. Recover with: $($result.Adapter.Recovery)"
        return $result
    }

    try {
        if (-not (Initialize-WinRTTypes)) {
            $result.Error = 'WinRT unavailable'
            return $result
        }

        $radioType  = [Windows.Devices.Radios.Radio, Windows.Devices.Radios, ContentType = WindowsRuntime]
        $statusType = [Windows.Devices.Radios.RadioAccessStatus, Windows.Devices.Radios, ContentType = WindowsRuntime]
        $access     = Await-WinRTAsync -AsyncOp ($radioType::RequestAccessAsync()) `
                          -ResultType $statusType -TimeoutMs $TimeoutMs
        if ("$access" -ne 'Allowed') {
            $result.Error = "Radio access not granted: $access"
            return $result
        }

        $radios = Await-WinRTAsync -AsyncOp ($radioType::GetRadiosAsync()) `
                      -ResultType ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]]) `
                      -TimeoutMs $TimeoutMs
        if ($null -eq $radios) {
            $result.Error = 'Radio enumeration timed out'
            return $result
        }

        foreach ($r in $radios) {
            $result.Radios += [PSCustomObject]@{
                Name  = $r.Name
                Kind  = "$($r.Kind)"
                State = "$($r.State)"
            }
        }
        $result.Available = $true

        $bt = @($result.Radios | Where-Object { $_.Kind -eq 'Bluetooth' })
        if ($bt.Count -gt 0) {
            $result.BluetoothOn = [bool]@($bt | Where-Object { $_.State -eq 'On' }).Count
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function ConvertTo-BluetoothRadioPnpState {
    <#
    .SYNOPSIS
        Classifies a Bluetooth host radio PnP device object into a state record.
    .DESCRIPTION
        Split out from the live collector so the classification is testable
        without depending on the state of the machine running the tests. The
        case that matters is CM_PROB_DISABLED: it is an administrative disable
        that survives reboot, so "reboot and retry" -- the usual first advice --
        cannot clear it, and the operator has no toggle in Settings to undo it.

        Read-only. Takes an already-read device object, touches nothing.
    .PARAMETER Device
        A Get-PnpDevice result for the host radio, or $null if none was found.
    .OUTPUTS
        [hashtable] Present, InstanceId, FriendlyName, Status, Problem,
        Disabled, Recovery, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Device
    )

    $state = @{
        Present      = $false
        InstanceId   = $null
        FriendlyName = $null
        Status       = $null
        Problem      = $null
        Disabled     = $false
        Recovery     = $null
        Error        = $null
    }

    if ($null -eq $Device) { return $state }

    $state.Present      = $true
    $state.InstanceId   = $Device.InstanceId
    $state.FriendlyName = $Device.FriendlyName
    $state.Status       = "$($Device.Status)"
    $state.Problem      = "$($Device.Problem)"

    if ($state.Problem -eq 'CM_PROB_DISABLED') {
        $state.Disabled = $true
        $state.Recovery = "Enable-PnpDevice -InstanceId '$($Device.InstanceId)' -Confirm:`$false (run as administrator)"
    }

    return $state
}

function Get-BluetoothRadioPnpState {
    <#
    .SYNOPSIS
        Reads the host Bluetooth radio's PnP state (read-only).
    .DESCRIPTION
        Answers "is there a radio, and is Windows willing to use it", which
        WinRT cannot answer for a disabled radio because it stops enumerating
        one. Selects the host controller rather than a peripheral by instance
        id prefix: the radio enumerates under USB\ or PCI\, while paired
        devices and protocol nodes enumerate under BTHENUM\, BTHLE\,
        BTHLEDEVICE\ or BTH\MS_*.

        Read-only -- Get-PnpDevice only, never Enable/Disable.
    .OUTPUTS
        [hashtable] see ConvertTo-BluetoothRadioPnpState
    #>
    [CmdletBinding()]
    param()

    try {
        $radio = @(
            Get-PnpDevice -Class Bluetooth -ErrorAction Stop |
                Where-Object {
                    $_.InstanceId -match '^(USB|PCI)\\' -and
                    -not (Test-IsTransportOrServiceNode -Name $_.FriendlyName)
                }
        ) | Select-Object -First 1

        return ConvertTo-BluetoothRadioPnpState -Device $radio
    }
    catch {
        $state = ConvertTo-BluetoothRadioPnpState -Device $null
        $state.Error = $_.Exception.Message
        return $state
    }
}

function Get-BluetoothLinkHistory {
    <#
    .SYNOPSIS
        Reads DEVPKEY_Bluetooth_LastConnectedTime for a device MAC.
    .DESCRIPTION
        Intended as the one non-intrusive way to ask "did anything actually
        connect to this device, and when", which an open attempt answers only by
        taking the port away from whatever is using it.

        ⚠️ DO NOT TRUST THIS VALUE WITHOUT THE PredatesBoot CHECK. On
        MMEVOLD_06 (2026-07-27) it behaved as documented: frozen through the
        broken window, advancing the instant an open succeeded. On the dev box
        (2026-07-30) it was stale for EVERY paired device, measured as a
        deliberate control:

            NeurOptimal Arc   connected 12:27-13:00   reported 08:58:16
            MX Master 4       in active use           reported 07:55:43
            ORA by Kanto      IsConnected True        reported 08:09:32
            Keychron Q3 Pro   IsConnected True        no value at all
            Satechi           idle                    reported 20 days earlier

        Boot was 08:58:35, so three of those PREDATE THE BOOT they are being
        read in. A timestamp earlier than last boot cannot describe link
        activity in the current boot session, so PredatesBoot marks it unusable
        and callers must not render it as "last RFCOMM link-up". That guard
        catches the demonstrable case only; a post-boot value is not thereby
        proven correct, so this stays evidence and never a diagnosis.

        Reading the newest across all matching nodes is deliberate. On
        MMEVOLD_06 the property sat on the service child nodes (..._C0000000N);
        on the dev box it sat on the parent BLUETOOTHDEVICE node with the
        children blank. Neither placement is safe to assume.
    .PARAMETER Address
        MAC, with or without separators.
    .PARAMETER BootTime
        Last boot. Injectable so the staleness rule can be tested against
        captured data. Queried from Win32_OperatingSystem when omitted; if that
        fails, PredatesBoot is $null rather than $false - unknown, not clean.
    .OUTPUTS
        [hashtable] Address, LastConnectedTime, AgeHours, Found, BootTime,
        PredatesBoot, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Address,
        [datetime]$BootTime
    )

    $result = @{
        Address           = $Address
        LastConnectedTime = $null
        AgeHours          = $null
        Found             = $false
        BootTime          = $null
        PredatesBoot      = $null
        Error             = $null
    }

    if ($PSBoundParameters.ContainsKey('BootTime')) {
        $result.BootTime = $BootTime
    } else {
        try {
            $result.BootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
        } catch { }
    }

    # Must be a full 12-hex-digit address. A partial one is worse than none:
    # it is used as a regex against every Bluetooth InstanceId, so a 2-character
    # fragment happily matches unrelated device nodes and reports some other
    # device's LastConnectedTime as this one's.
    $bare = ($Address -replace '[^0-9A-Fa-f]', '')
    if ($bare.Length -ne 12) {
        $result.Error = "Not a usable Bluetooth address: '$Address' reduces to $($bare.Length) hex digit(s), expected 12"
        return $result
    }

    try {
        $nodes = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
                   Where-Object { $_.InstanceId -match $bare })
        $times = @()
        foreach ($n in $nodes) {
            try {
                $p = Get-PnpDeviceProperty -InstanceId $n.InstanceId `
                        -KeyName '{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 11' -ErrorAction Stop
                if ($p -and $p.Data) { $times += [datetime]$p.Data }
            } catch { }
        }
        if ($times.Count -gt 0) {
            $newest = ($times | Sort-Object -Descending)[0]
            $result.LastConnectedTime = $newest
            $result.AgeHours = [math]::Round(((Get-Date) - $newest).TotalHours, 2)
            $result.Found = $true

            # Stays $null when boot time is unknown. Unknown must not read as
            # "not stale" - that is the failure mode this whole guard exists to
            # stop.
            if ($result.BootTime) {
                $result.PredatesBoot = ($newest -lt $result.BootTime)
            }
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-SerialFaultFingerprint {
    <#
    .SYNOPSIS
        Pure. Classifies which FI-012 fault a box is in WITHOUT opening a port.
    .DESCRIPTION
        Test-BluetoothSerialPortOpen is the only thing that can CONFIRM fault 2,
        and it is operator-initiated only -- it must never run inside the Flight
        Recorder, which records live client sessions. That leaves the recorder
        reporting nothing at all for fault 2 today.

        This closes that gap as far as it honestly can, by joining the serial
        integrity verdict, the target's link state, the radio state, and
        LastConnectedTime.

        IMPORTANT -- read the FI-012 trap before strengthening any of this:
        "not connected" is NOT on its own a finding. SPP devices hold no profile
        open, so a perfectly healthy idle Arc reads Disconnected; during the
        field case IsConnected read False while both ports opened fine. So
        NoActiveLink is reported as EVIDENCE at 'Weak' confidence, never as a
        diagnosis, and LastConnectedTime is carried alongside it because that is
        the signal that actually discriminated during the field case (frozen
        through the broken window, advancing the instant an open succeeded).

        Faults:
          SerialStackBroken   fault 1 - integrity unhealthy; reboot. Confirmed.
          RadioOff            radio is off; nothing else can be concluded.
          LinkObservedInSession
                              the RECORDING watched this device hold a link.
                              Confirmed, and it retires the fault-2 question
                              regardless of what the post-stop sample says.
                              Clears the transport only, never data flow.
          LinkUp              linked in the final sample, but this recording
                              never observed a link itself. Weak.
          NoActiveLink        no ACL link AND the session never saw one.
                              CONSISTENT with fault 2 and equally consistent
                              with an idle or powered-off device. Weak. Needs an
                              open attempt to become a diagnosis.
          Unknown             not enough data.
    .PARAMETER Integrity
        Result of Test-/Get-BluetoothSerialPortIntegrity, or $null.
    .PARAMETER PairedDevices
        Objects with Name / IsConnected, e.g. from Get-BluetoothDevicesWinRT.
    .PARAMETER RadioOn
        $true/$false/$null (unknown).
    .PARAMETER LinkHistory
        Result of Get-BluetoothLinkHistory for the target, or $null.
    .PARAMETER TargetMac
        The MAC the recording selected. Pins the assessment to that one device.
        Prefer this always: without it the function runs its own name match and
        can describe a DIFFERENT headset than the rest of the capture.
    .PARAMETER TargetNamePattern
        Regex picking the device that matters out of PairedDevices. Fallback
        only, for when no TargetMac is known.
    .PARAMETER SessionObservedLink
        $true when the recording ITSELF watched the target hold an ACL link at
        any point (Session.BtLinkEverConnected).

        This is first-hand evidence from minutes ago and it outranks both of the
        other link signals, which are the weakest things this function reads:

          - PairedDevices[].IsConnected is sampled AFTER the operator presses
            Stop. Ending a session releases the link, so a completely healthy
            capture routinely samples Disconnected.
          - LastConnectedTime is a registry property FI-012 records as
            untrustworthy; on the dev box it was stale for every paired device.

        Capture B9F9F0EE5E21 (SP6, Arc 000013, 2026-08-07) is the shape: the
        recorder logged "BT radio link stable throughout session (no drops
        observed)" across the whole run, the operator stopped early, the
        post-stop sample read Disconnected, and the fingerprint reported
        NoActiveLink citing a LastConnectedTime four hours old -- raising FI-012
        fault 2 on a box whose link this very recording had just watched be up.
    #>
    [CmdletBinding()]
    param(
        $Integrity,
        [AllowEmptyCollection()][array]$PairedDevices = @(),
        [System.Nullable[bool]]$RadioOn,
        $LinkHistory,
        [string]$TargetMac,
        [string]$TargetNamePattern = 'NeurOptimal|Arc',
        [System.Nullable[bool]]$SessionObservedLink
    )

    $result = @{
        Fault             = 'Unknown'
        Confidence        = 'None'
        Summary           = $null
        Action            = $null
        TargetName        = $null
        LastConnectedTime = $null
        LastConnectedAgeHours = $null
        Intrusive         = $false
    }
    if ($LinkHistory) {
        $result.LastConnectedTime     = $LinkHistory.LastConnectedTime
        $result.LastConnectedAgeHours = $LinkHistory.AgeHours
    }

    if ($Integrity -and -not $Integrity.Healthy) {
        $result.Fault      = 'SerialStackBroken'
        $result.Confidence = 'Confirmed'
        $result.Summary    = "FI-012 fault 1: $($Integrity.Summary)"
        $result.Action     = 'Reboot. Do not unpair.'
        return $result
    }

    if ($RadioOn -eq $false) {
        $result.Fault      = 'RadioOff'
        $result.Confidence = 'Confirmed'
        $result.Summary    = 'The Bluetooth radio is off, so no device can link. Nothing further can be concluded about the serial ports until it is on.'
        $result.Action     = 'Turn the Bluetooth radio on, then re-run.'
        return $result
    }

    # TargetMac pins this to the device the recording actually selected. Without
    # it this ran its own name regex over every paired device and took [0] --
    # a SECOND selector, independent of the recorder's. On capture 8E39860E4AF2
    # the two disagreed: the recording watched Arc 000019 while this fingerprint
    # described Arc 000013, inside one artifact, with nothing flagging it.
    # The name pattern remains only as the single-Arc fallback.
    $wantMac = ([string]$TargetMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $targets = if ($wantMac) {
        @($PairedDevices | Where-Object {
            $_ -and (([string]$_.Address -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $wantMac)
        })
    } else {
        @($PairedDevices | Where-Object { $_.Name -and $_.Name -match $TargetNamePattern })
    }
    if ($targets.Count -eq 0) {
        $result.Summary = if ($wantMac) {
            "The selected target ($wantMac) is not in the paired device list, so its link state could not be assessed."
        } else {
            'No paired target device found to assess; serial port registrations look consistent'
        }
        if ($Integrity) { $result.Fault = 'Unknown' }
        return $result
    }

    $target = $targets[0]
    $result.TargetName = $target.Name

    # ── Session-observed link outranks both point-in-time signals ─────────────
    # Precedence overall: integrity fault -> radio off -> SESSION-OBSERVED LINK
    # -> current link state -> registry fallback.
    #
    # Deliberately NOT reported as 'LinkUp': the post-stop sample may genuinely
    # be disconnected, and claiming a link is up when it is not would be the
    # same class of error in the opposite direction. The claim made here is
    # exactly what was measured -- this recording SAW a link -- which is enough
    # to retire the FI-012 fault-2 question without asserting anything about
    # right now.
    #
    # LastConnectedTime stays in the result (set above, before any branch) so
    # the raw registry value is still archived; it simply stops driving the
    # verdict.
    if ($SessionObservedLink -eq $true) {
        $nowState = if ($target.IsConnected) {
            'It is still linked as this snapshot is taken.'
        } else {
            'It reads disconnected in this final snapshot, which is the NORMAL result after a session ends -- SPP devices hold no profile open, and stopping the session releases the link.'
        }
        $result.Fault      = 'LinkObservedInSession'
        $result.Confidence = 'Confirmed'
        # Same caveat 'LinkUp' carries, and it applies at least as strongly: an
        # observed ACL link clears the transport and says nothing about whether
        # EEG data reached NO.exe. The 2026-07-30 field case sat in exactly this
        # state while NO.exe showed "Arc Not Detected".
        $result.Summary    = "This recording observed '$($target.Name)' holding an active Bluetooth link during the session. $nowState That clears the transport layer only -- it does NOT establish that EEG data is reaching NeurOptimal. A held COM port with no data flowing presents exactly like this."
        $result.Action     = 'If NeurOptimal is still reporting a missing or undetected Arc in this state, capture it: the fault is above the Bluetooth transport and is not one this fingerprint can classify.'
        return $result
    }

    if ($target.IsConnected) {
        # NOT 'Healthy/Confirmed'. An ACL link plus consistent registrations means
        # the transport is up -- it does not mean data is reaching NO.exe. The
        # 2026-07-30 field case sat in exactly this state (paired, ports clean,
        # integrity healthy, radio linked) while NO.exe showed "Arc Not Detected":
        # the port was held and nothing was arriving through it. Reporting
        # Confirmed Healthy there is worse than reporting nothing, because it is
        # the verdict that tells an operator to stop capturing evidence.
        $result.Fault      = 'LinkUp'
        $result.Confidence = 'Weak'
        $result.Summary    = "Serial port registrations are consistent and '$($target.Name)' has an active link. That clears the transport layer only -- it does NOT establish that EEG data is reaching NeurOptimal. A held COM port with no data flowing presents exactly like this."
        $result.Action     = 'If NeurOptimal is still reporting a missing or undetected Arc in this state, capture it: the fault is above the Bluetooth transport and is not one this fingerprint can classify.'
        return $result
    }

    $result.Fault      = 'NoActiveLink'
    $result.Confidence = 'Weak'
    # A LastConnectedTime older than the boot it is read in cannot describe link
    # activity in this boot session. Rendering it as "last RFCOMM link-up" states
    # a falsehood as fact and points the tech at "asleep or off" - measured on
    # the dev box 2026-07-30, where the Arc had just run a 33 minute connected
    # session and the property still read 19 seconds BEFORE boot. This branch is
    # the common one for SPP, not an edge case: FI-012 records that SPP devices
    # always read IsConnected False, so a healthy Arc reaches it every time.
    $lastSeen = if ($LinkHistory -and $LinkHistory.Found -and $LinkHistory.PredatesBoot -eq $true) {
        "A LastConnectedTime of $($LinkHistory.LastConnectedTime) is recorded, but it PREDATES the last boot ($($LinkHistory.BootTime)) - it is carried over from an earlier boot session and says NOTHING about whether this device has linked since. Ignore it."
    } elseif ($LinkHistory -and $LinkHistory.Found -and $null -eq $LinkHistory.PredatesBoot) {
        "A LastConnectedTime of $($LinkHistory.LastConnectedTime) is recorded, but boot time was unavailable so its freshness could not be checked - do not rely on it."
    } elseif ($LinkHistory -and $LinkHistory.Found) {
        "Last RFCOMM link-up was $($LinkHistory.LastConnectedTime) ($($LinkHistory.AgeHours)h ago), which is after the last boot. Corroborate before relying on it: this property was completely stale for every paired device on the dev box."
    } else {
        'No LastConnectedTime recorded for it.'
    }
    $result.Summary = "Serial port registrations and symlinks are clean and the radio is on, but '$($target.Name)' has no active link. $lastSeen This is CONSISTENT with FI-012 fault 2 and equally consistent with the device simply being idle or powered off - SPP devices hold no profile open, so a healthy Arc reads disconnected too. It is evidence, not a diagnosis."
    $result.Action  = 'Confirm the device is POWERED ON first - that is the step that makes everything after it meaningful. Then, with NO.exe closed, run Test-BluetoothSerialPortOpen. ERROR_SEM_TIMEOUT on a device you have confirmed is on means fault 2 (toggle the radio, >=10s off); the same error on a device that is off means nothing at all. FI-012 records that the two are indistinguishable from the error alone.'
    return $result
}

function Initialize-SerialOpenApi {
    <#
    .SYNOPSIS
        Loads the CreateFile P/Invoke used to open a COM port and read the raw
        win32 error. Idempotent.
    .DESCRIPTION
        System.IO.Ports.SerialPort cannot be used for this. It throws IOException
        whose HResult is the generic COR_E_IO (0x80131620) -- the win32 code
        survives only inside the LOCALIZED message text ("The port 'COM6' does
        not exist."). Classifying on that string would silently misclassify every
        non-English machine in the field, and the whole point of this check is to
        tell ERROR_FILE_NOT_FOUND (reboot) apart from ERROR_SEM_TIMEOUT (toggle
        the radio). CreateFile + GetLastError gives the number directly.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:SerialOpenApiAvailable) { return $true }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'WinConfigSerialOpen').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinConfigSerialOpen {
    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // Returns 0 when the port opened, otherwise the raw win32 error. The handle
    // is closed immediately -- this establishes and tears down an RFCOMM link,
    // it does not hold the port. No DCB/baud configuration is performed, so it
    // disturbs the device as little as an open possibly can.
    public static int TryOpen(string portName) {
        string path = @"\\.\" + portName;
        IntPtr h = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero,
                              OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == IntPtr.Zero || h.ToInt64() == -1) { return Marshal.GetLastWin32Error(); }
        CloseHandle(h);
        return 0;
    }
}
'@ -ErrorAction Stop
        }
        $script:SerialOpenApiAvailable = $true
        return $true
    } catch {
        return $false
    }
}

function Get-SerialOpenClassification {
    <#
    .SYNOPSIS
        Maps a raw win32 error from a COM-port open into a FI-012 verdict.
    .DESCRIPTION
        Pure. Split out so the mapping is testable without a Bluetooth radio.
        The three codes that matter were all observed on MMEVOLD_06 2026-07-27:

          0   opened                     -> Healthy
          2   ERROR_FILE_NOT_FOUND       -> PortMissing        (fault 1, reboot)
          5   ERROR_ACCESS_DENIED        -> InUse              (another process holds it)
          121 ERROR_SEM_TIMEOUT          -> DeviceNotResponding (fault 2)

        121 IS AMBIGUOUS ON A SINGLE ATTEMPT. A cold ACL link and a powered-off
        device both return it at ~5.1s. Measured 2026-08-06 on Arc 000019: cold
        link failed once at 5146ms and then opened (752ms, then 2745, 4011);
        the same unit powered off returned 121 on three consecutive passes with
        no recovery. Only the retry outcome separates them, so the caller passes
        the first attempt's code alongside the final one.
    .PARAMETER Win32Error
        The FINAL attempt's error code.
    .PARAMETER FirstWin32Error
        The FIRST attempt's error code, when a retry happened. Leave at the
        default when there was only one attempt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Win32Error,
        [int]$FirstWin32Error = -1
    )

    # A timeout that clears on retry is a cold link, not a fault. Classifying it
    # as DeviceNotResponding is what sent techs cycling the radio for a headset
    # that was merely asleep.
    if ($Win32Error -eq 0 -and $FirstWin32Error -eq 121) {
        return @{ Classification = 'ColdLink'
                  Meaning = 'ERROR_SEM_TIMEOUT on the first attempt, then the port opened - a cold ACL link being established, not a fault. The device IS reachable.'
                  Action  = $null }
    }

    switch ($Win32Error) {
        0   { return @{ Classification = 'Healthy'; Meaning = 'Port opened'; Action = $null } }
        2   { return @{ Classification = 'PortMissing'
                        Meaning = 'ERROR_FILE_NOT_FOUND - the COM symlink does not exist, so no process can open this port'
                        Action  = 'Reboot. HKLM\HARDWARE is volatile and rebuilt at boot. Do not re-pair first.' } }
        5   { return @{ Classification = 'InUse'
                        Meaning = 'ERROR_ACCESS_DENIED - the port exists and another process holds it'
                        Action  = 'Close the application holding the port (usually NO.exe) and retry.' } }
        121 {
            $persisted = if ($FirstWin32Error -eq 121) { ' on the first attempt and again on retry, so this is not a cold link' } else { '' }
            return @{ Classification = 'DeviceNotResponding'
                      Meaning = "ERROR_SEM_TIMEOUT - the port is healthy; the device did not answer the RFCOMM connect$persisted"
                      Action  = 'Check the headset is powered ON and in range FIRST. A powered-off device fails exactly this way on every retry while every static signal - PnP nodes, SERIALCOMM, port integrity - still reads healthy. Only once it is confirmed on does a Bluetooth radio toggle (>=10s off) apply.' }
        }
        default { return @{ Classification = 'Unknown'
                            Meaning = "win32 error $Win32Error"
                            Action  = $null } }
    }
}

function Get-SerialOpenIsolation {
    <#
    .SYNOPSIS
        Pure. Decides which layer an open-attempt failure implicates, and
        refuses to draw a system-wide conclusion from a subset of the ports.
    .DESCRIPTION
        Other Bluetooth SPP ports opening normally while the target's time out
        is a real discriminator: it proves CreateFile, the symlinks and the
        serial stack all work on this box, so the fault is specific to that
        device or its channels. The converse - every port failing - points back
        at the stack itself.

        THAT CONVERSE IS ONLY VALID WHEN EVERY PORT WAS TESTED. Observed
        2026-08-06: called with -PortName COM6 alone, the old code returned
        AllPortsFailed and "EVERY Bluetooth COM port failed, which points at the
        serial stack" - from 1 of 1. The same box at the same moment, called
        with no -PortName, correctly returned DeviceSpecific (COM3/COM5 opened,
        only COM4 failed). The first answer routes a tech from one headset to
        rebuilding the serial stack, which is the worst misroute the tool can
        produce. So a partial run reports AllTestedFailed and says so.
    .PARAMETER Results
        The per-port result objects, each with PortName and Opened.
    .PARAMETER KnownPortName
        Every Bluetooth SPP port on the box. Empty or omitted means enumeration
        failed, which is also not grounds for an every-port claim.
    .OUTPUTS
        [hashtable] Isolation, Coverage, Summary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Results,
        [string[]]$KnownPortName
    )

    $tested = @($Results | ForEach-Object { [string]$_.PortName })
    $known  = @($KnownPortName | Where-Object { $_ })
    $missed = @($known | Where-Object { $tested -notcontains $_ })

    $coverage = if ($known.Count -eq 0) { 'Unknown' }
                elseif ($missed.Count -eq 0) { 'Full' }
                else { 'Subset' }

    $bad  = @($Results | Where-Object { -not $_.Opened })
    $good = @($Results | Where-Object { $_.Opened })

    if ($bad.Count -eq 0) {
        return @{ Isolation = 'AllOpened'
                  Coverage  = $coverage
                  Summary   = "All $($Results.Count) Bluetooth COM port(s) opened" }
    }

    $base = "$($bad.Count) of $($Results.Count) port(s) failed to open: $(($bad | ForEach-Object { "$($_.PortName)=$($_.Classification)" }) -join ', ')"

    if ($good.Count -gt 0) {
        return @{ Isolation = 'DeviceSpecific'
                  Coverage  = $coverage
                  Summary   = "$base. The other $($good.Count) Bluetooth COM port(s) opened normally, so CreateFile, the COM symlinks and the serial stack are all working - the fault is specific to this device or its channels, not system-wide." }
    }

    if ($coverage -eq 'Full') {
        return @{ Isolation = 'AllPortsFailed'
                  Coverage  = $coverage
                  Summary   = "$base. EVERY Bluetooth COM port failed, which points at the serial stack rather than at one device - check Get-BluetoothSerialPortIntegrity." }
    }

    $scope = if ($coverage -eq 'Subset') {
        "only $($tested.Count) of the $($known.Count) Bluetooth COM port(s) on this box were tested ($($missed -join ', ') untested)"
    } else {
        "the Bluetooth COM ports on this box could not be enumerated, so there is nothing to compare against"
    }
    return @{ Isolation = 'AllTestedFailed'
              Coverage  = $coverage
              Summary   = "$base. Every port TESTED failed, but $scope - that cannot tell a device fault from a serial-stack fault. Re-run Test-BluetoothSerialPortOpen with no -PortName to test them all before concluding anything about the serial stack." }
}

function Test-BluetoothSerialPortOpen {
    <#
    .SYNOPSIS
        GUARDED. Attempts to open Bluetooth COM ports and classifies the result,
        distinguishing the two FI-012 faults from each other.
    .DESCRIPTION
        This is the only way to observe FI-012 fault 2 (`ERROR_SEM_TIMEOUT`:
        registrations and symlinks healthy, device not answering). Registry
        inspection cannot see it -- the port looks perfect until something tries
        to open it.

        INTRUSIVE BY NATURE. Opening a port establishes an RFCOMM link, and if
        NO.exe is mid-connect the open can be stolen from it, producing exactly
        the spurious "Control Port not valid" this whole investigation was about.
        So:
          - it refuses to run while NO.exe is up unless -Force,
          - it is NOT called anywhere in the Flight Recorder path. The recorder
            runs during real client sessions; an automatic open attempt there
            would break sessions to diagnose them.
        Operator-initiated only.

        A failing open costs ~5s per port (the RFCOMM connect timeout), and a
        cold successful open on the command port takes ~4.5s.

        NAMING A SUBSET OF PORTS WEAKENS THE VERDICT. The isolation call needs
        the ports that opened as much as the ones that failed; see
        Get-SerialOpenIsolation. Prefer running with no -PortName.
    .PARAMETER PortName
        Ports to test. Defaults to the Bluetooth SPP ports found on the system.
    .PARAMETER Force
        Run even though a blocking process is up. Accepts the risk of stealing
        the port from a live session.
    .PARAMETER BlockingProcess
        Process names that must not be running. Defaults to NO.
    .PARAMETER RetryCount
        Extra attempts made ONLY on win32 121, whose single-attempt reading is
        ambiguous between a cold link and an unreachable device. 0 disables the
        retry and restores the old one-shot behaviour. Costs ~5s per retry when
        the device really is unreachable.
    .PARAMETER RetryDelayMs
        Settle time before a retry.
    #>
    [CmdletBinding()]
    param(
        [string[]]$PortName,
        [switch]$Force,
        [string[]]$BlockingProcess = @('NO'),
        [int]$RetryCount = 1,
        [int]$RetryDelayMs = 1000
    )

    $result = @{
        Ran       = $false
        Refused   = $false
        Reason    = $null
        Results   = @()
        Isolation = $null
        Coverage  = $null
        KnownPort = @()
        Summary   = $null
    }

    $running = @()
    foreach ($p in $BlockingProcess) {
        if (Get-Process -Name $p -ErrorAction SilentlyContinue) { $running += $p }
    }
    if ($running.Count -gt 0 -and -not $Force) {
        $result.Refused = $true
        $result.Reason  = "Refused: $($running -join ', ') is running. Opening a COM port can steal it from a live session and produce the very error being diagnosed. Close it, or pass -Force to accept that risk."
        $result.Summary = $result.Reason
        return $result
    }

    if (-not (Initialize-SerialOpenApi)) {
        $result.Reason  = 'CreateFile P/Invoke unavailable'
        $result.Summary = $result.Reason
        return $result
    }

    # Enumerate once. The same call supplies the default port list, the role
    # labels, and -- the part that was missing -- the DENOMINATOR the isolation
    # verdict needs in order to know whether "every port failed" was measured or
    # merely assumed from whatever the caller happened to name.
    #
    # Role labels come from BusReportedDeviceDesc; FriendlyName is the generic
    # "Standard Serial over Bluetooth link (COMx)" on every SPP channel.
    $knownPorts = @()
    $roles      = @{}
    try {
        foreach ($p in (Get-BluetoothCOMPorts).COMPorts) {
            if ($p.COMPort) {
                $knownPorts += $p.COMPort
                $roles[$p.COMPort] = $p.BusReportedDeviceDesc
            }
        }
    } catch { }
    $knownPorts = @($knownPorts | Select-Object -Unique)
    $result.KnownPort = $knownPorts

    if (-not $PortName -or $PortName.Count -eq 0) { $PortName = $knownPorts }
    if (-not $PortName -or $PortName.Count -eq 0) {
        $result.Reason  = 'No Bluetooth COM ports found to test'
        $result.Summary = $result.Reason
        return $result
    }

    $result.Ran = $true
    foreach ($port in $PortName) {
        $sw  = [Diagnostics.Stopwatch]::StartNew()
        $err = [WinConfigSerialOpen]::TryOpen($port)
        $sw.Stop()

        $first    = $err
        $firstMs  = $sw.ElapsedMilliseconds
        $retryMs  = $null
        $attempts = 1

        # Retry ONLY on 121. It is the single ambiguous code: a cold ACL link
        # and a powered-off device both produce it at ~5.1s, and the recovery
        # is what tells them apart. 2 and 5 are unambiguous, so retrying them
        # would only burn the operator's time.
        while ($err -eq 121 -and $attempts -le $RetryCount) {
            if ($RetryDelayMs -gt 0) { Start-Sleep -Milliseconds $RetryDelayMs }
            $sw2 = [Diagnostics.Stopwatch]::StartNew()
            $err = [WinConfigSerialOpen]::TryOpen($port)
            $sw2.Stop()
            $retryMs = $sw2.ElapsedMilliseconds
            $attempts++
        }

        $c = Get-SerialOpenClassification -Win32Error $err -FirstWin32Error $first
        $result.Results += [PSCustomObject]@{
            PortName        = $port
            Role            = $roles[$port]
            Opened          = ($err -eq 0)
            Win32Error      = $err
            FirstWin32Error = $first
            Attempts        = $attempts
            Recovered       = (($first -eq 121) -and ($err -eq 0))
            ElapsedMs       = $firstMs
            RetryElapsedMs  = $retryMs
            Classification  = $c.Classification
            Meaning         = $c.Meaning
            Action          = $c.Action
        }
    }

    $iso = Get-SerialOpenIsolation -Results @($result.Results) -KnownPortName $knownPorts
    $result.Isolation = $iso.Isolation
    $result.Coverage  = $iso.Coverage
    $result.Summary   = $iso.Summary
    return $result
}

function Test-BluetoothDeviceReachability {
    <#
    .SYNOPSIS
        Pure. Answers the one question nothing else in this module answers: was
        the device actually powered on and reachable when this was captured?
    .DESCRIPTION
        A POWERED-OFF ARC READS GREEN ON EVERY STATIC SIGNAL. Measured end to
        end on the dev box 2026-08-06 with the headset confirmed off by the
        operator, so device state was known rather than inferred:

          PnP nodes (all 4)              OK / CM_PROB_NONE / Present=True   LIE
          BTHPORT\Parameters\Devices     present, named                    LIE
          SERIALCOMM                     4 entries, unchanged              LIE
          Get-BluetoothSerialPortIntegrity  Healthy, 0 collisions          LIE
          setupapi.dev.log               no growth at all                  LIE
          retried port open              win32 121 every pass, ~5.12s      TRUTH
          WinRT ConnectionStatus         Remembered / IsConnected=False    TRUTH

        BR/EDR nodes persist once paired and do not reflect connection state:
        Present=True means "this device is known", never "this device is on".
        So a bundle captured while the Arc is off renders fully green, and a
        tech reading it is told the box is healthy and the port is at fault.

        Only the two truthful signals feed this verdict, and it reports Unknown
        rather than guessing when neither was observed. An Unknown here is the
        useful answer - it tells the reader the bundle cannot settle the
        question, which is exactly what the green static surface concealed.

        ASYMMETRY THAT MATTERS: IsConnected=$true proves the device is on.
        IsConnected=$false proves nothing - an Arc that is powered on but idle
        holds no ACL link either. It is recorded as non-probative, never as
        evidence of an unreachable device.
    .PARAMETER OpenResults
        Per-port results from Test-BluetoothSerialPortOpen, already filtered to
        this device. These must come from a RETRIED run: a single win32 121
        cannot separate a cold link from a powered-off device.
    .PARAMETER IsConnected
        WinRT ConnectionStatus for the device. Omit when it was not observed;
        do not pass $false to mean "not observed".
    .PARAMETER DeviceName
        Used only in the summary text.
    .PARAMETER OpenSkippedReason
        Why no open attempt was made, when there was one - e.g. the NO.exe
        guard refused. Surfaced so an Unknown says what would fix it.
    .OUTPUTS
        [hashtable] Verdict (Reachable|Unreachable|Unknown), Evidence,
        Summary, Action
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][array]$OpenResults = @(),
        [System.Nullable[bool]]$IsConnected,
        [string]$DeviceName,
        [string]$OpenSkippedReason
    )

    $who      = if ($DeviceName) { "'$DeviceName'" } else { 'The device' }
    $whoLower = if ($DeviceName) { "'$DeviceName'" } else { 'the device' }

    $opened      = @($OpenResults | Where-Object { $_.Opened })
    $persistent  = @($OpenResults | Where-Object { $_.Classification -eq 'DeviceNotResponding' })
    $portMissing = @($OpenResults | Where-Object { $_.Classification -eq 'PortMissing' })
    $inUse       = @($OpenResults | Where-Object { $_.Classification -eq 'InUse' })

    $evidence = @()

    foreach ($r in $opened) {
        $how = if ($r.Classification -eq 'ColdLink') {
            "opened on retry after a $($r.ElapsedMs)ms timeout (cold ACL link)"
        } else {
            "opened in $($r.ElapsedMs)ms"
        }
        $evidence += "TRUTH: $($r.PortName) $how - the device answered RFCOMM, so it was powered on and in range."
    }
    foreach ($r in $persistent) {
        $tail = if ($r.Attempts -gt 1) { "on all $($r.Attempts) attempts" } else { 'on a single attempt (NOT retried - this reading is ambiguous)' }
        $evidence += "TRUTH: $($r.PortName) timed out (win32 121) $tail."
    }
    foreach ($r in $portMissing) {
        $evidence += "NON-PROBATIVE: $($r.PortName) does not exist (win32 2), so no reachability test happened on it. That is FI-012 fault 1, a host-side fault - see Get-BluetoothSerialPortIntegrity."
    }
    foreach ($r in $inUse) {
        $evidence += "NON-PROBATIVE: $($r.PortName) is held by another process (win32 5), so it could not be tested. Note the holder is usually NO.exe, which implies the device WAS reachable when it opened the port."
    }

    if ($null -eq $IsConnected) {
        $evidence += 'NOT OBSERVED: WinRT ConnectionStatus was not read.'
    } elseif ($IsConnected) {
        $evidence += 'TRUTH: WinRT ConnectionStatus = Connected - an ACL link exists right now, so the device is on.'
    } else {
        $evidence += 'NON-PROBATIVE: WinRT ConnectionStatus = Remembered (IsConnected=False). A powered-on but idle device reads this way too, so it is NOT evidence the device is off.'
    }

    if ($opened.Count -gt 0 -or $IsConnected -eq $true) {
        $verdict = 'Reachable'
        $summary = "$who was POWERED ON and reachable at capture time."
        $action  = $null
    } elseif ($persistent.Count -gt 0) {
        $verdict = 'Unreachable'
        $retried = @($persistent | Where-Object { $_.Attempts -gt 1 }).Count -gt 0
        $summary = "$who did NOT answer on $($persistent.Count) port(s) and was UNREACHABLE at capture time - powered off, out of range, or asleep."
        if (-not $retried) {
            $summary += ' Only one attempt was made, so a cold ACL link cannot be ruled out; re-run with a retry.'
        }
        $action = 'Power-cycle the headset and confirm it is on and in range, THEN re-run. Do not act on the rest of the diagnostics first: PnP nodes, SERIALCOMM and port integrity all read healthy for a powered-off device, so every other signal in this capture is green regardless.'
    } else {
        $verdict = 'Unknown'
        $why = if ($OpenSkippedReason) { " No open attempt was made: $OpenSkippedReason" }
               elseif ($OpenResults.Count -eq 0) { ' No port-open attempt was made.' }
               else { ' No port produced a usable reading.' }
        $summary = "Whether $whoLower was powered on at capture time CANNOT be determined from this capture.$why"
        $action  = 'Treat the rest of this capture as unproven. A powered-off device leaves PnP nodes, SERIALCOMM, port integrity and setupapi.dev.log all reading healthy, so a green bundle is not evidence the headset was on. Re-run Test-BluetoothSerialPortOpen with NO.exe closed to settle it.'
    }

    return @{
        Verdict  = $verdict
        Evidence = $evidence
        Summary  = $summary
        Action   = $action
    }
}

function Get-BluetoothDeviceReachability {
    <#
    .SYNOPSIS
        Live wrapper for Test-BluetoothDeviceReachability: reads the two
        truthful signals for one device and returns the verdict.
    .DESCRIPTION
        INTRUSIVE, like Test-BluetoothSerialPortOpen, and for the same reason -
        it opens a COM port. It inherits that function's NO.exe guard and is
        NOT called from the Flight Recorder's automatic path. Operator-
        initiated, or explicitly invoked by an operator-driven action.

        Ports are attributed to the device by the MAC embedded in the SPP
        instance id, not by COM number. The COM number is never the identity:
        Arc 000019 moved from COM3/COM4 to COM4/COM6 across a single re-pair.
    .PARAMETER Address
        Device MAC, with or without separators.
    .PARAMETER NameLike
        Wildcard match on the device name, when the MAC is not to hand.
    .PARAMETER Force
        Passed through to Test-BluetoothSerialPortOpen. Accepts the risk of
        stealing the port from a live session.
    .PARAMETER RetryCount
        Passed through. Leave at the default; the retry is the whole point.
    .OUTPUTS
        [hashtable] As Test-BluetoothDeviceReachability, plus Address, Name,
        PortName, OpenResults, IsConnected.
    #>
    [CmdletBinding()]
    param(
        [string]$Address,
        [string]$NameLike,
        [switch]$Force,
        [int]$RetryCount = 1
    )

    $mac = ([string]$Address) -replace '[^0-9A-Fa-f]', ''

    $device = $null
    try {
        $winrt = @(Get-BluetoothDevicesWinRT)
        $device = $winrt | Where-Object {
            ($mac -and ((([string]$_.Address) -replace '[^0-9A-Fa-f]', '') -eq $mac)) -or
            ($NameLike -and $_.Name -like $NameLike)
        } | Select-Object -First 1
    } catch { }

    if (-not $mac -and $device) { $mac = (([string]$device.Address) -replace '[^0-9A-Fa-f]', '') }

    # Attribute SPP ports to this device by the MAC in the instance id, matched
    # EXACTLY rather than as a substring. The MAC is the last &-delimited field
    # before the trailing channel suffix:
    #
    #   BTHENUM\{1101-...}_VID&0001000F_PID&0401\7&1D67848D&0&8C1F64710013_C00000000
    #   BTHENUM\{1101-...}_LOCALMFG&0000\7&1D67848D&0&000000000000_0000006D
    #
    # A substring match is not good enough here. The second shape above is a
    # real port on the dev box with an all-zero MAC, so looking up
    # 00:00:00:00:00:00 by substring returns two ports that belong to no
    # device -- and any MAC that happens to appear inside the VID/PID or GUID
    # fields would collide the same way.
    $ports = @()
    if ($mac) {
        try {
            $ports = @((Get-BluetoothCOMPorts).COMPorts | Where-Object {
                    if (-not $_.COMPort) { return $false }
                    $m = [regex]::Match([string]$_.InstanceId, '&([0-9A-Fa-f]{12})_')
                    $m.Success -and ($m.Groups[1].Value -eq $mac)
                } | Select-Object -ExpandProperty COMPort -Unique)
        } catch { }
    }

    $open    = $null
    $skipped = $null
    if ($ports.Count -gt 0) {
        $open = Test-BluetoothSerialPortOpen -PortName $ports -Force:$Force -RetryCount $RetryCount
        if ($open.Refused)   { $skipped = $open.Reason }
        elseif (-not $open.Ran) { $skipped = $open.Reason }
    } else {
        $skipped = if ($mac) {
            "no Bluetooth SPP COM port is registered for $mac, so there is no port to open"
        } else {
            'the device could not be identified, so no port could be attributed to it'
        }
    }

    # $device.IsConnected is $null when the device was not found at all, which
    # is what "not observed" must look like to the pure function.
    $connected = $null
    if ($device) { $connected = [bool]$device.IsConnected }

    $verdict = Test-BluetoothDeviceReachability `
        -OpenResults @(if ($open) { $open.Results } else { @() }) `
        -IsConnected $connected `
        -DeviceName $(if ($device) { $device.Name } else { $NameLike }) `
        -OpenSkippedReason $skipped

    $verdict.Address     = $(if ($device) { $device.Address } elseif ($mac) { $mac } else { $null })
    $verdict.Name        = $(if ($device) { $device.Name } else { $null })
    $verdict.PortName    = $ports
    $verdict.OpenResults = @(if ($open) { $open.Results } else { @() })
    $verdict.IsConnected = $connected
    return $verdict
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
        Preview which devices would be removed without making changes. This is
        the standard ShouldProcess common parameter - do NOT redeclare it in
        the param block. Declaring it alongside SupportsShouldProcess makes
        every invocation throw "A parameter with the name 'WhatIf' was defined
        multiple times for the command", which is what made this function
        permanently uncallable before 2026-07-27.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Force
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
        Integrity = $null
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

        # An empty ghost list does NOT mean the COM ports work. Ghost
        # enumeration only sees non-present PnP nodes; the SERIALCOMM
        # collision / destroyed-symlink fault leaves every node Present and
        # OK while no process can open any Bluetooth COM port. Reporting
        # "nothing to do" there sends the operator to unpair/re-pair, which
        # makes it worse. See Get-BluetoothSerialPortIntegrity.
        try {
            $integrity = Get-BluetoothSerialPortIntegrity
            $result.Integrity = $integrity
            if (-not $integrity.Healthy) {
                $result.Message = "No ghost COM ports to remove, but the serial port registrations are corrupt: $($integrity.Summary)"
                foreach ($f in $integrity.Findings) { $result.Details += $f }
                if ($integrity.Recommendation) { $result.Details += $integrity.Recommendation }
            } else {
                $result.Details += $integrity.Summary
            }
        } catch {
            $result.Details += "Serial port integrity check failed: $($_.Exception.Message)"
        }
        return $result
    }

    $result.Details += "Found $($ghostPorts.Count) ghost Bluetooth COM port(s)"

    if ($WhatIfPreference) {
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

# Cache of the STATIC per-device-node properties read by
# Get-BluetoothComPortSnapshot, keyed by InstanceId.
#
# Why this exists (measured, dev box, 2026-08-07): each Get-PnpDeviceProperty
# call costs ~300 ms. The snapshot read two keys per device across two separate
# calls, so with 8 port nodes one snapshot spent ~4.8 s inside CIM. The Flight
# Recorder calls it on a "every 3s" tick from the WinForms UI thread, so the
# recorder window was blocked ~5.5 s out of every ~5.5 s -- the stated 3 s
# cadence and the real cadence were two different answers, and only one of them
# reached the operator.
#
# Both cached keys are fixed for the lifetime of a device NODE: DEVPKEY_Device_Parent
# is assigned when the node is enumerated, and BusReportedDeviceDesc is what the
# device reported at that same enumeration. Neither can change while the node
# exists under one InstanceId. Entries for InstanceIds absent from the current
# enumeration are pruned every call, so a remove/re-add re-reads from the device.
#
# Archival snapshots (baseline/final, and anything persisted as evidence) pass
# -NoCache and always read fresh -- the cache is a tick-path optimization and
# must never be the thing a stored artifact was built from.
$script:BtComPortStaticPropCache = @{}

# Monotonic generation counter, bumped once per Get-BluetoothComPortSnapshot.
# Used instead of a clock so retry pacing is deterministic and testable.
$script:BtComPortSnapshotSeq = 0

# How many snapshot generations a FAILED property read is remembered before the
# device is asked again. At the recorder's 3 s tick this is roughly half a
# minute: long enough that a permanently denied property does not reintroduce a
# per-tick cost, short enough that a transient failure does not silently cost
# the capture a field for its whole duration.
$script:BtComPortPropRetryGenerations = 10

function Clear-BluetoothComPortPropertyCache {
    <#
    .SYNOPSIS
        Empties the static COM-port property cache used by Get-BluetoothComPortSnapshot.
    .DESCRIPTION
        Exists so a recording session can start from a cold cache, and so tests
        can assert cache behaviour without reloading the module.
    #>
    [CmdletBinding()]
    param()
    $script:BtComPortStaticPropCache = @{}
}

function Get-BluetoothComPortStaticProperty {
    <#
    .SYNOPSIS
        Reads the static (node-lifetime-constant) PnP properties for one port node.
    .DESCRIPTION
        Returns DEVPKEY_Device_Parent and DEVPKEY_Device_BusReportedDeviceDesc for
        an InstanceId, batching both keys into ONE Get-PnpDeviceProperty call.

        Measured: one call with two keys costs the same as one call with one key
        (~270 ms vs ~300 ms), so batching alone halves the cost even with the
        cache cold. A batch containing ANY key the platform rejects returns
        nothing at all, so a batch that comes back short falls back to reading
        each key on its own -- preserving the previous behaviour exactly on hosts
        where one of the keys is unavailable.

        Best-effort throughout: a denied or missing property yields $null for that
        field and must never cost the caller its whole snapshot.
    .PARAMETER InstanceId
        The device node to read.
    .PARAMETER NoCache
        Bypass the cache for both read and write. Use for archival snapshots.
    .OUTPUTS
        [pscustomobject] ParentInstanceId, BusReportedDeviceDesc.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$InstanceId,

        [switch]$NoCache
    )

    if ([string]::IsNullOrWhiteSpace($InstanceId)) {
        return [pscustomobject]@{ ParentInstanceId = $null; BusReportedDeviceDesc = $null }
    }

    if (-not $NoCache -and $script:BtComPortStaticPropCache.ContainsKey($InstanceId)) {
        $hit = $script:BtComPortStaticPropCache[$InstanceId]
        # A cached SUCCESS is final -- the values are node-lifetime constants. A
        # cached FAILURE only suppresses retries for a bounded number of
        # generations, then the device gets asked again.
        if (-not $hit.ReadFailed -or $script:BtComPortSnapshotSeq -lt $hit.RetryAtSeq) {
            return $hit
        }
    }

    $parentKey = 'DEVPKEY_Device_Parent'
    # The BusReportedDeviceDesc key in raw GUID form. Windows echoes it back under
    # its canonical name, so results are matched on both spellings.
    $busKeyRaw  = '{540b947e-8b40-45bc-a8a2-6a0b894cbda2} 4'
    $busKeyName = 'DEVPKEY_Device_BusReportedDeviceDesc'

    $parent  = $null
    $busDesc = $null
    # Tracked PER KEY, and separately from the value. "The read succeeded and this
    # device reports no bus description" and "the read did not happen" are
    # different facts: the first is static and safe to cache forever, the second
    # is not static at all and must not be frozen in for the whole recording.
    $parentOk = $false
    $busOk    = $false

    $props = @()
    try {
        $props = @(Get-PnpDeviceProperty -InstanceId $InstanceId `
            -KeyName $parentKey, $busKeyRaw -ErrorAction SilentlyContinue)
    } catch { $props = @() }

    foreach ($p in $props) {
        $kn = [string]$p.KeyName
        if ($kn -eq $parentKey) {
            $parentOk = $true
            if ($p.Data) { $parent = [string]$p.Data }
        } elseif ($kn -eq $busKeyName -or $kn -eq $busKeyRaw) {
            $busOk = $true
            if ($p.Data) { $busDesc = [string]$p.Data }
        }
    }

    # Per-key fallback, driven by which keys are actually MISSING rather than by
    # whether the batch returned anything at all. A batch that comes back with
    # one of the two keys used to skip the fallback entirely and silently leave
    # the other field null.
    if (-not $parentOk) {
        try {
            $pp = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $parentKey -ErrorAction Stop
            if ($pp) { $parentOk = $true; if ($pp.Data) { $parent = [string]$pp.Data } }
        } catch { }
    }
    if (-not $busOk) {
        try {
            $bp = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $busKeyRaw -ErrorAction Stop
            if ($bp) { $busOk = $true; if ($bp.Data) { $busDesc = [string]$bp.Data } }
        } catch { }
    }

    $readFailed = -not ($parentOk -and $busOk)

    $result = [pscustomobject]@{
        ParentInstanceId      = $parent
        BusReportedDeviceDesc = $busDesc
        ReadFailed            = $readFailed
        # When a failed read becomes eligible for another attempt, in snapshot
        # generations. Retrying every tick would hand back the per-tick cost this
        # cache exists to remove on a box where the property is simply denied;
        # never retrying would let one transient glitch blank
        # BusReportedDeviceDesc -- the only field that tells the COMMAND port from
        # the DATA port -- for an entire capture.
        RetryAtSeq            = if ($readFailed) { $script:BtComPortSnapshotSeq + $script:BtComPortPropRetryGenerations } else { 0 }
    }
    if (-not $NoCache) { $script:BtComPortStaticPropCache[$InstanceId] = $result }
    return $result
}

function Get-BluetoothPnpInventory {
    <#
    .SYNOPSIS
        Takes ONE full PnP device enumeration for several collectors to project.
    .DESCRIPTION
        The recorder's tick ran four separate Get-PnpDevice queries -- Bluetooth
        class, Ports class, and the BTHENUM prefix TWICE, once per snapshot
        function. Measured on the dev box that is ~1,230 ms; a single unfiltered
        enumeration plus client-side projection is ~400 ms, and the three
        projections are byte-identical to the scoped queries they replace
        (verified on hardware with both Arcs paired).

        The second benefit matters as much as the speed: the PnP and COM-port
        snapshots currently describe enumeration instants roughly half a second
        apart, so a device appearing or vanishing between them produces a capture
        whose two halves disagree about the machine. Projecting both from one
        inventory makes them describe the same instant by construction.

        NEVER THROWS. A failed enumeration comes back as Ok = $false with the
        reason attached, so the caller can fall back to letting each collector
        run its own scoped queries. That fallback is the point: sharing one
        enumeration must not mean losing both evidence channels together.
    .OUTPUTS
        PSCustomObject (PSTypeName WinConfig.FlightRecorder.PnpInventory) with
        CapturedAt, Ok, Devices, Failure.
    #>
    [CmdletBinding()]
    param()

    try {
        $all = @(Get-PnpDevice -ErrorAction Stop)
        return [pscustomobject]@{
            PSTypeName = 'WinConfig.FlightRecorder.PnpInventory'
            CapturedAt = Get-Date
            Ok         = $true
            Devices    = $all
            Failure    = $null
        }
    } catch {
        return [pscustomobject]@{
            PSTypeName = 'WinConfig.FlightRecorder.PnpInventory'
            CapturedAt = Get-Date
            Ok         = $false
            Devices    = @()
            Failure    = $_.Exception.Message
        }
    }
}

function Test-BluetoothPnpInventoryUsable {
    <#
    .SYNOPSIS
        Whether an inventory object may be projected from.
    .DESCRIPTION
        Central so every collector applies the same admission rule: anything
        malformed, failed, or absent falls back to the collector's own scoped
        queries rather than silently projecting from nothing and reporting an
        empty machine.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Inventory)

    if ($null -eq $Inventory) { return $false }
    try {
        if (-not $Inventory.Ok) { return $false }
        if ($null -eq $Inventory.Devices) { return $false }
    } catch { return $false }
    return $true
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
    .PARAMETER NoCache
        Read every device node's static properties fresh instead of reusing the
        per-InstanceId cache. Use for baseline/final and any snapshot persisted
        as evidence; the cache exists to keep the recorder's 3 s tick from
        blocking its own UI thread for seconds at a time.
    #>
    [CmdletBinding()]
    param(
        [switch]$NoCache,
        [AllowNull()]$Inventory
    )

    $now = Get-Date
    $failures = @()
    $ports = @()
    $script:BtComPortSnapshotSeq++

    # Project from a shared enumeration when one is supplied and usable; run the
    # scoped queries otherwise. Anything failed or malformed falls through to the
    # original behaviour so this collector never loses its independent failure
    # path just because a caller tried to share work.
    $useInv = Test-BluetoothPnpInventoryUsable -Inventory $Inventory

    $candidates = @()
    try {
        if ($useInv) {
            $candidates += @($Inventory.Devices | Where-Object { $_.Class -eq 'Ports' })
        } else {
            $candidates += Get-PnpDevice -Class Ports -ErrorAction Stop
        }
    } catch {
        $failures += [pscustomobject]@{ Query = 'Get-PnpDevice -Class Ports'; Reason = $_.Exception.Message }
    }
    # Catch any Bluetooth-tagged entries that aren't class Ports (e.g. RFCOMM
    # service nodes that expose a PortName via friendly text).
    #
    # The BTHENUM prefix is pushed into the -InstanceId query rather than being
    # applied client-side to a full device-tree enumeration: on this dev box that
    # is 24 objects marshalled instead of 313, for a verified-identical result
    # set. The client-side regex is KEPT below so the filter's meaning does not
    # depend on the provider's wildcard semantics, and an unsupported -InstanceId
    # falls back to the original full enumeration rather than silently returning
    # fewer devices.
    try {
        $btScoped = $null
        if ($useInv) {
            $btScoped = @($Inventory.Devices)
        } else {
            try {
                $btScoped = @(Get-PnpDevice -InstanceId 'BTHENUM\*' -ErrorAction Stop)
            } catch {
                $btScoped = @(Get-PnpDevice -ErrorAction Stop)
            }
        }
        $extra = $btScoped | Where-Object {
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

        # DEVPKEY_Device_BusReportedDeviceDesc -- the per-channel name the DEVICE
        # reports ("NEUROPTIMAL COMMAND" / "NEUROPTIMAL DATA"). FriendlyName is
        # the generic "Standard Serial over Bluetooth link (COMx)" for every SPP
        # channel, so this is the ONLY field that tells the command port from the
        # data port. Read here (passively, no port is opened) because the Flight
        # Recorder's watch path consumes this snapshot: the property was already
        # being read elsewhere in this module, just never on the path that
        # produces a bundle, so every recorder capture reported two
        # indistinguishable ports for one MAC.
        #
        # Batched with the parent lookup into a single cached read -- see
        # Get-BluetoothComPortStaticProperty for why that matters.
        $staticProps = Get-BluetoothComPortStaticProperty -InstanceId $instanceId -NoCache:$NoCache
        $parentId = $staticProps.ParentInstanceId
        $busDesc  = $staticProps.BusReportedDeviceDesc

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
            BusReportedDeviceDesc     = if ($busDesc) { [string]$busDesc } else { $null }
        }
    }

    # Prune cache entries for device nodes that are no longer enumerated. A node
    # that disappears and comes back is re-read from the device rather than
    # answered from a value captured before it went away.
    #
    # Gated on the enumeration having SUCCEEDED, not on it having returned
    # something. Those are different: a query that failed is no evidence that the
    # devices it would have returned are gone, while a query that succeeded and
    # returned nothing is exactly the case where every entry should be dropped --
    # every port vanishing at once is the FI-012/FI-014 shape, the one time a
    # stale cache would be most misleading. Keying on Count previously made the
    # total-loss case the one case that never pruned.
    $enumerationOk = ($failures.Count -eq 0)
    if (-not $NoCache -and $enumerationOk) {
        $live = @{}
        foreach ($c in $candidates) { $live[[string]$c.InstanceId] = $true }
        foreach ($stale in @($script:BtComPortStaticPropCache.Keys | Where-Object { -not $live.ContainsKey($_) })) {
            $script:BtComPortStaticPropCache.Remove($stale)
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
    .PARAMETER Inventory
        Optional Get-BluetoothPnpInventory result to project from instead of
        running this function's own device queries. Anything absent, failed or
        malformed is ignored and the scoped queries run as before.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Inventory
    )

    $now = Get-Date
    $failures = @()
    $devices = @()

    $useInv = Test-BluetoothPnpInventoryUsable -Inventory $Inventory

    try {
        $btClass = if ($useInv) {
            @($Inventory.Devices | Where-Object { $_.Class -eq 'Bluetooth' })
        } else {
            Get-PnpDevice -Class Bluetooth -ErrorAction Stop
        }
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
        # Scope the query provider-side (see Get-BluetoothComPortSnapshot for the
        # measurement); the client-side regex stays as the authority on what
        # counts as a match, and an unsupported -InstanceId falls back to the
        # full enumeration rather than quietly returning fewer devices.
        $bthScoped = $null
        if ($useInv) {
            $bthScoped = @($Inventory.Devices)
        } else {
            try {
                $bthScoped = @(Get-PnpDevice -InstanceId 'BTHENUM\*' -ErrorAction Stop)
            } catch {
                $bthScoped = @(Get-PnpDevice -ErrorAction Stop)
            }
        }
        $bthEnum = $bthScoped | Where-Object { $_.InstanceId -match '^BTHENUM\\' }
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
    'Get-BluetoothSerialPortIntegrity',
    'Test-BluetoothSerialPortIntegrity',
    # FI-014: pairing records left behind by a device removal, which mark the
    # no-node state and can accompany a failed re-pair. Only a fault when
    # scoped to a device the operator expects to be paired - unscoped they are
    # ordinary removal residue. Must be checked BEFORE the FI-012 triage tree -
    # neither a reboot nor a radio toggle clears a non-volatile registry record.
    'Get-BluetoothOrphanPairingRecord',
    # Resolves the MAC the orphan check is scoped to. Needed because the
    # recorder's PnP-based target lookup returns nothing in exactly the FI-014
    # case, which would leave every real capture unscoped and therefore Healthy.
    'Select-BluetoothSessionTarget',
    'Resolve-BluetoothTargetMac',
    'Test-BluetoothOrphanPairingRecord',
    'Initialize-RegistryKeyTimeApi',
    'Get-BluetoothPowerCycleContext',
    'Get-SerialRegistrationCorrelation',
    'Get-BluetoothRadioState',
    'Get-BluetoothRadioPnpState',
    'ConvertTo-BluetoothRadioPnpState',
    'Get-SerialFaultFingerprint',
    'Get-BluetoothLinkHistory',
    # Paired-device link state. Exported because the FI-012 fault-2 fingerprint
    # needs IsConnected, and the recorder builds that fingerprint outside this
    # module.
    'Get-BluetoothDevicesWinRT',
    # Get-BluetoothDevicesWinRT enumerates PAIRED devices only. This is the one
    # thing that can answer "can this box see the Arc at all". MTA only.
    'Get-BluetoothInquiryScan',
    'Test-BluetoothSerialPortOpen',
    'Get-SerialOpenClassification',
    'Get-SerialOpenIsolation',
    # "Was the headset actually on when this was captured?" - the question no
    # static signal answers, because a powered-off Arc reads green on all of
    # them. INTRUSIVE (opens a port); operator-initiated, never the recorder.
    'Test-BluetoothDeviceReachability',
    'Get-BluetoothDeviceReachability',
    'Initialize-SerialSymlinkApi',
    'Initialize-SerialOpenApi',
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
    # One shared enumeration the tick's collectors project from, so both describe
    # the same instant and pay for it once. Optional everywhere by design.
    'Get-BluetoothPnpInventory',
    'Test-BluetoothPnpInventoryUsable',
    'Get-BluetoothPnpSnapshot',
    'Get-BluetoothAdapterSnapshot',
    'Get-BluetoothServiceSnapshot',
    'Get-BluetoothComPortSnapshot',
    'Get-BluetoothComPortPortName',
    # Static per-node property read + its cache control. Exported so the recorder
    # can start each session cold and so tests can assert the cache is bypassed
    # on the evidence path.
    'Get-BluetoothComPortStaticProperty',
    'Clear-BluetoothComPortPropertyCache',
    'Get-BluetoothServiceSurfaceSnapshot',
    'Get-BluetoothEventLogInventory',
    'Get-BluetoothRecentEvents',
    'Compare-BluetoothSnapshot'
)

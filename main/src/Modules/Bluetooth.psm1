# Bluetooth.psm1 - Bluetooth audio diagnostics for WinConfig
# Provides diagnostics, service control, and Kodi audio path analysis

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
        Returns a list of user-recognizable Bluetooth audio devices (not transport nodes).
    .DESCRIPTION
        Enumerates Bluetooth audio devices suitable for display in the UI. Excludes
        transport/profile nodes (A2DP/AVRCP/HFP "Transport") and service nodes.
        Returns user-friendly device names like "AirPods Pro", "Dime 3", etc.
    .OUTPUTS
        PSCustomObject[] with properties:
        - Name: User-friendly device name
        - InstanceId: PnP device instance ID
        - Status: PnP status (OK, Error, Unknown)
        - ConnectionState: Connected, Paired, Disconnected, or Unknown (best-effort)
        - IsAudioDevice: $true (all returned devices are audio)
        - DeviceKind: Headphones, Earbuds, Speaker, or Unknown
        - SupportsA2DP: $true/$false/$null (best-effort)
        - SupportsHFP: $true/$false/$null (best-effort)
        - IsDefaultPlayback: $true/$false/$null (best-effort)
        - Notes: Array of detection notes
    #>
    [CmdletBinding()]
    param()

    $devices = @()
    $notes = @("Filtered: transport nodes excluded", "Best-effort connection inference")

    try {
        # Get current default playback device name for comparison
        $defaultPlaybackName = $null
        try {
            $regPath = "HKCU:\Software\Microsoft\Multimedia\Sound Mapper"
            if (Test-Path $regPath) {
                $defaultPlaybackName = (Get-ItemProperty -Path $regPath -Name "Playback" -ErrorAction SilentlyContinue).Playback
            }
        }
        catch { }

        # Get all Bluetooth devices from Class Bluetooth
        $btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue

        # Get audio endpoints that appear to be Bluetooth (for profile detection)
        $btAudioEndpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FriendlyName -match "Bluetooth|BT|Hands-Free|Headset|Speaker|Headphone|AirPods|Buds|WH-|WF-|Jabra|Bose|Sony|JBL|Beats|Dime|Kanto|ORA" -or
                $_.InstanceId -match "BTHENUM|BTH"
            }

        # Build a map of base device names to their audio capabilities
        $deviceProfiles = @{}
        foreach ($endpoint in $btAudioEndpoints) {
            # Extract base device name (remove profile indicators)
            $baseName = $endpoint.FriendlyName -replace '\s*(Stereo|Hands-Free AG Audio|Hands-Free|HFP|A2DP|Audio)$', '' -replace '\s+$', ''

            if (-not $deviceProfiles.ContainsKey($baseName)) {
                $deviceProfiles[$baseName] = @{
                    HasA2DP = $false
                    HasHFP = $false
                    Endpoints = @()
                }
            }

            # Detect profiles
            if ($endpoint.FriendlyName -match "Stereo|A2DP") {
                $deviceProfiles[$baseName].HasA2DP = $true
            }
            if ($endpoint.FriendlyName -match "Hands-Free|HFP|AG Audio") {
                $deviceProfiles[$baseName].HasHFP = $true
            }

            $deviceProfiles[$baseName].Endpoints += $endpoint
        }

        # Find parent/user-facing Bluetooth devices (not transport nodes)
        $seenDevices = @{}

        foreach ($dev in $btDevices) {
            # Skip transport/service nodes
            if (Test-IsTransportOrServiceNode -Name $dev.FriendlyName) {
                continue
            }

            # Skip enumerators and system devices
            if ($dev.FriendlyName -match "^Microsoft Bluetooth|Enumerator") {
                continue
            }

            # Check if this looks like an audio device
            $isAudioDevice = $false
            $deviceKind = "Unknown"

            # Check by name patterns (common audio brands/models)
            if ($dev.FriendlyName -match "AirPods|Buds|WH-|WF-|Jabra|Bose|Sony|JBL|Beats|Headphone|Headset|Earbuds|Dime|Kanto|ORA|Speaker|Soundbar|Echo|HomePod|Pill|Flip|Charge|Xtreme|Boom") {
                $isAudioDevice = $true

                # Classify device kind
                if ($dev.FriendlyName -match "AirPods|Buds|Earbuds|WF-") {
                    $deviceKind = "Earbuds"
                }
                elseif ($dev.FriendlyName -match "Headphone|Headset|WH-|Jabra|Over-Ear") {
                    $deviceKind = "Headphones"
                }
                elseif ($dev.FriendlyName -match "Speaker|Soundbar|Echo|HomePod|Pill|Flip|Charge|Xtreme|Boom|Kanto|ORA|Dime") {
                    $deviceKind = "Speaker"
                }
            }

            # Also check if device has audio endpoints
            $baseName = $dev.FriendlyName -replace '\s*(Stereo|Hands-Free AG Audio|Hands-Free|HFP|A2DP|Audio)$', '' -replace '\s+$', ''
            if ($deviceProfiles.ContainsKey($baseName)) {
                $isAudioDevice = $true
            }

            # Skip non-audio devices
            if (-not $isAudioDevice) {
                continue
            }

            # Avoid duplicates (same base name)
            $normalizedName = $baseName.Trim()
            if ($seenDevices.ContainsKey($normalizedName)) {
                continue
            }
            $seenDevices[$normalizedName] = $true

            # Determine connection state (best-effort)
            $connectionState = "Unknown"
            if ($dev.Status -eq 'OK' -and $dev.Present) {
                # Device is present and OK - at least paired
                # Check if any of its audio endpoints are active
                $profiles = $deviceProfiles[$baseName]
                $hasActiveEndpoint = $false
                if ($profiles -and $profiles.Endpoints) {
                    foreach ($ep in $profiles.Endpoints) {
                        if ($ep.Status -eq 'OK') {
                            $hasActiveEndpoint = $true
                            break
                        }
                    }
                }

                if ($hasActiveEndpoint) {
                    $connectionState = "Connected"
                }
                else {
                    $connectionState = "Paired"
                }
            }
            elseif ($dev.Present) {
                $connectionState = "Paired"
            }
            else {
                $connectionState = "Disconnected"
            }

            # Check A2DP/HFP support
            $supportsA2DP = $null
            $supportsHFP = $null
            if ($deviceProfiles.ContainsKey($baseName)) {
                $supportsA2DP = $deviceProfiles[$baseName].HasA2DP
                $supportsHFP = $deviceProfiles[$baseName].HasHFP
            }

            # Check if default playback
            $isDefaultPlayback = $null
            if ($defaultPlaybackName) {
                # Case-insensitive match - check if default device name contains this device name
                if ($defaultPlaybackName -match [regex]::Escape($normalizedName)) {
                    $isDefaultPlayback = $true
                }
                else {
                    $isDefaultPlayback = $false
                }
            }

            $devices += [PSCustomObject]@{
                Name = $normalizedName
                InstanceId = $dev.InstanceId
                Status = $dev.Status
                ConnectionState = $connectionState
                IsAudioDevice = $true
                DeviceKind = $deviceKind
                SupportsA2DP = $supportsA2DP
                SupportsHFP = $supportsHFP
                IsDefaultPlayback = $isDefaultPlayback
                Notes = $notes
            }
        }

        # Also add devices found only via audio endpoints (in case BT class didn't catch them)
        foreach ($baseName in $deviceProfiles.Keys) {
            $normalizedName = $baseName.Trim()
            if ($seenDevices.ContainsKey($normalizedName)) {
                continue
            }

            # Skip transport nodes
            if (Test-IsTransportOrServiceNode -Name $normalizedName) {
                continue
            }

            $profiles = $deviceProfiles[$baseName]
            $primaryEndpoint = $profiles.Endpoints | Where-Object { $_.Status -eq 'OK' } | Select-Object -First 1
            if (-not $primaryEndpoint) {
                $primaryEndpoint = $profiles.Endpoints | Select-Object -First 1
            }

            if (-not $primaryEndpoint) { continue }

            # Determine device kind
            $deviceKind = "Unknown"
            if ($normalizedName -match "AirPods|Buds|Earbuds|WF-") {
                $deviceKind = "Earbuds"
            }
            elseif ($normalizedName -match "Headphone|Headset|WH-|Jabra|Over-Ear") {
                $deviceKind = "Headphones"
            }
            elseif ($normalizedName -match "Speaker|Soundbar|Echo|HomePod|Pill|Flip|Charge|Xtreme|Boom|Kanto|ORA|Dime") {
                $deviceKind = "Speaker"
            }

            # Connection state from endpoint
            $connectionState = if ($primaryEndpoint.Status -eq 'OK') { "Connected" } else { "Paired" }

            # Check if default playback
            $isDefaultPlayback = $null
            if ($defaultPlaybackName) {
                if ($defaultPlaybackName -match [regex]::Escape($normalizedName)) {
                    $isDefaultPlayback = $true
                }
                else {
                    $isDefaultPlayback = $false
                }
            }

            $seenDevices[$normalizedName] = $true

            $devices += [PSCustomObject]@{
                Name = $normalizedName
                InstanceId = $primaryEndpoint.InstanceId
                Status = $primaryEndpoint.Status
                ConnectionState = $connectionState
                IsAudioDevice = $true
                DeviceKind = $deviceKind
                SupportsA2DP = $profiles.HasA2DP
                SupportsHFP = $profiles.HasHFP
                IsDefaultPlayback = $isDefaultPlayback
                Notes = $notes
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
    #>
    [CmdletBinding()]
    param()

    $cutoffTime = (Get-Date).AddMinutes(-60)
    $hints = @()
    $logsAccessible = @{
        BthUSB = $false
        System = $false
    }

    # BthUSB operational log - may be disabled or not present on some systems (normal)
    try {
        $btEvents = Get-WinEvent -LogName "Microsoft-Windows-Bluetooth-BthUSB/Operational" -MaxEvents 50 -ErrorAction Stop |
            Where-Object { $_.TimeCreated -gt $cutoffTime }

        $logsAccessible.BthUSB = $true

        foreach ($evt in $btEvents) {
            if ($evt.LevelDisplayName -in @("Error", "Warning") -or $evt.Message -match "disconnect|removed|failed|reset") {
                $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                $hints += @{
                    Source = "BthUSB"
                    Time = $evt.TimeCreated
                    Level = $evt.LevelDisplayName
                    Id = $evt.Id
                    Message = $msgSnippet
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
            if ($evt.LevelDisplayName -in @("Error", "Warning")) {
                $msgSnippet = if ($evt.Message.Length -gt 200) { $evt.Message.Substring(0, 200) + "..." } else { $evt.Message }
                $hints += @{
                    Source = "System"
                    Time = $evt.TimeCreated
                    Level = $evt.LevelDisplayName
                    Id = $evt.Id
                    ProviderName = $evt.ProviderName
                    Message = $msgSnippet
                }
            }
        }
    }
    catch {
        # Silent fail - log access issues are not diagnostic concerns
        $logsAccessible.System = $false
    }

    $disconnectCount = ($hints | Where-Object { $_.Message -match "disconnect|removed|lost" }).Count

    return @{
        Count = $hints.Count
        HasErrors = ($hints | Where-Object { $_.Level -eq "Error" }).Count -gt 0
        HasWarnings = ($hints | Where-Object { $_.Level -eq "Warning" }).Count -gt 0
        DisconnectEvents = $disconnectCount
        FrequentDisconnects = $disconnectCount -ge 3
        LogsAccessible = $logsAccessible
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
                    Severity = "FAIL"
                    AppliesTo = "Hardware"
                    Evidence = @("No Bluetooth radio detected on this system")
                    ActionHint = "Verify Bluetooth hardware is installed or enable in BIOS"
                }
            }
            "ADAPTER_DISABLED" {
                @{
                    Id = "ADAPTER_DISABLED"
                    Title = "Bluetooth Adapter Disabled"
                    Severity = "FAIL"
                    AppliesTo = "Hardware"
                    Evidence = @("Bluetooth adapter status: $($Diagnostics.Adapter.Status)")
                    ActionHint = "Enable Bluetooth in Windows Settings or Device Manager"
                }
            }
            "AUDIO_SERVICE_DEAD" {
                @{
                    Id = "AUDIO_SERVICE_DEAD"
                    Title = "Windows Audio Service Stopped"
                    Severity = "FAIL"
                    AppliesTo = "Audio"
                    Evidence = @("Audiosrv service is not running")
                    ActionHint = "Restart Windows Audio service"
                }
            }
            "PASSTHROUGH_BT_CONFLICT" {
                @{
                    Id = "PASSTHROUGH_BT_CONFLICT"
                    Title = "Passthrough Incompatible with Bluetooth"
                    Severity = "FAIL"
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
                    Severity = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @("Device: $($hfpDevice.Name)", "HFP provides mono 8kHz audio", "Stereo A2DP profile preferred")
                    ActionHint = "Switch to Stereo output in Windows Sound settings"
                }
            }
            "DEFAULT_IS_HFP" {
                @{
                    Id = "DEFAULT_IS_HFP"
                    Title = "Default Playback is Hands-Free"
                    Severity = "WARN"
                    AppliesTo = "Audio Quality"
                    Evidence = @("Default device: $($Diagnostics.DefaultPlayback.RegistryDevice)", "HFP mode has reduced audio quality")
                    ActionHint = "Set Stereo variant as default in Sound settings"
                }
            }
            "WASAPI_BT_RISK" {
                @{
                    Id = "WASAPI_BT_RISK"
                    Title = "WASAPI Mode with Bluetooth"
                    Severity = "WARN"
                    AppliesTo = "Stability"
                    Evidence = @("Kodi using WASAPI output", "Bluetooth device active", "Exclusive mode may cause audio dropouts")
                    ActionHint = "Change Kodi to DirectSound: Default output"
                }
            }
            "FREQUENT_DISCONNECTS" {
                @{
                    Id = "FREQUENT_DISCONNECTS"
                    Title = "Frequent Bluetooth Disconnects"
                    Severity = "WARN"
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
                    Severity = "WARN"
                    AppliesTo = "Device Routing"
                    Evidence = @("$ghostCount disconnected Bluetooth audio endpoint(s)", "May cause routing confusion")
                    ActionHint = "Use 'Remove Stale BT Audio Endpoints' to clean up"
                }
            }
            "BTHSERV_STOPPED" {
                @{
                    Id = "BTHSERV_STOPPED"
                    Title = "Bluetooth Service Stopped"
                    Severity = "WARN"
                    AppliesTo = "Connectivity"
                    Evidence = @("Bluetooth Support Service (bthserv) not running")
                    ActionHint = "Use 'Restart Bluetooth + Audio Services' button"
                }
            }
            "BTAG_STOPPED" {
                @{
                    Id = "BTAG_STOPPED"
                    Title = "Bluetooth Audio Gateway Stopped"
                    Severity = "WARN"
                    AppliesTo = "Audio Routing"
                    Evidence = @("BTAGService not running", "May affect audio device discovery")
                    ActionHint = "Use 'Restart Bluetooth + Audio Services' button"
                }
            }
            "EVENT_LOG_ERRORS" {
                @{
                    Id = "EVENT_LOG_ERRORS"
                    Title = "Bluetooth Errors in Event Log"
                    Severity = "INFO"
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
                    Severity = "WARN"
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
                    Severity = "WARN"
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
                    Severity = "WARN"
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
                Severity = "INFO"
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
        $probeResult.Result = "FAIL"
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
        $probeResult.Result = "FAIL"
        $probeResult.TerminalState = "ProbeTimedOut"
        $probeResult.Confidence = "Low"
    }
    elseif ($probeResult.Disconnects -gt 0) {
        $probeResult.Result = "FAIL"
        $probeResult.TerminalState = "ProbeCompleted"
        $probeResult.Confidence = "High"
    }
    elseif ($probeResult.DeviceChanges -gt 1) {
        $probeResult.Result = "FAIL"
        $probeResult.TerminalState = "ProbeCompleted"
        $probeResult.Confidence = "Med"
    }
    elseif ($probeResult.Error) {
        $probeResult.Result = "FAIL"
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
        return @{
            Success = $true
            DryRun = $true
            Changed = $false
            TerminalState = "ResetCompleted"
            Message = "Dry-run mode - no changes made"
        }
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
        return @{
            Success = $true
            DryRun = $true
            Changed = $false
            TerminalState = "CleanupCompleted"
            Message = "Dry-run mode - no changes made"
        }
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
        return @{
            Success = $true
            DryRun = $true
            Changed = $false
            TerminalState = "ResetCompleted"
            Message = "Dry-run mode - no changes made"
        }
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
        return @{
            Success = $true
            DryRun = $true
            Changed = $false
            TerminalState = "DisableCompleted"
            Message = "Dry-run mode - no changes made"
        }
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
        return @{
            Success = $true
            DryRun = $true
            Changed = $false
            TerminalState = "RemoveCompleted"
            Message = "Dry-run mode - no changes made"
        }
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
    'Test-BufferUnderrunRisk'
)

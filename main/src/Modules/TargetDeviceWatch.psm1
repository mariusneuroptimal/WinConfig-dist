# TargetDeviceWatch.psm1 - Mode A: Non-audio Device Watch for the Flight Recorder
#
# Owns:
#   - Target configuration (name, MAC, pairing EXE, app process)
#   - MAC + name normalization
#   - Correlation against PnP snapshots (Get-BluetoothPnpSnapshot output)
#   - Process observation (pairing EXE, app process) via Get-Process
#   - Append-only state-change observation log
#   - target-watch.json persistence
#
# READ-ONLY: this module MUST NOT pair, unpair, kill processes, restart
# services, reset adapters, delete registry keys, or remove devices. It
# only reads PnP snapshots and process state.
#
# The module is mock-friendly: Get-TargetDeviceProcessSnapshot is a thin
# wrapper around Get-Process and is the seam tests replace with Mock.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# STATE MODEL - closed set of values used in target-watch.json
# =============================================================================
# Device-presence states are derived from PnP correlation. Process states are
# derived from process observation. COM-port states are derived from the
# Bluetooth COM-port snapshot via Find-TargetBluetoothComPort. Keep this list
# authoritative; tests read from $script:TargetWatchStates.
$script:TargetWatchStates = @(
    'Unconfigured',
    'Configured',
    'SeenByPnp',
    'PairedCandidate',
    'Missing',
    'Ambiguous',
    'PairingProcessStarted',
    'PairingProcessExited',
    'AppProcessStarted',
    'AppProcessExited',
    'ComPortFound',
    'ComPortMissing',
    'ComPortAmbiguous',
    'ComPortUnconfigured'
)

# COM-port match confidence ladder. 'high' = parent InstanceId / MAC match;
# 'medium' = friendly-name match; 'low' = BTHENUM parent without identifier
# evidence; 'none' = no candidate.
$script:ComPortConfidenceValues = @('none', 'low', 'medium', 'high')

function Get-TargetWatchStateValues {
    [CmdletBinding()]
    param()
    return ,@($script:TargetWatchStates)
}

# =============================================================================
# NORMALIZATION
# =============================================================================

function ConvertTo-NormalizedBluetoothMac {
    <#
    .SYNOPSIS
        Normalizes a Bluetooth MAC address to 12 uppercase hex chars (no
        separators). Returns $null when the input is not a parseable MAC.
    .DESCRIPTION
        Accepts the most common Bluetooth MAC formats:
            AA:BB:CC:DD:EE:FF
            AA-BB-CC-DD-EE-FF
            AABBCCDDEEFF
            aa bb cc dd ee ff
            Dev_AABBCCDDEEFF (lifted from a BTHENUM InstanceId fragment)
        Anything that does not collapse to exactly 12 hex digits returns $null.
        This is intentional: callers branch on $null to record "MAC not
        configured" vs "MAC malformed".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Mac
    )

    if ([string]::IsNullOrWhiteSpace($Mac)) { return $null }

    # Strip the BTHENUM "Dev_" prefix so callers can pass a raw InstanceId
    # fragment without pre-trimming.
    $candidate = $Mac.Trim()
    if ($candidate -match '^Dev_([0-9A-Fa-f]{12})$') {
        return $Matches[1].ToUpperInvariant()
    }

    # Drop common separators and whitespace.
    $stripped = ($candidate -replace '[\s:\-\.]', '').ToUpperInvariant()
    if ($stripped -match '^[0-9A-F]{12}$') {
        return $stripped
    }
    return $null
}

function ConvertTo-NormalizedDeviceName {
    <#
    .SYNOPSIS
        Normalizes a Bluetooth device friendly name for fuzzy comparison.
    .DESCRIPTION
        Lower-cases, collapses whitespace, and strips zero-width / soft
        hyphen characters so two name strings that look identical on screen
        compare equal. Returns $null for null/empty input so callers can
        branch on "name not configured".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    # Strip zero-width / soft-hyphen characters. PowerShell 5.1 lacks the
    # `u{XXXX} escape so the character set is built from [char] literals.
    $zw = -join @(
        [char]0x200B, [char]0x200C, [char]0x200D, [char]0xFEFF, [char]0x00AD
    )
    $pattern = '[' + [regex]::Escape($zw) + ']'
    $cleaned = $Name -replace $pattern, ''
    # Collapse internal whitespace.
    $cleaned = ($cleaned -replace '\s+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($cleaned)) { return $null }
    return $cleaned.ToLowerInvariant()
}

function Get-MacFromPnpInstanceId {
    <#
    .SYNOPSIS
        Extracts a normalized MAC (12 hex, uppercase) from a PnP InstanceId,
        or $null when none is present.
    .DESCRIPTION
        Bluetooth devices live under BTHENUM\ and BTHLEDevice\ trees. The
        device-address fragment is the 12-hex segment of the InstanceId.
        Examples handled:
            BTHENUM\Dev_AABBCCDDEEFF\7&...
            BTHENUM\{...}_VID&...\7&AABBCCDDEEFF&0&...
            BTHLEDevice\Dev_AABBCCDDEEFF\8&...
            BTHLE\Dev_AABBCCDDEEFF
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$InstanceId
    )

    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $null }

    # Direct Dev_ form.
    if ($InstanceId -match 'Dev_([0-9A-Fa-f]{12})') {
        return $Matches[1].ToUpperInvariant()
    }
    # Embedded 12-hex run preceded by `&` (the second InstanceId form above).
    if ($InstanceId -match '&([0-9A-Fa-f]{12})&') {
        return $Matches[1].ToUpperInvariant()
    }
    return $null
}

function Test-IsBluetoothPnpInstanceId {
    <#
    .SYNOPSIS
        Returns $true when an InstanceId is rooted under a Bluetooth tree
        (BTHENUM, BTHLE, BTHLEDevice). Used to filter PnP snapshot entries
        when scoring a target match.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$InstanceId)

    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $false }
    return ($InstanceId -match '^BTHENUM\\' -or
            $InstanceId -match '^BTHLE\\'  -or
            $InstanceId -match '^BTHLEDevice\\')
}

# =============================================================================
# TARGET CONFIGURATION
# =============================================================================

function New-TargetDeviceConfiguration {
    <#
    .SYNOPSIS
        Builds the target configuration hashtable persisted with the session.
    .DESCRIPTION
        Captures raw inputs as the operator typed them PLUS the normalized
        forms used for matching. Either or all inputs may be empty; an
        Unconfigured target is a legitimate state, recorded as evidence.
    .OUTPUTS
        [hashtable] with keys:
            TargetName            : raw, may be $null
            TargetMac             : raw, may be $null
            NormalizedTargetName  : normalized or $null
            NormalizedTargetMac   : 12-hex-uppercase or $null
            MacInputProvided      : $true if user typed something in the MAC field
            MacMalformed          : $true if MacInputProvided but normalization failed
            PairingExePath        : optional path to pairing helper EXE
            PairingExeName        : leaf-name (no extension) used as process key
            AppProcessName        : optional process name (no extension)
            IsConfigured          : $true if any identifier is present
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$TargetName,
        [AllowNull()][AllowEmptyString()][string]$TargetMac,
        [AllowNull()][AllowEmptyString()][string]$PairingExePath,
        [AllowNull()][AllowEmptyString()][string]$AppProcessName
    )

    $rawName = if ([string]::IsNullOrWhiteSpace($TargetName)) { $null } else { $TargetName.Trim() }
    $rawMac  = if ([string]::IsNullOrWhiteSpace($TargetMac))  { $null } else { $TargetMac.Trim() }
    $normName = ConvertTo-NormalizedDeviceName -Name $rawName
    $normMac  = ConvertTo-NormalizedBluetoothMac -Mac $rawMac

    $macInputProvided = -not [string]::IsNullOrWhiteSpace($rawMac)
    $macMalformed     = $macInputProvided -and (-not $normMac)

    $pairingPath = if ([string]::IsNullOrWhiteSpace($PairingExePath)) { $null } else { $PairingExePath.Trim() }
    $pairingProc = $null
    if ($pairingPath) {
        try {
            $pairingProc = [System.IO.Path]::GetFileNameWithoutExtension($pairingPath)
            if ([string]::IsNullOrWhiteSpace($pairingProc)) { $pairingProc = $null }
        } catch { $pairingProc = $null }
    }

    $appProc = if ([string]::IsNullOrWhiteSpace($AppProcessName)) { $null } else { $AppProcessName.Trim() }
    if ($appProc) {
        # Allow operators to paste "labview.exe" or "labview".
        $appProc = [System.IO.Path]::GetFileNameWithoutExtension($appProc)
        if ([string]::IsNullOrWhiteSpace($appProc)) { $appProc = $null }
    }

    $isConfigured = [bool]($normName -or $normMac -or $pairingProc -or $appProc)

    return @{
        TargetName           = $rawName
        TargetMac            = $rawMac
        NormalizedTargetName = $normName
        NormalizedTargetMac  = $normMac
        MacInputProvided     = $macInputProvided
        MacMalformed         = $macMalformed
        PairingExePath       = $pairingPath
        PairingExeName       = $pairingProc
        AppProcessName       = $appProc
        IsConfigured         = $isConfigured
    }
}

# =============================================================================
# CORRELATION
# =============================================================================

function Test-DeviceNameMatch {
    <#
    .SYNOPSIS
        Returns $true when a configured target name corresponds to an enumerated
        device name, tolerating the serial/unit suffix Windows appends.
    .DESCRIPTION
        A paired Bluetooth device frequently enumerates under a name that is the
        base product name plus a unit suffix, e.g. a headset configured as
        "NeurOptimal Headset" appears in PnP as "NeurOptimal Headset - 000019".
        Exact-equality matching misses that device forever, so we also accept a
        token-boundary prefix relationship in either direction. Both arguments
        must already be normalized (see ConvertTo-NormalizedDeviceName).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Target,
        [AllowNull()][AllowEmptyString()][string]$Candidate
    )

    if ([string]::IsNullOrEmpty($Target) -or [string]::IsNullOrEmpty($Candidate)) { return $false }
    if ($Candidate -eq $Target) { return $true }

    # Accept only at a separator boundary so "headset" cannot match "headsets".
    foreach ($sep in @(' ', '-')) {
        if ($Candidate.StartsWith($Target + $sep, [System.StringComparison]::Ordinal)) { return $true }
        if ($Target.StartsWith($Candidate + $sep, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

function Find-TargetDeviceInPnpSnapshot {
    <#
    .SYNOPSIS
        Scores PnP snapshot entries against a target configuration and returns
        a match result.
    .DESCRIPTION
        Correlation order:
          1. MAC match (extracted from InstanceId) — highest confidence.
          2. Normalized friendly-name match — medium confidence.
          3. No match — Missing.
        Ambiguous = >1 candidate at the chosen confidence level.
    .PARAMETER Snapshot
        Output of Get-BluetoothPnpSnapshot (or any object with a Devices
        array of {InstanceId, FriendlyName, Status, Present}).
    .PARAMETER Configuration
        Output of New-TargetDeviceConfiguration.
    .OUTPUTS
        [hashtable] with keys:
            State       : Missing | SeenByPnp | PairedCandidate | Ambiguous | Unconfigured
            Confidence  : 'mac' | 'name' | 'none' | 'unconfigured'
            Matches     : [pscustomobject[]] of matched devices
            Reason      : free-text diagnostic ("matched by MAC 'AABBCCDDEEFF'")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)] [hashtable]$Configuration
    )

    if (-not $Configuration.IsConfigured) {
        return @{
            State      = 'Unconfigured'
            Confidence = 'unconfigured'
            Matches    = @()
            Reason     = 'No target identifiers configured.'
        }
    }

    $devices = @()
    if ($Snapshot -and ($Snapshot.PSObject.Properties.Name -contains 'Devices')) {
        $devices = @($Snapshot.Devices)
    }
    if ($devices.Count -eq 0) {
        return @{
            State      = 'Missing'
            Confidence = 'none'
            Matches    = @()
            Reason     = 'No Bluetooth devices found by Windows (PnP snapshot empty).'
        }
    }

    # Pass 1: MAC.
    if ($Configuration.NormalizedTargetMac) {
        $macMatches = @()
        foreach ($d in $devices) {
            $idMac = Get-MacFromPnpInstanceId -InstanceId $d.InstanceId
            if ($idMac -and ($idMac -eq $Configuration.NormalizedTargetMac)) {
                $macMatches += $d
            }
        }
        if ($macMatches.Count -gt 1) {
            return @{
                State      = 'Ambiguous'
                Confidence = 'mac'
                Matches    = $macMatches
                Reason     = "Multiple devices found with same Bluetooth address $($Configuration.NormalizedTargetMac) (ambiguous PnP MAC match)."
            }
        }
        if ($macMatches.Count -eq 1) {
            $state = if ($macMatches[0].Present) { 'PairedCandidate' } else { 'SeenByPnp' }
            return @{
                State      = $state
                Confidence = 'mac'
                Matches    = $macMatches
                Reason     = "Identified by Bluetooth address $($Configuration.NormalizedTargetMac) (PnP MAC match)."
            }
        }
    }

    # Pass 2: friendly name.
    if ($Configuration.NormalizedTargetName) {
        $target = $Configuration.NormalizedTargetName
        $nameMatches = @()
        foreach ($d in $devices) {
            $n = ConvertTo-NormalizedDeviceName -Name $d.FriendlyName
            if (Test-DeviceNameMatch -Target $target -Candidate $n) { $nameMatches += $d }
        }
        if ($nameMatches.Count -gt 1) {
            return @{
                State      = 'Ambiguous'
                Confidence = 'name'
                Matches    = $nameMatches
                Reason     = "Multiple devices found with name '$($Configuration.TargetName)' (ambiguous PnP name match)."
            }
        }
        if ($nameMatches.Count -eq 1) {
            $state = if ($nameMatches[0].Present) { 'PairedCandidate' } else { 'SeenByPnp' }
            return @{
                State      = $state
                Confidence = 'name'
                Matches    = $nameMatches
                Reason     = "Matched by name '$($Configuration.TargetName)'."
            }
        }
    }

    return @{
        State      = 'Missing'
        Confidence = 'none'
        Matches    = @()
        Reason     = 'Windows cannot see the target headset -- is it powered on and in range? (no PnP match).'
    }
}

# =============================================================================
# COM-PORT CORRELATION
# =============================================================================

function Find-TargetBluetoothComPort {
    <#
    .SYNOPSIS
        Correlates Bluetooth COM-port snapshot entries to a target configuration.
    .DESCRIPTION
        Scores each port in a Get-BluetoothComPortSnapshot output against the
        target by, in order of confidence:
            high   : normalized MAC present in InstanceId / ParentBluetoothInstanceId
            medium : normalized target name present in FriendlyName / DeviceName
            low    : BTHENUM-rooted entry with no identifier evidence (only
                     emitted when the operator explicitly opted into a name-only
                     match and the name regex didn't fire — kept for visibility,
                     never used as a "Found" state)

        Returns a closed-shape result. MatchState transitions are emitted to the
        timeline only when they actually change (see Update-TargetWatchState).
    .PARAMETER Snapshot
        Output of Get-BluetoothComPortSnapshot (or any object with a Ports
        array of {InstanceId, FriendlyName, DeviceName, PortName,
        ParentBluetoothInstanceId, AssociatedBluetoothMac}).
    .PARAMETER Configuration
        Output of New-TargetDeviceConfiguration.
    .OUTPUTS
        [hashtable] with keys:
            MatchState        : Unconfigured | Missing | Found | Ambiguous
            Confidence        : none | low | medium | high
            Matches           : [pscustomobject[]]
            AmbiguousMatches  : [pscustomobject[]]
            Unresolved        : [string[]]   (operator-readable issue summaries)
            Reason            : free-text diagnostic
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)][hashtable]$Configuration
    )

    if (-not $Configuration.IsConfigured) {
        return @{
            MatchState       = 'Unconfigured'
            Confidence       = 'none'
            Matches          = @()
            AmbiguousMatches = @()
            Unresolved       = @()
            Reason           = 'No target identifiers configured.'
        }
    }

    $ports = @()
    if ($Snapshot -and ($Snapshot.PSObject.Properties.Name -contains 'Ports')) {
        $ports = @($Snapshot.Ports)
    }

    if ($ports.Count -eq 0) {
        return @{
            MatchState       = 'Missing'
            Confidence       = 'none'
            Matches          = @()
            AmbiguousMatches = @()
            Unresolved       = @('No Bluetooth serial ports found -- headset may not be paired yet (BTHENUM empty).')
            Reason           = 'No Bluetooth serial ports found -- headset may not be paired yet (BTHENUM empty).'
        }
    }

    # Pass 1: MAC. The MAC may live on the port row itself OR on its parent
    # BTHENUM node; Get-BluetoothComPortSnapshot pre-fills AssociatedBluetoothMac
    # from whichever was inferable.
    if ($Configuration.NormalizedTargetMac) {
        $hits = @()
        foreach ($p in $ports) {
            $m = $null
            if ($p.PSObject.Properties.Name -contains 'AssociatedBluetoothMac') { $m = $p.AssociatedBluetoothMac }
            if (-not $m) { $m = Get-MacFromPnpInstanceId -InstanceId $p.InstanceId }
            if (-not $m -and ($p.PSObject.Properties.Name -contains 'ParentBluetoothInstanceId')) {
                $m = Get-MacFromPnpInstanceId -InstanceId $p.ParentBluetoothInstanceId
            }
            # RFCOMM / SPP COM-port InstanceId form: ...&0&AABBCCDDEEFF_CHANNEL
            # e.g. BTHENUM\{00001101-...}_VID&...\7&xxxx&0&8C1F6471000B_C00000000
            # Not matched by Get-MacFromPnpInstanceId (which uses Dev_ and &MAC& forms
            # only, to avoid false-positives on service sub-entries in PnP matching).
            if (-not $m -and $p.InstanceId -match '&0&([0-9A-Fa-f]{12})_') {
                $m = $Matches[1].ToUpperInvariant()
            }
            if ($m -and ($m -eq $Configuration.NormalizedTargetMac)) { $hits += $p }
        }
        if ($hits.Count -gt 1) {
            return @{
                MatchState       = 'Ambiguous'
                Confidence       = 'high'
                Matches          = $hits
                AmbiguousMatches = $hits
                Unresolved       = @("Multiple COM ports for Bluetooth address $($Configuration.NormalizedTargetMac) (ambiguous BTHENUM MAC match).")
                Reason           = "Multiple COM ports for Bluetooth address $($Configuration.NormalizedTargetMac) (ambiguous BTHENUM MAC match)."
            }
        }
        if ($hits.Count -eq 1) {
            $unresolved = @()
            if (-not $hits[0].PortName) { $unresolved += "COM port entry found but no port number assigned (InstanceId=$($hits[0].InstanceId))." }
            return @{
                MatchState       = 'Found'
                Confidence       = 'high'
                Matches          = $hits
                AmbiguousMatches = @()
                Unresolved       = $unresolved
                Reason           = "COM port identified by Bluetooth address $($Configuration.NormalizedTargetMac) -> $(if ($hits[0].PortName) { $hits[0].PortName } else { '(no PortName)' }) (BTHENUM MAC match)."
            }
        }
    }

    # Pass 2: friendly name. Use ConvertTo-NormalizedDeviceName on the source
    # text so casing/whitespace doesn't gate the match.
    if ($Configuration.NormalizedTargetName) {
        $target = $Configuration.NormalizedTargetName
        $hits = @()
        foreach ($p in $ports) {
            $candidates = @()
            if ($p.PSObject.Properties.Name -contains 'FriendlyName') { $candidates += [string]$p.FriendlyName }
            if ($p.PSObject.Properties.Name -contains 'DeviceName')   { $candidates += [string]$p.DeviceName }
            foreach ($c in $candidates) {
                $n = ConvertTo-NormalizedDeviceName -Name $c
                if ($n -and ($n -eq $target -or $n.Contains($target))) {
                    $hits += $p
                    break
                }
            }
        }
        if ($hits.Count -gt 1) {
            return @{
                MatchState       = 'Ambiguous'
                Confidence       = 'medium'
                Matches          = $hits
                AmbiguousMatches = $hits
                Unresolved       = @("Multiple COM ports found with name '$($Configuration.TargetName)' (ambiguous BTHENUM name match).")
                Reason           = "Multiple COM ports found with name '$($Configuration.TargetName)' (ambiguous BTHENUM name match)."
            }
        }
        if ($hits.Count -eq 1) {
            $unresolved = @()
            if (-not $hits[0].PortName) { $unresolved += "COM port entry found but no port number assigned (InstanceId=$($hits[0].InstanceId))." }
            return @{
                MatchState       = 'Found'
                Confidence       = 'medium'
                Matches          = $hits
                AmbiguousMatches = @()
                Unresolved       = $unresolved
                Reason           = "COM port identified by name '$($Configuration.TargetName)' -> $(if ($hits[0].PortName) { $hits[0].PortName } else { '(no PortName)' }) (BTHENUM name match)."
            }
        }
    }

    return @{
        MatchState       = 'Missing'
        Confidence       = 'none'
        Matches          = @()
        AmbiguousMatches = @()
        Unresolved       = @('No COM port assigned to the headset -- usually appears after pairing completes (no BTHENUM match).')
        Reason           = 'No COM port assigned to the headset -- usually appears after pairing completes (no BTHENUM match).'
    }
}

# =============================================================================
# PROCESS OBSERVATION
# =============================================================================

function Get-TargetDeviceProcessSnapshot {
    <#
    .SYNOPSIS
        Returns the set of running process names (no extension, lower case).
        Mock seam for tests.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    try {
        $names = Get-Process -ErrorAction Stop |
            ForEach-Object { $_.ProcessName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.ToLowerInvariant() }
        return ,@($names | Select-Object -Unique)
    } catch {
        return ,@()
    }
}

function Test-ProcessRunningInSnapshot {
    <#
    .SYNOPSIS
        Case-insensitive test for whether $Name (with or without .exe) is in
        a process-name list.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ProcessNames,
        [Parameter(Mandatory)][string]$Name
    )
    $key = [System.IO.Path]::GetFileNameWithoutExtension($Name).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) { return $false }
    if ($ProcessNames.Count -eq 0) { return $false }
    return ($ProcessNames -contains $key)
}

# =============================================================================
# WATCH STATE - in-memory tracker for an active session
# =============================================================================

function New-TargetWatchState {
    <#
    .SYNOPSIS
        Builds a fresh watch-state record. Caller is responsible for handing
        this to Update-TargetWatchState on each poll.
    .OUTPUTS
        [hashtable]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Configuration
    )
    return @{
        Configuration         = $Configuration
        DeviceState           = if ($Configuration.IsConfigured) { 'Configured' } else { 'Unconfigured' }
        DeviceConfidence      = if ($Configuration.IsConfigured) { 'pending' } else { 'unconfigured' }
        FirstSeenTime         = $null
        LastSeenTime          = $null
        PairingProcessState   = 'NotRunning'
        AppProcessState       = 'NotRunning'
        Observations          = New-Object System.Collections.ArrayList
        AmbiguousMatches      = New-Object System.Collections.ArrayList
        LastMatch             = $null
        # COM-port tracking. ComPortState is 'pending' until the first
        # Find-TargetBluetoothComPort pass runs so we can distinguish "never
        # observed" from "observed missing".
        ComPortState          = if ($Configuration.IsConfigured) { 'pending' } else { 'ComPortUnconfigured' }
        ComPortConfidence     = 'none'
        FirstComPortSeenTime  = $null
        LastComPortSeenTime   = $null
        ComPortMatches        = New-Object System.Collections.ArrayList
        AmbiguousComPortMatches = New-Object System.Collections.ArrayList
        LastComPortMatch      = $null
        ServiceSurfaceSummary = $null
        ComPortUnresolved     = New-Object System.Collections.ArrayList
    }
}

function Add-TargetWatchObservation {
    <#
    .SYNOPSIS
        Internal: append-only observation row. Returns the appended row so
        the caller can mirror it into the session timeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)][ValidateSet('device', 'process', 'comport')][string]$Kind,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$Reason,
        [hashtable]$Data,
        [datetime]$When = (Get-Date)
    )
    if ($State -notin $script:TargetWatchStates) {
        throw "Invalid target-watch state '$State'. Valid: $($script:TargetWatchStates -join ', ')"
    }
    $entry = [ordered]@{
        Time   = $When.ToString('o')
        Kind   = $Kind
        State  = $State
        Reason = $Reason
    }
    if ($Data) { $entry.Data = $Data }
    [void]$WatchState.Observations.Add([pscustomobject]$entry)
    return [pscustomobject]$entry
}

function Update-TargetWatchState {
    <#
    .SYNOPSIS
        Reconciles a watch state with a fresh PnP snapshot + process snapshot
        (+ optional COM-port snapshot) and appends observation rows ONLY when
        the state actually changes.
    .PARAMETER WatchState
        Hashtable from New-TargetWatchState.
    .PARAMETER PnpSnapshot
        Output of Get-BluetoothPnpSnapshot.
    .PARAMETER ProcessNames
        Output of Get-TargetDeviceProcessSnapshot.
    .PARAMETER ComPortSnapshot
        Optional output of Get-BluetoothComPortSnapshot. When omitted, COM-port
        state is not updated this pass (older callers stay source-compatible).
    .PARAMETER Now
        Override for the "current time" (tests). Defaults to Get-Date.
    .OUTPUTS
        [pscustomobject[]] - the observation rows appended this pass (may be
        empty when nothing changed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)] $PnpSnapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ProcessNames,
        [Parameter()] $ComPortSnapshot,
        [datetime]$Now = (Get-Date)
    )

    $appended = @()
    $cfg = $WatchState.Configuration

    # ---- device correlation -----------------------------------------------
    $match = Find-TargetDeviceInPnpSnapshot -Snapshot $PnpSnapshot -Configuration $cfg
    $WatchState.LastMatch = $match
    $newState = $match.State

    if ($newState -in @('PairedCandidate', 'SeenByPnp')) {
        if (-not $WatchState.FirstSeenTime) { $WatchState.FirstSeenTime = $Now }
        $WatchState.LastSeenTime = $Now
    }

    if ($newState -ne $WatchState.DeviceState) {
        $oldState = $WatchState.DeviceState
        $WatchState.DeviceState      = $newState
        $WatchState.DeviceConfidence = $match.Confidence
        $data = @{
            From       = $oldState
            To         = $newState
            Confidence = $match.Confidence
            MatchCount = @($match.Matches).Count
        }
        if (@($match.Matches).Count -gt 0) {
            $data.MatchedInstanceIds = @($match.Matches | ForEach-Object { $_.InstanceId })
        }
        if ($newState -eq 'Ambiguous') {
            foreach ($m in @($match.Matches)) {
                [void]$WatchState.AmbiguousMatches.Add([pscustomobject]@{
                    Time         = $Now.ToString('o')
                    InstanceId   = $m.InstanceId
                    FriendlyName = $m.FriendlyName
                    Confidence   = $match.Confidence
                })
            }
        }
        $appended += Add-TargetWatchObservation `
            -WatchState $WatchState -Kind 'device' -State $newState `
            -Reason $match.Reason -Data $data -When $Now
    }

    # ---- pairing process --------------------------------------------------
    if ($cfg.PairingExeName) {
        $running = Test-ProcessRunningInSnapshot -ProcessNames $ProcessNames -Name $cfg.PairingExeName
        $current = $WatchState.PairingProcessState
        if ($running -and $current -ne 'Running') {
            $WatchState.PairingProcessState = 'Running'
            $appended += Add-TargetWatchObservation `
                -WatchState $WatchState -Kind 'process' -State 'PairingProcessStarted' `
                -Reason "Pairing process '$($cfg.PairingExeName)' started." `
                -Data @{ Process = $cfg.PairingExeName } -When $Now
        } elseif (-not $running -and $current -eq 'Running') {
            $WatchState.PairingProcessState = 'NotRunning'
            $appended += Add-TargetWatchObservation `
                -WatchState $WatchState -Kind 'process' -State 'PairingProcessExited' `
                -Reason "Pairing process '$($cfg.PairingExeName)' exited." `
                -Data @{ Process = $cfg.PairingExeName } -When $Now
        }
    }

    # ---- app process ------------------------------------------------------
    if ($cfg.AppProcessName) {
        $running = Test-ProcessRunningInSnapshot -ProcessNames $ProcessNames -Name $cfg.AppProcessName
        $current = $WatchState.AppProcessState
        if ($running -and $current -ne 'Running') {
            $WatchState.AppProcessState = 'Running'
            $appended += Add-TargetWatchObservation `
                -WatchState $WatchState -Kind 'process' -State 'AppProcessStarted' `
                -Reason "App process '$($cfg.AppProcessName)' started." `
                -Data @{ Process = $cfg.AppProcessName } -When $Now
        } elseif (-not $running -and $current -eq 'Running') {
            $WatchState.AppProcessState = 'NotRunning'
            $appended += Add-TargetWatchObservation `
                -WatchState $WatchState -Kind 'process' -State 'AppProcessExited' `
                -Reason "App process '$($cfg.AppProcessName)' exited." `
                -Data @{ Process = $cfg.AppProcessName } -When $Now
        }
    }

    # ---- com port correlation --------------------------------------------
    if ($null -ne $ComPortSnapshot) {
        $cpAppended = Update-TargetComPortState `
            -WatchState $WatchState -ComPortSnapshot $ComPortSnapshot -Now $Now
        if ($cpAppended) { $appended += $cpAppended }
    }

    return ,@($appended)
}

function Update-TargetComPortState {
    <#
    .SYNOPSIS
        Internal helper: reconciles COM-port state with a fresh ComPortSnapshot,
        mutates the watch-state hashtable in place, and returns the observation
        rows appended this pass. Factored out so tests can drive COM-port
        transitions without manufacturing a full PnP snapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)] $ComPortSnapshot,
        [datetime]$Now = (Get-Date)
    )

    $cfg = $WatchState.Configuration
    $appended = @()

    $cpMatch = Find-TargetBluetoothComPort -Snapshot $ComPortSnapshot -Configuration $cfg
    $WatchState.LastComPortMatch = $cpMatch

    # Convert the MatchState into the timeline state vocabulary. We use
    # ComPortFound / ComPortMissing / ComPortAmbiguous / ComPortUnconfigured
    # so timeline filters can distinguish device vs. com-port transitions.
    $cpStateNew = switch ($cpMatch.MatchState) {
        'Found'        { 'ComPortFound' }
        'Missing'      { 'ComPortMissing' }
        'Ambiguous'    { 'ComPortAmbiguous' }
        'Unconfigured' { 'ComPortUnconfigured' }
        default        { 'ComPortMissing' }
    }
    $cpStateOld = $WatchState.ComPortState

    # Count ComPortAmbiguous as "seen" -- both SPP channels present is healthy.
    if ($cpStateNew -eq 'ComPortFound' -or $cpStateNew -eq 'ComPortAmbiguous') {
        if (-not $WatchState.FirstComPortSeenTime) { $WatchState.FirstComPortSeenTime = $Now }
        $WatchState.LastComPortSeenTime = $Now
    }

    # Replace the rolling matches/ambiguous arrays so the report carries the
    # latest evidence, but only ADD a timeline entry on actual state changes.
    $WatchState.ComPortConfidence = $cpMatch.Confidence
    $WatchState.ComPortMatches.Clear()
    foreach ($m in @($cpMatch.Matches)) {
        [void]$WatchState.ComPortMatches.Add([pscustomobject]@{
            InstanceId               = $m.InstanceId
            FriendlyName             = $m.FriendlyName
            PortName                 = $m.PortName
            Present                  = $m.Present
            Status                   = $m.Status
            ParentBluetoothInstanceId= if ($m.PSObject.Properties.Name -contains 'ParentBluetoothInstanceId') { $m.ParentBluetoothInstanceId } else { $null }
            AssociatedBluetoothMac   = if ($m.PSObject.Properties.Name -contains 'AssociatedBluetoothMac')    { $m.AssociatedBluetoothMac }    else { $null }
            Confidence               = $cpMatch.Confidence
        })
    }

    $WatchState.ComPortUnresolved.Clear()
    foreach ($u in @($cpMatch.Unresolved)) { [void]$WatchState.ComPortUnresolved.Add($u) }

    if ($cpStateNew -ne $cpStateOld) {
        $WatchState.ComPortState = $cpStateNew
        $portName = $null
        if (@($cpMatch.Matches).Count -gt 0) { $portName = ($cpMatch.Matches[0]).PortName }
        $data = @{
            From       = $cpStateOld
            To         = $cpStateNew
            Confidence = $cpMatch.Confidence
            MatchCount = @($cpMatch.Matches).Count
            PortName   = $portName
        }
        if (@($cpMatch.Matches).Count -gt 0) {
            $data.MatchedInstanceIds = @($cpMatch.Matches | ForEach-Object { $_.InstanceId })
        }
        if ($cpStateNew -eq 'ComPortAmbiguous') {
            # Clear before re-populating so repeated ComPortAmbiguous transitions
            # don't accumulate duplicate entries across reconnect cycles.
            $WatchState.AmbiguousComPortMatches.Clear()
            foreach ($m in @($cpMatch.AmbiguousMatches)) {
                [void]$WatchState.AmbiguousComPortMatches.Add([pscustomobject]@{
                    Time         = $Now.ToString('o')
                    InstanceId   = $m.InstanceId
                    FriendlyName = $m.FriendlyName
                    PortName     = $m.PortName
                    Confidence   = $cpMatch.Confidence
                })
            }
        }
        $appended += Add-TargetWatchObservation `
            -WatchState $WatchState -Kind 'comport' -State $cpStateNew `
            -Reason $cpMatch.Reason -Data $data -When $Now
    }

    return ,@($appended)
}

function Set-TargetWatchServiceSurfaceSummary {
    <#
    .SYNOPSIS
        Stamps the latest service-surface snapshot summary onto the watch state
        so target-watch.json can carry it forward.
    .DESCRIPTION
        Pure record-keeper: doesn't emit timeline entries on its own (the
        session module owns service-surface narration). Stores a compact view
        (TotalPresent + ByService counts + Failures) instead of the full
        Surfaces array to keep target-watch.json bounded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)] $ServiceSurfaceSnapshot
    )

    if (-not $ServiceSurfaceSnapshot) { return }

    # ByService arrives as either a hashtable (in-process) or a PSCustomObject
    # (after a JSON round-trip). Normalize to a flat array either way so the
    # report layer can iterate without caring about the source path.
    $byService = @()
    if ($ServiceSurfaceSnapshot.PSObject.Properties.Name -contains 'Summary' -and $ServiceSurfaceSnapshot.Summary) {
        $sum = $ServiceSurfaceSnapshot.Summary
        if ($sum.PSObject.Properties.Name -contains 'ByService' -and $sum.ByService) {
            $bs = $sum.ByService
            if ($bs -is [hashtable] -or $bs -is [System.Collections.IDictionary]) {
                foreach ($k in @($bs.Keys)) { $byService += $bs[$k] }
            } else {
                foreach ($prop in @($bs.PSObject.Properties)) { $byService += $prop.Value }
            }
        }
    }
    $failureCount = 0
    if ($ServiceSurfaceSnapshot.PSObject.Properties.Name -contains 'Failures' -and $ServiceSurfaceSnapshot.Failures) {
        $failureCount = @($ServiceSurfaceSnapshot.Failures).Count
    }
    $count = 0
    if ($ServiceSurfaceSnapshot.PSObject.Properties.Name -contains 'Count') { $count = [int]$ServiceSurfaceSnapshot.Count }

    $WatchState.ServiceSurfaceSummary = [pscustomobject]@{
        CapturedAt   = if ($ServiceSurfaceSnapshot.PSObject.Properties.Name -contains 'CapturedAt') { $ServiceSurfaceSnapshot.CapturedAt } else { (Get-Date) }
        Count        = $count
        TotalPresent = if ($ServiceSurfaceSnapshot.Summary -and ($ServiceSurfaceSnapshot.Summary.PSObject.Properties.Name -contains 'TotalPresent')) { [int]$ServiceSurfaceSnapshot.Summary.TotalPresent } else { 0 }
        ByService    = $byService
        FailureCount = $failureCount
    }
}

# =============================================================================
# PERSISTENCE - target-watch.json
# =============================================================================

function New-TargetWatchReport {
    <#
    .SYNOPSIS
        Builds the persisted target-watch.json payload from a watch state.
    .DESCRIPTION
        Pure transform: no I/O. Tests can assert on the returned object
        without writing to disk.
    .OUTPUTS
        [pscustomobject] with PSTypeName 'WinConfig.FlightRecorder.TargetWatchReport'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState
    )

    $cfg = $WatchState.Configuration
    $unresolved = @()
    if ($cfg.MacMalformed) {
        $unresolved += "MAC '$($cfg.TargetMac)' did not parse as 12 hex digits."
    }
    if ($WatchState.AmbiguousMatches.Count -gt 0) {
        $unresolved += "Ambiguous PnP matches recorded (count=$($WatchState.AmbiguousMatches.Count))."
    }
    if ($cfg.IsConfigured -and -not $WatchState.FirstSeenTime) {
        $unresolved += 'Target never matched a PnP entry during the session.'
    }
    # Only flag "never exposed COM port" if no COM port was seen at ANY point during
    # the session. If the device was simply disconnected at session end, ComPortState
    # will be ComPortMissing even though ports were seen earlier -- don't report that.
    if ($cfg.IsConfigured -and -not $WatchState.FirstComPortSeenTime) {
        $unresolved += 'Target never exposed a Bluetooth COM port during the session.'
    }
    if ($WatchState.AmbiguousComPortMatches.Count -gt 0) {
        $unresolved += "Ambiguous COM-port matches recorded (count=$($WatchState.AmbiguousComPortMatches.Count))."
    }
    # ComPortUnresolved holds the last snapshot's per-match reasons. Only include
    # them if a COM port was never seen -- otherwise they just reflect end-of-session
    # disconnect state, which is already captured by ComPortState.
    if (-not $WatchState.FirstComPortSeenTime) {
        foreach ($u in @($WatchState.ComPortUnresolved)) {
            if ($u -and ($unresolved -notcontains $u)) { $unresolved += $u }
        }
    }

    return [pscustomobject]@{
        PSTypeName      = 'WinConfig.FlightRecorder.TargetWatchReport'
        Configuration   = [pscustomobject]@{
            TargetName            = $cfg.TargetName
            TargetMac             = $cfg.TargetMac
            NormalizedTargetName  = $cfg.NormalizedTargetName
            NormalizedTargetMac   = $cfg.NormalizedTargetMac
            MacInputProvided      = $cfg.MacInputProvided
            MacMalformed          = $cfg.MacMalformed
            PairingExePath        = $cfg.PairingExePath
            PairingExeName        = $cfg.PairingExeName
            AppProcessName        = $cfg.AppProcessName
            IsConfigured          = $cfg.IsConfigured
        }
        DeviceState     = $WatchState.DeviceState
        DeviceConfidence= $WatchState.DeviceConfidence
        FirstSeenTime   = if ($WatchState.FirstSeenTime) { $WatchState.FirstSeenTime.ToString('o') } else { $null }
        LastSeenTime    = if ($WatchState.LastSeenTime)  { $WatchState.LastSeenTime.ToString('o')  } else { $null }
        ProcessObservations = [pscustomobject]@{
            PairingProcessName = $cfg.PairingExeName
            PairingProcessState= $WatchState.PairingProcessState
            AppProcessName     = $cfg.AppProcessName
            AppProcessState    = $WatchState.AppProcessState
        }
        Observations    = @($WatchState.Observations)
        AmbiguousMatches= @($WatchState.AmbiguousMatches)
        # ---- COM port + service-surface correlation ------------------------
        ComPortState            = $WatchState.ComPortState
        ComPortConfidence       = $WatchState.ComPortConfidence
        FirstComPortSeenTime    = if ($WatchState.FirstComPortSeenTime) { $WatchState.FirstComPortSeenTime.ToString('o') } else { $null }
        LastComPortSeenTime     = if ($WatchState.LastComPortSeenTime)  { $WatchState.LastComPortSeenTime.ToString('o')  } else { $null }
        ComPortMatches          = @($WatchState.ComPortMatches)
        AmbiguousComPortMatches = @($WatchState.AmbiguousComPortMatches)
        ServiceSurfaceSummary   = $WatchState.ServiceSurfaceSummary
        Unresolved              = $unresolved
    }
}

function Save-TargetWatchReport {
    <#
    .SYNOPSIS
        Writes target-watch.json to a session directory. Returns the full
        path. Errors propagate to the caller because failure to persist
        evidence is worth surfacing in the timeline.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)][string]$SessionRoot
    )
    $report = New-TargetWatchReport -WatchState $WatchState
    $outPath = Join-Path $SessionRoot 'target-watch.json'
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outPath -Encoding UTF8
    return $outPath
}

Export-ModuleMember -Function @(
    'Get-TargetWatchStateValues',
    'ConvertTo-NormalizedBluetoothMac',
    'ConvertTo-NormalizedDeviceName',
    'Get-MacFromPnpInstanceId',
    'Test-IsBluetoothPnpInstanceId',
    'Test-DeviceNameMatch',
    'New-TargetDeviceConfiguration',
    'Find-TargetDeviceInPnpSnapshot',
    'Find-TargetBluetoothComPort',
    'Get-TargetDeviceProcessSnapshot',
    'Test-ProcessRunningInSnapshot',
    'New-TargetWatchState',
    'Add-TargetWatchObservation',
    'Update-TargetWatchState',
    'Update-TargetComPortState',
    'Set-TargetWatchServiceSurfaceSummary',
    'New-TargetWatchReport',
    'Save-TargetWatchReport'
)

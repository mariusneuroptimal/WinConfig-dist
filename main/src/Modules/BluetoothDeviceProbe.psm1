# BluetoothDeviceProbe.psm1 - Deep device probe engine for the Flight Recorder GUI
#
# Extracted from Probe-NeurOptimalDevice.ps1 (winconfig-bluetooth). Provides:
#   - Win32 BluetoothGetDeviceInfo P/Invoke for ACL radio link state
#   - COM port in-use detection (EEG streaming detection)
#   - Pattern recognition engine ([ok]/[~]/[!] classification)
#   - Session state management (COM port history, reconnect times, link flaps)
#   - Session summary generation (structured findings for dev review)
#   - Anomaly diagnostic snapshot capture
#
# READ-ONLY: this module never pairs, unpairs, kills processes, restarts
# services, or modifies the registry. It only reads state.
#
# All mutable state lives on a $Session hashtable (from New-DeviceProbeSession),
# not in $script: scope. This makes the module testable and avoids global-state
# contamination across multiple probe runs in the same process.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BtWin32Available = $false

# =============================================================================
# WIN32 BLUETOOTH API
# =============================================================================

function Initialize-BtWin32Api {
    <#
    .SYNOPSIS
        Loads the BtWin32 P/Invoke type for BluetoothGetDeviceInfo. Idempotent.
    .OUTPUTS
        [bool] $true if the API is available, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:BtWin32Available) { return $true }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'BtWin32').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BtWin32 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct BLUETOOTH_DEVICE_INFO {
        public uint  dwSize;
        public ulong Address;
        public uint  ulClassofDevice;
        [MarshalAs(UnmanagedType.Bool)] public bool fConnected;
        [MarshalAs(UnmanagedType.Bool)] public bool fRemembered;
        [MarshalAs(UnmanagedType.Bool)] public bool fAuthenticated;
        public ushort stLastSeen_Year, stLastSeen_Month, stLastSeen_DOW, stLastSeen_Day,
                      stLastSeen_Hour,  stLastSeen_Min,  stLastSeen_Sec, stLastSeen_Ms;
        public ushort stLastUsed_Year, stLastUsed_Month, stLastUsed_DOW, stLastUsed_Day,
                      stLastUsed_Hour,  stLastUsed_Min,  stLastUsed_Sec, stLastUsed_Ms;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)]
        public string szName;
    }
    [DllImport("Bthprops.cpl", SetLastError = true)]
    public static extern int BluetoothGetDeviceInfo(IntPtr hRadio, ref BLUETOOTH_DEVICE_INFO pbtdi);
    public static bool? GetConnected(string macHex) {
        try {
            var info = new BLUETOOTH_DEVICE_INFO();
            info.dwSize = (uint)Marshal.SizeOf(info);
            info.Address = Convert.ToUInt64(macHex, 16);
            int hr = BluetoothGetDeviceInfo(IntPtr.Zero, ref info);
            if (hr == 0) return info.fConnected;
            return null;
        } catch { return null; }
    }
}
'@ -ErrorAction Stop
        }
        $script:BtWin32Available = $true
        return $true
    } catch {
        return $false
    }
}

function Get-BtConnectionState {
    <#
    .SYNOPSIS
        Returns 'Connected', 'NotConnected', or 'Unknown' for the target device's
        active ACL radio link -- the same flag Windows Bluetooth settings displays.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Mac,
        [bool]$BtWin32Available = $script:BtWin32Available
    )

    if (-not $BtWin32Available -or -not $Mac) { return 'Unknown' }
    try {
        $result = [BtWin32]::GetConnected($Mac)
        if ($null -eq $result) { return 'Unknown' }
        if ($result) { return 'Connected' } else { return 'NotConnected' }
    } catch { return 'Unknown' }
}

# =============================================================================
# STREAMING DETECTION
# =============================================================================

function Test-ComPortInUse {
    <#
    .SYNOPSIS
        Tests whether a COM port is held open by another process.
        UnauthorizedAccessException = port in use (streaming active).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$PortName)

    if ([string]::IsNullOrWhiteSpace($PortName)) { return $false }
    $sp = $null
    try {
        $sp = New-Object System.IO.Ports.SerialPort $PortName
        $sp.Open()
        $sp.Close()
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true
    } catch {
        return $false
    } finally {
        if ($sp) { try { $sp.Dispose() } catch { } }
    }
}

function Get-StreamingState {
    <#
    .SYNOPSIS
        Returns 'Active' if any target COM ports are held open, 'Stopped' otherwise.
    .OUTPUTS
        [hashtable] with State ('Active'/'Stopped'/'Unknown') and ActivePort.
    #>
    [CmdletBinding()]
    param([hashtable]$WatchState)

    if ($WatchState.ComPortState -notin @('ComPortFound', 'ComPortAmbiguous')) {
        return @{ State = 'Stopped'; ActivePort = $null }
    }

    $ports = @()
    if ($WatchState.ComPortMatches.Count -gt 0) {
        $ports += $WatchState.ComPortMatches | ForEach-Object { $_.PortName }
    }
    if ($WatchState.AmbiguousComPortMatches.Count -gt 0) {
        $ports += $WatchState.AmbiguousComPortMatches | ForEach-Object { $_.PortName }
    }
    $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
    if ($ports.Count -eq 0) { return @{ State = 'Unknown'; ActivePort = $null } }

    $activePorts = @()
    foreach ($p in $ports) {
        if (Test-ComPortInUse -PortName $p) { $activePorts += $p }
    }

    if ($activePorts.Count -gt 0) {
        return @{ State = 'Active'; ActivePort = ($activePorts -join ', ') }
    }
    return @{ State = 'Stopped'; ActivePort = $null }
}

# =============================================================================
# PATTERN RECOGNITION
# =============================================================================

function Get-PatternAnnotation {
    <#
    .SYNOPSIS
        Classifies a state transition as [ok], [~], or [!] with reasoning.
    .OUTPUTS
        [string] annotation text, or $null when no note adds value.
    #>
    [CmdletBinding()]
    param(
        [string]$Kind,
        [string]$NewState,
        [hashtable]$WatchState,
        [datetime]$Now,
        [hashtable]$Session
    )

    $prevEnteredAt = $Session.StateEnteredAt[$Kind]
    $elapsedInPrev = if ($prevEnteredAt) { [int]($Now - $prevEnteredAt).TotalSeconds } else { $null }

    switch ($Kind) {
        'device' {
            switch ($NewState) {
                'Missing' {
                    $noActive   = ($WatchState.AppProcessState -eq 'Running')
                    $comDropped = ($WatchState.ComPortState -eq 'ComPortMissing')
                    $paired     = $elapsedInPrev
                    $pairStr    = if ($paired) { " (was paired for ${paired}s)" } else { '' }

                    if ($noActive -and -not $comDropped) {
                        return "[!] ANOMALY: device disappeared while NO.exe active and COM port still alive$pairStr -- unexpected mid-session disconnect"
                    }
                    if ($noActive -and $comDropped) {
                        return "[~] Device + COM dropped together while NO.exe running$pairStr -- clean disconnect (intentional unpair or tidy dropout)"
                    }
                    if ($comDropped) {
                        return "[ok] COM ports cleared first, then device -- normal pairing/reconnect sequence$pairStr"
                    }
                    return "[~] Device missing -- may be unpairing or reconnecting$pairStr"
                }
                'PairedCandidate' {
                    $missingAt = $Session.StateEnteredAt['device_Missing_at']
                    if ($missingAt) {
                        $outSec = [int]($Now - $missingAt).TotalSeconds
                        if ($outSec -lt 5)   { return "[ok] Back in ${outSec}s -- PnP blip only" }
                        if ($outSec -lt 90)  { return "[ok] Back after ${outSec}s -- normal pairing/reconnect cycle" }
                        if ($outSec -lt 300) { return "[~] Back after ${outSec}s -- slow reconnect, worth monitoring" }
                        return "[!] Back after ${outSec}s -- extended outage, investigate"
                    }
                }
                'SeenByPnp' {
                    return "[~] Device seen in PnP but not yet paired/connected"
                }
            }
        }
        'comport' {
            switch ($NewState) {
                'ComPortMissing' {
                    if ($WatchState.DeviceState -eq 'PairedCandidate') {
                        return "[~] COM ports cleared while device still appears paired -- likely leading edge of disconnect, watch for device to follow"
                    }
                    return "[ok] COM ports cleared (device also disconnected -- expected)"
                }
                'ComPortAmbiguous' {
                    $currentPorts = @($WatchState.AmbiguousComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ } | Sort-Object)
                    $portList     = $currentPorts -join ', '
                    $annotation   = "[ok] Both NeurOptimal SPP channels present -- normal ($portList)"
                    if ($Session.LastComPortNames.Count -gt 0) {
                        $prev = $Session.LastComPortNames | Sort-Object
                        $added   = $currentPorts | Where-Object { $_ -notin $prev }
                        $removed = $prev | Where-Object { $_ -notin $currentPorts }
                        if ($added -or $removed) {
                            $changeNote = "port numbers changed after re-pair"
                            if ($removed) { $changeNote += ": lost $($removed -join ', ')" }
                            if ($added)   { $changeNote += ", gained $($added -join ', ')" }
                            $annotation = "[~] $changeNote -- if NO.exe has a hardcoded port it may fail to connect ($portList now)"
                        }
                    }
                    $Session.LastComPortNames = $currentPorts
                    return $annotation
                }
                'ComPortFound' {
                    $currentPorts = @($WatchState.ComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ } | Sort-Object)
                    $portList     = $currentPorts -join ', '
                    $annotation   = "[ok] Serial port acquired ($portList)"
                    if ($Session.LastComPortNames.Count -gt 0) {
                        $prev = $Session.LastComPortNames | Sort-Object
                        $added   = $currentPorts | Where-Object { $_ -notin $prev }
                        $removed = $prev | Where-Object { $_ -notin $currentPorts }
                        if ($added -or $removed) {
                            $changeNote = "port number changed after re-pair"
                            if ($removed) { $changeNote += ": lost $($removed -join ', ')" }
                            if ($added)   { $changeNote += ", gained $($added -join ', ')" }
                            $annotation = "[~] $changeNote -- if NO.exe has a hardcoded port it may fail ($portList now)"
                        }
                    }
                    $Session.LastComPortNames = $currentPorts
                    return $annotation
                }
            }
        }
        'process' {
            switch ($NewState) {
                'AppProcessStarted' {
                    $devState = $WatchState.DeviceState
                    if ($devState -eq 'PairedCandidate') { return "[ok] NO.exe started, device already paired" }
                    return "[~] NO.exe started but device not yet paired (state: $devState)"
                }
                'AppProcessExited' {
                    if ($WatchState.DeviceState -eq 'PairedCandidate') {
                        return "[!] NO.exe exited while device still paired -- unexpected crash or force-close?"
                    }
                    return "[ok] NO.exe exited after device disconnected"
                }
                'PairingProcessStarted' {
                    return "[ok] Pairing EXE launched -- expect disconnect/reconnect cycle"
                }
                'PairingProcessExited' {
                    return "[ok] Pairing EXE finished"
                }
            }
        }
    }
    return $null
}

function Get-EstimatedScanCycles {
    <#
    .SYNOPSIS
        Estimates how many NO.exe scan cycles were needed to discover the device.
    #>
    [CmdletBinding()]
    param([int]$GapSeconds, [int]$OrigTime = 3, [int]$Increment = 1, [int]$MaxTime = 10)

    $scanTime    = $OrigTime
    $totalScan   = 0
    $cycles      = 0
    $breakdown   = @()
    while ($totalScan -lt $GapSeconds -and $cycles -lt 20) {
        $totalScan += $scanTime
        $cycles++
        $breakdown += "${scanTime}s"
        $scanTime = [math]::Min($scanTime + $Increment, $MaxTime)
    }
    $breakStr = $breakdown -join ' + '
    $plural = if ($cycles -ne 1) { 's' } else { '' }
    return "~$cycles scan cycle$plural ($breakStr = ${totalScan}s scan time; gap was ${GapSeconds}s)"
}

# =============================================================================
# SESSION STATE
# =============================================================================

function New-DeviceProbeSession {
    <#
    .SYNOPSIS
        Creates a fresh session-tracking state hashtable for a probe run.
    #>
    [CmdletBinding()]
    param()

    return @{
        StateEnteredAt           = @{}
        LastComPortNames         = @()
        SustainedComAnomaly      = $false
        ComPortHistory           = [System.Collections.ArrayList]::new()
        ReconnectTimes           = [System.Collections.ArrayList]::new()
        BtLinkState              = 'Unknown'
        BtLinkEnteredAt          = $null
        BtLinkFlapCount          = 0
        StreamingState           = 'Stopped'
        ActiveStreamPort         = $null
        StreamPeakCpuS           = 0.0
        StreamPeakWorkingSetMB   = 0
        StartupSppChannelCount   = 0
        BtWin32Available         = $false
        AdapterInfo              = $null
        PowerPlan                = $null
        PendingConfirmation      = $null
    }
}

# =============================================================================
# PER-TICK PROCESSING
# =============================================================================

function Invoke-DeviceProbeTick {
    <#
    .SYNOPSIS
        Processes one probe tick: streaming detection, BT link monitoring,
        pattern annotation, and session tracking. Returns renderable events.
    .PARAMETER Session
        Session state hashtable from New-DeviceProbeSession.
    .PARAMETER WatchState
        TargetDeviceWatch state from New-TargetWatchState (already updated
        via Update-TargetWatchState before calling this function).
    .PARAMETER NewObservations
        Observation rows returned by Update-TargetWatchState this tick.
    .PARAMETER TargetMac
        Normalized MAC for BT link monitoring.
    .PARAMETER AppProcessName
        Process name (e.g. 'NO') for health sampling.
    .OUTPUTS
        [hashtable[]] Array of renderable events, each with:
            Kind, State, Reason, Annotation, Level, Timestamp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [Parameter(Mandatory)][hashtable]$WatchState,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$NewObservations,
        [string]$TargetMac,
        [string]$AppProcessName = 'NO'
    )

    $events = @()
    $now = Get-Date

    # ── Streaming detection ──────────────────────────────────────────────
    $streamResult = Get-StreamingState -WatchState $WatchState
    $newStreamState = $streamResult.State

    if ($newStreamState -ne $Session.StreamingState) {
        $prevStreaming = $Session.StreamingState
        $Session.StreamingState = $newStreamState

        if ($newStreamState -eq 'Active') {
            $Session.StreamPeakCpuS         = 0.0
            $Session.StreamPeakWorkingSetMB = 0
            $portInfo = if ($streamResult.ActivePort) { " on $($streamResult.ActivePort)" } else { '' }
            $Session.ActiveStreamPort = $streamResult.ActivePort
            $evt = @{ Kind = 'STREAM'; State = 'Active'; Reason = "NO.exe has COM port open (EEG data streaming)$portInfo"; Annotation = $null; Level = 'OK'; Timestamp = $now }
            if ($WatchState.DeviceState -ne 'PairedCandidate') {
                $evt.Annotation = "[!] Streaming started but device state is '$($WatchState.DeviceState)' -- unexpected"
                $evt.Level = 'FAIL'
            }
            $events += $evt
            $Session.StateEnteredAt['streaming_Active_at'] = $now
        } elseif ($prevStreaming -eq 'Active') {
            $elapsed = if ($Session.StateEnteredAt['streaming_Active_at']) {
                [int]($now - $Session.StateEnteredAt['streaming_Active_at']).TotalSeconds
            } else { 0 }
            $durationStr = if ($elapsed -gt 0) { " after ${elapsed}s" } else { '' }
            $peakInfo    = if ($Session.StreamPeakWorkingSetMB -gt 0) {
                "  (NO.exe peak: CPU=$($Session.StreamPeakCpuS)s  mem=$($Session.StreamPeakWorkingSetMB)MB)"
            } else { '' }

            $deviceOk = ($WatchState.DeviceState -eq 'PairedCandidate')
            $appOk    = ($WatchState.AppProcessState -eq 'Running')

            if (-not $deviceOk) {
                $events += @{ Kind = 'STREAM'; State = "Stopped$durationStr"; Reason = "device disconnected mid-stream$peakInfo"; Annotation = "[!] Stream interrupted by Bluetooth disconnect"; Level = 'FAIL'; Timestamp = $now }
            } elseif (-not $appOk) {
                $events += @{ Kind = 'STREAM'; State = "Stopped$durationStr"; Reason = "NO.exe exited$peakInfo"; Annotation = "[~] NO.exe closed while device still paired"; Level = 'WARN'; Timestamp = $now }
            } else {
                $events += @{ Kind = 'STREAM'; State = "Stopped$durationStr"; Reason = "COM port released, device + NO.exe still active$peakInfo"; Annotation = "[~] Could not determine cause -- was this a manual stop or unexpected?"; Level = 'WARN'; Timestamp = $now }
                $Session.PendingConfirmation = @{
                    EventLabel = "stream stopped while device+app active"
                    EventTime  = $now
                    WatchState = $WatchState
                    DiagSince  = $now.AddMinutes(-2)
                }
            }
        }
    }

    # ── BT link monitoring ───────────────────────────────────────────────
    $newBtLink = Get-BtConnectionState -Mac $TargetMac -BtWin32Available $Session.BtWin32Available
    if ($newBtLink -ne 'Unknown' -and $newBtLink -ne $Session.BtLinkState) {
        $prevBtLink = $Session.BtLinkState
        $Session.BtLinkState = $newBtLink
        $linkElapsed = if ($Session.BtLinkEnteredAt) { [int]($now - $Session.BtLinkEnteredAt).TotalSeconds } else { 0 }
        $Session.BtLinkEnteredAt = $now

        if ($newBtLink -eq 'Connected') {
            $fromStr = if ($prevBtLink -ne 'Unknown') { " after ${linkElapsed}s unconnected" } else { '' }
            $anno = $null
            $level = 'OK'
            if ($WatchState.DeviceState -ne 'PairedCandidate') {
                $anno = "[~] Link connected but device PnP state is '$($WatchState.DeviceState)'"
                $level = 'WARN'
            }
            $events += @{ Kind = 'BTLINK'; State = 'Connected'; Reason = "ACL radio link established$fromStr"; Annotation = $anno; Level = $level; Timestamp = $now }
        } elseif ($newBtLink -eq 'NotConnected') {
            $fromStr = if ($prevBtLink -eq 'Connected') { " after ${linkElapsed}s connected" } else { '' }
            if ($Session.StreamingState -eq 'Active') {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "ACL link dropped during active EEG stream$fromStr"; Annotation = "[!] Radio link lost while streaming -- this is the mid-session disconnect event"; Level = 'FAIL'; Timestamp = $now }
            } elseif ($WatchState.DeviceState -eq 'PairedCandidate') {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "ACL link dropped, device still in PnP$fromStr"; Annotation = "[~] Device paired but radio link down"; Level = 'WARN'; Timestamp = $now }
                $Session.BtLinkFlapCount++
            } else {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "ACL link down$fromStr"; Annotation = $null; Level = 'DIM'; Timestamp = $now }
            }
        }
    }

    # ── NO.exe health sampling ───────────────────────────────────────────
    if ($Session.StreamingState -eq 'Active' -and $AppProcessName) {
        try {
            $noProc = Get-Process -Name $AppProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($noProc) {
                $cpuS = [math]::Round($noProc.CPU, 1)
                $wsMB = [math]::Round($noProc.WorkingSet64 / 1MB, 0)
                if ($cpuS -gt $Session.StreamPeakCpuS)        { $Session.StreamPeakCpuS = $cpuS }
                if ($wsMB -gt $Session.StreamPeakWorkingSetMB) { $Session.StreamPeakWorkingSetMB = $wsMB }
            }
        } catch { }
    }

    # ── Process state-change observations ────────────────────────────────
    foreach ($obs in $NewObservations) {
        $oldComPortNames = @($Session.LastComPortNames)
        $annotation = Get-PatternAnnotation -Kind $obs.Kind -NewState $obs.State `
                          -WatchState $WatchState -Now $now -Session $Session

        $level = switch -Wildcard ($obs.State) {
            'PairedCandidate'      { 'OK' }
            'Missing'              { 'WARN' }
            'SeenByPnp'            { 'INFO' }
            'Ambiguous'            { 'WARN' }
            '*Started'             { 'OK' }
            '*Exited'              { 'WARN' }
            'ComPortFound'         { 'OK' }
            'ComPortMissing'       { 'WARN' }
            'ComPortAmbiguous'     { 'OK' }
            default                { 'INFO' }
        }
        if ($annotation -and $annotation.StartsWith('[!]')) { $level = 'FAIL' }
        elseif ($annotation -and $annotation.StartsWith('[~]')) { $level = 'WARN' }

        $events += @{ Kind = $obs.Kind; State = $obs.State; Reason = $obs.Reason; Annotation = $annotation; Level = $level; Timestamp = $now }

        # Record timing
        $Session.StateEnteredAt[$obs.Kind] = $now
        if ($obs.State -eq 'Missing') {
            $Session.StateEnteredAt['device_Missing_at'] = $now
        }
        if ($obs.Kind -eq 'comport' -and $obs.State -eq 'ComPortMissing') {
            $Session.StateEnteredAt['comport_ComPortMissing_at'] = $now
        } elseif ($obs.Kind -eq 'comport' -and $obs.State -ne 'ComPortMissing') {
            $Session.StateEnteredAt['comport_ComPortMissing_at'] = $null
        }

        # COM port history
        if ($obs.Kind -eq 'comport' -and $obs.State -in @('ComPortAmbiguous', 'ComPortFound')) {
            $currentPorts = @($Session.LastComPortNames)
            $added        = @($currentPorts | Where-Object { $_ -notin $oldComPortNames })
            $removed      = @($oldComPortNames | Where-Object { $_ -notin $currentPorts })
            [void]$Session.ComPortHistory.Add([PSCustomObject]@{
                RepairNum = $Session.ComPortHistory.Count + 1
                Time      = $now
                Ports     = $currentPorts
                Changed   = ($added.Count -gt 0 -or $removed.Count -gt 0)
                Added     = $added
                Removed   = $removed
                IsFirst   = ($oldComPortNames.Count -eq 0)
            })
        }

        # Reconnect time
        if ($obs.Kind -eq 'device' -and $obs.State -eq 'PairedCandidate') {
            $missingAt = $Session.StateEnteredAt['device_Missing_at']
            if ($missingAt) {
                [void]$Session.ReconnectTimes.Add([int]($now - $missingAt).TotalSeconds)
            }
        }
    }

    # ── Sustained COM anomaly ────────────────────────────────────────────
    $comMissingAt = $Session.StateEnteredAt['comport_ComPortMissing_at']
    if ($comMissingAt -and $WatchState.ComPortState -eq 'ComPortMissing' `
                       -and $WatchState.DeviceState -eq 'PairedCandidate') {
        $comMissingSec = [int]($now - $comMissingAt).TotalSeconds
        if ($comMissingSec -ge 15 -and -not $Session.SustainedComAnomaly) {
            $Session.SustainedComAnomaly = $true
            $events += @{ Kind = 'ANOMALY'; State = 'SustainedComMissing'; Reason = "COM port missing for ${comMissingSec}s while device stays paired -- serial layer instability"; Annotation = $null; Level = 'FAIL'; Timestamp = $now }
        }
    } else {
        $Session.SustainedComAnomaly = $false
    }

    return ,$events
}

# =============================================================================
# SESSION SUMMARY
# =============================================================================

function Get-DeviceProbeSessionSummary {
    <#
    .SYNOPSIS
        Generates structured session summary with findings for dev review.
    .OUTPUTS
        [hashtable] with Findings (array of strings), ComPortHistory, ReconnectStats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Session,
        [Parameter(Mandatory)][hashtable]$WatchState
    )

    $findings = [System.Collections.ArrayList]::new()

    # COM port number stats
    $allPortNums = @($Session.ComPortHistory | ForEach-Object { $_.Ports } | ForEach-Object {
        if ($_ -match 'COM(\d+)') { [int]$Matches[1] }
    } | Where-Object { $_ })

    # COM port reassignment
    if ($Session.ComPortHistory.Count -gt 1) {
        $changedCount = @($Session.ComPortHistory | Where-Object { $_.Changed -and -not $_.IsFirst }).Count
        $totalRepairs = $Session.ComPortHistory.Count - 1
        if ($changedCount -eq $totalRepairs) {
            [void]$findings.Add("[!] COM port reassignment: occurred on EVERY re-pair ($changedCount/$totalRepairs) -- NO.exe cache invalidated each time")
        } elseif ($changedCount -gt 0) {
            [void]$findings.Add("[~] COM port reassignment: occurred on $changedCount of $totalRepairs re-pairs")
        } else {
            [void]$findings.Add("[ok] COM port numbers stable across all $totalRepairs re-pairs")
        }
    }

    # COM port exhaustion
    if ($allPortNums -and $allPortNums.Count -gt 0) {
        $slotsUsed = ($allPortNums | Select-Object -Unique | Measure-Object).Count
        $maxPort   = ($allPortNums | Measure-Object -Maximum).Maximum
        if ($maxPort -ge 10) {
            [void]$findings.Add("[!] COM port exhaustion: reached COM$maxPort this session ($slotsUsed slots consumed)")
        } elseif ($slotsUsed -gt 4) {
            [void]$findings.Add("[~] COM port churn: $slotsUsed unique slots consumed this session")
        }
    }

    # BT link stability
    if ($Session.BtWin32Available) {
        if ($Session.BtLinkFlapCount -ge 3) {
            [void]$findings.Add("[!] BT link instability: $($Session.BtLinkFlapCount) link drop(s) detected while device stayed in PnP")
        } elseif ($Session.BtLinkFlapCount -gt 0) {
            [void]$findings.Add("[~] BT link flap: $($Session.BtLinkFlapCount) link drop(s) while device stayed paired")
        } else {
            [void]$findings.Add("[ok] BT link stable throughout session (no ACL drops observed)")
        }
        [void]$findings.Add("[info] Final BT link state: $($Session.BtLinkState)")
    } else {
        [void]$findings.Add("[info] BT link monitoring unavailable (Bthprops.cpl not loaded)")
    }

    # SPP server channel accumulation
    if ($Session.StartupSppChannelCount -ge 4) {
        [void]$findings.Add("[~] SPP server channel accumulation: $($Session.StartupSppChannelCount) LOCALMFG entries at startup")
    } elseif ($Session.StartupSppChannelCount -gt 0) {
        [void]$findings.Add("[ok] SPP server channels at startup: $($Session.StartupSppChannelCount) (normal)")
    } else {
        [void]$findings.Add('[ok] No SPP server channel entries at startup (clean slate)')
    }

    # USB selective suspend
    if ($Session.AdapterInfo -and $Session.AdapterInfo.PowerManagementEnabled -eq $true) {
        [void]$findings.Add("[~] USB selective suspend: ENABLED on '$($Session.AdapterInfo.FriendlyName)'")
    }

    # Slow discovery
    if ($Session.ReconnectTimes.Count -gt 0) {
        $maxReconnect = ($Session.ReconnectTimes | Measure-Object -Maximum).Maximum
        $avgReconnect = [math]::Round(($Session.ReconnectTimes | Measure-Object -Average).Average, 0)
        $slowCount    = @($Session.ReconnectTimes | Where-Object { $_ -ge 90 }).Count
        if ($slowCount -gt 0) {
            [void]$findings.Add("[~] Slow discovery: $slowCount reconnect(s) took >= 90s (avg=${avgReconnect}s, max=${maxReconnect}s)")
        } else {
            [void]$findings.Add("[ok] Discovery times within expected range (avg=${avgReconnect}s, max=${maxReconnect}s)")
        }
    }

    # Driver / adapter info
    if ($Session.AdapterInfo -and $Session.AdapterInfo.Present) {
        $driverVer = if ($Session.AdapterInfo.DriverInfo -and $Session.AdapterInfo.DriverInfo.Version) { $Session.AdapterInfo.DriverInfo.Version } else { 'unknown' }
        [void]$findings.Add("[info] Adapter: $($Session.AdapterInfo.FriendlyName)  driver: $driverVer")
    }
    if ($Session.PowerPlan) {
        $planStr = $Session.PowerPlan.ActivePlan
        if ($Session.PowerPlan.IsPowerSaver) { $planStr += ' [Power Saver]' }
        [void]$findings.Add("[info] Power plan: $planStr")
    }

    # Reconnect stats
    $reconnectStats = $null
    if ($Session.ReconnectTimes.Count -gt 0) {
        $reconnectStats = @{
            Min   = ($Session.ReconnectTimes | Measure-Object -Minimum).Minimum
            Avg   = [math]::Round(($Session.ReconnectTimes | Measure-Object -Average).Average, 0)
            Max   = ($Session.ReconnectTimes | Measure-Object -Maximum).Maximum
            Count = $Session.ReconnectTimes.Count
        }
    }

    return @{
        Findings        = @($findings)
        ComPortHistory  = @($Session.ComPortHistory)
        ReconnectStats  = $reconnectStats
        BtLinkFlapCount = $Session.BtLinkFlapCount
        ObservationCount = $WatchState.Observations.Count
    }
}

# =============================================================================
# ANOMALY DIAGNOSTIC
# =============================================================================

function Invoke-AnomalyDiagnosticSnapshot {
    <#
    .SYNOPSIS
        Captures diagnostic context when user confirms an anomaly as unexpected.
    .OUTPUTS
        [hashtable] with EventLogs, AdapterState, ComPortStatus, DeviceState, PowerPlan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $snapshot = @{
        CapturedAt  = (Get-Date).ToString('o')
        EventLabel  = $Context.EventLabel
        EventTime   = $Context.EventTime.ToString('o')
    }

    # BT event log from 2 minutes before the anomaly
    try {
        if (Get-Command Get-BluetoothRecentEvents -ErrorAction SilentlyContinue) {
            $evtResult = Get-BluetoothRecentEvents -Since $Context.DiagSince -MaxEventsPerLog 100
            $evtEntries = @($evtResult.Events | ForEach-Object {
                $tc = try { $_.TimeCreated.ToString('o') } catch { $null }
                $msg = try { ($_.Message -replace '\s+', ' ').Trim() } catch { '' }
                @{ TimeCreated = $tc; ProviderName = $_.ProviderName; Id = $_.Id; Message = $msg }
            })
            $snapshot.EventLogs = @{
                Events       = $evtEntries
                FailureCount = @($evtResult.Failures).Count
            }
        }
    } catch {
        $snapshot.EventLogs = @{ Error = $_.ToString() }
    }

    # Adapter state
    try {
        if (Get-Command Get-BluetoothAdapterSnapshot -ErrorAction SilentlyContinue) {
            $adap = Get-BluetoothAdapterSnapshot
            $snapshot.AdapterState = $adap
        }
    } catch { }

    # COM port status
    $ports = @()
    if ($Context.WatchState) {
        if ($Context.WatchState.ComPortMatches)          { $ports += @($Context.WatchState.ComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ }) }
        if ($Context.WatchState.AmbiguousComPortMatches)  { $ports += @($Context.WatchState.AmbiguousComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ }) }
    }
    $ports = @($ports | Select-Object -Unique)
    if ($ports.Count -gt 0) {
        $snapshot.ComPortStatus = @($ports | ForEach-Object {
            @{ PortName = $_; InUse = (Test-ComPortInUse -PortName $_) }
        })
    }

    # Device state
    if ($Context.WatchState) {
        $snapshot.DeviceState  = $Context.WatchState.DeviceState
        $snapshot.ComPortState = $Context.WatchState.ComPortState
    }

    # Power plan
    try {
        if (Get-Command Get-PowerPlanInfo -ErrorAction SilentlyContinue) {
            $snapshot.PowerPlan = Get-PowerPlanInfo
        }
    } catch { }

    return $snapshot
}

# =============================================================================
# GUI HELPERS
# =============================================================================

function Get-ProbeStateGuiLevel {
    <#
    .SYNOPSIS
        Maps a state to a Console.psm1 GUI level for Write-WinConfigGuiDiagnostic.
    #>
    [CmdletBinding()]
    param([string]$State)

    switch -Wildcard ($State) {
        'PairedCandidate'      { return 'OK' }
        'Missing'              { return 'WARN' }
        'SeenByPnp'            { return 'INFO' }
        'Ambiguous'            { return 'WARN' }
        '*Started'             { return 'OK' }
        '*Exited'              { return 'WARN' }
        'ComPortFound'         { return 'OK' }
        'ComPortMissing'       { return 'WARN' }
        'ComPortAmbiguous'     { return 'OK' }
        'Connected'            { return 'OK' }
        'NotConnected'         { return 'WARN' }
        'Active'               { return 'OK' }
        'Stopped'              { return 'DIM' }
        default                { return 'INFO' }
    }
}

function Get-ProbeStateUserText {
    [CmdletBinding()]
    param(
        [string]$Kind,
        [string]$State,
        [switch]$Short
    )

    $shortText = @{
        'device.Missing'              = 'Not found'
        'device.PairedCandidate'      = 'Paired'
        'device.SeenByPnp'            = 'Discovered'
        'device.Ambiguous'            = 'Ambiguous'
        'device.Configured'           = 'Configured'
        'device.Unconfigured'         = 'Not configured'
        'comport.ComPortMissing'      = 'None'
        'comport.ComPortFound'        = 'Found'
        'comport.ComPortAmbiguous'    = 'Multiple'
        'comport.ComPortUnconfigured' = 'N/A'
        'btlink.Connected'            = 'Connected'
        'btlink.NotConnected'         = 'Disconnected'
        'btlink.Unknown'              = 'Unknown'
        'stream.Active'               = 'Active'
        'stream.Stopped'              = 'Idle'
    }
    $longText = @{
        'device.Missing'              = 'Not found -- Windows has not discovered the headset yet. Turn it on and put it in pairing mode.'
        'device.PairedCandidate'      = 'Paired -- Windows recognizes this device and has saved its pairing key'
        'device.SeenByPnp'            = 'Discovered -- Windows can see the device broadcasting, but it is not paired yet'
        'device.Ambiguous'            = 'Ambiguous -- multiple Bluetooth devices match the target name. Only one should be active.'
        'device.Configured'           = 'Configured -- device is paired and has assigned COM ports for data transfer'
        'device.Unconfigured'         = 'Not configured -- device is paired but has no COM ports assigned yet'
        'comport.ComPortMissing'      = 'No COM port -- COM ports are virtual serial connections that NeurOptimal uses to talk to the headset. They appear after successful pairing.'
        'comport.ComPortFound'        = 'COM port assigned -- the headset has a virtual serial port for NeurOptimal communication'
        'comport.ComPortAmbiguous'    = 'Multiple COM ports found -- usually means old ghost ports from previous pairings still exist'
        'comport.ComPortUnconfigured' = 'N/A -- COM ports only apply when a device is paired'
        'btlink.Connected'            = 'Radio connected -- the Bluetooth radio has an active wireless link to the headset'
        'btlink.NotConnected'         = 'Radio disconnected -- no active Bluetooth wireless link to the headset'
        'btlink.Unknown'              = 'Radio unknown -- cannot determine Bluetooth radio link status (requires admin rights and a discovered device)'
        'stream.Active'               = 'EEG streaming -- NeurOptimal is actively receiving data from the headset over the COM port'
        'stream.Stopped'              = 'EEG idle -- no data is flowing between the headset and NeurOptimal'
    }

    $key = "$Kind.$State"
    $table = if ($Short) { $shortText } else { $longText }
    if ($table.ContainsKey($key)) { return $table[$key] }

    if ($Kind -eq 'stream' -and $State -like 'Stopped*') { return $State }
    if ($Kind -eq 'comport') { return $State -replace 'ComPort','' }
    return $State
}

function Get-ProbeStateColor {
    <#
    .SYNOPSIS
        Maps a state to a System.Drawing.Color for status strip indicators.
    #>
    [CmdletBinding()]
    [OutputType([System.Drawing.Color])]
    param([string]$State)

    switch -Wildcard ($State) {
        'PairedCandidate'      { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'Missing'              { return [System.Drawing.Color]::FromArgb(180, 50, 50) }
        'SeenByPnp'            { return [System.Drawing.Color]::FromArgb(60, 160, 200) }
        'Ambiguous'            { return [System.Drawing.Color]::FromArgb(160, 60, 160) }
        'ComPortFound'         { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'ComPortAmbiguous'     { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'ComPortMissing'       { return [System.Drawing.Color]::FromArgb(180, 50, 50) }
        'Connected'            { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'NotConnected'         { return [System.Drawing.Color]::FromArgb(200, 160, 40) }
        'Active'               { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'Running'              { return [System.Drawing.Color]::FromArgb(40, 160, 60) }
        'Stopped'              { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
        'NotRunning'           { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
        'Unknown'              { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
        default                { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
    }
}

Export-ModuleMember -Function @(
    'Initialize-BtWin32Api',
    'Get-BtConnectionState',
    'Test-ComPortInUse',
    'Get-StreamingState',
    'Get-PatternAnnotation',
    'Get-EstimatedScanCycles',
    'New-DeviceProbeSession',
    'Invoke-DeviceProbeTick',
    'Get-DeviceProbeSessionSummary',
    'Invoke-AnomalyDiagnosticSnapshot',
    'Get-ProbeStateGuiLevel',
    'Get-ProbeStateColor',
    'Get-ProbeStateUserText'
)

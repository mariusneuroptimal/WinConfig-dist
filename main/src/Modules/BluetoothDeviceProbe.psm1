# BluetoothDeviceProbe.psm1 - Deep device probe engine for the Flight Recorder GUI
#
# Extracted from Probe-NeurOptimalDevice.ps1 (winconfig-bluetooth). Provides:
#   - Win32 BluetoothGetDeviceInfo P/Invoke for Bluetooth radio link state
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

# NO.exe >= this version resolves the Arc COM port from its Bluetooth MAC on every
# connect (the 4.0 "Device Panel" overhaul that removed cached-port usage), so a
# COM-port reassignment across reconnects no longer breaks a connection. Older
# builds cache the port and fail when it changes. Single source of truth for the
# gate -- adjust here if the exact first build is pinned down (4.0.0.5 is the
# earliest confirmed to carry the change; 4.0.0.0 is the conservative boundary).
$script:NoMacResolveMinVersion = [version]'4.0.0.0'

# =============================================================================
# NO.EXE VERSION GATE
# =============================================================================

function Get-NoExeVersion {
    <#
    .SYNOPSIS
        Reads the NeurOptimal (NO.exe) product version as a [version], or $null if
        it can't be determined. Prefers the running process's on-disk image, then
        an explicit path, then the canonical install location.
    .DESCRIPTION
        The version gates Test-NoUsesMacResolve: NO.exe >= 4.0 re-resolves each
        Arc's COM port from its MAC on every connect, so a port-number change is
        benign on those builds but breaks older cached-port builds.
    #>
    [CmdletBinding()]
    [OutputType([version])]
    param([string]$ExePath)

    $candidates = @()
    if ($ExePath) { $candidates += $ExePath }
    # The exact image that's actually running is the most authoritative source.
    try {
        $proc = Get-Process -Name 'NO' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) {
            $running = try { $proc.MainModule.FileName } catch { $null }
            if ($running) { $candidates += $running }
        }
    } catch { }
    $candidates += 'C:\zengar\NO.exe'

    foreach ($c in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $c)) { continue }
            $vi  = (Get-Item -LiteralPath $c).VersionInfo
            $raw = if ($vi.ProductVersion) { $vi.ProductVersion } else { $vi.FileVersion }
            if (-not $raw) { continue }
            # Version strings can carry a suffix ("4.0.0.5 (internal)") -- take the
            # leading dotted-numeric (major.minor required so [version] never throws).
            $m = [regex]::Match([string]$raw, '\d+\.\d+(\.\d+){0,2}')
            if ($m.Success) { return [version]$m.Value }
        } catch { continue }
    }
    return $null
}

function Test-NoUsesMacResolve {
    <#
    .SYNOPSIS
        $true if the given NO.exe version resolves COM ports from the device MAC on
        every connect (>= $script:NoMacResolveMinVersion), making a COM-port
        reassignment benign. A $null/unknown version returns $false: the field fleet
        is pre-overhaul, so we keep the strong cached-port warning unless we can
        prove the box runs a fixed build.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([version]$Version)

    if (-not $Version) { return $false }
    return ($Version -ge $script:NoMacResolveMinVersion)
}

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
        Bluetooth radio link -- the same flag Windows Bluetooth settings displays.
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
                        if ($outSec -lt 5)   { return "[ok] Back in ${outSec}s -- brief glitch only" }
                        if ($outSec -lt 90)  { return "[ok] Back after ${outSec}s -- normal pairing/reconnect cycle" }
                        if ($outSec -lt 300) { return "[~] Back after ${outSec}s -- slow reconnect, worth monitoring" }
                        return "[!] Back after ${outSec}s -- extended outage, investigate"
                    }
                }
                'SeenByPnp' {
                    return "[~] Windows sees the device but it is not paired or connected yet"
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
                            if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
                                $annotation = "[ok] $changeNote -- NO.exe $($Session.NoExeVersion) re-resolves the port from the device MAC, so this is harmless ($portList now)"
                            } else {
                                $annotation = "[~] $changeNote -- if NO.exe has a hardcoded port it may fail to connect ($portList now)"
                            }
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
                            if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
                                $annotation = "[ok] $changeNote -- NO.exe $($Session.NoExeVersion) re-resolves the port from the device MAC, so this is harmless ($portList now)"
                            } else {
                                $annotation = "[~] $changeNote -- if NO.exe has a hardcoded port it may fail ($portList now)"
                            }
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
    .DESCRIPTION
        Defaults model NO.exe >= 4.0's Device Panel discovery cadence: start 1s,
        +1s per cycle, cap 3s (the 4.0 overhaul cut this from the old "start ~10s,
        +3s, cap 10s"). Pass OrigTime/Increment/MaxTime to model a pre-4.0 build.
        NOTE: currently unused -- the live slow-discovery signal is the >=90s
        reconnect-gap threshold in Get-DeviceProbeSessionSummary, which measures
        Windows re-pair wall-time and is independent of NO.exe's scan cadence.
    #>
    [CmdletBinding()]
    param([int]$GapSeconds, [int]$OrigTime = 1, [int]$Increment = 1, [int]$MaxTime = 3)

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
        BtLinkEverConnected      = $false
        StreamingState           = 'Stopped'
        ActiveStreamPort         = $null
        StreamPeakCpuS           = 0.0
        StreamPeakWorkingSetMB   = 0
        AppNotRespondingTicks    = 0
        AppHangReported          = $false
        StartupSppChannelCount   = 0
        BtWin32Available         = $false
        NoExeVersion             = $null
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
    if ($newBtLink -eq 'Connected') { $Session.BtLinkEverConnected = $true }
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
                $anno = "[~] Radio link connected but device state is '$(Get-ProbeStateUserText -Kind device -State $WatchState.DeviceState -Short)'"
                $level = 'WARN'
            }
            $events += @{ Kind = 'BTLINK'; State = 'Connected'; Reason = "Bluetooth radio link established$fromStr"; Annotation = $anno; Level = $level; Timestamp = $now }
        } elseif ($newBtLink -eq 'NotConnected') {
            $fromStr = if ($prevBtLink -eq 'Connected') { " after ${linkElapsed}s connected" } else { '' }
            if ($Session.StreamingState -eq 'Active') {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link dropped during active EEG stream$fromStr"; Annotation = "[!] Radio link lost while streaming -- this is the mid-session disconnect event"; Level = 'FAIL'; Timestamp = $now }
            } elseif ($WatchState.DeviceState -eq 'PairedCandidate') {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link dropped, device still paired$fromStr"; Annotation = "[~] Device paired but radio link down"; Level = 'WARN'; Timestamp = $now }
                $Session.BtLinkFlapCount++
            } else {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link down$fromStr"; Annotation = $null; Level = 'DIM'; Timestamp = $now }
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

                # Sync-VISA hang detection. NO.exe >= 4.0 does synchronous serial
                # (VISA) read/write, so a stalled Arc blocks the UI thread and the
                # main window stops pumping messages -> Responding = false. We only
                # look while streaming (COM held open), and stop after the first
                # report so a genuinely hung window's ~5s SendMessageTimeout cost is
                # paid at most a few times, not every tick. A healthy window answers
                # instantly, so healthy sessions pay nothing.
                if (-not $Session.AppHangReported) {
                    $responding = try { $noProc.Responding } catch { $true }
                    if (-not $responding) {
                        $Session.AppNotRespondingTicks++
                        # Ticks are ~3s apart; require 3 consecutive (~9s) so a brief
                        # stall doesn't read as a hang.
                        if ($Session.AppNotRespondingTicks -ge 3) {
                            $Session.AppHangReported = $true
                            $hangSec = $Session.AppNotRespondingTicks * 3
                            $hangAnno = if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
                                "[!] NO.exe UI frozen mid-stream -- on 4.0+ the serial (VISA) read/write is synchronous, so a stalled Arc blocks the UI thread"
                            } else {
                                "[!] NO.exe UI frozen mid-stream -- app not responding while the COM port is held open"
                            }
                            $events += @{ Kind = 'ANOMALY'; State = 'AppNotResponding'; Reason = "NO.exe stopped responding for ~${hangSec}s while EEG streaming"; Annotation = $hangAnno; Level = 'FAIL'; Timestamp = $now }
                        }
                    } else {
                        $Session.AppNotRespondingTicks = 0
                    }
                }
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

    # COM port reassignment across reconnects.
    # Base this on the actual device re-pair count (ReconnectTimes), NOT on the
    # ComPortHistory row count. A single re-pair produces SEVERAL COM-history
    # rows -- the headset exposes two SPP channels that re-register on separate
    # ticks -- so the old `changedCount / (rowCount - 1)` math produced nonsense
    # like "2 of 1 re-pairs", and the `rowCount -gt 1` gate silently dropped the
    # single-row case (a real reassignment on one reconnect went unreported).
    $comChangeRows = @($Session.ComPortHistory | Where-Object { $_.Changed -and -not $_.IsFirst })
    if ($comChangeRows.Count -gt 0) {
        $repairCount  = @($Session.ReconnectTimes).Count
        $reconLabel   = if ($repairCount -le 1) { '1 reconnect' } else { "$repairCount reconnects" }
        $changedTimes = $comChangeRows.Count
        if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
            # NO.exe >= 4.0 re-resolves the COM port from the device MAC on every
            # connect, so a changed port number invalidates nothing. Keep the
            # "COM port reassignment" phrase but under [ok]; the dashboard's problem
            # signal keys on the [!] prefix (dashboard/scripts/lib/bt-zip.js), so a
            # benign observation no longer inflates the rollup.
            [void]$findings.Add("[ok] COM port reassignment: the headset's serial port changed $changedTimes time(s) across $reconLabel -- benign on NO.exe $($Session.NoExeVersion), which resolves the COM port from the device MAC on every connect (no cached port to invalidate)")
        } else {
            # Pre-4.0 (or unknown) NO.exe caches the port, so any reassignment
            # invalidates it -- always [!].
            [void]$findings.Add("[!] COM port reassignment: the headset's serial port changed $changedTimes time(s) across $reconLabel -- NO.exe's cached port is invalidated, so it must re-enumerate the COM port on every connect")
        }
    } elseif ($Session.ReconnectTimes.Count -gt 0) {
        [void]$findings.Add("[ok] COM port numbers stayed stable across $($Session.ReconnectTimes.Count) reconnect(s)")
    }

    # COM port exhaustion / stale-slot accumulation. High COM numbers mean stale
    # (hidden) COM ports are holding the low slots -- the "abnormally increased COM
    # port numbers" the NO dev saw under intensive testing. NO.exe >= 4.0 ships a
    # first-party cleanup tool for exactly this (NO Device Manager > Configuration,
    # needs the UAC prompt); older builds have no such button.
    if ($allPortNums -and $allPortNums.Count -gt 0) {
        $slotsUsed = ($allPortNums | Select-Object -Unique | Measure-Object).Count
        $maxPort   = ($allPortNums | Measure-Object -Maximum).Maximum
        $exhaustionHit = $false
        if ($maxPort -ge 10) {
            [void]$findings.Add("[!] COM port exhaustion: reached COM$maxPort this session ($slotsUsed slots consumed)")
            $exhaustionHit = $true
        } elseif ($slotsUsed -gt 4) {
            [void]$findings.Add("[~] COM port churn: $slotsUsed unique slots consumed this session")
            $exhaustionHit = $true
        }
        if ($exhaustionHit) {
            if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
                [void]$findings.Add("[info] Remediation: NO Device Manager > Configuration has a built-in Bluetooth cleanup tool that removes stale COM ports (accept the UAC prompt when it runs)")
            } else {
                [void]$findings.Add("[info] Remediation: clear stale COM ports (Device Manager > View > Show hidden devices, remove greyed-out COM ports) -- or update NO.exe to 4.0+, which adds a built-in cleanup tool")
            }
        }
    }

    # NO.exe UI hang during streaming (sync-VISA stall). Flagged live in
    # Invoke-DeviceProbeTick; surface it in the summary too.
    if ($Session.AppHangReported) {
        if (Test-NoUsesMacResolve -Version $Session.NoExeVersion) {
            [void]$findings.Add("[!] NO.exe UI hang during streaming: the app stopped responding while the COM port was held open -- likely a synchronous serial (VISA) read/write stall on NO.exe $($Session.NoExeVersion)")
        } else {
            [void]$findings.Add("[!] NO.exe UI hang during streaming: the app stopped responding while the COM port was held open")
        }
    }

    # BT link stability. "No drops" only means "stable" if the link actually
    # came up at some point -- a radio that never connected has nothing to drop,
    # so claiming [ok] stable would mislead the operator (field bug 2026-07-08:
    # session showed Radio: Disconnected end-to-end yet reported [ok] stable).
    if ($Session.BtWin32Available) {
        if ($Session.BtLinkFlapCount -ge 3) {
            [void]$findings.Add("[!] Radio link instability: $($Session.BtLinkFlapCount) link drop(s) detected while device stayed paired")
        } elseif ($Session.BtLinkFlapCount -gt 0) {
            [void]$findings.Add("[~] BT link flap: $($Session.BtLinkFlapCount) link drop(s) while device stayed paired")
        } elseif (-not $Session.BtLinkEverConnected) {
            if ($Session.BtLinkState -eq 'Unknown') {
                [void]$findings.Add("[info] BT radio link state could not be read this session (no readings -- likely no MAC available)")
            } else {
                [void]$findings.Add("[~] BT radio link never connected during this session (radio stayed disconnected) -- link stability could not be assessed")
            }
        } else {
            [void]$findings.Add("[ok] BT radio link stable throughout session (no drops observed)")
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
        BtLinkEverConnected = $Session.BtLinkEverConnected
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
    'Get-NoExeVersion',
    'Test-NoUsesMacResolve',
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

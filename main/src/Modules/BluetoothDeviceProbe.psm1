# BluetoothDeviceProbe.psm1 - Deep device probe engine for the Flight Recorder GUI
#
# Extracted from Probe-NeurOptimalDevice.ps1 (winconfig-bluetooth). Provides:
#   - Win32 BluetoothGetDeviceInfo P/Invoke for Bluetooth radio link state
#   - COM port hold detection (a HANDLE test -- never a data-flow measurement)
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
# DATA-FLOW CORROBORATION (process I/O)
# =============================================================================

# Field capture 2026-07-30 15:30 (NO code 12006, "Arc Connection Lost") showed
# why total CPU is not enough. The Bluetooth layer was clean end to end -- RFCOMM
# link up, both COM ports Present/OK, integrity healthy, ZERO probe events across
# the whole recording -- and NO.exe raised a lost-connection dialog anyway. The
# session audio kept playing throughout, so NO.exe was never idle and a
# CPU-flatline test could not fire. Only ONE of the application's jobs died.
#
# Read OPERATION count is the discriminator. EEG over a synchronous serial read
# produces a high rate of small reads; audio playback is buffered and produces
# comparatively few large ones. So when the serial path stalls, the read-op RATE
# collapses even while CPU and byte throughput stay healthy.
#
# HONEST LIMIT: these counters are process-wide. Nothing here attributes a read to
# the COM port, and nothing can -- Windows exposes no per-handle I/O counter to
# another process. This detects "this process stopped doing the kind of I/O it was
# doing a moment ago", which is why it is reported with the measured numbers
# attached rather than as a diagnosis.
#
# MEASURED on MMEVOLD_06, NO.exe 4.0.0.5, Arc on COM3/COM6, 30 samples at the
# probe's own 3s cadence during a live streaming session (2026-07-30):
#
#   streaming : median 438 read ops/tick, min 422, max 451  (+/- 3.3%)
#               ~135 bytes per read -- a small-packet profile, which is why
#               operation COUNT is the axis and byte throughput is not
#   idle      : exactly 0 ops/tick, zero ticks of noise, before and after
#
# Two things follow. The reads ARE issued by the NO.exe process -- 4.x routes
# serial I/O through NI-VISA and the worry was that VISA would issue them from
# its own service, leaving this detector watching the wrong process. It does not.
# And the separation is effectively total: streaming and idle do not overlap, and
# in-session jitter is under 4%.
#
# WHY THIS IS SAFE TO RUN ON EVERY SESSION. Measured on the same box immediately
# after a normal session stop: NO.exe keeps running and RELEASES the port -- all
# four COM names read Free -- while its read rate goes to 0. So a routine stop
# never presents as "port held with no reads", and the detector cannot fire on
# it: the hold test flips to Stopped first and this block stops sampling. Had NO
# kept the port open between sessions, every clinic stopping a session would have
# raised a FAIL. That ordering is load-bearing, so it is pinned by tests rather
# than assumed.

# Samples needed before a baseline is trusted. Ticks are ~3s, so ~15s of history.
# With IoCollapseTicks that means no verdict before ~27s of streaming.
$script:IoBaselineMinTicks = 5
# Below this median read-op rate there is nothing to collapse FROM, and claiming a
# collapse would be noise. Reported as "no baseline", never as healthy. A real
# session measured 438, so this floor sits ~22x below normal.
$script:IoBaselineMinOpsPerTick = 20
# Fraction of baseline that counts as collapsed. Measured in-session jitter is
# ~3.3%, so 0.25 sits roughly 7x outside normal variation while still catching a
# PARTIAL stall -- a headset transmitting intermittently, not only one that has
# gone completely silent. The original 0.1 only caught near-total silence and
# would have missed a 60% degradation entirely.
$script:IoCollapseFraction = 0.25
# Consecutive collapsed ticks required (~12s) so a scheduling hiccup cannot fire it.
$script:IoCollapseTicks = 4

# Idle recording, in seconds, past which the tail is worth naming in the
# findings. An idle tail is not inert: the baseline is a MEDIAN over the samples
# before the trailing window, so empty ticks pull it down until the run's own
# baseline drops under IoBaselineMinOpsPerTick and the episode is discarded as
# 'NoBaseline' (capture 31D0729CA5B8, 15.4 h of idle after a 33-minute session).
# Ten minutes is well past a clinic packing up and far short of the erosion that
# actually destroyed a capture, so it warns long before anything is lost.
$script:IoIdleTailWarnSeconds = 600

# Post-baseline seconds at or above which an Observed capture is called
# 'Sustained' rather than 'Brief'. Five minutes: comfortably more than the ~27s
# a baseline needs to exist at all, and short enough that it does not label
# ordinary clinic sessions as glances. It is a FLOOR for "worth weighing", not a
# guarantee -- the field collapses on record took 7 and 14.5 minutes to appear,
# so a clean Sustained capture still needs repeating. Consumers wanting a
# different bar read PostBaselineSeconds directly.
$script:CoverageSustainedSeconds = 300

$script:ProcessIoApiAvailable = $false

function Initialize-ProcessIoApi {
    <#
    .SYNOPSIS
        Loads the GetProcessIoCounters P/Invoke. Idempotent.
    .DESCRIPTION
        System.Diagnostics.Process exposes CPU and working set but NOT I/O
        counters, so this is the only way to see read activity from outside the
        process.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:ProcessIoApiAvailable) { return $true }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'WinConfigProcessIo').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinConfigProcessIo {
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

    // Returns null rather than throwing when the handle cannot be queried -- a
    // recording must never die because one counter read was denied.
    public static ulong[] Read(IntPtr hProcess) {
        try {
            IO_COUNTERS c;
            if (!GetProcessIoCounters(hProcess, out c)) { return null; }
            return new ulong[] { c.ReadOperationCount, c.ReadTransferCount };
        } catch { return null; }
    }
}
'@ -ErrorAction Stop
        }
        $script:ProcessIoApiAvailable = $true
        return $true
    } catch {
        return $false
    }
}

function Get-ProcessIoSample {
    <#
    .SYNOPSIS
        Reads cumulative read-operation and read-byte counts for a process.
    .OUTPUTS
        [hashtable] ReadOps / ReadBytes, or $null when unavailable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Process)

    if (-not $script:ProcessIoApiAvailable) { return $null }
    try {
        $h = $Process.Handle
        if (-not $h -or $h -eq [IntPtr]::Zero) { return $null }
        $r = [WinConfigProcessIo]::Read($h)
        if ($null -eq $r) { return $null }
        return @{ ReadOps = [double]$r[0]; ReadBytes = [double]$r[1] }
    } catch {
        # Access denied on the handle, or the process exited between calls.
        return $null
    }
}

function Test-IoReadCollapse {
    <#
    .SYNOPSIS
        Pure. Decides whether a series of per-tick read-operation deltas shows a
        collapse against its own established baseline.
    .DESCRIPTION
        Relative, not absolute. An absolute ops/sec threshold would need
        calibrating per box, per NO build and per session type; a box's own
        recent history is the only reference that travels. The baseline is the
        MEDIAN of the samples before the collapse window, so one scheduling
        outlier cannot move it.

        Returns Verdict:
          Collapsed     rate fell below the fraction of baseline and stayed there
          Degrading     at least one tick has fallen below the collapse limit but
                        the debounce is not satisfied yet -- a collapse in
                        progress, or an intermittent one
          Streaming     a baseline is established and the rate is holding
          NoBaseline    not enough samples, or the baseline rate is too low to
                        collapse from -- explicitly NOT a clean bill of health

        WHY 'Degrading' EXISTS. Field capture C2FB1FD51A35 (2026-07-31): the
        operator marked NO code 12006 while the read rate was at 56 ops/tick
        against a 444 baseline -- 13%, already far under the 25% collapse limit.
        The verdict still read 'Streaming' because only two or three of the four
        trailing ticks had dropped, so the marker recorded "Streaming" at the
        exact instant of the fault and the cross-check that keys on a stalled
        read path never ran. The debounce is right for FIRING a fault; it is
        wrong as a description of a moment. Collapsed keeps its old meaning
        exactly -- all four ticks below the limit -- so nothing that used to fire
        fires differently. Degrading only fills the silence in between.

        A single tick under the limit is not noise: measured in-session jitter is
        ~3.3% and the limit sits at 25% of baseline, ~7x outside that.
    .PARAMETER Deltas
        Per-tick read-operation deltas, oldest first.
    .OUTPUTS
        [hashtable] Verdict, BaselineOpsPerTick, RecentOpsPerTick, CollapsedTicks,
        FractionOfBaseline.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][array]$Deltas = @())

    $d = @($Deltas | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    $result = @{
        Verdict            = 'NoBaseline'
        BaselineOpsPerTick = 0
        RecentOpsPerTick   = 0
        CollapsedTicks     = 0
        # Recent rate as a percentage of the session's own baseline. Carried as a
        # number so triage can rank severity without re-deriving it from two
        # counters, and so a marker stays readable if the verdict wording changes.
        # $null (not 0) whenever there is no baseline to be a fraction OF.
        FractionOfBaseline = $null
    }
    if ($d.Count -lt ($script:IoBaselineMinTicks + $script:IoCollapseTicks)) { return $result }

    # Everything before the trailing window is the reference period.
    $window   = @($d[($d.Count - $script:IoCollapseTicks) .. ($d.Count - 1)])
    $baseline = @($d[0 .. ($d.Count - $script:IoCollapseTicks - 1)])
    if ($baseline.Count -lt $script:IoBaselineMinTicks) { return $result }

    $sorted = @($baseline | Sort-Object)
    $median = if ($sorted.Count % 2 -eq 1) {
        $sorted[[int](($sorted.Count - 1) / 2)]
    } else {
        ($sorted[($sorted.Count / 2) - 1] + $sorted[$sorted.Count / 2]) / 2
    }
    $result.BaselineOpsPerTick = [math]::Round($median, 0)

    $recentAvg = ($window | Measure-Object -Average).Average
    $result.RecentOpsPerTick = [math]::Round($recentAvg, 0)

    if ($median -lt $script:IoBaselineMinOpsPerTick) { return $result }

    $result.FractionOfBaseline = [math]::Round(($recentAvg / $median) * 100, 0)

    $limit = $median * $script:IoCollapseFraction
    $collapsed = @($window | Where-Object { $_ -lt $limit }).Count
    $result.CollapsedTicks = $collapsed

    if ($collapsed -ge $script:IoCollapseTicks) {
        $result.Verdict = 'Collapsed'
    } elseif ($collapsed -gt 0) {
        # Some of the window is already under the limit. Not enough to fire a
        # fault -- deliberately, so a scheduling hiccup cannot -- but saying
        # "Streaming" here is what let a marked 12006 record itself as healthy.
        $result.Verdict = 'Degrading'
    } else {
        $result.Verdict = 'Streaming'
    }
    return $result
}

# =============================================================================
# STREAMING DETECTION
# =============================================================================

function Get-ComPortHoldState {
    <#
    .SYNOPSIS
        Classifies whether a COM port is currently held open by another process.
    .DESCRIPTION
        This is a HANDLE test, not a data test. It answers "can this port be
        opened right now", which is a proxy for "does some process already have
        it". It says NOTHING about whether bytes are flowing -- NO.exe holds the
        Arc's port from connect to disconnect whether or not the headset is
        actually delivering EEG. Every caller must preserve that distinction;
        conflating the two is what let a stalled Arc read as a healthy stream in
        the field (2026-07-30: probe reported streaming while NO.exe showed
        "Arc Not Detected").

        States:
          Held         UnauthorizedAccessException -- someone owns the handle.
          Free         opened cleanly -- nobody owns it, so nothing is streaming.
          Unavailable  IOException -- the port exists in SERIALCOMM but cannot be
                       opened. Cause is NOT determined here: an absent symlink
                       (FI-012 fault 1) and a stale one produce DIFFERENT win32
                       errors, and SerialPort collapses both into IOException
                       with COR_E_IO -- the win32 code survives only in the
                       LOCALIZED message text, so classifying further from here
                       would misclassify every non-English box. See
                       Initialize-SerialOpenApi for the CreateFile path that CAN
                       split them; it is operator-initiated only.
          Unknown      anything else.

        The old bool form folded Unavailable and Free together, so a box whose
        serial stack was broken read identically to a healthy idle one.
    .OUTPUTS
        [string] Held / Free / Unavailable / Unknown
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$PortName)

    if ([string]::IsNullOrWhiteSpace($PortName)) { return 'Unknown' }
    $sp = $null
    try {
        $sp = New-Object System.IO.Ports.SerialPort $PortName
        $sp.Open()
        $sp.Close()
        return 'Free'
    } catch [System.UnauthorizedAccessException] {
        return 'Held'
    } catch [System.IO.IOException] {
        return 'Unavailable'
    } catch {
        return 'Unknown'
    } finally {
        if ($sp) { try { $sp.Dispose() } catch { } }
    }
}

function Test-ComPortInUse {
    <#
    .SYNOPSIS
        Back-compat bool wrapper over Get-ComPortHoldState. $true only for 'Held'.
        Prefer Get-ComPortHoldState: this form cannot tell an unopenable port
        apart from a free one.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$PortName)

    return ((Get-ComPortHoldState -PortName $PortName) -eq 'Held')
}

function Get-StreamingState {
    <#
    .SYNOPSIS
        Reports whether the target's COM ports are HELD OPEN. Despite the name
        this is not a measure of EEG data flow -- see Get-ComPortHoldState.
    .DESCRIPTION
        State stays 'Active'/'Stopped' because it drives the session transition
        machine, but it means "a port is held" / "no port is held". The extra
        fields carry what the operator-facing text needs to stay honest:
          HeldPorts         ports someone has open
          UnavailablePorts  ports that exist but would not open (serial stack)
    .OUTPUTS
        [hashtable] State ('Active'/'Stopped'/'Unknown'), ActivePort, HeldPorts,
        UnavailablePorts.
    #>
    [CmdletBinding()]
    param([hashtable]$WatchState)

    if ($WatchState.ComPortState -notin @('ComPortFound', 'ComPortAmbiguous')) {
        return @{ State = 'Stopped'; ActivePort = $null; HeldPorts = @(); UnavailablePorts = @() }
    }

    $ports = @()
    if ($WatchState.ComPortMatches.Count -gt 0) {
        $ports += $WatchState.ComPortMatches | ForEach-Object { $_.PortName }
    }
    if ($WatchState.AmbiguousComPortMatches.Count -gt 0) {
        $ports += $WatchState.AmbiguousComPortMatches | ForEach-Object { $_.PortName }
    }
    $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
    if ($ports.Count -eq 0) { return @{ State = 'Unknown'; ActivePort = $null; HeldPorts = @(); UnavailablePorts = @() } }

    $activePorts = @()
    $deadPorts   = @()
    # Ports we actually OPENED and closed on this tick. This is the number the
    # invasiveness question turns on: on a port NO.exe holds, the open fails with
    # a sharing violation and no handle is ever acquired, but on a FREE port we
    # really do open and close it -- once every ~3s for the length of a
    # recording. Nothing in a bundle recorded how often that happened, so the
    # question could only be argued, not answered. Counting it is a prerequisite
    # for deciding whether to back the interval off; measure first.
    $openedPorts = @()
    # DURATION, not just count. The count says how often we touched the port; it
    # cannot say for how long we owned it, and on a Bluetooth SPP port an open is
    # not local -- it brings up an RFCOMM channel over the air. Two questions ride
    # on this and neither could be answered from a capture (issue #83):
    #   1. Is this the tick cost? `Update` measures ~82% of the tick but spans
    #      several calls, so blaming the opens was an INFERENCE.
    #   2. What fraction of the recording did the probe own a port NO.exe was
    #      trying to open? That is the observer-effect number.
    # Timed at the CALL SITE deliberately: Get-ComPortHoldState keeps its string
    # return and its signature, so every existing caller and every test mock of it
    # is untouched.
    $durations = @()
    foreach ($p in $ports) {
        $holdSw = [System.Diagnostics.Stopwatch]::StartNew()
        $holdState = Get-ComPortHoldState -PortName $p
        $holdSw.Stop()
        $durations += @{ Port = $p; State = $holdState; DurationMs = $holdSw.Elapsed.TotalMilliseconds }
        switch ($holdState) {
            'Held'        { $activePorts += $p }
            'Unavailable' { $deadPorts   += $p }
            'Free'        { $openedPorts += $p }
        }
    }

    if ($activePorts.Count -gt 0) {
        return @{
            State             = 'Active'
            ActivePort        = ($activePorts -join ', ')
            HeldPorts         = @($activePorts)
            UnavailablePorts  = @($deadPorts)
            OpenedPorts       = @($openedPorts)
            ProbedPorts       = @($ports)
            PortOpenDurations = @($durations)
        }
    }
    return @{
        State = 'Stopped'; ActivePort = $null; HeldPorts = @()
        UnavailablePorts = @($deadPorts); OpenedPorts = @($openedPorts); ProbedPorts = @($ports)
        PortOpenDurations = @($durations)
    }
}

function Add-PortOpenTimingSample {
    <#
    .SYNOPSIS
        Pure-ish. Folds one timed Get-ComPortHoldState result into the session's
        per-port timing accumulator, in place.
    .DESCRIPTION
        Split by RETURNED STATE, because the states cost wildly different things
        and averaging them together hides the only one that matters. A 'Held'
        result is a sharing violation and returns almost immediately; a 'Free'
        result means a handle really was taken, which is both the slow case and
        the invasive one. A single mean over both understates 'Free' by however
        often NO.exe happened to be holding the port.
    .PARAMETER Timing
        The accumulator hashtable, keyed by port name.
    .PARAMETER Phase
        Which part of the recording this sample came from: 'Selection' (target
        selection), 'Startup' (the arrival snapshot) or 'Tick' (the probe loop).
        Recorded because the recording window opens BEFORE the first two, so a
        report built from ticks alone divides a tick-only numerator by a
        whole-session denominator and understates the observer effect -- and the
        opens it drops are the COLD ones, the slowest on a Bluetooth SPP port.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Timing,
        # AllowEmptyString, deliberately. The tick path feeds this from
        # ([string]$d.Port) on a hashtable it did not build, so a malformed entry
        # arrives as ''. Rejecting it at the binder throws INSIDE the tick and
        # takes the whole tick down -- the failure mode every other tolerance in
        # this function exists to prevent. Bind it, then drop it below.
        [Parameter(Mandatory)][AllowEmptyString()][string]$PortName,
        [string]$State = 'Unknown',
        [double]$DurationMs = 0,
        [AllowEmptyString()][string]$Phase = 'Tick'
    )

    if ([string]::IsNullOrWhiteSpace($PortName)) { return }
    $st = if ([string]::IsNullOrWhiteSpace($State)) { 'Unknown' } else { $State }
    $ph = if ([string]::IsNullOrWhiteSpace($Phase)) { 'Unknown' } else { $Phase }

    if (-not $Timing.ContainsKey($PortName)) {
        $Timing[$PortName] = @{ Count = 0; TotalMs = [double]0; MaxMs = [double]0; MinMs = $null; ByState = @{}; ByPhase = @{} }
    }
    $port = $Timing[$PortName]
    # Back-fill for an accumulator seeded by an older build of this function, so
    # a mid-session module reload cannot throw on a missing key.
    if (-not $port.ContainsKey('ByPhase')) { $port['ByPhase'] = @{} }
    $port.Count++
    $port.TotalMs += $DurationMs
    if ($DurationMs -gt $port.MaxMs) { $port.MaxMs = $DurationMs }
    # $null, not 0 -- a MinMs seeded at 0 can never be beaten and would report a
    # zero-cost open on every box.
    if ($null -eq $port.MinMs -or $DurationMs -lt [double]$port.MinMs) { $port.MinMs = $DurationMs }

    if (-not $port.ByState.ContainsKey($st)) {
        $port.ByState[$st] = @{ Count = 0; TotalMs = [double]0; MaxMs = [double]0 }
    }
    $bucket = $port.ByState[$st]
    $bucket.Count++
    $bucket.TotalMs += $DurationMs
    if ($DurationMs -gt $bucket.MaxMs) { $bucket.MaxMs = $DurationMs }

    if (-not $port.ByPhase.ContainsKey($ph)) {
        $port.ByPhase[$ph] = @{ Count = 0; TotalMs = [double]0; OpenCount = 0; OpenMs = [double]0 }
    }
    $pb = $port.ByPhase[$ph]
    $pb.Count++
    $pb.TotalMs += $DurationMs
    # Only 'Free' -- same rule as the headline. Split out per phase so a reader
    # can see how much of the number came from the one-off startup opens and how
    # much from the loop, rather than having to trust that both were counted.
    if ($st -eq 'Free') { $pb.OpenCount++; $pb.OpenMs += $DurationMs }
}

function Add-PortOpenTimingSamples {
    <#
    .SYNOPSIS
        Folds a whole PortOpenDurations list into the session's timing
        accumulator. The ONE place any caller feeds this channel.
    .DESCRIPTION
        A choke point, not a convenience. The first cut of this measurement was
        fed from the probe tick only (Invoke-DeviceProbeTick), while the
        recording window it is divided by opens earlier -- at $btRecordStart,
        before target selection and before the arrival snapshot. Both of those
        also open ports, and being the FIRST opens of the session they are the
        cold ones. Numerator missing them, denominator including their wall
        clock: the observer effect came out biased LOW, in the direction that
        makes the recorder look innocent.

        Every producer of a duration list now goes through here with a Phase
        label, so adding a third call site is one call and shows up in the
        report instead of silently skewing it.
    .PARAMETER Durations
        The PortOpenDurations list from Get-StreamingState, or any list of
        entries carrying Port / State / DurationMs.
    .PARAMETER Phase
        'Selection' | 'Startup' | 'Tick'.
    .OUTPUTS
        [int] samples accepted. Returned so a caller can assert it wired up.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        $Timing,
        $Durations,
        [AllowEmptyString()][string]$Phase = 'Tick'
    )

    # Tolerant for the same reason the tick path is: this runs inside the
    # recording loop and inside startup, and neither may be taken down by a
    # malformed entry. A run that measured nothing must report nothing.
    if ($Timing -isnot [hashtable]) { return 0 }
    $n = 0
    foreach ($d in @($Durations)) {
        if (-not $d) { continue }
        $port = try { [string]$d.Port } catch { '' }
        if ([string]::IsNullOrWhiteSpace($port)) { continue }
        $state = try { [string]$d.State } catch { 'Unknown' }
        $ms    = try { [double]$d.DurationMs } catch { [double]0 }
        Add-PortOpenTimingSample -Timing $Timing -PortName $port -State $state -DurationMs $ms -Phase $Phase
        $n++
    }
    return $n
}

function Get-PortOpenTimingReport {
    <#
    .SYNOPSIS
        Pure. Summarises the per-port hold-test timing accumulator for a capture.
    .DESCRIPTION
        The headline is SuccessfulOpenCallMs: the summed wall-clock duration of
        the Get-ComPortHoldState calls that RETURNED 'Free', i.e. the ones where
        a handle was genuinely acquired. A 'Held' result cost time but took no
        handle, and an 'Unavailable' one never had a handle to hold.

        WHAT THIS IS NOT. It is not the time the probe owned the handle. The
        stopwatch spans the entire call -- SerialPort construction, the RFCOMM
        bring-up, Open(), Close() and Dispose() -- and ownership is a strict
        subset of that. So the figure is an UPPER BOUND on the interval in which
        NO.exe would have been locked out, not a measurement of it. Naming it
        "handle held" would have made the recorder look more invasive than
        anything here proves, and an upper bound is what the release-blocker
        decision actually needs: if the bound is small the question is closed,
        and if it is large the exact interval has to be established at the
        Windows level before anyone acts on it. Basis travels with the number,
        because a metric and the thing it licenses you to say must not get
        separated (see Get-ComPortHoldState on handle-vs-dataflow).

        Percentages are reported PER PORT as well as pooled. The Arc's two SPP
        channels are not interchangeable -- 12005 names the COMMAND port -- and
        a pooled figure can hide a heavily-probed channel behind a quiet one.

        Returns $null when nothing was sampled, so an unmeasured run renders as
        absent rather than as a confident zero.
    .PARAMETER Timing
        The session's PortOpenTiming accumulator.
    .PARAMETER RecordingSeconds
        Recording length, used only for the percentages. Omit and they are $null
        rather than a divide-by-zero or a misleading 0.
    .PARAMETER PortRoles
        Optional PortName/Role pairs (from WatchState.ComPortMatches) so each
        port carries DATA/COMMAND. Never key off the COM number: the roles swap
        on every re-pair.
    .OUTPUTS
        [pscustomobject] Ports, SampleCount, HandleAcquiredCount,
        SuccessfulOpenCallMs, SuccessfulOpenCallPercentOfRecording,
        SlowestHoldProbeMs, SlowestPort, SlowestPortState, Phases, Basis.
    #>
    [CmdletBinding()]
    param(
        $Timing,
        [Nullable[double]]$RecordingSeconds = $null,
        $PortRoles = $null
    )

    if ($Timing -isnot [hashtable] -or $Timing.Keys.Count -eq 0) { return $null }

    $roleOf = @{}
    foreach ($r in @($PortRoles)) {
        if (-not $r) { continue }
        $rn = try { [string]$r.PortName } catch { '' }
        if ([string]::IsNullOrWhiteSpace($rn)) { continue }
        $rv = try { [string]$r.Role } catch { '' }
        if (-not [string]::IsNullOrWhiteSpace($rv)) { $roleOf[$rn] = $rv }
    }

    $msToPct = {
        param([double]$Ms)
        if ($null -ne $RecordingSeconds -and [double]$RecordingSeconds -gt 0) {
            [math]::Round(($Ms / ([double]$RecordingSeconds * 1000)) * 100, 2)
        } else { $null }
    }

    $ports        = @()
    $sampleCount  = 0
    $openMs       = [double]0
    $openCount    = 0
    $slowestMs    = [double]0
    $slowestPort  = $null
    $slowestState = $null
    $phaseTotals  = @{}

    foreach ($name in @($Timing.Keys | Sort-Object)) {
        $p = $Timing[$name]
        if (-not $p -or [int]$p.Count -le 0) { continue }
        $sampleCount += [int]$p.Count

        $states     = @()
        $portOpenMs = [double]0
        $portOpens  = 0
        foreach ($stName in @($p.ByState.Keys | Sort-Object)) {
            $b = $p.ByState[$stName]
            if (-not $b -or [int]$b.Count -le 0) { continue }
            $states += [pscustomobject]@{
                State  = $stName
                Count  = [int]$b.Count
                MeanMs = [math]::Round([double]$b.TotalMs / [int]$b.Count, 1)
                MaxMs  = [math]::Round([double]$b.MaxMs, 1)
            }
            if ($stName -eq 'Free') {
                $portOpenMs += [double]$b.TotalMs
                $portOpens  += [int]$b.Count
            }
            # The slowest call is attributed to the state it returned. Its
            # maximum can come from an Unavailable or a Held result -- neither of
            # which is an open -- so calling it the slowest OPEN would have been
            # wrong on exactly the captures where the serial stack is broken.
            if ([double]$b.MaxMs -gt $slowestMs) {
                $slowestMs    = [double]$b.MaxMs
                $slowestPort  = $name
                $slowestState = $stName
            }
        }
        $openMs    += $portOpenMs
        $openCount += $portOpens

        foreach ($phName in @($p.ByPhase.Keys)) {
            $pb = $p.ByPhase[$phName]
            if (-not $pb -or [int]$pb.Count -le 0) { continue }
            if (-not $phaseTotals.ContainsKey($phName)) {
                $phaseTotals[$phName] = @{ Count = 0; OpenCount = 0; OpenMs = [double]0 }
            }
            $phaseTotals[$phName].Count     += [int]$pb.Count
            $phaseTotals[$phName].OpenCount += [int]$pb.OpenCount
            $phaseTotals[$phName].OpenMs    += [double]$pb.OpenMs
        }

        $ports += [pscustomobject]@{
            PortName = $name
            Role     = $(if ($roleOf.ContainsKey($name)) { $roleOf[$name] } else { $null })
            Count    = [int]$p.Count
            MeanMs   = [math]::Round([double]$p.TotalMs / [int]$p.Count, 1)
            MinMs    = if ($null -eq $p.MinMs) { $null } else { [math]::Round([double]$p.MinMs, 1) }
            MaxMs    = [math]::Round([double]$p.MaxMs, 1)
            TotalMs  = [math]::Round([double]$p.TotalMs, 1)
            # Per port, because pooling DATA and COMMAND can bury the channel the
            # operator-facing error is actually about.
            HandleAcquiredCount                 = $portOpens
            SuccessfulOpenCallMs                = [math]::Round($portOpenMs, 1)
            SuccessfulOpenCallPercentOfRecording = & $msToPct $portOpenMs
            ByState  = @($states)
        }
    }

    if ($ports.Count -eq 0) { return $null }

    $phases = @()
    foreach ($phName in @($phaseTotals.Keys | Sort-Object)) {
        $pt = $phaseTotals[$phName]
        $phases += [pscustomobject]@{
            Phase                = $phName
            SampleCount          = [int]$pt.Count
            HandleAcquiredCount  = [int]$pt.OpenCount
            SuccessfulOpenCallMs = [math]::Round([double]$pt.OpenMs, 1)
        }
    }

    return [pscustomobject]@{
        PSTypeName                           = 'WinConfig.FlightRecorder.PortOpenTiming'
        Ports                                = @($ports)
        SampleCount                          = $sampleCount
        HandleAcquiredCount                  = $openCount
        SuccessfulOpenCallMs                 = [math]::Round($openMs, 1)
        SuccessfulOpenCallPercentOfRecording = & $msToPct $openMs
        SlowestHoldProbeMs                   = [math]::Round($slowestMs, 1)
        SlowestPort                          = $slowestPort
        SlowestPortState                     = $slowestState
        # Where the samples came from. 'Tick' alone on a capture that also ran
        # selection and startup means those paths were not wired -- which is the
        # defect this field exists to make visible rather than plausible.
        Phases                               = @($phases)
        Basis                                = 'Full Get-ComPortHoldState call: SerialPort construct + RFCOMM bring-up + Open + Close + Dispose. UPPER BOUND on the exclusive-ownership interval, not a measurement of it.'
    }
}

function Get-ProbeStateConsistency {
    <#
    .SYNOPSIS
        Pure. Cross-checks the probe's state fields against each other and
        returns the combinations that cannot all be true of a healthy box.
    .DESCRIPTION
        Every other alarm in this module is TRANSITION-driven: it fires when a
        field CHANGES. That leaves a hole the field walked straight into
        (2026-07-30) -- a box that is ALREADY in a bad combination when the
        operator hits Record produces no transitions at all, so the startup
        snapshot printed each field on its own line, each individually
        unremarkable, and nothing was flagged while NO.exe was showing
        "Arc Not Detected" on the other monitor.

        This runs on the snapshot itself, so the arrival state is judged as a
        whole rather than field by field.

        FI-012 TRAP -- read before strengthening the no-link rule. "Not
        connected" is NOT on its own a finding: SPP devices hold no profile
        open, so a perfectly healthy idle Arc reads Disconnected, and during the
        FI-012 field case IsConnected read False while both ports opened fine.
        The rule below therefore fires on the CONJUNCTION (a port is held AND
        there is no link) and still reports at [~], because a process holding
        the port means something believes it has a session -- strictly more
        evidence than no-link alone, but not proof. It escalates to [!] only
        when the caller has independently corroborated a stall (flat NO.exe CPU
        while the port is held); that is what CpuStalled is for.
    .PARAMETER StreamState
        'Active' (a port is held) / 'Stopped' / 'Unknown'.
    .PARAMETER CpuStalled
        $true when NO.exe CPU has been observed flat while the port was held.
        Escalates the held-port-without-link rule from evidence to a finding.
    .PARAMETER IoStalled
        $true when NO.exe's read-operation rate collapsed against its own
        baseline while the port was held. Escalates the same way as CpuStalled,
        and catches the case CpuStalled cannot: an application still busy with
        its other work while only its serial path is dead.
    .PARAMETER IoDegrading
        $true when the read rate has begun falling under the collapse limit but
        the debounce has not been satisfied. Fires the same clean-transport rule
        as IoStalled at WARN instead of FAIL. This exists because an operator
        marks the instant the dialog appears, which is BEFORE the four-tick
        debounce completes -- see Test-IoReadCollapse and field capture
        C2FB1FD51A35. Without it the most informative moment in a recording
        cross-checks as clean.
    .OUTPUTS
        [hashtable[]] each with Level ('FAIL'/'WARN'/'INFO') and Text. Wrap call
        sites in @() -- a single finding unrolls on return.
    #>
    [CmdletBinding()]
    param(
        [string]$DeviceState,
        [string]$ComPortState,
        [string]$BtLinkState,
        [string]$StreamState,
        [AllowEmptyCollection()][array]$HeldPorts = @(),
        [AllowEmptyCollection()][array]$UnavailablePorts = @(),
        [System.Nullable[bool]]$AppRunning,
        [bool]$CpuStalled = $false,
        [bool]$IoStalled = $false,
        [bool]$IoDegrading = $false,
        [bool]$SerialIntegrityFault = $false,
        [bool]$TargetEverActive = $false
    )

    $out = @()
    $held     = @($HeldPorts | Where-Object { $_ })
    $dead     = @($UnavailablePorts | Where-Object { $_ })
    $heldStr  = if ($held.Count -gt 0) { $held -join ', ' } else { 'a COM port' }
    # The Arc exposes two SPP channels, so a held-port list is routinely plural.
    # These findings are read by clinic techs; "COM3, COM6 is held open" reads as
    # a bug in the tool and costs the sentence its authority.
    $heldVerb = if ($held.Count -gt 1) { 'are' } else { 'is' }
    $isHeld   = ($StreamState -eq 'Active')
    # Either corroborator is enough. They observe different failure shapes and a
    # box only has to be in one of them.
    $stalled  = ($CpuStalled -or $IoStalled)

    # Ports that exist but will not open.
    #
    # This was unconditionally FAIL, and that is wrong for the commonest reason a
    # port will not open: the headset is switched off. The open fails with
    # ERROR_SEM_TIMEOUT either way -- FI-012 records that a broken serial stack
    # and an absent device are INDISTINGUISHABLE from the error alone. Capture
    # 8E39860E4AF2 turned an Arc sitting in a drawer into two [!] problems and a
    # failed verdict on a session that had gone perfectly.
    #
    # So it stays FAIL only where something else corroborates a real fault:
    #   - the serial integrity check found an OS-level fault (fault 1), or
    #   - this target WAS working earlier in the recording and then went
    #     unavailable, which no power switch explains.
    # Otherwise it is unavailability, reported as evidence with the power state
    # named first -- the same hedge Get-SerialFaultFingerprint already applies to
    # NoActiveLink, and for exactly the same reason.
    if ($dead.Count -gt 0) {
        $corroborated = ($SerialIntegrityFault -or $TargetEverActive)
        if ($corroborated) {
            $why = if ($SerialIntegrityFault) {
                'The serial port integrity check independently reports an OS-level fault, so this is not simply a device that is switched off.'
            } else {
                'This headset was reachable earlier in the same recording and then stopped opening, which being switched off does not explain.'
            }
            $out += @{
                Level = 'FAIL'
                Text  = "[!] $($dead -join ', ') is registered as a Bluetooth serial port but will not open. $why NO.exe cannot receive EEG through a port in this state -- expect 'Control Port not valid' or 'Arc not detected'. The probe deliberately does not guess the cause here: an absent symlink and a stale one give different win32 errors and need different fixes. Run the serial port integrity check (operator-initiated, with NO.exe closed) to split them."
            }
        } elseif ($BtLinkState -ne 'Connected') {
            $out += @{
                Level = 'INFO'
                Text  = "[i] $($dead -join ', ') is registered as a Bluetooth serial port and did not open, and the radio reports no link to this headset. The most likely reason by far is that the headset is switched off or out of range -- a port with nothing on the other end times out exactly like a broken one, and FI-012 records that the two are indistinguishable from the error alone. This is NOT evidence of a fault. To turn it into one: power the headset on, confirm it connects, then run the serial port integrity check with NO.exe closed."
            }
        } else {
            $out += @{
                Level = 'WARN'
                Text  = "[~] $($dead -join ', ') is registered as a Bluetooth serial port but will not open, even though the radio reports an active link to this headset. A linked device whose port refuses to open is worth capturing. The probe deliberately does not guess the cause here: an absent symlink and a stale one give different win32 errors and need different fixes. Run the serial port integrity check with NO.exe closed to classify it."
            }
        }
    }

    # The combination that was missing. A held port with no radio link underneath
    # it means something owns the serial handle while the wireless pipe is down.
    if ($isHeld -and $BtLinkState -eq 'NotConnected') {
        if ($stalled) {
            $evidence = if ($CpuStalled -and $IoStalled) {
                "NO.exe's CPU has stayed flat and its read rate has collapsed"
            } elseif ($IoStalled) {
                "NO.exe's read rate has collapsed"
            } else {
                "NO.exe's CPU has stayed flat"
            }
            $out += @{
                Level = 'FAIL'
                Text  = "[!] $heldStr $heldVerb held open but the Bluetooth radio has no link to the headset, and $evidence while holding it. Nothing is arriving: the application is sitting on a serial port with no live connection under it. This is what 'Arc not detected' looks like from the OS side."
            }
        } else {
            $out += @{
                Level = 'WARN'
                Text  = "[~] $heldStr $heldVerb held open, but the Bluetooth radio reports no active link to the headset. A held port means something (normally NO.exe) believes it has a session, so this pairing is worth capturing -- but it is NOT proof on its own: SPP devices hold no profile open, so a healthy Arc can also read disconnected. Check whether NeurOptimal is showing an error right now."
            }
        }
    }

    # The 12006 shape. Field capture 2026-07-30 15:30: RFCOMM link up, both ports
    # Present/OK, integrity healthy, zero probe events for the whole recording --
    # and NO.exe raised "Arc Connection Lost" anyway. Nothing in the Bluetooth
    # layer contradicts anything, which is precisely the finding: a clean
    # transport with dead reads localizes the fault ABOVE Bluetooth, and the
    # recorder used to have no way to say that.
    #
    # Confirmed again by C2FB1FD51A35 (2026-07-31), which is also why IoDegrading
    # is here: at the marked instant the rate was 13% of baseline and still
    # classified 'Streaming', so this rule -- already written, already correct --
    # was gated off at the one moment it existed for.
    if ($isHeld -and ($IoStalled -or $IoDegrading) -and $BtLinkState -ne 'NotConnected') {
        if ($IoStalled) {
            $out += @{
                Level = 'FAIL'
                Text  = "[!] $heldStr $heldVerb held open and the Bluetooth link is up, but NO.exe has stopped reading from it. The transport is intact -- device paired, ports present, link established -- so this is not a Bluetooth failure. Either the headset stopped transmitting while its baseband link stayed up, or NeurOptimal's read path stalled. Expect 'Arc Connection Lost' on screen with nothing wrong on the Windows side."
            }
        } else {
            $out += @{
                Level = 'WARN'
                Text  = "[~] $heldStr $heldVerb held open and the Bluetooth link is up, but NO.exe's read rate is already falling below the level this session established for itself. The transport is intact, so this is not a Bluetooth failure -- it is the first part of a read-path stall, caught before it finished. If NeurOptimal is showing 'Arc Connection Lost' right now, this is what it looks like from outside."
            }
        }
    }

    # Something holds the headset's port and it is not NO.exe.
    if ($isHeld -and $AppRunning -eq $false) {
        $out += @{
            Level = 'WARN'
            Text  = "[~] $heldStr $heldVerb held open while NeurOptimal is not running. Another process owns the headset's serial port; NO.exe will not be able to open it until that process releases it."
        }
    }

    # A port cannot honestly be held for a device Windows does not consider paired.
    if ($isHeld -and $DeviceState -and $DeviceState -ne 'PairedCandidate') {
        $out += @{
            Level = 'FAIL'
            Text  = "[!] $heldStr $heldVerb held open but Windows does not report the headset as paired (device state: $(Get-ProbeStateUserText -Kind device -State $DeviceState -Short)). The port and the pairing record disagree -- one of them is stale."
        }
    }

    return $out
}

# =============================================================================
# OPERATOR MARKERS
# =============================================================================

function New-ProbeStateMarker {
    <#
    .SYNOPSIS
        Pure. Builds a timestamped, LABELLED snapshot of every probe state field,
        tagged with whatever NeurOptimal was telling the operator at that moment.
    .DESCRIPTION
        The recorder captures state continuously but has never captured what the
        APPLICATION said about that state. That gap matters more than it looks:
        NO's error codes are still being mapped, and several dialogs that look
        identical on screen are different failures underneath. Without a label,
        a recording is an unlabelled state vector -- it cannot help separate one
        12005 from another.

        A marker is the operator pressing "this is happening right now, and here
        is the code on my screen". One marker is a labelled sample; enough of
        them across enough boxes is what lets a code that means two things come
        apart into two clusters.

        Deliberately NOT clustered or hashed here. PpfFingerprint exists for
        that, but its contract is one fingerprint per session computed at
        finalization, and a bucketing scheme frozen now would be frozen while
        the code mapping is still moving. Record the raw vector; cluster it
        offline in the analyzer, where the scheme can change without
        invalidating the archive.
    .PARAMETER Label
        Raw operator input. Any leading digit run is also surfaced as NoCode so
        a typed "12005" or "NO Code 12005" both key correctly, while free text
        ("headset light on, no trace") is preserved intact.
    .OUTPUTS
        [hashtable] one marker record.
    #>
    [CmdletBinding()]
    param(
        [string]$Label,
        [datetime]$At = (Get-Date),
        [int]$ElapsedSeconds = 0,
        [string]$DeviceState,
        [string]$ComPortState,
        [string]$BtLinkState,
        [string]$StreamState,
        [AllowEmptyCollection()][array]$HeldPorts = @(),
        [AllowEmptyCollection()][array]$UnavailablePorts = @(),
        [System.Nullable[bool]]$AppRunning,
        [string]$NoExeVersion,
        [string]$IoVerdict,
        [int]$IoBaselineOpsPerTick = 0,
        [int]$IoRecentOpsPerTick = 0,
        # Corroboration for the dead-port rule. Without these a marker placed
        # while the headset happened to be off would cross-check as a hard port
        # fault; with them the same instant reads as an unreachable device.
        [bool]$SerialIntegrityFault = $false,
        [bool]$TargetEverActive = $false
    )

    $clean = if ($Label) { ([string]$Label).Trim() } else { '' }
    $code  = $null
    if ($clean) {
        $m = [regex]::Match($clean, '\d{3,}')
        if ($m.Success) { $code = $m.Value }
    }

    # The cross-check verdict at the marked instant, carried WITH the label. This
    # is what makes the sample worth having: not just "the operator saw 12005"
    # but "the operator saw 12005 while the port was held with no link under it".
    # Both read-rate states are passed through. A marker is placed at the instant
    # a dialog appeared, which is systematically EARLIER than the four-tick
    # debounce behind 'Collapsed' -- so keying the cross-check on 'Collapsed'
    # alone made the cross-check blindest exactly when it mattered most.
    $contradictions = @(Get-ProbeStateConsistency `
        -DeviceState $DeviceState -ComPortState $ComPortState `
        -BtLinkState $BtLinkState -StreamState $StreamState `
        -HeldPorts $HeldPorts -UnavailablePorts $UnavailablePorts `
        -AppRunning $AppRunning -IoStalled ($IoVerdict -eq 'Collapsed') `
        -IoDegrading ($IoVerdict -eq 'Degrading') `
        -SerialIntegrityFault $SerialIntegrityFault -TargetEverActive $TargetEverActive)

    # Recomputed here rather than passed in so a marker is self-describing: the
    # archive is read long after the fact, and a raw pair of counters makes the
    # reader do arithmetic to see that 56-against-444 is a fault.
    $fraction = if ($IoBaselineOpsPerTick -gt 0) {
        [math]::Round(($IoRecentOpsPerTick / $IoBaselineOpsPerTick) * 100, 0)
    } else { $null }

    return @{
        At               = $At
        AtIso            = $At.ToString('o')
        ElapsedSeconds   = $ElapsedSeconds
        Label            = $clean
        NoCode           = $code
        DeviceState      = $DeviceState
        ComPortState     = $ComPortState
        BtLinkState      = $BtLinkState
        StreamState      = $StreamState
        HeldPorts        = @($HeldPorts | Where-Object { $_ })
        UnavailablePorts = @($UnavailablePorts | Where-Object { $_ })
        AppRunning       = $AppRunning
        NoExeVersion     = if ($NoExeVersion) { [string]$NoExeVersion } else { $null }
        # Read-rate state at the marked instant. This is the field that turns a
        # marker into evidence about NO's own read path rather than only about
        # the Bluetooth layer.
        IoVerdict            = if ($IoVerdict) { $IoVerdict } else { 'NoBaseline' }
        IoBaselineOpsPerTick = $IoBaselineOpsPerTick
        IoRecentOpsPerTick   = $IoRecentOpsPerTick
        IoFractionOfBaseline = $fraction
        Contradictions   = @($contradictions | ForEach-Object { $_.Text })
    }
}

function Format-ProbeStateMarker {
    <#
    .SYNOPSIS
        Pure. Renders one marker as a single operator-readable line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Marker)

    $what = if ($Marker.NoCode) { "NO code $($Marker.NoCode)" } else { 'an issue' }
    $extra = if ($Marker.Label -and $Marker.Label -ne $Marker.NoCode) { " (`"$($Marker.Label)`")" } else { '' }
    $mins  = [int][math]::Floor($Marker.ElapsedSeconds / 60)
    $secs  = $Marker.ElapsedSeconds % 60
    $when  = '{0}  {1}m{2:00}s into the recording' -f $Marker.At.ToString('HH:mm:ss'), $mins, $secs

    $ports = if (@($Marker.HeldPorts).Count -gt 0) { "held $(@($Marker.HeldPorts) -join ', ')" } else { 'no port held' }

    # The read rate belongs on this line. Without it the marker for capture
    # C2FB1FD51A35 rendered as a tidy all-green state vector -- device paired,
    # radio connected, ports held, NO.exe running -- while the one number that
    # showed the fault (56 against a 444 baseline) sat unread in the record.
    $io = switch ($Marker.IoVerdict) {
        'Collapsed'  { "reads COLLAPSED to $($Marker.IoRecentOpsPerTick)/tick from a $($Marker.IoBaselineOpsPerTick) baseline" }
        'Degrading'  { "reads FALLING at $($Marker.IoRecentOpsPerTick)/tick against a $($Marker.IoBaselineOpsPerTick) baseline" }
        'Streaming'  { "reads steady at ~$($Marker.IoRecentOpsPerTick)/tick" }
        default      { 'read rate not assessed' }
    }
    if ($null -ne $Marker.IoFractionOfBaseline -and $Marker.IoVerdict -ne 'Streaming' -and $Marker.IoVerdict -ne 'NoBaseline') {
        $io += " ($($Marker.IoFractionOfBaseline)% of normal)"
    }

    $state = @(
        "device=$(Get-ProbeStateUserText -Kind device -State $Marker.DeviceState -Short)"
        "radio=$(Get-ProbeStateUserText -Kind btlink -State $Marker.BtLinkState -Short)"
        $ports
        "NO.exe=$(if ($Marker.AppRunning -eq $true) { 'running' } elseif ($Marker.AppRunning -eq $false) { 'not running' } else { 'unknown' })"
        $io
    ) -join ', '

    return "Operator marked $what$extra at $when -- $state"
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
        # Ever-held, as opposed to held-on-the-last-tick. Drives observation
        # coverage; see Get-ProbeObservationCoverage.
        #
        # Latched straight off HeldPorts on EVERY tick. It replaces
        # StreamEverActive (issue #67), which latched only inside the
        # StreamingState TRANSITION branch and so could not see a port that was
        # ALREADY held when Record was pressed: the recorder seeds
        # StreamingState from the arrival snapshot, so a session already
        # streaming produces no transition and the flag stayed false for the
        # whole run. Capture 2DC7C9DFD5FA held both ports on 1300 of 1302
        # probes and still reported "No process ever held the target headset's
        # COM port", downgrading the first clean 30-minute run to Partial.
        # The name now matches the source: this field IS HeldPorts, remembered.
        PortEverHeld             = $false
        ActiveStreamPort         = $null
        # Last tick's port classification. HeldPorts drives the honest operator
        # text; UnavailablePorts is the FI-012 signal the old bool test erased by
        # folding "would not open" in with "nobody has it open".
        HeldPorts                = @()
        UnavailablePorts         = @()
        StreamPeakCpuS           = 0.0
        StreamPeakWorkingSetMB   = 0
        # Data-flow corroboration. The probe cannot read the EEG bytes -- the port
        # is held by NO.exe, and opening it to look would steal it. NO.exe's own
        # CPU is the honest proxy available from outside: a live stream keeps
        # burning CPU, a stalled one flatlines while still holding the handle.
        StreamCpuFirstSample     = $null
        StreamCpuLastSample      = $null
        StreamFlatCpuTicks       = 0
        StreamCpuStalled         = $false
        StreamCpuStallReported   = $false
        # Read-operation rate. Catches the case CPU cannot: only ONE of the
        # application's jobs dies, so it stays busy (audio kept playing through
        # the 12006 capture) while its serial reads stop. Relative to the box's
        # own recent history -- no absolute rate would survive a different NO
        # build or a different session type.
        IoApiAvailable           = $false
        IoLastReadOps            = $null
        IoReadOpDeltas           = [System.Collections.ArrayList]::new()
        IoVerdict                = 'NoBaseline'
        IoBaselineOpsPerTick     = 0
        IoRecentOpsPerTick       = 0
        IoFractionOfBaseline     = $null
        # An intermittent stall never satisfies the four-tick debounce, so it
        # used to summarise as "held steady" -- the reading a dropout-every-
        # 30-seconds headset would produce. These two remember the dips.
        IoDegradedTicks          = 0
        # The worst read rate seen on the TICK path, kept as a PAIR. The fraction
        # was tracked alone, and the ops/tick that produced it was recovered from
        # a different channel entirely (the collapsed-episode ledger), so capture
        # E0C8B0588CC7 reported a worst fraction of 0% beside a worst rate of
        # null: two halves of one observation, sourced from two places, one of
        # which had nothing to say. Both are $null until something is measured --
        # 0 in a percentage field would read as "total collapse" (issue #65).
        IoWorstFractionOfBaseline = $null
        IoWorstRecentOpsPerTick   = $null
        IoStalled                = $false
        IoStallReported          = $false
        # A collapse WAS detected at some point in this run. Unresettable, and
        # deliberately separate from IoStalled, which the port-re-open wipe
        # clears because a baseline may not span two handles.
        #
        # #59 kept a collapse that a RE-OPEN would have erased, by closing the
        # episode into IoClosedEpisodes first. Capture 31D0729CA5B8 found the
        # other way to lose one: TIME. A 33-minute session was followed by 15.4 h
        # of idle recording with the port still held, so the trailing median
        # decayed to zero, the live episode evaluated to 'NoBaseline' and
        # New-IoEpisodeRecord discarded it -- taking the collapse with it. No
        # re-open ever happened, so BaselineResetCount stayed 0 and the
        # documented escape hatch could not catch it (issue #63).
        IoCollapseEverDetected   = $false
        # Last tick that actually moved read operations. The idle tail is the
        # difference between this and the final tick, and it is the single fact
        # that explains a capture like 31D0729CA5B8 to a reader.
        IoLastNonZeroReadAt      = $null
        # Closed read-rate EPISODES.
        #
        # The live fields above describe one port-open episode and are wiped
        # whenever the port is re-opened, because a baseline may not span two
        # handles. That reset is correct for the live measurement and was
        # catastrophic for the record: field capture C0AE9604CDAC (Arc 000013,
        # 2026-08-07) established a 776 ops/tick baseline, collapsed to 1% of it
        # across 12 ticks, was marked by the operator against NO code 12006 with
        # IoVerdict=Collapsed -- and then NO.exe re-opened the port, which reset
        # the live verdict to 'NoBaseline' and the baseline to 0. The session
        # ended reporting verdict NoBaseline / collapsed false / baseline 0, so
        # the bundle counted a measured collapse as "data flow unmeasured".
        #
        # Every episode that ends is stamped here first. Never reset.
        IoClosedEpisodes         = [System.Collections.ArrayList]::new()
        # How many times the live measurement restarted. A reader needs this to
        # know that "no baseline at the end" can mean "the baseline was thrown
        # away", not "none was ever found".
        IoBaselineResetCount     = 0
        # One-shot: has the operator been told a read baseline exists? Without
        # this the recorder is silent during a healthy stretch and silent during
        # a dead one, so nobody can tell "reads are at 440/tick" from "reads are
        # at 0/tick" until the ZIP is decoded. Field capture BD54BA02FE25
        # (Surface Pro 6, 2026-07-31) uploaded 'NoBaseline' with zero reads all
        # session and the operator had no way to know while it was happening.
        IoBaselineReported       = $false
        # ...and these two put that announcement IN THE ARCHIVE. The event above
        # is live-only: it scrolls past the operator and is never written to
        # probe-session.json, so reading a bundle afterwards could not tell a run
        # that announced a baseline from one that never did -- build provenance
        # came down to whether someone remembered seeing a green line. Capture
        # D8EE48E60DF2 (2026-08-01) had to be confirmed that way.
        #
        # The RATE is stored alongside the time because the baseline is a running
        # median: what was announced is not necessarily what the run ends on, and
        # the announced figure is the one the operator actually saw.
        IoBaselineAnnouncedAt    = $null
        IoBaselineAnnouncedOpsPerTick = $null
        AppNotRespondingTicks    = 0
        AppHangReported          = $false
        # How long the recording actually ran, and how many samples are behind
        # every verdict in it. Neither was recoverable from a bundle: a 55-second
        # capture and a 6-hour one both report "ObservationCount 3" (observations
        # are transitions, and an arrived-already-in-state box produces three at
        # tick one and nothing after). Duration is what decides whether a tail of
        # link flaps is a fault or an unattended overnight run -- D8EE48E60DF2
        # needed StartedAtUtc subtracted from PackagedAtUtc to establish that.
        # TickCount is the confidence denominator: a verdict off 9 ticks and one
        # off 7000 are not the same evidence.
        TickCount                = 0
        FirstTickAt              = $null
        LastTickAt               = $null
        # ── The recording window, which is NOT the tick window (issue #78) ────
        # The tick loop starts at least one tick interval after the operator
        # pressed Record, and on a starved run far later -- capture
        # 236061907514 took 11.85 s to reach its first tick and stopped
        # ~25 s after its last one. Deriving "how long did this run?" from
        # FirstTickAt..LastTickAt therefore UNDERSTATES it, and did: the
        # manifest said 69 s for a run carrying operator markers stamped at 86 s
        # and 107 s, with a read-rate episode ending ~134 s in.
        #
        # That is the channel-mismatch shape. Two clocks answered one question:
        # the operator marker and the on-screen "Recording mm:ss" label both
        # count from the moment Record was pressed, while the manifest counted
        # tick span. Only one may be authoritative, and it has to be the one the
        # operator and the markers already use -- so these two are set by the
        # recording loop and the duration is derived from them. FirstTickAt/
        # LastTickAt survive for what they genuinely measure: tick cadence.
        #
        # The understatement is not cosmetic. durationSeconds / tickCount is the
        # documented way to get real cadence, and 69/22 = 3.14 s reads as a
        # healthy 3 s loop; the true ~134/22 = 6.1 s is the 82 %-missed-deadline
        # starvation that should have flagged the capture.
        RecordingStartedAt       = $null
        RecordingStoppedAt       = $null
        # How invasive the recorder actually was. Get-ComPortHoldState is the
        # only non-admin way to learn whether a port is held, but it works by
        # OPENING the port -- the very thing Test-BluetoothSerialPortOpen is
        # forbidden from doing mid-session. On a port NO.exe holds, the attempt
        # is denied and no handle is taken; on a FREE port we genuinely open and
        # close it every ~3s. These counters say which happened and how often,
        # so the question "is the recorder perturbing the device it is watching"
        # is answered from a capture instead of argued from first principles.
        PortOpenAttempts         = 0
        PortOpenAcquired         = 0
        PortOpenDenied           = 0
        # ...and for HOW LONG. The counters above answer "how often"; they cannot
        # bound the time NO.exe could not have had the port, which is the
        # observer-effect question. Keyed by port name, split by returned hold
        # state AND by phase -- the recording window opens before target
        # selection, so a tick-only numerator understates it. Fed only through
        # Add-PortOpenTimingSamples. See Get-PortOpenTimingReport on why the
        # headline is an upper bound rather than a measurement.
        PortOpenTiming           = @{}
        # Cross-field contradictions present in the arrival snapshot, before any
        # transition could fire. Populated by the caller at startup.
        StartupConsistency       = @()
        # Operator-labelled state vectors: what NeurOptimal was reporting on
        # screen, bound to what the machine looked like at that instant. The
        # recorder is blind to the application's own error dialogs, so without
        # these the archive is a pile of unlabelled samples.
        OperatorMarkers          = [System.Collections.ArrayList]::new()
        StartupSppChannelCount   = 0
        BtWin32Available         = $false
        NoExeVersion             = $null
        AdapterInfo              = $null
        PowerPlan                = $null
        PendingConfirmation      = $null
        # SERIALCOMM / COM-symlink integrity, captured at session start and end.
        # Two samples rather than one because the interesting case is a box that
        # was healthy when recording began and corrupt when it ended -- that
        # pins the corruption to something that happened during the session.
        SerialPortIntegrity      = $null
        SerialPortIntegrityEnd   = $null
        # FI-012 fault 2 fingerprint (paired, ports clean, no link). Derived
        # without opening a port, because the open collector must never run
        # inside a live recording session.
        SerialFaultFingerprint   = $null
        # FI-014: BTHPORT pairing record vs PnP node, target-scoped, at session
        # start and end. Two samples for the same reason as the pair above --
        # only the transition tells you the node was torn down DURING this
        # recording rather than at some point before it.
        #
        # The MAC and its source are stored because they qualify the verdict:
        # Source='None' means nothing could be scoped to, and an unscoped
        # verdict is Healthy by construction. A reader must not take that for a
        # clean bill of health.
        # The canonical target identity for this recording, from
        # Select-BluetoothSessionTarget, plus the MAC frozen from it. Every
        # target-scoped consumer reads TargetMacFrozen so one capture can never
        # describe two different headsets (capture 8E39860E4AF2 did).
        SessionTarget            = $null
        TargetMacFrozen          = $null
        PairingRecord            = $null
        PairingRecordEnd         = $null
        PairingTargetMac         = $null
        PairingTargetSource      = 'None'
        PairingTargetSummary     = $null
        # Discovery scan, only run when the target has no node AND NO.exe is
        # closed. Carries its own not-collected reason, because "no devices
        # found" and "never scanned" are opposite conclusions.
        InquiryScan              = $null
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

    $Session.TickCount++
    if (-not $Session.FirstTickAt) { $Session.FirstTickAt = $now }
    $Session.LastTickAt = $now

    # ── Port-hold detection (NOT a data-flow measurement) ────────────────
    $streamResult = Get-StreamingState -WatchState $WatchState
    $newStreamState = $streamResult.State
    # Tolerate a result without the port lists: Get-StreamingState is mocked in
    # tests and may be replaced by an older caller, and a missing list must not
    # take the whole tick down.
    $Session.HeldPorts = @(
        if ($streamResult -is [hashtable] -and $streamResult.ContainsKey('HeldPorts')) { $streamResult.HeldPorts } else { @() }
    )
    $newDeadPorts = @(
        if ($streamResult -is [hashtable] -and $streamResult.ContainsKey('UnavailablePorts')) { $streamResult.UnavailablePorts } else { @() }
    )
    # Union across the session: a port that failed to open at any point stays in
    # the record even if it opens later.
    $Session.UnavailablePorts = @(@($Session.UnavailablePorts) + $newDeadPorts | Where-Object { $_ } | Select-Object -Unique)

    # Session-long memory of the port hold. HeldPorts is the LAST tick only, so
    # without this nothing can answer "was the target's port ever held at any
    # point?" -- the question that separates "the session had a problem" from
    # "this recording never saw the session".
    #
    # Deliberately OUTSIDE the transition branch below, and read off exactly the
    # list PortOpenDenied is incremented from a few lines down. Issue #67: the
    # old latch lived in the transition branch, so it never fired on a run whose
    # port was held from the first tick onwards -- the shape of every healthy
    # capture where the operator starts the recorder during a session.
    if (@($Session.HeldPorts | Where-Object { $_ }).Count -gt 0) { $Session.PortEverHeld = $true }

    # Invasiveness accounting. Tolerates a result without the lists for the same
    # reason as HeldPorts above: Get-StreamingState is mocked in tests and an
    # older caller must not take the tick down.
    if ($streamResult -is [hashtable]) {
        if ($streamResult.ContainsKey('ProbedPorts')) {
            $Session.PortOpenAttempts += @($streamResult.ProbedPorts | Where-Object { $_ }).Count
        }
        if ($streamResult.ContainsKey('OpenedPorts')) {
            $Session.PortOpenAcquired += @($streamResult.OpenedPorts | Where-Object { $_ }).Count
        }
        $Session.PortOpenDenied += @($Session.HeldPorts | Where-Object { $_ }).Count
        # Tolerates absence for the same reason as the lists above: an older
        # caller or a test mock of Get-StreamingState must not take the tick down.
        # A capture from such a run reports no timing rather than a wrong zero.
        if ($streamResult.ContainsKey('PortOpenDurations')) {
            $null = Add-PortOpenTimingSamples -Timing $Session.PortOpenTiming `
                -Durations $streamResult.PortOpenDurations -Phase 'Tick'
        }
    }

    if ($newStreamState -ne $Session.StreamingState) {
        $prevStreaming = $Session.StreamingState
        $Session.StreamingState = $newStreamState

        if ($newStreamState -eq 'Active') {
            # NOTE: the session-long port-hold latch is NOT set here. It is set
            # every tick from HeldPorts above, because this branch only runs on
            # a CHANGE and a port held from the start of the recording never
            # produces one. See PortEverHeld / issue #67.
            $Session.StreamPeakCpuS         = 0.0
            $Session.StreamPeakWorkingSetMB = 0
            $Session.StreamCpuFirstSample   = $null
            $Session.StreamCpuLastSample    = $null
            $Session.StreamFlatCpuTicks     = 0
            $Session.StreamCpuStalled       = $false
            $Session.StreamCpuStallReported = $false
            # Close out the read-rate episode BEFORE wiping it. The reset below
            # is correct -- a baseline must not span two port handles -- but it
            # used to be the only thing that happened, so a collapse already
            # measured was erased by NO.exe simply re-opening the port, and the
            # session ended claiming no baseline was ever established. See
            # IoClosedEpisodes in New-DeviceProbeSession for the field capture.
            $closing = New-IoEpisodeRecord -Session $Session -At $now
            if ($closing) { [void]$Session.IoClosedEpisodes.Add($closing) }
            if ([int]$Session.IoBaselineOpsPerTick -gt 0) { $Session.IoBaselineResetCount++ }

            $Session.IoLastReadOps          = $null
            $Session.IoReadOpDeltas.Clear()
            $Session.IoVerdict              = 'NoBaseline'
            $Session.IoBaselineOpsPerTick   = 0
            $Session.IoRecentOpsPerTick     = 0
            $Session.IoFractionOfBaseline   = $null
            $Session.IoStalled              = $false
            $Session.IoStallReported        = $false
            $Session.IoBaselineReported     = $false
            $portInfo = if ($streamResult.ActivePort) { " on $($streamResult.ActivePort)" } else { '' }
            $Session.ActiveStreamPort = $streamResult.ActivePort
            # Deliberately does not say "EEG data streaming" -- this event fires on
            # a handle being taken, which NO.exe does at connect whether or not the
            # headset ever delivers a sample.
            $evt = @{ Kind = 'STREAM'; State = 'Active'; Reason = "NO.exe has the COM port open$portInfo (data flow not verified -- the probe cannot read the port while it is held)"; Annotation = $null; Level = 'OK'; Timestamp = $now }
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

                # Data-flow corroboration. "Port held" alone cannot distinguish a
                # live session from NO.exe sitting on a port that never delivers a
                # sample -- the exact case that reported healthy in the field while
                # NO.exe showed "Arc Not Detected". Cumulative process CPU is the
                # proxy: real EEG processing keeps accumulating it, a stall does
                # not. The threshold is deliberately slack (< 0.06s of CPU per ~3s
                # tick, i.e. under ~2% of one core) and needs 8 consecutive flat
                # ticks (~24s), so a momentarily quiet but working session resets
                # the counter long before this fires.
                $rawCpu = try { [double]$noProc.CPU } catch { $null }
                if ($null -ne $rawCpu) {
                    if ($null -eq $Session.StreamCpuFirstSample) { $Session.StreamCpuFirstSample = $rawCpu }
                    if ($null -ne $Session.StreamCpuLastSample) {
                        $cpuDelta = $rawCpu - [double]$Session.StreamCpuLastSample
                        if ($cpuDelta -lt 0.06) {
                            $Session.StreamFlatCpuTicks++
                        } else {
                            $Session.StreamFlatCpuTicks = 0
                        }
                    }
                    $Session.StreamCpuLastSample = $rawCpu

                    if ($Session.StreamFlatCpuTicks -ge 8 -and -not $Session.StreamCpuStallReported) {
                        $Session.StreamCpuStalled       = $true
                        $Session.StreamCpuStallReported = $true
                        $flatSec  = $Session.StreamFlatCpuTicks * 3
                        $totalCpu = [math]::Round($rawCpu - [double]$Session.StreamCpuFirstSample, 2)
                        $portStr  = if ($Session.ActiveStreamPort) { $Session.ActiveStreamPort } else { 'the COM port' }
                        $linkNote = if ($Session.BtLinkState -eq 'NotConnected') {
                            ' The radio also reports no active link, so there is nothing underneath the port to deliver data.'
                        } else { '' }
                        $events += @{
                            Kind = 'ANOMALY'; State = 'StreamStalled'
                            Reason = "NO.exe is holding $portStr but has used only ${totalCpu}s of CPU over the last ${flatSec}s"
                            Annotation = "[!] Port held, no data flow: a live EEG session keeps NO.exe busy, and this one is idle while still owning the port.$linkNote Expect 'Arc not detected' on screen even though the headset's light suggests it is streaming."
                            Level = 'FAIL'; Timestamp = $now
                        }
                    }
                }

                # Read-operation rate. Sampled independently of CPU -- the two
                # catch different shapes and neither should be able to suppress
                # the other. CPU flatline catches an application doing nothing at
                # all; a read collapse catches one still busy with its other work
                # while only the serial path is dead. The 12005 and 12006 field
                # captures are one of each.
                $ioSample = Get-ProcessIoSample -Process $noProc
                if ($ioSample) {
                    if ($null -ne $Session.IoLastReadOps) {
                        $opsDelta = $ioSample.ReadOps - [double]$Session.IoLastReadOps
                        # Counters are monotonic within a process. A negative
                        # delta means this is a different NO.exe, so drop the
                        # history rather than baseline across two processes.
                        if ($opsDelta -lt 0) {
                            $Session.IoReadOpDeltas.Clear()
                        } else {
                            [void]$Session.IoReadOpDeltas.Add($opsDelta)
                            # Stamped from the tick path, so the idle tail is
                            # measured rather than inferred from wall clock.
                            if ($opsDelta -gt 0) { $Session.IoLastNonZeroReadAt = $now }
                        }
                    }
                    $Session.IoLastReadOps = $ioSample.ReadOps

                    $ioVerdict = Test-IoReadCollapse -Deltas @($Session.IoReadOpDeltas)
                    $Session.IoVerdict            = $ioVerdict.Verdict
                    $Session.IoBaselineOpsPerTick = $ioVerdict.BaselineOpsPerTick
                    $Session.IoRecentOpsPerTick   = $ioVerdict.RecentOpsPerTick
                    $Session.IoFractionOfBaseline = $ioVerdict.FractionOfBaseline

                    # Session-long memory of dips. A headset that drops out
                    # briefly and recovers never satisfies the debounce, so
                    # without this the summary would call the whole recording
                    # steady -- the exact reading an intermittent Arc produces.
                    if ($Session.IoVerdict -in @('Degrading', 'Collapsed')) {
                        $Session.IoDegradedTicks++
                    }
                    if ($null -ne $ioVerdict.FractionOfBaseline -and
                        ($null -eq $Session.IoWorstFractionOfBaseline -or
                         $ioVerdict.FractionOfBaseline -lt $Session.IoWorstFractionOfBaseline)) {
                        $Session.IoWorstFractionOfBaseline = $ioVerdict.FractionOfBaseline
                        # Captured in the SAME assignment as the fraction, so the
                        # two can only ever describe the same tick.
                        $Session.IoWorstRecentOpsPerTick   = [int]$ioVerdict.RecentOpsPerTick
                    }

                    # Baseline established -- the ONLY positive confirmation the
                    # operator ever gets that read-rate monitoring is working on
                    # this box. Every other read-rate event is a failure event,
                    # so their absence was indistinguishable from the detector
                    # watching the wrong process: NO 4.x does its serial I/O
                    # through NI-VISA, and if VISA proxied the port through its
                    # own service the counters would land there and NO.exe would
                    # read zero forever. This line settles that live, in seconds,
                    # instead of after an upload and a decode.
                    #
                    # Fires on 'Streaming' only, which already requires
                    # IoBaselineMinTicks samples above IoBaselineMinOpsPerTick --
                    # so it cannot announce a baseline that is too thin to judge
                    # a collapse against. One-shot per streaming period; the
                    # reset above re-arms it when a new port hold begins.
                    if ($ioVerdict.Verdict -eq 'Streaming' -and -not $Session.IoBaselineReported) {
                        $Session.IoBaselineReported = $true
                        # Persisted to the manifest so the archive says this for
                        # itself instead of depending on operator recall.
                        #
                        # FIRST announcement of the RUN, deliberately: unlike
                        # IoBaselineReported (which re-arms per streaming period
                        # so the operator sees the line each time), this is never
                        # reset. It answers a run-level question -- "was data
                        # flow EVER measurable during this recording?" -- and a
                        # later streaming period must not overwrite the earliest
                        # yes. Still null at the end means never, which is the
                        # BD54BA02FE25 signal, now legible without decoding the
                        # session log.
                        if ($null -eq $Session.IoBaselineAnnouncedAt) {
                            $Session.IoBaselineAnnouncedAt = $now
                            $Session.IoBaselineAnnouncedOpsPerTick = $ioVerdict.BaselineOpsPerTick
                        }
                        $events += @{
                            Kind = 'STREAM'; State = 'ReadBaseline'
                            Reason = "NO.exe read baseline established at ~$($ioVerdict.BaselineOpsPerTick) read operations per tick"
                            Annotation = "[ok] Data flow is measurable on this machine, so a stall later in this recording will be caught. The number is this session's own normal -- it varies by box and by build, and only the ratio against it means anything."
                            Level = 'OK'; Timestamp = $now
                        }
                    }

                    if ($ioVerdict.Verdict -eq 'Collapsed' -and -not $Session.IoStallReported) {
                        $Session.IoStalled       = $true
                        $Session.IoStallReported = $true
                        # The unresettable twin. IoStalled above is wiped by a
                        # port re-open and eroded by an idle tail; this is the
                        # run-level fact that a collapse was measured at all.
                        $Session.IoCollapseEverDetected = $true
                        $ioPort = if ($Session.ActiveStreamPort) { $Session.ActiveStreamPort } else { 'the COM port' }
                        # Distinguishes this from the CPU-flatline case in the
                        # operator's own terms: the app is visibly still working.
                        $busyNote = if ($Session.StreamFlatCpuTicks -lt 4) {
                            ' NO.exe is still busy with its other work, so this is not the application freezing -- one of its jobs died and the rest kept running.'
                        } else { '' }
                        $events += @{
                            Kind = 'ANOMALY'; State = 'ReadRateCollapsed'
                            Reason = "NO.exe read rate collapsed from ~$($ioVerdict.BaselineOpsPerTick) to ~$($ioVerdict.RecentOpsPerTick) read operations per tick while still holding $ioPort"
                            Annotation = "[!] The application stopped reading while keeping the port open.$busyNote Windows can still show the Bluetooth link as connected here: the baseband link stays up while the headset stops delivering data, which is what 'Arc Connection Lost' looks like from outside."
                            Level = 'FAIL'; Timestamp = $now
                        }
                    }
                }

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

    # ── SERIALCOMM / COM-symlink integrity ────────────────────────────────────
    # FI-012. This is the state where Device Manager shows the ports Present/OK,
    # NO.exe resolves the command port correctly, and CreateFile still fails with
    # ERROR_FILE_NOT_FOUND because the \GLOBAL??\COMx symlink is gone. Nothing
    # else in the recorder can see it -- ghost-device enumeration reports zero
    # ghosts on a box in this state -- so it goes first, above the COM-port
    # findings, which are noise by comparison when the ports cannot be opened at
    # all. Populated by the caller; absent on older sessions.
    $integStart = $Session.SerialPortIntegrity
    $integEnd   = $Session.SerialPortIntegrityEnd
    $integ      = if ($integEnd) { $integEnd } else { $integStart }

    if ($integ) {
        if (-not $integ.Healthy -and $integ.MissingSymlinkCount -gt 0) {
            [void]$findings.Add("[!] Bluetooth COM ports are broken at the OS level: $($integ.EntryCount) SERIALCOMM registrations for $($integ.ComNameCount) COM name(s), $($integ.CollisionCount) collided, $($integ.MissingSymlinkCount) symlink(s) absent. No process can open ANY Bluetooth COM port in this state -- expect 'Control Port not valid' / 'Arc not detected'. FIX: reboot. Re-pairing also clears it but is more disruptive and adds another COM-name generation.")
        } elseif (-not $integ.Healthy -and $integ.CollisionCount -gt 0) {
            [void]$findings.Add("[!] Bluetooth serial port registrations are colliding: $($integ.CollisionCount) COM name(s) claimed by more than one device object, but the symlinks still resolve. Ports work right now -- this is the state that precedes 'Control Port not valid'. A reboot clears it before it bites.")
        } elseif ($integ.Healthy) {
            [void]$findings.Add("[ok] Bluetooth serial port registrations are consistent ($($integ.EntryCount) entries for $($integ.ComNameCount) COM name(s), all symlinks resolve)")
        }

        # Stale symlink: resolves, but to an abandoned device object. Reported
        # separately from the absent-symlink case because the two produce
        # DIFFERENT win32 errors and an operator who sees the timeout will
        # otherwise be sent to toggle the radio, which cannot fix this.
        $dangling = 0
        try { if ($null -ne $integ.DanglingSymlinkCount) { $dangling = [int]$integ.DanglingSymlinkCount } } catch { }
        if ($dangling -gt 0) {
            [void]$findings.Add("[!] $dangling Bluetooth COM symlink(s) point at a device object that is no longer registered. Opens against them time out (ERROR_SEM_TIMEOUT) and look like a headset that is not answering -- it is not, the serial stack is stale. FIX: reboot. A radio toggle will NOT clear this.")
        }

        # The causal claim, carried as a number. 'Unexplained' is the interesting
        # one: it means resumes do not account for the extra registrations on
        # this box and the FI-012 story is incomplete for it.
        $corr = $null
        try { $corr = $integ.Correlation } catch { }
        if ($corr -and $corr.Assessment -eq 'Unexplained') {
            [void]$findings.Add("[!] $($corr.Summary). Worth capturing: FI-012 assumes sleep/resume is the trigger, and this box contradicts that.")
        } elseif ($corr -and $corr.Assessment -eq 'Consistent') {
            [void]$findings.Add("[i] $($corr.Summary)")
        }

        # Degraded mid-session: the recorder's unique contribution. A single
        # sample cannot tell you whether the box arrived broken or broke while
        # you watched; this can, and it pins the trigger to this session.
        if ($integStart -and $integEnd -and $integStart.Healthy -and -not $integEnd.Healthy) {
            [void]$findings.Add("[!] Bluetooth serial port registrations DEGRADED during this session: healthy at start, $($integEnd.CollisionCount) collision(s) / $($integEnd.MissingSymlinkCount) absent symlink(s) at end. Whatever happened in this recording is what corrupts them -- check the session log for sleep/resume or a re-pair.")
        }
    }

    # ── FI-014: pairing record vs device node, for the target ─────────────────
    # Above the FI-012 material for the same reason the integrity check is:
    # if the headset has no device node there is no COM port to reason about,
    # and every finding below it is downstream noise.
    $prStart = $Session.PairingRecord
    $prEnd   = $Session.PairingRecordEnd
    $pr      = if ($prEnd) { $prEnd } else { $prStart }

    if ($pr) {
        if ($prStart -and $prEnd -and $prStart.TargetState -eq 'Paired' -and $prEnd.TargetState -eq 'Orphan') {
            [void]$findings.Add("[!] The headset LOST its device node during this recording: it had one when recording began and only a BTHPORT registry record at the end. Something removed the device while you watched -- a removal in NO.exe's device panel and one in Windows Settings both do this. That is the trigger, and this capture contains it.")
        } elseif ($pr.TargetState -eq 'Orphan') {
            foreach ($f in @($pr.Findings)) { [void]$findings.Add("[!] $f") }
            if ($pr.Recommendation) { [void]$findings.Add("[!] $($pr.Recommendation)") }
        } elseif ($pr.TargetState -eq 'Sighting') {
            [void]$findings.Add("[!] This box has only ever SEEN the target headset in a scan, never paired with it. There is a registry record, but it is a sighting -- no pairing was ever completed. Pair it through Windows Settings.")
        } elseif ($pr.TargetState -eq 'NoRecord') {
            [void]$findings.Add("[i] No BTHPORT pairing record for the target headset at all -- this box has no memory of it. Nothing to clean up; it simply needs pairing.")
        } elseif ($pr.Scoped -and $pr.TargetState -eq 'Paired') {
            [void]$findings.Add("[ok] The target headset has both a BTHPORT pairing record and a live device node -- no FI-014 residue for this device")
        }

        # An unscoped verdict is Healthy by construction. Saying nothing here
        # would let "we could not identify the target" read as "the target is
        # fine", which is the same silent-pass shape the read-rate NoBaseline
        # branch exists to prevent.
        if (-not $pr.Scoped) {
            [void]$findings.Add("[info] The headset could not be identified on this box (no device node and no pairing record matching it), so the pairing-record check ran unscoped and reports an inventory only -- it did NOT assess any specific device. A never-paired headset lands here: Windows stores no name for a device it has merely seen, so only its MAC address could scope the check.")
        }
        if ($pr.ResidueCount -gt 0) {
            [void]$findings.Add("[i] $($pr.ResidueCount) other Bluetooth device(s) on this box have a pairing record with no device node. That is the ordinary residue of removing a device and needs no action.")
        }
    }

    # ── Discovery: can this box hear the headset at all? ──────────────────────
    $inq = $Session.InquiryScan
    if ($inq -and $inq.Collected -and $inq.Result) {
        if ([int]$inq.Result.Count -gt 0) {
            [void]$findings.Add("[ok] A discovery scan heard $($inq.Result.Count) unpaired device(s), so this box's radio can discover devices -- the headset can be paired from here")
        } else {
            [void]$findings.Add("[~] A discovery scan heard NOTHING. INCONCLUSIVE on its own: an Arc that has idled itself off answers no inquiry at all. Power-cycle the headset and scan again before treating this as a discovery fault.")
        }
    } elseif ($inq -and $inq.Reason) {
        [void]$findings.Add("[info] Discovery scan not run. $($inq.Reason)")
    }

    # ── FI-012 fault 2, without opening a port ────────────────────────────────
    # Test-BluetoothSerialPortOpen is the only thing that can CONFIRM fault 2 and
    # it must never run here -- an open during a live client session can steal
    # the port from NO.exe and manufacture the very error being diagnosed. So the
    # recorder reports the fingerprint instead, explicitly as unconfirmed.
    # Populated by the caller; absent on older sessions and when the radio or
    # device state could not be read.
    # NoActiveLink is reported as [i], not [!]: a healthy idle Arc reads
    # disconnected too, so raising it as a problem would cry wolf on every box
    # whose device happens to be off. RadioOff IS actionable and is a [!].
    $fp = $Session.SerialFaultFingerprint
    if ($fp -and $fp.Fault -eq 'RadioOff') {
        [void]$findings.Add("[!] $($fp.Summary) NEXT: $($fp.Action)")
    } elseif ($fp -and $fp.Fault -eq 'NoActiveLink') {
        [void]$findings.Add("[i] $($fp.Summary) NEXT: $($fp.Action)")
    }

    # ── Arrival-state contradictions ──────────────────────────────────────────
    # Carried from the startup snapshot, because a box that was ALREADY in a bad
    # combination when Record was pressed generates no transitions and would
    # otherwise reach the uploaded record with nothing said about it.
    foreach ($c in @($Session.StartupConsistency)) {
        if ($c -and $c.Text) { [void]$findings.Add("$($c.Text) (state on arrival, before recording began)") }
    }

    # ── Port held with no data flowing ────────────────────────────────────────
    # The finding the recorder previously could not produce: it reported "EEG
    # streaming: Active" for any held handle, so a stalled Arc looked healthy.
    if ($Session.StreamCpuStalled) {
        $portStr = if ($Session.ActiveStreamPort) { $Session.ActiveStreamPort } else { 'the headset COM port' }
        [void]$findings.Add("[!] Port held without data flow: NO.exe kept $portStr open while its CPU stayed flat, which a live EEG session does not do. The handle being open is NOT evidence of streaming -- this is the state that shows 'Arc not detected' on screen while the headset's own light suggests it is transmitting.")
    }

    # ── Read-rate collapse ────────────────────────────────────────────────────
    # The signal for the fault CPU cannot see: the application stays busy while
    # only its serial path dies. Reported with the measured numbers because it is
    # a process-wide counter -- nothing here attributes a read to the COM port.
    # Session-long, not last-tick. IoStalled answers "was it collapsing when the
    # recording ended", which a port re-open silently turns into "no". See
    # Get-IoSessionReadRateRecord.
    $ioRecord = Get-IoSessionReadRateRecord -Session $Session
    if ($Session.IoStalled -or $ioRecord.EverCollapsed) {
        # Do NOT name a single port when several are held. The counter is
        # process-wide, so with COM3 and COM6 both open (the Arc's normal
        # two-channel shape) picking ActiveStreamPort asserts an attribution the
        # measurement cannot support -- capture C2FB1FD51A35 reported "on COM6"
        # on exactly that evidence.
        $heldNow = @($Session.HeldPorts | Where-Object { $_ })
        $portStr = if ($heldNow.Count -gt 1) {
            "$($heldNow -join ' / ') (held together; the counter cannot say which)"
        } elseif ($Session.ActiveStreamPort) { $Session.ActiveStreamPort }
        elseif ($heldNow.Count -eq 1) { $heldNow[0] }
        else { 'the headset COM port' }
        $linkNote = if ($Session.BtLinkState -eq 'Connected') {
            " The Bluetooth link was UP at the same time, so this is not a transport failure -- either the headset stopped transmitting while its baseband link stayed alive, or NeurOptimal's read path stalled."
        } else { '' }
        # Numbers come from the session record, so they survive a port re-open.
        # Reading them off the live fields printed "~0 to ~0" on exactly the
        # captures where the collapse had already been erased.
        $fromOps = if ($Session.IoStalled) { [int]$Session.IoBaselineOpsPerTick } else { [int]$ioRecord.PeakBaselineOpsPerTick }
        $toOps   = if ($Session.IoStalled) { [int]$Session.IoRecentOpsPerTick } else { [int]$ioRecord.WorstRecentOpsPerTick }
        # The live baseline erodes with the recording window: on capture
        # 31D0729CA5B8 a 15.4 h idle tail dragged it to 0, and this sentence read
        # "went from ~0 to ~0 read operations per tick" -- a 0-to-0 collapse. The
        # record's peak now honours the announcement latch, so it holds the rate
        # this run actually established. Never report a from-rate below it.
        if ([int]$ioRecord.PeakBaselineOpsPerTick -gt $fromOps) {
            $fromOps = [int]$ioRecord.PeakBaselineOpsPerTick
        }
        # A collapse that is over by the end of the recording is still a
        # collapse. Saying so explicitly, because the live verdict now reads
        # clean and a reader comparing the two needs to know which is which.
        #
        # But the CAUSE must be evidenced. This sentence used to assert "the port
        # was re-opened" from nothing but `-not IoStalled`, which is true of any
        # run whose live measurement was lost -- including the #63 erosion shape,
        # where BaselineResetCount is 0 and no re-open ever happened. Inventing a
        # mechanism is worse than naming none: a reader chasing a re-open that did
        # not occur is being sent somewhere by the tool.
        $endedNote =
            if ($Session.IoStalled) { '' }
            elseif ($ioRecord.BaselineResetCount -gt 0) {
                " The port was re-opened after this, which restarted the read-rate measurement -- so the recording ENDS looking clean and the collapse is only visible in this record. Re-opening is NOT evidence the underlying problem was fixed."
            }
            elseif ($ioRecord.EverCollapsed) {
                " The live read-rate measurement was lost before the recording ended, so the recording ENDS looking clean and the collapse is only visible in this record. That is NOT evidence the underlying problem went away -- and the record does not say what ended the measurement."
            }
            else { '' }
        $epNote = if ($ioRecord.CollapseEpisodes -gt 1) { " This happened in $($ioRecord.CollapseEpisodes) separate episodes." } else { '' }
        [void]$findings.Add("[!] Read rate collapsed while the port stayed open: NO.exe went from ~$fromOps to ~$toOps read operations per tick on $portStr.$linkNote$endedNote$epNote Note this counter is process-wide, so it shows the application stopped doing the I/O it had been doing, not specifically that the port went quiet.")
    } elseif ($Session.IoVerdict -eq 'NoBaseline' -and $Session.StreamingState -eq 'Active') {
        # Explicitly NOT a clean bill of health. Saying nothing here would let an
        # unmeasurable session read as a measured-healthy one.
        #
        # Zero is called out separately from merely-low because the two mean
        # different things. Measured on the dev box 2026-07-30: an idle NO.exe
        # reports exactly 0 read operations per tick while its CPU keeps
        # climbing. If that stays 0 through a session that IS streaming, the
        # reads are not being issued by NO.exe at all -- NO 4.x does its serial
        # I/O through NI-VISA, and if VISA proxies the port through its own
        # service process the counters land there instead. That would mean this
        # detector is watching the wrong process, which is a fixable thing to
        # know and an invisible one if the summary just stays quiet.
        # BaselineResetCount ONLY -- deliberately not "a peak baseline exists".
        # Test-IoReadCollapse reports a rate even when it is below the floor
        # needed to baseline, so a sub-floor reading makes PeakBaselineOpsPerTick
        # nonzero without any baseline ever having been established, let alone
        # discarded. The counter increments only when a real baseline was thrown
        # away, which is exactly the claim being made here.
        if ($ioRecord.BaselineResetCount -gt 0) {
            # 'NoBaseline' here means the baseline was THROWN AWAY by a port
            # re-open, not that none was ever found. Claiming no read activity
            # was visible would be flatly contradicted by the record.
            [void]$findings.Add("[i] Read-rate monitoring restarted $($ioRecord.BaselineResetCount) time(s) during this recording because the COM port was re-opened, and the last episode had not re-established a baseline when the recording ended. Data flow WAS measured earlier (peak ~$($ioRecord.PeakBaselineOpsPerTick) read operations per tick). The end-of-session read-rate figures describe only the final episode -- do not read them as the whole session.")
        } elseif ([int]$Session.IoBaselineOpsPerTick -eq 0) {
            [void]$findings.Add("[info] No read activity was visible on NO.exe at all this session, so data flow was NOT assessed. If the headset WAS streaming during this recording, the reads are not being issued by the NO.exe process -- on 4.x the serial I/O goes through NI-VISA, which may issue them from its own service process. Worth checking before trusting any read-rate result from this box.")
        } else {
            [void]$findings.Add("[info] Read-rate monitoring could not establish a baseline for NO.exe this session (observed ~$($Session.IoBaselineOpsPerTick) read operations per tick, below the floor needed to call a collapse). Data flow was NOT assessed -- the absence of a read-collapse finding means nothing was measured, not that nothing was wrong.")
        }
    } elseif ($Session.IoVerdict -eq 'Degrading' -and $Session.StreamingState -eq 'Active') {
        # The recording ended mid-decay WITH THE PORT STILL HELD. That last
        # condition is the whole safety argument: a normal session stop also
        # ends on a falling read rate, but it RELEASES the port on the way out,
        # so it lands on 'Stopped' and never reaches this branch. Held-and-
        # falling is the fault shape; released-and-falling is a clinic finishing
        # a session. Without the gate every stop in the field would warn.
        [void]$findings.Add("[!] NO.exe's read rate was FALLING when the recording ended, with the port still open: ~$($Session.IoRecentOpsPerTick) read operations per tick against the ~$($Session.IoBaselineOpsPerTick) this session established for itself$(if ($null -ne $Session.IoFractionOfBaseline) { " ($($Session.IoFractionOfBaseline)% of normal)" }). It had not stayed down long enough to call a collapse, so this is a stall caught in progress. Record for longer if this repeats -- a few more seconds would have settled it.")
    } elseif ([int]$Session.IoDegradedTicks -gt $script:IoCollapseTicks) {
        # Dips that recovered. An intermittent dropout looks exactly like this
        # and used to summarise as a clean "[ok] held steady".
        #
        # The threshold is deliberately ABOVE IoCollapseTicks: the tail of a
        # normal session stop can contribute up to three degraded ticks in the
        # gap before the port is released, so anything at or below that budget
        # would fire on routine stops.
        # "Recovering each time" is only true if the measurement ran continuously.
        # A port re-open resets it, which looks identical to a recovery and is not
        # one, so the claim is dropped when a reset could explain it.
        $recoveryClaim = if ($ioRecord.BaselineResetCount -gt 0) {
            "The read-rate measurement also restarted $($ioRecord.BaselineResetCount) time(s) when the port was re-opened, so these dips cannot be assumed to have recovered on their own"
        } else {
            'recovering each time'
        }
        [void]$findings.Add("[~] NO.exe's read rate dipped below a quarter of its own baseline on $($Session.IoDegradedTicks) tick(s) during this recording, $recoveryClaim (worst point ~$($ioRecord.WorstFractionOfBaseline)% of normal). No single dip lasted long enough to call a collapse, but a healthy stream does not do this -- suspect an intermittent link or an Arc dropping out briefly.")
    } elseif ($ioRecord.Outcome -eq 'Stable') {
        # Was `$Session.IoVerdict -eq 'Streaming'` -- the LAST tick's verdict.
        # Capture 91C5F8EB3E3F: 33 minutes, a 446 ops/tick baseline held across
        # 667 ticks, nothing degraded beyond one teardown tick -- and because the
        # terminal verdict landed on 'Degrading' rather than 'Streaming' it
        # matched no arm of this chain at all and the capture said NOTHING about
        # data flow. Silence is the one thing a diagnostic must never emit about
        # a measurement it successfully took: a reader fills it in with "fine",
        # which is right by luck here and would be wrong the next time.
        #
        # Baseline reported from the session record, not the terminal field, so
        # a port re-open cannot zero the number in the sentence.
        $steadyOps = if ($ioRecord.PeakBaselineOpsPerTick -gt 0) { $ioRecord.PeakBaselineOpsPerTick } else { $Session.IoBaselineOpsPerTick }
        $steadyNote = if ($Session.IoDegradedTicks -gt 0) {
            " (one brief dip, within the allowance a normal session stop accounts for)"
        } else { '' }
        [void]$findings.Add("[ok] NO.exe read rate held steady at ~$steadyOps read operations per tick while the port was open$steadyNote -- consistent with data actually flowing")
    } elseif (@($Session.IoReadOpDeltas).Count -eq 0) {
        # THE SILENT CASE. Every branch above is gated, directly or indirectly,
        # on the target's port having been held: read sampling only runs while
        # StreamingState is 'Active'. So a recording where that never happened
        # said NOTHING AT ALL about data flow -- the guard against unmeasured
        # sessions was itself behind the condition that fails. Capture
        # 8E39860E4AF2 ran 37 minutes and its 13 findings did not contain one
        # word about whether data was flowing.
        #
        # An absent measurement must be visible as an absent measurement, never
        # as silence a reader will fill in with "fine".
        $whyNot = if (-not $Session.BtLinkEverConnected) {
            "the headset never linked to the radio, so its port was never held and there was nothing to sample"
        } else {
            "the target's COM port was never held by any process, and read sampling only runs while it is"
        }
        [void]$findings.Add("[info] Data flow was NOT assessed in this recording: $whyNot. This is not a clean result -- nothing was measured. If NeurOptimal was running a session during this recording, it was not using the headset this recording watched.")
    }

    # ── The idle tail ─────────────────────────────────────────────────────────
    # A recording left running long after the session ends does not simply add
    # harmless empty ticks: the read-rate baseline is the MEDIAN of the samples
    # before the trailing window, so idle zeros drag it down until the run's own
    # baseline falls under the floor and the live episode is discarded as
    # 'NoBaseline'. Capture 31D0729CA5B8 ran 15.9 h for a 33-minute session and
    # ended reporting no baseline at all, having announced 436 ops/tick.
    #
    # This must be stated, not left for a reader to work out from timestamps.
    # It is the difference between "this capture cannot answer the question" and
    # "the answer is no".
    if ($ioRecord.BaselineLostAfterAnnouncement) {
        $tailNote = if ($null -ne $ioRecord.IdleTailSeconds) {
            " The recording continued for $([int]($ioRecord.IdleTailSeconds / 60)) minute(s) after the last read activity"
        } else { ' The recording continued after read activity stopped' }
        # What is unassessed is the interval AFTER the measurement was lost --
        # never a collapse that was already confirmed. The first version of this
        # finding said "this capture CANNOT say whether reads collapsed"
        # unconditionally, so on the 31D0729CA5B8 shape it contradicted its own
        # record (EverCollapsed true, Outcome 'Collapsed') in the same summary.
        # That is precisely the channel-mismatch class this work exists to close,
        # reintroduced one layer out in prose.
        if ($ioRecord.EverCollapsed) {
            [void]$findings.Add("[!] This recording MEASURED data flow -- a baseline of ~$($ioRecord.AnnouncedBaselineOpsPerTick) read operations per tick was established -- and CONFIRMED at least one read collapse, and then lost the measurement before the recording ended.$tailNote, and idle ticks drag the baseline down until it falls under the floor needed to detect a collapse. The confirmed collapse STANDS. What this capture cannot say is what the read rate did after the measurement was lost -- read that interval as 'not assessed'. Stop the recorder when the session stops.")
        } else {
            [void]$findings.Add("[!] This recording MEASURED data flow -- a baseline of ~$($ioRecord.AnnouncedBaselineOpsPerTick) read operations per tick was established -- and then lost the measurement before the recording ended.$tailNote, and idle ticks drag the baseline down until it falls under the floor needed to detect a collapse. So this capture CANNOT say whether reads collapsed during the session: read its collapse fields as 'not assessed', not as 'nothing went wrong'. Stop the recorder when the session stops.")
        }
    } elseif ($null -ne $ioRecord.IdleTailSeconds -and $ioRecord.IdleTailSeconds -ge $script:IoIdleTailWarnSeconds) {
        [void]$findings.Add("[~] The recording ran for $([int]($ioRecord.IdleTailSeconds / 60)) minute(s) after the last read activity. The measurement survived it this time, but an idle tail erodes the read-rate baseline and long enough of one destroys it -- stop the recorder when the session stops.")
    }

    # ── Operator-marked moments ───────────────────────────────────────────────
    # These go near the top of the findings on purpose: an operator marker is the
    # only place in the record where the APPLICATION's own verdict appears. It
    # outranks anything the probe inferred, because the probe cannot see NO's
    # dialogs at all.
    $markers = @($Session.OperatorMarkers)
    foreach ($mk in $markers) {
        if (-not $mk) { continue }
        $line = Format-ProbeStateMarker -Marker $mk
        $contra = @($mk.Contradictions)
        if ($contra.Count -gt 0) {
            [void]$findings.Add("[!] $line. Cross-check at that moment: $($contra -join ' ')")
        } elseif ($mk.IoVerdict -eq 'NoBaseline') {
            # "No contradiction" is a much weaker statement when the read rate
            # was never measurable: the one layer most likely to hold the answer
            # was not being watched. Saying "originates above Bluetooth" here
            # would dress an unmeasured moment up as a localised one.
            [void]$findings.Add("[!] $line. Nothing in the Bluetooth layer contradicted itself at that moment -- but the read rate was not being measured either, so this marker cannot localise the fault. Treat it as unclassified, not as clean.")
        } else {
            # No contradiction found does NOT mean nothing was wrong -- it means
            # the fault is above anything the probe measures. Say so, because
            # this is exactly the case the code mapping needs to hear about.
            [void]$findings.Add("[!] $line. The probe found no contradiction in the Bluetooth layer at that moment, and reads were still flowing normally, so whatever NeurOptimal was reporting originates above both -- capture this one.")
        }
    }
    if ($markers.Count -eq 0) {
        [void]$findings.Add('[info] No operator markers in this recording. If NeurOptimal showed an error during it, the record cannot say which machine state produced it.')
    }

    # Ports that exist but refuse to open, seen at any point in the session.
    #
    # Same narrowing as the arrival cross-check, and for the same reason: a
    # switched-off headset produces this exact symptom, and calling it a fault
    # is how capture 8E39860E4AF2 failed a session that had gone perfectly.
    # FAIL survives only with corroboration -- an OS-level integrity fault, or a
    # target that WAS working in this recording and then went unavailable.
    $deadPorts = @($Session.UnavailablePorts | Where-Object { $_ })
    if ($deadPorts.Count -gt 0) {
        $integForDead = if ($Session.SerialPortIntegrityEnd) { $Session.SerialPortIntegrityEnd } else { $Session.SerialPortIntegrity }
        $integBad     = [bool]($integForDead -and -not $integForDead.Healthy)
        if ($integBad -or $Session.PortEverHeld) {
            $why = if ($integBad) {
                'The serial port integrity check independently reports an OS-level fault, so this is not simply a device that was switched off.'
            } else {
                'This headset was reachable earlier in the same recording and then stopped opening, which being switched off does not explain.'
            }
            [void]$findings.Add("[!] $($deadPorts -join ', ') registered as a Bluetooth serial port but would not open during this session. $why No process can reach the headset through it. Cause not classified here (an absent symlink and a stale one need different fixes) -- run the serial port integrity check with NO.exe closed.")
        } elseif (-not $Session.BtLinkEverConnected) {
            [void]$findings.Add("[i] $($deadPorts -join ', ') registered as a Bluetooth serial port and never opened during this session, and the headset never linked to the radio either. The likeliest explanation by far is that it was switched off or out of range for the whole recording -- a port with nothing behind it times out exactly like a broken one, and FI-012 records that the two cannot be told apart from the error alone. This is NOT evidence of a fault. Power the headset on, confirm it connects, then run the serial port integrity check with NO.exe closed if you want it classified.")
        } else {
            [void]$findings.Add("[~] $($deadPorts -join ', ') registered as a Bluetooth serial port but would not open during this session, although the headset did link to the radio at some point. Worth capturing, but not classified: the probe cannot tell an absent symlink from a stale one. Run the serial port integrity check with NO.exe closed.")
        }
    }

    # Which SPP channel each port is. Two ports for one MAC is the Arc's normal
    # shape, and the recorder used to report exactly that as an unresolved
    # ambiguity on every healthy capture -- a permanent flag teaches readers to
    # skip the field. Roles come from two sources that must agree, so a label
    # here is never a guess.
    $roleRows = @($WatchState.ComPortMatches | Where-Object { $_.PortName -and $_.ChannelRole })
    if ($WatchState.ComPortRoleConflict) {
        [void]$findings.Add("[!] COM port channel roles CONFLICT: the name the device reports for a channel and the RFCOMM channel number disagree about which port is DATA and which is COMMAND. FI-012 records channel-to-role as invariant, so this capture contradicts it -- do not act on a role label from this machine, and treat the invariant as unproven here.")
    } elseif ($roleRows.Count -gt 0) {
        $roleText = ($roleRows | ForEach-Object { "$($_.PortName) = $($_.ChannelRole.ToUpperInvariant())" }) -join ', '
        $srcNote = if (@($roleRows | Where-Object { $_.ChannelRoleSource -eq 'both' }).Count -eq $roleRows.Count) {
            'device-reported name and RFCOMM channel number agree'
        } else {
            'from a single source -- the other was unavailable'
        }
        [void]$findings.Add("[ok] COM port channel roles: $roleText ($srcNote). The COM NUMBER is not an identity and moves on every re-pair; the channel role does not.")
    }

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
        OperatorMarkers = @($Session.OperatorMarkers)
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

function Get-ProbeRecordingWindow {
    <#
    .SYNOPSIS
        Pure. THE single answer to "how long did this recording run?", and the
        join guard that catches anything stamped outside that window.
    .DESCRIPTION
        Field bug, capture 236061907514 (2026-08-10, issue #78). The manifest
        reported RecordingDurationSeconds 69 for a run carrying operator markers
        at ElapsedSeconds 86 and 107, with a read-rate episode ending ~134 s in.
        The run was roughly TWICE its reported length.

        Two clocks were answering one question:

          the operator marker and the on-screen "Recording mm:ss" label counted
          from the moment Record was pressed;
          the manifest counted FirstTickAt..LastTickAt -- the TICK span.

        Those differ by however long the loop took to reach its first tick plus
        however long it ran past its last one. On a healthy run that is a couple
        of seconds and nobody notices. On the capture above the first tick landed
        11.85 s in and the loop was starved (MeanIntervalMs 3750 against a 3000
        target, 18 of 22 deadlines missed), so the gap was ~65 s.

        This is the channel-mismatch class, so it is fixed the way that class has
        to be fixed: the second answerer is REMOVED, not reconciled. The
        authoritative clock is the one the operator and the markers already use,
        because a marker is the whole point of the artifact -- it binds an
        on-screen NeurOptimal error to a machine state, and a timeline the
        markers fall outside of is not a timeline.

        NO FALLBACK TO THE TICK SPAN. If the recording window was never set, this
        reports DurationSeconds $null and says so in a finding. Substituting the
        tick span would re-create the very second answerer this removes, and a
        wrong duration is worse than an absent one: 69/22 reads as a healthy
        3.14 s cadence, which is exactly how an 82 %-missed-deadline run passed
        for normal. TickSpanSeconds is still reported, under a name that says
        what it is.

        WHY THE GUARD LIVES HERE. Per the channel-mismatch pattern, the assertion
        belongs where the channels are JOINED, not inside each detector -- a
        detector handed its own fixture input will always agree with itself. The
        markers, the episode ledger and the duration only ever meet here.
    .PARAMETER Session
        The probe session (RecordingStartedAt, RecordingStoppedAt, FirstTickAt,
        LastTickAt, OperatorMarkers, IoClosedEpisodes).
    .OUTPUTS
        [pscustomobject] StartedAt, StoppedAt, DurationSeconds, TickSpanSeconds,
        Consistent, Findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session
    )

    $startedAt = $Session.RecordingStartedAt
    $stoppedAt = $Session.RecordingStoppedAt

    $durationSeconds = if ($startedAt -and $stoppedAt) {
        [int][math]::Round([math]::Max(0, (([datetime]$stoppedAt) - ([datetime]$startedAt)).TotalSeconds))
    } else { $null }

    # Kept, and deliberately NOT used as a duration. The tick span is a real
    # measurement of a different thing: how long the sampling loop was alive.
    $tickSpanSeconds = if ($Session.FirstTickAt -and $Session.LastTickAt) {
        [int][math]::Round([math]::Max(0, (([datetime]$Session.LastTickAt) - ([datetime]$Session.FirstTickAt)).TotalSeconds))
    } else { $null }

    $findings = @()

    if ($null -eq $durationSeconds) {
        # Absent renders as absent. The alternative -- quietly reporting the tick
        # span -- is the defect.
        $findings += '[~] The recording window was never stamped, so this capture cannot say how long it ran. Tick span is reported separately and is NOT the same measurement.'
    }

    # ── The join: nothing may be stamped outside the window it belongs to ─────
    if ($null -ne $durationSeconds) {
        # A marker's ElapsedSeconds counts from the same origin the duration now
        # does, so this comparison is apples to apples by construction. One
        # second of slack absorbs the truncation in [int]$elapsed.TotalSeconds.
        $lateMarkers = @($Session.OperatorMarkers | Where-Object {
            $_ -and $null -ne $_.ElapsedSeconds -and ([int]$_.ElapsedSeconds) -gt ($durationSeconds + 1)
        })
        foreach ($mk in $lateMarkers) {
            $findings += "[!] An operator marker is stamped $([int]$mk.ElapsedSeconds)s into a recording reported as $($durationSeconds)s long. The marker clock and the duration clock have diverged, so this capture's timeline cannot be trusted (issue #78)."
        }

        if ($startedAt -and $stoppedAt) {
            $windowStart = ([datetime]$startedAt).AddSeconds(-1)
            $windowEnd   = ([datetime]$stoppedAt).AddSeconds(1)
            # CLOSED episodes only. The in-flight episode is stamped by
            # New-IoEpisodeRecord with (Get-Date) at summary time, which is
            # legitimately a moment after the window closed -- checking it would
            # manufacture a divergence finding on every clean run.
            foreach ($ep in @($Session.IoClosedEpisodes)) {
                if (-not $ep -or -not $ep.EndedAtIso) { continue }
                $endedAt = $null
                # A malformed stamp is not evidence of a divergence, so it is
                # skipped rather than reported as one.
                try { $endedAt = [datetime]::Parse($ep.EndedAtIso, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { continue }
                if ($endedAt -lt $windowStart -or $endedAt -gt $windowEnd) {
                    $findings += "[!] A read-rate episode ended at $($ep.EndedAtIso), outside the recording window. The episode ledger and the duration clock have diverged, so this capture's timeline cannot be trusted (issue #78)."
                }
            }
        }
    }

    return [pscustomobject]@{
        PSTypeName      = 'WinConfig.FlightRecorder.RecordingWindow'
        StartedAt       = $startedAt
        StoppedAt       = $stoppedAt
        DurationSeconds = $durationSeconds
        # How long the SAMPLING LOOP was alive, which is shorter than the
        # recording by the time to first tick plus the time after the last one.
        # Published so the gap is visible rather than inferred.
        TickSpanSeconds = $tickSpanSeconds
        Consistent      = ($findings.Count -eq 0)
        Findings        = @($findings)
    }
}

function Get-ProbeObservationCoverage {
    <#
    .SYNOPSIS
        Pure. Says how much of the session this recording actually observed.
    .DESCRIPTION
        Field bug (capture 8E39860E4AF2): a clean 37-minute session on Arc
        000013 was recorded against Arc 000019, which sat powered off in a
        drawer. Every finding was true of 019; none was about the session. The
        capture reported "2 problems" and "did NOT end clean" -- confidently
        wrong, in a way indistinguishable from a real fault.

        "This session had problems" and "this recording never saw your session"
        are different claims, and nothing in the record could express the
        second. That is what this adds: coverage is a first-class, structured
        property of a capture, not an inference a reader makes from silence.

          Observed      the target linked, its port was held, and reads were
                        sampled -- the record can speak to the session
          Partial       some evidence, not all. Findings stand, but the record
                        is thinner than it looks
          NotObserved   no link, no held port, no reads. The record says
                        NOTHING about the session that ran, whatever findings
                        it happens to contain about the device it watched

        NotObserved is strengthened, not created, by a rival candidate: two
        Arcs paired and the watched one silent is the signature of watching the
        wrong device. But a single powered-off Arc is equally NotObserved --
        coverage is about what was measured, never about blame.
    .PARAMETER Session
        The probe session (BtLinkEverConnected, PortEverHeld, IoReadOpDeltas).
    .PARAMETER WatchState
        The target watch state (FirstComPortSeenTime).
    .PARAMETER Target
        Optional Select-BluetoothSessionTarget result, for rival-candidate
        evidence.
    .OUTPUTS
        [pscustomobject] Level, Reasons, Summary, DataFlowMeasured and the raw
        evidence booleans.

        Level and DataFlowMeasured are DIFFERENT claims and both are needed.
        Level is categorical -- were all the channels seen -- and is not
        weakened by duration or usability. DataFlowMeasured says whether there
        was a measured window to speak about. A capture can legitimately be
        Observed with DataFlowMeasured false: every channel was seen, and none
        of them was measured.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        $WatchState,
        $Target
    )

    $linked     = [bool]$Session.BtLinkEverConnected
    # Sourced from the port-hold latch, NOT from a stream classification. The
    # field is named TargetPortEverHeld and the operator sentence below asserts a
    # port hold, so anything else here is name/source drift (issue #67).
    $heldPort   = [bool]$Session.PortEverHeld
    $ioSamples  = @($Session.IoReadOpDeltas).Count
    $sawPort    = if ($WatchState) { [bool]$WatchState.FirstComPortSeenTime } else { $false }

    # A rival is any OTHER candidate the selector saw. Activity on the rival is
    # the strongest single indicator that the recording is pointed at the wrong
    # headset, so it is tracked separately from mere presence.
    $rivals = @()
    $rivalActive = $false
    if ($Target -and $Target.Candidates) {
        $rivals = @($Target.Candidates | Where-Object { $_ -and $_.Mac -and $_.Mac -ne $Target.Mac })
        $rivalActive = @($rivals | Where-Object { @($_.HeldPorts).Count -gt 0 }).Count -gt 0
    }

    $reasons = @()
    if (-not $linked)        { $reasons += 'The target headset never linked to the radio during this recording.' }
    if (-not $heldPort)      { $reasons += 'No process ever held the target headset''s COM port during this recording.' }
    if ($ioSamples -eq 0)    { $reasons += 'No read-rate samples were taken, so data flow was never measured.' }
    if ($rivalActive)        { $reasons += "Another paired NeurOptimal headset WAS holding a COM port while this one was idle -- this recording is very likely pointed at the wrong headset." }
    elseif ($rivals.Count -gt 0) { $reasons += "$($rivals.Count) other NeurOptimal headset(s) are paired on this box, so the recording may have watched the wrong one." }

    $level =
        if (-not $linked -and -not $heldPort -and $ioSamples -eq 0) { 'NotObserved' }
        elseif ($linked -and $heldPort -and $ioSamples -gt 0)       { 'Observed' }
        else                                                        { 'Partial' }

    # ── Observation QUALITY: a separate axis from Level ──────────────────────
    # Level answers "did we see all the channels?". It is categorical and it is
    # NOT weakened here -- a capture that linked, held the port and measured data
    # flow is Observed however briefly it ran, because every channel was seen.
    #
    # Quality answers a different question: "for how long?". Two field captures
    # of the same headset both scored Observed and are not remotely the same
    # evidence:
    #   B9F9F0EE5E21  ~17 SECONDS of measurement after the baseline landed, on a
    #                 baseline taken mid-ramp (trailing rate 152% of it).
    #   91C5F8EB3E3F  ~32 MINUTES after the baseline, steady throughout.
    # Collapsing that into one word is how a 17-second glance gets weighed as a
    # clean run.
    #
    # Pure: every figure comes off the session, no clock is read here.
    $firstTick = $Session.FirstTickAt
    $lastTick  = $Session.LastTickAt
    $baselineAt = $Session.IoBaselineAnnouncedAt

    $observationSeconds = if ($firstTick -and $lastTick) {
        [int]([math]::Max(0, ($lastTick - $firstTick).TotalSeconds))
    } else { $null }
    $secondsToBaseline = if ($firstTick -and $baselineAt) {
        [int]([math]::Max(0, ($baselineAt - $firstTick).TotalSeconds))
    } else { $null }
    $postBaselineSeconds = if ($baselineAt -and $lastTick) {
        [int]([math]::Max(0, ($lastTick - $baselineAt).TotalSeconds))
    } else { $null }

    # The threshold is a FLOOR for "worth weighing", never a guarantee. In this
    # investigation the read collapse fired 7 and 14.5 minutes into a recording,
    # so even a Sustained capture that ends clean has to be repeated before a
    # clean result means anything. Consumers that want a different bar have the
    # raw seconds; this label is convenience, not the evidence.
    $quality =
        if ($null -eq $postBaselineSeconds)                          { 'None' }
        elseif ($postBaselineSeconds -ge $script:CoverageSustainedSeconds) { 'Sustained' }
        else                                                          { 'Brief' }

    $qualitySummary = switch ($quality) {
        'Sustained' {
            "Data flow was measured for $([int]($postBaselineSeconds / 60)) minute(s) after the read baseline was established. That is long enough for this capture to carry weight -- though a clean result still wants repeating, because the collapses on record took 7 and 14.5 minutes to appear."
        }
        'Brief' {
            "Data flow was measured for only $postBaselineSeconds second(s) after the read baseline was established. Every channel was seen, so this capture is not invalid -- but it is a glance, not a watch, and 'nothing went wrong' over this window is very weak evidence."
        }
        default {
            'No read baseline was ever established, so there is no measured window to size.'
        }
    }

    # ── Was data flow actually MEASURED? (issue #77) ─────────────────────────
    # Samples COLLECTED is not the same claim as data flow MEASURED, and the
    # operator sentence below used to conflate them. On capture 236061907514 the
    # Summary read "...and data flow was measured" while QualitySummary in the
    # same object read "No read baseline was ever established" and the findings
    # said data flow was NOT assessed. Three renderings of one run, two of them
    # true. #68 item 1: never assert something the same record contradicts.
    #
    # This is derived from $postBaselineSeconds -- the SAME value QualitySummary
    # is built from -- and not re-derived from the session. That is deliberate:
    # it makes "Summary claims measurement while Quality is None" unrepresentable
    # rather than merely untested, which is what guarding at the join means when
    # the join is inside one function.
    #
    # ⚠️ NOT the same claim as ReadRateRecord.BaselineEstablished, and it must
    # not be "corrected" into it. That field asks "did any channel ever hold a
    # baseline", including an episode-ledger baseline that was never announced.
    # This asks the narrower question the operator sentence actually makes: was
    # there a measured WINDOW to speak about. A baseline with no window after it
    # gives an operator nothing, and claiming otherwise is the defect.
    $dataFlowMeasured = ($null -ne $postBaselineSeconds)

    if ($ioSamples -gt 0 -and -not $dataFlowMeasured) {
        $reasons += 'Read-rate samples were taken but no baseline was ever established, so data flow was NOT assessed -- the absence of a read-collapse finding here means nothing was measured, not that nothing was wrong.'
    }

    # Level is NOT weakened by this. It answers "were all the channels seen?",
    # stays categorical, and a capture that linked, held the port and sampled
    # reads has seen them all. The honesty belongs in the sentence a human
    # reads and in DataFlowMeasured, which a consumer can branch on -- moving it
    # into Level would silently merge "saw nothing" with "saw everything,
    # measured nothing", two very different captures.
    $summary = switch ($level) {
        'NotObserved' {
            $who = if ($Target -and $Target.Name) { "'$($Target.Name)'" } else { 'the target headset' }
            "This recording did not observe a session. $who never linked, its COM port was never held, and no data flow was measured, so nothing here describes what NeurOptimal was doing."
        }
        'Partial' {
            'This recording observed the session only partly, so its findings rest on less evidence than a full capture.'
        }
        default {
            if ($dataFlowMeasured) {
                'This recording observed the session: the headset linked, its port was held, and data flow was measured.'
            } else {
                'This recording observed the session: the headset linked and its port was held -- but data flow was NOT assessed. Read-rate samples were taken and no baseline was ever established, so nothing here says whether the EEG read path was healthy.'
            }
        }
    }

    return [pscustomobject]@{
        PSTypeName        = 'WinConfig.FlightRecorder.ObservationCoverage'
        Level             = $level
        Reasons           = @($reasons)
        Summary           = $summary
        TargetEverLinked  = $linked
        TargetPortEverHeld = $heldPort
        IoSampleCount     = $ioSamples
        TargetComPortSeen = $sawPort
        RivalCandidates   = $rivals.Count
        RivalWasActive    = $rivalActive
        # Quality axis. Deliberately separate from Level so that "did we see all
        # channels?" and "for how long?" stay separate claims.
        Quality              = $quality
        QualitySummary       = $qualitySummary
        # Whether there was a measured window at all, as a fact a consumer can
        # branch on instead of parsing the English above (issue #77). True iff
        # Quality is not 'None', by construction.
        DataFlowMeasured     = $dataFlowMeasured
        ObservationSeconds   = $observationSeconds
        TickCount            = [int]$Session.TickCount
        SecondsToReadBaseline = $secondsToBaseline
        PostBaselineSeconds  = $postBaselineSeconds
        SustainedThresholdSeconds = $script:CoverageSustainedSeconds
    }
}

function Get-ProbeSessionVerdict {
    <#
    .SYNOPSIS
        Derives the recorder's closing verdict from EVERY issue channel, not one.
    .DESCRIPTION
        Field bug (capture B499E903C68C, 2026-08-07): the recorder printed
        "No unresolved issues." in green at the end of a session that carried 12
        findings, 3 of them [!] -- including a read-rate collapse (479 -> 2
        ops/tick) and two operator-marked NO error codes (12006).

        Cause: the closing line consulted the watch report's Unresolved list and
        nothing else. That list is built exclusively from COM-port matching
        (never exposed a port / roles conflict / roles unestablished), so on any
        box whose ports are present it is empty BY CONSTRUCTION. It can never
        hold a read collapse, an operator marker, port-held-without-data, FI-012
        degradation, FI-014 residue or link flaps -- those live only in the
        session summary's Findings.

        So the verdict is derived from Findings, with Unresolved folded in as
        one MORE source and never as the sole one. Same failure class as
        BaselineVerdict/FinalVerdict being audio-domain only.

        Pure transform: no I/O. The caller only renders what comes back.
    .PARAMETER Findings
        Get-DeviceProbeSessionSummary's Findings, prefixed [!] / [~] / [ok] /
        [i] / [info].
    .PARAMETER Unresolved
        New-TargetWatchReport's Unresolved list.
    .PARAMETER Coverage
        Get-ProbeObservationCoverage's result. When coverage is NotObserved the
        verdict is INCONCLUSIVE regardless of what the findings say: a recording
        that never saw the session cannot pass OR fail it, and reporting "2
        problems found" about a headset that was not in the session is the same
        class of confident-but-wrong as the green line this function replaced.
    .OUTPUTS
        [pscustomobject] with Level (FAIL|WARN|OK|INCONCLUSIVE), GuiLevel,
        Header, Lines (Text/Level pairs to print in order), and the counts.

        ⚠️ Level is SEMANTIC and INCONCLUSIVE is not a Console -Level value --
        that ValidateSet is OK/WARN/FAIL/INFO/STEP/ACTION/DIM and throws at
        runtime on anything else. Render with GuiLevel; never pass Level to
        Write-WinConfigGuiDiagnostic.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Findings,
        [string[]]$Unresolved,
        $Coverage
    )

    # Two COM ports for one MAC is the Arc's NORMAL shape (a DATA channel and a
    # COMMAND channel), so these two messages are not faults. The filter lives
    # here rather than at the call site so the whole verdict is testable.
    $realUnresolved = @($Unresolved | Where-Object {
        $_ -and $_ -notmatch 'Ambiguous COM-port matches' -and $_ -notmatch 'Multiple COM-port entries share MAC'
    })

    $critical = @($Findings | Where-Object { $_ -and $_.StartsWith('[!]') })
    $warnings = @($Findings | Where-Object { $_ -and $_.StartsWith('[~]') })

    $notObserved = ($Coverage -and $Coverage.Level -eq 'NotObserved')

    $level =
        if ($notObserved) { 'INCONCLUSIVE' }
        elseif ($critical.Count -gt 0 -or $realUnresolved.Count -gt 0) { 'FAIL' }
        elseif ($warnings.Count -gt 0) { 'WARN' }
        else { 'OK' }

    $lines = [System.Collections.ArrayList]::new()

    if ($notObserved) {
        # Deliberately NOT a pass and NOT a failure. The findings below are real
        # observations of the watched device; what is missing is any evidence
        # they describe the session the operator ran. Counting them as problems
        # is how capture 8E39860E4AF2 told an operator their clean 37-minute
        # session "did NOT end clean".
        $header = 'RECORDING DID NOT OBSERVE A SESSION'
        [void]$lines.Add([pscustomobject]@{ Text = $Coverage.Summary; Level = 'WARN' })
        foreach ($r in @($Coverage.Reasons)) {
            [void]$lines.Add([pscustomobject]@{ Text = "- $r"; Level = 'WARN' })
        }
        if ($critical.Count -gt 0 -or $warnings.Count -gt 0) {
            $seen = @()
            if ($critical.Count -gt 0) { $seen += "$($critical.Count) marked [!]" }
            if ($warnings.Count -gt 0) { $seen += "$($warnings.Count) marked [~]" }
            [void]$lines.Add([pscustomobject]@{
                Text  = "FINDINGS above ($($seen -join ', ')) describe the headset that was WATCHED, which this recording cannot show was in your session. Do not read them as a verdict on the session."
                Level = 'WARN'
            })
        }
        [void]$lines.Add([pscustomobject]@{
            Text  = 'To get a usable capture: confirm the headset you are using is powered on and connected, make sure the recorder selected THAT headset, and record again.'
            Level = 'ACTION'
        })
    } elseif ($level -eq 'OK') {
        [void]$lines.Add([pscustomobject]@{ Text = 'No unresolved issues.'; Level = 'OK' })
        $header = $null
    } else {
        # Not "UNRESOLVED ISSUES": under the fix most FAILs come from the
        # findings, not from the COM-port unresolved list, and that header over
        # an empty list read as a rendering bug.
        $header = if ($level -eq 'FAIL') { 'PROBLEMS FOUND' } else { 'WARNINGS' }

        # Unresolved lines are printed nowhere else, so they go in full.
        foreach ($u in $realUnresolved) {
            [void]$lines.Add([pscustomobject]@{ Text = "- $u"; Level = 'WARN' })
        }

        # The findings themselves were just printed above in FINDINGS; repeating
        # whole paragraphs here would bury the verdict. Count them and point.
        $parts = @()
        if ($critical.Count -gt 0) { $parts += "$($critical.Count) problem(s) marked [!]" }
        if ($warnings.Count -gt 0) { $parts += "$($warnings.Count) warning(s) marked [~]" }
        if ($parts.Count -gt 0) {
            [void]$lines.Add([pscustomobject]@{
                Text  = "$($parts -join ' and ') in FINDINGS above. This session did NOT end clean."
                Level = $level
            })
        }
    }

    return [pscustomobject]@{
        PSTypeName      = 'WinConfig.FlightRecorder.SessionVerdict'
        Level           = $level
        # Renderable equivalent. INCONCLUSIVE has no Console -Level and would
        # throw; it prints as WARN because it is neither a pass nor a fault.
        GuiLevel        = if ($level -eq 'INCONCLUSIVE') { 'WARN' } else { $level }
        Header          = $header
        Lines           = @($lines)
        CriticalCount   = $critical.Count
        WarningCount    = $warnings.Count
        UnresolvedCount = $realUnresolved.Count
        Unresolved      = $realUnresolved
        Coverage        = if ($Coverage) { $Coverage.Level } else { $null }
    }
}

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
        # "Port open", not "Active": the probe measures a handle, not data flow.
        'stream.Active'               = 'Port open'
        'stream.Stopped'              = 'Port idle'
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
        # Two ports is the NORMAL, healthy shape for this headset -- it exposes a
        # DATA and a COMMAND SPP channel, and TargetDeviceWatch counts this state
        # as "seen" for exactly that reason. The old text called it ghost ports,
        # which sent operators hunting for a problem that was not there.
        'comport.ComPortAmbiguous'    = 'Two COM ports found -- normal for this headset, which exposes a data channel and a command channel. More than two can mean leftovers from previous pairings.'
        'comport.ComPortUnconfigured' = 'N/A -- COM ports only apply when a device is paired'
        'btlink.Connected'            = 'Radio connected -- the Bluetooth radio has an active wireless link to the headset'
        'btlink.NotConnected'         = 'Radio disconnected -- no active Bluetooth wireless link to the headset'
        'btlink.Unknown'              = 'Radio unknown -- cannot determine Bluetooth radio link status (requires admin rights and a discovered device)'
        # These used to assert that data was flowing. The probe cannot see that:
        # it detects a HELD HANDLE, which NO.exe takes at connect and keeps
        # whether or not the headset delivers a single sample. Saying otherwise
        # is what made a stalled Arc read as a healthy session in the field.
        'stream.Active'               = 'COM port open -- NeurOptimal is holding the headset''s serial port. This does NOT confirm EEG data is arriving; the probe cannot read the port while another process owns it.'
        'stream.Stopped'              = 'COM port idle -- no process is holding the headset''s serial port, so NeurOptimal is not connected to it right now'
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

function New-IoEpisodeRecord {
    <#
    .SYNOPSIS
        Snapshots one read-rate episode's outcome before its live state is wiped.
    .DESCRIPTION
        Pure. Called when a port-open episode ends, and again (without mutating)
        for the in-flight episode when the session is summarised.
    .OUTPUTS
        [pscustomobject], or $null when the episode never established a baseline
        and so has nothing to say.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [datetime]$At = (Get-Date)
    )

    $baseline = [int]$Session.IoBaselineOpsPerTick
    $verdict  = [string]$Session.IoVerdict

    # No baseline and no verdict worth keeping: an episode that never measured
    # anything contributes nothing and must not dilute the ones that did.
    if ($baseline -le 0 -and $verdict -in @('NoBaseline', '', $null)) { return $null }

    return [pscustomobject]@{
        PSTypeName          = 'WinConfig.FlightRecorder.IoEpisode'
        Verdict             = if ($verdict) { $verdict } else { 'NoBaseline' }
        BaselineOpsPerTick  = $baseline
        RecentOpsPerTick    = [int]$Session.IoRecentOpsPerTick
        FractionOfBaseline  = $Session.IoFractionOfBaseline
        Collapsed           = ($verdict -eq 'Collapsed')
        Degrading           = ($verdict -eq 'Degrading')
        EndedAtIso          = $At.ToString('o')
    }
}

function Get-IoSessionReadRateRecord {
    <#
    .SYNOPSIS
        The session-long read-rate record: closed episodes plus the live one.
    .DESCRIPTION
        The single answer to "did data flow ever collapse during this recording?"
        -- across BOTH channels that can observe one: the trailing-window episode
        ledger and the instantaneous operator markers. Neither alone is the
        answer, and only joining them here keeps the record from contradicting
        its own findings text (issue #65).

        The live IoVerdict answers only "was it collapsing at the last tick",
        which is a different question and the wrong one to build a bundle on. A
        port re-open resets the live fields, so a recording can end reporting
        'NoBaseline' minutes after a measured collapse -- and every consumer
        downstream then reads a collapse as an unmeasured session.

        Pure: reads the session, mutates nothing, so the summary and the bundle
        can both call it and cannot disagree.
    .OUTPUTS
        [pscustomobject] EverCollapsed, EverDegrading, CollapseEpisodes,
        MarkerCollapseCount, CollapseObservedBy, EpisodeCount,
        BaselineResetCount, PeakBaselineOpsPerTick, WorstRecentOpsPerTick,
        WorstFractionOfBaseline, FirstCollapseAtIso, Episodes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session)

    $episodes = @()
    if ($Session.IoClosedEpisodes) { $episodes += @($Session.IoClosedEpisodes) }
    # The episode still running has not been stamped anywhere, and on a session
    # that ends mid-collapse it is the ONLY one that carries the collapse.
    $live = New-IoEpisodeRecord -Session $Session
    if ($live) { $episodes += $live }
    $episodes = @($episodes | Where-Object { $_ })

    $collapsed = @($episodes | Where-Object { $_.Collapsed })

    # ── The SECOND answerer: operator markers ────────────────────────────────
    # The episode ledger evaluates on a TRAILING WINDOW; a marker samples the
    # INSTANT the operator saw the dialog. Both are correct and they measure
    # different things, so they can legitimately disagree -- and on capture
    # E0C8B0588CC7 they did: the window bottomed at 14% of baseline and never
    # crossed the collapse threshold, while a marker caught 8 ops/tick against a
    # 444 baseline, 2%, and stamped IoVerdict 'Collapsed'. The record then held
    # EverCollapsed: false in the same file as the marker text "reads COLLAPSED
    # to 8/tick ... (2% of normal)".
    #
    # That run was the Wi-Fi coexistence control. "Never collapsed" invited
    # exactly the wrong conclusion -- that cutting Wi-Fi had prevented the
    # collapse -- when the operator had hit 12006 twice, mid-session, and the
    # hypothesis was in fact refuted. A summary field nearly inverted an
    # experimental result (issue #65).
    #
    # Joining here, in the one function both the findings and the bundle call,
    # is what makes the contradiction UNEMITTABLE rather than merely detected:
    # there is no longer an input for which EverCollapsed is false while a
    # marker says Collapsed. The two counts stay separate below, because "how
    # many episodes collapsed" and "how many times an operator caught one" are
    # different questions and blurring them would lose the marker's evidence.
    $markers = @($Session.OperatorMarkers | Where-Object { $_ })
    $markerCollapsed = @($markers | Where-Object { $_.IoVerdict -eq 'Collapsed' })

    # ── The THIRD answerer: the announcement latch ───────────────────────────
    # IoBaselineAnnouncedAt/OpsPerTick is set once per run and never reset -- it
    # was built to answer "was data flow EVER measurable during this recording?"
    # and it is the honest terminal fact. The record never consulted it, so on
    # capture 31D0729CA5B8 three channels disagreed about whether a baseline
    # existed: the announcement said 436 ops/tick at 20:39:50, coverage said
    # Sustained after 238 s -- and THIS record, the one that gates collapse
    # detection, said BaselineEstablished false with a peak of 0.
    #
    # The cause is erosion, not a reset: 15.4 h of idle ticks after a 33-minute
    # session dragged the trailing median to zero, so the live episode evaluated
    # to 'NoBaseline' and was discarded by New-IoEpisodeRecord. BaselineResetCount
    # was 0 throughout, which is why gating on it does not catch this (issue #63).
    $announcedAt  = $Session.IoBaselineAnnouncedAt
    $announcedOps = [int]$Session.IoBaselineAnnouncedOpsPerTick
    $announced    = ($null -ne $announcedAt -and $announcedOps -gt 0)

    $peak = 0
    foreach ($e in $episodes) {
        if ([int]$e.BaselineOpsPerTick -gt $peak) { $peak = [int]$e.BaselineOpsPerTick }
    }
    foreach ($m in $markerCollapsed) {
        if ([int]$m.IoBaselineOpsPerTick -gt $peak) { $peak = [int]$m.IoBaselineOpsPerTick }
    }
    # A peak below the rate that was ANNOUNCED is not a measurement, it is
    # erosion. Reporting 0 here is what produced the finding that read
    # "went from ~0 to ~0 read operations per tick".
    if ($announcedOps -gt $peak) { $peak = $announcedOps }

    # ── The worst observation, as ONE pair from ONE channel ──────────────────
    # WorstFractionOfBaseline used to be read off the session by the bundle while
    # WorstRecentOpsPerTick was read off this record, so the manifest carried two
    # halves of one observation assembled from two objects -- and they contradicted
    # (0% beside null). They are chosen together here: whichever channel saw the
    # lowest fraction supplies BOTH numbers, so they always describe one moment.
    $worstCandidates = @()
    foreach ($e in $collapsed) {
        $worstCandidates += [pscustomobject]@{ Fraction = $e.FractionOfBaseline; Recent = [int]$e.RecentOpsPerTick }
    }
    foreach ($m in $markerCollapsed) {
        $worstCandidates += [pscustomobject]@{ Fraction = $m.IoFractionOfBaseline; Recent = [int]$m.IoRecentOpsPerTick }
    }
    if ($null -ne $Session.IoWorstFractionOfBaseline) {
        $worstCandidates += [pscustomobject]@{
            Fraction = $Session.IoWorstFractionOfBaseline
            Recent   = [int]$Session.IoWorstRecentOpsPerTick
        }
    }
    $worst = $null
    foreach ($c in @($worstCandidates | Where-Object { $null -ne $_.Fraction })) {
        if ($null -eq $worst -or $c.Fraction -lt $worst.Fraction) { $worst = $c }
    }
    # A collapsed observation with no fraction attached still carries a rate, and
    # dropping it would put null in the field a finding quotes.
    $worstRecent = if ($worst) { $worst.Recent } else {
        $bare = @(@($collapsed | ForEach-Object { [int]$_.RecentOpsPerTick }) +
                  @($markerCollapsed | ForEach-Object { [int]$_.IoRecentOpsPerTick }))
        if ($bare.Count -gt 0) { ($bare | Measure-Object -Minimum).Minimum } else { $null }
    }
    $worstFraction = if ($worst) { $worst.Fraction } else { $null }

    # ── Session-level outcome ────────────────────────────────────────────────
    # Derived ONCE, here, so the findings and the bundle manifest cannot answer
    # "how did data flow behave this session?" differently. Field capture
    # 91C5F8EB3E3F (SP6, Arc 013, 33 min, clean) is why: its TERMINAL verdict was
    # 'Degrading' because the trailing 4-tick window straddled port teardown --
    # one near-zero tick as the port closed -- while the trailing AVERAGE was
    # 2627 ops/tick against a 446 baseline, i.e. 589% of baseline and rising.
    # The findings chain already guards this correctly (Degrading only counts
    # with the port still held; dips only count above the teardown allowance);
    # the dashboard read the bare verdict and badged a clean 33-minute capture as
    # degraded, alongside the genuine 013 collapse.
    #
    # Test-IoReadCollapse is deliberately NOT changed: 'Degrading' remains a
    # useful INSTANTANEOUS state for operator markers, and trimming trailing
    # samples could hide a real failure that happens near teardown.
    #
    # 'Stable' requires a baseline to have actually been ESTABLISHED, which is
    # what an episode verdict other than NoBaseline means. A sub-floor read rate
    # leaves BaselineOpsPerTick nonzero while the verdict stays NoBaseline, so
    # peak alone would call an unmeasurable session stable.
    # A marker stamped 'Collapsed' against a real baseline is itself proof a
    # baseline was established, so it counts here too -- otherwise the record
    # could report Outcome 'Collapsed' beside BaselineEstablished false, which is
    # the same contradiction one field over.
    $ledgerBaseline = (@($episodes | Where-Object {
        $_.Verdict -in @('Streaming', 'Degrading', 'Collapsed')
    }).Count -gt 0) -or
        (@($markerCollapsed | Where-Object { [int]$_.IoBaselineOpsPerTick -gt 0 }).Count -gt 0)
    # An announcement is proof on its own. "BaselineEstablished false while
    # ReadBaselineAnnouncedAtUtc is populated" is an impossible state and the
    # record must not be able to emit it.
    $baselineEstablished = ($ledgerBaseline -or $announced)
    # ...but say so when the two disagree, rather than papering over it. This is
    # the state that makes EverCollapsed vacuous: the ledger that gates collapse
    # detection no longer holds the baseline the run actually established, so
    # "no collapse recorded" means "not assessed", not "nothing went wrong".
    $baselineLostAfterAnnouncement = ($announced -and -not $ledgerBaseline)

    # Held-and-falling is the fault shape; released-and-falling is a clinic
    # finishing a session. Same gate the findings use.
    $terminalDegrading = ($Session.IoVerdict -eq 'Degrading' -and $Session.StreamingState -eq 'Active')
    $dipsBeyondTeardown = ([int]$Session.IoDegradedTicks -gt $script:IoCollapseTicks)

    # A marker counts here exactly as an episode does. It is a measurement the
    # operator stood next to, and it is the only channel that samples the moment
    # the fault was visible in NeurOptimal.
    # The detector's own latch counts as a channel. On 31D0729CA5B8 a collapse
    # fired during the run -- and then the only record of it, the live episode,
    # decayed below the baseline floor and was discarded, so the ledger held
    # nothing at all.
    $detectorCollapsed = [bool]$Session.IoCollapseEverDetected
    $everCollapsed = ($collapsed.Count -gt 0 -or $markerCollapsed.Count -gt 0 -or $detectorCollapsed)

    # Which channels saw it, joined rather than ranked -- three can now observe a
    # collapse and a reader comparing the counts needs to know which ones did.
    $observers = @()
    if ($collapsed.Count -gt 0)       { $observers += 'Episode' }
    if ($markerCollapsed.Count -gt 0) { $observers += 'Marker' }
    if ($detectorCollapsed)           { $observers += 'Detector' }
    $collapseObservedBy = if ($observers.Count -gt 0) { $observers -join '+' } else { $null }

    # How long the recording ran on AFTER read activity stopped. An unbounded
    # window silently destroys the read-rate channel -- 15.4 h of idle ticks
    # dragged a 436 ops/tick baseline to zero -- so the tail is published as its
    # own number instead of being left for a reader to infer from timestamps.
    $idleTailSeconds = if ($Session.IoLastNonZeroReadAt -and $Session.LastTickAt) {
        [int][math]::Max(0, ($Session.LastTickAt - $Session.IoLastNonZeroReadAt).TotalSeconds)
    } else { $null }

    # Earliest sighting from EITHER channel. ISO-8601 with a fixed offset sorts
    # lexicographically in chronological order.
    $collapseStamps = @()
    if ($collapsed.Count -gt 0)       { $collapseStamps += $collapsed[0].EndedAtIso }
    if ($markerCollapsed.Count -gt 0) { $collapseStamps += $markerCollapsed[0].AtIso }
    # Indexing [0] into an empty array THROWS under Set-StrictMode -Version
    # Latest, and the empty case is the common one -- every clean session.
    $sortedStamps = @($collapseStamps | Where-Object { $_ } | Sort-Object)
    $firstCollapseIso = if ($sortedStamps.Count -gt 0) { $sortedStamps[0] } else { $null }

    $outcome =
        if ($everCollapsed)                                { 'Collapsed' }
        elseif ($terminalDegrading -or $dipsBeyondTeardown) { 'Degraded' }
        # Measured once, then the ledger that answers the collapse question lost
        # it. 'Stable' would be a claim this capture cannot support -- the whole
        # point of #63 is that a vacuous pass is indistinguishable from a real
        # one. Deliberately reuses the existing four-value vocabulary rather
        # than adding a fifth the dashboard would not recognise.
        elseif ($baselineLostAfterAnnouncement)             { 'Unassessed' }
        elseif ($baselineEstablished)                       { 'Stable' }
        else                                                { 'Unassessed' }

    return [pscustomobject]@{
        PSTypeName             = 'WinConfig.FlightRecorder.IoSessionReadRate'
        EverCollapsed          = $everCollapsed
        # IoDegradedTicks is counted here too. Capture 31D0729CA5B8 shipped
        # EverDegrading false beside Outcome 'Degraded' and
        # MeaningfullyDegraded true, in one object -- the outcome was derived
        # from the tick counter while this field looked only at episodes.
        EverDegrading          = ((@($episodes | Where-Object { $_.Degrading }).Count -gt 0) -or
                                  (@($markers | Where-Object { $_.IoVerdict -eq 'Degrading' }).Count -gt 0) -or
                                  ([int]$Session.IoDegradedTicks -gt 0))
        # Episodes and markers are counted SEPARATELY on purpose. Folding a
        # marker into CollapseEpisodes would claim an episode the ledger never
        # closed; dropping it would lose the only channel that saw the collapse.
        CollapseEpisodes       = $collapsed.Count
        MarkerCollapseCount    = $markerCollapsed.Count
        # Which channel actually saw it. A reader comparing this record against
        # the marker list needs to know why the counts differ.
        CollapseObservedBy     = $collapseObservedBy
        EpisodeCount           = $episodes.Count
        BaselineResetCount     = [int]$Session.IoBaselineResetCount
        PeakBaselineOpsPerTick = $peak
        WorstRecentOpsPerTick  = $worstRecent
        # Paired with the line above by construction; see the selection block.
        WorstFractionOfBaseline = $worstFraction
        FirstCollapseAtIso     = $firstCollapseIso
        Episodes               = $episodes
        # Collapsed | Degraded | Stable | Unassessed
        Outcome                = $outcome
        BaselineEstablished    = $baselineEstablished
        # True when a baseline was announced during the run but the episode
        # ledger no longer holds one. The collapse question was NOT assessed on
        # this capture, whatever EverCollapsed says, and a reader must be told
        # that rather than left to read "false" as "nothing went wrong".
        BaselineLostAfterAnnouncement = $baselineLostAfterAnnouncement
        AnnouncedBaselineOpsPerTick   = if ($announced) { $announcedOps } else { $null }
        # Seconds the recording ran on after read activity stopped.
        IdleTailSeconds        = $idleTailSeconds
        # The claim a badge should be built from. A terminal 'Degrading' caused
        # by teardown is NOT this.
        MeaningfullyDegraded   = ($outcome -eq 'Degraded')
    }
}

function Get-NextProbeTickDeadline {
    <#
    .SYNOPSIS
        Computes the next probe-tick deadline using fixed-rate scheduling.
    .DESCRIPTION
        The recorder claims to check "every 3s", and every tick-count-based
        detection window is denominated in that interval. Two scheduling mistakes
        break that claim in opposite directions, and this function exists so both
        are decided in one pure, testable place instead of inline in the GUI loop:

          - Scheduling from the END of a tick makes the real period
            interval + execution time. A 1 s tick would then start every 4 s and
            every detection window would silently stretch by a third.

          - Scheduling from the previous deadline with no overrun handling puts
            the next deadline in the PAST whenever a tick outruns its interval,
            so it fires again immediately and the UI message pump never runs.
            That is what made a ~5 s tick block the recorder window continuously.

        So: the next deadline is the previous DEADLINE plus the interval; if that
        has already passed, whole missed periods are SKIPPED rather than run as
        back-to-back catch-up ticks, and the result is pushed out far enough to
        guarantee a minimum slice of message-pump time.

        Pure: no clock reads, no I/O. The caller supplies both timestamps.
    .PARAMETER PreviousDeadline
        The deadline the tick that just ran was scheduled for (NOT when it began).
    .PARAMETER TickEnd
        When that tick finished.
    .PARAMETER IntervalSeconds
        The nominal tick interval.
    .PARAMETER MinPumpRecoveryMs
        Guaranteed gap between TickEnd and the next deadline.
    .OUTPUTS
        [pscustomobject] NextDeadline, MissedDeadlines, PumpFloorApplied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$PreviousDeadline,
        [Parameter(Mandatory)][datetime]$TickEnd,
        [ValidateRange(1, 3600)][int]$IntervalSeconds = 3,
        [ValidateRange(0, 60000)][int]$MinPumpRecoveryMs = 250
    )

    $next = $PreviousDeadline.AddSeconds($IntervalSeconds)
    $missed = 0

    if ($next -le $TickEnd) {
        # Skip whole periods rather than replaying them.
        $overdueSec = ($TickEnd - $next).TotalSeconds
        $missed = [int][Math]::Floor($overdueSec / $IntervalSeconds) + 1
        $next = $next.AddSeconds($IntervalSeconds * $missed)
    }

    $floor = $TickEnd.AddMilliseconds($MinPumpRecoveryMs)
    $floorApplied = $false
    if ($next -lt $floor) {
        $next = $floor
        $floorApplied = $true
    }

    return [pscustomobject]@{
        PSTypeName       = 'WinConfig.FlightRecorder.TickSchedule'
        NextDeadline     = $next
        MissedDeadlines  = $missed
        PumpFloorApplied = $floorApplied
    }
}

Export-ModuleMember -Function @(
    'Initialize-BtWin32Api',
    'Get-NextProbeTickDeadline',
    # Session-long read-rate record. Exported because the bundle summary must be
    # built from the same answer the findings are, not from the live last-tick
    # fields that a port re-open silently resets.
    'New-IoEpisodeRecord',
    # Invasiveness accounting (#83). Exported so the manifest is built from the
    # same summariser the tests assert on, rather than a second one at the call
    # site -- the channel-mismatch pattern this repo keeps re-filing.
    'Add-PortOpenTimingSample',
    'Add-PortOpenTimingSamples',
    'Get-PortOpenTimingReport',
    'Get-IoSessionReadRateRecord',
    'Get-NoExeVersion',
    'Test-NoUsesMacResolve',
    'Get-BtConnectionState',
    'Test-ComPortInUse',
    'Get-ComPortHoldState',
    'Get-StreamingState',
    'Get-ProbeStateConsistency',
    'Initialize-ProcessIoApi',
    'Get-ProcessIoSample',
    'Test-IoReadCollapse',
    'New-ProbeStateMarker',
    'Format-ProbeStateMarker',
    'Get-PatternAnnotation',
    'Get-EstimatedScanCycles',
    'New-DeviceProbeSession',
    'Invoke-DeviceProbeTick',
    'Get-DeviceProbeSessionSummary',
    'Invoke-AnomalyDiagnosticSnapshot',
    'Get-ProbeObservationCoverage',
    # The single answerer for "how long did this recording run?", plus the join
    # guard over markers and the episode ledger (issue #78). Exported because
    # the manifest must read the same answer the guard checked, not a second
    # derivation of it.
    'Get-ProbeRecordingWindow',
    'Get-ProbeSessionVerdict',
    'Get-ProbeStateGuiLevel',
    'Get-ProbeStateColor',
    'Get-ProbeStateUserText'
)

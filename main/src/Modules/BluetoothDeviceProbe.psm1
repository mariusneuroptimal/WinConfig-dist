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

# THE UNIT IS OPS PER SECOND, AND A TICK IS NOT A UNIT OF TIME (#86).
#
# These thresholds were per-TICK, which silently mixed a rate with a duration.
# Capture DB98B6EE3324 ran its ticks from the 3000 ms target out to 13506 ms
# (mean 4619 ms), so the same data flow reads as a different number depending on
# how starved the box was. The direction is counter-intuitive and is what makes
# it dangerous: a LONG tick accumulates more operations and reads as a SPIKE, a
# short one as a DIP. #82 makes long ticks common exactly when the machine is
# struggling, so the artefact CORRELATES WITH THE FAULT.
#
# The corpus shows the normalisation working. Healthy baselines span 422-776
# ops/TICK across the 45 uploaded packages -- a 1.84x spread that looks like real
# variation between boxes and is not. Divided by each run's own cadence they
# collapse onto 141-149 ops/SECOND. The clean instance is C0AE9604CDAC: 776
# ops/tick, by far the highest ever recorded, on a run whose mean interval was
# 5.43 s -- 142.9 ops/s, dead centre of the 3-second cohort. It was never a busy
# session, only a slow-ticking one.
#
# (Long runs need care with that arithmetic: 8E5C4470B593 reports 433 ops/tick
# against a 5.35 s WHOLE-RUN mean, which converts to an off-cluster 80.9 ops/s.
# Its baseline is a LEADING-window statistic and the mean is dragged up by a
# 1.9-hour tail; at the 3 s cadence its baseline window actually ran at, 433
# gives 144.3 ops/s -- back on the cluster. The per-interval stamping below is
# precisely so nothing has to be reconstructed from a whole-run average again.)

# Elapsed streaming time before a baseline is trusted. Was 5 ticks; 5 x the 3 s
# target is the same 15 s, so nothing about the intended wait has changed -- only
# that a starved box no longer has to wait proportionally longer to be judged.
# With IoCollapseSeconds that means no verdict before ~27s of streaming.
#
# This also shortens the blind window the field capture exposed: DB98B6EE3324
# needed 9 deltas at a 4.6 s mean = ~46 s to rebuild a baseline after each port
# re-open, against a 27-36 s re-acquire cycle, so the recorder could NEVER hold a
# baseline during that fault. 27 s of elapsed time is still marginal against a
# 27 s cycle -- this is an improvement, NOT a fix for that; see #85/#87.
$script:IoBaselineMinSeconds = 15
# Below this median read rate there is nothing to collapse FROM, and claiming a
# collapse would be noise. Reported as "no baseline", never as healthy.
#
# RE-DERIVED FROM THE CORPUS, NOT TRANSLITERATED. The old floor was 20 ops/tick;
# dividing by the nominal tick would give ~6.7 ops/s and dividing nothing at all
# would give 20 ops/s, and BOTH are wrong -- 20 ops/s would have retracted
# DB98B6EE3324's own 7% collapse finding, whose episode baselined at 60 ops/tick
# over 4.6 s ticks = 13 ops/s. Instead the floor is bracketed by the decisions
# the shipped corpus has already made:
#
#   lowest baseline the old floor ACCEPTED  3E75BF45FC02, 28 ops/tick @ 5.32 s
#                                           = 5.26 ops/s (9.33 if its baseline
#                                           window ran at the 3 s target)
#   highest baseline it REJECTED            236061907514, 6 ops/tick @ 3.29 s
#                                           = 1.82 ops/s (2.0 at the target)
#
# Any floor inside (2.0, 5.26) preserves every accept/reject decision in all 45
# packages under either cadence assumption. 3.0 is the geometric middle of that
# bracket, and sits ~48x below the 146 ops/s a healthy session measures.
$script:IoBaselineMinOpsPerSecond = 3.0
# Fraction of baseline that counts as collapsed. Measured in-session jitter is
# ~3.3%, so 0.25 sits roughly 7x outside normal variation while still catching a
# PARTIAL stall -- a headset transmitting intermittently, not only one that has
# gone completely silent. The original 0.1 only caught near-total silence and
# would have missed a 60% degradation entirely. Dimensionless, so the unit change
# leaves it exactly as it was.
$script:IoCollapseFraction = 0.25
# Contiguous elapsed seconds below the collapse limit required to fire, so a
# scheduling hiccup cannot. Was 4 consecutive ticks, which at the 3 s target is
# the same 12 s -- but on DB98B6EE3324's 13.5 s ticks those 4 ticks would have
# demanded up to 54 s of silence, and on a fast run as little as 12 s. Same
# intent, now actually constant.
$script:IoCollapseSeconds = 12
# An interval longer than this is not a slow tick, it is a gap -- the app hung,
# the process was suspended, or the recorder was descheduled -- and dividing an
# operation count by it produces a rate that describes no real period. The worst
# interval ever recorded in the field is 13.5 s, so 30 s is well clear of "slow"
# and firmly in "something stopped". Such intervals are DISCARDED FROM THE RATES
# AND COUNTED, never silently averaged in: see DiscardedIntervals.
$script:IoMaxSampleIntervalSeconds = 30

# Idle recording, in seconds, past which the tail is worth naming in the
# findings. An idle tail is not inert: the baseline is a MEDIAN over the samples
# before the trailing window, so empty ticks pull it down until the run's own
# baseline drops under IoBaselineMinOpsPerSecond and the episode is discarded as
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

# Hard ceiling on the stamped I/O sample ledger (#84). The longest run on record
# (31D0729CA5B8, 15.4 h) would produce ~18 k entries at a ~3 s tick, so this is
# roughly 3x the worst real capture and exists only so a pathological run cannot
# grow the ledger without limit. Overflow is COUNTED and reported, never silently
# dropped: a truncated ledger that reads as complete is the same class of lie as
# an unmeasured zero rendered as 0.
$script:IoSampleLedgerMax = 60000

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

function Add-IoReadRateSample {
    <#
    .SYNOPSIS
        Folds one stamped read-counter sample into the session ledger (#84).
        Runs on EVERY tick NO.exe exists -- not only while a port is held.
    .DESCRIPTION
        The one place the ungated channel is written. It does NOT touch
        IoLastReadOps, IoReadSamples or any verdict field: the scoped series
        that feeds Test-IoReadCollapse stays exactly what it was, because the
        process-wide counter includes file I/O and widening the detector's input
        would raise its baseline and hide the serial-only collapse it exists to
        catch.

        Stamps the held-port SET, not a boolean, so a later reader can scope a
        rate to a particular port rather than only to "some port was held". The
        counter itself still cannot attribute a read to a port -- see
        Get-ProcessIoSample -- so this records the scope, it does not invent
        attribution.
    .PARAMETER Session
        The probe session.
    .PARAMETER ReadOps
        Cumulative read-operation count for NO.exe at this instant.
    .PARAMETER At
        Timestamp of the sample.
    .PARAMETER HeldPorts
        The ports held at this instant, from the same tick's stream result.
    .OUTPUTS
        [hashtable] the appended record, or $null if it was not recorded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][double]$ReadOps,
        [Parameter(Mandatory)][datetime]$At,
        $HeldPorts = @()
    )

    if ($Session.IoSamples -isnot [System.Collections.ArrayList]) { return $null }

    $held = @($HeldPorts | Where-Object { $_ })

    $deltaOps = $null
    $deltaSec = $null
    if ($null -ne $Session.IoUnscopedLastReadOps -and $null -ne $Session.IoUnscopedLastAt) {
        $d = $ReadOps - [double]$Session.IoUnscopedLastReadOps
        # Counters are monotonic within a process. A negative delta means a
        # DIFFERENT NO.exe, so the interval spans two processes and is not a
        # rate at all -- record the sample, drop the delta.
        if ($d -ge 0) {
            $deltaOps = $d
            $deltaSec = ($At - [datetime]$Session.IoUnscopedLastAt).TotalSeconds
            $Session.IoUnscopedTotalOps += $d
        }
    }

    $rec = @{
        At           = $At
        ReadOps      = $ReadOps
        DeltaOps     = $deltaOps
        # Seconds, not ticks. Every consumer of this ledger needs a per-second
        # rate (#86: the detector compares ops-per-tick against a 3.0-13.5 s
        # cadence), and a tick is not a unit of time on a starved run.
        DeltaSeconds = $deltaSec
        HeldPorts    = $held
        PortHeld     = ($held.Count -gt 0)
    }

    if ($Session.IoSamples.Count -ge $script:IoSampleLedgerMax) {
        $Session.IoSamplesDropped++
        return $null
    }
    [void]$Session.IoSamples.Add($rec)

    if ($null -eq $Session.IoUnscopedFirstAt) { $Session.IoUnscopedFirstAt = $At }
    $Session.IoUnscopedLastReadOps = $ReadOps
    $Session.IoUnscopedLastAt      = $At
    return $rec
}

function Get-IoReadRateScopes {
    <#
    .SYNOPSIS
        Pure. Derives a port-held-scoped read rate and an unscoped one from the
        stamped sample ledger (#84).
    .DESCRIPTION
        Two rates because there are two questions, and one gate used to answer
        only the first:

          PortHeld*  reads during intervals when a port was held. This is the
                     window the collapse detector judges, and the only one that
                     can speak to 12006.
          Unscoped*  reads across the whole recording. The ONLY channel that can
                     say anything about a 12005, where NO holds no port and the
                     old gate therefore took no sample at all.

        Neither is evidence that a read went to the Arc. The counter is
        process-wide and cannot attribute a read to a port
        (Get-ProcessIoSample). A HIGH unscoped rate beside a zero port-held rate
        says NO.exe was busy with something else, not that the serial path was
        alive -- which is precisely the 12005 shape worth being able to see.

        Intervals, not samples, are the unit: an interval is scoped port-held
        only when BOTH ends were held, since a read that landed inside it could
        have arrived on either side of the release.

        Returns $null when nothing was sampled, so an unmeasured run renders as
        absent rather than as a confident zero.
    .PARAMETER Samples
        The session's IoSamples ledger.
    .PARAMETER DroppedCount
        Samples the ledger cap refused, so a truncated ledger says so.
    .OUTPUTS
        [pscustomobject] SampleCount, IntervalCount, PortHeldSeconds,
        UnscopedSeconds, PortHeldOps, UnscopedOps, PortHeldOpsPerSecond,
        UnscopedOpsPerSecond, SamplesDropped, Basis.
    #>
    [CmdletBinding()]
    param(
        $Samples,
        [int]$DroppedCount = 0
    )

    $list = @($Samples | Where-Object { $_ })
    if ($list.Count -eq 0) { return $null }

    $heldOps = [double]0; $heldSec = [double]0; $heldIntervals = 0
    $allOps  = [double]0; $allSec  = [double]0; $intervals     = 0
    $prev = $null

    foreach ($s in $list) {
        $d  = $s.DeltaOps
        $ds = $s.DeltaSeconds
        # A sample with no delta is a real observation of the counter, it just
        # opens no interval -- the first of the run, or the first after a
        # process change. Counted in SampleCount, absent from the rates.
        if ($null -ne $d -and $null -ne $ds -and [double]$ds -gt 0) {
            $intervals++
            $allOps += [double]$d
            $allSec += [double]$ds
            if ($prev -and $prev.PortHeld -and $s.PortHeld) {
                $heldIntervals++
                $heldOps += [double]$d
                $heldSec += [double]$ds
            }
        }
        $prev = $s
    }

    # $null, never 0. A rate of 0 means "measured, nothing read"; an absent
    # rate means "no interval to measure over". Collapsing them is how a
    # capture starts claiming a healthy zero.
    $heldRate = if ($heldSec -gt 0) { [math]::Round($heldOps / $heldSec, 1) } else { $null }
    $allRate  = if ($allSec  -gt 0) { [math]::Round($allOps  / $allSec,  1) } else { $null }

    return [pscustomobject]@{
        PSTypeName           = 'WinConfig.FlightRecorder.IoReadRateScopes'
        SampleCount          = $list.Count
        IntervalCount        = $intervals
        PortHeldIntervalCount = $heldIntervals
        PortHeldOps          = [math]::Round($heldOps, 0)
        PortHeldSeconds      = [math]::Round($heldSec, 1)
        PortHeldOpsPerSecond = $heldRate
        UnscopedOps          = [math]::Round($allOps, 0)
        UnscopedSeconds      = [math]::Round($allSec, 1)
        UnscopedOpsPerSecond = $allRate
        # Reported, not silent: a capped ledger must not read as a complete one.
        SamplesDropped       = $DroppedCount
        Basis                = 'Process-wide ReadOperationCount for NO.exe, sampled every tick the process existed. Includes file I/O and CANNOT attribute a read to a COM port. PortHeld* covers intervals held at both ends.'
    }
}

function Test-IoReadCollapse {
    <#
    .SYNOPSIS
        Pure. Decides whether a series of STAMPED read-operation samples shows a
        collapse against its own established baseline. Ops per SECOND (#86).
    .DESCRIPTION
        Relative, not absolute. An absolute ops/sec threshold would need
        calibrating per box, per NO build and per session type; a box's own
        recent history is the only reference that travels. The baseline is the
        MEDIAN of the samples before the collapse window, so one scheduling
        outlier cannot move it.

        Returns Verdict:
          Collapsed     rate fell below the fraction of baseline and stayed there
          Degrading     the newest interval is below the collapse limit but the
                        debounce is not satisfied yet -- a collapse in progress
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

        A single interval under the limit is not noise: measured in-session
        jitter is ~3.3% and the limit sits at 25% of baseline, ~7x outside that.

        WHY SECONDS AND NOT TICKS (#86). Every quantity here used to be counted
        in ticks against a cadence that ran 3.0 s to 13.5 s in the field, so the
        verdict moved when only the SCHEDULER had moved. Three separate things
        needed the unit:

          the rate       ops/interval / interval seconds, per interval, so a long
                         tick no longer reads as a spike
          the baseline   IoBaselineMinSeconds of ELAPSED history, so a starved
                         box does not have to wait proportionally longer to be
                         judged than a healthy one
          the debounce   IoCollapseSeconds of CONTIGUOUS TRAILING time below the
                         limit, which is what "4 consecutive ticks" was trying to
                         say and only said at exactly the 3 s target

        The recent rate is TIME-WEIGHTED (total ops / total seconds over the
        window), not a mean of per-interval rates: the mean of rates would let one
        short interval count as much as a long one and reintroduce the artefact at
        the last step.
    .PARAMETER Samples
        Stamped read-operation samples, oldest first. Each needs DeltaOps and
        DeltaSeconds; anything else is counted as malformed, never averaged in.
    .OUTPUTS
        [hashtable] Verdict, BaselineOpsPerSecond, RecentOpsPerSecond,
        CollapsedSeconds, DegradedIntervals, FractionOfBaseline, BaselineSeconds,
        WindowSeconds, DiscardedIntervals, MalformedSamples.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][array]$Samples = @())

    $result = @{
        Verdict              = 'NoBaseline'
        BaselineOpsPerSecond = 0
        RecentOpsPerSecond   = 0
        # Contiguous seconds at the END of the series below the collapse limit --
        # the debounce itself, so a reader can see how close a Degrading verdict
        # came to firing without re-deriving it.
        CollapsedSeconds     = 0
        # How many intervals ANYWHERE in the trailing window were below the limit.
        # Separate from the above because an intermittent stall scatters them and
        # a real collapse runs them together, and only the second fires.
        DegradedIntervals    = 0
        # Recent rate as a percentage of the session's own baseline. Carried as a
        # number so triage can rank severity without re-deriving it from two
        # counters, and so a marker stays readable if the verdict wording changes.
        # $null (not 0) whenever there is no baseline to be a fraction OF.
        FractionOfBaseline   = $null
        # Elapsed time each half of the judgement actually rests on. A capture
        # that says NoBaseline can now show WHY -- too little history, versus
        # history at too low a rate -- which used to need the tick count and a
        # guess at the cadence.
        BaselineSeconds      = 0
        WindowSeconds        = 0
        # Intervals thrown out for being longer than IoMaxSampleIntervalSeconds
        # or non-positive. Counted, never silent: a rate computed over a gap
        # describes no real period, and a discard that leaves no trace is
        # indistinguishable from an interval that never existed.
        DiscardedIntervals   = 0
        # Samples that carried no usable (DeltaOps, DeltaSeconds) pair -- an
        # un-migrated caller still pushing bare numbers, which would otherwise
        # degrade to a silent NoBaseline forever.
        MalformedSamples     = 0
    }

    # ── Normalise to intervals ───────────────────────────────────────────────
    # An interval, not a sample, is the unit that can carry a rate: it is the
    # only thing with both a numerator and a denominator.
    $iv = [System.Collections.ArrayList]::new()
    foreach ($s in $Samples) {
        if ($null -eq $s) { continue }
        $ops = $null; $sec = $null
        try { $ops = $s.DeltaOps; $sec = $s.DeltaSeconds } catch { }
        if ($null -eq $ops -and $null -eq $sec) {
            # Includes a bare number: (5).DeltaOps is $null, so a legacy caller
            # lands here and SAYS SO rather than quietly producing no verdict.
            $result.MalformedSamples++
            continue
        }
        # A sample with no delta is a real observation that opens no interval --
        # the first of a series, or the first after a process change. Neither
        # malformed nor discarded; it contributes nothing to a rate, but it DOES
        # break continuity, for the same reason a discarded interval does.
        if ($null -eq $ops -or $null -eq $sec) {
            [void]$iv.Add(@{ Break = $true; Sec = [double]0 })
            continue
        }
        $secD = [double]$sec
        if ($secD -le 0 -or $secD -gt $script:IoMaxSampleIntervalSeconds) {
            $result.DiscardedIntervals++
            # A DISCONTINUITY MARKER, not a deletion. Dropping the interval
            # outright would splice the two sides of the gap together and let
            # them look adjacent: six quiet seconds, a 31-second hole nobody
            # measured, six more quiet seconds, and the debounce would count a
            # contiguous 12 seconds of collapse across a period it has no
            # observation of at all. The gap is exactly where the reads might
            # have resumed. It carries Sec = 0 so it contributes nothing to any
            # rate, duration or median -- it only stops the contiguity walk.
            [void]$iv.Add(@{ Break = $true; Sec = [double]0 })
            continue
        }
        [void]$iv.Add(@{ Ops = [double]$ops; Sec = $secD; Rate = ([double]$ops / $secD); Break = $false })
    }
    if (@($iv | Where-Object { -not $_.Break }).Count -eq 0) { return $result }

    # ── Split by ELAPSED TIME, not by count ──────────────────────────────────
    # Walk back from the newest interval until the trailing window covers at
    # least IoCollapseSeconds. The interval straddling the boundary belongs to
    # the window, so the window is never SHORTER than the debounce it feeds.
    $windowSec = [double]0
    $splitIdx  = $iv.Count
    for ($i = $iv.Count - 1; $i -ge 0; $i--) {
        $windowSec += $iv[$i].Sec
        $splitIdx = $i
        if ($windowSec -ge $script:IoCollapseSeconds) { break }
    }
    # Stamped BEFORE the early returns. A run that is merely too short still
    # measured a real amount of time, and reporting 0 there would say "nothing
    # was observed" about a period that was observed and found wanting.
    $baselineSec = [double]0
    for ($i = 0; $i -lt $splitIdx; $i++) { $baselineSec += $iv[$i].Sec }
    $result.BaselineSeconds = [math]::Round($baselineSec, 1)
    $result.WindowSeconds   = [math]::Round($windowSec, 1)

    if ($windowSec -lt $script:IoCollapseSeconds) { return $result }
    if ($baselineSec -lt $script:IoBaselineMinSeconds) { return $result }

    # Discontinuity markers are excluded from every RATE calculation below --
    # they carry no ops and no seconds, and exist only for the contiguity walk.
    $window   = @($iv[$splitIdx .. ($iv.Count - 1)] | Where-Object { -not $_.Break })
    $baseline = @($iv[0 .. ($splitIdx - 1)]          | Where-Object { -not $_.Break })
    if ($baseline.Count -eq 0 -or $window.Count -eq 0) { return $result }

    # Median of the per-interval RATES, deliberately unweighted: each interval is
    # an independent estimate of the same rate, and the median's whole job is to
    # be unmoved by the outlier. Weighting by duration would hand the outlier
    # back the influence the median just took away.
    $sorted = @($baseline | ForEach-Object { $_.Rate } | Sort-Object)
    $median = if ($sorted.Count % 2 -eq 1) {
        $sorted[[int](($sorted.Count - 1) / 2)]
    } else {
        ($sorted[($sorted.Count / 2) - 1] + $sorted[$sorted.Count / 2]) / 2
    }
    $result.BaselineOpsPerSecond = [math]::Round($median, 1)

    # Time-weighted, per the note above.
    $winOps = [double]0
    foreach ($w in $window) { $winOps += $w.Ops }
    $recentRate = $winOps / $windowSec
    $result.RecentOpsPerSecond = [math]::Round($recentRate, 1)

    # Reported above BEFORE this return, deliberately: a sub-floor rate is a real
    # measurement and the record should carry it. Only the VERDICT is withheld.
    if ($median -lt $script:IoBaselineMinOpsPerSecond) { return $result }

    $result.FractionOfBaseline = [math]::Round(($recentRate / $median) * 100, 0)

    $limit = $median * $script:IoCollapseFraction
    $result.DegradedIntervals = @($window | Where-Object { $_.Rate -lt $limit }).Count

    # The debounce: contiguous seconds below the limit, counted back from the
    # newest interval. "All four window ticks below" said the same thing at the
    # 3 s target and something different at every other cadence.
    #
    # A DISCONTINUITY ENDS THE RUN, exactly as a healthy interval does. The
    # seconds have to be contiguous in the RECORDING, not merely adjacent in the
    # buffer: an unmeasured gap is the most likely place for the reads to have
    # come back, so counting across it would assert a collapse over a period
    # nothing observed. Erring toward Degrading here is the safe direction --
    # Collapsed is the verdict that fires a fault.
    $contig = [double]0
    for ($i = $iv.Count - 1; $i -ge 0; $i--) {
        if ($iv[$i].Break) { break }
        if ($iv[$i].Rate -lt $limit) { $contig += $iv[$i].Sec } else { break }
    }
    $result.CollapsedSeconds = [math]::Round($contig, 1)

    if ($contig -ge $script:IoCollapseSeconds) {
        $result.Verdict = 'Collapsed'
    } elseif ($contig -gt 0) {
        # The NEWEST interval is under the limit. Not enough to fire a fault --
        # deliberately, so a scheduling hiccup cannot -- but saying "Streaming"
        # here is what let a marked 12006 record itself as healthy.
        #
        # DegradedIntervals deliberately remembers every low interval in the
        # trailing window, but it must not drive the LIVE verdict after reads
        # have recovered. Capture 961FAB4BC165 ended at 777.9/s against a
        # 145.4/s baseline (535% of normal) and still rendered "Reads falling"
        # solely because one earlier low interval remained in the 12-second
        # window. The session-long dip counter keeps that observation; the live
        # state answers what is happening now.
        $result.Verdict = 'Degrading'
    } else {
        $result.Verdict = 'Streaming'
    }
    return $result
}

# =============================================================================
# ACTIVE PORT-OPEN PROBE SETTING (pre-registration section 5.3)
# =============================================================================

# The environment variable that selects the treatment for the hold-probe A-B-A
# control. ONE published build, runtime-selected -- not a compile-time constant
# and not a second artifact, because all three arms must run on a build whose
# identity is byte-identical or the comparison is between two programs.
#
# Named for what it governs. It disables the ACTIVE OPENS specifically
# (Get-ComPortHoldState, i.e. SerialPort.Open on a target port); passive
# observation of the same fact must stay possible under any later mechanism, so
# the name must not claim the whole subject of "hold probing".
$script:ActivePortOpenProbeEnvVar = 'WINCONFIG_ACTIVE_PORT_OPEN_PROBE'

function Get-ActivePortOpenProbeSetting {
    <#
    .SYNOPSIS
        Reads the effective ActivePortOpenProbeEnabled setting ONCE, with the
        provenance of the read attached.
    .DESCRIPTION
        Two requirements that pull in opposite directions, and both are honoured
        here rather than being traded off:

          1. A CLINIC capture must never be silently degraded by a config this
             experiment introduced. So absent or unreadable => active opens
             ENABLED, i.e. exactly today's behaviour.
          2. An EXPERIMENTAL arm must never be scored when the toggle was not
             demonstrably what the protocol said. So the read STATUS is recorded
             beside the value, and anything but a clean explicit read invalidates
             an arm (pre-registration section 3.4(2)).

        A single boolean cannot serve both: `enabled` reached by default and
        `enabled` reached by an operator typing it are the same behaviour and
        completely different evidence. Hence SettingReadStatus.

        This function does NOT cache. Caching would hide a mid-run change, and
        the drift check at session end exists precisely to SEE one. The lock
        against hot-switching lives in the session (New-DeviceProbeSession reads
        this once and every gate reads the session), not in this function.
    .PARAMETER RawValue
        Override for the raw setting text, for tests. When bound -- including as
        an empty string -- the environment is not consulted at all, so a test can
        exercise the missing case without mutating the process environment.
    .OUTPUTS
        [pscustomobject] Enabled, SettingReadStatus, Source, RawValue, Reason.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()]
        [string]$RawValue
    )

    $envName = $script:ActivePortOpenProbeEnvVar
    $raw     = $null
    $source  = "Environment:$envName"
    $status  = 'DefaultedMissing'
    $enabled = $true
    $reason  = $null

    if ($PSBoundParameters.ContainsKey('RawValue')) {
        $raw    = $RawValue
        $source = 'Explicit:RawValue'
    } else {
        try {
            $raw = [System.Environment]::GetEnvironmentVariable($envName)
        } catch {
            # A genuine failure to READ, as opposed to a value that would not
            # parse. Both default to enabled; they are different diagnoses and
            # the operator needs to be able to tell them apart.
            return [pscustomobject]@{
                PSTypeName        = 'WinConfig.FlightRecorder.ActivePortOpenProbeSetting'
                Enabled           = $true
                SettingReadStatus = 'DefaultedError'
                Source            = $source
                RawValue          = $null
                Reason            = "Could not read `$env:$envName ($($_.Exception.Message)); active port-open probe left ENABLED, which is the shipped default."
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        $status  = 'DefaultedMissing'
        $enabled = $true
        $reason  = "`$env:$envName is not set; active port-open probe ENABLED (shipped default)."
    } else {
        # Deliberately a CLOSED set with the common spellings in it. A closed set
        # means a typo lands in DefaultedError where it is visible, instead of
        # being coerced -- PowerShell would read the string 'false' as $true,
        # which is the one wrong answer that looks like a right one.
        switch -Regex ($raw.Trim()) {
            '^(?i)(1|true|on|yes|enabled|enable)$'   { $status = 'Explicit'; $enabled = $true }
            '^(?i)(0|false|off|no|disabled|disable)$' { $status = 'Explicit'; $enabled = $false }
            default {
                $status  = 'DefaultedError'
                $enabled = $true
            }
        }
        $reason = switch ($status) {
            'Explicit'       { "`$env:$envName = '$raw'; active port-open probe $(if ($enabled) { 'ENABLED' } else { 'DISABLED' }) by explicit setting." }
            'DefaultedError' { "`$env:$envName = '$raw', which is not a recognised value; active port-open probe left ENABLED (shipped default). An experimental arm read this way is INVALID." }
        }
    }

    return [pscustomobject]@{
        PSTypeName        = 'WinConfig.FlightRecorder.ActivePortOpenProbeSetting'
        Enabled           = [bool]$enabled
        SettingReadStatus = $status
        Source            = $source
        # The exact text that was read, so a capture can be audited without
        # re-deriving it from a machine nobody still has.
        RawValue          = $raw
        Reason            = $reason
    }
}

function Test-ActivePortOpenProbeEnabled {
    <#
    .SYNOPSIS
        The ONE answerer for "may this code path open a target COM port?".
    .DESCRIPTION
        Reads the value LOCKED onto the session, never the environment. That is
        the whole point: the setting is resolved once, before the first possible
        open, and every gate downstream reads the same frozen answer -- so the
        treatment cannot change halfway through an arm, and a capture cannot
        contain opens taken under two different settings.

        A session from a build or a test that predates the field is treated as
        ENABLED, matching the shipped default and the pre-toggle behaviour.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Session)

    if ($null -eq $Session) { return $true }
    if ($Session -is [hashtable]) {
        if (-not $Session.ContainsKey('ActivePortOpenProbeEnabled')) { return $true }
        if ($null -eq $Session['ActivePortOpenProbeEnabled'])        { return $true }
        return [bool]$Session['ActivePortOpenProbeEnabled']
    }
    $prop = $Session.PSObject.Properties['ActivePortOpenProbeEnabled']
    if (-not $prop -or $null -eq $prop.Value) { return $true }
    return [bool]$prop.Value
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
    return (Get-ComPortOpenObservation -PortName $PortName).CoarseState
}

function Get-ComPortOpenObservation {
    <#
    .SYNOPSIS
        One open attempt against one port, returning the RAW win32 code beside
        the coarse state. This is what Get-ComPortHoldState now runs on.
    .DESCRIPTION
        WHY THE OPEN MECHANISM CHANGED. The recorder took two blocking opens per
        tick and threw the only diagnostic part away: System.IO.Ports.SerialPort
        raises IOException whose HResult is the generic COR_E_IO (0x80131620),
        so 2 (reboot), 121 (device not answering), 433 (dead RFCOMM target,
        reboot without unpairing) and 1231 all collapsed into the single string
        'Unavailable'. A field capture with four Unavailable observations could
        not say which of those it saw, and they need different fixes.

        This makes ONE attempt through the shared primitive
        Invoke-SerialRawOpenAttempt -- the same call the operator-driven probe
        uses -- and keeps the raw code. It REPLACES the existing open. It does
        not add one, and unlike the operator path it never retries and never
        sleeps: the recorder runs during real client sessions.

        FALLBACK IS RECORDED, NOT SILENT. If the CreateFile P/Invoke cannot be
        loaded, the old SerialPort path still answers the coarse question, so a
        clinic capture is never degraded by this change. The observation then
        carries Contract = 'SerialPortLegacy/v1' and a null Win32Error, because
        that path genuinely cannot know the code. A reader must be able to tell
        "no raw code was recorded" from "the raw code was 0".

        THE TWO CONTRACTS MUST NOT BE POOLED. A SerialPort call configures
        DCB/baud and a CreateFile call does not, so their timings measure
        different work. The Contract field is what keeps them separable, and the
        timing accumulators are fed separately on it.
    .OUTPUTS
        [pscustomobject] WinConfig.Serial.OpenAttempt
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortName,
        [string]$Role,
        [string]$Phase = 'Tick'
    )

    if (Get-Command Invoke-SerialRawOpenAttempt -ErrorAction SilentlyContinue) {
        $raw = Invoke-SerialRawOpenAttempt -PortName $PortName -Role $Role -Phase $Phase
        # PRESENCE OF THE FUNCTION IS NOT SUCCESS OF THE API. When
        # Initialize-SerialOpenApi cannot Add-Type, the primitive still returns
        # -- with Attempted = $false and no code. Returning that here would have
        # meant NO open was made at all and the coarse state read 'Unknown',
        # which is a silently degraded capture: exactly what the fallback exists
        # to prevent, and what this branch previously did.
        if ($raw -and $raw.Attempted) { return $raw }
    }

    # --- Legacy path: coarse state only, and it says so. ---
    $attemptedAt = (Get-Date).ToUniversalTime()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $state = 'Unknown'
    $sp = $null
    try {
        $sp = New-Object System.IO.Ports.SerialPort $PortName
        $sp.Open()
        $sp.Close()
        $state = 'Free'
    } catch [System.UnauthorizedAccessException] {
        $state = 'Held'
    } catch [System.IO.IOException] {
        $state = 'Unavailable'
    } catch {
        $state = 'Unknown'
    } finally {
        if ($sp) { try { $sp.Dispose() } catch { } }
    }
    $sw.Stop()

    return [pscustomobject]@{
        PSTypeName     = 'WinConfig.Serial.OpenAttempt'
        PortName       = $PortName
        Role           = $Role
        Phase          = $Phase
        TimestampIso   = $attemptedAt.ToString('o')
        Attempted      = $true
        Win32Error     = $null
        ElapsedMs      = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
        HandleAcquired = ($state -eq 'Free')
        CoarseState    = $state
        Contract       = 'SerialPortLegacy/v1'
        Unavailable    = 'Raw win32 code not observable through System.IO.Ports'
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

function Get-ActiveOpenDecision {
    <#
    .SYNOPSIS
        Pure. Decides whether THIS tick may take an exclusive handle on the
        target's COM ports, and says why.
    .DESCRIPTION
        WHY THIS EXISTS. Measured 2026-08-19, from our own captures and from an
        independent sampler outside the process:

          * The probe owns at least one of the Arc's serial ports for **12-23 %
            of every window in which no other process holds them** -- 23.3 % over
            the 79 s pre-streaming window of capture 026B63C26C4D, 15.6 % over
            the device-present span of E470A928F98C. The shipped headline said
            4.6 % / 11.8 % because it divided by the whole recording, including
            the streaming ticks where the open is refused at ~0 ms and no handle
            is ever taken.
          * A held port **fails a NO session start outright** -- instantly, with
            no retry, reporting 12005 "No valid Headset at port COMn" (P11,
            2026-08-19, against a control that started normally seconds later).
          * A handle held across a device REMOVAL strands the registration
            permanently. Reproduced end to end the same afternoon, with NO itself
            as the holder: both of the Arc's channels stranded, both names reused
            by the next pairing, both symlinks resolving to the corpses.

        Together those make the tick loop's unconditional open a genuine hazard
        rather than an academic one: a diagnostic that can manufacture the fault
        it was sent to observe. This function is the throttle.

        THE RULES, in order, and each one is a separate decision:

          1. Non-tick phases (Selection / Startup / Anomaly) ALWAYS probe. They
             are one-shot, they are the cold opens that carry the most diagnostic
             value, and backing them off would trade the whole point of the
             snapshot for nothing.
          2. TEARDOWN INTERLOCK. If the target device is not currently resolvable
             -- device Missing, or no COM port matched -- do not open. That is
             the removal window, the only window in which an open can strand a
             registration, and there is nothing to learn from an open that is
             about to fail anyway.
          3. ANY CHANGE RESETS THE STREAK. A different port set, a change in
             whether the application is running, or a change in radio link state
             all mean the world moved and the next observation is worth its cost.
          4. Otherwise back off once the answer has been the same for
             StreakBeforeBackoff ticks: probe one tick in BackoffCadence.

        WHAT THE BACKOFF COSTS, stated rather than hidden: a transition from free
        to held can be observed up to (BackoffCadence - 1) ticks late, so a
        session start may be stamped up to ~12 s after it happened. The read-rate
        baseline is scoped to port-held windows and takes ~99 s to establish, so
        a 12 s clip at the head is tolerable. Rule 3 exists to keep that cost
        bounded to genuinely quiet stretches -- the moment anything moves, the
        cadence returns to every tick.

        A DENIED open is free (~0 ms, no handle) and a SUCCESSFUL one is not.
        The backoff therefore only ever suppresses the expensive, hazardous case,
        which is why the streak counts consecutive ticks where we ACQUIRED.
    .PARAMETER Session
        Read for the streak state and the last-seen world. Mutated only by
        Set-ActiveOpenStreak, never here -- this function is pure so it can be
        tested without a session at all.
    .PARAMETER Phase
        'Selection' | 'Startup' | 'Tick' | 'Anomaly'.
    .OUTPUTS
        [pscustomobject] Probe (bool), Reason (string), Rule (string).
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Selection', 'Startup', 'Tick', 'Anomaly')]
        [string]$Phase = 'Tick',
        [int]$TickCount = 0,
        [int]$AcquiredStreak = 0,
        [bool]$WorldChanged = $false,
        [bool]$TargetResolvable = $true,
        [int]$StreakBeforeBackoff = 3,
        [int]$BackoffCadence = 5
    )

    if ($Phase -ne 'Tick') {
        return [pscustomobject]@{ Probe = $true; Rule = 'NonTickPhase'; Reason = "Phase '$Phase' is a one-shot snapshot; it always probes." }
    }
    if (-not $TargetResolvable) {
        return [pscustomobject]@{ Probe = $false; Rule = 'TeardownInterlock'; Reason = 'The target device is not currently resolvable (removed, or no COM port matched). An open here cannot succeed and is the one condition under which a handle can strand a registration.' }
    }
    if ($WorldChanged) {
        return [pscustomobject]@{ Probe = $true; Rule = 'WorldChanged'; Reason = 'The port set, the application process state, or the radio link state changed since the last tick; the next observation is worth taking.' }
    }
    if ($AcquiredStreak -lt $StreakBeforeBackoff) {
        return [pscustomobject]@{ Probe = $true; Rule = 'WarmUp'; Reason = "Only $AcquiredStreak consecutive ticks have acquired the handle (backoff begins at $StreakBeforeBackoff)." }
    }
    if ($BackoffCadence -le 1 -or ($TickCount % $BackoffCadence) -eq 0) {
        return [pscustomobject]@{ Probe = $true; Rule = 'BackoffCadence'; Reason = "Backoff is active and this is the 1-in-$BackoffCadence tick that still probes." }
    }
    return [pscustomobject]@{ Probe = $false; Rule = 'BackoffSkip'; Reason = "Nothing has held these ports for $AcquiredStreak consecutive ticks and nothing changed; skipping the open rather than taking a handle that would tell us what we already know." }
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
    .PARAMETER Session
        The probe session, read ONLY for the locked ActivePortOpenProbeEnabled
        setting. Omitted => enabled, which is the shipped default and what every
        pre-toggle caller and test mock means.
    .PARAMETER Phase
        Which part of the recording these opens belong to. This function serves
        BOTH the tick loop and the arrival snapshot, and the arrival opens are
        the COLD ones -- the slowest, and the first chance in a session to see
        433. Hardcoding 'Tick' filed them under the wrong phase, which is the
        same downward bias #83 was filed to remove, so the caller states it.
        Defaults to 'Tick' for every pre-existing caller and test mock.
    .OUTPUTS
        [hashtable] State ('Active'/'Stopped'/'Unknown'/'DisabledBySetting'),
        ActivePort, HeldPorts, UnavailablePorts.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$WatchState,
        $Session,
        [ValidateSet('Selection', 'Startup', 'Tick', 'Anomaly')]
        [string]$Phase = 'Tick'
    )

    # ── The gate, FIRST ──────────────────────────────────────────────────
    # Before the ComPortState check and before anything that could enumerate
    # ports, so no path through this function can reach an open. The whole
    # treatment in the A-B-A control is this branch.
    #
    # It returns a state of its own -- NOT 'Stopped'. 'Stopped' is a
    # MEASUREMENT: it means the probe opened every target port and found none of
    # them held. Returning it here would manufacture that measurement out of a
    # config flag, and every downstream consumer would then honestly report a
    # stream that stopped. The keys a held-port reader wants are OMITTED rather
    # than emptied, for the same reason: an empty set is an observation that
    # nothing was held, and nothing observed anything.
    if (-not (Test-ActivePortOpenProbeEnabled -Session $Session)) {
        return @{
            State                = 'DisabledBySetting'
            ActivePort           = $null
            ActiveProbeDisabled  = $true
            # PortOpenDurations is present and EMPTY, unlike the port lists,
            # because it measures an ACTION this function took. Zero opens over
            # zero milliseconds is a true statement about what was done; an
            # empty held-port list would be a false statement about what is.
            PortOpenDurations    = @()
            # Same reasoning for the raw-code channel: zero attempts is a true
            # statement about what this function did, and an empty list keeps a
            # reader from inferring that attempts were made and all succeeded.
            PortOpenObservations = @()
        }
    }

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

    # ── The throttle ─────────────────────────────────────────────────────
    # Placed AFTER port resolution (which opens nothing) and BEFORE the first
    # open, so a skipped tick costs one registry read rather than two RFCOMM
    # channel setups over the air. See Get-ActiveOpenDecision for the measured
    # basis: 12-23 % occupancy of the uncontended window, a held port failing a
    # NO session start outright, and a handle held across a removal stranding a
    # registration permanently.
    #
    # Sessions that predate this (older callers, test mocks, $null) have none of
    # the state keys, so $sessionHas is false throughout and every tick probes --
    # exactly the pre-existing behaviour. The throttle can only ever REDUCE opens
    # on a session that opted in by carrying the fields.
    $sessionHas = ($Session -is [hashtable]) -and $Session.ContainsKey('ActiveOpenAcquiredStreak')
    if ($sessionHas) {
        # The "world" is the set of facts that, if any of them moved, make the
        # next observation worth its cost. Deliberately NOT the held set itself:
        # that is the thing being measured, and keying the decision to measure on
        # the measurement is how a detector goes blind.
        # StrictMode makes an absent hashtable key THROW, and WatchState is
        # hand-built by several callers and by every test mock -- a missing
        # DeviceState must degrade to "unknown", never take the tick down.
        $wsGet = {
            param($Key)
            if ($null -eq $WatchState) { return '' }
            if ($WatchState -is [hashtable]) {
                if ($WatchState.ContainsKey($Key)) { return [string]$WatchState[$Key] } else { return '' }
            }
            $prop = $WatchState.PSObject.Properties[$Key]
            if ($prop) { return [string]$prop.Value } else { return '' }
        }
        $wsAppState    = & $wsGet 'AppProcessState'
        $wsDeviceState = & $wsGet 'DeviceState'
        $worldNow = @(
            ($ports -join ',')
            $wsAppState
            $wsDeviceState
            $(if ($Session.ContainsKey('BtLinkState')) { [string]$Session.BtLinkState } else { '' })
        ) -join '|'
        $worldChanged = ($Session.ActiveOpenLastWorld -ne $worldNow)

        $decision = Get-ActiveOpenDecision -Phase $Phase `
            -TickCount ([int]$Session.TickCount) `
            -AcquiredStreak ([int]$Session.ActiveOpenAcquiredStreak) `
            -WorldChanged $worldChanged `
            -TargetResolvable ($wsDeviceState -ne 'Missing') `
            -StreakBeforeBackoff ([int]$Session.ActiveOpenStreakBeforeBackoff) `
            -BackoffCadence ([int]$Session.ActiveOpenBackoffCadence)

        $Session.ActiveOpenLastWorld = $worldNow

        if (-not $decision.Probe) {
            $Session.ActiveOpenSkippedTicks++
            # CARRY FORWARD, do not invent. Returning 'Stopped' would manufacture
            # the measurement "the probe opened every port and found none held"
            # out of a decision not to look -- the same error the
            # DisabledBySetting branch above exists to avoid. The backoff's whole
            # premise is that nothing changed, so the previous answer is the
            # honest one to repeat, and it is stamped as CARRIED so no reader can
            # mistake it for a fresh observation.
            #
            # PortOpenDurations and PortOpenObservations are present and EMPTY:
            # zero opens over zero milliseconds is a true statement about what
            # this tick did, and it keeps the timing accumulators and the
            # attempt counters from counting a tick that never opened anything.
            $carriedHeld = @($(if ($Session.ContainsKey('HeldPorts')) { $Session.HeldPorts } else { @() }) | Where-Object { $_ })
            return @{
                State                = $(if ($carriedHeld.Count -gt 0) { 'Active' } else { 'Stopped' })
                ActivePort           = $(if ($carriedHeld.Count -gt 0) { ($carriedHeld -join ', ') } else { $null })
                HeldPorts            = $carriedHeld
                UnavailablePorts     = @($(if ($Session.ContainsKey('UnavailablePortsCurrent')) { $Session.UnavailablePortsCurrent } else { @() }) | Where-Object { $_ })
                OpenedPorts          = @()
                ProbedPorts          = @()
                PortOpenDurations    = @()
                PortOpenObservations = @()
                ActiveOpenCarried    = $true
                ActiveOpenSkipRule   = $decision.Rule
                ActiveOpenSkipReason = $decision.Reason
            }
        }
        $Session.ActiveOpenProbedTicks++
    }

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
    # ONE attempt per port, exactly as before -- the mechanism changed, the
    # number of opens did not. The attempt now times itself and returns the raw
    # win32 code, so there is no second call and no stopwatch wrapped around a
    # call that already measured itself.
    $durations    = @()
    $observations = @()
    foreach ($p in $ports) {
        $obs = Get-ComPortOpenObservation -PortName $p -Phase $Phase
        $holdState = $obs.CoarseState
        $observations += $obs
        $durations += @{
            Port       = $p
            State      = $holdState
            # 0 only when no attempt was made, in which case State is 'Unknown'
            # and the timing folder counts nothing for it.
            DurationMs = $(if ($null -ne $obs.ElapsedMs) { [double]$obs.ElapsedMs } else { [double]0 })
            Win32Error = $obs.Win32Error
            Contract   = $obs.Contract
        }
        switch ($holdState) {
            'Held'        { $activePorts += $p }
            'Unavailable' { $deadPorts   += $p }
            'Free'        { $openedPorts += $p }
        }
    }

    # Streak bookkeeping for the throttle. Counts consecutive ticks on which we
    # ACQUIRED every port and nothing was held or unavailable -- the only shape
    # that is both expensive (a real handle, an RFCOMM setup over the air) and
    # uninformative (the same answer as last time). A held or unavailable port
    # resets it, because those are the transitions worth catching promptly.
    if ($sessionHas) {
        if ($activePorts.Count -eq 0 -and $deadPorts.Count -eq 0 -and $openedPorts.Count -eq $ports.Count) {
            $Session.ActiveOpenAcquiredStreak++
        } else {
            $Session.ActiveOpenAcquiredStreak = 0
        }
    }

    if ($activePorts.Count -gt 0) {
        return @{
            State                = 'Active'
            ActivePort           = ($activePorts -join ', ')
            HeldPorts            = @($activePorts)
            UnavailablePorts     = @($deadPorts)
            OpenedPorts          = @($openedPorts)
            ProbedPorts          = @($ports)
            PortOpenDurations    = @($durations)
            PortOpenObservations = @($observations)
        }
    }
    return @{
        State = 'Stopped'; ActivePort = $null; HeldPorts = @()
        UnavailablePorts = @($deadPorts); OpenedPorts = @($openedPorts); ProbedPorts = @($ports)
        PortOpenDurations = @($durations)
        PortOpenObservations = @($observations)
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
        # CONTRACT SEGREGATION. This accumulator's Basis string describes a
        # System.IO.Ports call. A CreateFile attempt measures different work
        # (no DCB/baud configuration), so folding one into the other would
        # produce a number that matches neither and is labelled as the wrong
        # one. Raw-contract samples belong to Get-SerialOpenAttemptReport;
        # entries with no Contract are legacy by definition, which is what
        # every pre-existing caller supplies.
        $contract = try { [string]$d.Contract } catch { '' }
        if (-not [string]::IsNullOrWhiteSpace($contract) -and $contract -ne 'SerialPortLegacy/v1') { continue }
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

# THE evidence schema version. ONE constant, one owner. Every artifact that
# needs to state which shape it was written in reads this; a second literal
# somewhere else is how two halves of an archive come to claim different
# versions. Bump when a capture's evidence SHAPE changes in a way a reader
# must branch on -- not for additive fields a reader can ignore.
$script:BtEvidenceSchemaVersion = '1.0.0'

function Get-BtEvidenceProvenance {
    <#
    .SYNOPSIS
        Answers "which build produced this capture, and how were its port opens
        measured" -- so an archive is attributable without asking the operator.
    .DESCRIPTION
        Every field capture so far has been unattributable: nothing in the
        manifest carried a build id, so a package could not be tied to the code
        that wrote it. That is fine until two builds disagree, at which point
        the corpus cannot be split and every conclusion drawn across it is
        suspect.

        NEVER THROWS, NEVER BLOCKS A RECORDING. Provenance is metadata about the
        evidence; failing to read it must not cost the evidence. Missing or
        malformed input renders as a NULL value with an explicit read status,
        which is a different fact from a commit that was read cleanly.

        THE OPEN CONTRACT IS DERIVED, NOT DECLARED. Hardcoding
        CreateFileRawWin32/v1 would be a claim rather than an observation, and
        it would be WRONG for a legitimate fallback capture that ran on
        SerialPortLegacy/v1. A run with the probe disabled, or one that never
        reached a port, observed no contract at all and says so.
    .PARAMETER SerialOpenRecord
        The session's raw-open accumulator. Omitted or empty => the contract
        renders as NotObserved.
    .PARAMETER SourceCommitRawValue
        Override for the raw commit text, for tests. When bound -- INCLUDING as
        an empty string -- the environment is not consulted at all, so a test
        can exercise the missing case without mutating the process environment.
    .OUTPUTS
        [pscustomobject] WinConfig.Evidence.Provenance
    #>
    [CmdletBinding()]
    param(
        $SerialOpenRecord,
        [AllowNull()][AllowEmptyString()][string]$SourceCommitRawValue
    )

    $raw = if ($PSBoundParameters.ContainsKey('SourceCommitRawValue')) {
        $SourceCommitRawValue
    } else {
        # Bootstrap sets this, and explicitly sets it to $null on its own error
        # path, so absent is a REAL case rather than a theoretical one.
        $env:WINCONFIG_SOURCE_COMMIT
    }

    $commit = $null
    $status = 'Missing'
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $status = 'Missing'
    } elseif ($raw -match '^[0-9a-fA-F]{7,40}$') {
        $commit = $raw.ToLowerInvariant()
        $status = 'Explicit'
    } else {
        # Kept as raw text, not coerced. A value that is present but not a
        # commit is evidence about the build pipeline, and silently nulling it
        # would hide that.
        $status = 'Malformed'
    }

    $contracts = @()
    if ($SerialOpenRecord -is [hashtable]) {
        $rawCount    = try { [int]$SerialOpenRecord.AttemptCount } catch { 0 }
        $legacyCount = try { [int]$SerialOpenRecord.LegacyContractCount } catch { 0 }
        if ($rawCount -gt 0)    { $contracts += [string]$SerialOpenRecord.Contract }
        if ($legacyCount -gt 0) { $contracts += 'SerialPortLegacy/v1' }
    }
    $contracts = @($contracts | Where-Object { $_ } | Select-Object -Unique)

    # Mixed is a real outcome, not an error: the P/Invoke can be available for
    # part of a run and not another. It renders as Mixed with both listed
    # rather than as whichever happened to be counted first.
    $contractStatus = switch ($contracts.Count) {
        0       { 'NotObserved' }
        1       { 'Single' }
        default { 'Mixed' }
    }

    return [pscustomobject]@{
        PSTypeName                  = 'WinConfig.Evidence.Provenance'
        EvidenceSchemaVersion       = $script:BtEvidenceSchemaVersion
        SourceCommit                = $commit
        SourceCommitReadStatus      = $status
        SourceCommitRawValue        = $(if ([string]::IsNullOrWhiteSpace($raw)) { $null } else { [string]$raw })
        SerialOpenContract          = $(if ($contracts.Count -eq 1) { $contracts[0] } else { $null })
        SerialOpenContractStatus    = $contractStatus
        SerialOpenContractsObserved = @($contracts)
    }
}

function New-BluetoothEventEvidenceRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [datetime]$WindowStart = (Get-Date).AddMinutes(-10),
        [int]$MaxEvents = 2500
    )

    return @{
        Contract            = 'WinConfig.BluetoothEventEvidence/v1'
        WindowStart         = $WindowStart
        MaxEvents           = [Math]::Max(1, $MaxEvents)
        Events              = @()
        EventKeys           = @()
        Seen                = @{}
        Queries             = @()
        Failures            = @()
        PollCount           = 0
        DuplicateCount      = 0
        DroppedEventCount   = 0
        DroppedQueryCount   = 0
        DroppedFailureCount = 0
        FinalDrainStatus    = 'NotAttempted'
        FinalDrainReason    = $null
        FinalDrainAt        = $null
        LastCollectorAt     = $null
    }
}

function Add-BluetoothEventEvidenceBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [AllowNull()]$Batch,
        [AllowNull()][string]$CollectorError
    )

    if ($Record -isnot [hashtable]) {
        return [pscustomobject]@{ AcceptedCount = 0; AcceptedEvents = @(); NextSince = $null }
    }

    $Record.PollCount++
    $capturedAt = Get-Date
    if ($null -ne $Batch -and @($Batch.PSObject.Properties.Name) -contains 'CapturedAt' -and $Batch.CapturedAt) {
        $capturedAt = [datetime]$Batch.CapturedAt
    }
    $Record.LastCollectorAt = $capturedAt

    if (-not [string]::IsNullOrWhiteSpace($CollectorError)) {
        $Record.Failures += [pscustomobject]@{
            At       = $capturedAt
            LogName  = '(collector)'
            Provider = $null
            Reason   = $CollectorError
        }
    }

    $batchProperties = if ($null -eq $Batch) {
        @()
    } elseif ($Batch -is [System.Collections.IDictionary]) {
        @($Batch.Keys)
    } else {
        @($Batch.PSObject.Properties.Name)
    }
    if ($batchProperties -contains 'Failures') {
        foreach ($failure in @($Batch.Failures)) {
            $Record.Failures += [pscustomobject]@{
                At       = $capturedAt
                LogName  = if ($failure.Log) { [string]$failure.Log } else { $null }
                Provider = if ($failure.Provider) { [string]$failure.Provider } else { $null }
                Reason   = [string]$failure.Reason
            }
        }
    }
    if ($batchProperties -contains 'Queries') {
        $Record.Queries += @($Batch.Queries)
    }
    while ($Record.Failures.Count -gt $Record.MaxEvents) {
        $Record.Failures = @($Record.Failures | Select-Object -Skip 1)
        $Record.DroppedFailureCount++
    }
    while ($Record.Queries.Count -gt ($Record.MaxEvents * 4)) {
        $Record.Queries = @($Record.Queries | Select-Object -Skip 1)
        $Record.DroppedQueryCount++
    }

    $accepted = 0
    $acceptedEvents = @()
    if ($batchProperties -contains 'Events') {
        foreach ($eventRow in @($Batch.Events)) {
            if ($null -eq $eventRow) { continue }
            $names = if ($eventRow -is [System.Collections.IDictionary]) { @($eventRow.Keys) } else { @($eventRow.PSObject.Properties.Name) }
            $logName = if ($names -contains 'LogName') { [string]$eventRow.LogName } else { '' }
            $recordId = if ($names -contains 'RecordId' -and $null -ne $eventRow.RecordId) { [string]$eventRow.RecordId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($recordId)) {
                $key = 'record|{0}|{1}' -f $logName.ToLowerInvariant(), $recordId
            } else {
                $provider = if ($names -contains 'ProviderName') { [string]$eventRow.ProviderName } else { '' }
                $id = if ($names -contains 'Id') { [string]$eventRow.Id } else { '' }
                $time = if ($names -contains 'TimeCreated' -and $eventRow.TimeCreated) { ([datetime]$eventRow.TimeCreated).ToUniversalTime().Ticks } else { 0 }
                $body = if ($names -contains 'Xml' -and $eventRow.Xml) { [string]$eventRow.Xml } elseif ($names -contains 'Message') { [string]$eventRow.Message } else { '' }
                $key = 'fallback|{0}|{1}|{2}|{3}|{4}' -f $logName.ToLowerInvariant(), $provider.ToLowerInvariant(), $id, $time, $body
            }
            if ($Record.Seen.ContainsKey($key)) {
                $Record.DuplicateCount++
                continue
            }
            $Record.Seen[$key] = $true
            $Record.Events += $eventRow
            $Record.EventKeys += $key
            $accepted++
            $acceptedEvents += $eventRow
            while ($Record.Events.Count -gt $Record.MaxEvents) {
                $droppedKey = $Record.EventKeys[0]
                $Record.Events = @($Record.Events | Select-Object -Skip 1)
                $Record.EventKeys = @($Record.EventKeys | Select-Object -Skip 1)
                [void]$Record.Seen.Remove($droppedKey)
                $Record.DroppedEventCount++
            }
        }
    }

    # Event-log commits can trail the event timestamp. Re-query a generous
    # overlap and rely on LogName+RecordId deduplication; advancing to the exact
    # capture time can permanently miss a late-arriving authentication row.
    $nextSince = $capturedAt.AddSeconds(-30)
    return [pscustomobject]@{ AcceptedCount = $accepted; AcceptedEvents = @($acceptedEvents); NextSince = $nextSince }
}

function Set-BluetoothEventEvidenceFinalDrain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][ValidateSet('Collected', 'Failed', 'TimedOut')][string]$Status,
        [AllowNull()][string]$Reason
    )
    if ($Record -isnot [hashtable]) { return $false }
    $Record.FinalDrainStatus = $Status
    $Record.FinalDrainReason = $Reason
    $Record.FinalDrainAt = Get-Date
    return $true
}

function Get-BluetoothEventEvidenceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [AllowNull()][string]$TargetMac
    )

    if ($Record -isnot [hashtable]) { return $null }
    $normalizedTarget = if ($TargetMac) { ($TargetMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } else { '' }
    $structuredMatches = 0
    $messageOnlyMatches = 0
    if ($normalizedTarget) {
        foreach ($eventRow in @($Record.Events)) {
            $eventNames = if ($eventRow -is [System.Collections.IDictionary]) { @($eventRow.Keys) } else { @($eventRow.PSObject.Properties.Name) }
            $eventDataValues = if ($eventNames -contains 'EventData') { @($eventRow.EventData | ForEach-Object { [string]$_.Value }) } else { @() }
            # Do not search the rendered Message (which may also appear under
            # RenderingInfo in XML) as structured evidence. Only event payload
            # values can establish a target match; localized text stays context.
            $structuredText = $eventDataValues -join ' '
            $structuredNormalized = ($structuredText -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($structuredNormalized -like "*$normalizedTarget*") {
                $structuredMatches++
            } else {
                $messageValue = if ($eventNames -contains 'Message') { [string]$eventRow.Message } else { '' }
                $messageNormalized = ($messageValue -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                if ($messageNormalized -like "*$normalizedTarget*") { $messageOnlyMatches++ }
            }
        }
    }

    $queryFailures = @($Record.Queries | Where-Object { $_.Status -eq 'Failed' }).Count
    $queryTruncations = @($Record.Queries | Where-Object { $_.HitLimit }).Count
    # ProviderAbsent is a static fact about the box, kept apart from Failed so
    # a reader can tell "this host does not have that provider" from "a query
    # broke" -- conflating them put 657 phantom failures into a healthy capture.
    $providerAbsentQueries = @($Record.Queries | Where-Object { $_.Status -eq 'ProviderAbsent' })
    $absentProviders = @($providerAbsentQueries | ForEach-Object { [string]$_.ProviderName } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
    return [pscustomobject]@{
        PSTypeName                 = 'WinConfig.BluetoothEventEvidence.Report'
        Contract                   = $Record.Contract
        WindowStart                = $Record.WindowStart
        LastCollectorAt            = $Record.LastCollectorAt
        EventCount                 = @($Record.Events).Count
        Events                     = @($Record.Events | Sort-Object TimeCreated, LogName, RecordId)
        PollCount                  = [int]$Record.PollCount
        DuplicateCount             = [int]$Record.DuplicateCount
        DroppedEventCount          = [int]$Record.DroppedEventCount
        MaxEvents                  = [int]$Record.MaxEvents
        QueryCount                 = @($Record.Queries).Count
        QueryFailureCount          = $queryFailures
        QueryHitLimitCount         = $queryTruncations
        QueryProviderAbsentCount   = @($providerAbsentQueries).Count
        AbsentProviders            = $absentProviders
        DroppedQueryCount          = [int]$Record.DroppedQueryCount
        Queries                    = @($Record.Queries)
        FailureCount               = @($Record.Failures).Count
        DroppedFailureCount        = [int]$Record.DroppedFailureCount
        Failures                   = @($Record.Failures)
        FinalDrainStatus           = $Record.FinalDrainStatus
        FinalDrainReason           = $Record.FinalDrainReason
        FinalDrainAt               = $Record.FinalDrainAt
        TargetMac                  = if ($normalizedTarget) { $normalizedTarget } else { $null }
        StructuredTargetMatchCount = $structuredMatches
        MessageOnlyTargetMatchCount = $messageOnlyMatches
        MessageDiagnosticUse       = 'ContextOnlyLocalized'
    }
}

function Complete-SerialOpenTopologyRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [AllowNull()]$Snapshot,
        [AllowNull()][string]$FailureReason
    )

    if ($Record -isnot [hashtable] -or $null -eq $Record.TopologyRequest) { return $false }
    $request = $Record.TopologyRequest
    if ($request.Status -ne 'Pending') { return $false }
    $request['CollectedAt'] = (Get-Date).ToString('o')
    if (-not [string]::IsNullOrWhiteSpace($FailureReason) -or $null -eq $Snapshot) {
        $request.Status = 'Failed'
        $request.Snapshot = $null
        $request['FailureReason'] = if ($FailureReason) { $FailureReason } else { 'Topology collector returned no snapshot.' }
    } else {
        $request.Status = 'Collected'
        $request.Snapshot = $Snapshot
        $request['FailureReason'] = $null
    }
    return $true
}

function New-SerialOpenAttemptRecord {
    <#
    .SYNOPSIS
        Creates the session accumulator for raw open attempts.
    .DESCRIPTION
        AGGREGATE, NEVER A ROW PER TICK. A 524-tick recording over four ports is
        ~2000 attempts; storing each one would bloat every archive to describe a
        session whose answer is usually "the same code, over and over". What a
        reader actually needs is: which codes did this port produce, how often,
        how long did each take, when was each first and last seen, and WHEN DID
        THE CODE CHANGE. Transitions are the expensive-to-reconstruct part, so
        they are kept explicitly and everything else is folded.
    .OUTPUTS
        [hashtable]
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([int]$MaxTransitions = 200)

    return @{
        Contract               = 'CreateFileRawWin32/v1'
        Ports                  = @{}
        AttemptCount           = 0
        NotAttemptedCount      = 0
        LegacyContractCount    = 0
        Transitions            = @()
        MaxTransitions         = $MaxTransitions
        DroppedTransitionCount = 0
        TopologyRequest        = $null
    }
}

function Add-SerialOpenAttempt {
    <#
    .SYNOPSIS
        Folds ONE open observation into the session record, in place.
    .DESCRIPTION
        Tolerant by design: this runs inside the recording loop, and a malformed
        observation must not take the tick down.

        Also raises the TOPOLOGY REQUEST. The first time a port produces a code
        that indicates a dead or missing target (2 or 433), this sets a pending
        request so a background collector can capture the serial topology ONCE.
        It does no topology work itself -- nothing here may touch the tick
        thread beyond folding numbers.
    .PARAMETER Record
        Accumulator from New-SerialOpenAttemptRecord.
    .PARAMETER Observation
        A WinConfig.Serial.OpenAttempt from Get-ComPortOpenObservation.
    .OUTPUTS
        [bool] whether the observation was accepted.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][AllowNull()]$Observation
    )

    if ($Record -isnot [hashtable]) { return $false }
    if ($null -eq $Observation)     { return $false }

    $names = @($Observation.PSObject.Properties.Name)
    $port  = if ($names -contains 'PortName') { [string]$Observation.PortName } else { '' }
    if ([string]::IsNullOrWhiteSpace($port)) { return $false }

    $contract = if ($names -contains 'Contract') { [string]$Observation.Contract } else { '' }
    if ($contract -ne $Record.Contract) {
        # A legacy SerialPort observation carries no win32 code. Count it so the
        # archive can say the raw-code channel was NOT available, rather than
        # letting a reader infer from an empty code table that nothing failed.
        $Record.LegacyContractCount++
        return $false
    }

    $attempted = if ($names -contains 'Attempted') { [bool]$Observation.Attempted } else { $false }
    if (-not $attempted) {
        $Record.NotAttemptedCount++
        return $false
    }

    $code = if ($names -contains 'Win32Error' -and $null -ne $Observation.Win32Error) { [int]$Observation.Win32Error } else { $null }
    if ($null -eq $code) { $Record.NotAttemptedCount++; return $false }

    $ms   = if ($names -contains 'ElapsedMs' -and $null -ne $Observation.ElapsedMs) { [double]$Observation.ElapsedMs } else { [double]0 }
    $iso  = if ($names -contains 'TimestampIso') { [string]$Observation.TimestampIso } else { '' }
    $ph   = if ($names -contains 'Phase' -and -not [string]::IsNullOrWhiteSpace([string]$Observation.Phase)) { [string]$Observation.Phase } else { 'Unknown' }
    $role = if ($names -contains 'Role') { [string]$Observation.Role } else { '' }

    if (-not $Record.Ports.ContainsKey($port)) {
        $Record.Ports[$port] = @{
            Role     = $role
            Codes    = @{}
            LastCode = $null
            Phases   = @{}
        }
    }
    $pe = $Record.Ports[$port]
    if ([string]::IsNullOrWhiteSpace($pe.Role) -and -not [string]::IsNullOrWhiteSpace($role)) { $pe.Role = $role }

    $key = [string]$code
    if (-not $pe.Codes.ContainsKey($key)) {
        $pe.Codes[$key] = @{
            Code      = $code
            Count     = 0
            FirstIso  = $iso
            LastIso   = $iso
            TotalMs   = [double]0
            MinMs     = $ms
            MaxMs     = $ms
        }
    }
    $ce = $pe.Codes[$key]
    $ce.Count++
    $ce.LastIso = $iso
    $ce.TotalMs += $ms
    if ($ms -lt $ce.MinMs) { $ce.MinMs = $ms }
    if ($ms -gt $ce.MaxMs) { $ce.MaxMs = $ms }

    if (-not $pe.Phases.ContainsKey($ph)) { $pe.Phases[$ph] = 0 }
    $pe.Phases[$ph]++

    # Code CHANGE, not code presence. This is the sequence a reader cannot
    # rebuild from counts alone: healthy -> 433 at a known instant is the Modern
    # Standby signature; 433 from the first tick is a box that arrived broken.
    if ($null -ne $pe.LastCode -and $pe.LastCode -ne $code) {
        if ($Record.Transitions.Count -lt $Record.MaxTransitions) {
            $Record.Transitions += @{ Port = $port; FromCode = $pe.LastCode; ToCode = $code; AtIso = $iso; Phase = $ph }
        } else {
            # Bounded, and the drop is COUNTED. A silently truncated list reads
            # as a session that stopped flapping.
            $Record.DroppedTransitionCount++
        }
    }
    $pe.LastCode = $code
    $Record.AttemptCount++

    # Single-flight: first interesting code only, and never overwritten.
    if ($null -eq $Record.TopologyRequest -and ($code -eq 433 -or $code -eq 2)) {
        $Record.TopologyRequest = @{
            Reason      = "FirstWin32Code:$code"
            Port        = $port
            Phase       = $ph
            RequestedAt = $iso
            Status      = 'Pending'
            Snapshot    = $null
        }
    }

    return $true
}

function Get-SerialOpenAttemptReport {
    <#
    .SYNOPSIS
        Renders the session's raw open-attempt evidence.
    .DESCRIPTION
        Supersedes PortOpenTiming for captures taken through the CreateFile
        primitive, and carries the invasiveness accounting (#83) that the legacy
        key carried, so nothing is lost by the switch.

        THE TWO KEYS MUST NEVER BE POOLED. PortOpenTiming measured a
        System.IO.Ports call, which configures DCB/baud; this measures a bare
        CreateFile, which does not. Same units, different work. Contract is
        emitted so a reader cannot merge them by accident, and a capture that
        used the legacy path emits the legacy key instead of this one.
    .PARAMETER Record
        Accumulator from New-SerialOpenAttemptRecord.
    .PARAMETER RecordingSeconds
        Total recording length, for the observer-effect percentage. Omit and the
        percentage renders as absent rather than as 0.
    .OUTPUTS
        [pscustomobject] or $null when nothing was observed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [double]$RecordingSeconds = 0
    )

    if ($Record -isnot [hashtable]) { return $null }
    if ($Record.AttemptCount -le 0 -and $Record.LegacyContractCount -le 0 -and $Record.NotAttemptedCount -le 0) { return $null }

    $ports       = @()
    $openMs      = [double]0
    $openCount   = 0
    $codeTotals  = @{}

    foreach ($portName in @($Record.Ports.Keys | Sort-Object)) {
        $pe = $Record.Ports[$portName]
        $codes = @()
        foreach ($k in @($pe.Codes.Keys | Sort-Object { [int]$_ })) {
            $ce = $pe.Codes[$k]
            $codes += [pscustomobject]@{
                Win32Error = $ce.Code
                Count      = [int]$ce.Count
                FirstIso   = $ce.FirstIso
                LastIso    = $ce.LastIso
                TotalMs    = [math]::Round([double]$ce.TotalMs, 1)
                MeanMs     = [math]::Round(([double]$ce.TotalMs / [Math]::Max(1, $ce.Count)), 1)
                MinMs      = [math]::Round([double]$ce.MinMs, 1)
                MaxMs      = [math]::Round([double]$ce.MaxMs, 1)
            }
            if (-not $codeTotals.ContainsKey($k)) { $codeTotals[$k] = 0 }
            $codeTotals[$k] += [int]$ce.Count
            if ([int]$ce.Code -eq 0) {
                $openCount += [int]$ce.Count
                $openMs    += [double]$ce.TotalMs
            }
        }
        $ports += [pscustomobject]@{
            PortName = $portName
            Role     = $pe.Role
            LastCode = $pe.LastCode
            Codes    = @($codes)
            Phases   = @($pe.Phases.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Phase = $_; Count = [int]$pe.Phases[$_] } })
        }
    }

    $pct = if ($RecordingSeconds -gt 0) { [math]::Round((($openMs / 1000.0) / $RecordingSeconds) * 100, 2) } else { $null }

    # ── The denominator that the invasiveness question actually turns on ──
    # PercentOfRecording divides by the WHOLE recording, which includes every
    # tick where another process held the port and our open was refused at ~0 ms
    # with no handle taken. Those ticks cost nothing and cannot collide with
    # anything, so including them understates the probe's real occupancy.
    #
    # The events that matter -- a user pressing Start, or unpairing and
    # re-pairing -- happen ONLY when nobody else holds the port. The probability
    # that one of them lands on a tick where WE hold the handle is therefore
    # openMs over the UNCONTENDED window, not over the recording.
    #
    # Measured 2026-08-19 on two captures already collected:
    #   026B63C26C4D  18,471 ms over a 79 s uncontended window  = 23.3 %  (headline said 4.6 %)
    #   E470A928F98C  31,694 ms over a 203 s device-present span = 15.6 %  (headline said 11.8 %)
    # so the shipped headline understated occupancy ~5x for the window in which
    # a collision is possible at all. P11 (2026-08-19) then established that a
    # held port fails a NO session start outright, which is what makes this
    # number a safety figure rather than a curiosity.
    #
    # ESTIMATOR, and its assumption stated: attempts are evenly spaced by the
    # tick loop, so the fraction of attempts NOT refused estimates the fraction
    # of wall clock in which acquisition was possible. Against 026B63C26C4D that
    # gives 77 s where the true window was 79 s. It is an estimate and the field
    # name does not pretend otherwise.
    # Keyed by whatever type the per-port Codes table used, which is not
    # guaranteed to be [int] -- ContainsKey(5) against string keys silently
    # returns 0 refusals and hands back the whole recording as the "uncontended"
    # window, i.e. exactly the overstatement this field exists to remove.
    $refusedCount = 0
    foreach ($ck in $codeTotals.Keys) { if ([int]$ck -eq 5) { $refusedCount += [int]$codeTotals[$ck] } }
    $totalAttempts = [int]$Record.AttemptCount
    $uncontendedSeconds = if ($RecordingSeconds -gt 0 -and $totalAttempts -gt 0) {
        [math]::Round($RecordingSeconds * (($totalAttempts - $refusedCount) / [double]$totalAttempts), 1)
    } else { $null }
    $uncontendedPct = if ($uncontendedSeconds -gt 0) {
        [math]::Round((($openMs / 1000.0) / $uncontendedSeconds) * 100, 2)
    } else { $null }

    $topology = if ($null -eq $Record.TopologyRequest) {
        $null
    } else {
        $tr = $Record.TopologyRequest
        # A request that nothing serviced must say so. Rendering it as absent
        # would let a reader conclude no topology defect was present, when in
        # fact the question was asked and never answered.
        $status = if ($tr.Status -eq 'Pending') { 'RequestedButNotCollected' } else { $tr.Status }
        [pscustomobject]@{
            Reason      = $tr.Reason
            Port        = $tr.Port
            Phase       = $tr.Phase
            RequestedAt = $tr.RequestedAt
            Status      = $status
            Snapshot    = $tr.Snapshot
            CollectedAt  = if ($tr.ContainsKey('CollectedAt')) { $tr.CollectedAt } else { $null }
            FailureReason = if ($tr.ContainsKey('FailureReason')) { $tr.FailureReason } else { $null }
        }
    }

    return [pscustomobject]@{
        PSTypeName                           = 'WinConfig.Serial.OpenAttemptReport'
        Contract                             = $Record.Contract
        Ports                                = @($ports)
        AttemptCount                         = [int]$Record.AttemptCount
        NotAttemptedCount                    = [int]$Record.NotAttemptedCount
        LegacyContractCount                  = [int]$Record.LegacyContractCount
        CodeTotals                           = @($codeTotals.Keys | Sort-Object { [int]$_ } | ForEach-Object { [pscustomobject]@{ Win32Error = [int]$_; Count = [int]$codeTotals[$_] } })
        Transitions                          = @($Record.Transitions)
        DroppedTransitionCount               = [int]$Record.DroppedTransitionCount
        HandleAcquiredCount                  = $openCount
        SuccessfulOpenCallMs                 = [math]::Round($openMs, 1)
        SuccessfulOpenCallPercentOfRecording = $pct
        UncontendedWindowSeconds             = $uncontendedSeconds
        SuccessfulOpenCallPercentOfUncontendedWindow = $uncontendedPct
        TopologyRequest                      = $topology
        Basis                                = 'One CreateFile open attempt per port per phase: CreateFile + (on success) CloseHandle. No DCB/baud configuration, no retry, no sleep. UPPER BOUND on the exclusive-ownership interval, not a measurement of it. PercentOfRecording divides by the whole recording; PercentOfUncontendedWindow divides by the estimated wall clock in which no other process held the port, which is the only window in which a session start or a re-pair can collide with this probe. Read the second one for exposure.'
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
        # Ordered subset of UnavailablePorts: each named port was observed held
        # on an earlier tick and unavailable on a later one.  This is the only
        # evidence that can support "reachable earlier, then stopped opening".
        [AllowEmptyCollection()][array]$UnavailableAfterHeldPorts = @(),
        [System.Nullable[bool]]$AppRunning,
        [bool]$CpuStalled = $false,
        [bool]$IoStalled = $false,
        [bool]$IoDegrading = $false,
        [bool]$SerialIntegrityFault = $false,
        # Retained for callers/bundles from the pre-#81 API.  Ever-active is a
        # coverage fact, not ordering evidence, and must not corroborate the
        # unavailable-port rule.
        [bool]$TargetEverActive = $false,
        # Whether the port-hold channel was observed at all. $false only when the
        # active port-open probe is disabled by setting.
        #
        # Every rule below keys on $isHeld or on a non-empty dead-port list, so a
        # disabled probe fires NOTHING -- and that silence is the danger. This
        # function's whole job is to stop a bad combination reading as
        # unremarkable, and a caller that gets back an empty array concludes the
        # box is consistent. An unobserved channel has to SAY it was unobserved,
        # in the same array a reader is already looking at.
        [bool]$PortHoldObserved = $true
    )

    $out = @()
    $held     = @($HeldPorts | Where-Object { $_ })
    $dead     = @($UnavailablePorts | Where-Object { $_ })
    $afterHeld = @($UnavailableAfterHeldPorts | Where-Object {
        $_ -and $_ -in $dead
    } | Select-Object -Unique)
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
        # Integrity corruption corroborates every currently unavailable port.
        # Otherwise only the per-port ordered subset can support the temporal
        # claim.  `TargetEverActive` used to make the opposite ordering
        # (unavailable first, held later) read as a failure (#81).
        # Wrap the conditional itself: PowerShell otherwise unwraps a one-item
        # branch to a scalar under StrictMode, where `.Count` is unavailable.
        $failedDead = @(if ($SerialIntegrityFault) { $dead } else { $afterHeld })
        $uncorroboratedDead = @($dead | Where-Object { $_ -notin $failedDead })

        if ($failedDead.Count -gt 0) {
            $why = if ($SerialIntegrityFault) {
                'The serial port integrity check independently reports an OS-level fault, so this is not simply a device that is switched off.'
            } else {
                'Each named port was held earlier in this recording and became unavailable on a later tick, which being switched off before the session does not explain.'
            }
            $out += @{
                Level = 'FAIL'
                Text  = "[!] $($failedDead -join ', ') is registered as a Bluetooth serial port but will not open. $why NO.exe cannot receive EEG through a port in this state -- expect 'Control Port not valid' or 'Arc not detected'. The probe deliberately does not guess the cause here: an absent symlink and a stale one give different win32 errors and need different fixes. Run the serial port integrity check (operator-initiated, with NO.exe closed) to split them."
            }
        }

        if ($uncorroboratedDead.Count -gt 0 -and $BtLinkState -ne 'Connected') {
            $out += @{
                Level = 'INFO'
                Text  = "[i] $($uncorroboratedDead -join ', ') is registered as a Bluetooth serial port and did not open, and the radio reports no link to this headset. The most likely reason by far is that the headset is switched off or out of range -- a port with nothing on the other end times out exactly like a broken one, and FI-012 records that the two are indistinguishable from the error alone. This is NOT evidence of a fault. To turn it into one: power the headset on, confirm it connects, then run the serial port integrity check with NO.exe closed."
            }
        } elseif ($uncorroboratedDead.Count -gt 0) {
            $out += @{
                Level = 'WARN'
                Text  = "[~] $($uncorroboratedDead -join ', ') is registered as a Bluetooth serial port but will not open, even though the radio reports an active link to this headset. A linked device whose port refuses to open is worth capturing. The probe deliberately does not guess the cause here: an absent symlink and a stale one give different win32 errors and need different fixes. Run the serial port integrity check with NO.exe closed to classify it."
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

    # Emitted LAST and unconditionally when the channel was off, so it travels
    # with whatever else this snapshot found. Four of the six rules above need a
    # held port to fire; without this row their combined silence is
    # indistinguishable from a clean cross-check, and the operator-facing line
    # that reads "the Bluetooth layer looks consistent at this moment" would be
    # asserting the consistency of fields nothing read.
    if (-not $PortHoldObserved) {
        $out += @{
            Level = 'INFO'
            Text  = "[i] COM port hold was NOT OBSERVED at this instant: the active port-open probe is disabled by setting for this recording. Four of the cross-checks here need a held port to fire, so their silence is not a clean result -- it is the absence of a reading. Do not read this snapshot as ruling out a held-port fault."
        }
    }

    return $out
}

# =============================================================================
# TARGET BINDING
# =============================================================================

function Get-BtTargetBinding {
    <#
    .SYNOPSIS
        Pure. Says WHICH headset this recording is about and how strongly that
        is known. A PREREQUISITE for the diagnostic chain, not a node in it.
    .DESCRIPTION
        THE DEFECT THIS CLOSES. A recording could simultaneously print
        "NO HEADSET SELECTED -- this recording is not scoped to a device" in the
        identity strip and "FIRST FAILING STEP: adapter present -> Windows
        pairing record" in the chain. Those two sentences cannot both be safe.
        If you do not know which headset you are diagnosing, you cannot say its
        pairing record is the first failure -- you only know that the candidate
        the recorder happened to fall back on has no device record right now.

        Target identity is NOT another health node, and modelling it as one
        would be wrong twice over. It is not a thing that is healthy or broken:
        it is the SCOPE that decides whether any device-scoped health claim is
        admissible at all. A node would also sit inside the dependency walk and
        start blocking siblings, which would turn "we do not know which headset"
        into "the headset is at fault" -- the exact confusion being removed.

          Explicit    an operator chose this MAC. Not second-guessed.
          Unique      positive evidence pins exactly one candidate: it is the
                      only NeurOptimal on the box, or the only one holding a
                      COM port. Either is a fact about the world, not a
                      tie-break over an unordered list.
          Inferred    a candidate is NAMED but not confirmed -- typically
                      recovered from a BTHPORT pairing record when PnP had no
                      device node at all (the FI-014 shape). Enough to say what
                      is probably being looked at, never enough to convict it.
          Ambiguous   several candidates, none distinguished.
          Unscoped    no defensible target.
          Unknown     the caller stated no binding. NOT a synonym for Unscoped:
                      it means nothing answered, which is the honest rendering
                      of an absent measurement and is what a stale caller
                      produces. The wiring assertion in the suite is what stops
                      that from being how this feature quietly dies.

        THIS FUNCTION NEVER SELECTS. Select-BluetoothSessionTarget is the single
        answerer for "which headset", and it deliberately refuses to guess --
        capture 8E39860E4AF2 recorded a clean 37-minute session on Arc 000013
        while watching Arc 000019 in a drawer, because a first-match pick over
        an unordered enumeration silently chose. Anything here that ranked
        candidates would be a second selector, and two selectors disagreeing is
        how one capture came to describe two headsets.

        'Inferred' is therefore a NAME FOR A STATE THAT ALREADY HAPPENS, not a
        new licence to pick: when PnP holds no NeurOptimal node the app already
        falls back to the pairing record for a MAC, and until now that fallback
        arrived at the chain wearing the same face as a confirmed selection.
    .PARAMETER SessionTarget
        A Select-BluetoothSessionTarget result, or $null when selection never
        ran (an older module copy, or a recording that failed before it).
    .PARAMETER RecordCandidateMac
        MAC recovered from a BTHPORT pairing record when PnP had no node. This
        is what makes the difference between Inferred and Unscoped.
    .PARAMETER RecordCandidateName
        Friendly name for that record, when the record carries one.
    .OUTPUTS
        [pscustomobject] Binding, Confirmed, LocalizationScope, Mac, Name,
        Reason, Evidence, Summary, CandidateCount.
    #>
    [CmdletBinding()]
    param(
        $SessionTarget,
        [string]$RecordCandidateMac,
        [string]$RecordCandidateName
    )

    # Set-StrictMode -Version Latest is in force at module scope: reading a
    # property that does not exist THROWS rather than returning $null. The
    # session target can legitimately come from an older module copy with a
    # narrower shape, so every read goes through this.
    $prop = {
        param($Obj, [string]$Name)
        if (-not $Obj) { return $null }
        if ($Obj -is [hashtable]) { if ($Obj.ContainsKey($Name)) { return $Obj[$Name] } else { return $null } }
        if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
        return $null
    }

    $mode     = [string](& $prop $SessionTarget 'Mode')
    $reason   = [string](& $prop $SessionTarget 'Reason')
    $mac      = [string](& $prop $SessionTarget 'Mac')
    $name     = [string](& $prop $SessionTarget 'Name')
    $resolved = [bool]  (& $prop $SessionTarget 'IsResolved')
    $cands    = @(& $prop $SessionTarget 'Candidates')

    $recMac  = ([string]$RecordCandidateMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $recName = [string]$RecordCandidateName

    $binding  = 'Unknown'
    $bReason  = 'NoSelectionRun'
    $evidence = 'Nothing in this recording stated which headset it is about.'

    if ($SessionTarget) {
        switch ($mode) {
            'Explicit' {
                $binding = 'Explicit'; $bReason = 'OperatorSelected'
                $evidence = 'The operator chose this headset for the recording.'
            }
            'Automatic' {
                if ($resolved -and $reason -eq 'SoleActiveComPort') {
                    $binding = 'Unique'; $bReason = 'SoleActiveComPort'
                    $evidence = 'Several NeurOptimal headsets are paired, and this is the only one whose COM port a process is holding -- the one signal that means something is talking to it right now.'
                } elseif ($resolved) {
                    $binding = 'Unique'; $bReason = 'SingleCandidate'
                    $evidence = 'This is the only NeurOptimal headset Windows knows about on this PC, so there is nothing to confuse it with.'
                } else {
                    # Exactly one candidate, but no MAC to pin it to. Identity is
                    # by NAME only, which the watch config can still match on --
                    # so this is a real candidate, and it is not confirmed.
                    $binding = 'Inferred'; $bReason = 'NameOnlyNoMac'
                    $evidence = 'One NeurOptimal headset was found but its Bluetooth address could not be read, so it is identified by name only.'
                }
            }
            'AmbiguousRequiresChoice' {
                $binding = 'Ambiguous'; $bReason = 'MultipleCandidates'
                $evidence = "$($cands.Count) NeurOptimal headsets are paired on this PC and nothing distinguishes which one this session is about."
                $mac = $null; $name = $null
            }
            default {
                # 'None' -- selection ran and found nothing to select.
                $binding = 'Unscoped'; $bReason = 'NoCandidates'
                $evidence = 'Windows is not showing a NeurOptimal device node for any headset on this PC, so there was no candidate to select.'
                $mac = $null; $name = $null
            }
        }
    }

    # The historical fallback. It only ever UPGRADES Unscoped/Unknown -- it must
    # never overwrite a selection that was actually made, because the record
    # ranking deliberately prefers the NODELESS device (the FI-014 case) and
    # that is precisely not the headset in a live clinical session.
    if ($recMac -and $binding -in @('Unscoped', 'Unknown')) {
        $binding  = 'Inferred'
        $bReason  = 'HistoricalPairingRecord'
        $mac      = $recMac
        $name     = if ($recName) { $recName } else { $null }
        $evidence = 'This headset was named by a stored Windows pairing record, not by a device Windows is showing now. The PC has met it before; it is not enumerated at the moment.'
    }

    # Confirmed means "a device-specific conclusion is admissible", nothing
    # softer. Inferred is deliberately NOT confirmed: a named candidate is
    # enough to tell an operator what is probably being looked at, and not
    # enough to convict it of the failure.
    $confirmed = ($binding -in @('Explicit', 'Unique'))
    $scope = switch ($binding) {
        'Explicit'  { 'Confirmed' }
        'Unique'    { 'Confirmed' }
        'Inferred'  { 'Provisional' }
        'Ambiguous' { 'Suspended' }
        'Unscoped'  { 'Suspended' }
        default     { 'Unstated' }
    }

    $label = if ($name -and $mac) { "$name ($mac)" }
             elseif ($name)       { $name }
             elseif ($mac)        { $mac }
             else                 { $null }

    $summary = switch ($scope) {
        'Confirmed'   { "Target: $label. $evidence" }
        'Provisional' { "TARGET NOT CONFIRMED. Candidate: $(if ($label) { $label } else { 'unnamed' }). $evidence" }
        'Suspended'   { "TARGET NOT CONFIRMED. $evidence" }
        default       { "TARGET NOT STATED. $evidence" }
    }

    return [pscustomobject]@{
        PSTypeName        = 'WinConfig.FlightRecorder.TargetBinding'
        Binding           = $binding
        Confirmed         = $confirmed
        LocalizationScope = $scope
        Mac               = $mac
        Name              = $name
        Label             = $label
        Reason            = $bReason
        Evidence          = $evidence
        Summary           = $summary
        CandidateCount    = $cands.Count
    }
}

# =============================================================================
# DIAGNOSTIC CHAIN
# =============================================================================

function Get-BtDiagnosticChain {
    <#
    .SYNOPSIS
        Pure. Orders the probe's independent state fields into a DEPENDENCY
        CHAIN and localizes the first step that cannot be verified.
    .DESCRIPTION
        WHAT THIS FIXES. The recorder measures five things and renders them side
        by side as five equals. They are not equals: a dead radio link makes the
        port-hold reading, the read rate and every downstream conclusion
        consequences rather than findings. An operator reading five indicators
        counts FOUR problems where there is one cause and three effects, and the
        remedy they pick is chosen from the wrong layer.

        The chain answers a different question: what is the LAST step that is
        verified good, and what is the FIRST one that is not. That is the
        sentence a clinic tech can act on and a remote assistant can triage from
        a screenshot.

        THREE THINGS ARE KEPT APART, because collapsing any pair of them is how
        this recorder has misled readers before:

          Health       what the reading SAYS      Healthy/Idle/Degraded/Failed/Unknown
          Observation  where the reading CAME FROM Observed/Inferred/Historical/
                                                   NotObserved/NotMeasurable
          BlockedBy    whether it is a CONSEQUENCE  upstream node id, or $null

        'Idle' is not a soft 'Failed'. It is a reading that is legitimately
        negative: a headset with no radio link before a session has started, a
        COM port nobody is holding because NeurOptimal is not open. FI-012 is the
        standing warning here -- SPP devices hold no profile open, so a perfectly
        healthy idle Arc reads Disconnected. Painting that red would reproduce
        the wall of false problems this function exists to remove, in the
        opposite direction.

        'NotObserved' is not 'Healthy' and not 'Idle'. When the active port-open
        probe is disabled by setting (the non-intrusive arm), NOTHING looked at
        the port hold. The chain must stop there and say so, because a chain that
        walks past an unread sensor and reports a boundary further down is
        asserting the health of a link nothing measured.

        BlockedBy IS AN ATTRIBUTE, NOT A HEALTH VALUE, and the difference is
        deliberate. Overwriting a downstream node's health with 'BLOCKED' throws
        away a reading that was actually taken. If the radio is down AND we
        observed that no process holds the port, both facts are worth keeping:
        the node reports Idle, and BlockedBy names the radio as the explanation.

        THE EDGE ORDER IS NOT THE OBVIOUS ONE. COM port registration is NOT
        downstream of the radio link. Ports stay registered while the radio is
        disconnected -- they are a HISTORICAL fact about a past pairing, which is
        why the ComPorts node is marked Observation='Historical' even when it is
        green. Placing it under the link, as a layer-stack reading of the problem
        suggests, would make every idle box show a broken COM layer.

        WHAT IS NOT A NODE HERE. There is no protocol/handshake node: this tool
        never writes to the Arc, so bytes-sent is unobservable by design, and a
        permanently-Unknown node is noise that trains readers to skip the chain.
        Host and OS are not nodes either -- they do not fail in a way that
        produces a Bluetooth boundary, so they would be permanent green.

        TARGET IDENTITY IS A PREREQUISITE, NOT A NODE. Every node from Pairing
        down is a claim ABOUT A PARTICULAR HEADSET. If the recording could not
        establish which headset that is, those readings are still real -- they
        are simply not attributable, and a boundary drawn across them names a
        failure in a device nobody identified. TargetBinding therefore gates the
        CLAIM, not the readings: the nodes keep their measured health, and the
        localization sentence downgrades to provisional or refuses to name a
        boundary at all. Dimming the readings instead would hide evidence that
        was honestly obtained, which is the same class of error in reverse.

        WHY UnavailablePorts DOES NOT SET A HEALTH HERE. A registered port that
        will not open is already judged, with the FI-012 hedge, by
        Get-ProbeStateConsistency. Judging it a second time in this function
        would be two pieces of code independently answering one question -- the
        channel-mismatch class. It travels as EVIDENCE on the PortHold node so a
        reader sees it, and the verdict stays with the single answerer.
    .PARAMETER StreamState
        'Active' (a port is held) / 'Stopped' / 'DisabledBySetting' / 'Unknown'.
    .PARAMETER PortHoldObserved
        $false only when the active port-open probe is disabled by setting.
    .PARAMETER IoObserved
        $false when the read-rate API could not be initialised. Note this is
        INDEPENDENT of PortHoldObserved: read-rate sampling reads NO.exe's own
        counters and opens no port, so it survives the non-intrusive arm and is
        the only data-flow channel left there.
    .PARAMETER TargetBinding
        Get-BtTargetBinding's Binding: Explicit / Unique / Inferred / Ambiguous
        / Unscoped. Defaults to 'Unknown' -- the caller stated nothing -- which
        leaves today's wording untouched rather than suspending localization on
        every stale caller. 'Unknown' is visible in the output and in
        chain.jsonl precisely so a broken wiring shows up as a state rather
        than as silence.
    .PARAMETER TargetLabelName
        Friendly name of the bound or candidate headset, for the sentence.
    .PARAMETER TargetLabelMac
        Its MAC, for the sentence.
    .PARAMETER TargetBindingEvidence
        One sentence on WHERE that identity came from, from Get-BtTargetBinding.
        Passed rather than re-derived: a second place that explains the binding
        is a second place that can disagree with the first.
    .PARAMETER PairingRecordPresent
        $true when Windows holds a BTHPORT pairing record for the target,
        $false when it is known not to, $null when nothing looked. Kept
        separate from the PnP device node because they are different Windows
        concepts and "Headset paired: Not found" collapses them: the FI-014
        shape is a record that is PRESENT while the device node is ABSENT, and
        a reader told only "not paired" will go and re-pair a headset whose
        pairing key was never the problem.
    .OUTPUTS
        PSCustomObject (PSTypeName WinConfig.FlightRecorder.DiagnosticChain).
    #>
    [CmdletBinding()]
    param(
        [string]$DeviceState,
        [string]$ComPortState,
        [AllowEmptyCollection()][array]$ComPortNames = @(),
        [string]$BtLinkState,
        [string]$StreamState,
        [AllowEmptyCollection()][array]$HeldPorts = @(),
        [AllowEmptyCollection()][array]$UnavailablePorts = @(),
        [System.Nullable[bool]]$AppRunning,
        [bool]$BtLinkEverConnected = $false,
        [bool]$PortHoldObserved = $true,
        [string]$IoVerdict = 'NoBaseline',
        [bool]$IoObserved = $true,
        [int]$IoSamplesTotal = 0,
        [System.Nullable[double]]$IoFractionOfBaseline,
        [System.Nullable[double]]$IoRecentOpsPerSecond,
        [System.Nullable[double]]$IoBaselineOpsPerSecond,
        [hashtable]$AdapterInfo,
        # Get-ComPortRoleMap's output, passed through rather than re-derived.
        # Resolve-ComPortRole is the one place that decides which port is DATA
        # and which is COMMAND; this function carries that answer to the panel
        # that shows it and adds nothing to it. Absent (an older caller) is a
        # state of its own -- 'NotStated' -- and is NOT the same as a map that
        # was taken and found nothing.
        [hashtable]$ComPortRoleMap,
        [ValidateSet('Explicit', 'Unique', 'Inferred', 'Ambiguous', 'Unscoped', 'Unknown')]
        [string]$TargetBinding = 'Unknown',
        [string]$TargetLabelName,
        [string]$TargetLabelMac,
        [string]$TargetBindingEvidence,
        [System.Nullable[bool]]$PairingRecordPresent
    )

    $held = @($HeldPorts | Where-Object { $_ })
    $dead = @($UnavailablePorts | Where-Object { $_ })
    $ports = @($ComPortNames | Where-Object { $_ })

    # Local builder. Evidence entries carry their OWN kind rather than
    # inheriting the node's Observation, because a single node routinely mixes
    # them: the port-hold node states an observation AND the inference drawn
    # from it AND the caveat that the inference does not reach EEG.
    # Local, NOT script:-scoped. A script:-scoped inner function would be
    # redefined into module scope on every call and would outlive this one.
    function New-ChainEvidence { param([string]$Kind, [string]$Text)
        return [pscustomobject]@{ Kind = $Kind; Text = $Text }
    }

    $nodes = New-Object System.Collections.ArrayList

    # ── 1. Adapter ────────────────────────────────────────────────────────────
    # Historical by construction: AdapterInfo is collected ONCE, at recording
    # start. Saying 'Observed' would claim a live reading the recorder does not
    # take on every tick.
    $adapterHealth = 'Unknown'
    $adapterObs    = 'NotObserved'
    $adapterDetail = 'Not read'
    $adapterEv     = @()
    # Carried as their own fields, not left for a renderer to recover from an
    # evidence sentence. "Which Bluetooth hardware is this PC using" is the
    # question the host panel answers, and parsing it back out of prose would be
    # a second answerer to a question this branch has already answered.
    $adapterNameOut   = $null
    $adapterDriverOut = $null
    if ($AdapterInfo) {
        $adapterObs = 'Historical'
        $adapterName = if ($AdapterInfo.FriendlyName) { $AdapterInfo.FriendlyName } else { 'Bluetooth adapter' }
        if ($AdapterInfo.FriendlyName) { $adapterNameOut = [string]$AdapterInfo.FriendlyName }
        if (-not $AdapterInfo.Present) {
            $adapterHealth = 'Failed'
            $adapterDetail = 'Not found'
            $adapterEv += (New-ChainEvidence 'Historical' 'No Bluetooth adapter was found on this PC when the recording started.')
        } elseif ($AdapterInfo.Enabled) {
            $adapterHealth = 'Healthy'
            $adapterDetail = 'OK'
            $adapterEv += (New-ChainEvidence 'Historical' "$adapterName reported status OK when the recording started.")
        } else {
            $adapterHealth = 'Failed'
            $adapterDetail = "Status $($AdapterInfo.Status)"
            $adapterEv += (New-ChainEvidence 'Historical' "$adapterName reported status '$($AdapterInfo.Status)' when the recording started.")
        }
        if ($AdapterInfo.DriverInfo -and $AdapterInfo.DriverInfo.Version) {
            $adapterDriverOut = [string]$AdapterInfo.DriverInfo.Version
            $adapterEv += (New-ChainEvidence 'Historical' "Driver $($AdapterInfo.DriverInfo.Version).")
        }
        $adapterEv += (New-ChainEvidence 'NotObserved' 'Read once at the start of the recording, not on every check. An adapter that failed mid-session is not reflected here.')
    } else {
        $adapterEv += (New-ChainEvidence 'NotObserved' 'Adapter information was not collected for this recording.')
    }
    [void]$nodes.Add(@{
        Id = 'Adapter'; Title = 'Bluetooth adapter'; EdgeLabel = $null; DependsOn = @()
        Health = $adapterHealth; Observation = $adapterObs; Detail = $adapterDetail; Evidence = $adapterEv
        AdapterName = $adapterNameOut; DriverVersion = $adapterDriverOut
    })

    # ── 2. Pairing ────────────────────────────────────────────────────────────
    # 'Unconfigured' means paired but with no COM ports assigned. The PAIRING
    # step succeeded, so it stays green here and the ComPorts node below carries
    # the failure. Reporting one fact at two nodes would double-count a single
    # cause -- which is what this whole function is built to stop.
    $pairHealth = 'Unknown'; $pairEv = @()
    switch ($DeviceState) {
        'PairedCandidate' { $pairHealth = 'Healthy' }
        'Configured'      { $pairHealth = 'Healthy' }
        'Unconfigured'    { $pairHealth = 'Healthy' }
        'Ambiguous'       { $pairHealth = 'Degraded' }
        'SeenByPnp'       { $pairHealth = 'Failed' }
        'Missing'         { $pairHealth = 'Failed' }
        default           { $pairHealth = 'Unknown' }
    }
    $pairText = Get-ProbeStateUserText -Kind device -State $DeviceState -Short
    $pairEv += (New-ChainEvidence 'Observed' (Get-ProbeStateUserText -Kind device -State $DeviceState))
    if ($pairHealth -eq 'Healthy') {
        $pairEv += (New-ChainEvidence 'Inferred' 'Windows holds a pairing record for this headset. That is a stored key, not a live connection.')
    }
    # TWO WINDOWS CONCEPTS, KEPT APART. A stored BTHPORT pairing record and a
    # currently-enumerated PnP device node are different facts, and "Headset
    # paired: Not found" collapses them into one. FI-014 is exactly the state
    # where they disagree -- record present, node absent -- and a reader told
    # only "not paired" re-pairs a headset whose pairing key was never at fault.
    #
    # The chip count stays at eight. This rides on the DETAIL and the evidence,
    # which is where a distinction this specific belongs: a ninth chip would be
    # permanently green on every healthy box and would be skipped by the time it
    # mattered.
    $pairTitle = 'Windows device'
    $pairEdge  = 'adapter present -> Windows device enumeration'
    if ($pairHealth -ne 'Healthy' -and $PairingRecordPresent -eq $true) {
        $pairText = 'Record only, no device'
        $pairEdge = 'stored pairing record -> Windows device enumeration'
        $pairEv += (New-ChainEvidence 'Historical' 'Windows still holds a stored pairing record (BTHPORT) for this headset, so this PC has met it before.')
        $pairEv += (New-ChainEvidence 'Observed' 'What is missing is the live device node: Windows is not enumerating the headset right now, which is why it shows as not paired.')
        $pairEv += (New-ChainEvidence 'Inferred' 'A record without a device node does NOT mean the pairing key is wrong. Re-pairing is not automatically the remedy -- one such headset re-paired successfully with the record left in place.')
    } elseif ($pairHealth -ne 'Healthy' -and $PairingRecordPresent -eq $false) {
        $pairEdge = 'adapter present -> Windows pairing record'
        $pairEv += (New-ChainEvidence 'Observed' 'Windows holds no stored pairing record for this headset either, so this is an unpaired device rather than one that lost its device node.')
    } elseif ($pairHealth -ne 'Healthy') {
        $pairEv += (New-ChainEvidence 'NotObserved' 'Whether Windows still holds a stored pairing record for this headset was not checked, so "not paired" here is about the live device node only.')
    }
    [void]$nodes.Add(@{
        # Id remains Pairing for artifact compatibility. The visible title and
        # boundary name the fact this node actually tests: live PnP device
        # enumeration. Pairing history is evidence on that node, not a failed
        # step when the BTHPORT record is demonstrably present.
        Id = 'Pairing'; Title = $pairTitle; EdgeLabel = $pairEdge; DependsOn = @('Adapter')
        Health = $pairHealth; Observation = 'Observed'; Detail = $pairText; Evidence = $pairEv
    })

    # ── 3. COM ports registered ───────────────────────────────────────────────
    # HISTORICAL even when green. This is the single most over-read fact in the
    # whole recorder: registered ports are what a PREVIOUS successful pairing
    # left behind, and they persist through a flat battery, a headset in a
    # drawer, and a driver that has stopped working.
    $comHealth = 'Unknown'; $comEv = @()
    switch ($ComPortState) {
        'ComPortFound'        { $comHealth = 'Healthy' }
        'ComPortAmbiguous'    { $comHealth = 'Healthy' }
        'ComPortMissing'      { $comHealth = 'Failed' }
        'ComPortUnconfigured' { $comHealth = 'Unknown' }
        default               { $comHealth = 'Unknown' }
    }
    $comDetail = if ($ports.Count -gt 0) { $ports -join ', ' } else { Get-ProbeStateUserText -Kind comport -State $ComPortState -Short }
    $comEv += (New-ChainEvidence 'Observed' (Get-ProbeStateUserText -Kind comport -State $ComPortState))
    if ($ports.Count -gt 0) { $comEv += (New-ChainEvidence 'Observed' "Registered: $($ports -join ', ').") }
    if ($comHealth -eq 'Healthy') {
        $comEv += (New-ChainEvidence 'Historical' 'A registered COM port is what a previous successful pairing left behind. It survives a flat battery, a headset in a drawer and a broken driver, so it does NOT show that anything is connected now.')
    }
    # The port names and the DATA/COMMAND mapping travel ON the node, because
    # the panel that shows this node is where an operator asks "which ports are
    # this headset's, and is anyone using them". 'NotStated' is the caller not
    # having a map to give, which is a different fact from a map that came back
    # empty -- the same distinction the ComPorts health itself keeps.
    $roleState = 'NotStated'
    $rolePorts = @()
    if ($ComPortRoleMap) {
        if ($ComPortRoleMap.ContainsKey('State')) { $roleState = [string]$ComPortRoleMap.State }
        if ($ComPortRoleMap.ContainsKey('Ports')) { $rolePorts = @($ComPortRoleMap.Ports) }
    }
    [void]$nodes.Add(@{
        Id = 'ComPorts'; Title = 'COM ports registered'; EdgeLabel = 'Windows device enumeration -> virtual serial ports'; DependsOn = @('Pairing')
        Health = $comHealth; Observation = 'Historical'; Detail = $comDetail; Evidence = $comEv
        Ports = $ports; RoleState = $roleState; Roles = $rolePorts
    })

    # ── 4. Radio link ─────────────────────────────────────────────────────────
    # THE FI-012 TRAP LIVES HERE. 'NotConnected' on its own is NOT a fault: SPP
    # holds no profile open, so an idle Arc that is working perfectly reads
    # disconnected, and during the FI-012 field case IsConnected read False while
    # both ports opened fine. It is only a failure when something else contradicts
    # it -- a port is held (something believes it has a session), or this
    # recording already saw the link UP and it has since gone (a drop, which no
    # power switch explains).
    $linkHealth = 'Unknown'; $linkObs = 'Observed'; $linkEv = @()
    $linkDetail = Get-ProbeStateUserText -Kind btlink -State $BtLinkState -Short
    # WHY the link reads as it does, as a token rather than as prose. Health
    # alone cannot separate "was up and dropped" from "never came up while a
    # port is held", and both are 'Failed'. A renderer that needed the
    # distinction had two options: parse the evidence sentences (fragile), or
    # re-derive it from BtLinkEverConnected (a second answerer to a question
    # this branch has just answered). Neither is acceptable, so the branch
    # states its own reason. It is additive: nothing consumes it as a verdict,
    # and chain.jsonl's node projection is unchanged.
    $linkCause = 'NotRead'
    if ($BtLinkState -eq 'Connected') {
        $linkHealth = 'Healthy'
        $linkCause = 'Connected'
        $linkEv += (New-ChainEvidence 'Observed' 'The Bluetooth radio reports an active link to this headset.')
    } elseif ($BtLinkState -eq 'NotConnected') {
        if ($StreamState -eq 'Active') {
            $linkHealth = 'Failed'
            $linkCause = 'PortHeldWithoutLink'
            $linkEv += (New-ChainEvidence 'Observed' 'The radio reports no link to this headset, while a process is holding its COM port.')
            $linkEv += (New-ChainEvidence 'Inferred' 'Something believes it has a session over a link that is not there. This is the shape "Arc not detected" takes from the OS side.')
        } elseif ($BtLinkEverConnected) {
            $linkHealth = 'Failed'
            $linkCause = 'Dropped'
            $linkEv += (New-ChainEvidence 'Observed' 'The radio reports no link now, but it DID report one earlier in this same recording.')
            $linkEv += (New-ChainEvidence 'Inferred' 'A link that was up and is now down is a drop. Being switched off does not explain a link that existed minutes ago.')
        } else {
            $linkHealth = 'Idle'
            $linkCause = 'IdleNoSession'
            $linkEv += (New-ChainEvidence 'Observed' 'The radio reports no active link to this headset.')
            $linkEv += (New-ChainEvidence 'Inferred' 'This is NORMAL between sessions. This headset holds no Bluetooth profile open while idle, so a healthy Arc sitting on the desk reads exactly like this. It is only a fault if it happens DURING a session.')
        }
    } else {
        $linkHealth = 'Unknown'; $linkObs = 'NotObserved'
        $linkEv += (New-ChainEvidence 'NotObserved' 'The radio link state could not be read. This check needs administrator rights and a discovered device.')
    }
    [void]$nodes.Add(@{
        Id = 'RadioLink'; Title = 'Live radio link'; EdgeLabel = 'Windows device enumeration -> live wireless link'; DependsOn = @('Adapter', 'Pairing')
        Health = $linkHealth; Observation = $linkObs; Detail = $linkDetail; Evidence = $linkEv
        Cause = $linkCause
    })

    # ── 5. Application ────────────────────────────────────────────────────────
    # Idle, never Failed. NeurOptimal not being open is an operator state, not a
    # defect, and it is the correct EXPLANATION for an idle port below.
    $appHealth = 'Unknown'; $appDetail = 'Unknown'; $appEv = @()
    if ($AppRunning -eq $true) {
        $appHealth = 'Healthy'; $appDetail = 'Running'
        $appEv += (New-ChainEvidence 'Observed' 'NeurOptimal is running.')
    } elseif ($AppRunning -eq $false) {
        $appHealth = 'Idle'; $appDetail = 'Not running'
        $appEv += (New-ChainEvidence 'Observed' 'NeurOptimal is not running.')
        $appEv += (New-ChainEvidence 'Inferred' 'Nothing below this point can happen while the application is closed. This is expected before a session starts -- it is not a fault.')
    } else {
        $appEv += (New-ChainEvidence 'NotObserved' 'The process list could not be read.')
    }
    [void]$nodes.Add(@{
        # DependsOn is EMPTY, and that is the whole reason this function models
        # dependencies instead of a single spine. NeurOptimal runs perfectly well
        # with no radio link and no headset. Chaining it under the link would
        # report "NeurOptimal not running" as a CONSEQUENCE of a Bluetooth
        # failure, which is a false causal claim on the one screen an operator
        # uses to choose a remedy.
        Id = 'App'; Title = 'NeurOptimal running'; EdgeLabel = 'operator starts NeurOptimal'; DependsOn = @()
        Health = $appHealth; Observation = $(if ($null -eq $AppRunning) { 'NotObserved' } else { 'Observed' }); Detail = $appDetail; Evidence = $appEv
    })

    # ── 6. Port ownership ─────────────────────────────────────────────────────
    $holdHealth = 'Unknown'; $holdObs = 'Observed'; $holdEv = @()
    $holdDetail = Get-ProbeStateUserText -Kind stream -State $StreamState -Short
    if (-not $PortHoldObserved) {
        # The chain STOPS here in the non-intrusive arm, and that is correct.
        # Nothing looked. Reporting a boundary further down would be asserting
        # the health of a link no sensor read.
        $holdHealth = 'Unknown'; $holdObs = 'NotObserved'
        $holdDetail = 'Not observed'
        $holdEv += (New-ChainEvidence 'NotObserved' 'The active port-open probe is DISABLED by setting for this recording, so nothing checked whether a process is holding the headset''s COM port. This is not a report that the port is idle.')
        $holdEv += (New-ChainEvidence 'NotObserved' 'The chain cannot be evaluated past this point from port ownership. Read-rate below is a separate sensor and is still running.')
    } elseif ($StreamState -eq 'Active') {
        $holdHealth = 'Healthy'
        $holdDetail = if ($held.Count -gt 0) { "Held ($($held -join ', '))" } else { 'Held' }
        $holdEv += (New-ChainEvidence 'Observed' "A process is holding $(if ($held.Count -gt 0) { $held -join ', ' } else { 'the headset''s COM port' }).")
        $holdEv += (New-ChainEvidence 'Inferred' 'A held port means some process believes it has a session. It does NOT mean data is flowing: NeurOptimal keeps the port open whether or not the headset sends a single sample.')
    } elseif ($StreamState -eq 'Stopped' -and $ports.Count -eq 0) {
        # NOT Idle. 'Stopped' with no registered port is the port-open probe
        # finding nothing to open -- an absent measurement, and the standing
        # rule is that an absent measurement renders as absent. Reported as
        # Idle it reads "we checked, nobody is using it", which is a statement
        # about a port that does not exist. This is the same defect as an unset
        # numeric serialising as 0 in a field whose 0 is meaningful.
        #
        # This node is BlockedBy ComPorts in that state anyway, so the boundary
        # does not move; what changes is that the chip stops claiming a reading.
        $holdHealth = 'Unknown'; $holdObs = 'NotObserved'
        $holdDetail = 'No port to watch'
        $holdEv += (New-ChainEvidence 'NotObserved' 'There is no registered COM port for this headset, so there was nothing for the port-open probe to test. This is not a report that the port is free -- there is no port.')
    } elseif ($StreamState -eq 'Stopped') {
        $holdHealth = 'Idle'
        $holdEv += (New-ChainEvidence 'Observed' 'No process is holding the headset''s COM port.')
    } else {
        $holdHealth = 'Unknown'; $holdObs = 'NotObserved'
        $holdEv += (New-ChainEvidence 'NotObserved' "Port ownership state '$StreamState' could not be interpreted.")
    }
    # Evidence, deliberately NOT a verdict -- see the header note. The single
    # answerer for whether a dead port is a fault is Get-ProbeStateConsistency,
    # which applies the FI-012 hedge that a switched-off headset and a broken
    # serial stack are indistinguishable from the error alone.
    if ($dead.Count -gt 0) {
        $holdEv += (New-ChainEvidence 'Observed' "$($dead -join ', ') is registered but did not open when tested. Whether that is a fault depends on the headset's power state -- see the cross-check findings in the log; this chain does not judge it.")
    }
    [void]$nodes.Add(@{
        # Three dependencies merging. This is where the transport branch and the
        # application branch join, and it is the first node that can honestly be
        # called a consequence of either.
        Id = 'PortHold'; Title = 'COM port held'; EdgeLabel = 'live link + application -> owns the serial port'; DependsOn = @('ComPorts', 'RadioLink', 'App')
        Health = $holdHealth; Observation = $holdObs; Detail = $holdDetail; Evidence = $holdEv
        # WHICH port is held, as a list rather than baked into Detail. The COM
        # panel marks the held port inside the role mapping, and re-parsing
        # "Held (COM3)" to find it would be a renderer inventing a second
        # answerer for a fact this node was handed.
        HeldPorts = $held
    })

    # ── 7. Data flow ──────────────────────────────────────────────────────────
    # Read-rate is NOT gated on the port-hold probe. It samples NO.exe's own I/O
    # counters and opens nothing, so it is the sensor that survives the
    # non-intrusive arm -- the only corroboration left there.
    $dataHealth = 'Unknown'; $dataObs = 'Observed'; $dataDetail = 'Unknown'; $dataEv = @()
    if (-not $IoObserved) {
        $dataObs = 'NotObserved'; $dataDetail = 'Not observed'
        $dataEv += (New-ChainEvidence 'NotObserved' 'Read-rate monitoring was unavailable for this recording, so data flow was never assessed.')
    } else {
        switch ($IoVerdict) {
            'Streaming'  { $dataHealth = 'Healthy';  $dataDetail = 'Reads steady' }
            'Degrading'  { $dataHealth = 'Degraded'; $dataDetail = 'Possible read pause' }
            'Collapsed'  { $dataHealth = 'Failed';   $dataDetail = 'Reads collapsed' }
            'NoBaseline' { $dataHealth = 'Unknown';  $dataDetail = 'No baseline yet' }
            default      { $dataHealth = 'Unknown';  $dataDetail = $IoVerdict }
        }
        if ($IoVerdict -eq 'NoBaseline') {
            $dataEv += (New-ChainEvidence 'NotObserved' "No read-rate baseline has been established yet ($IoSamplesTotal sample(s) so far). A baseline needs a stretch of steady reading to compare against.")
        } else {
            $rateText = ''
            if ($null -ne $IoRecentOpsPerSecond -and $null -ne $IoBaselineOpsPerSecond) {
                $rateText = " ($([Math]::Round([double]$IoRecentOpsPerSecond,1))/s against a $([Math]::Round([double]$IoBaselineOpsPerSecond,1))/s baseline)"
            }
            $dataEv += (New-ChainEvidence 'Observed' "NeurOptimal's read-operation rate$rateText.")
            if ($null -ne $IoFractionOfBaseline) {
                $dataEv += (New-ChainEvidence 'Observed' "That is $([Math]::Round([double]$IoFractionOfBaseline * 100))% of the level this session established for itself.")
            }
            $dataEv += (New-ChainEvidence 'Inferred' 'This counts READ OPERATIONS by NeurOptimal, not EEG samples. It is a proxy for the serial path being alive, measured from outside the application.')
        }
    }
    [void]$nodes.Add(@{
        Id = 'DataFlow'; Title = 'Data arriving'; EdgeLabel = 'owns the port -> bytes actually being read'; DependsOn = @('PortHold')
        Health = $dataHealth; Observation = $dataObs; Detail = $dataDetail; Evidence = $dataEv
    })

    # ── 8. EEG ────────────────────────────────────────────────────────────────
    # Always NotMeasurable, and that is the point of including it. Everything
    # above going green is routinely read as "the session is fine". It is not:
    # nothing in this tool validates EEG content, and a node that says so in the
    # chain is the only place a reader will meet that limit at the moment they
    # are drawing the conclusion.
    [void]$nodes.Add(@{
        Id = 'Eeg'; Title = 'Valid EEG signal'; EdgeLabel = 'bytes read -> usable EEG'; DependsOn = @('DataFlow')
        Health = 'Unknown'; Observation = 'NotMeasurable'; Detail = 'Not measurable'
        Evidence = @(
            (New-ChainEvidence 'NotMeasurable' 'This tool cannot read or validate EEG content. The port is owned by NeurOptimal, and opening it to look would take it away from the application.')
            (New-ChainEvidence 'NotMeasurable' 'Every step above being green does NOT prove the EEG signal is good. It proves the transport underneath it is.')
        )
    })

    # ── Root-cause walk ───────────────────────────────────────────────────────
    # A DEPENDENCY walk, not a positional one. The first version of this scanned
    # the display list for the first non-Healthy node and blamed everything after
    # it -- which marked "NeurOptimal not running" a consequence of a dead radio
    # link. It is not: the application has no Bluetooth dependency at all. A
    # false causal claim on the one screen an operator uses to pick a remedy is
    # worse than the five-independent-indicators problem this replaces.
    #
    # ROOT: a node that is not Healthy while every node it depends on IS.
    # BLOCKED: a node that is not Healthy and has at least one non-Healthy
    # dependency, so its own reading is explained from above.
    $byId = @{}
    foreach ($n in $nodes) { $byId[$n.Id] = $n }

    $roots = New-Object System.Collections.ArrayList
    foreach ($n in $nodes) {
        $n.BlockedBy = $null
        if ($n.Health -eq 'Healthy') { continue }
        # First unhealthy dependency IN DECLARED ORDER, so the named cause is
        # stable across ticks rather than depending on hashtable enumeration.
        $badDep = $null
        foreach ($depId in @($n.DependsOn)) {
            if ($byId.ContainsKey($depId) -and $byId[$depId].Health -ne 'Healthy') { $badDep = $depId; break }
        }
        if ($badDep) { $n.BlockedBy = $badDep } else { [void]$roots.Add($n) }
    }

    $blocked  = @($nodes | Where-Object { $_.BlockedBy } | ForEach-Object { $_.Id })
    $verified = @($nodes | Where-Object { $_.Health -eq 'Healthy' } | ForEach-Object { $_.Id })

    # A SECOND, NARROWER SET, under its own name -- never a second meaning for
    # $blocked. BlockedNodeIds is the dependency walk's complete answer and stays
    # that. What the SENTENCE may claim is smaller: EEG is NotMeasurable on every
    # tick of every recording, so "EEG is a consequence of this failure" asserts
    # that but for this fault it would have been measurable. It never is. That is
    # the same reason NotMeasurable roots are excluded from the second-root
    # clause below, and the two exclusions must agree or the EEG caveat is
    # suppressed as a root and counted as a consequence in the same sentence.
    $consequences = @($nodes | Where-Object { $_.BlockedBy -and $_.Observation -ne 'NotMeasurable' } | ForEach-Object { $_.Id })

    # Which root to headline. Severity first so a real failure is never hidden
    # behind an idle sibling branch, display order as the tie-break so the answer
    # does not flicker between two equally-severe roots from tick to tick.
    #
    # The EEG node ranks BELOW idle deliberately: it is only ever a root when
    # everything measurable is green, and in that state the honest headline is
    # "this tool cannot see further", not "EEG is a problem".
    $severity = @{ 'Failed' = 4; 'Degraded' = 3; 'Unknown' = 2; 'Idle' = 1 }
    $boundaryNode = $null
    $bestRank = -1
    foreach ($r in $roots) {
        $rank = if ($r.Observation -eq 'NotMeasurable') { 0 }
                elseif ($severity.ContainsKey($r.Health)) { $severity[$r.Health] }
                else { 2 }
        if ($rank -gt $bestRank) { $bestRank = $rank; $boundaryNode = $r }
    }
    # Defensive: Eeg is always non-Healthy, so there is always at least one root.
    # If a future edit makes every node Healthy, headline the last node rather
    # than dereferencing $null.
    if (-not $boundaryNode) { $boundaryNode = $nodes[$nodes.Count - 1] }

    # Localization: WHY the chain stops, which is a different question from what
    # the boundary node's health is. An operator needs to know whether they are
    # looking at a fault, at an expected idle state, or at a sensor nobody read.
    $localization = switch ($boundaryNode.Health) {
        'Failed'   { 'Failure' }
        'Degraded' { 'Degrading' }
        'Idle'     { 'Idle' }
        default    { if ($boundaryNode.Observation -eq 'NotMeasurable') { 'LimitOfTool' } else { 'NotObserved' } }
    }

    # ── Localization SCOPE: is a device-scoped claim admissible at all? ───────
    # Derived from the target binding and nothing else, and applied to the
    # CLAIM rather than to the readings. Every node from Pairing down describes
    # a particular headset; if the recording never established which one, the
    # readings remain honest and the attribution does not.
    #
    # Unstated is not Suspended. A caller that says nothing has not told us the
    # target is unknown -- it has told us nothing -- so the sentence is left
    # exactly as it was rather than degraded on a guess. It is emitted, so a
    # wiring break shows up in chain.jsonl as a state instead of as silence.
    $localizationScope = switch ($TargetBinding) {
        'Explicit'  { 'Confirmed' }
        'Unique'    { 'Confirmed' }
        'Inferred'  { 'Provisional' }
        'Ambiguous' { 'Suspended' }
        'Unscoped'  { 'Suspended' }
        default     { 'Unstated' }
    }
    $targetLabel = if ($TargetLabelName -and $TargetLabelMac) { "$TargetLabelName ($TargetLabelMac)" }
                   elseif ($TargetLabelName) { $TargetLabelName }
                   elseif ($TargetLabelMac)  { $TargetLabelMac }
                   else { $null }

    # Discrete, and about the LOCALIZATION claim rather than about the world. A
    # boundary the probe watched directly is a strong claim; a boundary that is
    # just where the readings ran out is a weak one. No numeric score: nothing
    # here computes a calibrated probability, and printing 0.95 would invent one.
    $confidence = if ($boundaryNode.Health -eq 'Failed' -and $boundaryNode.Observation -eq 'Observed') { 'High' }
                  elseif ($boundaryNode.Health -in @('Degraded', 'Idle') -and $boundaryNode.Observation -eq 'Observed') { 'Medium' }
                  else { 'Low' }
    # CAPPED by scope, because confidence is a claim about the localization and
    # the localization is only as good as the identity it is scoped to. A
    # boundary observed directly on a headset nobody identified was reading
    # 'High' -- the strongest label this function has -- on the one screen where
    # the identity was simultaneously printed as unknown.
    if ($localizationScope -eq 'Provisional' -and $confidence -eq 'High') { $confidence = 'Medium' }
    if ($localizationScope -eq 'Suspended') { $confidence = 'Low' }

    # THE EDGE LABEL IS THE BOUNDARY STATEMENT. "pairing record -> live wireless
    # link" already names the verified side and the unverified side, so a
    # "verified through X" preamble in front of it is the same fact twice.
    #
    # The verified SET is not enumerated in the sentence either. It is the set of
    # green chips directly above, and re-listing seven of them pushed this line
    # to three dense rows -- at which point the conclusion an operator needs is
    # buried in a restatement of the picture they can already see. The counts
    # stay, because "6 of 8" is the part the chips do not say at a glance.
    $verifiedCount = $verified.Count
    $totalCount    = $nodes.Count

    $summary = switch ($localization) {
        'Failure'     { "FIRST FAILING STEP: $($boundaryNode.EdgeLabel).  ($verifiedCount of $totalCount steps verified.)" }
        'Degrading'   { "FIRST DEGRADING STEP: $($boundaryNode.EdgeLabel).  ($verifiedCount of $totalCount steps verified.)" }
        'Idle'        { "Chain stops at '$($boundaryNode.Title)': $($boundaryNode.Detail) -- an expected idle state, not a fault.  ($verifiedCount of $totalCount verified.)" }
        'LimitOfTool' { "All $verifiedCount measurable steps verified. '$($boundaryNode.Title)' is beyond what this tool can measure, so this is NOT proof the session is good." }
        default       { "Chain stops at '$($boundaryNode.Title)': NOT OBSERVED -- nothing that depends on it is ruled in or out.  ($verifiedCount of $totalCount verified.)" }
    }

    # ── The scope gate on the sentence ───────────────────────────────────────
    # SUSPENDED replaces the boundary claim outright. "FIRST FAILING STEP:
    # adapter present -> Windows pairing record" alongside "no headset selected"
    # is a failure attributed to a device this recording never identified. The
    # counts survive, because how much was verified is true whatever the
    # readings are about.
    #
    # PROVISIONAL keeps the boundary and marks it. A named candidate is a real
    # working hypothesis and withholding it would throw away the most useful
    # thing on the screen; presenting it as settled is what this fixes.
    #
    # Deliberately does NOT touch Idle or LimitOfTool: neither attributes a
    # fault to a device, so neither is weakened by not knowing which device.
    #
    # The WHERE-FROM sentence is NOT inlined here. It travels as TargetEvidence,
    # which chain.jsonl records and the window puts on its own scope line. Two
    # paragraphs in the boundary label is how the conclusion stops being read at
    # all, and this line is the highest-value one in the window.
    if ($localizationScope -eq 'Suspended' -and $localization -in @('Failure', 'Degrading', 'NotObserved')) {
        $why = if ($TargetBinding -eq 'Ambiguous') {
            'more than one NeurOptimal headset is paired here and this recording was never told which one this session is about'
        } else {
            'this recording is not scoped to a headset'
        }
        $summary = "TARGET NOT CONFIRMED -- $why. LOCALIZATION SUSPENDED: the readings below are real, but nothing attributes them to a known device, so no failing step is named. ($verifiedCount of $totalCount steps verified.) Identify the headset to localize this."
    } elseif ($localizationScope -eq 'Provisional' -and $localization -in @('Failure', 'Degrading', 'NotObserved')) {
        $cand = if ($targetLabel) { "candidate: $targetLabel" } else { 'candidate not named' }
        $summary = "TARGET NOT CONFIRMED ($cand) -- PROVISIONAL. $summary"
    }
    # A second root is reported rather than dropped. Two independent branches
    # being down at once is a materially different situation from one, and the
    # headline can only carry one of them.
    #
    # NotMeasurable roots are excluded here. The EEG node is a root on every
    # healthy tick, so listing it in this clause would put the same sentence on
    # screen permanently and train readers to skip the clause -- at which point
    # it stops delivering the second root it exists for. Its caveat is not lost:
    # when everything measurable IS healthy, EEG becomes the headline boundary
    # and the caveat is the whole summary, which is the moment it matters.
    $otherRoots = @($roots | Where-Object { $_.Id -ne $boundaryNode.Id -and $_.Observation -ne 'NotMeasurable' })
    if ($otherRoots.Count -gt 0) {
        $otherTitles = @($otherRoots | ForEach-Object { "$($_.Title) ($($_.Detail))" })
        $summary += " Also unverified, independently: $($otherTitles -join ', ')."
    }
    # Counted, not listed. Which steps are consequences is already carried by the
    # dimmed chips; what the sentence has to add is that they are consequences at
    # all -- the "four problems" reading this whole function exists to prevent.
    #
    # $consequences, NOT $blocked: see the note where it is built. And not at all
    # when localization is suspended, because "consequences of THIS" points at a
    # boundary the sentence has just refused to name.
    if ($consequences.Count -gt 0 -and $localizationScope -ne 'Suspended') {
        $stepWord = if ($consequences.Count -eq 1) { 'step below is a consequence' } else { 'steps below are consequences' }
        $summary += " $($consequences.Count) $stepWord of this, not separate problems."
    }

    $nodeObjects = @($nodes | ForEach-Object {
        [pscustomobject]@{
            PSTypeName   = 'WinConfig.FlightRecorder.DiagnosticChainNode'
            Id           = $_.Id
            Title        = $_.Title
            EdgeLabel    = $_.EdgeLabel
            DependsOn    = @($_.DependsOn)
            Health       = $_.Health
            Observation  = $_.Observation
            Detail       = $_.Detail
            # $null on every node that does not set one. ContainsKey rather than
            # a bare property read: this module runs under Set-StrictMode, where
            # reading an absent hashtable key THROWS rather than returning
            # $null, so "additive" has to be spelled out.
            Cause        = $(if ($_.ContainsKey('Cause')) { $_.Cause } else { $null })
            # Node-specific identity fields, projected the same defensive way as
            # Cause and for the same reason: they exist on ONE node each, and a
            # bare property read under StrictMode would throw on every other.
            # They are what the panels print; nothing here judges them, and
            # chain.jsonl's node projection is unchanged.
            AdapterName   = $(if ($_.ContainsKey('AdapterName'))   { $_.AdapterName }   else { $null })
            DriverVersion = $(if ($_.ContainsKey('DriverVersion')) { $_.DriverVersion } else { $null })
            Ports         = @($(if ($_.ContainsKey('Ports'))       { $_.Ports }         else { @() }))
            RoleState     = $(if ($_.ContainsKey('RoleState'))     { $_.RoleState }     else { $null })
            Roles         = @($(if ($_.ContainsKey('Roles'))       { $_.Roles }         else { @() }))
            HeldPorts     = @($(if ($_.ContainsKey('HeldPorts'))   { $_.HeldPorts }     else { @() }))
            BlockedBy    = $_.BlockedBy
            IsRoot       = ($null -eq $_.BlockedBy -and $_.Health -ne 'Healthy')
            Evidence     = @($_.Evidence)
        }
    })

    return [pscustomobject]@{
        PSTypeName      = 'WinConfig.FlightRecorder.DiagnosticChain'
        Nodes           = $nodeObjects
        # No leading comma on these. The `,@()` idiom guards against PowerShell
        # unrolling a single-element array on RETURN from a function; a property
        # assignment does not unroll, so the comma here would nest each list
        # inside a one-element wrapper and every consumer joining it would print
        # System.Object[].
        VerifiedNodeIds = $verified
        RootNodeIds     = @($roots | ForEach-Object { $_.Id })
        BoundaryNodeId  = $boundaryNode.Id
        BoundaryEdge    = $boundaryNode.EdgeLabel
        BlockedNodeIds  = $blocked
        # Its own name, alongside BlockedNodeIds rather than instead of it. One
        # field, one answerer: BlockedNodeIds is the dependency walk, this is the
        # subset the operator sentence is entitled to call consequences.
        ConsequenceNodeIds = $consequences
        Localization    = $localization
        # Scope is reported SEPARATELY from Localization, not folded into it.
        # "where does the chain stop" and "may this recording attribute that to a
        # device" are different questions, and a single enum carrying both would
        # make an unscoped failure indistinguishable from an idle box.
        TargetBinding     = $TargetBinding
        TargetConfirmed   = ($TargetBinding -in @('Explicit', 'Unique'))
        TargetLabel       = $targetLabel
        # The two halves as well as the joined label. The Arc panel prints the
        # device on one line and its MAC on another, and splitting "Name (MAC)"
        # back apart in the renderer would be a parser standing in for a fact
        # this function was given. TargetLabel is unchanged and stays the one
        # string chain.jsonl records.
        TargetName        = $(if ($TargetLabelName) { [string]$TargetLabelName } else { $null })
        TargetMac         = $(if ($TargetLabelMac)  { [string]$TargetLabelMac }  else { $null })
        # Echoed, not re-derived. The window's scope line and chain.jsonl both
        # need "where did this identity come from", and Get-BtTargetBinding is
        # the one place that answers it.
        TargetEvidence    = $TargetBindingEvidence
        LocalizationScope = $localizationScope
        Confidence      = $confidence
        Summary         = $summary
    }
}

# =============================================================================
# RECORDER VIEW MODEL  (presentation mapping -- decides nothing)
# =============================================================================

function Get-BtRecorderView {
    <#
    .SYNOPSIS
        Pure. Projects a Get-BtDiagnosticChain result onto the six panels the
        Flight Recorder window draws, plus one plain-language verdict.
    .DESCRIPTION
        WHAT THIS IS FOR. The chain is eight nodes, five health values, five
        observation values and a boundary sentence written for a triage
        engineer. The operator in a clinic has three questions -- is it working,
        roughly where is the problem, has anything changed -- and the old window
        answered them with a wall of chips and prose. This maps the SAME chain
        object onto a picture: three connection panels and three supporting
        signals.

        IT DECIDES NOTHING. Every health value, observation, BlockedBy and the
        boundary itself are read off the chain unchanged. There is no second
        opinion here about what is wrong, because a second opinion is the
        channel-mismatch defect this repo has filed nine instances of: the
        moment two answerers disagree, whichever one a human happens to be
        looking at wins. What this function chooses is only which panel a node
        appears in, which short word to print, and which glyph to draw.

        THE PANELS ALSO CARRY THE IDENTIFIERS. This System names the adapter and
        its driver, NeurOptimal Arc names the headset and its MAC, and COM Ports
        carries the DATA/COMMAND mapping. Those three facts used to be printed
        in a header strip above the picture, which meant the screen stated the
        target twice and the ports twice -- and two statements of one fact can
        disagree. They are read off the chain here and rendered once, in the
        panel whose question they answer.

        THE PICTURE IS NOT THE DEPENDENCY GRAPH, and the difference is
        deliberate. The connection row is This System - Bluetooth Link -
        NeurOptimal Arc. "Bluetooth Link" rather than "Bluetooth" because the
        panel to its left already names the Bluetooth adapter, and one word for
        both is how a healthy adapter gets read as a healthy connection. The
        supporting signals -- NeurOptimal, COM Ports, Data Flow -- are drawn
        UNCONNECTED, side by side, because they do not form a chain:

          * NeurOptimal has no Bluetooth dependency at all. Chaining it under
            the radio would report "NeurOptimal is closed" as a consequence of a
            dead link, which is false and sends the operator to the wrong layer.
          * COM registration is HISTORICAL. Registered ports are what an earlier
            successful pairing left behind; they survive a flat battery and a
            headset in a drawer. Drawing them downstream of the live link would
            make every idle box show a broken COM layer.
          * Data activity is a measurement of read operations, not proof of a
            valid EEG session.

        WHAT THE COM PANEL MERGES, AND THE RULE IT USES. Two chain nodes land in
        one panel: ComPorts (are ports registered -- historical) and PortHold
        (is a process holding one right now -- observed, or NOT observed in the
        non-intrusive arm). One panel showing two facts must never let the
        stronger-sounding one speak for the weaker, so the precedence is fixed
        and stated:

          1. no ports registered            -> the registration failure wins
          2. hold was NOT observed          -> says so; never reads as 'idle'
          3. a port is held                 -> current, positive, Observed
          4. registered but nobody holds it -> Idle + a HISTORICAL marker
          5. anything else                  -> carries PortHold's own reading

        Rule 4 is the one that matters: an idle registered port must not look
        like a live connection, and it must not look like a fault either.

        EEG IS NOT A PANEL. It is a permanent footnote. Every measurable step
        going green does not prove the session is good, and a node that is
        NotMeasurable on every tick of every recording would be skipped by the
        time it mattered. As a footnote under the verdict it is read at exactly
        the moment the reader is drawing the conclusion it limits.

        TARGET IDENTITY GATES THE ARC PANEL, NOT THE READINGS. When the chain
        reports LocalizationScope 'Suspended' the recording never established
        which headset it is describing, so the Arc panel shows "Not confirmed"
        rather than a device-specific verdict. The other panels keep their
        measured faces: those readings are honest, they are simply not
        attributable.
    .PARAMETER Chain
        A WinConfig.FlightRecorder.DiagnosticChain from Get-BtDiagnosticChain.
    .OUTPUTS
        PSCustomObject (PSTypeName WinConfig.FlightRecorder.RecorderView).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Chain)

    $byId = @{}
    foreach ($n in @($Chain.Nodes)) { if ($n -and $n.Id) { $byId[$n.Id] = $n } }

    # Marker text AND a shape, never colour alone. Roughly one man in twelve
    # cannot separate this palette's green from its red, and these windows are
    # read over the phone from a screenshot.
    #
    # Local, NOT script:-scoped. A script:-scoped inner function would be
    # redefined into module scope on every call and would outlive this one.
    function Resolve-TileFace {
        param([string]$Health, [string]$Observation)
        switch ($Health) {
            'Healthy'  { return @{ Marker = '[ok]';   Glyph = 'Check';    Level = 'Healthy'  } }
            'Failed'   { return @{ Marker = '[!]';    Glyph = 'Cross';    Level = 'Failed'   } }
            'Degraded' { return @{ Marker = '[~]';    Glyph = 'Warn';     Level = 'Degraded' } }
            'Idle'     { return @{ Marker = '[idle]'; Glyph = 'Dash';     Level = 'Idle'     } }
        }
        if ($Observation -eq 'NotMeasurable') { return @{ Marker = '[n/a]'; Glyph = 'NotApplicable'; Level = 'NotMeasurable' } }
        return @{ Marker = '[?]'; Glyph = 'Question'; Level = 'Unknown' }
    }

    function New-ViewTile {
        param(
            [string]$Slot, [string]$Label, $Node, [string]$Caption,
            [hashtable]$Face, [string]$Note, [string]$Caveat, [array]$NodeIds,
            [array]$Details
        )
        $f = if ($Face) { $Face } else { Resolve-TileFace $Node.Health $Node.Observation }
        return [pscustomobject]@{
            PSTypeName  = 'WinConfig.FlightRecorder.RecorderViewTile'
            Slot        = $Slot
            Label       = $Label
            Marker      = $f.Marker
            Glyph       = $f.Glyph
            Level       = $f.Level
            Caption     = $Caption
            # IDENTIFIERS, not state. Adapter driver, headset MAC, DATA/COMMAND
            # port numbers: the facts that used to be crammed into the header
            # strip, moved to the panel whose question they answer. They are a
            # SEPARATE field from Caption and Note because they are neither a
            # reading nor context on one -- a renderer must be able to draw them
            # in their own weight, and a reader must not mistake a COM number
            # for a verdict.
            Details     = @($(if ($Details) { $Details | Where-Object { $_ } } else { @() }))
            # A note is context on a reading that WAS taken ("checked at start").
            # A caveat is a warning that limits what the reading may be used for
            # ("target not confirmed"). They are rendered differently, so they
            # are separate fields rather than one string a renderer has to
            # classify.
            Note        = $Note
            Caveat      = $Caveat
            # Historical is its own axis, never folded into Level. A fact that
            # was true earlier and was not re-checked must not draw the same as
            # a live healthy reading.
            Historical  = [bool]($Node -and $Node.Observation -eq 'Historical')
            Blocked     = [bool]($Node -and $Node.BlockedBy)
            BlockedBy   = $(if ($Node) { $Node.BlockedBy } else { $null })
            NodeId      = $(if ($Node) { $Node.Id } else { $null })
            NodeIds     = @($(if ($NodeIds) { $NodeIds } elseif ($Node) { @($Node.Id) } else { @() }))
            Node        = $Node
        }
    }

    # ── This System  <- Adapter ───────────────────────────────────────────────
    # Historical by construction: the adapter is read once, at recording start.
    # The note says so rather than letting a start-of-run reading pass as live.
    #
    # NAMED, not just graded. "Bluetooth ready" was true of every working box
    # and told a reader nothing they could act on; WHICH radio and WHICH driver
    # is the question this panel exists for, and the answer differs on every
    # machine a capture arrives from. The green ring and the glyph still carry
    # the state -- the caption stops repeating them.
    #
    # ONE identifier line, deliberately. This is not a hardware inventory: the
    # full adapter record is already in the technical details and in the
    # capture, and a panel that grows a line per fact is the header problem
    # moved rather than fixed.
    $adapter = $byId['Adapter']
    $adapterName = [string]$adapter.AdapterName
    $hostDetails = @()
    $hostCaption = switch ($adapter.Health) {
        'Healthy' { if ($adapterName) { $adapterName } else { 'Bluetooth ready' } }
        'Failed'  { $adapter.Detail }
        default   { 'Not read' }
    }
    if ($adapter.Health -eq 'Healthy') {
        if ($adapter.DriverVersion) { $hostDetails += "Driver $($adapter.DriverVersion)" }
    } elseif ($adapterName) {
        # A fault takes the caption, so the identity drops to the detail line --
        # "Status Error" is not actionable without knowing which adapter it is
        # about, and that is exactly the state where the name matters most.
        $hostDetails += $adapterName
    }
    $hostNote = if ($adapter.Observation -eq 'Historical') { 'read at start' } else { '' }
    $tileHost = New-ViewTile -Slot 'Host' -Label 'This System' -Node $adapter -Caption $hostCaption -Note $hostNote -Details $hostDetails

    # ── Bluetooth Link  <- RadioLink ──────────────────────────────────────────
    # NOT "Bluetooth". The panel to its left already names the Bluetooth
    # ADAPTER, and one screen carrying "Bluetooth" twice for two different
    # things -- the hardware in this PC and the live connection to the headset --
    # is the ambiguity that makes an operator read a healthy adapter as a
    # healthy connection.
    # Cause, not health, chooses the words. 'Failed' covers both a link that
    # dropped and a link that was never there while a port is held, and telling
    # an operator "connection lost" about the second is a claim the reading does
    # not support.
    $link = $byId['RadioLink']
    $wirelessCaption = switch ($link.Health) {
        'Healthy' { 'Connected' }
        'Failed'  {
            switch ([string]$link.Cause) {
                'Dropped'             { 'Connection lost' }
                'PortHeldWithoutLink' { 'No link' }
                default               { 'No link' }
            }
        }
        'Idle'    { 'Not connected' }
        default   { 'Not read' }
    }
    # Idle is a legitimately-negative reading, not a fault, and the note is
    # where that is said in the panel rather than in a paragraph below it.
    $wirelessNote = if ($link.Health -eq 'Idle') { 'normal between sessions' } else { '' }
    $tileWireless = New-ViewTile -Slot 'Wireless' -Label 'Bluetooth Link' -Node $link -Caption $wirelessCaption -Note $wirelessNote

    # ── NeurOptimal Arc  <- Pairing, gated by target identity ─────────────────
    # THE PANEL NAMES THE DEVICE. Capture 8E39860E4AF2 measured the wrong
    # headset for 37 minutes, and the fix at the time was to pin the identity in
    # the header strip. It is pinned here instead: the same fact, in the panel
    # that is about that device, rather than repeated in two places where the
    # two can disagree about which headset this recording is scoped to.
    #
    # "Identified" is gone as a caption wherever an identity is actually shown.
    # A tick, a device number and a MAC already say it was identified; the word
    # only survives for the case where the pairing reading is healthy and no
    # identity reached this function -- where it is the honest answer.
    $pair = $byId['Pairing']
    $arcFace   = $null
    $arcCaveat = ''
    $arcDetails = @()
    $arcName = [string]$Chain.TargetName
    $arcMac  = [string]$Chain.TargetMac
    # The panel is already labelled "NeurOptimal Arc", so a device named
    # "NeurOptimal Arc 000013" would print the product name twice and push the
    # only distinguishing part -- the device number -- to the ellipsis. Trimmed
    # by exact literal prefix, never by a pattern: renaming a device in a
    # renderer is how a capture ends up describing a headset that was not there.
    $arcIdentity = $arcName
    foreach ($prefix in @('NeurOptimal Arc ', 'NeurOptimal ')) {
        if ($arcIdentity -and $arcIdentity.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $arcIdentity = $arcIdentity.Substring($prefix.Length).Trim()
            break
        }
    }
    $arcCaption = switch ($pair.Health) {
        'Healthy'  {
            if ($arcIdentity) { $arcIdentity }
            elseif ($arcMac)  { $arcMac }
            else              { 'Identified' }
        }
        'Degraded' { 'More than one match' }
        default    { $pair.Detail }
    }
    # The MAC stays on screen through a FAILED pairing reading too. "Windows is
    # not seeing the Arc" is a claim about a particular headset, and a reader
    # sent to check a headset needs to know which one.
    if ($arcMac -and $arcCaption -ne $arcMac) { $arcDetails += $arcMac }
    if ($Chain.LocalizationScope -eq 'Suspended') {
        # The Pairing reading here is about a fallback candidate, so printing it
        # under a panel labelled "Arc" would name a device this recording never
        # identified. The reading is not discarded -- it is still on the node and
        # in the details -- but the panel stops claiming it describes the Arc.
        $arcFace    = @{ Marker = '[?]'; Glyph = 'Question'; Level = 'Unknown' }
        $arcCaption = 'Not confirmed'
        # The identity lines are DROPPED here, not merely caveated. A MAC printed
        # confidently under a panel that has just said the target is unconfirmed
        # is the overconfident device conclusion this scope gate exists to
        # prevent; the candidate travels as a caveat, which is drawn as a
        # warning rather than as a fact.
        $arcDetails = @()
        $arcCaveat  = if ($Chain.TargetLabel) { "Candidate: $($Chain.TargetLabel)" } else { 'No candidate named' }
    } elseif ($Chain.LocalizationScope -eq 'Provisional') {
        $arcCaveat = 'Target not confirmed'
    } elseif ($Chain.LocalizationScope -eq 'Unstated') {
        # A caller that told this recording nothing about its target. It is not
        # Suspended -- nothing has claimed the target is unknown -- but it must
        # not read as a confirmed one either. This used to be said only on a
        # header line; with that line gone it has to be said here or a wiring
        # break becomes silence, which is the failure mode this repo keeps
        # finding: an absent measurement rendered as nothing at all.
        $arcCaveat = 'Target not stated'
    }
    $tileArc = New-ViewTile -Slot 'Arc' -Label 'NeurOptimal Arc' -Node $pair -Caption $arcCaption -Face $arcFace -Caveat $arcCaveat -Details $arcDetails

    # ── NeurOptimal  <- App ───────────────────────────────────────────────────
    $app = $byId['App']
    $appCaption = switch ($app.Health) {
        'Healthy' { 'Running' }
        'Idle'    { 'Not running' }
        default   { 'Not read' }
    }
    $appNote = if ($app.Health -eq 'Idle') { 'not a fault' } else { '' }
    $tileApp = New-ViewTile -Slot 'App' -Label 'NeurOptimal' -Node $app -Caption $appCaption -Note $appNote

    # ── COM Ports  <- ComPorts + PortHold, by the precedence in the header ────
    $com  = $byId['ComPorts']
    $hold = $byId['PortHold']
    $comNode = $hold
    $comCaption = $hold.Detail
    $comNote = ''
    if ($com.Health -eq 'Failed') {
        $comNode    = $com
        $comCaption = 'None registered'
    } elseif ($hold.Observation -eq 'NotObserved') {
        # Never 'idle'. Nothing looked, and an unread sensor that draws like a
        # reading is the silence a reader fills in with "fine".
        $comCaption = $hold.Detail
    } elseif ($hold.Health -eq 'Healthy') {
        # Deliberately NOT "held by NO.exe", which is what the brief for this
        # panel asked for. The hold test opens a port and observes that it is
        # refused; that proves SOME process owns it, and nothing in this
        # recording binds the handle to NeurOptimal (issue #93). Naming a
        # process here would be the recorder asserting an owner it did not
        # measure, on the one screen an operator uses to pick a remedy.
        #
        # The port numbers left this caption when they gained their own lines
        # below, and the note that used to say "in use by a process" moved INTO
        # the caption: two lines saying the same thing beside a mapping that
        # says something new is the density this pass is removing.
        $comCaption = 'Held by a process'
    } elseif ($hold.Health -eq 'Idle') {
        $comCaption = 'Registered, idle'
        $comNote    = 'nobody is using it'
    }

    # ── The DATA / COMMAND mapping, which used to live in the header strip ────
    #
    # Roles come from Resolve-ComPortRole via Get-ComPortRoleMap and are read
    # here, never re-derived: FI-012 records that the COM NUMBER moves on every
    # re-pair while the channel does not, so a positional guess ("the lower
    # number is DATA") would be wrong on exactly the machines this recorder
    # exists for. Where the roles are not established the ports are still shown
    # -- WITHOUT role labels. A tech sent to the wrong port with confidence is
    # worse off than one told the roles are not known.
    $comPorts = @($com.Ports | Where-Object { $_ })
    $comHeld  = @($hold.HeldPorts | Where-Object { $_ })
    $comRoles = @($com.Roles | Where-Object { $_ })
    # Marks the port a process is holding, inside the mapping rather than as a
    # separate line. Which CHANNEL is held is diagnostic in itself -- a held
    # command port with an idle data port is not the same situation as the
    # reverse -- and that distinction had nowhere to appear before.
    function Format-ComPortList {
        param([array]$Ports, [array]$Held)
        return (@($Ports | ForEach-Object {
            if ($Held -contains $_) { "$_ (in use)" } else { "$_" }
        }) -join ', ')
    }
    $comDetails = @()
    $roleState = [string]$com.RoleState
    if ($roleState -eq 'Conflict') {
        # The FI-012 invariant failed on this box. Say nothing about which port
        # is which -- this panel prints the ports and refuses the labels.
        $comDetails += 'Roles CONFLICT -- not stated'
        if ($comPorts.Count -gt 0) { $comDetails += "Ports: $(Format-ComPortList -Ports $comPorts -Held $comHeld)" }
    } else {
        # A resolved role whose PORT NAME Windows never returned still gets its
        # line, saying so. Dropping it would delete a channel the recorder did
        # resolve, and the panel would show one port where there are two.
        $dataPorts = @($comRoles | Where-Object { $_.Role -eq 'Data' }    | ForEach-Object { if ($_.Port) { [string]$_.Port } else { '(port name not reported)' } })
        $cmdPorts  = @($comRoles | Where-Object { $_.Role -eq 'Command' } | ForEach-Object { if ($_.Port) { [string]$_.Port } else { '(port name not reported)' } })
        if ($dataPorts.Count -gt 0) { $comDetails += "Data: $(Format-ComPortList -Ports $dataPorts -Held $comHeld)" }
        if ($cmdPorts.Count -gt 0)  { $comDetails += "Command: $(Format-ComPortList -Ports $cmdPorts -Held $comHeld)" }
        # Degrade to the bare port list rather than to silence. This covers the
        # older caller that passes no map at all, a map taken before any port
        # matched, and a port whose channel could not be resolved from either
        # source -- all of which have registered ports worth showing and no
        # roles this panel is entitled to claim.
        $unroled = @($comPorts | Where-Object { $_ -notin $dataPorts -and $_ -notin $cmdPorts })
        if ($unroled.Count -gt 0) {
            $label = if ($dataPorts.Count -gt 0 -or $cmdPorts.Count -gt 0) { 'Role not established' } else { 'Ports' }
            $comDetails += "${label}: $(Format-ComPortList -Ports $unroled -Held $comHeld)"
        }
    }
    # The HISTORICAL marker rides on the panel when registration is the only
    # positive fact left -- ports exist, and we LOOKED and nobody is holding
    # one. Without it, "COM ok" during a dropped link reads as live
    # connectivity.
    #
    # Not on the not-observed path, deliberately. There the panel is reporting
    # that nothing was measured, and an H badge beside it would advertise a
    # historical POSITIVE that this recording is not entitled to lean on.
    $comHistorical = ($com.Observation -eq 'Historical' -and $com.Health -eq 'Healthy' -and $hold.Health -eq 'Idle')
    $tileCom = New-ViewTile -Slot 'Com' -Label 'COM Ports' -Node $comNode -Caption $comCaption -Note $comNote -NodeIds @('ComPorts', 'PortHold') -Details $comDetails
    # Assigned after construction: New-ViewTile derives Historical from ONE
    # node, and this panel's historical-ness is a fact about the pair.
    $tileCom.Historical = [bool]$comHistorical

    # ── Data Flow  <- DataFlow ────────────────────────────────────────────────
    # "Data Flow", and the captions stay the chain's own words -- "Reads
    # steady", not "Steady". This counts NeurOptimal's read OPERATIONS from
    # outside the application; dropping the verb would let the panel read as a
    # statement about the EEG data itself, which is the one claim the footnote
    # under it exists to refuse.
    $data = $byId['DataFlow']
    $tileData = New-ViewTile -Slot 'Data' -Label 'Data Flow' -Node $data -Caption $data.Detail

    # ── The connecting edges ──────────────────────────────────────────────────
    # Both edges carry the WIRELESS state, because the wireless node IS the
    # link. Giving them independent states would invent a distinction nothing
    # measures.
    $edgeState = switch ($tileWireless.Level) {
        'Healthy'  { 'Live' }
        'Failed'   { 'Broken' }
        'Degraded' { 'Degrading' }
        'Idle'     { 'Idle' }
        default    { 'Unknown' }
    }

    # ── Where the eye should go ───────────────────────────────────────────────
    # One focus panel, from the chain's own boundary node. Not "every non-green
    # panel": painting the consequences too is the four-problems-one-cause
    # reading the chain exists to prevent.
    $slotOfNode = @{
        Adapter = 'Host'; Pairing = 'Arc'; RadioLink = 'Wireless'
        App = 'App'; ComPorts = 'Com'; PortHold = 'Com'; DataFlow = 'Data'
        Eeg = $null
    }
    $focusSlot = if ($Chain.LocalizationScope -eq 'Suspended') { 'Arc' }
                 elseif ($slotOfNode.ContainsKey([string]$Chain.BoundaryNodeId)) { $slotOfNode[[string]$Chain.BoundaryNodeId] }
                 else { $null }

    # A SECOND independent root is marked too, and only a root. Two branches
    # being down at once is materially different from one, and the headline can
    # only carry one of them. NotMeasurable roots are excluded: Eeg is a root on
    # every healthy tick.
    $attention = New-Object System.Collections.ArrayList
    if ($focusSlot) { [void]$attention.Add($focusSlot) }
    foreach ($rootId in @($Chain.RootNodeIds)) {
        if ([string]$rootId -eq [string]$Chain.BoundaryNodeId) { continue }
        $rootNode = $byId[[string]$rootId]
        if (-not $rootNode -or $rootNode.Observation -eq 'NotMeasurable') { continue }
        $slot = $slotOfNode[[string]$rootId]
        if ($slot -and $slot -notin $attention) { [void]$attention.Add($slot) }
    }

    # ── One sentence ──────────────────────────────────────────────────────────
    # The technical localization ("FIRST FAILING STEP: pairing record -> live
    # wireless link (4 of 8)") is not deleted -- it is Chain.Summary and it
    # still renders in the technical details. What goes on the main screen is
    # the thing a non-technical operator can act on.
    $boundary = $byId[[string]$Chain.BoundaryNodeId]
    $verdict = 'The recorder could not summarise this state.'
    $verdictLevel = 'Unknown'
    if ($Chain.LocalizationScope -eq 'Suspended') {
        $verdict = 'The target Arc has not been confirmed.'
        $verdictLevel = 'Unscoped'
    } elseif ($Chain.Localization -eq 'LimitOfTool') {
        $verdict = 'Everything measurable is working.'
        $verdictLevel = 'Healthy'
    } else {
        $verdictLevel = switch ($Chain.Localization) {
            'Failure'   { 'Failure' }
            'Degrading' { 'Degrading' }
            'Idle'      { 'Idle' }
            default     { 'Unknown' }
        }
        $verdict = switch ([string]$Chain.BoundaryNodeId) {
            'Adapter' {
                if ($boundary.Health -eq 'Failed') { "This PC's Bluetooth adapter is not available." }
                else { "This PC's Bluetooth adapter was not read." }
            }
            'Pairing' {
                if ($boundary.Detail -eq 'Record only, no device') { 'Windows is not seeing the Arc, although it is still paired with it.' }
                elseif ($boundary.Health -eq 'Degraded') { 'More than one Arc matches -- which one is in use is not certain.' }
                elseif ($boundary.Health -eq 'Failed') { 'Windows is not seeing the Arc.' }
                else { 'Windows could not be asked about the Arc.' }
            }
            'RadioLink' {
                switch ([string]$boundary.Cause) {
                    'Dropped'             { 'Wireless connection to the Arc was lost.' }
                    'PortHeldWithoutLink' { "The Arc's COM port is held open, but there is no wireless connection." }
                    'IdleNoSession'       { 'No wireless connection yet -- this is normal before a session starts.' }
                    default               { 'The wireless connection could not be read.' }
                }
            }
            'App' {
                if ($boundary.Health -eq 'Idle') { 'NeurOptimal is not running.' }
                else { 'Whether NeurOptimal is running could not be read.' }
            }
            'ComPorts' {
                if ($boundary.Health -eq 'Failed') { 'No COM ports are registered for the Arc.' }
                else { "The Arc's COM ports could not be read." }
            }
            'PortHold' {
                if ($boundary.Health -eq 'Idle') { "NeurOptimal has not opened the Arc's COM connection." }
                elseif ($boundary.Observation -eq 'NotObserved') { 'COM port ownership was not measured during this recording.' }
                else { "The Arc's COM connection could not be read." }
            }
            'DataFlow' {
                if ($boundary.Health -eq 'Failed') { 'The connection is present, but data activity has stopped.' }
                elseif ($boundary.Health -eq 'Degraded') { 'The connection is present, but data activity is falling.' }
                elseif ($boundary.Observation -eq 'NotObserved') { 'Data activity was not measured during this recording.' }
                else { 'Establishing a data baseline -- keep recording.' }
            }
            default { "The recorder stopped at '$($boundary.Title)'." }
        }
    }

    # One short clause of context, and only when it changes what the reader
    # should do. "NeurOptimal is still running" beside a wireless fault is the
    # difference between blaming the app and blaming the link.
    $verdictContext = ''
    if ($verdictLevel -in @('Failure', 'Degrading') -and $focusSlot -ne 'App' -and $app.Health -eq 'Healthy') {
        $verdictContext = 'NeurOptimal is still running.'
    }

    return [pscustomobject]@{
        PSTypeName     = 'WinConfig.FlightRecorder.RecorderView'
        Connection     = @($tileHost, $tileWireless, $tileArc)
        Signals        = @($tileApp, $tileCom, $tileData)
        EdgeState      = $edgeState
        FocusSlot      = $focusSlot
        AttentionSlots = @($attention)
        Verdict        = $verdict
        VerdictLevel   = $verdictLevel
        VerdictContext = $verdictContext
        # Permanent, and permanently outside the panels. Nothing this tool
        # measures certifies session quality.
        Footnote       = 'EEG signal quality cannot be measured by this tool.'
        TargetState    = $Chain.LocalizationScope
        TargetLabel    = $Chain.TargetLabel
        # Echoed, never re-derived. The header line, the details view and
        # chain.jsonl must all read one answer to "where did this identity come
        # from".
        TargetEvidence = $Chain.TargetEvidence
        # The engineer-facing sentence, carried through unchanged so the
        # technical details view renders the same words the capture records.
        TechnicalSummary = $Chain.Summary
    }
}

function Get-BtRecorderEventText {
    <#
    .SYNOPSIS
        Pure. Turns one probe event into the short transition phrase the
        "Session events" list shows, or $null if it is not worth a line.
    .DESCRIPTION
        The old window showed every event and every heartbeat, so a 30-minute
        recording scrolled roughly 200 lines past the operator and the three
        that mattered were indistinguishable from the rest. This is the filter:
        STATE TRANSITIONS ONLY, in the operator's words.

        RETURNING $null IS A REAL ANSWER and is the common case. Anything this
        function drops is still written to events.jsonl and still printed in the
        raw technical log -- nothing is lost from the capture, it is simply not
        promoted to the summary list. Filtering at render time rather than at
        collection time is deliberate: a filter in the collector would remove
        evidence from the record, which is the one thing this redesign must not
        do.
    .OUTPUTS
        [hashtable] @{ Text; Level } or $null.
    #>
    [CmdletBinding()]
    param(
        [string]$Kind,
        [string]$State,
        [string]$Level = 'INFO'
    )

    $text = $null
    switch ($Kind) {
        'BTLINK' {
            if ($State -eq 'Connected')    { $text = 'Wireless connected' }
            if ($State -eq 'NotConnected') { $text = 'Wireless disconnected' }
        }
        'STREAM' {
            # State carries a duration suffix on stop ("Stopped (12s)"), so this
            # matches a prefix rather than the whole value.
            if ($State -eq 'Active')            { $text = 'COM connection opened' }
            elseif ($State -like 'Stopped*')    { $text = 'COM connection released' }
            elseif ($State -eq 'ReadBaseline')  { $text = 'Data baseline established' }
            elseif ($State -eq 'HeldPortsChanged') { $text = 'COM ports changed hands' }
        }
        'ANOMALY' {
            switch ($State) {
                'StreamStalled'       { $text = 'Data flow stalled' }
                'ReadRateCollapsed'   { $text = 'Data flow collapsed' }
                'AppNotResponding'    { $text = 'NeurOptimal stopped responding' }
                'SustainedComMissing' { $text = 'COM ports missing' }
                default               { $text = 'Diagnostic finding' }
            }
        }
        'process' {
            if ($State -eq 'Running')    { $text = 'NeurOptimal started' }
            if ($State -eq 'NotRunning') { $text = 'NeurOptimal stopped' }
        }
        'device' {
            switch ($State) {
                'Missing'   { $text = 'Arc no longer seen by Windows' }
                'Ambiguous' { $text = 'More than one Arc matches' }
                'SeenByPnp' { $text = 'Arc seen but not paired' }
                default     { $text = 'Arc seen by Windows' }
            }
        }
        'comport' {
            if ($State -eq 'ComPortMissing')      { $text = 'COM ports gone' }
            elseif ($State -eq 'ComPortAmbiguous'){ $text = 'COM ports ambiguous' }
            elseif ($State -eq 'ComPortFound')    { $text = 'COM ports registered' }
        }
    }

    if (-not $text) { return $null }
    return @{ Text = $text; Level = $Level }
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
        [AllowEmptyCollection()][array]$UnavailableAfterHeldPorts = @(),
        [System.Nullable[bool]]$AppRunning,
        [string]$NoExeVersion,
        [string]$IoVerdict,
        [double]$IoBaselineOpsPerSecond = 0,
        [double]$IoRecentOpsPerSecond = 0,
        # The read-rate episode live at this instant (#87). Stamped, never
        # reconstructed at summary time from timestamps: re-deriving it would be
        # a second answerer for a question the marker can answer itself, and it
        # is unreliable anyway because an episode is a Stopped -> Active epoch
        # and not necessarily one port handle (#85).
        [string]$EpisodeId,
        # Corroboration for the dead-port rule. Without these a marker placed
        # while the headset happened to be off would cross-check as a hard port
        # fault; with them the same instant reads as an unreachable device.
        [bool]$SerialIntegrityFault = $false,
        [bool]$TargetEverActive = $false,
        # See Get-ProbeStateConsistency. $false only under a disabled active
        # port-open probe, and it must reach the stored marker, not just the
        # cross-check: the marker IS the labelling channel, read months later by
        # someone who has no way to know which arm produced it.
        [bool]$PortHoldObserved = $true
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
        -UnavailableAfterHeldPorts $UnavailableAfterHeldPorts `
        -AppRunning $AppRunning -IoStalled ($IoVerdict -eq 'Collapsed') `
        -IoDegrading ($IoVerdict -eq 'Degrading') `
        -SerialIntegrityFault $SerialIntegrityFault -TargetEverActive $TargetEverActive `
        -PortHoldObserved $PortHoldObserved)

    # Recomputed here rather than passed in so a marker is self-describing: the
    # archive is read long after the fact, and a raw pair of counters makes the
    # reader do arithmetic to see that 56-against-444 is a fault.
    $fraction = if ($IoBaselineOpsPerSecond -gt 0) {
        [math]::Round(($IoRecentOpsPerSecond / $IoBaselineOpsPerSecond) * 100, 0)
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
        # $null, not @(), when nothing looked. An empty list in a stored marker
        # is the sentence "no port was held when the operator saw this dialog" --
        # and on a 12005 that is precisely the finding the corpus turns on, so a
        # fabricated one would not sit harmlessly in the archive, it would be
        # read as the discriminator.
        # Leading comma: without it an observed-but-empty held set unrolls to
        # $null and becomes indistinguishable from the unobserved case, which is
        # the exact distinction these two lines exist to make.
        HeldPorts        = $(if ($PortHoldObserved) { ,@($HeldPorts | Where-Object { $_ }) } else { $null })
        UnavailablePorts = $(if ($PortHoldObserved) { ,@($UnavailablePorts | Where-Object { $_ }) } else { $null })
        UnavailableAfterHeldPorts = $(if ($PortHoldObserved) { ,@($UnavailableAfterHeldPorts | Where-Object { $_ }) } else { $null })
        # Stated as its own field so no reader has to know that $null above is
        # meaningful, and so a marker from a pre-toggle build (field absent) is
        # not confused with one that recorded a genuine observation.
        PortHoldObserved = [bool]$PortHoldObserved
        AppRunning       = $AppRunning
        NoExeVersion     = if ($NoExeVersion) { [string]$NoExeVersion } else { $null }
        # Read-rate state at the marked instant. This is the field that turns a
        # marker into evidence about NO's own read path rather than only about
        # the Bluetooth layer.
        IoVerdict            = if ($IoVerdict) { $IoVerdict } else { 'NoBaseline' }
        IoBaselineOpsPerSecond = $IoBaselineOpsPerSecond
        IoRecentOpsPerSecond   = $IoRecentOpsPerSecond
        IoFractionOfBaseline = $fraction
        # $null when no episode was open -- no port was held, so the marker sits
        # in no episode. That is a real answer and must not be filled in.
        EpisodeId            = if ($EpisodeId) { $EpisodeId } else { $null }
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

    # THREE cases, not two. 'no port held' is the 12005 signature and the single
    # most consequential phrase this line can print; rendering it for a run that
    # never looked would put a fabricated discriminator into the corpus. A marker
    # from a pre-toggle build has no PortHoldObserved field at all, and that is
    # treated as observed -- which it was.
    $holdObserved = -not ($Marker.ContainsKey('PortHoldObserved') -and -not $Marker.PortHoldObserved)
    $ports =
        if (-not $holdObserved)                    { 'port hold NOT OBSERVED (active port-open probe disabled)' }
        elseif (@($Marker.HeldPorts).Count -gt 0)  { "held $(@($Marker.HeldPorts) -join ', ')" }
        else                                       { 'no port held' }

    # The read rate belongs on this line. Without it the marker for capture
    # C2FB1FD51A35 rendered as a tidy all-green state vector -- device paired,
    # radio connected, ports held, NO.exe running -- while the one number that
    # showed the fault (56 against a 444 baseline) sat unread in the record.
    $io = switch ($Marker.IoVerdict) {
        'Collapsed'  { "reads COLLAPSED to $($Marker.IoRecentOpsPerSecond)/s from a $($Marker.IoBaselineOpsPerSecond)/s baseline" }
        'Degrading'  { "reads FALLING at $($Marker.IoRecentOpsPerSecond)/s against a $($Marker.IoBaselineOpsPerSecond)/s baseline" }
        'Streaming'  { "reads steady at ~$($Marker.IoRecentOpsPerSecond)/s" }
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
    .PARAMETER ActivePortOpenProbeSetting
        The already-read setting object from Get-ActivePortOpenProbeSetting.
        Defaults to reading it here, which is deliberate and is the LOCK: this
        constructor runs before target selection and before the arrival
        snapshot, i.e. before the first instant at which any code in this
        recorder could open a target port. Every gate downstream reads the value
        off the session, so the treatment is fixed for the whole run and cannot
        be hot-switched by editing the environment mid-recording.
    .PARAMETER ForcePassiveOnly
        Forces the active port-open probe OFF for this session regardless of
        the environment setting. Introduced 2026-08-19 for the FI-012 serial
        preflight (defect D3): a corrupt namespace is now RECORDED passively
        instead of refusing to record at all, and recording it must not open
        ports into the fault. The underlying setting read is preserved
        separately (ActivePortOpenProbeSettingEnabled) so the end-of-run drift
        check still compares like with like.
    .PARAMETER ForcePassiveOnlyReason
        Human-readable provenance for the force, carried into the capture.
    #>
    [CmdletBinding()]
    param(
        $ActivePortOpenProbeSetting,
        [switch]$ForcePassiveOnly,
        [string]$ForcePassiveOnlyReason
    )

    $apop = if ($null -ne $ActivePortOpenProbeSetting) {
        $ActivePortOpenProbeSetting
    } else {
        Get-ActivePortOpenProbeSetting
    }

    # The EFFECTIVE treatment: the setting, overridden to off when the caller
    # proved the namespace corrupt before construction. All downstream gates
    # read ActivePortOpenProbeEnabled, so one computed value here is the lock.
    $apopEffective = [bool]$apop.Enabled -and -not $ForcePassiveOnly

    return @{
        # ── The active port-open probe treatment, LOCKED at construction ────
        # Pre-registration section 5.3. Absent or unreadable => ENABLED, so a
        # clinic capture can never be silently degraded by a config this
        # experiment introduced; the READ STATUS beside it is what lets an
        # experimental arm be invalidated for the same condition (section
        # 3.4(2)). One boolean could not carry both, so there are two fields.
        ActivePortOpenProbeEnabled    = $apopEffective
        # The SETTING as read, before any force. The end-of-run drift check
        # re-reads the environment and must compare against this, not against
        # the effective value -- a preflight-forced session would otherwise
        # false-flag drift on every run.
        ActivePortOpenProbeSettingEnabled = [bool]$apop.Enabled
        ActivePortOpenProbeForcedOff  = [bool]$ForcePassiveOnly
        ActivePortOpenProbeForcedOffReason = $(if ($ForcePassiveOnly) {
            if ($ForcePassiveOnlyReason) { [string]$ForcePassiveOnlyReason }
            else { 'Forced passive-only by the caller; no reason supplied.' }
        } else { $null })
        ActivePortOpenProbeReadStatus = [string]$apop.SettingReadStatus
        ActivePortOpenProbeSource     = [string]$apop.Source
        ActivePortOpenProbeRawValue   = $apop.RawValue
        # The Reason must describe the EFFECTIVE treatment. Copying the
        # setting's prose verbatim shipped a PROVENANCE line whose Reason said
        # "probe ENABLED (shipped default)" beside Enabled:false/ForcedOff:true
        # (D8, capture 41194CD099B1). The setting's own prose survives inside
        # the composed text, attributed as the setting read, so the audit
        # trail loses nothing.
        ActivePortOpenProbeReason     = $(if ($ForcePassiveOnly) {
            $fpWhy = if ($ForcePassiveOnlyReason) { [string]$ForcePassiveOnlyReason } else { 'no reason supplied' }
            "Active port-open probe FORCED OFF for this session: $fpWhy. Setting as read: $([string]$apop.Reason)"
        } else { [string]$apop.Reason })
        ActivePortOpenProbeLockedAt   = Get-Date
        # End-of-run re-read. Drift is DETECTED and reported; it never changes
        # behaviour, because a run whose treatment changed halfway through is not
        # a run with a late treatment, it is an invalid run.
        ActivePortOpenProbeEndEnabled    = $null
        ActivePortOpenProbeEndReadStatus = $null
        ActivePortOpenProbeDrift         = $null
        # Which sensors were actually live for the port-hold question. The
        # explicit list exists so absence is legible: a reader must be able to
        # tell "no sensor looked" from "a sensor looked and saw nothing", and no
        # field may be populated by whichever sensor happened to be available
        # (the channel-mismatch class, nine instances filed).
        PortObservationSources        = @(if ($apopEffective) { 'ActiveOpenProbe' })
        # 'ForcedPassiveByPreflight' is deliberately distinct from
        # 'DisabledBySetting': the first says the machine state forbade opens,
        # the second says the operator's configuration did. A scorer must be
        # able to tell an experimental arm from a fault-state capture.
        ActiveSensorState             = $(if ($apopEffective) { 'Observing' }
                                          elseif ($ForcePassiveOnly) { 'ForcedPassiveByPreflight' }
                                          else { 'DisabledBySetting' })
        # ── NO application evidence (read-only; see the collector section) ──
        # The message-store watch is opt-in by THIS seed's presence: an older
        # caller or test mock without it makes Update-NoMessageStoreWatch a
        # no-op. The change list is capped and the cap is counted -- never a
        # silent truncation.
        NoMessageStore = @{
            SampleCount        = 0
            ReadErrorCount     = 0
            ChangeCount        = 0
            DroppedChangeCount = 0
            EverNonEmpty       = $false
            FirstSnapshot      = $null
            LastSnapshot       = $null
            MaxChanges         = 50
            Changes            = [System.Collections.ArrayList]::new()
        }
        # Start/end snapshots of NO's own device table, set by the recorder.
        NoDeviceConfigStart = $null
        NoDeviceConfigEnd   = $null
        StateEnteredAt           = @{}
        LastComPortNames         = @()
        SustainedComAnomaly      = $false
        ComPortHistory           = [System.Collections.ArrayList]::new()
        ReconnectTimes           = [System.Collections.ArrayList]::new()
        BtLinkState              = 'Unknown'
        BtLinkEnteredAt          = $null
        BtLinkFlapCount          = 0
        # A Connected -> NotConnected transition before any target port has
        # ever been held is setup/connection negotiation, not evidence that an
        # established application session dropped.  Keep it in the record, but
        # separately, so the closing verdict cannot turn a pre-session radio
        # transition into session instability (CDE30CD6BF8C).
        BtLinkPreSessionFlapCount = 0
        # Link drops while a target port is actually held are the temporal
        # session fault.  The legacy total above remains for compatibility and
        # fleet counting; this field is the ordering-aware answer used by the
        # verdict.
        BtLinkActiveSessionDropCount = 0
        BtLinkEverConnected      = $false
        # Cross-evidence context findings are latched for the run. A scope
        # mismatch can disappear from the live inputs when NeurOptimal exits;
        # the saved capture must still say that it was observed.
        ScopeFindings            = @()
        # Seeded to the DISABLED state rather than 'Stopped' when the active
        # probe is off, and that is load-bearing twice over. It keeps a
        # measurement word out of a capture that took no measurement; and
        # because the transition machine below fires on
        # ($newStreamState -ne $Session.StreamingState), seeding it to the value
        # every tick will return is what stops arm B manufacturing a spurious
        # STREAM transition on tick one and an episode boundary out of a config
        # flag.
        # A preflight-forced session also seeds 'DisabledBySetting': that is
        # the value Get-StreamingState returns for ANY effectively-disabled
        # session, and the seed must equal the per-tick value or tick one
        # manufactures a spurious STREAM transition. The forced/by-setting
        # distinction is carried by ActiveSensorState and the ForcedOff fields.
        StreamingState           = $(if ($apopEffective) { 'Stopped' } else { 'DisabledBySetting' })
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
        #
        # $null when the active probe is disabled, and this is the field where
        # that matters most. $false here is the sentence "No process ever held
        # the target headset's COM port during this recording" -- a flat
        # negative claim about the session, rendered to the operator and used to
        # downgrade coverage. In arm B nothing ever looked, so the claim has no
        # basis. This is the shape #67 shipped once already, with a latch that
        # could not fire; the difference now is that the sensor is off ON
        # PURPOSE, which makes an unobserved $false even easier to believe.
        PortEverHeld             = $(if ($apopEffective) { $false } else { $null })
        # Recomputed from the live held set on EVERY tick since #85, and left
        # $null while more than one port is held rather than naming one of them:
        # the read counter is process-wide, so picking a single port out of a set
        # asserts an attribution nothing here can support. It was previously
        # assigned only on the Stopped -> Active edge, so it kept naming the set
        # from the last edge and could blame a port released mid-epoch.
        ActiveStreamPort         = $null
        # Last tick's held SET, for change detection. Compared as a sorted set,
        # not a count -- COM5 released while COM3 is acquired keeps the count at
        # one, and that is precisely the change that used to be invisible (#85).
        HeldPortsPrev            = @()
        # How often the held set changed WITHOUT ever emptying. Session-long and
        # episode-scoped, as two fields rather than one whose meaning depends on
        # when it is read.
        #
        # >0 means this recording's read baseline spans more than one port
        # handle. That is a deliberate choice and not a defect -- see the tick
        # path for why the alternative is worse -- but it IS a limit on
        # precision, and a limit a reader cannot see is indistinguishable from
        # one that does not exist.
        HeldPortSetChangeCount        = 0
        HeldPortSetChangeCountEpisode = 0
        # Every port the CURRENT episode has held at any point, so the episode
        # record can say whether its baseline covered one handle or several.
        HeldPortsThisEpisode     = @()
        # EPISODE IDENTITY (#87). Episodes carried EndedAtIso and nothing else,
        # so no operator marker could ever be placed INSIDE one -- which is
        # exactly the join needed to answer "did the 12006 land on the measured
        # collapse?". On DB98B6EE3324 both facts were measured and the question
        # was still unanswerable from the record.
        #
        # The marker stamps the id live, and the episode record carries the same
        # id, so the join is RECORDED rather than reconstructed. Reconstructing
        # it from timestamps would be a second answerer for a question the
        # marker can answer itself -- the channel-mismatch class this repo has
        # filed nine instances of -- and it is unreliable anyway, because an
        # episode is a Stopped -> Active epoch and not necessarily one handle
        # (#85).
        IoEpisodeSeq             = 0
        IoEpisodeId              = $null
        IoEpisodeStartedAt       = $null
        # Last tick's port classification. HeldPorts drives the honest operator
        # text; UnavailablePorts is the FI-012 signal the old bool test erased by
        # folding "would not open" in with "nobody has it open".
        #
        # $null, NOT @(), when the active open probe is disabled -- and that is
        # the same distinction one more time. An empty list is a MEASUREMENT
        # ("we looked at every target port and none was held"); $null is the
        # absence of one ("no sensor looked"). Seeding these to @() on a run
        # where nothing will ever observe them would put a confident negative
        # into a capture and every reader downstream would believe it.
        #
        # NOTE THE LEADING COMMA, here and in the three below. `$(if (..) { @() })`
        # evaluates to $null, not to an empty array -- PowerShell unrolls a
        # single-element pipeline and an empty array unrolls to nothing. Without
        # the comma the ENABLED branch silently produces exactly the $null the
        # disabled branch is supposed to be the only source of, which would
        # make every ordinary clinic capture claim its port hold was unobserved.
        HeldPorts                = $(if ($apopEffective) { ,@() } else { $null })
        UnavailablePorts         = $(if ($apopEffective) { ,@() } else { $null })
        # Explicit current/ever pairs (#88). The two above are kept because the
        # module reads them everywhere, but a CONSUMER must never have to know
        # that one is last-tick and the other a session union -- that asymmetry,
        # joined without noticing, is #81.
        HeldPortsEver            = $(if ($apopEffective) { ,@() } else { $null })
        UnavailablePortsCurrent  = $(if ($apopEffective) { ,@() } else { $null })
        UnavailablePortsEver     = $(if ($apopEffective) { ,@() } else { $null })
        # Per-port temporal join for #81.  A port belongs here only when an
        # unavailable observation happened on a LATER tick than a held
        # observation for that same port.  `UnavailablePortsEver` deliberately
        # remains the lossless union; consumers that make the sentence
        # "worked, then stopped opening" must use this ordered subset.
        UnavailableAfterHeldPorts        = $(if ($apopEffective) { ,@() } else { $null })
        UnavailableAfterHeldPortsCurrent = $(if ($apopEffective) { ,@() } else { $null })
        # ── Active-open throttle state (see Get-ActiveOpenDecision) ──────
        # The probe owns a target port for 12-23 % of every window in which
        # nobody else holds it (measured 2026-08-19 from captures 026B63C26C4D
        # and E470A928F98C). A held port fails a NO session start outright, and
        # a handle held across a device removal strands a registration
        # permanently. These fields exist so a quiet stretch stops costing an
        # RFCOMM setup every three seconds on both channels.
        #
        # Their PRESENCE is what opts a session in: Get-StreamingState checks
        # ContainsKey, so any older caller or test mock without them probes every
        # tick exactly as before.
        ActiveOpenAcquiredStreak      = 0
        ActiveOpenLastWorld           = $null
        ActiveOpenSkippedTicks        = 0
        ActiveOpenProbedTicks         = 0
        # Tunables, on the session rather than as constants, so an experimental
        # arm can set them and the capture records what was in force. 3 and 5
        # give: probe every tick until the answer has been identical three times,
        # then one tick in five (~15 s), with any change in the port set, the
        # application's process state, the device state or the radio link state
        # returning immediately to every tick.
        ActiveOpenStreakBeforeBackoff = 3
        ActiveOpenBackoffCadence      = 5
        StreamPeakCpuS           = 0.0
        StreamPeakWorkingSetMB   = 0
        # Was the monitored application EVER observed running during this
        # recording? Guards every sentence that makes a process-lifecycle claim
        # ("NO.exe exited") from a PORT observation. Without it the probe asserted
        # an exit for a process it had never once seen -- capture E470A928F98C,
        # 2026-08-19, four times in 27 seconds while NO.exe was not running.
        # Latching (never cleared) is deliberate: "exited" is a statement about
        # the whole run, not about the current tick.
        AppEverRunning           = $false
        # Data-flow corroboration. The probe cannot read the EEG bytes -- the port
        # is held by NO.exe, and opening it to look would steal it. NO.exe's own
        # CPU is the honest proxy available from outside: a live stream keeps
        # burning CPU, a stalled one flatlines while still holding the handle.
        StreamCpuFirstSample     = $null
        StreamCpuLastSample      = $null
        StreamFlatCpuTicks       = 0
        StreamCpuStalled         = $false
        StreamCpuStallReported   = $false
        # The stall threshold, OWNED HERE and read by the tick (one constant,
        # one owner) -- and exported with the capture so a reader can score the
        # raw series below against what was in force. The shipped value is
        # measurably ~3x too tight against the one real 12006 stall on record
        # (fires < 0.06 s/tick; the stall burned 0.183 s/tick, D6). It is NOT
        # retuned here: the retune must be argued from a corpus, and the raw
        # series below is what makes that corpus exist.
        StreamCpuStallThresholdSPerTick = 0.06
        StreamCpuStallFlatTicks         = 8
        # Raw CPU-per-tick series for the stall channel, persisted to
        # probe-session.json so the threshold can be re-scored OFFLINE from
        # field captures. Record, don't decide. Bounded; the drop is counted.
        # 4800 samples at the ~3 s cadence is ~4 hours of streaming.
        StreamCpuSamples         = [System.Collections.ArrayList]::new()
        StreamCpuSampleMax       = 4800
        StreamCpuSamplesDropped  = 0
        # Read-operation rate. Catches the case CPU cannot: only ONE of the
        # application's jobs dies, so it stays busy (audio kept playing through
        # the 12006 capture) while its serial reads stop. Relative to the box's
        # own recent history -- no absolute rate would survive a different NO
        # build or a different session type.
        IoApiAvailable           = $false
        IoLastReadOps            = $null
        # Paired with IoLastReadOps and reset with it, so every scoped sample
        # carries the elapsed time of its OWN interval (#86). The unscoped ledger
        # keeps its own pair -- see IoUnscopedLastAt -- because the two series are
        # cleared at different moments and sharing one clock would make the
        # scoped deltas span a reset.
        IoLastReadAt             = $null
        # Stamped scoped samples: @{ DeltaOps; DeltaSeconds; At }.
        #
        # RENAMED from IoReadSamples, which held bare doubles. The rename is the
        # point (#86): a rate needs a denominator, and any writer still pushing a
        # bare number now fails on a property that does not exist instead of
        # feeding the detector a duration-contaminated count it cannot tell from a
        # rate. Test-IoReadCollapse counts such samples as MalformedSamples for
        # the same reason.
        IoReadSamples            = [System.Collections.ArrayList]::new()
        # Session TOTAL samples, monotonic, never cleared (#88).
        #
        # IoReadSamples above is the CURRENT episode's buffer and is Clear()ed on
        # every port re-open, so its length answers "could a verdict be reached
        # right now", not "how many samples did this recording take". Coverage
        # asked it the second question and got the first: DB98B6EE3324 reported
        # IoSampleCount 7 while also reporting a baseline announced at 176
        # ops/tick, a peak of 297 and TWO baseline resets -- and a verdict needs
        # IoBaselineMinSeconds + IoCollapseSeconds = 27 s of history to exist at
        # all, which at that run's 4.6 s cadence is 6 samples minimum. 7 is
        # arithmetically implausible as a session total; it was the tail after the
        # last reset.
        #
        # This matters beyond the number: Coverage.Level keys off it, so a run
        # whose port is re-opened on its final tick reported 0 and could be
        # downgraded to 'NotObserved' -- a capture that measured data flow for its
        # whole length rendering as one that never measured any. That is the
        # absent-must-render-as-absent rule failing in the opposite direction: a
        # PRESENT measurement rendered as absent.
        IoSamplesTotal           = 0
        IoVerdict                = 'NoBaseline'
        IoBaselineOpsPerSecond   = 0
        IoRecentOpsPerSecond     = 0
        IoFractionOfBaseline     = $null
        # An intermittent stall never satisfies the debounce, so it used to
        # summarise as "held steady" -- the reading a dropout-every-30-seconds
        # headset would produce. These two remember the dips.
        #
        # SECONDS, not ticks (#86). This is compared against IoCollapseSeconds in
        # two places, and a tick count against a seconds threshold is not a
        # comparison at all -- on 13.5 s ticks four of them are 54 s of trouble
        # and on 3 s ticks they are 12 s. It accumulates each degraded interval's
        # OWN elapsed time.
        IoDegradedSeconds        = 0.0
        # The worst read rate seen on the TICK path, kept as a PAIR. The fraction
        # was tracked alone, and the rate that produced it was recovered from a
        # different channel entirely (the collapsed-episode ledger), so capture
        # E0C8B0588CC7 reported a worst fraction of 0% beside a worst rate of
        # null: two halves of one observation, sourced from two places, one of
        # which had nothing to say. Both are $null until something is measured --
        # 0 in a percentage field would read as "total collapse" (issue #65).
        IoWorstFractionOfBaseline = $null
        IoWorstRecentOpsPerSecond = $null
        IoStalled                = $false
        IoStallReported          = $false
        # A collapse WAS detected at some point in this run. Unresettable, and
        # deliberately separate from IoStalled, which the release/reacquire reset
        # clears because continuity is unknown while no port is held.
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
        # The live fields above describe one port-hold episode and are wiped when
        # the held set empties and later refills, because continuity is unknown
        # across that release window. A non-empty held-set change does NOT reset
        # them (#85). That reset is correct for the live measurement and was
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
        IoBaselineAnnouncedOpsPerSecond = $null
        # ── Stamped sample ledger (#84) ──────────────────────────────────────
        # Every tick on which NO.exe existed, whether or not a port was held.
        #
        # The measurement above is gated on StreamingState -eq 'Active', which is
        # derived from the INVASIVE port-open hold test. That coupling has two
        # consequences and both are structural, not incidental:
        #
        #   1. A 12005 can never be scored by read rate. 12005 means NO holds no
        #      port, so StreamingState is 'Stopped', so no sample was taken. In
        #      DB98B6EE3324 three of six markers were 12005 and were unscoreable
        #      BY CONSTRUCTION -- not for want of evidence, but because the
        #      instrument was switched off exactly when the thing occurred.
        #   2. Turning the port-open probe off (#83) would silently turn the
        #      primary measurement off with it, so the control run meant to
        #      exonerate the probe could not be scored at all.
        #
        # Each entry stamps the time, the cumulative counter, the delta and the
        # HELD-PORT SET at that moment, so a rate can be scoped after the fact
        # instead of only at capture time. That is what keeps the collapse
        # detector honest: Get-ProcessIoSample counts reads for the WHOLE process
        # (file I/O included), and today's 'Active' gate incidentally scoped the
        # baseline to port-held windows. Sampling everything without recording
        # the scope would let NO's config and session-file reads raise the
        # baseline and make a serial-only collapse HARDER to see.
        IoSamples                = [System.Collections.ArrayList]::new()
        # Bounded, and the bound is REPORTED. ~3 s ticks over the 15.4 h run in
        # 31D0729CA5B8 is ~18 k entries; the cap is well above that and exists so
        # a pathological run cannot grow this without limit. A dropped sample
        # must never be silent -- a truncated ledger that reads as complete is
        # the same class of lie as an unmeasured zero.
        IoSamplesDropped         = 0
        # The UNSCOPED counter pair, kept separate from IoLastReadOps so the
        # scoped series feeding Test-IoReadCollapse is bit-for-bit what it was.
        # Two questions, two series: "did the serial read path collapse while the
        # port was held" is the detector's; "was this process reading at all"
        # is the one a 12005 needs, and it has no port to be scoped to.
        IoUnscopedLastReadOps    = $null
        IoUnscopedTotalOps       = [double]0
        IoUnscopedFirstAt        = $null
        IoUnscopedLastAt         = $null
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
        # Raw win32 evidence for the same opens, under its own versioned
        # contract. Separate from PortOpenTiming on purpose: the two measure
        # different work and must never be pooled.
        SerialOpenAttempts       = (New-SerialOpenAttemptRecord)
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
        # SERIALCOMM / COM-symlink integrity. Preflight is the passive hard gate
        # evaluated before the recorder is constructed; start/end remain full
        # samples because only their transition can pin corruption to the run.
        SerialPortPreflight      = $null
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
    .PARAMETER Now
        The instant this tick represents. Defaults to Get-Date, which is what
        production always uses.

        It is injectable because since #86 the clock is not merely a label on
        the tick -- it is the DENOMINATOR of every read rate the tick computes.
        A detector that needs IoBaselineMinSeconds + IoCollapseSeconds of elapsed
        time to reach a verdict cannot be exercised end-to-end by a test loop
        that runs in milliseconds, and the alternative -- making the test sleep
        27 seconds, or mocking Get-Date module-wide and catching every other
        caller of it with it -- is worse than one parameter with a real default.
        ONE choke point: every timestamp in this tick derives from $now.
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
        [string]$AppProcessName = 'NO',
        [datetime]$Now = (Get-Date)
    )

    $events = @()
    $now = $Now

    $Session.TickCount++
    if (-not $Session.FirstTickAt) { $Session.FirstTickAt = $now }
    $Session.LastTickAt = $now

    # Latch BEFORE anything can render a process-lifecycle sentence this tick.
    # ContainsKey-guarded so a session built by an older caller or a test mock
    # that predates the field cannot throw under StrictMode.
    if ($Session.ContainsKey('AppEverRunning') -and $WatchState.AppProcessState -eq 'Running') {
        $Session.AppEverRunning = $true
    }

    # ── Port-hold detection (NOT a data-flow measurement) ────────────────
    # The Session is passed for exactly one reason: Get-StreamingState reads the
    # locked ActivePortOpenProbeEnabled off it and refuses to open anything when
    # the treatment is off. It is the gate for this path AND for the arrival
    # snapshot. Candidate selection is another path; the anomaly snapshot's
    # Test-ComPortInUse wrapper is the fourth and is gated independently.
    $activeProbe  = Test-ActivePortOpenProbeEnabled -Session $Session
    $streamResult = Get-StreamingState -WatchState $WatchState -Session $Session
    $newStreamState = $streamResult.State
    # Snapshot BEFORE this tick's observations are folded into the ever-union.
    # Ordering is the evidence: unavailable on this tick counts as "after held"
    # only if the SAME port was held on an earlier tick (or at arrival).
    $heldBeforeTick = @($Session.HeldPortsEver | Where-Object { $_ })
    # Tolerate a result without the port lists: Get-StreamingState is mocked in
    # tests and may be replaced by an older caller, and a missing list must not
    # take the whole tick down.
    #
    # The two absences are NOT the same and must not collapse into one branch. A
    # tolerated older caller genuinely probed and this code merely cannot see
    # what it found, so @() is the safe floor it always was. A DISABLED probe did
    # not look at all, and the only honest rendering of that is $null -- see the
    # seeding in New-DeviceProbeSession. The discriminator is the SESSION's
    # locked setting, never the shape of the result: one field, one answerer.
    #
    # LEADING COMMAS on both array branches. `$x = if (..) { @() }` assigns
    # $null: PowerShell unrolls the statement's output and an empty array
    # unrolls to nothing. The previous form wrapped the whole if in @(), which
    # hid this -- and it cannot be wrapped any more, because $null is now a
    # meaningful third value that @() would flatten straight back to @().
    $Session.HeldPorts =
        if ($streamResult -is [hashtable] -and $streamResult.ContainsKey('HeldPorts')) {
            ,@($streamResult.HeldPorts)
        } elseif (-not $activeProbe) { $null } else { ,@() }
    $newDeadPorts = @(
        if ($streamResult -is [hashtable] -and $streamResult.ContainsKey('UnavailablePorts')) { $streamResult.UnavailablePorts } else { @() }
    )
    # CURRENT vs EVER, as two fields rather than one whose meaning depends on
    # when you read it (#88, and the shape behind #81). HeldPorts is last-tick
    # only; UnavailablePorts is a session-long UNION. Joining those two without
    # noticing the mismatch is how #81's false "port will not open" was produced.
    if ($activeProbe) {
        $Session.UnavailablePortsCurrent = @($newDeadPorts | Where-Object { $_ })
        $afterHeldNow = @($Session.UnavailablePortsCurrent | Where-Object {
            $_ -in $heldBeforeTick
        } | Select-Object -Unique)
        $Session.UnavailableAfterHeldPortsCurrent = @($afterHeldNow)
        $Session.UnavailableAfterHeldPorts = @(
            @($Session.UnavailableAfterHeldPorts) + $afterHeldNow |
                Where-Object { $_ } | Select-Object -Unique
        )
        # Union across the session: a port that failed to open at any point stays
        # in the record even if it opens later.
        $Session.UnavailablePorts = @(@($Session.UnavailablePorts) + $newDeadPorts | Where-Object { $_ } | Select-Object -Unique)
        $Session.UnavailablePortsEver = @($Session.UnavailablePorts)
        # The counterpart the record never had: which ports were held at ANY
        # point. PortEverHeld below answers the boolean; nothing answered "which".
        $Session.HeldPortsEver = @(
            @($Session.HeldPortsEver) + @($Session.HeldPorts) | Where-Object { $_ } | Select-Object -Unique
        )
    }
    # else: left at the $null New-DeviceProbeSession seeded. Assigning @() here
    # -- even "harmlessly", even to a union that will never gain a member -- is
    # the precise mistake this whole section exists to avoid: it converts "not
    # observed" into "observed to be nothing" on every single tick.

    # ── Held-port SET changes (#85) ──────────────────────────────────────────
    # StreamingState is a two-valued aggregate: Active if ANY target port is
    # held, Stopped if none is. Every consequence of a port changing hands used
    # to hang off the Stopped -> Active edge, so a change in WHICH ports are held
    # -- COM5 released and reacquired while COM3 stays open -- produced no edge
    # and therefore no consequence at all. It was invisible in the record.
    #
    # DECISION, and it is deliberate: a set change is RECORDED, NOT reset.
    #
    # The comment on the reset below used to assert "a baseline must not span two
    # port handles". That rule is retired here, because the measurement never
    # supported it. The read counter is process-wide and cannot attribute a read
    # to a port (Get-ProcessIoSample), so a baseline was never per-handle -- it
    # was per-process-while-holding-something, and resetting on a set change
    # would enforce a precision the instrument does not have.
    #
    # The other half is evidence preservation. Every reset is a chance to lose a
    # measured collapse: #59 lost one to a re-open, #63 lost one to erosion. At
    # DB98B6EE3324's 27-36 s re-acquire cycle against the ~27 s a baseline needs
    # to rebuild, resetting on set changes as well would leave the detector
    # permanently blind in exactly the fault it exists to catch.
    #
    # So the imprecision is rendered instead of acted on: the episode carries how
    # many times the set changed and which ports it ever contained, and a reader
    # who wants per-handle precision can see that they do not have it.
    $heldNowSet = @($Session.HeldPorts | Where-Object { $_ } | Sort-Object)
    $heldWasSet = @($Session.HeldPortsPrev | Where-Object { $_ } | Sort-Object)
    if (($heldNowSet -join '|') -ne ($heldWasSet -join '|')) {
        # Only counted WITHIN an epoch. The set going empty and refilling is the
        # Stopped -> Active edge, which is already an episode boundary and must
        # not also be counted as a change spanning one.
        if ($heldWasSet.Count -gt 0 -and $heldNowSet.Count -gt 0) {
            $Session.HeldPortSetChangeCount++
            $Session.HeldPortSetChangeCountEpisode++
            $gained = @($heldNowSet | Where-Object { $_ -notin $heldWasSet })
            $lost   = @($heldWasSet | Where-Object { $_ -notin $heldNowSet })
            $parts  = @()
            if ($lost.Count)   { $parts += "released $($lost -join ', ')" }
            if ($gained.Count) { $parts += "acquired $($gained -join ', ')" }
            # WORDING: the hold test opens a port and observes that it is
            # refused. That proves SOME process holds it -- it does not prove
            # which, and nothing here binds the handle to NO.exe. Naming NO.exe
            # would be the same over-claim as attributing a process-wide read
            # counter to a particular port.
            $events += @{
                Kind = 'STREAM'; State = 'HeldPortsChanged'
                Reason = "the set of held COM ports changed: $($parts -join ' and '), still held: $($heldNowSet -join ', ')"
                Annotation = "[i] The set of COM ports held by another process changed without ever emptying, so this is not a stream stop. The read-rate baseline is deliberately NOT restarted here -- the read counter is process-wide and cannot attribute a read to a port, so it now spans more than one handle. Read this episode's rate as covering the whole set."
                Level = 'INFO'; Timestamp = $now
            }
        }
        $Session.HeldPortsPrev = @($heldNowSet)
    }
    # Open the FIRST episode of the run here rather than on the transition edge
    # below (#87). A session already streaming when Record was pressed produces
    # no Stopped -> Active edge at all -- the recorder seeds StreamingState from
    # the arrival snapshot -- so an episode opened only on the edge would leave
    # every such run with a null EpisodeId and no marker join. Same mistake as
    # #67's port-hold latch, caught before it shipped this time.
    $startedEpisodeThisTick = $false
    if ($heldNowSet.Count -gt 0 -and -not $Session.IoEpisodeId) {
        $null = Start-IoEpisode -Session $Session -At $now
        $startedEpisodeThisTick = $true
    }
    # Ports this EPISODE has held at any point, so the episode record can say
    # whether its baseline covered one handle or several.
    $Session.HeldPortsThisEpisode = @(
        @($Session.HeldPortsThisEpisode) + $heldNowSet | Where-Object { $_ } | Select-Object -Unique | Sort-Object
    )
    # Recomputed EVERY tick from the live set, not once per Stopped -> Active
    # edge. It was assigned in exactly one place -- inside the transition branch
    # -- so it kept naming the port set from the last edge and could attribute a
    # stall to a port that had been released partway through the epoch.
    $Session.ActiveStreamPort = if ($heldNowSet.Count -eq 1) {
        $heldNowSet[0]
    } elseif ($heldNowSet.Count -gt 1) {
        # Deliberately $null rather than a pick. With both RFCOMM channels open
        # -- the Arc's normal shape -- naming one asserts an attribution the
        # process-wide counter cannot support. Callers already fall back to the
        # live set, which is the honest answer.
        $null
    } else {
        # Nothing held right now. Keep the last known name so a teardown message
        # can still say which port it was about.
        $Session.ActiveStreamPort
    }

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
        # Raw codes for the SAME attempts -- no extra open. Absent on an older
        # caller or a test mock of Get-StreamingState, in which case the record
        # stays empty and the archive reports no raw evidence rather than
        # implying every attempt succeeded.
        if ($streamResult.ContainsKey('PortOpenObservations') -and $Session.SerialOpenAttempts) {
            foreach ($obs in @($streamResult.PortOpenObservations)) {
                $null = Add-SerialOpenAttempt -Record $Session.SerialOpenAttempts -Observation $obs
            }
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
            # is correct -- the set of held ports went EMPTY and refilled, so
            # nothing was streaming in between -- but it used to be the only
            # thing that happened, so a collapse already measured was erased by
            # NO.exe simply re-opening the port, and the session ended claiming
            # no baseline was ever established. See IoClosedEpisodes in
            # New-DeviceProbeSession for the field capture.
            #
            # RETIRED CLAIM (#85): this comment used to read "a baseline must not
            # span two port handles". It can and now does. The reset boundary is
            # the set EMPTYING, not any change to it -- see the held-port-set
            # block above for why, and HeldPortSetChangeCount for what a reader
            # gets instead.
            # Normally already closed, at RELEASE, by the Stopped branch below --
            # this call is the idempotent backstop for the paths that reach
            # 'Active' without having passed through it.
            #
            # SKIPPED when this tick already opened an episode, which is the
            # normal reacquisition shape: the block above sees an empty id and
            # opens the new episode BEFORE this branch runs, so closing here
            # would immediately close the episode that is only microseconds old,
            # leaving the id null until the next tick and burning an id on an
            # episode that never existed.
            if (-not $startedEpisodeThisTick) {
                $null = Close-IoEpisode -Session $Session -At $now
            }
            # Counted HERE, where a restart genuinely happens: the baseline
            # about to be wiped is one the measurement is starting over from.
            if ([double]$Session.IoBaselineOpsPerSecond -gt 0) { $Session.IoBaselineResetCount++ }

            $Session.IoLastReadOps          = $null
            # Reset WITH IoLastReadOps, never separately: a surviving timestamp
            # beside a cleared counter would make the first sample of the new
            # episode span the whole re-open gap, which is exactly the kind of
            # interval the detector must not divide by.
            $Session.IoLastReadAt           = $null
            $Session.IoReadSamples.Clear()
            $Session.IoVerdict              = 'NoBaseline'
            $Session.IoBaselineOpsPerSecond   = 0
            $Session.IoRecentOpsPerSecond     = 0
            $Session.IoFractionOfBaseline   = $null
            $Session.IoStalled              = $false
            $Session.IoStallReported        = $false
            $Session.IoBaselineReported     = $false
            $portInfo = if ($streamResult.ActivePort) { " on $($streamResult.ActivePort)" } else { '' }
            # A NEW episode begins here, with its own id and start time (#87).
            # This also clears the episode-scoped held-port counters, so the next
            # episode's record does not inherit this one's handle churn -- the
            # session-long counter beside it is never reset, for the same reason
            # IoClosedEpisodes is not.
            #
            # Guarded, because the FIRST tick of a run that was already streaming
            # satisfies both openers: the block above opens the run's first
            # episode, and this edge fires on the same tick. Opening twice would
            # burn E1 unused and start every such capture at E2 -- an id that
            # refers to nothing, in the field the marker join depends on.
            if (-not $startedEpisodeThisTick) {
                $null = Start-IoEpisode -Session $Session -At $now
            }
            # ActiveStreamPort is NOT assigned here any more (#85). It is
            # recomputed from the live held set every tick, above -- assigning it
            # only on this edge is what let it go stale and misattribute a stall
            # to a port released partway through the epoch.
            # Deliberately does not say "EEG data streaming" -- this event fires on
            # a handle being taken, which NO.exe does at connect whether or not the
            # headset ever delivers a sample.
            # WHO holds the port is a DIFFERENT question from WHETHER it is held,
            # and only one of them was measured. The open attempt returns
            # ERROR_ACCESS_DENIED, which says "some process owns this handle" and
            # names nobody. Naming NO.exe from that alone is a one-field/one-answerer
            # violation, and it fired in the field: capture E470A928F98C logged
            # 'NO.exe has the COM port open on COM6' four times on 2026-08-19 while
            # NO.exe was NOT RUNNING -- the holder was our own sampler. A technician
            # reading that capture would conclude a session started and stopped four
            # times in 27 seconds. Nothing of the sort happened.
            #
            # So the name is now conditioned on the one piece of evidence we do
            # have: whether the process is running at all. That is still not proof
            # of ownership -- it is a necessary condition, not a sufficient one --
            # and the wording says "the port is held" rather than "NO.exe is
            # streaming" in both branches.
            $holderKnownRunning = ($WatchState.AppProcessState -eq 'Running')
            $holderPhrase = if ($holderKnownRunning) {
                "NO.exe is running and the COM port is held$portInfo"
            } else {
                "the COM port is held by another process$portInfo -- NO.exe is NOT running, so this hold is NOT a NO session"
            }
            $evt = @{ Kind = 'STREAM'; State = 'Active'; Reason = "$holderPhrase (holder not identified: an open refusal names no process. Data flow not verified -- the probe cannot read the port while it is held)"; Annotation = $null; Level = 'OK'; Timestamp = $now }
            if (-not $holderKnownRunning) {
                $evt.Annotation = "[!] A port was taken while NO.exe was not running. Some other program on this PC is opening the headset's serial ports -- including, possibly, this diagnostic itself."
                $evt.Level = 'WARN'
            }
            if ($WatchState.DeviceState -ne 'PairedCandidate') {
                $evt.Annotation = "[!] Streaming started but device state is '$($WatchState.DeviceState)' -- unexpected"
                $evt.Level = 'FAIL'
            }
            $events += $evt
            $Session.StateEnteredAt['streaming_Active_at'] = $now
        } elseif ($prevStreaming -eq 'Active') {
            # The port set EMPTIED, so the episode ends HERE -- at the release,
            # not at the next reacquisition (#87). Leaving it open across the
            # stopped interval stamped the old id onto markers taken while no
            # port was held, which is precisely the 12005 shape, and dated every
            # episode's end to the moment the port came back.
            $null = Close-IoEpisode -Session $Session -At $now

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
                # 'NO.exe exited' is a PROCESS-LIFECYCLE claim, and this branch is
                # reached by a PORT being released. Those coincide only if NO.exe
                # was ever running in the first place. On 2026-08-19 this asserted
                # 'NO.exe exited' four times in a capture where NO.exe never ran at
                # any point -- a claim about a process the probe had not observed.
                # AppEverRunning is the guard: it is set on any tick where the
                # process was seen, so 'exited' can only be said of something that
                # was once there.
                # Missing key => a session from an older caller or a test mock that
                # predates this guard. Fall back to the previous wording rather
                # than asserting the new one on evidence that was never collected.
                if (-not $Session.ContainsKey('AppEverRunning') -or $Session.AppEverRunning) {
                    $events += @{ Kind = 'STREAM'; State = "Stopped$durationStr"; Reason = "NO.exe exited$peakInfo"; Annotation = "[~] NO.exe closed while device still paired"; Level = 'WARN'; Timestamp = $now }
                } else {
                    $events += @{ Kind = 'STREAM'; State = "Stopped$durationStr"; Reason = "the COM port was released$peakInfo"; Annotation = "[~] A port was held and released while NO.exe was never running during this recording. The holder was some other program on this PC; this was not a NO session."; Level = 'WARN'; Timestamp = $now }
                }
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
                $Session.BtLinkFlapCount++
                $Session.BtLinkActiveSessionDropCount++
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link dropped during active EEG stream$fromStr"; Annotation = "[!] Radio link lost while streaming -- this is the mid-session disconnect event"; Level = 'FAIL'; Timestamp = $now }
            } elseif ($WatchState.DeviceState -eq 'PairedCandidate') {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link dropped, device still paired$fromStr"; Annotation = "[~] Device paired but radio link down"; Level = 'WARN'; Timestamp = $now }
                $Session.BtLinkFlapCount++
                if (-not [bool]$Session.PortEverHeld) {
                    $Session.BtLinkPreSessionFlapCount++
                }
            } else {
                $events += @{ Kind = 'BTLINK'; State = 'NotConnected'; Reason = "Radio link down$fromStr"; Annotation = $null; Level = 'DIM'; Timestamp = $now }
            }
        }
    }

    # ── Read-rate sampling: UNGATED (#84) ────────────────────────────────
    # Everything below this comment used to sit behind StreamingState -eq
    # 'Active', i.e. behind the invasive port-open hold test. The primary
    # measurement the Flight Recorder exists to produce was therefore switched
    # off exactly when NO.exe held no port -- which is the definition of a 12005,
    # so a 12005 could never be scored by read rate no matter how long anyone
    # recorded. It also meant the #83 control (run once with the port probe
    # disabled) would have disabled the measurement it was meant to be scored on.
    #
    # The PROCESS LOOKUP AND THE COUNTER READ ARE HOISTED, not duplicated. One
    # Get-Process and one Get-ProcessIoSample per tick, shared by both channels:
    # a second pair would add cost to the tick #83 is about, and would let the
    # two channels disagree about the same instant.
    $noProcTick   = $null
    $ioSampleTick = $null
    if ($AppProcessName) {
        try { $noProcTick = Get-Process -Name $AppProcessName -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { $noProcTick = $null }
    }
    if ($noProcTick) {
        try {
            $ioSampleTick = Get-ProcessIoSample -Process $noProcTick
            if ($ioSampleTick) {
                # HeldPorts is assigned earlier in this tick, from the same
                # stream result the scoped channel uses, so the scope stamped
                # here and the gate below can never describe different instants.
                $null = Add-IoReadRateSample -Session $Session -ReadOps $ioSampleTick.ReadOps `
                    -At $now -HeldPorts $Session.HeldPorts
            }
        } catch { $ioSampleTick = $null }
    }

    # ── NO.exe health sampling (port-held scope) ─────────────────────────
    # Still gated, deliberately. The CPU-flatline stall means "holding the port
    # and idle", which is meaningless without the hold; and the collapse
    # detector's baseline must stay scoped to port-held windows, because
    # Get-ProcessIoSample counts the WHOLE process and letting config and
    # session-file reads in would raise the baseline and hide the serial-only
    # collapse it exists to catch.
    if ($Session.StreamingState -eq 'Active' -and $AppProcessName) {
        try {
            $noProc = $noProcTick
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
                    # Threshold and tick count come off the SESSION (seeded in
                    # New-DeviceProbeSession, exported with the capture), with
                    # the shipped literals as fallback for a session built by
                    # an older module copy or a bare test fixture.
                    $cpuFlatThreshold = if ($Session.ContainsKey('StreamCpuStallThresholdSPerTick')) { [double]$Session.StreamCpuStallThresholdSPerTick } else { 0.06 }
                    $cpuFlatTicksNeeded = if ($Session.ContainsKey('StreamCpuStallFlatTicks')) { [int]$Session.StreamCpuStallFlatTicks } else { 8 }
                    if ($null -eq $Session.StreamCpuFirstSample) { $Session.StreamCpuFirstSample = $rawCpu }
                    if ($null -ne $Session.StreamCpuLastSample) {
                        $cpuDelta = $rawCpu - [double]$Session.StreamCpuLastSample
                        # The raw series, kept beside the verdict so the D6
                        # threshold can be re-scored offline from the capture.
                        # AtUtc lets a reader recover the real tick interval --
                        # the cadence is a target, not a fact.
                        if ($Session.ContainsKey('StreamCpuSamples')) {
                            if ($Session.StreamCpuSamples.Count -lt [int]$Session.StreamCpuSampleMax) {
                                [void]$Session.StreamCpuSamples.Add(@{
                                    AtUtc     = $now.ToUniversalTime().ToString('o')
                                    CpuTotalS = [math]::Round($rawCpu, 3)
                                    CpuDeltaS = [math]::Round($cpuDelta, 3)
                                })
                            } else {
                                $Session.StreamCpuSamplesDropped++
                            }
                        }
                        if ($cpuDelta -lt $cpuFlatThreshold) {
                            $Session.StreamFlatCpuTicks++
                        } else {
                            $Session.StreamFlatCpuTicks = 0
                        }
                    }
                    $Session.StreamCpuLastSample = $rawCpu

                    if ($Session.StreamFlatCpuTicks -ge $cpuFlatTicksNeeded -and -not $Session.StreamCpuStallReported) {
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
                # The SAME read the ungated channel stamped above -- not a second
                # syscall. One counter value per tick means the scoped verdict
                # and the stamped ledger can never describe different instants.
                $ioSample = $ioSampleTick
                if ($ioSample) {
                    if ($null -ne $Session.IoLastReadOps) {
                        $opsDelta = $ioSample.ReadOps - [double]$Session.IoLastReadOps
                        # Counters are monotonic within a process. A negative
                        # delta means this is a different NO.exe, so drop the
                        # history rather than baseline across two processes.
                        if ($opsDelta -lt 0) {
                            $Session.IoReadSamples.Clear()
                        } else {
                            # The DENOMINATOR, measured on the same path that
                            # produced the numerator (#86). Taken from this
                            # session's own last scoped sample rather than from
                            # the tick target, because the target is what the
                            # cadence FAILED to be: DB98B6EE3324 aimed at 3000 ms
                            # and delivered up to 13506 ms, and using the aim
                            # would have preserved the exact artefact the unit
                            # change exists to remove.
                            $deltaSec = if ($null -ne $Session.IoLastReadAt) {
                                ($now - [datetime]$Session.IoLastReadAt).TotalSeconds
                            } else { $null }
                            [void]$Session.IoReadSamples.Add(@{
                                DeltaOps     = $opsDelta
                                DeltaSeconds = $deltaSec
                                At           = $now
                            })
                            # Incremented in the SAME place the sample is added,
                            # so the total and the buffer can never disagree about
                            # what was sampled -- only about what survives a
                            # reset, which is the whole point (#88).
                            $Session.IoSamplesTotal++
                            # Stamped from the tick path, so the idle tail is
                            # measured rather than inferred from wall clock.
                            if ($opsDelta -gt 0) { $Session.IoLastNonZeroReadAt = $now }
                        }
                    }
                    $Session.IoLastReadOps = $ioSample.ReadOps
                    # Advanced on EVERY scoped sample including the first and the
                    # post-reset one, so the next interval is measured from the
                    # last observation rather than from the last USABLE one.
                    $ioPrevReadAt = $Session.IoLastReadAt
                    $Session.IoLastReadAt = $now

                    $ioVerdict = Test-IoReadCollapse -Samples @($Session.IoReadSamples)
                    $Session.IoVerdict            = $ioVerdict.Verdict
                    $Session.IoBaselineOpsPerSecond = $ioVerdict.BaselineOpsPerSecond
                    $Session.IoRecentOpsPerSecond   = $ioVerdict.RecentOpsPerSecond
                    $Session.IoFractionOfBaseline = $ioVerdict.FractionOfBaseline

                    # Session-long memory of dips. A headset that drops out
                    # briefly and recovers never satisfies the debounce, so
                    # without this the summary would call the whole recording
                    # steady -- the exact reading an intermittent Arc produces.
                    #
                    # Accumulates THIS interval's own elapsed time, not 1 (#86).
                    # A tick count compared against IoCollapseSeconds is not a
                    # comparison, and the two places that make it are the
                    # intermittent-dip finding and the teardown-dip test.
                    if ($Session.IoVerdict -in @('Degrading', 'Collapsed')) {
                        $degSec = if ($null -ne $ioPrevReadAt) {
                            ($now - [datetime]$ioPrevReadAt).TotalSeconds
                        } else { 0 }
                        # A gap is not a dip that lasted that long -- the same
                        # ceiling the detector applies to an interval it would
                        # otherwise divide by.
                        if ($degSec -gt 0 -and $degSec -le $script:IoMaxSampleIntervalSeconds) {
                            $Session.IoDegradedSeconds += $degSec
                        }
                    }
                    if ($null -ne $ioVerdict.FractionOfBaseline -and
                        ($null -eq $Session.IoWorstFractionOfBaseline -or
                         $ioVerdict.FractionOfBaseline -lt $Session.IoWorstFractionOfBaseline)) {
                        $Session.IoWorstFractionOfBaseline = $ioVerdict.FractionOfBaseline
                        # Captured in the SAME assignment as the fraction, so the
                        # two can only ever describe the same tick. NOT [int]:
                        # the rates that matter most here are the small ones, and
                        # truncating 0.87 ops/s to 0 would report a measured
                        # trickle as total silence.
                        $Session.IoWorstRecentOpsPerSecond   = [double]$ioVerdict.RecentOpsPerSecond
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
                    # IoBaselineMinSeconds samples above IoBaselineMinOpsPerSecond --
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
                            $Session.IoBaselineAnnouncedOpsPerSecond = $ioVerdict.BaselineOpsPerSecond
                        }
                        $events += @{
                            Kind = 'STREAM'; State = 'ReadBaseline'
                            Reason = "NO.exe read baseline established at ~$($ioVerdict.BaselineOpsPerSecond) read operations per second"
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
                            Reason = "NO.exe read rate collapsed from ~$($ioVerdict.BaselineOpsPerSecond) to ~$($ioVerdict.RecentOpsPerSecond) read operations per second while still holding $ioPort"
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
            [void]$findings.Add("[!] Bluetooth serial port registrations are colliding: $($integ.CollisionCount) COM name(s) claimed by more than one device object. The symlinks still resolve, but they resolve to the ABANDONED generation -- measured in this exact state, every Bluetooth COM port on the box failed to open with win32 433 in under 2 ms, including ports with no device behind them. Treat this as broken now, not as an early warning. FIX: reboot without unpairing.")
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
        $fromOps = if ($Session.IoStalled) { [double]$Session.IoBaselineOpsPerSecond } else { [double]$ioRecord.PeakBaselineOpsPerSecond }
        $toOps   = if ($Session.IoStalled) { [double]$Session.IoRecentOpsPerSecond } else { [double]$ioRecord.WorstRecentOpsPerSecond }
        # The live baseline erodes with the recording window: on capture
        # 31D0729CA5B8 a 15.4 h idle tail dragged it to 0, and this sentence read
        # "went from ~0 to ~0 read operations per tick" -- a 0-to-0 collapse. The
        # record's peak now honours the announcement latch, so it holds the rate
        # this run actually established. Never report a from-rate below it.
        if ([double]$ioRecord.PeakBaselineOpsPerSecond -gt $fromOps) {
            $fromOps = [double]$ioRecord.PeakBaselineOpsPerSecond
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
        [void]$findings.Add("[!] Read rate collapsed while the port stayed open: NO.exe went from ~$fromOps to ~$toOps read operations per second on $portStr.$linkNote$endedNote$epNote Note this counter is process-wide, so it shows the application stopped doing the I/O it had been doing, not specifically that the port went quiet.")
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
        # needed to baseline, so a sub-floor reading makes PeakBaselineOpsPerSecond
        # nonzero without any baseline ever having been established, let alone
        # discarded. The counter increments only when a real baseline was thrown
        # away, which is exactly the claim being made here.
        if ($ioRecord.BaselineResetCount -gt 0) {
            # 'NoBaseline' here means the baseline was THROWN AWAY by a port
            # re-open, not that none was ever found. Claiming no read activity
            # was visible would be flatly contradicted by the record.
            [void]$findings.Add("[i] Read-rate monitoring restarted $($ioRecord.BaselineResetCount) time(s) during this recording because the COM port was re-opened, and the last episode had not re-established a baseline when the recording ended. Data flow WAS measured earlier (peak ~$($ioRecord.PeakBaselineOpsPerSecond) read operations per second). The end-of-session read-rate figures describe only the final episode -- do not read them as the whole session.")
        } elseif ([double]$Session.IoBaselineOpsPerSecond -eq 0) {
            [void]$findings.Add("[info] No read activity was visible on NO.exe at all this session, so data flow was NOT assessed. If the headset WAS streaming during this recording, the reads are not being issued by the NO.exe process -- on 4.x the serial I/O goes through NI-VISA, which may issue them from its own service process. Worth checking before trusting any read-rate result from this box.")
        } else {
            [void]$findings.Add("[info] Read-rate monitoring could not establish a baseline for NO.exe this session (observed ~$($Session.IoBaselineOpsPerSecond) read operations per second, below the floor needed to call a collapse). Data flow was NOT assessed -- the absence of a read-collapse finding means nothing was measured, not that nothing was wrong.")
        }
    } elseif ($Session.IoVerdict -eq 'Degrading' -and $Session.StreamingState -eq 'Active') {
        # The recording ended mid-decay WITH THE PORT STILL HELD. That last
        # condition is the whole safety argument: a normal session stop also
        # ends on a falling read rate, but it RELEASES the port on the way out,
        # so it lands on 'Stopped' and never reaches this branch. Held-and-
        # falling is the fault shape; released-and-falling is a clinic finishing
        # a session. Without the gate every stop in the field would warn.
        [void]$findings.Add("[!] NO.exe's read rate was FALLING when the recording ended, with the port still open: ~$($Session.IoRecentOpsPerSecond) read operations per second against the ~$($Session.IoBaselineOpsPerSecond) this session established for itself$(if ($null -ne $Session.IoFractionOfBaseline) { " ($($Session.IoFractionOfBaseline)% of normal)" }). It had not stayed down long enough to call a collapse, so this is a stall caught in progress. Record for longer if this repeats -- a few more seconds would have settled it.")
    } elseif ([double]$Session.IoDegradedSeconds -gt $script:IoCollapseSeconds) {
        # Dips that recovered. An intermittent dropout looks exactly like this
        # and used to summarise as a clean "[ok] held steady".
        #
        # The threshold is deliberately ABOVE IoCollapseSeconds: the tail of a
        # normal session stop can contribute up to about three ticks' worth of
        # degraded time in the gap before the port is released, so anything at or
        # below that budget would fire on routine stops. In seconds that budget
        # no longer changes size with the box's cadence -- the old tick form gave
        # a struggling machine a budget up to 4.5x larger than a healthy one,
        # which is backwards: it was most forgiving exactly where dips matter.
        # "Recovering each time" is only true if the measurement ran continuously.
        # A port re-open resets it, which looks identical to a recovery and is not
        # one, so the claim is dropped when a reset could explain it.
        $recoveryClaim = if ($ioRecord.BaselineResetCount -gt 0) {
            "The read-rate measurement also restarted $($ioRecord.BaselineResetCount) time(s) when the port was re-opened, so these dips cannot be assumed to have recovered on their own"
        } else {
            'recovering each time'
        }
        [void]$findings.Add("[~] NO.exe's read rate dipped below a quarter of its own baseline for about $([math]::Round([double]$Session.IoDegradedSeconds, 0))s in total during this recording, $recoveryClaim (worst point ~$($ioRecord.WorstFractionOfBaseline)% of normal). No single dip lasted long enough to call a collapse, but a healthy stream does not do this -- suspect an intermittent link or an Arc dropping out briefly.")
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
        $steadyOps = if ($ioRecord.PeakBaselineOpsPerSecond -gt 0) { $ioRecord.PeakBaselineOpsPerSecond } else { $Session.IoBaselineOpsPerSecond }
        $steadyNote = if ($Session.IoDegradedSeconds -gt 0) {
            " (one brief dip, within the allowance a normal session stop accounts for)"
        } else { '' }
        [void]$findings.Add("[ok] NO.exe read rate held steady at ~$steadyOps read operations per second while the port was open$steadyNote -- consistent with data actually flowing")
    } elseif (@($Session.IoReadSamples).Count -eq 0) {
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
            [void]$findings.Add("[!] This recording MEASURED data flow -- a baseline of ~$($ioRecord.AnnouncedBaselineOpsPerSecond) read operations per second was established -- and CONFIRMED at least one read collapse, and then lost the measurement before the recording ended.$tailNote, and idle ticks drag the baseline down until it falls under the floor needed to detect a collapse. The confirmed collapse STANDS. What this capture cannot say is what the read rate did after the measurement was lost -- read that interval as 'not assessed'. Stop the recorder when the session stops.")
        } else {
            [void]$findings.Add("[!] This recording MEASURED data flow -- a baseline of ~$($ioRecord.AnnouncedBaselineOpsPerSecond) read operations per second was established -- and then lost the measurement before the recording ended.$tailNote, and idle ticks drag the baseline down until it falls under the floor needed to detect a collapse. So this capture CANNOT say whether reads collapsed during the session: read its collapse fields as 'not assessed', not as 'nothing went wrong'. Stop the recorder when the session stops.")
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
    # FAIL survives only with corroboration -- an OS-level integrity fault, or
    # the same port held on an earlier tick and unavailable on a later one.
    $deadPorts = @(
        @($Session.UnavailablePortsEver) + @($Session.UnavailablePorts) |
            Where-Object { $_ } | Select-Object -Unique
    )
    # Ordered evidence, per port.  `UnavailablePortsEver` is intentionally a
    # lossless union and cannot say which observation came first.  Joining it
    # to PortEverHeld produced #81: an offline-at-arrival port that worked later
    # was rendered as "worked, then failed".  Only this subset supports that
    # temporal sentence.
    $deadAfterHeld = @($Session.UnavailableAfterHeldPorts | Where-Object {
        $_ -and $_ -in $deadPorts
    } | Select-Object -Unique)
    $heldEver = @($Session.HeldPortsEver | Where-Object { $_ })
    $resolvedStartupDead = @($deadPorts | Where-Object {
        $_ -in $heldEver -and $_ -notin $deadAfterHeld
    })
    $uncorroboratedDead = @($deadPorts | Where-Object {
        $_ -notin $resolvedStartupDead -and $_ -notin $deadAfterHeld
    })

    if ($deadPorts.Count -gt 0) {
        $integForDead = if ($Session.SerialPortIntegrityEnd) { $Session.SerialPortIntegrityEnd } else { $Session.SerialPortIntegrity }
        $integBad     = [bool]($integForDead -and -not $integForDead.Healthy)
        if ($integBad) {
            [void]$findings.Add("[!] $($deadPorts -join ', ') registered as a Bluetooth serial port but would not open during this session. The serial port integrity check independently reports an OS-level fault, so this is not simply a device that was switched off. No process can reach the headset through it. Cause not classified here (an absent symlink and a stale one need different fixes) -- run the serial port integrity check with NO.exe closed.")
        } else {
            if ($deadAfterHeld.Count -gt 0) {
                [void]$findings.Add("[!] $($deadAfterHeld -join ', ') was held successfully earlier in this recording and became unavailable on a later tick. That ordering is a real in-run loss, not a headset that was merely off before the session. Cause not classified here (an absent symlink and a stale one need different fixes) -- run the serial port integrity check with NO.exe closed.")
            }
            if ($resolvedStartupDead.Count -gt 0) {
                [void]$findings.Add("[i] $($resolvedStartupDead -join ', ') did not open before the application session, then was held successfully later. The ordered evidence shows a resolved startup/offline condition rather than a later port-opening failure.")
            }
            if ($uncorroboratedDead.Count -gt 0 -and -not $Session.BtLinkEverConnected) {
                [void]$findings.Add("[i] $($uncorroboratedDead -join ', ') registered as a Bluetooth serial port and never opened during this session, and the headset never linked to the radio either. The likeliest explanation by far is that it was switched off or out of range for the whole recording -- a port with nothing behind it times out exactly like a broken one, and FI-012 records that the two cannot be told apart from the error alone. This is NOT evidence of a fault. Power the headset on, confirm it connects, then run the serial port integrity check with NO.exe closed if you want it classified.")
            } elseif ($uncorroboratedDead.Count -gt 0) {
                [void]$findings.Add("[~] $($uncorroboratedDead -join ', ') registered as a Bluetooth serial port but would not open during this session, although the headset did link to the radio at some point. Worth capturing, but not classified: the probe cannot tell an absent symlink from a stale one. Run the serial port integrity check with NO.exe closed.")
            }
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
        $preSessionFlaps = [int]$Session.BtLinkPreSessionFlapCount
        $activeDrops     = [int]$Session.BtLinkActiveSessionDropCount
        $sessionFlaps    = [math]::Max(0, [int]$Session.BtLinkFlapCount - $preSessionFlaps)
        if ($preSessionFlaps -gt 0) {
            [void]$findings.Add("[i] BT link setup transition: $preSessionFlaps link drop(s) occurred before any target COM port was held. Recorded, but not classified as an application-session failure.")
        }
        if ($activeDrops -gt 0) {
            [void]$findings.Add("[!] Radio link instability: $activeDrops link drop(s) occurred while a target COM port was actively held")
        } elseif ($sessionFlaps -ge 3) {
            [void]$findings.Add("[!] Radio link instability: $sessionFlaps link drop(s) detected after the application session first held a target port")
        } elseif ($sessionFlaps -gt 0) {
            [void]$findings.Add("[~] BT link flap: $sessionFlaps link drop(s) after the application session first held a target port")
        } elseif (-not $Session.BtLinkEverConnected) {
            if ($Session.BtLinkState -eq 'Unknown') {
                [void]$findings.Add("[info] BT radio link state could not be read this session (no readings -- likely no MAC available)")
            } else {
                [void]$findings.Add("[~] BT radio link never connected during this session (radio stayed disconnected) -- link stability could not be assessed")
            }
        } elseif ($preSessionFlaps -eq 0) {
            [void]$findings.Add("[ok] BT radio link stable throughout session (no drops observed)")
        }
        [void]$findings.Add("[info] Final BT link state: $($Session.BtLinkState)")
    } else {
        [void]$findings.Add("[info] BT link monitoring unavailable (Bthprops.cpl not loaded)")
    }

    # SPP server channel accumulation
    if ($Session.StartupSppChannelCount -ge 4) {
        # A raw LOCALMFG count is not itself corruption.  CDE30CD6BF8C had four
        # entries with two paired Arcs while the independently measured serial
        # namespace was clean 8/8 at both ends.  Keep the count, but warn only
        # when the namespace cannot corroborate that those registrations are
        # unique and resolvable.
        $sppIntegrity = if ($Session.SerialPortIntegrityEnd) {
            $Session.SerialPortIntegrityEnd
        } else { $Session.SerialPortIntegrity }
        $sppVerifiedHealthy = [bool](
            $sppIntegrity -and $sppIntegrity.Healthy -and
            $sppIntegrity.SymlinksChecked -and
            [int]$sppIntegrity.EntryCount -gt 0 -and
            [int]$sppIntegrity.EntryCount -eq [int]$sppIntegrity.ComNameCount
        )
        if ($sppVerifiedHealthy) {
            [void]$findings.Add("[info] SPP server channels at startup: $($Session.StartupSppChannelCount) LOCALMFG entries; serial namespace independently verified healthy ($($sppIntegrity.EntryCount)/$($sppIntegrity.ComNameCount)), so the count alone is not a fault")
        } else {
            [void]$findings.Add("[~] SPP server channel accumulation: $($Session.StartupSppChannelCount) LOCALMFG entries at startup; serial namespace was not independently verified healthy")
        }
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
        BtLinkPreSessionFlapCount = $Session.BtLinkPreSessionFlapCount
        BtLinkActiveSessionDropCount = $Session.BtLinkActiveSessionDropCount
        BtLinkEverConnected = $Session.BtLinkEverConnected
        UnavailableAfterHeldPorts = @($Session.UnavailableAfterHeldPorts | Where-Object { $_ })
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
    .PARAMETER Session
        The probe session, read ONLY for the locked ActivePortOpenProbeEnabled.
    .OUTPUTS
        [hashtable] with EventLogs, AdapterState, ComPortStatus, DeviceState, PowerPlan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        $Session
    )

    # ── The FOURTH active-open path ──────────────────────────────────────
    # ComPortStatus below calls Test-ComPortInUse, which is Get-ComPortHoldState,
    # which opens the port. This one is not on the tick path and is easy to miss:
    # it fires once, from an operator confirmation, long after the toggle was
    # read.
    #
    # It is arguably unreachable with the probe disabled -- PendingConfirmation
    # is only ever set on the Active -> Stopped stream edge, which cannot occur
    # when nothing classifies the stream. The gate is here anyway, because
    # "unreachable via the path I happened to trace" is not the contract. The
    # contract is that the disabled state prevents EVERY active open, and a gate
    # that depends on a second component's behaviour to hold is not a gate.
    $activeProbe = Test-ActivePortOpenProbeEnabled -Session $Session

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
    if ($ports.Count -gt 0 -and $activeProbe) {
        # ONE detailed observation per port, not a bool over a discarded one.
        # This path spends a real open at the most diagnostic moment in the
        # recording -- the operator has just confirmed something went wrong --
        # and it previously kept only InUse, throwing the win32 code away. The
        # same observation feeds the snapshot AND the session accumulator, so
        # nothing here opens the port twice.
        $anomalyObs = @($ports | ForEach-Object { Get-ComPortOpenObservation -PortName $_ -Phase 'Anomaly' })
        $snapshot.ComPortStatus = @($anomalyObs | ForEach-Object {
            @{
                PortName   = $_.PortName
                InUse      = ($_.CoarseState -eq 'Held')
                State      = $_.CoarseState
                Win32Error = $_.Win32Error
                ElapsedMs  = $_.ElapsedMs
                Contract   = $_.Contract
            }
        })
        if ($Session -and $Session.SerialOpenAttempts) {
            foreach ($ao in $anomalyObs) {
                $null = Add-SerialOpenAttempt -Record $Session.SerialOpenAttempts -Observation $ao
            }
        }
    } elseif ($ports.Count -gt 0) {
        # Named as NOT COLLECTED with a reason, rather than omitted or emitted
        # with InUse = $false. An omitted key reads as "there were no ports";
        # an InUse of $false is a measurement nobody took, on the one artifact
        # produced specifically because something went wrong.
        $snapshot.ComPortStatus = $null
        $snapshot.ComPortStatusNotCollected = @{
            Ports  = @($ports)
            Reason = 'The active port-open probe is disabled by setting for this recording, so port-hold state was not read. This is not a report that the ports were free.'
        }
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
        The probe session (BtLinkEverConnected, PortEverHeld, IoReadSamples).
    .PARAMETER WatchState
        The target watch state (FirstComPortSeenTime).
    .PARAMETER Target
        Optional Select-BluetoothSessionTarget result, for rival-candidate
        evidence.
    .PARAMETER AppRunningSeconds
        How long NeurOptimal has continuously been observed running. This is
        presentation-independent input to the scope-conflict rule: once the app
        has been up long enough to expect a session but the candidate has never
        linked, the recorder may be observing the wrong headset.
    .PARAMETER ScopeWarningThresholdSeconds
        Minimum app-running time before silence becomes a scope warning. Kept
        explicit and injectable so the rule can be tested without a clock.
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
        $Target,
        [ValidateRange(0, 2147483647)]
        [int]$AppRunningSeconds = 0,
        [ValidateRange(1, 2147483647)]
        [int]$ScopeWarningThresholdSeconds = 120
    )

    $linked     = [bool]$Session.BtLinkEverConnected
    # Sourced from the port-hold latch, NOT from a stream classification. The
    # field is named TargetPortEverHeld and the operator sentence below asserts a
    # port hold, so anything else here is name/source drift (issue #67).
    $heldPort   = [bool]$Session.PortEverHeld
    # ...and separately, whether anything was in a position to answer. With the
    # active port-open probe disabled the latch is $null, not $false: no sensor
    # looked. The two must stay distinct all the way to the rendered sentence,
    # because "we watched and no process ever took the port" and "we did not
    # watch" are opposite conclusions that a bare $false merges.
    $heldPortObserved = ($null -ne $Session.PortEverHeld)
    # SESSION TOTAL, not the current episode's buffer (#88). The buffer is
    # Clear()ed on every port re-open, so asking it "how many samples did this
    # recording take" returns the residue since the last reset -- and a run whose
    # port re-opened on its final tick answered 0, which drove Level to
    # 'NotObserved' on a capture that measured data flow throughout.
    #
    # Falls back to the buffer only for a session built by an older module copy,
    # where the total does not exist. That fallback can still understate; it
    # cannot overstate, so it degrades toward the old behaviour rather than
    # inventing coverage.
    # MAX of the two, never the total alone. The total can never legitimately be
    # smaller than the buffer that feeds it -- they increment in the same place --
    # so a smaller total means the session did not come through the tick path: an
    # older module copy, or a fixture that populated the buffer directly. Taking
    # the max degrades toward the old behaviour and CANNOT understate, which is
    # the only direction that matters here: understating is what downgraded a
    # measured capture to 'NotObserved'. The real wiring is asserted separately,
    # so this tolerance cannot quietly hide a broken counter.
    $ioSamples  = [math]::Max([int]$Session.IoSamplesTotal, @($Session.IoReadSamples).Count)
    # Kept, under a name that says what it is: the honest answer to "could a
    # verdict be reached right now", which is a real question and a different one.
    $ioSamplesCurrent = @($Session.IoReadSamples).Count
    $sawPort    = if ($WatchState) { [bool]$WatchState.FirstComPortSeenTime } else { $false }

    # A rival is any OTHER candidate the selector saw. Activity on the rival is
    # the strongest single indicator that the recording is pointed at the wrong
    # headset, so it is tracked separately from mere presence.
    #
    # Null vs empty is the discriminator here, never Count: a probe-OFF run
    # seeds every candidate's HeldPorts to $null on purpose ("no sensor
    # looked"), and @($null).Count is 1 in PS 5.1 -- which scored every
    # UNEXAMINED rival as holding a port and fired this verdict's High-severity
    # finding on every probe-OFF capture (verified on published 7b02521,
    # 2026-08-17, in a run with zero active opens). The examined/unexamined
    # split is carried to the output as a tri-state, mirroring
    # TargetPortEverHeld/TargetPortHoldObserved above.
    $rivals = @()
    $rivalsExamined = @()
    $rivalActive = $false
    if ($Target -and $Target.Candidates) {
        $rivals = @($Target.Candidates | Where-Object { $_ -and $_.Mac -and $_.Mac -ne $Target.Mac })
        $rivalsExamined = @($rivals | Where-Object { $null -ne $_.HeldPorts })
        $rivalActive = @($rivalsExamined | Where-Object { @($_.HeldPorts | Where-Object { $_ }).Count -gt 0 }).Count -gt 0
    }
    # Vacuously observed when there are no rivals: nothing existed to examine,
    # and RivalCandidates = 0 beside it says why.
    $rivalHoldObserved = ($rivals.Count -eq 0) -or ($rivalsExamined.Count -gt 0)

    $reasons = @()
    if (-not $linked)        { $reasons += 'The target headset never linked to the radio during this recording.' }
    if (-not $heldPortObserved) {
        $reasons += 'Whether any process held the target headset''s COM port was NOT OBSERVED: the active port-open probe was disabled by setting for this recording. This is not a report that the port was free.'
    } elseif (-not $heldPort) {
        $reasons += 'No process ever held the target headset''s COM port during this recording.'
    }
    if ($ioSamples -eq 0)    { $reasons += 'No read-rate samples were taken, so data flow was never measured.' }
    if ($rivalActive)        { $reasons += "Another paired NeurOptimal headset WAS holding a COM port while this one was idle -- this recording is very likely pointed at the wrong headset." }
    elseif ($rivals.Count -gt 0 -and -not $rivalHoldObserved) { $reasons += "$($rivals.Count) other NeurOptimal headset(s) are paired on this box, and whether any of them held a COM port was NOT OBSERVED (the active port-open probe was disabled) -- wrong-headset activity can neither be claimed nor ruled out." }
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

    # Structured cross-evidence findings. These are NOT component failures and
    # do not enter the health DAG: they question whether the graph describes the
    # same headset as the running application. Keeping this classification on
    # the coverage object makes the live strip, saved probe-session.json and any
    # offline consumer read one answer instead of parsing warning prose.
    $findings = @($Session.ScopeFindings | Where-Object { $_ })
    $scopeMismatch = $rivalActive -or
        ($AppRunningSeconds -ge $ScopeWarningThresholdSeconds -and -not $linked)
    if ($scopeMismatch) {
        $candidate = if ($Target -and $Target.Name) { [string]$Target.Name } else { 'the candidate headset' }
        $observed = New-Object System.Collections.ArrayList
        if ($AppRunningSeconds -ge $ScopeWarningThresholdSeconds) {
            [void]$observed.Add("NeurOptimal has been running for $([int]($AppRunningSeconds / 60)) minute(s).")
        }
        if (-not $linked) { [void]$observed.Add("$candidate never linked during this capture.") }
        if ($heldPortObserved -and -not $heldPort) {
            [void]$observed.Add("No process ever held $candidate's COM port during this capture.")
        } elseif (-not $heldPortObserved) {
            [void]$observed.Add('COM port ownership was not observed because the active port-open probe was disabled.')
        }
        if ($rivalActive) {
            [void]$observed.Add('Another paired NeurOptimal headset held a COM port while this candidate was idle.')
        }
        $finding = [pscustomobject]@{
            PSTypeName  = 'WinConfig.FlightRecorder.DiagnosticFinding'
            FindingKind = 'EvidenceConflict'
            Code        = 'ScopeMismatchSuspected'
            Severity    = if ($rivalActive) { 'High' } else { 'Warning' }
            Title       = 'SCOPE MISMATCH SUSPECTED'
            Summary     = 'Recorder may not be scoped to the headset NeurOptimal is using.'
            Evidence    = @($observed)
        }
        # One finding per code. Keep the latest evidence (not two copies) when
        # this pure function is called on every UI tick.
        $findings = @($findings | Where-Object { $_.Code -ne $finding.Code }) + @($finding)
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
            # The port clause is SPLIT, because in the disabled-probe arm the
            # original wording -- "its COM port was never held" -- is a finding
            # this run is in no position to make. Everything else in the
            # sentence survives; only the channel that was switched off changes
            # from a claim into a statement of what was not looked at.
            $portClause = if ($heldPortObserved) {
                'its COM port was never held'
            } else {
                'whether its COM port was held was not observed (the active port-open probe was disabled)'
            }
            "This recording did not observe a session. $who never linked, $portClause, and no data flow was measured, so nothing here describes what NeurOptimal was doing."
        }
        'Partial' {
            if ($heldPortObserved) {
                'This recording observed the session only partly, so its findings rest on less evidence than a full capture.'
            } else {
                'This recording observed the session only partly: the active port-open probe was disabled by setting, so the COM port-hold channel was not observed at all. Read whatever follows as silence on that channel, not as a clean result on it.'
            }
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
        Findings          = @($findings)
        Summary           = $summary
        TargetEverLinked  = $linked
        # TRI-STATE: $true / $false / $null-for-not-observed. Consumers that
        # branch on truthiness keep working; consumers that need to tell a
        # negative from a silence now can, and TargetPortHoldObserved beside it
        # says which without anyone having to know that $null is meaningful.
        TargetPortEverHeld = $Session.PortEverHeld
        TargetPortHoldObserved = $heldPortObserved
        # Session total. The name kept its meaning; the source was wrong (#88).
        IoSampleCount     = $ioSamples
        # ...and the current-episode buffer, named so nobody has to guess which
        # question a number answers. Two clearly-named fields beat one field
        # whose meaning depends on when you read it.
        IoSampleCountCurrentEpisode = $ioSamplesCurrent
        TargetComPortSeen = $sawPort
        RivalCandidates   = $rivals.Count
        # TRI-STATE like TargetPortEverHeld: $true / $false / $null when rivals
        # exist but no sensor examined their ports (probe-OFF run). Truthiness
        # consumers keep working; RivalHoldObserved beside it says which
        # without anyone having to know that $null is meaningful.
        RivalWasActive    = $(if (-not $rivalHoldObserved) { $null } else { $rivalActive })
        RivalHoldObserved = $rivalHoldObserved
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
        # NOT a third value of the same scale. 'Port open' and 'Port idle' are
        # both readings; this one says no reading was taken, and the wording has
        # to make an operator glancing at a strip stop rather than file it beside
        # 'idle'.
        'stream.DisabledBySetting'    = 'Not observed'
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
        'stream.DisabledBySetting'    = 'COM port hold NOT OBSERVED -- the active port-open probe is disabled by setting for this recording, so nothing checked whether a process is holding the headset''s serial port. This is not a report that the port is idle.'
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
        # Blue-grey, not the neutral grey the measured-but-idle states use. Grey
        # is what an operator reads as "fine, nothing happening"; this state is
        # "nobody is watching this channel", and it should not look the same.
        'DisabledBySetting'    { return [System.Drawing.Color]::FromArgb(90, 120, 165) }
        'Unknown'              { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
        default                { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
    }
}

function Start-IoEpisode {
    <#
    .SYNOPSIS
        Opens a new read-rate episode: assigns its id and start time and clears
        the episode-scoped counters (#87).
    .DESCRIPTION
        ONE choke point, called from two places that both genuinely open an
        episode:

          the Stopped -> Active edge, after the previous episode is closed; and
          the first tick that finds a port held with no episode open.

        The second is not redundant. The recorder seeds StreamingState from the
        arrival snapshot, so a session that was ALREADY streaming when Record
        was pressed produces no transition at all -- the shape of every healthy
        capture where the operator starts mid-session. Issue #67 is the same
        mistake made with the port-hold latch: a fact derived only on an edge is
        absent from every run that never had one.
    .PARAMETER Session
        The probe session.
    .PARAMETER At
        The instant the episode begins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][datetime]$At
    )
    $Session.IoEpisodeSeq++
    # Sequence, not a GUID: it has to be readable in a log line an operator
    # screenshots, and it only has to be unique within one recording.
    $Session.IoEpisodeId        = "E$($Session.IoEpisodeSeq)"
    $Session.IoEpisodeStartedAt = $At
    $Session.HeldPortSetChangeCountEpisode = 0
    $Session.HeldPortsThisEpisode          = @()
    return $Session.IoEpisodeId
}

function Close-IoEpisode {
    <#
    .SYNOPSIS
        Closes the open read-rate episode at the instant the port set EMPTIED,
        and clears its identity (#87).
    .DESCRIPTION
        The episode used to be closed only on REACQUISITION, which left it "live"
        for the whole stopped interval. Two things went wrong with that:

          - the App stamps the live EpisodeId onto every operator marker, so a
            12005 marked while NO holds NO port -- the defining shape of a 12005
            (see the 12005/12006 discriminator) -- was stamped with the PRECEDING
            episode's id and could be counted inside it. The one marker class
            that is definitionally outside an episode was being joined into one.
          - EndedAtIso recorded the moment the port came BACK, not the moment it
            was released, so every episode's interval was inflated by the whole
            release gap.

        Idempotent: closing twice is a no-op, so the reacquisition path can call
        it without knowing whether the release path already did.
    .PARAMETER Session
        The probe session.
    .PARAMETER At
        The instant the episode ends -- the release, not the reacquisition.
    .OUTPUTS
        [pscustomobject] the closed episode record, or $null if none was open or
        it had nothing worth keeping.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][datetime]$At
    )
    if (-not $Session.IoEpisodeId) { return $null }

    $closing = New-IoEpisodeRecord -Session $Session -At $At
    if ($closing) { [void]$Session.IoClosedEpisodes.Add($closing) }
    # IoBaselineResetCount is deliberately NOT touched here. It counts times the
    # measurement RESTARTED, and it is incremented on the reacquisition path
    # where a restart actually happens. Counting it at the close would make the
    # final release of every normal session claim a restart that never occurred,
    # and that number feeds an operator-facing finding.

    $Session.IoEpisodeId        = $null
    $Session.IoEpisodeStartedAt = $null
    return $closing
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

    $baseline = [double]$Session.IoBaselineOpsPerSecond
    $verdict  = [string]$Session.IoVerdict

    # No baseline and no verdict worth keeping: an episode that never measured
    # anything contributes nothing and must not dilute the ones that did.
    if ($baseline -le 0 -and $verdict -in @('NoBaseline', '', $null)) { return $null }

    return [pscustomobject]@{
        PSTypeName           = 'WinConfig.FlightRecorder.IoEpisode'
        Verdict              = if ($verdict) { $verdict } else { 'NoBaseline' }
        BaselineOpsPerSecond = $baseline
        RecentOpsPerSecond   = [double]$Session.IoRecentOpsPerSecond
        FractionOfBaseline   = $Session.IoFractionOfBaseline
        Collapsed            = ($verdict -eq 'Collapsed')
        Degrading            = ($verdict -eq 'Degrading')
        EndedAtIso           = $At.ToString('o')
        # #87: an episode used to carry EndedAtIso and nothing else, so nothing
        # could be placed INSIDE it. The id is what operator markers join on;
        # the start time is what makes the interval readable to a human.
        # $null on a session fixture that never opened one, rather than a made-up
        # id -- an absent join key must read as absent.
        EpisodeId            = $Session.IoEpisodeId
        StartedAtIso         = if ($Session.IoEpisodeStartedAt) {
            ([datetime]$Session.IoEpisodeStartedAt).ToString('o')
        } else { $null }
        # How many samples the verdict above actually rests on. With the window
        # in elapsed seconds (#86) the sample count no longer follows from the
        # duration, so it has to be stated.
        SampleCount          = @($Session.IoReadSamples).Count
        # THE PRECISION THIS RECORD ACTUALLY HAS (#85). An episode is a
        # Stopped -> Active EPOCH, not one port-handle lifetime: the held set can
        # change hands inside it without ever emptying, and the baseline
        # deliberately survives that. These two say so, in the record, so nobody
        # has to infer it -- any reasoning that treats an episode as one handle
        # is over-precise, and until now the record gave no way to tell.
        HandleChangeCount    = [int]$Session.HeldPortSetChangeCountEpisode
        PortsSeen            = @($Session.HeldPortsThisEpisode | Where-Object { $_ })
        BaselineSpansHandles = ([int]$Session.HeldPortSetChangeCountEpisode -gt 0)
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
        BaselineResetCount, PeakBaselineOpsPerSecond, WorstRecentOpsPerSecond,
        WorstFractionOfBaseline, FirstCollapseAtIso, Episodes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session)

    $episodes = @()
    if ($Session.IoClosedEpisodes) { $episodes += @($Session.IoClosedEpisodes) }
    # The episode still running has not been stamped anywhere, and on a session
    # that ends mid-collapse it is the ONLY one that carries the collapse.
    #
    # ONLY when one is actually running (#87). Episodes are closed at RELEASE
    # now, so a recording that ended with no port held has already stamped its
    # last episode into the ledger -- building a live record as well would enter
    # the same episode twice, inflating EpisodeCount and CollapseEpisodes.
    $live = if ($Session.IoEpisodeId) { New-IoEpisodeRecord -Session $Session } else { $null }
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
    $announcedOps = [double]$Session.IoBaselineAnnouncedOpsPerSecond
    $announced    = ($null -ne $announcedAt -and $announcedOps -gt 0)

    $peak = 0
    foreach ($e in $episodes) {
        if ([double]$e.BaselineOpsPerSecond -gt $peak) { $peak = [double]$e.BaselineOpsPerSecond }
    }
    foreach ($m in $markerCollapsed) {
        if ([double]$m.IoBaselineOpsPerSecond -gt $peak) { $peak = [double]$m.IoBaselineOpsPerSecond }
    }
    # A peak below the rate that was ANNOUNCED is not a measurement, it is
    # erosion. Reporting 0 here is what produced the finding that read
    # "went from ~0 to ~0 read operations per tick".
    if ($announcedOps -gt $peak) { $peak = $announcedOps }

    # ── The worst observation, as ONE pair from ONE channel ──────────────────
    # WorstFractionOfBaseline used to be read off the session by the bundle while
    # WorstRecentOpsPerSecond was read off this record, so the manifest carried two
    # halves of one observation assembled from two objects -- and they contradicted
    # (0% beside null). They are chosen together here: whichever channel saw the
    # lowest fraction supplies BOTH numbers, so they always describe one moment.
    $worstCandidates = @()
    foreach ($e in $collapsed) {
        $worstCandidates += [pscustomobject]@{ Fraction = $e.FractionOfBaseline; Recent = [double]$e.RecentOpsPerSecond }
    }
    foreach ($m in $markerCollapsed) {
        $worstCandidates += [pscustomobject]@{ Fraction = $m.IoFractionOfBaseline; Recent = [double]$m.IoRecentOpsPerSecond }
    }
    if ($null -ne $Session.IoWorstFractionOfBaseline) {
        $worstCandidates += [pscustomobject]@{
            Fraction = $Session.IoWorstFractionOfBaseline
            Recent   = [double]$Session.IoWorstRecentOpsPerSecond
        }
    }
    $worst = $null
    foreach ($c in @($worstCandidates | Where-Object { $null -ne $_.Fraction })) {
        if ($null -eq $worst -or $c.Fraction -lt $worst.Fraction) { $worst = $c }
    }
    # A collapsed observation with no fraction attached still carries a rate, and
    # dropping it would put null in the field a finding quotes.
    $worstRecent = if ($worst) { $worst.Recent } else {
        $bare = @(@($collapsed | ForEach-Object { [double]$_.RecentOpsPerSecond }) +
                  @($markerCollapsed | ForEach-Object { [double]$_.IoRecentOpsPerSecond }))
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
    # leaves BaselineOpsPerSecond nonzero while the verdict stays NoBaseline, so
    # peak alone would call an unmeasurable session stable.
    # A marker stamped 'Collapsed' against a real baseline is itself proof a
    # baseline was established, so it counts here too -- otherwise the record
    # could report Outcome 'Collapsed' beside BaselineEstablished false, which is
    # the same contradiction one field over.
    $ledgerBaseline = (@($episodes | Where-Object {
        $_.Verdict -in @('Streaming', 'Degrading', 'Collapsed')
    }).Count -gt 0) -or
        (@($markerCollapsed | Where-Object { [double]$_.IoBaselineOpsPerSecond -gt 0 }).Count -gt 0)
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
    $dipsBeyondTeardown = ([double]$Session.IoDegradedSeconds -gt $script:IoCollapseSeconds)

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
        # IoDegradedSeconds is counted here too. Capture 31D0729CA5B8 shipped
        # EverDegrading false beside Outcome 'Degraded' and
        # MeaningfullyDegraded true, in one object -- the outcome was derived
        # from the tick counter while this field looked only at episodes.
        EverDegrading          = ((@($episodes | Where-Object { $_.Degrading }).Count -gt 0) -or
                                  (@($markers | Where-Object { $_.IoVerdict -eq 'Degrading' }).Count -gt 0) -or
                                  ([double]$Session.IoDegradedSeconds -gt 0))
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
        PeakBaselineOpsPerSecond = $peak
        WorstRecentOpsPerSecond  = $worstRecent
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
        AnnouncedBaselineOpsPerSecond   = if ($announced) { $announcedOps } else { $null }
        # Seconds the recording ran on after read activity stopped.
        IdleTailSeconds        = $idleTailSeconds
        # The claim a badge should be built from. A terminal 'Degrading' caused
        # by teardown is NOT this.
        MeaningfullyDegraded   = ($outcome -eq 'Degraded')
        # How often NO.exe's held-port set changed hands WITHOUT the set ever
        # emptying, across the whole recording (#85). >0 means at least one
        # episode's baseline covers more than one port handle -- deliberately,
        # because the read counter is process-wide and a reset would cost more
        # evidence than the precision is worth, but the reader is told rather
        # than left to assume an episode is one handle.
        HandleChangeCount      = [int]$Session.HeldPortSetChangeCount
        # THE JOIN #87 EXISTS FOR: markers that fall inside an episode which
        # collapsed, matched on the EpisodeId the marker RECORDED at the time.
        #
        # Deliberately NOT the same claim as MarkerCollapseCount above, which
        # counts markers whose OWN verdict was Collapsed at the marked instant.
        # DB98B6EE3324 is why they must stay separate: all six markers stamped
        # 'NoBaseline' -- the detector was inside its rebuild window -- while the
        # episode they sat in ended Collapsed at 7% of a 60 baseline. The marker
        # channel was blind and the episode channel was not, and a record that
        # reported only the first said the corpus pattern had broken when it had
        # not.
        #
        # Joined on a recorded id, never re-derived from timestamps: that would
        # be a second answerer for a question the marker already answers.
        MarkerInCollapsedEpisodeCount = @(
            $markers | Where-Object {
                $_.EpisodeId -and $_.EpisodeId -in @($collapsed | ForEach-Object { $_.EpisodeId })
            }
        ).Count
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

function Get-BluetoothGhostPortPlan {
    <#
    .SYNOPSIS
        Pure. THE answer to "which Bluetooth COM port devices would a cleanup
        remove", for both the Dry Run preview and the live removal.
    .DESCRIPTION
        This exists because the preview and the execution had DIFFERENT answers.
        Live selection took the all-zero LOCALMFG local-service registration OR
        any BTHENUM port whose device is no longer present; the Dry Run planner
        took only the all-zero set. The preview therefore under-reported a
        DESTRUCTIVE scope -- an operator who approved "1 port" could have three
        removed. Both sides now call this function, so there is one answerer.

        Scope note, deliberately narrow: a ghost here means a port node that is
        not present, or the all-zero local-service placeholder. It does NOT
        cover the FI-012 fault-3 state, where every affected node stays
        `Present = $true` and reads healthy while its symlink points at an
        abandoned RFCOMM generation. Nothing in this plan detects that, and
        removing nodes does not repair it -- the fix there is a reboot without
        unpairing. Do not grow this predicate to try to catch it.
    .PARAMETER PortDevices
        Raw `Get-PnpDevice -Class Ports` output. The BTHENUM filter is applied
        HERE rather than at the call sites, so callers cannot narrow the input
        and reintroduce the divergence this function removes.
    .OUTPUTS
        Hashtable: Targets (array), TargetCount, AllZeroCount, NotPresentCount.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$PortDevices
    )

    $targets = @()
    $allZero = 0
    $notPresent = 0

    foreach ($dev in @($PortDevices)) {
        if (-not $dev) { continue }

        # StrictMode-safe property reads: Get-PnpDevice objects always carry
        # these, but the tests feed synthetic rows and an absent key must not
        # throw (see project-powershell-test-gotchas).
        $names = @($dev.PSObject.Properties.Name)
        $instanceId = if ($names -contains 'InstanceId') { [string]$dev.InstanceId } else { '' }
        if ([string]::IsNullOrWhiteSpace($instanceId)) { continue }
        if ($instanceId -notmatch 'BTHENUM') { continue }

        $reasons = @()
        if ($instanceId -match 'LOCALMFG' -and $instanceId -match '000000000000') {
            $reasons += 'AllZeroLocalService'
        }
        # Absent/null Present is NOT treated as absent hardware. Only an
        # explicit $false marks a node gone: guessing from a missing property
        # would make the plan destructive on incomplete input.
        if ($names -contains 'Present' -and $dev.Present -eq $false) {
            $reasons += 'NotPresent'
        }
        if ($reasons.Count -eq 0) { continue }

        if ($reasons -contains 'AllZeroLocalService') { $allZero++ }
        if ($reasons -contains 'NotPresent') { $notPresent++ }

        $targets += @{
            InstanceId   = $instanceId
            FriendlyName = if ($names -contains 'FriendlyName') { [string]$dev.FriendlyName } else { '' }
            Status       = if ($names -contains 'Status') { [string]$dev.Status } else { '' }
            Present      = if ($names -contains 'Present') { $dev.Present } else { $null }
            Reasons      = $reasons
            Reason       = ($reasons -join ', ')
        }
    }

    return @{
        Targets         = $targets
        TargetCount     = $targets.Count
        AllZeroCount    = $allZero
        NotPresentCount = $notPresent
    }
}

# =============================================================================
# NO APPLICATION EVIDENCE (read-only; FI-012 "fold NO's own channel in")
# =============================================================================
#
# NO's error dialogs are a reliable readout of its handle state (verified 4x on
# 2026-08-19: 12005 <=> holds no port, 12006 <=> holds both), and both stores
# below are readable with ZERO intrusion. These collectors READ ONLY, from two
# named files under C:\ProgramData\NeurOptimal -- deliberately NOT the clinical
# data trees (C:\zengar\sessions, C:\zengar\BLT_data are on the hard deny-list
# and are never touched), and deliberately not VAULT/NOTATE or any other
# NeurOptimal store that could carry client information.
#
#  1. NO_messages.xml -- a LabVIEW-flattened message array. Measured EMPTY
#     during a live 12006 on 2026-08-10 (written seven minutes before the
#     event) and empty again after a full day of 12005s on 2026-08-19, so it
#     behaves as a queue that is cleared, not a log. The per-tick watcher
#     exists to MEASURE whether this channel ever carries the codes: every
#     content change is recorded with a timestamp, and a store that stays
#     empty through a failure renders as a counted absence, never as silence.
#
#  2. NO Device Manager.config -- NO's own device table. The LabVIEW blob
#     carries recoverable plain text: device aliases, COM port assignments and
#     MAC addresses (confirmed on MMEVOLD_06 2026-08-19: alias 000013 ->
#     COM4/COM6 -> 8C:1F:64:71:00:0D, plus the current alias). A start/end
#     snapshot lets a capture prove "NO's record is stale" against the live
#     namespace -- previously only observable by operator screenshot, which is
#     banned.

$script:NoMessageStorePath        = 'C:\ProgramData\NeurOptimal\NO_Messages\NO_messages.xml'
$script:NoDeviceManagerConfigPath = 'C:\ProgramData\NeurOptimal\NO Device Manager\NO Device Manager.config'

function Get-NoMessageStoreSnapshot {
    <#
    .SYNOPSIS
        Reads NO's message store once: existence, timestamps, hash, content.
    .DESCRIPTION
        Read-only. Absolute path by default ([IO.File] ignores the provider
        working directory, so a relative override is the caller's own risk).
        MessageCount is parsed from the LabVIEW <Dimsize> element: 0 means the
        array is present and EMPTY, which is a real observation, distinct from
        $null (store missing or unparseable).
    #>
    [CmdletBinding()]
    param(
        [string]$Path = $script:NoMessageStorePath,
        [int]$MaxContentBytes = 65536
    )
    $r = [ordered]@{
        Path             = $Path
        SampledAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
        Exists           = $false
        Length           = $null
        LastWriteTimeUtc = $null
        Sha256           = $null
        Content          = $null
        ContentTruncated = $false
        MessageCount     = $null
        ReadStatus       = 'Missing'
        Error            = $null
    }
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if (-not $fi.Exists) { return [pscustomobject]$r }
        $r.Exists           = $true
        $r.Length           = [long]$fi.Length
        $r.LastWriteTimeUtc = $fi.LastWriteTimeUtc.ToString('o')
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $r.Sha256 = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') }
        finally { $sha.Dispose() }
        $take = [Math]::Min($bytes.Length, [Math]::Max(0, $MaxContentBytes))
        $r.ContentTruncated = ($bytes.Length -gt $take)
        $r.Content = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $take)
        if ($r.Content -match '<Dimsize>(\d+)</Dimsize>') { $r.MessageCount = [int]$Matches[1] }
        $r.ReadStatus = 'Read'
    } catch {
        $r.ReadStatus = 'Error'
        $r.Error      = $_.Exception.Message
    }
    return [pscustomobject]$r
}

function Update-NoMessageStoreWatch {
    <#
    .SYNOPSIS
        Folds one message-store snapshot into the session; returns the change
        record when the store changed, else $null.
    .DESCRIPTION
        Opt-in by session-field presence (the throttle pattern): a session
        without the NoMessageStore seed -- every older caller and test mock --
        is a silent no-op, never a throw.

        The FIRST sample is the baseline and is never reported as a change.
        Change detection is on existence + content hash, not on LastWriteTime
        alone (a rewrite of identical bytes is not evidence of a message).
        The per-session change list is capped, and the cap is COUNTED
        (DroppedChangeCount) -- a capped list that reads as complete is the
        silent-truncation lie. A dropped change is still RETURNED, so the
        caller's timeline line survives even when the session list is full.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Session,
        $Snapshot,
        [datetime]$Now = (Get-Date)
    )
    if ($Session -isnot [hashtable] -or -not $Session.ContainsKey('NoMessageStore')) { return $null }
    $st = $Session['NoMessageStore']
    if ($null -eq $st) { return $null }
    if ($null -eq $Snapshot) { $Snapshot = Get-NoMessageStoreSnapshot }

    $st.SampleCount = [int]$st.SampleCount + 1
    if ($Snapshot.ReadStatus -eq 'Error') { $st.ReadErrorCount = [int]$st.ReadErrorCount + 1 }
    if ($null -ne $Snapshot.MessageCount -and [int]$Snapshot.MessageCount -gt 0) { $st.EverNonEmpty = $true }

    if ($null -eq $st.FirstSnapshot) {
        $st.FirstSnapshot = $Snapshot
        $st.LastSnapshot  = $Snapshot
        return $null
    }

    $prev = $st.LastSnapshot
    $st.LastSnapshot = $Snapshot
    $changed = ([bool]$Snapshot.Exists -ne [bool]$prev.Exists) -or
               ([string]$Snapshot.Sha256 -ne [string]$prev.Sha256)
    if (-not $changed) { return $null }

    $st.ChangeCount = [int]$st.ChangeCount + 1
    $rec = [ordered]@{
        AtUtc            = $Now.ToUniversalTime().ToString('o')
        ChangeType       = $(if (-not $Snapshot.Exists) { 'Removed' }
                            elseif (-not $prev.Exists)  { 'Appeared' }
                            else { 'Modified' })
        Length           = $Snapshot.Length
        LastWriteTimeUtc = $Snapshot.LastWriteTimeUtc
        MessageCount     = $Snapshot.MessageCount
        Sha256           = $Snapshot.Sha256
        Content          = $Snapshot.Content
        ContentTruncated = [bool]$Snapshot.ContentTruncated
        ReadStatus       = $Snapshot.ReadStatus
        Error            = $Snapshot.Error
    }
    if ($st.Changes.Count -ge [int]$st.MaxChanges) {
        $st.DroppedChangeCount = [int]$st.DroppedChangeCount + 1
    } else {
        [void]$st.Changes.Add($rec)
    }
    return [pscustomobject]$rec
}

function Get-NoDeviceManagerConfigSnapshot {
    <#
    .SYNOPSIS
        Reads NO's Device Manager config once and extracts its device table.
    .DESCRIPTION
        Read-only. The file is a LabVIEW-flattened blob whose device table
        survives as plain text; the extraction is a printable-string regex
        pass, never a claim to parse the LabVIEW format. RawBase64 preserves
        the whole file (size-capped, and the cap is stated when hit) so a
        later, better parser can re-read exactly what was captured.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = $script:NoDeviceManagerConfigPath,
        [int]$MaxRawBytes = 262144
    )
    $r = [ordered]@{
        Path             = $Path
        SampledAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
        Exists           = $false
        Length           = $null
        LastWriteTimeUtc = $null
        Sha256           = $null
        ComPorts         = $null
        MacAddresses     = $null
        DeviceLabels     = $null
        RawBase64        = $null
        RawOmittedReason = $null
        ReadStatus       = 'Missing'
        Error            = $null
    }
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if (-not $fi.Exists) { return [pscustomobject]$r }
        $r.Exists           = $true
        $r.Length           = [long]$fi.Length
        $r.LastWriteTimeUtc = $fi.LastWriteTimeUtc.ToString('o')
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $r.Sha256 = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') }
        finally { $sha.Dispose() }
        # Latin-1: a 1:1 byte-to-char decode, so the regex pass sees every
        # printable run regardless of what binary surrounds it.
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $r.ComPorts     = @([regex]::Matches($text, 'COM\d{1,3}') | ForEach-Object { $_.Value } | Select-Object -Unique)
        $r.MacAddresses = @([regex]::Matches($text, '(?i)\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b') | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique)
        $r.DeviceLabels = @([regex]::Matches($text, 'NeurOptimal Arc - \d{6}') | ForEach-Object { $_.Value } | Select-Object -Unique)
        if ($bytes.Length -le $MaxRawBytes) {
            $r.RawBase64 = [System.Convert]::ToBase64String($bytes)
        } else {
            $r.RawOmittedReason = "File is $($bytes.Length) bytes, over the $MaxRawBytes-byte raw-capture cap; string extraction above still covers the full file."
        }
        $r.ReadStatus = 'Read'
    } catch {
        $r.ReadStatus = 'Error'
        $r.Error      = $_.Exception.Message
    }
    return [pscustomobject]$r
}

Export-ModuleMember -Function @(
    'Get-NoMessageStoreSnapshot',
    'Update-NoMessageStoreWatch',
    'Get-NoDeviceManagerConfigSnapshot',
    'Initialize-BtWin32Api',
    'Get-NextProbeTickDeadline',
    # Session-long read-rate record. Exported because the bundle summary must be
    # built from the same answer the findings are, not from the live last-tick
    # fields that a port re-open silently resets.
    'New-IoEpisodeRecord',
    'Start-IoEpisode',
    'Close-IoEpisode',
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
    # Raw open evidence. Get-ComPortHoldState keeps its string contract and is
    # now a thin coarse view over this; the detailed form is what carries the
    # win32 code the recorder used to discard. Aggregation is exported for the
    # same reason the chain is: the window, the archive and the tests must read
    # ONE computation, not three.
    'Get-ComPortOpenObservation',
    # Capture provenance. Exported so the manifest, the archive and the tests
    # read ONE answer to "which build wrote this, and how were its opens
    # measured" -- and so the open contract is DERIVED from the evidence rather
    # than asserted a second time at the render site.
    'Get-BtEvidenceProvenance',
    'New-BluetoothEventEvidenceRecord',
    'Add-BluetoothEventEvidenceBatch',
    'Set-BluetoothEventEvidenceFinalDrain',
    'Get-BluetoothEventEvidenceReport',
    'Complete-SerialOpenTopologyRequest',
    'New-SerialOpenAttemptRecord',
    'Add-SerialOpenAttempt',
    'Get-SerialOpenAttemptReport',
    # Ghost-port removal target plan. Exported because the Dry Run preview and
    # the live removal MUST read one computation of "what would be deleted" --
    # they previously read two, and the preview reported the smaller scope.
    'Get-BluetoothGhostPortPlan',
    'Get-StreamingState',
    'Get-ActivePortOpenProbeSetting',
    # Pure decision function for the active-open throttle. Exported so the
    # rule table can be tested directly rather than inferred from tick behaviour.
    'Get-ActiveOpenDecision',
    'Test-ActivePortOpenProbeEnabled',
    'Get-ProbeStateConsistency',
    # The failure-boundary chain. Exported because the window, the persisted
    # chain.jsonl and the tests must all read ONE computation of "where does the
    # verified part of the chain end" -- deriving it a second time at the render
    # site is the channel-mismatch class this repo keeps re-filing.
    'Get-BtDiagnosticChain',
    # Target identity, as a diagnostic-context property rather than a health
    # node. Exported for the same reason the chain is: the window, chain.jsonl
    # and the tests must read ONE answer to "which headset is this about, and
    # how strongly is that known".
    'Get-BtTargetBinding',
    # Presentation mapping for the recorder window. Exported so the panel
    # arrangement and the plain-language verdict are testable without a form,
    # and so the window has exactly one place that turns chain state into
    # something an operator reads.
    'Get-BtRecorderView',
    'Get-BtRecorderEventText',
    'Initialize-ProcessIoApi',
    'Get-ProcessIoSample',
    'Add-IoReadRateSample',
    'Get-IoReadRateScopes',
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

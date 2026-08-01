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
    foreach ($p in $ports) {
        switch (Get-ComPortHoldState -PortName $p) {
            'Held'        { $activePorts += $p }
            'Unavailable' { $deadPorts   += $p }
        }
    }

    if ($activePorts.Count -gt 0) {
        return @{
            State            = 'Active'
            ActivePort       = ($activePorts -join ', ')
            HeldPorts        = @($activePorts)
            UnavailablePorts = @($deadPorts)
        }
    }
    return @{ State = 'Stopped'; ActivePort = $null; HeldPorts = @(); UnavailablePorts = @($deadPorts) }
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
        [bool]$IoDegrading = $false
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

    # Ports that exist but will not open. Independent of everything else: no
    # process can talk to the headset in this state, whatever the other fields say.
    if ($dead.Count -gt 0) {
        $out += @{
            Level = 'FAIL'
            Text  = "[!] $($dead -join ', ') is registered as a Bluetooth serial port but will not open. NO.exe cannot receive EEG through a port in this state -- expect 'Control Port not valid' or 'Arc not detected'. The probe deliberately does not guess the cause here: an absent symlink and a stale one give different win32 errors and need different fixes. Run the serial port integrity check (operator-initiated, with NO.exe closed) to split them."
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
        [int]$IoRecentOpsPerTick = 0
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
        -IoDegrading ($IoVerdict -eq 'Degrading'))

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
        IoWorstFractionOfBaseline = $null
        IoStalled                = $false
        IoStallReported          = $false
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

    if ($newStreamState -ne $Session.StreamingState) {
        $prevStreaming = $Session.StreamingState
        $Session.StreamingState = $newStreamState

        if ($newStreamState -eq 'Active') {
            $Session.StreamPeakCpuS         = 0.0
            $Session.StreamPeakWorkingSetMB = 0
            $Session.StreamCpuFirstSample   = $null
            $Session.StreamCpuLastSample    = $null
            $Session.StreamFlatCpuTicks     = 0
            $Session.StreamCpuStalled       = $false
            $Session.StreamCpuStallReported = $false
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
    if ($Session.IoStalled) {
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
        [void]$findings.Add("[!] Read rate collapsed while the port stayed open: NO.exe went from ~$($Session.IoBaselineOpsPerTick) to ~$($Session.IoRecentOpsPerTick) read operations per tick on $portStr.$linkNote Note this counter is process-wide, so it shows the application stopped doing the I/O it had been doing, not specifically that the port went quiet.")
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
        if ([int]$Session.IoBaselineOpsPerTick -eq 0) {
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
        [void]$findings.Add("[~] NO.exe's read rate dipped below a quarter of its own baseline on $($Session.IoDegradedTicks) tick(s) during this recording, recovering each time (worst point ~$($Session.IoWorstFractionOfBaseline)% of normal). No single dip lasted long enough to call a collapse, but a healthy stream does not do this -- suspect an intermittent link or an Arc dropping out briefly.")
    } elseif ($Session.IoVerdict -eq 'Streaming') {
        [void]$findings.Add("[ok] NO.exe read rate held steady at ~$($Session.IoBaselineOpsPerTick) read operations per tick while the port was open -- consistent with data actually flowing")
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
    $deadPorts = @($Session.UnavailablePorts | Where-Object { $_ })
    if ($deadPorts.Count -gt 0) {
        [void]$findings.Add("[!] $($deadPorts -join ', ') registered as a Bluetooth serial port but would not open during this session. No process can reach the headset through it. Cause not classified here (an absent symlink and a stale one need different fixes) -- run the serial port integrity check with NO.exe closed.")
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

Export-ModuleMember -Function @(
    'Initialize-BtWin32Api',
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
    'Get-ProbeStateGuiLevel',
    'Get-ProbeStateColor',
    'Get-ProbeStateUserText'
)

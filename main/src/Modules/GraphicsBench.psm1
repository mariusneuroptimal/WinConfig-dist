# GraphicsBench.psm1
# GRAPHICS-BENCH-001 -- graphics measurement surface for NeurOptimal's two
# WebView2 hosts (video.js and butterchurn).
#
# CONTRACT:
# - READ-ONLY toward NO. Nothing here launches, drives, clicks, or injects
#   input into NO.exe, and nothing evaluates JavaScript in its renderers.
#   Every function reads process, window, performance-counter or file
#   METADATA only.
# - Nothing here touches C:\zengar\sessions or C:\zengar\BLT_data (clinical
#   data, hard deny-list). Assert-GfxPathAllowed guards the one path that is
#   operator-configurable (the media path from NOMP.config).
# - An absent measurement is $null and renders as an em dash. It is NEVER 0.
#   A 0 means "measured, and it was zero"; that distinction is the whole
#   point of the videodecode arm.
# - RECORD THE IDENTIFIER, NOT THE LABEL. Surfaces carry HostPid/GpuPid and
#   the document title verbatim, plus RoleSource saying how the role was
#   established.
#
# Consumed by scripts/Invoke-GraphicsSessionBench.ps1 (operator harness).

# Set-StrictMode is OFF here for the same reason SupportBundle.psm1 turns it
# off: the sampler's records are hashtables whose optional keys are LEGITIMATELY
# absent (a surface with no GPU counters carries no Engines key at all), and the
# whole contract of this module is that an absent measurement reads as absent.
# Under strict mode that read becomes a throw, which would turn "not measured"
# into "run failed".
Set-StrictMode -Off

# Engine types worth attributing. The GPU Engine counter instance name ends
# in _engtype_<Type>; anything outside this set is recorded but not summarised.
$script:GfxEngineTypes = @('3D', 'VideoDecode', 'VideoProcessing', 'Copy')

# Paths that must never be read, in any form, by anything in this module.
$script:GfxDeniedPathRoots = @('C:\zengar\sessions', 'C:\zengar\BLT_data')

# ---------------------------------------------------------------------------
# Guards and small helpers
# ---------------------------------------------------------------------------

function Assert-GfxPathAllowed {
    <#
    .SYNOPSIS
        Throws if a path falls under the clinical-data deny-list.
    .DESCRIPTION
        The media path comes out of NOMP.config, which an operator can point
        anywhere. This is the choke point: every filesystem read in this
        module that uses an operator-supplied root goes through here first.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $normalized = $Path.TrimEnd('\', '/')
    foreach ($denied in $script:GfxDeniedPathRoots) {
        if ($normalized -eq $denied -or $normalized.StartsWith($denied + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to read '$Path': it is under the clinical-data deny-list root '$denied'."
        }
    }
}

function Get-GfxPercentile {
    <#
    .SYNOPSIS
        Nearest-rank percentile over a numeric array. Returns $null for an
        empty sample -- never 0.
    #>
    [CmdletBinding()]
    param(
        [double[]]$Values,
        [Parameter(Mandatory)][ValidateRange(0, 100)][double]$Percentile
    )

    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = [double[]]($Values | Sort-Object)
    if ($sorted.Count -eq 1) { return $sorted[0] }
    $rank = [int][math]::Ceiling(($Percentile / 100.0) * $sorted.Count)
    if ($rank -lt 1) { $rank = 1 }
    if ($rank -gt $sorted.Count) { $rank = $sorted.Count }
    return $sorted[$rank - 1]
}

function Get-GfxStats {
    <#
    .SYNOPSIS
        n / mean / p50 / p95 / max over a sample. Every field is $null when
        the sample is empty, so an unmeasured series can never render as 0.
    #>
    [CmdletBinding()]
    param([double[]]$Values)

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return @{ N = 0; Mean = $null; P50 = $null; P95 = $null; Max = $null }
    }
    $sum = 0.0
    foreach ($v in $Values) { $sum += $v }
    return @{
        N    = $Values.Count
        Mean = [math]::Round($sum / $Values.Count, 3)
        P50  = [math]::Round((Get-GfxPercentile -Values $Values -Percentile 50), 3)
        P95  = [math]::Round((Get-GfxPercentile -Values $Values -Percentile 95), 3)
        Max  = [math]::Round(($Values | Measure-Object -Maximum).Maximum, 3)
    }
}

# ---------------------------------------------------------------------------
# Window scanning -- the passive role discriminator
# ---------------------------------------------------------------------------

function Initialize-GfxWindowScan {
    <#
    .SYNOPSIS
        Compiles the inline Win32 window-scan helper.
    .DESCRIPTION
        Add-Type assemblies are AppDomain-wide, so this must be called on the
        main thread BEFORE the sampler runspace starts; the runspace then uses
        the type without loading anything itself (same discipline as the
        Flight Recorder's WinConfigDiag.WindowScan).

        The dist ships text only, so this is inline C# rather than a DLL.
    .OUTPUTS
        [bool] whether the type is available.
    #>
    [CmdletBinding()]
    param()

    if ('WinConfigDiag.GfxWindowScan' -as [type]) { return $true }
    try {
        $source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinConfigDiag {
    // Reads window METADATA only: handle, owning pid, class name, title bar
    // text. Never window content, never child controls of a LabVIEW front
    // panel, never a pixel. No window is created, moved, shown, hidden,
    // activated or messaged.
    public static class GfxWindowScan {
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc f, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumWindowsProc f, IntPtr l);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder t, int m);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder t, int m);
        delegate bool EnumWindowsProc(IntPtr h, IntPtr l);

        static string Title(IntPtr h) { System.Text.StringBuilder sb = new System.Text.StringBuilder(512); GetWindowTextW(h, sb, 512); return sb.ToString(); }
        static string Cls(IntPtr h) { System.Text.StringBuilder sb = new System.Text.StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString(); }
        static uint Pid(IntPtr h) { uint p; GetWindowThreadProcessId(h, out p); return p; }

        // One pass over the host process's top-level windows plus their
        // descendants. Rows are pipe-delimited; the caller parses.
        //
        //   NOWIN|<hwnd>|<visible 0/1>|<class>|<title>
        //       every top-level window owned by hostPid
        //   SURFACE|<owningPid>|<hwnd>|<title>
        //       a Chrome_WidgetWin_1 descendant owned by ANOTHER process --
        //       this is the WebView2 visual host, and its title IS the
        //       rendered document's title
        //   D3DWIN|<owningPid>
        //       an "Intermediate D3D Window" descendant -- the compositing
        //       GPU process, corroborating process parentage
        public static string[] Scan(int hostPid) {
            List<string> rows = new List<string>();
            EnumWindows(delegate(IntPtr top, IntPtr l) {
                if (Pid(top) != (uint)hostPid) { return true; }
                rows.Add("NOWIN|" + top.ToInt64() + "|" + (IsWindowVisible(top) ? "1" : "0") + "|" + Cls(top) + "|" + Title(top));
                EnumChildWindows(top, delegate(IntPtr c, IntPtr l2) {
                    uint cp = Pid(c);
                    if (cp == (uint)hostPid) { return true; }
                    string cls = Cls(c);
                    if (cls == "Chrome_WidgetWin_1") { rows.Add("SURFACE|" + cp + "|" + c.ToInt64() + "|" + Title(c)); }
                    else if (cls == "Intermediate D3D Window") { rows.Add("D3DWIN|" + cp); }
                    return true;
                }, IntPtr.Zero);
                return true;
            }, IntPtr.Zero);
            return rows.ToArray();
        }
    }
}
"@
        Add-Type -TypeDefinition $source -ErrorAction Stop
        return [bool]('WinConfigDiag.GfxWindowScan' -as [type])
    } catch {
        return $false
    }
}

function ConvertFrom-GfxWindowScanRows {
    <#
    .SYNOPSIS
        Parses GfxWindowScan.Scan rows into surfaces, D3D pids and NO's own
        window list. Pure -- unit-testable without a live NO.
    .PARAMETER Rows
        The raw pipe-delimited rows.
    .OUTPUTS
        Hashtable: Surfaces (HostPid/Hwnd/DocumentTitle/Role/RoleSource),
        D3DPids, NoWindows (Hwnd/Visible/Class/Title).
    #>
    [CmdletBinding()]
    param([string[]]$Rows)

    $surfaces = @()
    $d3d = @()
    $noWindows = @()

    foreach ($row in @($Rows)) {
        if ([string]::IsNullOrEmpty($row)) { continue }
        $kind = ($row -split '\|', 2)[0]
        switch ($kind) {
            'NOWIN' {
                $p = $row -split '\|', 5
                if ($p.Count -lt 5) { break }
                $noWindows += @{ Hwnd = [long]$p[1]; Visible = ($p[2] -eq '1'); Class = [string]$p[3]; Title = [string]$p[4] }
            }
            'SURFACE' {
                $p = $row -split '\|', 4
                if ($p.Count -lt 4) { break }
                $title = [string]$p[3]
                $role = Get-GfxSurfaceRoleFromTitle -DocumentTitle $title
                $surfaces += @{
                    HostPid       = [int]$p[1]
                    Hwnd          = [long]$p[2]
                    DocumentTitle = $title
                    Role          = $role
                    # 'window-title' is direct evidence: the WebView2 visual
                    # host window carries the rendered document's own title.
                    # It is NOT correlation and NOT PID order.
                    RoleSource    = if ($role -eq 'Unknown') { 'unresolved' } else { 'window-title' }
                }
            }
            'D3DWIN' {
                $p = $row -split '\|', 2
                if ($p.Count -lt 2) { break }
                $d3d += [int]$p[1]
            }
        }
    }

    return @{
        Surfaces  = $surfaces
        D3DPids   = @($d3d | Sort-Object -Unique)
        NoWindows = $noWindows
    }
}

function Get-GfxSurfaceRoleFromTitle {
    <#
    .SYNOPSIS
        Maps a WebView2 document title to a surface role.
    .DESCRIPTION
        Measured on NO 4.0.0.7 (2026-09-08): the two Chrome_WidgetWin_1
        windows hosted inside NO's LabVIEW child window carry the document
        titles 'LabVIEW Video.js Player' and 'Butterchurn Music Visualizer'
        verbatim -- the same strings CDP reports for the two targets. That
        makes role resolution passive and authoritative: no debug port, no
        JavaScript, no PID-order guessing.

        Anything unrecognised returns 'Unknown' and the caller records it as
        unresolved rather than assigning a role it cannot defend.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DocumentTitle)

    if ($DocumentTitle -match 'Butterchurn') { return 'Butterchurn' }
    if ($DocumentTitle -match 'Video\.?js') { return 'VideoJs' }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Process tree
# ---------------------------------------------------------------------------

function Get-NoWebViewHostTree {
    <#
    .SYNOPSIS
        NO.exe's WebView2 host processes and their children.
    .DESCRIPTION
        Host processes are msedgewebview2.exe children of NO.exe; each has its
        own gpu-process, renderer, network/storage/audio utilities and
        crashpad handler (GRAPHICS-BENCH-001 section 2.2). The user-data-dir
        is per-launch (%TEMP%\lvtemporary_<n>.webview2), so nothing derived
        from it may be cached across an NO restart.
    .OUTPUTS
        Hashtable: NoPid, NoStartUtc, Hosts[] (HostPid, UserDataDir,
        RuntimePath, Children[] { Pid, Type }), Available, Reason.
    #>
    [CmdletBinding()]
    param([int]$NoPid = 0)

    $noProc = $null
    if ($NoPid -gt 0) {
        $noProc = Get-Process -Id $NoPid -ErrorAction SilentlyContinue
    } else {
        $noProc = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue) | Sort-Object StartTime | Select-Object -First 1
    }
    if (-not $noProc) {
        return @{ Available = $false; Reason = 'NO.exe is not running'; NoPid = $null; NoStartUtc = $null; Hosts = @() }
    }

    $webviews = @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" -ErrorAction SilentlyContinue |
        Select-Object ProcessId, ParentProcessId, CommandLine)

    $hosts = @()
    foreach ($hostProc in @($webviews | Where-Object { $_.ParentProcessId -eq $noProc.Id })) {
        $udd = $null
        if ($hostProc.CommandLine -match '--user-data-dir="([^"]+)"') { $udd = $Matches[1] }
        elseif ($hostProc.CommandLine -match '--user-data-dir=([^\s]+)') { $udd = $Matches[1] }

        $runtimePath = $null
        if ($hostProc.CommandLine -match '^"([^"]+msedgewebview2\.exe)"') { $runtimePath = $Matches[1] }

        $children = @()
        foreach ($kid in @($webviews | Where-Object { $_.ParentProcessId -eq $hostProc.ProcessId })) {
            $type = 'browser'
            if ($kid.CommandLine -match '--type=([^\s]+)') { $type = $Matches[1] }
            $children += @{ Pid = [int]$kid.ProcessId; Type = $type }
        }

        $hosts += @{
            HostPid     = [int]$hostProc.ProcessId
            UserDataDir = $udd
            RuntimePath = $runtimePath
            Children    = $children
            GpuPid      = @($children | Where-Object { $_.Type -eq 'gpu-process' } | ForEach-Object { $_.Pid }) | Select-Object -First 1
            RendererPid = @($children | Where-Object { $_.Type -eq 'renderer' } | ForEach-Object { $_.Pid }) | Select-Object -First 1
        }
    }

    $startUtc = $null
    try { $startUtc = $noProc.StartTime.ToUniversalTime() } catch { }

    return @{
        Available  = $true
        Reason     = $null
        NoPid      = [int]$noProc.Id
        NoStartUtc = $startUtc
        Hosts      = $hosts
    }
}

function Resolve-NoWebViewSurfaces {
    <#
    .SYNOPSIS
        Joins the window-title role evidence to the process tree.
    .DESCRIPTION
        Two independent channels are JOINED here, which is exactly where this
        repo's channel-mismatch bug class bites, so the join key is explicit:
        HostPid, from the window's owning process id on one side and
        Win32_Process on the other. Nothing is matched by order or by index.

        A host with no visual window yet (still starting) is returned with
        Role 'Unknown' and RoleSource 'unresolved' rather than dropped -- its
        counters are still real and the absence is itself a fact.
    .OUTPUTS
        Array of surface hashtables.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$HostTree,
        [hashtable]$WindowScan
    )

    if (-not $HostTree.Available) { return ,@() }

    $byPid = @{}
    if ($WindowScan -and $WindowScan.Surfaces) {
        foreach ($s in $WindowScan.Surfaces) { $byPid[[int]$s.HostPid] = $s }
    }

    $out = @()
    foreach ($h in $HostTree.Hosts) {
        $role = 'Unknown'
        $roleSource = 'unresolved'
        $docTitle = $null
        if ($byPid.ContainsKey($h.HostPid)) {
            $role = $byPid[$h.HostPid].Role
            $roleSource = $byPid[$h.HostPid].RoleSource
            $docTitle = $byPid[$h.HostPid].DocumentTitle
        }
        $out += @{
            Role          = $role
            RoleSource    = $roleSource
            DocumentTitle = $docTitle
            HostPid       = $h.HostPid
            GpuPid        = $h.GpuPid
            RendererPid   = $h.RendererPid
            UserDataDir   = $h.UserDataDir
            TreePids      = @(@($h.HostPid) + @($h.Children | ForEach-Object { $_.Pid }))
        }
    }
    return ,$out
}

# ---------------------------------------------------------------------------
# GPU counters
# ---------------------------------------------------------------------------

function Test-GfxGpuCounterSupport {
    <#
    .SYNOPSIS
        Whether the GPU Engine / GPU Process Memory counter categories exist.
    .DESCRIPTION
        Win10 1709+ and unelevated. On a box without them the run still has
        value (process CPU, memory, surface lifetime), so the caller degrades
        instead of failing -- and the record says WHY, never 0%.
    #>
    [CmdletBinding()]
    param()

    $result = @{ EngineAvailable = $false; MemoryAvailable = $false; Reason = $null }
    try {
        $result.EngineAvailable = [System.Diagnostics.PerformanceCounterCategory]::Exists('GPU Engine')
        $result.MemoryAvailable = [System.Diagnostics.PerformanceCounterCategory]::Exists('GPU Process Memory')
    } catch {
        $result.Reason = "Performance counter categories unreadable: $($_.Exception.Message)"
        return $result
    }
    if (-not $result.EngineAvailable) {
        # Counter names are English-only in the .NET category API; a localised
        # Windows install can legitimately fail here.
        $result.Reason = "The 'GPU Engine' performance counter category is not present (needs Windows 10 1709+, English counter names)."
    }
    return $result
}

function ConvertFrom-GfxEngineInstanceName {
    <#
    .SYNOPSIS
        Parses a GPU Engine counter instance name.
    .DESCRIPTION
        Shape: pid_<n>_luid_0x<hi>_0x<lo>_phys_<n>_eng_<n>_engtype_<Type>.
        Instances with an empty engtype exist and are skipped by the caller.
    .OUTPUTS
        Hashtable Pid/Luid/Engine, or $null when the name does not parse.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$InstanceName)

    if ($InstanceName -notmatch '^pid_(\d+)_luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)_phys_\d+_eng_\d+_engtype_(.+)$') { return $null }
    $engine = $Matches[3]
    if ([string]::IsNullOrWhiteSpace($engine)) { return $null }
    return @{ Pid = [int]$Matches[1]; Luid = $Matches[2]; Engine = $engine }
}

# ---------------------------------------------------------------------------
# Sampler -- background runspace, persistent counters
# ---------------------------------------------------------------------------

function Start-GraphicsSampler {
    <#
    .SYNOPSIS
        Starts the background sampler.
    .DESCRIPTION
        Background runspace + ConcurrentQueue + main-loop drain, the pattern
        the NO-window sampler already proved. A DoEvents-driven sampler would
        perturb exactly what it measures.

        THE COST THAT FORCED THIS DESIGN: Get-Counter with a wildcard over
        '\GPU Engine(*)\Utilization Percentage' measured 2.3-2.9 s per call on
        the reference box (579 instances). Persistent
        System.Diagnostics.PerformanceCounter objects over only the instances
        belonging to NO's host trees measured 14 ms for 8 counters -- ~165x
        cheaper. Instance enumeration itself costs ~5 s, so it runs only when
        the tracked PID set actually changes, and each refresh is announced on
        the queue as a CounterRefresh record so its cost is visible rather
        than showing up as sampler jitter.
    .PARAMETER IntervalMs
        Target cadence. Actual per-tick duration is recorded on every sample.
    .OUTPUTS
        Hashtable handle: Runspace, PowerShell, Handle, Control, Queue.
    #>
    [CmdletBinding()]
    param(
        [int]$IntervalMs = 1000,
        [int]$NoPid = 0
    )

    if (-not (Initialize-GfxWindowScan)) {
        throw 'Could not compile the window-scan helper; the sampler cannot attribute surfaces without it.'
    }

    $control = [hashtable]::Synchronized(@{
        Stop        = $false
        Error       = $null
        SampleCount = 0
        NoPid       = $NoPid
    })
    $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'

    # Self-contained on purpose: the runspace never touches this module's
    # session state. It reads, it enqueues, nothing else.
    $samplerScript = {
        param($Control, $Queue, $IntervalMs)

        function Parse-Instance {
            param([string]$Name)
            if ($Name -notmatch '^pid_(\d+)_luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)_phys_\d+_eng_\d+_engtype_(.+)$') { return $null }
            if ([string]::IsNullOrWhiteSpace($Matches[3])) { return $null }
            # The LUID identifies WHICH adapter the process is drawing on. On a
            # hybrid laptop that is the question, so it is carried as an
            # identifier rather than collapsed into a label.
            return @{ Pid = [int]$Matches[1]; Luid = $Matches[2]; Engine = $Matches[3] }
        }

        $engineOk = $false
        $memoryOk = $false
        $counterReason = $null
        try {
            $engineOk = [System.Diagnostics.PerformanceCounterCategory]::Exists('GPU Engine')
            $memoryOk = [System.Diagnostics.PerformanceCounterCategory]::Exists('GPU Process Memory')
            if (-not $engineOk) { $counterReason = "'GPU Engine' counter category not present" }
        } catch {
            $counterReason = "counter categories unreadable: $($_.Exception.Message)"
        }

        # pid -> @{ engine -> PerformanceCounter }
        $engineCounters = @{}
        $memCounters = @{}
        $luidByPid = @{}
        $countersForPids = @()
        # Runspace-local caches. Initialised explicitly so the first iteration
        # compares against a real value rather than an undefined variable.
        $script:GfxTreeKey = $null
        $script:GfxTree = @{}
        # pid -> @{ Cpu = TimeSpan; At = datetime } for CPU deltas
        $cpuPrev = @{}

        while (-not $Control.Stop) {
            $tickStart = [datetime]::UtcNow
            $tickSw = [Diagnostics.Stopwatch]::StartNew()
            try {
                $noPid = [int]$Control.NoPid
                if ($noPid -le 0) {
                    $p = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue) | Sort-Object StartTime | Select-Object -First 1
                    if ($p) { $noPid = $p.Id; $Control.NoPid = $noPid }
                }

                $surfaces = @()
                $noWindows = @()
                if ($noPid -gt 0) {
                    $rows = @()
                    try { $rows = [WinConfigDiag.GfxWindowScan]::Scan($noPid) } catch { }
                    $seen = @{}
                    foreach ($row in $rows) {
                        $kind = ($row -split '\|', 2)[0]
                        if ($kind -eq 'SURFACE') {
                            $p2 = $row -split '\|', 4
                            if ($p2.Count -lt 4) { continue }
                            $hp = [int]$p2[1]
                            if ($seen.ContainsKey($hp)) { continue }
                            $seen[$hp] = $true
                            $title = [string]$p2[3]
                            $role = 'Unknown'
                            if ($title -match 'Butterchurn') { $role = 'Butterchurn' }
                            elseif ($title -match 'Video\.?js') { $role = 'VideoJs' }
                            $surfaces += @{ HostPid = $hp; DocumentTitle = $title; Role = $role; RoleSource = $(if ($role -eq 'Unknown') { 'unresolved' } else { 'window-title' }) }
                        } elseif ($kind -eq 'NOWIN') {
                            $p2 = $row -split '\|', 5
                            if ($p2.Count -lt 5) { continue }
                            if ($p2[2] -eq '1' -and -not [string]::IsNullOrWhiteSpace($p2[4])) { $noWindows += [string]$p2[4] }
                        }
                    }
                }

                # Process tree, re-read only when the surface host set changes.
                $hostPids = @($surfaces | ForEach-Object { $_.HostPid } | Sort-Object)
                $treeKey = ($hostPids -join ',')
                if ($script:GfxTreeKey -ne $treeKey) {
                    $script:GfxTreeKey = $treeKey
                    $script:GfxTree = @{}
                    $wv = @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, CommandLine)
                    foreach ($hp in $hostPids) {
                        $kids = @($wv | Where-Object { $_.ParentProcessId -eq $hp })
                        $gpu = $null; $ren = $null; $all = @($hp)
                        foreach ($k in $kids) {
                            $all += [int]$k.ProcessId
                            $t = 'browser'
                            if ($k.CommandLine -match '--type=([^\s]+)') { $t = $Matches[1] }
                            if ($t -eq 'gpu-process' -and -not $gpu) { $gpu = [int]$k.ProcessId }
                            if ($t -eq 'renderer' -and -not $ren) { $ren = [int]$k.ProcessId }
                        }
                        $script:GfxTree[$hp] = @{ GpuPid = $gpu; RendererPid = $ren; TreePids = $all }
                    }
                }

                # Counter set, rebuilt only when the tracked pid set changes.
                $trackPids = @()
                foreach ($hp in $hostPids) { if ($script:GfxTree.ContainsKey($hp)) { $trackPids += $script:GfxTree[$hp].TreePids } }
                $trackPids = @($trackPids | Sort-Object -Unique)
                if ($engineOk -and (($trackPids -join ',') -ne ($countersForPids -join ','))) {
                    $refreshSw = [Diagnostics.Stopwatch]::StartNew()
                    $engineCounters = @{}
                    $memCounters = @{}
                    $luidByPid = @{}
                    try {
                        $wantSet = @{}
                        foreach ($tp in $trackPids) { $wantSet["pid_${tp}_"] = $true }
                        $cat = New-Object System.Diagnostics.PerformanceCounterCategory 'GPU Engine'
                        foreach ($inst in $cat.GetInstanceNames()) {
                            $parsed = Parse-Instance $inst
                            if (-not $parsed) { continue }
                            if ($trackPids -notcontains $parsed.Pid) { continue }
                            try {
                                $c = New-Object System.Diagnostics.PerformanceCounter 'GPU Engine', 'Utilization Percentage', $inst, $true
                                $null = $c.NextValue()
                                if (-not $luidByPid.ContainsKey($parsed.Pid)) { $luidByPid[$parsed.Pid] = @() }
                                if ($luidByPid[$parsed.Pid] -notcontains $parsed.Luid) { $luidByPid[$parsed.Pid] += $parsed.Luid }
                                if (-not $engineCounters.ContainsKey($parsed.Pid)) { $engineCounters[$parsed.Pid] = @{} }
                                if (-not $engineCounters[$parsed.Pid].ContainsKey($parsed.Engine)) { $engineCounters[$parsed.Pid][$parsed.Engine] = @() }
                                $engineCounters[$parsed.Pid][$parsed.Engine] += $c
                            } catch { }
                        }
                        if ($memoryOk) {
                            $mcat = New-Object System.Diagnostics.PerformanceCounterCategory 'GPU Process Memory'
                            foreach ($inst in $mcat.GetInstanceNames()) {
                                if ($inst -notmatch '^pid_(\d+)_') { continue }
                                $mp = [int]$Matches[1]
                                if ($trackPids -notcontains $mp) { continue }
                                try {
                                    $c = New-Object System.Diagnostics.PerformanceCounter 'GPU Process Memory', 'Local Usage', $inst, $true
                                    $null = $c.NextValue()
                                    if (-not $memCounters.ContainsKey($mp)) { $memCounters[$mp] = @() }
                                    $memCounters[$mp] += $c
                                } catch { }
                            }
                        }
                        $countersForPids = $trackPids
                    } catch {
                        $counterReason = "counter binding failed: $($_.Exception.Message)"
                    }
                    $refreshSw.Stop()
                    $Queue.Enqueue(@{ Kind = 'CounterRefresh'; AtUtc = [datetime]::UtcNow; DurationMs = [int]$refreshSw.ElapsedMilliseconds; TrackedPids = $trackPids; BoundPids = @($engineCounters.Keys) })
                }

                # Read.
                $sampleSurfaces = @()
                foreach ($s in $surfaces) {
                    $hp = $s.HostPid
                    $tree = $null
                    if ($script:GfxTree.ContainsKey($hp)) { $tree = $script:GfxTree[$hp] }
                    $gpuPid = $null; $renPid = $null; $treePids = @($hp)
                    if ($tree) { $gpuPid = $tree.GpuPid; $renPid = $tree.RendererPid; $treePids = $tree.TreePids }

                    # Engines are reported for the GPU process, which is where
                    # the compositor's work lands.
                    $engines = $null
                    if ($engineOk -and $gpuPid -and $engineCounters.ContainsKey($gpuPid)) {
                        $engines = @{}
                        foreach ($eng in $engineCounters[$gpuPid].Keys) {
                            $sum = 0.0
                            foreach ($c in $engineCounters[$gpuPid][$eng]) { try { $sum += [double]$c.NextValue() } catch { } }
                            $engines[$eng] = [math]::Round($sum, 3)
                        }
                    }

                    $gpuMemMB = $null
                    if ($memoryOk -and $gpuPid -and $memCounters.ContainsKey($gpuPid)) {
                        $mSum = 0.0
                        foreach ($c in $memCounters[$gpuPid]) { try { $mSum += [double]$c.NextValue() } catch { } }
                        $gpuMemMB = [math]::Round($mSum / 1MB, 1)
                    }

                    # Tree CPU + working set from process objects (no counters).
                    $wsMB = $null; $cpuPct = $null
                    $wsTotal = 0.0; $cpuTotal = [TimeSpan]::Zero; $any = $false
                    foreach ($tp in $treePids) {
                        try {
                            $proc = [System.Diagnostics.Process]::GetProcessById($tp)
                            $wsTotal += $proc.WorkingSet64
                            $cpuTotal = $cpuTotal.Add($proc.TotalProcessorTime)
                            $any = $true
                        } catch { }
                    }
                    if ($any) {
                        $wsMB = [math]::Round($wsTotal / 1MB, 1)
                        $now = [datetime]::UtcNow
                        if ($cpuPrev.ContainsKey($hp)) {
                            $dt = ($now - $cpuPrev[$hp].At).TotalSeconds
                            $dc = ($cpuTotal - $cpuPrev[$hp].Cpu).TotalSeconds
                            if ($dt -gt 0) { $cpuPct = [math]::Round(100.0 * $dc / ($dt * [Environment]::ProcessorCount), 2) }
                        }
                        $cpuPrev[$hp] = @{ Cpu = $cpuTotal; At = $now }
                    }

                    $adapterLuids = $null
                    if ($gpuPid -and $luidByPid.ContainsKey($gpuPid)) { $adapterLuids = $luidByPid[$gpuPid] }

                    $sampleSurfaces += @{
                        AdapterLuids  = $adapterLuids
                        Role          = $s.Role
                        RoleSource    = $s.RoleSource
                        DocumentTitle = $s.DocumentTitle
                        HostPid       = $hp
                        GpuPid        = $gpuPid
                        RendererPid   = $renPid
                        Engines       = $engines
                        GpuMemoryMB   = $gpuMemMB
                        WorkingSetMB  = $wsMB
                        CpuPercent    = $cpuPct
                    }
                }

                $noWs = $null; $noCpu = $null
                if ($noPid -gt 0) {
                    try {
                        $np = [System.Diagnostics.Process]::GetProcessById($noPid)
                        $noWs = [math]::Round($np.WorkingSet64 / 1MB, 1)
                        $now = [datetime]::UtcNow
                        if ($cpuPrev.ContainsKey('NO')) {
                            $dt = ($now - $cpuPrev['NO'].At).TotalSeconds
                            $dc = ($np.TotalProcessorTime - $cpuPrev['NO'].Cpu).TotalSeconds
                            if ($dt -gt 0) { $noCpu = [math]::Round(100.0 * $dc / ($dt * [Environment]::ProcessorCount), 2) }
                        }
                        $cpuPrev['NO'] = @{ Cpu = $np.TotalProcessorTime; At = $now }
                    } catch { }
                }

                $tickSw.Stop()
                $Control.SampleCount = [int]$Control.SampleCount + 1
                $Queue.Enqueue(@{
                    Kind             = 'Sample'
                    AtUtc            = $tickStart
                    TickMs           = [int]$tickSw.ElapsedMilliseconds
                    NoPid            = $(if ($noPid -gt 0) { $noPid } else { $null })
                    NoWorkingSetMB   = $noWs
                    NoCpuPercent     = $noCpu
                    NoVisibleWindows = $noWindows
                    Surfaces         = $sampleSurfaces
                    CountersOk       = $engineOk
                    CounterReason    = $counterReason
                })
            } catch {
                $Control.Error = $_.Exception.Message
                $Queue.Enqueue(@{ Kind = 'SamplerError'; AtUtc = [datetime]::UtcNow; Message = $_.Exception.Message })
            }

            $sleep = $IntervalMs - [int]$tickSw.ElapsedMilliseconds
            if ($sleep -lt 50) { $sleep = 50 }
            Start-Sleep -Milliseconds $sleep
        }
    }

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    $null = $ps.AddScript($samplerScript).AddArgument($control).AddArgument($queue).AddArgument($IntervalMs)
    $handle = $ps.BeginInvoke()

    return @{ Runspace = $runspace; PowerShell = $ps; Handle = $handle; Control = $control; Queue = $queue }
}

function Receive-GraphicsSamples {
    <#
    .SYNOPSIS
        Drains everything the sampler has enqueued since the last call.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Sampler)

    $out = @()
    $item = $null
    while ($Sampler.Queue.TryDequeue([ref]$item)) { $out += $item }
    return ,$out
}

function Stop-GraphicsSampler {
    <#
    .SYNOPSIS
        Stops the sampler and disposes the runspace. Safe to call twice.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Sampler)

    try { $Sampler.Control.Stop = $true } catch { }
    try { $null = $Sampler.PowerShell.EndInvoke($Sampler.Handle) } catch { }
    try { $Sampler.PowerShell.Dispose() } catch { }
    try { $Sampler.Runspace.Close(); $Sampler.Runspace.Dispose() } catch { }
}

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

function Get-GraphicsInventory {
    <#
    .SYNOPSIS
        The one-shot machine/graphics inventory: model, CPU, RAM, adapters,
        displays, power state, WebView2 fixed-version runtime.
    .DESCRIPTION
        Read-only WMI/CIM plus one registry read for the runtime version.
        Nothing here is a verdict; the dashboard rules judge, this reports.
        Every field that could not be read is $null, never a placeholder zero.
    #>
    [CmdletBinding()]
    param()

    $inv = @{
        CollectedAtUtc = [datetime]::UtcNow.ToString('o')
        System         = @{}
        Adapters       = @()
        Displays       = @()
        Power          = @{}
        WebView2       = @{}
        No             = @{}
        Errors         = @()
    }

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cpu = @(Get-CimInstance Win32_Processor -ErrorAction Stop) | Select-Object -First 1
        $inv.System = @{
            Manufacturer  = $cs.Manufacturer
            Model         = $cs.Model
            SystemSku     = $cs.SystemSKUNumber
            TotalRamGB    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            LogicalCores  = [int]$cs.NumberOfLogicalProcessors
            Cpu           = $cpu.Name
            OsCaption     = $os.Caption
            OsBuild       = $os.BuildNumber
            OsVersion     = $os.Version
        }
    } catch { $inv.Errors += "system: $($_.Exception.Message)" }

    try {
        foreach ($vc in @(Get-CimInstance Win32_VideoController -ErrorAction Stop)) {
            $drvDate = $null
            try { if ($vc.DriverDate) { $drvDate = ([datetime]$vc.DriverDate).ToString('yyyy-MM-dd') } } catch { }
            $pnp = [string]$vc.PNPDeviceID
            $venDev = $null
            if ($pnp -match 'VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})') { $venDev = "VEN_$($Matches[1])&DEV_$($Matches[2])" }
            $inv.Adapters += @{
                Name          = $vc.Name
                PnpDeviceId   = $pnp
                VenDev        = $venDev
                DriverVersion = $vc.DriverVersion
                DriverDate    = $drvDate
                VideoMemoryMB = $(if ($vc.AdapterRAM) { [math]::Round($vc.AdapterRAM / 1MB, 0) } else { $null })
                CurrentMode   = $(if ($vc.CurrentHorizontalResolution) { "$($vc.CurrentHorizontalResolution)x$($vc.CurrentVerticalResolution)@$($vc.CurrentRefreshRate)" } else { $null })
                Status        = $vc.Status
            }
        }
        # A hybrid laptop is the case where "which adapter did the pane use?"
        # is a real question rather than a formality. Flag it as a fact; the
        # per-host answer needs the ANGLE renderer string (CDP), and until
        # that exists the run carries the LUID it measured, not a guess.
        $vendors = @($inv.Adapters | ForEach-Object { $_.VenDev } | Where-Object { $_ } | ForEach-Object { ($_ -split '&')[0] } | Sort-Object -Unique)
        $inv.HybridGpu = ($vendors.Count -gt 1)
        $inv.DisplayDrivingAdapters = @($inv.Adapters | Where-Object { $_.CurrentMode } | ForEach-Object { $_.Name })
    } catch { $inv.Errors += "adapters: $($_.Exception.Message)" }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        foreach ($scr in [System.Windows.Forms.Screen]::AllScreens) {
            $inv.Displays += @{
                DeviceName = $scr.DeviceName
                Primary    = [bool]$scr.Primary
                Bounds     = "$($scr.Bounds.Width)x$($scr.Bounds.Height)"
                BitsPerPixel = $scr.BitsPerPixel
            }
        }
        $inv.MonitorCount = $inv.Displays.Count
    } catch { $inv.Errors += "displays: $($_.Exception.Message)" }

    try {
        $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue) | Select-Object -First 1
        $scheme = $null
        try { $scheme = (powercfg /getactivescheme 2>$null) -join ' ' } catch { }
        $inv.Power = @{
            OnBattery     = $(if ($battery) { $battery.BatteryStatus -eq 1 } else { $false })
            HasBattery    = [bool]$battery
            ActiveScheme  = $scheme
        }
    } catch { $inv.Errors += "power: $($_.Exception.Message)" }

    try {
        $runtimeExe = 'C:\ProgramData\NO WebView2 Runtime\runtime\x64\msedgewebview2.exe'
        if (Test-Path -LiteralPath $runtimeExe) {
            $fi = Get-Item -LiteralPath $runtimeExe
            $inv.WebView2 = @{
                Path            = $runtimeExe
                Version         = $fi.VersionInfo.ProductVersion
                FileVersion     = $fi.VersionInfo.FileVersion
                SizeBytes       = $fi.Length
                LastWriteUtc    = $fi.LastWriteTimeUtc.ToString('o')
            }
        } else {
            $inv.WebView2 = @{ Path = $runtimeExe; Version = $null; Reason = 'fixed-version runtime not found at the expected path' }
        }
    } catch { $inv.Errors += "webview2: $($_.Exception.Message)" }

    try {
        $noProc = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue) | Sort-Object StartTime | Select-Object -First 1
        if ($noProc) {
            $inv.No = @{
                Pid        = $noProc.Id
                Path       = $noProc.Path
                Version    = $(try { $noProc.MainModule.FileVersionInfo.ProductVersion } catch { $null })
                StartedUtc = $(try { $noProc.StartTime.ToUniversalTime().ToString('o') } catch { $null })
            }
        } else {
            $inv.No = @{ Pid = $null; Running = $false }
        }
    } catch { $inv.Errors += "no: $($_.Exception.Message)" }

    return $inv
}

function Get-NompConfigSnapshot {
    <#
    .SYNOPSIS
        Reads NOMP.config (NO's media-player component) for the graphics-
        relevant settings.
    .DESCRIPTION
        Same shape as Get-NoDeviceManagerConfigSnapshot: LabVIEW writes a
        flattened blob, so the file is decoded Latin-1 1:1 and scanned for
        printable strings.

        MEASURED 2026-09-08 on NO 4.0.0.7 (MM06), and it corrects an earlier
        reading of this file: NOMP.config's printable region is a LabVIEW TYPE
        DESCRIPTOR, not a settings store. It names the fields ('Enable
        Butterchurn', 'Session Type', 'Zengar Media Path') and even enumerates
        Session Type's legal values (Regular / Extended / Demo / Custom), but
        the file carries no adjacent VALUE for any of them, and it is rewritten
        at every NO launch (mtime tracked NO's start time exactly).

        So the schema is reported as schema and the values are reported as
        NOT READABLE, with a reason. Nothing here defaults 'Enable Butterchurn'
        to False or 'Session Type' to Regular: an unread setting must render as
        absent, and a fabricated default would silently mislabel every run in
        the comparison corpus.
    .OUTPUTS
        Hashtable: Path, Exists, Sha256, SizeBytes, SchemaKeysPresent,
        SessionTypeOptions, ValuesReadable, ValuesReason, EnableButterchurn,
        SessionType, MediaPath (all three $null until a value channel is
        found), Strings (capped).
    #>
    [CmdletBinding()]
    param([string]$Path = 'C:\ProgramData\NeurOptimal\NOMP\NOMP.config')

    $result = @{ Path = $Path; Exists = $false; Sha256 = $null; SizeBytes = $null; SchemaKeysPresent = @(); SessionTypeOptions = @(); ValuesReadable = $false; ValuesReason = $null; EnableButterchurn = $null; SessionType = $null; MediaPath = $null; Strings = @() }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $result.Exists = $true
        $result.SizeBytes = $bytes.Length
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $result.Sha256 = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') } finally { $sha.Dispose() }

        $text = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($bytes)
        $strings = @([regex]::Matches($text, '[\x20-\x7E]{4,}') | ForEach-Object { $_.Value })
        $result.Strings = @($strings | Select-Object -First 400)

        # Which known fields the schema declares. Presence of the key is a
        # fact; the value is not in this file.
        $knownKeys = @('Enable Butterchurn', 'Session Type', 'Zengar Media Path', 'Volume', 'Interrupts During Playback', 'Visualizer Window size (single monitor)', 'Do Not Show Dialogs')
        $joined = ($strings -join ' ')
        foreach ($k in $knownKeys) {
            if ($joined -like "*$k*") { $result.SchemaKeysPresent += $k }
        }
        if ($joined -match 'Session Type--enum\.ctl[^A-Za-z]{0,12}((?:Regular|Extended|Demo|Custom)[^A-Za-z]{0,4}){2,}') {
            $result.SessionTypeOptions = @([regex]::Matches($Matches[0], 'Regular|Extended|Demo|Custom') | ForEach-Object { $_.Value } | Select-Object -Unique)
        }
        $result.ValuesReadable = $false
        $result.ValuesReason = 'NOMP.config carries the LabVIEW type descriptor only; no value follows any key, and the file is rewritten at every NO launch.'
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-NoOpenedMediaFile {
    <#
    .SYNOPSIS
        Names the media file NO most recently opened, passively.
    .DESCRIPTION
        Uses LastAccessTime under the configured media root. Only meaningful
        when last-access updates are enabled on the volume, so the function
        reports Enabled/Unknown explicitly: where it is off the field renders
        'Unknown', NOT blank and NOT a guess, and the run is marked
        media-kind-unlabelled so it is never pooled with labelled runs.

        Provenance discipline: a file this tool itself has read carries our
        own timestamp. Only files accessed AFTER the run's start are reported,
        and the caller must not read the media tree for any other purpose
        during the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$MediaRoot,
        [Parameter(Mandatory)][datetime]$SinceUtc
    )

    $result = @{ LastAccessEnabled = $null; File = $null; AccessedUtc = $null; Reason = $null }

    if ([string]::IsNullOrWhiteSpace($MediaRoot)) {
        $result.Reason = 'no media path configured in NOMP.config'
        return $result
    }
    Assert-GfxPathAllowed -Path $MediaRoot
    if (-not (Test-Path -LiteralPath $MediaRoot)) {
        $result.Reason = "media path not found: $MediaRoot"
        return $result
    }

    try {
        $fsutil = & fsutil behavior query DisableLastAccess 2>$null
        $joined = ($fsutil -join ' ')
        if ($joined -match 'DisableLastAccess\s*=\s*(\d)') {
            # 0 and 2 mean updates are ENABLED (2 = system managed, enabled).
            $result.LastAccessEnabled = ($Matches[1] -eq '0' -or $Matches[1] -eq '2')
        }
    } catch { }

    if ($result.LastAccessEnabled -eq $false) {
        $result.Reason = 'last-access updates are disabled on this volume'
        return $result
    }

    try {
        $newest = Get-ChildItem -LiteralPath $MediaRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastAccessTimeUtc -gt $SinceUtc } |
            Sort-Object LastAccessTimeUtc -Descending | Select-Object -First 1
        if ($newest) {
            $result.File = $newest.FullName
            $result.AccessedUtc = $newest.LastAccessTimeUtc.ToString('o')
        } else {
            $result.Reason = 'no file under the media root was accessed since the run started'
        }
    } catch {
        $result.Reason = "media scan failed: $($_.Exception.Message)"
    }
    return $result
}

# ---------------------------------------------------------------------------
# Phase segmentation and summary -- pure functions
# ---------------------------------------------------------------------------

function Get-GraphicsActivityState {
    <#
    .SYNOPSIS
        Classifies one sample as Idle / Visualizer / Media / Both.
    .DESCRIPTION
        Derived from measured engine load against explicit floors, not from
        anything NO tells us. The classification is INFERRED and every record
        says so.

        THE NAMES DESCRIBE THE MEASUREMENT, NOT THE SESSION. Butterchurn's
        render loop is unconditional -- measured 9.1% 3D on this box with NO
        sitting idle at its main screen, and 7.6-10.6% in earlier captures --
        so 'VisualizerOnly' means the visualizer is drawing, which it does
        whether or not a session is running. Whether a SESSION is running is a
        separate question, answered by NO's own window set (see
        Get-NoUiChangePoints), and the two are reported separately on purpose.
    .OUTPUTS
        [string] Quiet | VisualizerOnly | MediaOnly | Both | Unmeasured
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Sample,
        [double]$VisualizerFloorPercent = 1.0,
        [double]$MediaFloorPercent = 0.3
    )

    $anyEngines = $false
    $vis = $false
    $media = $false
    foreach ($s in @($Sample.Surfaces)) {
        if ($null -eq $s.Engines) { continue }
        $anyEngines = $true
        $threeD = 0.0
        $decode = 0.0
        foreach ($k in $s.Engines.Keys) {
            if ($k -eq '3D') { $threeD += [double]$s.Engines[$k] }
            elseif ($k -eq 'VideoDecode' -or $k -eq 'VideoProcessing') { $decode += [double]$s.Engines[$k] }
        }
        if ($s.Role -eq 'Butterchurn' -and $threeD -ge $VisualizerFloorPercent) { $vis = $true }
        if ($s.Role -eq 'VideoJs' -and $decode -ge $MediaFloorPercent) { $media = $true }
        # An unresolved surface still counts toward media if it is decoding:
        # hardware decode is not something a visualizer does.
        if ($s.Role -eq 'Unknown' -and $decode -ge $MediaFloorPercent) { $media = $true }
    }

    if (-not $anyEngines) { return 'Unmeasured' }
    if ($vis -and $media) { return 'Both' }
    if ($media) { return 'MediaOnly' }
    if ($vis) { return 'VisualizerOnly' }
    return 'Quiet'
}

function Get-GraphicsActivitySpans {
    <#
    .SYNOPSIS
        Collapses per-sample states into dwell-filtered spans.
    .PARAMETER MinDwellSamples
        A state must hold for this many consecutive samples before it opens a
        span. Without it a single noisy tick mints a phase, and the summary
        fills with 1-second 'phases' that mean nothing.
    .OUTPUTS
        Array of @{ State, StartUtc, EndUtc, Samples }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$States,
        [int]$MinDwellSamples = 3
    )

    # Unary comma: preserve array shape for 0 and 1 element results.
    if ($States.Count -eq 0) { return ,@() }

    $spans = @()
    $current = $null
    $pending = $null
    $pendingCount = 0

    foreach ($row in $States) {
        $state = [string]$row.State
        if ($null -eq $current) {
            $current = @{ State = $state; StartUtc = $row.AtUtc; EndUtc = $row.AtUtc; Samples = 1 }
            continue
        }
        if ($state -eq $current.State) {
            $current.EndUtc = $row.AtUtc
            $current.Samples++
            $pending = $null
            $pendingCount = 0
            continue
        }
        if ($state -eq $pending) { $pendingCount++ } else { $pending = $state; $pendingCount = 1 }
        if ($pendingCount -ge $MinDwellSamples) {
            $spans += $current
            $current = @{ State = $state; StartUtc = $row.AtUtc; EndUtc = $row.AtUtc; Samples = $pendingCount }
            $pending = $null
            $pendingCount = 0
        } else {
            # Still inside the incumbent span until the new state proves it.
            $current.EndUtc = $row.AtUtc
            $current.Samples++
        }
    }
    if ($current) { $spans += $current }
    return ,$spans
}

function Get-NoUiChangePoints {
    <#
    .SYNOPSIS
        Finds when NO's own window set stopped looking like it did at the
        start of the run.
    .DESCRIPTION
        A session is something the operator starts in NO, and this tool never
        asks NO anything. What it can see, passively, is the set of VISIBLE
        top-level LabVIEW window titles NO owns -- the same channel the Flight
        Recorder already uses for dialog discrimination.

        The rule is deliberately self-calibrating rather than a hardcoded list
        of session VIs: the titles visible in the first samples ARE the idle
        baseline for this box and this NO build, and a change is any title
        appearing or disappearing relative to it. The events name the exact
        titles, so a reader can always check the call rather than trust it.

        This yields the run's own control arm: everything before the first
        sustained change is this box idling, measured minutes earlier on the
        same hardware, same driver, same NO launch.
    .PARAMETER MinDwellSamples
        A change must persist this many samples before it counts, so a
        transient dialog does not open a session.
    .OUTPUTS
        Hashtable: BaselineTitles, Changes[], FirstChangeIndex, FirstChangeUtc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [int]$BaselineSamples = 3,
        [int]$MinDwellSamples = 3
    )

    $result = @{ BaselineTitles = @(); Changes = @(); FirstChangeIndex = $null; FirstChangeUtc = $null }
    if ($Samples.Count -eq 0) { return $result }

    # Baseline = titles present in EVERY one of the first N samples, so a
    # window that was mid-open when we started does not poison it.
    $take = [Math]::Min($BaselineSamples, $Samples.Count)
    $baseline = $null
    for ($i = 0; $i -lt $take; $i++) {
        $titles = @($Samples[$i].NoVisibleWindows)
        if ($null -eq $baseline) { $baseline = $titles }
        else { $baseline = @($baseline | Where-Object { $titles -contains $_ }) }
    }
    $result.BaselineTitles = @($baseline | Sort-Object -Unique)

    $pendingFrom = $null
    for ($i = $take; $i -lt $Samples.Count; $i++) {
        $titles = @($Samples[$i].NoVisibleWindows)
        $added = @($titles | Where-Object { $result.BaselineTitles -notcontains $_ } | Sort-Object -Unique)
        $removed = @($result.BaselineTitles | Where-Object { $titles -notcontains $_ } | Sort-Object -Unique)
        $changed = (($added.Count + $removed.Count) -gt 0)

        if ($changed) {
            if ($null -eq $pendingFrom) { $pendingFrom = $i }
            if ((($i - $pendingFrom) + 1) -ge $MinDwellSamples -and $null -eq $result.FirstChangeIndex) {
                $result.FirstChangeIndex = $pendingFrom
                $result.FirstChangeUtc = $Samples[$pendingFrom].AtUtc
                $result.Changes += @{ AtUtc = $Samples[$pendingFrom].AtUtc; Added = $added; Removed = $removed }
            }
        } else {
            $pendingFrom = $null
        }
    }
    return $result
}

function Get-GfxRoleAggregate {
    <#
    .SYNOPSIS
        Per-surface-role aggregation over a set of samples. The single place
        engine/CPU/memory series become statistics.
    .DESCRIPTION
        Called once per arm (whole run, idle baseline, session) so the arms
        can never drift apart -- that drift is the same defect class as two
        live views of one run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [double]$DurationSec = 0
    )

    $roles = @{}
    foreach ($s in $Samples) {
        foreach ($surf in @($s.Surfaces)) {
            $key = "$($surf.Role)"
            if (-not $roles.ContainsKey($key)) {
                $roles[$key] = @{ Role = $surf.Role; RoleSource = $surf.RoleSource; DocumentTitle = $surf.DocumentTitle; HostPids = @(); GpuPids = @(); AdapterLuids = @(); Engines = @{}; WorkingSetMB = @(); CpuPercent = @(); GpuMemoryMB = @(); Samples = 0 }
            }
            $r = $roles[$key]
            $r.Samples++
            if ($surf.HostPid -and $r.HostPids -notcontains $surf.HostPid) { $r.HostPids += $surf.HostPid }
            if ($surf.GpuPid -and $r.GpuPids -notcontains $surf.GpuPid) { $r.GpuPids += $surf.GpuPid }
            foreach ($luid in @($surf.AdapterLuids)) {
                if ($luid -and $r.AdapterLuids -notcontains $luid) { $r.AdapterLuids += $luid }
            }
            if ($null -ne $surf.Engines) {
                foreach ($eng in $surf.Engines.Keys) {
                    if ($script:GfxEngineTypes -notcontains $eng) { continue }
                    if (-not $r.Engines.ContainsKey($eng)) { $r.Engines[$eng] = @() }
                    $r.Engines[$eng] += [double]$surf.Engines[$eng]
                }
            }
            if ($null -ne $surf.WorkingSetMB) { $r.WorkingSetMB += [double]$surf.WorkingSetMB }
            if ($null -ne $surf.CpuPercent) { $r.CpuPercent += [double]$surf.CpuPercent }
            if ($null -ne $surf.GpuMemoryMB) { $r.GpuMemoryMB += [double]$surf.GpuMemoryMB }
        }
    }

    $out = @()
    foreach ($key in $roles.Keys) {
        $r = $roles[$key]
        $engineStats = @{}
        foreach ($eng in $r.Engines.Keys) { $engineStats[$eng] = Get-GfxStats -Values ([double[]]$r.Engines[$eng]) }

        $wsFirst = $null; $wsLast = $null; $wsGrowth = $null; $wsGrowthPerMin = $null
        if ($r.WorkingSetMB.Count -ge 2) {
            $wsFirst = $r.WorkingSetMB[0]
            $wsLast = $r.WorkingSetMB[$r.WorkingSetMB.Count - 1]
            $wsGrowth = [math]::Round($wsLast - $wsFirst, 1)
            if ($DurationSec -gt 0) { $wsGrowthPerMin = [math]::Round($wsGrowth / ($DurationSec / 60.0), 2) }
        }

        $presence = $null
        if ($Samples.Count -gt 0) { $presence = [math]::Round($r.Samples / [double]$Samples.Count, 3) }

        $out += @{
            Role                     = $r.Role
            RoleSource               = $r.RoleSource
            DocumentTitle            = $r.DocumentTitle
            HostPids                 = $r.HostPids
            GpuPids                  = $r.GpuPids
            AdapterLuids             = $r.AdapterLuids
            SamplesPresent           = $r.Samples
            PresenceRatio            = $presence
            Engines                  = $engineStats
            Cpu                      = Get-GfxStats -Values ([double[]]$r.CpuPercent)
            WorkingSetMB             = Get-GfxStats -Values ([double[]]$r.WorkingSetMB)
            GpuMemoryMB              = Get-GfxStats -Values ([double[]]$r.GpuMemoryMB)
            WorkingSetFirstMB        = $wsFirst
            WorkingSetLastMB         = $wsLast
            WorkingSetGrowthMB       = $wsGrowth
            WorkingSetGrowthMBPerMin = $wsGrowthPerMin
        }
    }
    return ,$out
}

function Get-GraphicsBenchSessionSummary {
    <#
    .SYNOPSIS
        The ONE summariser. Both bench-session.json and the on-screen results
        read this -- never two implementations of the same number.
    .DESCRIPTION
        Three arms come out of a single passive run:

          Whole    every sample
          Idle     samples before NO's window set first changed -- this box
                   idling, on the same hardware, driver and NO launch, minutes
                   before the session. It is the control the comparison needs,
                   and in Session mode it costs nothing to collect.
          Session  samples from that change onward

        Deltas are Session minus Idle, per role and engine. A delta is $null
        when either arm is missing rather than 0: an unmeasured control is not
        a zero-cost control.

        The idle arm matters because butterchurn renders unconditionally. Its
        absolute 3D percentage answers no question on its own; what the visuals
        COST is the difference between the two arms on the same box.
    .PARAMETER Samples
        Every 'Sample' record drained from the sampler, in time order.
    .PARAMETER Markers
        Operator markers: @{ AtUtc, Text }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [array]$Markers = @(),
        [double]$VisualizerFloorPercent = 1.0,
        [double]$MediaFloorPercent = 0.3
    )

    $summary = @{
        SampleCount        = $Samples.Count
        StartUtc           = $null
        EndUtc             = $null
        DurationSec        = $null
        CountersOk         = $null
        CounterReason      = $null
        Surfaces           = @()
        Spans              = @()
        Markers            = @($Markers)
        Restarts           = @()
        TickMs             = @{}
        SessionStartUtc    = $null
        SessionStartSource = 'none-detected'
        NoUiBaselineTitles = @()
        NoUiChanges        = @()
        Arms               = @{ Idle = @(); Session = @() }
        ArmDurationSec     = @{ Idle = $null; Session = $null }
        Deltas             = @()
    }
    if ($Samples.Count -eq 0) { return $summary }

    $summary.StartUtc = $Samples[0].AtUtc
    $summary.EndUtc = $Samples[$Samples.Count - 1].AtUtc
    try { $summary.DurationSec = [math]::Round(([datetime]$summary.EndUtc - [datetime]$summary.StartUtc).TotalSeconds, 1) } catch { }
    $summary.CountersOk = [bool]$Samples[$Samples.Count - 1].CountersOk
    $summary.CounterReason = $Samples[$Samples.Count - 1].CounterReason
    $summary.TickMs = Get-GfxStats -Values @($Samples | ForEach-Object { [double]$_.TickMs })

    $states = @()
    foreach ($s in $Samples) {
        $states += @{ AtUtc = $s.AtUtc; State = (Get-GraphicsActivityState -Sample $s -VisualizerFloorPercent $VisualizerFloorPercent -MediaFloorPercent $MediaFloorPercent) }
    }
    foreach ($sp in (Get-GraphicsActivitySpans -States $states)) {
        $sec = $null
        try { $sec = [math]::Round(([datetime]$sp.EndUtc - [datetime]$sp.StartUtc).TotalSeconds, 1) } catch { }
        $summary.Spans += @{ State = $sp.State; StartUtc = $sp.StartUtc; EndUtc = $sp.EndUtc; Samples = $sp.Samples; DurationSec = $sec; Source = 'inferred-from-engine-load' }
    }

    # Arms, split at the first sustained change in NO's own window set.
    $ui = Get-NoUiChangePoints -Samples $Samples
    $summary.NoUiBaselineTitles = $ui.BaselineTitles
    $summary.NoUiChanges = $ui.Changes
    $splitIndex = $ui.FirstChangeIndex
    if ($null -ne $splitIndex) {
        $summary.SessionStartUtc = $ui.FirstChangeUtc
        $summary.SessionStartSource = 'no-window-set-change'
    }

    $idleSamples = @()
    $sessionSamples = @()
    if ($null -ne $splitIndex -and $splitIndex -gt 0) {
        $idleSamples = @($Samples[0..($splitIndex - 1)])
        $sessionSamples = @($Samples[$splitIndex..($Samples.Count - 1)])
    }

    $idleSec = $null
    if ($idleSamples.Count -ge 2) { try { $idleSec = [math]::Round(([datetime]$idleSamples[$idleSamples.Count - 1].AtUtc - [datetime]$idleSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $sessionSec = $null
    if ($sessionSamples.Count -ge 2) { try { $sessionSec = [math]::Round(([datetime]$sessionSamples[$sessionSamples.Count - 1].AtUtc - [datetime]$sessionSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $summary.ArmDurationSec.Idle = $idleSec
    $summary.ArmDurationSec.Session = $sessionSec

    $wholeSec = 0.0
    if ($null -ne $summary.DurationSec) { $wholeSec = [double]$summary.DurationSec }
    $idleSecArg = 0.0
    if ($null -ne $idleSec) { $idleSecArg = [double]$idleSec }
    $sessionSecArg = 0.0
    if ($null -ne $sessionSec) { $sessionSecArg = [double]$sessionSec }

    $summary.Surfaces = Get-GfxRoleAggregate -Samples $Samples -DurationSec $wholeSec
    $summary.Arms.Idle = Get-GfxRoleAggregate -Samples $idleSamples -DurationSec $idleSecArg
    $summary.Arms.Session = Get-GfxRoleAggregate -Samples $sessionSamples -DurationSec $sessionSecArg

    foreach ($sessRole in @($summary.Arms.Session | Where-Object { $null -ne $_ })) {
        $idleRole = @($summary.Arms.Idle | Where-Object { $_.Role -eq $sessRole.Role }) | Select-Object -First 1
        foreach ($eng in @($sessRole.Engines.Keys)) {
            $sessMean = $sessRole.Engines[$eng].Mean
            $idleMean = $null
            if ($idleRole -and $idleRole.Engines.ContainsKey($eng)) { $idleMean = $idleRole.Engines[$eng].Mean }
            $delta = $null
            if ($null -ne $sessMean -and $null -ne $idleMean) { $delta = [math]::Round($sessMean - $idleMean, 3) }
            $summary.Deltas += @{ Role = $sessRole.Role; Engine = $eng; IdleMean = $idleMean; SessionMean = $sessMean; DeltaMean = $delta }
        }
    }

    # A host or GPU pid changing mid-run means the process was replaced --
    # the pane-goes-blank failure class. Report the identities, not a count.
    foreach ($surf in @($summary.Surfaces)) {
        if (@($surf.HostPids).Count -gt 1 -or @($surf.GpuPids).Count -gt 1) {
            $summary.Restarts += @{ Role = $surf.Role; HostPids = $surf.HostPids; GpuPids = $surf.GpuPids }
        }
    }

    return $summary
}

function Get-GraphicsBenchFindings {
    <#
    .SYNOPSIS
        Curated findings shown to the tech at Stop. Max 3, ranked, using the
        Get-BluetoothFindings contract verbatim:
        @{ Id, Title, Result, AppliesTo, Evidence[], ActionHint }.
    .DESCRIPTION
        Results come from the sealed outcome taxonomy (FAIL/WARN/PASS/SKIP).
        Every finding is derived from a measured field; nothing is asserted
        that the summary does not carry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Summary,
        [int]$MemoryGrowthWarnMB = 250,
        [double]$MemoryGrowthWarnMBPerMin = 15
    )

    $candidates = @()

    foreach ($restart in @($Summary.Restarts)) {
        $candidates += @{
            Rank       = 1
            Id         = 'GFX-HOST-RESTART'
            Title      = "$($restart.Role) surface process was replaced mid-run"
            Result     = 'FAIL'
            AppliesTo  = 'WebView2 host'
            Evidence   = @(
                "Role '$($restart.Role)' was served by host PIDs $($restart.HostPids -join ', ') and GPU PIDs $($restart.GpuPids -join ', ') during one run.",
                'A replaced host or GPU process is the pane-goes-blank failure class: the surface is recreated and the visible pane can stay black with nothing logged.'
            )
            ActionHint = 'Collect this package and check the WebView2 crashpad dumps under the host user-data-dir before the next NO launch clears it.'
        }
    }

    if ($Summary.CountersOk -eq $false) {
        $reason = $Summary.CounterReason
        if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'GPU engine counters were not readable on this system.' }
        $candidates += @{
            Rank       = 2
            Id         = 'GFX-COUNTERS-UNAVAILABLE'
            Title      = 'GPU engine load was not measured'
            Result     = 'SKIP'
            AppliesTo  = 'Measurement'
            Evidence   = @($reason, 'GPU load is reported as absent, not as 0% -- this run cannot answer questions about GPU cost.')
            ActionHint = 'Process CPU, memory and surface lifetime in this package are still valid; re-run on a box with the GPU Engine counter set for GPU numbers.'
        }
    }

    foreach ($surf in @($Summary.Surfaces)) {
        if ($null -ne $surf.WorkingSetGrowthMB -and $surf.WorkingSetGrowthMB -ge $MemoryGrowthWarnMB) {
            $candidates += @{
                Rank       = 3
                Id         = 'GFX-MEMORY-GROWTH'
                Title      = "$($surf.Role) host tree grew $([int]$surf.WorkingSetGrowthMB) MB during the run"
                Result     = 'WARN'
                AppliesTo  = 'Memory'
                Evidence   = @(
                    "Working set went from $($surf.WorkingSetFirstMB) MB to $($surf.WorkingSetLastMB) MB over $($Summary.DurationSec) s ($($surf.WorkingSetGrowthMBPerMin) MB/min).",
                    "Host PIDs $($surf.HostPids -join ', ')."
                )
                ActionHint = 'Re-run for a full-length session on the same box; sustained growth at this rate is the 8 GB-machine failure mode.'
            }
        }
    }

    $videoSurfaces = @($Summary.Surfaces | Where-Object { $_.Role -eq 'VideoJs' })
    foreach ($surf in $videoSurfaces) {
        $decodeMax = $null
        if ($surf.Engines -and $surf.Engines.ContainsKey('VideoDecode')) { $decodeMax = $surf.Engines['VideoDecode'].Max }
        $mediaSpans = @($Summary.Spans | Where-Object { $_.State -eq 'Media' -or $_.State -eq 'Both' })
        if ($mediaSpans.Count -gt 0 -and $null -ne $decodeMax -and $decodeMax -le 0) {
            $candidates += @{
                Rank       = 3
                Id         = 'GFX-NO-HARDWARE-DECODE'
                Title      = 'Media played without any hardware video decode'
                Result     = 'WARN'
                AppliesTo  = 'Media path'
                Evidence   = @(
                    "The video.js surface was active for $($mediaSpans.Count) span(s) but its VideoDecode engine never rose above 0%.",
                    'On a healthy 4.0.0.7 box H.264 MP4 decodes in hardware; software decode costs CPU that competes with the session audio.'
                )
                ActionHint = 'Check the graphics driver version in this package against a known-good box with the same adapter.'
            }
        }
    }

    $unresolved = @($Summary.Surfaces | Where-Object { $_.RoleSource -eq 'unresolved' })
    if ($unresolved.Count -gt 0) {
        $candidates += @{
            Rank       = 4
            Id         = 'GFX-SURFACE-UNRESOLVED'
            Title      = "$($unresolved.Count) WebView2 surface(s) could not be identified"
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                'A WebView2 host was present but carried no recognised document title, so its numbers are recorded against role Unknown rather than guessed.',
                "Host PIDs: $(@($unresolved | ForEach-Object { $_.HostPids -join ',' }) -join '; ')."
            )
            ActionHint = 'Confirm the visualizer and media panes were both open; a host with no visual window yet is normal in the first seconds after launch.'
        }
    }

    if ($candidates.Count -eq 0) {
        $candidates += @{
            Rank       = 9
            Id         = 'GFX-RUN-CLEAN'
            Title      = 'Graphics run completed with no anomalies detected'
            Result     = 'PASS'
            AppliesTo  = 'Graphics'
            Evidence   = @(
                "$($Summary.SampleCount) samples over $($Summary.DurationSec) s.",
                'No host restart, no counter loss, no memory growth above threshold.'
            )
            ActionHint = 'Upload the package so this box joins the comparison corpus.'
        }
    }

    # Sort-Object cannot order [hashtable] rows by a key, so the rank walk is
    # explicit. Lower rank = more severe = shown first; the list is capped at
    # three so a tech reads findings rather than a log.
    $ordered = @()
    foreach ($rank in 1..9) {
        foreach ($c in $candidates) {
            if ([int]$c.Rank -ne $rank) { continue }
            $ordered += @{ Id = $c.Id; Title = $c.Title; Result = $c.Result; AppliesTo = $c.AppliesTo; Evidence = $c.Evidence; ActionHint = $c.ActionHint }
            if ($ordered.Count -ge 3) { break }
        }
        if ($ordered.Count -ge 3) { break }
    }
    return ,$ordered
}

function Test-GraphicsBenchPreconditions {
    <#
    .SYNOPSIS
        Checks everything that would make a run worthless, before it starts.
    .OUTPUTS
        Hashtable: Ok, Blocking[], Warnings[], Facts.
    #>
    [CmdletBinding()]
    param()

    $blocking = @()
    $warnings = @()
    $facts = @{}

    $counters = Test-GfxGpuCounterSupport
    $facts.GpuCounters = $counters
    if (-not $counters.EngineAvailable) { $warnings += "GPU engine counters unavailable: $($counters.Reason)" }

    if (-not (Initialize-GfxWindowScan)) {
        $blocking += 'The inline window-scan helper failed to compile; surfaces cannot be identified.'
    }

    $runtimeExe = 'C:\ProgramData\NO WebView2 Runtime\runtime\x64\msedgewebview2.exe'
    if (Test-Path -LiteralPath $runtimeExe) {
        $facts.WebView2RuntimePresent = $true
    } else {
        $facts.WebView2RuntimePresent = $false
        $warnings += "NO's fixed-version WebView2 runtime was not found at $runtimeExe -- the panes cannot render without it."
    }

    $noProc = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue)
    $facts.NoRunning = ($noProc.Count -gt 0)
    $facts.NoProcessCount = $noProc.Count
    if ($noProc.Count -gt 1) { $warnings += "$($noProc.Count) NO.exe processes are running; the sampler follows the earliest-started one." }

    try {
        $drive = Get-PSDrive -Name ((Get-Item $env:TEMP).PSDrive.Name) -ErrorAction Stop
        $freeGB = [math]::Round($drive.Free / 1GB, 1)
        $facts.TempFreeGB = $freeGB
        if ($freeGB -lt 1) { $blocking += "Less than 1 GB free on the temp volume ($freeGB GB); the run package cannot be written safely." }
    } catch { }

    return @{ Ok = ($blocking.Count -eq 0); Blocking = $blocking; Warnings = $warnings; Facts = $facts }
}

# ---------------------------------------------------------------------------
# Run folder, events, package, and the ONE report renderer
# ---------------------------------------------------------------------------
#
# The console harness and the app's Graphics tab are two live views of one run.
# That is exactly the shape this repo's channel-mismatch bug class takes, so the
# run folder, the event writer, the package writer and the REPORT TEXT all live
# here and both surfaces call them. Each surface owns only how it paints a line,
# never what the line says.

function New-GraphicsBenchRunFolder {
    <#
    .SYNOPSIS
        Creates one run folder and returns its paths.
    .OUTPUTS
        Hashtable: RunId, RunStamp, RunFolder, OutputRoot, EventsPath,
        SessionPath, ManifestPath.
    #>
    [CmdletBinding()]
    param([string]$OutputRoot)

    if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
        $OutputRoot = Join-Path $env:LOCALAPPDATA 'Temp\WinConfig-GraphicsBench'
    }
    $runStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $runId = ([guid]::NewGuid().ToString('N').Substring(0, 8)).ToUpper()
    $runFolder = Join-Path $OutputRoot "$runStamp-$runId"
    $null = New-Item -ItemType Directory -Path $runFolder -Force

    return @{
        RunId        = $runId
        RunStamp     = $runStamp
        OutputRoot   = $OutputRoot
        RunFolder    = $runFolder
        EventsPath   = (Join-Path $runFolder 'events.jsonl')
        SessionPath  = (Join-Path $runFolder 'bench-session.json')
        ManifestPath = (Join-Path $runFolder 'manifest.json')
    }
}

function Write-GraphicsBenchEvent {
    <#
    .SYNOPSIS
        Appends one record to events.jsonl.
    .DESCRIPTION
        UTF-8 without BOM, one compact object per line. The events stream is
        read UTF-8 first by every consumer in this repo, so it is written that
        way explicitly rather than left to the caller's default encoding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EventsPath,
        [Parameter(Mandatory)][string]$Kind,
        [hashtable]$Data = @{}
    )

    $rec = @{ kind = $Kind; atUtc = [datetime]::UtcNow.ToString('o') }
    foreach ($k in $Data.Keys) { $rec[$k] = $Data[$k] }
    $line = ($rec | ConvertTo-Json -Depth 8 -Compress)
    [System.IO.File]::AppendAllText($EventsPath, $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Save-GraphicsBenchRun {
    <#
    .SYNOPSIS
        Writes bench-session.json + manifest.json (and optionally a ZIP).
    .OUTPUTS
        Hashtable: SessionPath, ManifestPath, ZipPath (null when not written),
        ZipError.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Run,
        [Parameter(Mandatory)][hashtable]$Session,
        [switch]$NoZip
    )

    $Session | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Run.SessionPath -Encoding UTF8

    $manifest = @{
        toolId        = 'graphics-bench'
        runId         = $Run.RunId
        runMode       = $Session.runMode
        createdUtc    = [datetime]::UtcNow.ToString('o')
        artifacts     = @('events.jsonl', 'bench-session.json')
        sampleCount   = $Session.summary.SampleCount
        durationSec   = $Session.summary.DurationSec
        countersOk    = $Session.summary.CountersOk
        schemaVersion = 1
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Run.ManifestPath -Encoding UTF8

    $zipPath = $null
    $zipError = $null
    if (-not $NoZip) {
        try {
            $zipPath = Join-Path $Run.OutputRoot ("graphics-bench-{0}-{1}.zip" -f $Run.RunStamp, $Run.RunId)
            Compress-Archive -Path (Join-Path $Run.RunFolder '*') -DestinationPath $zipPath -Force
        } catch {
            $zipError = $_.Exception.Message
            $zipPath = $null
        }
    }

    return @{ SessionPath = $Run.SessionPath; ManifestPath = $Run.ManifestPath; ZipPath = $zipPath; ZipError = $zipError }
}

function Format-GraphicsValue {
    <#
    .SYNOPSIS
        Renders one measurement for display.
    .DESCRIPTION
        THE EM-DASH RULE, in one place. $null renders as an em dash; a measured
        zero renders as 0. Every surface calls this, so "not measured" can never
        become "measured zero" on one screen and not the other.
    #>
    [CmdletBinding()]
    param($Value, [string]$Suffix = '', [int]$Decimals = 1)

    if ($null -eq $Value) { return [string][char]0x2014 }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return [string][char]0x2014 }
        return $Value
    }
    try { return ('{0}{1}' -f [math]::Round([double]$Value, $Decimals), $Suffix) } catch { return [string]$Value }
}

function Format-GraphicsDuration {
    [CmdletBinding()]
    param($Seconds)
    if ($null -eq $Seconds) { return [string][char]0x2014 }
    $ts = [TimeSpan]::FromSeconds([math]::Max(0, [double]$Seconds))
    if ($ts.TotalHours -ge 1) { return ('{0}h{1:00}m{2:00}s' -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds) }
    if ($ts.TotalMinutes -ge 1) { return ('{0}m{1:00}s' -f [int]$ts.TotalMinutes, $ts.Seconds) }
    return ('{0}s' -f [int]$ts.TotalSeconds)
}

function Format-GraphicsInventoryReport {
    <#
    .SYNOPSIS
        The System / Graphics panels as renderable records.
    .OUTPUTS
        Array of @{ Level; Text; NoPrefix } where Level is one of the sealed
        GUI diagnostic levels (OK/WARN/FAIL/INFO/STEP/ACTION/DIM).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Inventory,
        [hashtable]$Nomp
    )

    $r = @()
    $r += @{ Level = 'STEP'; Text = 'SYSTEM'; NoPrefix = $true }
    $machine = ("$($Inventory.System.Manufacturer) $($Inventory.System.Model)").Trim()
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'Machine', (Format-GraphicsValue $machine)); NoPrefix = $true }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'CPU', (Format-GraphicsValue $Inventory.System.Cpu)); NoPrefix = $true }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1} GB RAM  |  {2} logical cores" -f 'Memory', (Format-GraphicsValue $Inventory.System.TotalRamGB), (Format-GraphicsValue $Inventory.System.LogicalCores)); NoPrefix = $true }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1} (build {2})" -f 'Windows', (Format-GraphicsValue $Inventory.System.OsCaption), (Format-GraphicsValue $Inventory.System.OsBuild)); NoPrefix = $true }

    $onBattery = ($Inventory.Power.HasBattery -and $Inventory.Power.OnBattery)
    $powerText = if (-not $Inventory.Power.HasBattery) { 'desktop / no battery' } elseif ($onBattery) { 'ON BATTERY -- not a comparable run' } else { 'on AC' }
    $r += @{ Level = $(if ($onBattery) { 'WARN' } else { 'INFO' }); Text = ("  {0,-14}{1}" -f 'Power', $powerText); NoPrefix = $true }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}  (PID {2})" -f 'NO.exe', (Format-GraphicsValue $Inventory.No.Version), (Format-GraphicsValue $Inventory.No.Pid)); NoPrefix = $true }

    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    $r += @{ Level = 'STEP'; Text = 'GRAPHICS'; NoPrefix = $true }
    foreach ($a in @($Inventory.Adapters)) {
        $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'Adapter', (Format-GraphicsValue $a.Name)); NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  |  driver {2} ({3})  |  {4}" -f '', (Format-GraphicsValue $a.VenDev), (Format-GraphicsValue $a.DriverVersion), (Format-GraphicsValue $a.DriverDate), (Format-GraphicsValue $a.CurrentMode)); NoPrefix = $true }
    }
    if (@($Inventory.Adapters).Count -eq 0) {
        $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'Adapter', [char]0x2014); NoPrefix = $true }
    }
    if ($Inventory.HybridGpu) {
        $r += @{ Level = 'WARN'; Text = '  HYBRID GPU: two vendors present. Which adapter each pane chose is recorded'; NoPrefix = $true }
        $r += @{ Level = 'WARN'; Text = '  as the measured LUID per surface, not inferred from the adapter list.'; NoPrefix = $true }
    }
    foreach ($d in @($Inventory.Displays)) {
        $primary = if ($d.Primary) { '  (primary)' } else { '' }
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  {2}{3}" -f 'Display', (Format-GraphicsValue $d.DeviceName), (Format-GraphicsValue $d.Bounds), $primary); NoPrefix = $true }
    }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}  (NO fixed-version runtime)" -f 'WebView2', (Format-GraphicsValue $Inventory.WebView2.Version)); NoPrefix = $true }
    if ($Nomp) {
        $nompText = if ($Nomp.Exists) { "schema only: $(@($Nomp.SchemaKeysPresent).Count) known fields declared, no values stored" } else { 'not found' }
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}" -f 'NOMP config', $nompText); NoPrefix = $true }
    }
    return ,$r
}

function Format-GraphicsBenchReport {
    <#
    .SYNOPSIS
        The whole end-of-run report as renderable records. THE one renderer.
    .DESCRIPTION
        Returns @{ Level; Text; NoPrefix } rows. The console harness maps Level
        to a console colour and the app's Graphics tab maps it to
        Write-WinConfigGuiDiagnostic; neither decides what a row SAYS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Summary,
        [array]$Findings = @(),
        [hashtable]$MediaFile
    )

    $dash = [string][char]0x2014
    $r = @()

    $r += @{ Level = 'STEP'; Text = ("RESULTS   {0}   {1} samples" -f (Format-GraphicsDuration $Summary.DurationSec), $Summary.SampleCount); NoPrefix = $true }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }

    # --- the headline: session minus this box's own idle arm ---
    $r += @{ Level = 'STEP'; Text = 'WHAT THE SESSION COST'; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = '  Session mean minus this box own idle baseline, measured minutes earlier on the'; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = '  same hardware, driver and NO launch. Butterchurn draws even when NO is idle,'; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = '  so the absolute percentage answers nothing on its own -- the delta does.'; NoPrefix = $true }

    if ($Summary.SessionStartSource -eq 'none-detected') {
        $r += @{ Level = 'WARN'; Text = '  No session start was detected: NO window set never changed for long enough,'; NoPrefix = $true }
        $r += @{ Level = 'WARN'; Text = '  so this run has no idle/session split and no deltas. The whole-run numbers'; NoPrefix = $true }
        $r += @{ Level = 'WARN'; Text = '  below are still valid. Re-run and start the session while the tool is up.'; NoPrefix = $true }
    } else {
        $r += @{ Level = 'DIM'; Text = ("  {0,-13}{1,-17}{2,10}{3,12}{4,12}" -f 'surface', 'engine', 'idle', 'session', 'delta'); NoPrefix = $true }
        if (@($Summary.Deltas).Count -eq 0) {
            $r += @{ Level = 'INFO'; Text = "  $dash"; NoPrefix = $true }
        }
        foreach ($d in @($Summary.Deltas | Sort-Object Role, Engine)) {
            $deltaText = if ($null -eq $d.DeltaMean) { $dash } else { ('{0}{1}%' -f $(if ($d.DeltaMean -ge 0) { '+' } else { '' }), [math]::Round($d.DeltaMean, 1)) }
            $level = if ($null -eq $d.DeltaMean) { 'DIM' } elseif ($d.DeltaMean -ge 1) { 'WARN' } else { 'INFO' }
            $r += @{ Level = $level; Text = ("  {0,-13}{1,-17}{2,10}{3,12}{4,12}" -f $d.Role, $d.Engine, (Format-GraphicsValue $d.IdleMean '%'), (Format-GraphicsValue $d.SessionMean '%'), $deltaText); NoPrefix = $true }
        }
        $split = $dash
        try { $split = ([datetime]$Summary.SessionStartUtc).ToLocalTime().ToString('HH:mm:ss') } catch { }
        $r += @{ Level = 'DIM'; Text = ("  idle arm {0}  |  session arm {1}  |  split at {2} ({3})" -f (Format-GraphicsDuration $Summary.ArmDurationSec.Idle), (Format-GraphicsDuration $Summary.ArmDurationSec.Session), $split, $Summary.SessionStartSource); NoPrefix = $true }
        $addedTitles = @()
        foreach ($c in @($Summary.NoUiChanges)) { $addedTitles += @($c.Added) }
        if ($addedTitles.Count -gt 0) {
            $r += @{ Level = 'DIM'; Text = ("  NO opened: {0}" -f (@($addedTitles | Sort-Object -Unique) -join ', ')); NoPrefix = $true }
        }
    }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }

    # --- media file, when the run could be labelled ---
    if ($MediaFile) {
        $mediaText = if ($MediaFile.file) { "$(Split-Path $MediaFile.file -Leaf)" } else { 'Unknown -- no media file was opened under the watched root' }
        $r += @{ Level = 'INFO'; Text = ("  Media opened by NO: {0}" -f $mediaText); NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = ("  watched root {0} ({1})" -f (Format-GraphicsValue $MediaFile.root), (Format-GraphicsValue $MediaFile.rootSource)); NoPrefix = $true }
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    }

    # --- time in each state ---
    $r += @{ Level = 'STEP'; Text = 'TIME IN EACH STATE'; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = '  Quiet / VisualizerOnly / MediaOnly / Both, inferred from GPU engine load.'; NoPrefix = $true }
    $byState = @{}
    foreach ($sp in @($Summary.Spans)) {
        if (-not $byState.ContainsKey($sp.State)) { $byState[$sp.State] = 0.0 }
        $byState[$sp.State] += [double]$sp.DurationSec
    }
    if ($byState.Keys.Count -eq 0) { $r += @{ Level = 'INFO'; Text = "  $dash"; NoPrefix = $true } }
    foreach ($st in @($byState.Keys | Sort-Object)) {
        $pct = $null
        if ($Summary.DurationSec -gt 0) { $pct = [math]::Round(100.0 * $byState[$st] / $Summary.DurationSec, 1) }
        $r += @{ Level = 'INFO'; Text = ("  {0,-18}{1,-10}{2} of the run" -f $st, (Format-GraphicsDuration $byState[$st]), (Format-GraphicsValue $pct '%')); NoPrefix = $true }
    }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }

    # --- per surface, whole run ---
    $r += @{ Level = 'STEP'; Text = 'PER SURFACE, WHOLE RUN   (GPU engine load, percent of the adapter)'; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = ("  {0,-13}{1,-13}{2,-17}{3,9}{4,9}{5,9}{6,9}" -f 'surface', 'role source', 'engine', 'mean', 'p50', 'p95', 'max'); NoPrefix = $true }
    if (@($Summary.Surfaces).Count -eq 0) {
        $r += @{ Level = 'WARN'; Text = '  no WebView2 surface was seen during the run'; NoPrefix = $true }
    }
    foreach ($surf in @($Summary.Surfaces)) {
        $printed = $false
        foreach ($eng in @('3D', 'VideoDecode', 'VideoProcessing')) {
            $st = $null
            if ($surf.Engines -and $surf.Engines.ContainsKey($eng)) { $st = $surf.Engines[$eng] }
            if ($null -eq $st) { continue }
            $label = ''
            $src = ''
            if (-not $printed) { $label = $surf.Role; $src = $surf.RoleSource }
            $r += @{ Level = 'INFO'; Text = ("  {0,-13}{1,-13}{2,-17}{3,9}{4,9}{5,9}{6,9}" -f $label, $src, $eng, (Format-GraphicsValue $st.Mean), (Format-GraphicsValue $st.P50), (Format-GraphicsValue $st.P95), (Format-GraphicsValue $st.Max)); NoPrefix = $true }
            $printed = $true
        }
        if (-not $printed) {
            $r += @{ Level = 'WARN'; Text = ("  {0,-13}{1,-13}{2,-17}{3,9}" -f $surf.Role, $surf.RoleSource, 'no GPU counters', $dash); NoPrefix = $true }
        }
        $luidText = if (@($surf.AdapterLuids).Count -gt 0) { @($surf.AdapterLuids) -join ', ' } else { $dash }
        $presence = if ($null -eq $surf.PresenceRatio) { $dash } else { "$([math]::Round(100 * $surf.PresenceRatio, 0))%" }
        $r += @{ Level = 'DIM'; Text = ("  {0,-13}host PID(s) {1} | GPU PID(s) {2} | adapter LUID {3} | present in {4} of samples" -f '', ($surf.HostPids -join ', '), ($surf.GpuPids -join ', '), $luidText, $presence); NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = ("  {0,-13}CPU mean {1} | working set {2} -> {3} MB (growth {4} MB, {5} MB/min) | VRAM mean {6} MB" -f '', (Format-GraphicsValue $surf.Cpu.Mean '%'), (Format-GraphicsValue $surf.WorkingSetFirstMB), (Format-GraphicsValue $surf.WorkingSetLastMB), (Format-GraphicsValue $surf.WorkingSetGrowthMB), (Format-GraphicsValue $surf.WorkingSetGrowthMBPerMin), (Format-GraphicsValue $surf.GpuMemoryMB.Mean)); NoPrefix = $true }
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    }

    # --- operator markers ---
    if (@($Summary.Markers).Count -gt 0) {
        $r += @{ Level = 'STEP'; Text = 'OPERATOR MARKERS'; NoPrefix = $true }
        foreach ($m in @($Summary.Markers)) {
            $at = $dash
            try { $at = ([datetime]$m.AtUtc).ToLocalTime().ToString('HH:mm:ss') } catch { }
            $r += @{ Level = 'DIM'; Text = ("  {0}   {1}" -f $at, $m.Text); NoPrefix = $true }
        }
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    }

    # --- findings, already capped and ranked ---
    $r += @{ Level = 'STEP'; Text = 'FINDINGS'; NoPrefix = $true }
    foreach ($f in @($Findings)) {
        $level = switch ($f.Result) { 'FAIL' { 'FAIL' } 'WARN' { 'WARN' } 'PASS' { 'OK' } 'SKIP' { 'DIM' } default { 'INFO' } }
        $r += @{ Level = $level; Text = ("  [{0}] {1}" -f $f.Result, $f.Title); NoPrefix = $true }
        foreach ($e in @($f.Evidence)) { $r += @{ Level = 'DIM'; Text = ("         {0}" -f $e); NoPrefix = $true } }
        $r += @{ Level = 'ACTION'; Text = ("         -> {0}" -f $f.ActionHint); NoPrefix = $true }
    }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    $r += @{ Level = 'DIM'; Text = ("  Sampler cost: tick mean {0} ms, p95 {1} ms, max {2} ms." -f (Format-GraphicsValue $Summary.TickMs.Mean '' 0), (Format-GraphicsValue $Summary.TickMs.P95 '' 0), (Format-GraphicsValue $Summary.TickMs.Max '' 0)); NoPrefix = $true }

    return ,$r
}

Export-ModuleMember -Function @(
    'Assert-GfxPathAllowed'
    'Get-GfxPercentile'
    'Get-GfxStats'
    'Initialize-GfxWindowScan'
    'ConvertFrom-GfxWindowScanRows'
    'Get-GfxSurfaceRoleFromTitle'
    'Get-NoWebViewHostTree'
    'Resolve-NoWebViewSurfaces'
    'Test-GfxGpuCounterSupport'
    'ConvertFrom-GfxEngineInstanceName'
    'Start-GraphicsSampler'
    'Receive-GraphicsSamples'
    'Stop-GraphicsSampler'
    'Get-GraphicsInventory'
    'Get-NompConfigSnapshot'
    'Get-NoOpenedMediaFile'
    'Get-GraphicsActivityState'
    'Get-GraphicsActivitySpans'
    'Get-NoUiChangePoints'
    'Get-GfxRoleAggregate'
    'Get-GraphicsBenchSessionSummary'
    'Get-GraphicsBenchFindings'
    'Test-GraphicsBenchPreconditions'
    'New-GraphicsBenchRunFolder'
    'Write-GraphicsBenchEvent'
    'Save-GraphicsBenchRun'
    'Format-GraphicsValue'
    'Format-GraphicsDuration'
    'Format-GraphicsInventoryReport'
    'Format-GraphicsBenchReport'
)

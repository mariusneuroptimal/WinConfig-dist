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

# Engine-load floors that separate "this surface is drawing" from "this
# surface is present but quiet". ONE definition, read by every classifier and
# published to the two harnesses through Get-GraphicsBenchFloors -- a floor
# that lives in four places is a floor that will one day differ between the
# live screen and the report.
#
# Measured, not chosen: butterchurn's unconditional render loop sits at
# 7.6-10.6% 3D on the boxes captured so far, and video.js hardware decode at
# 2.7-2.9% while playing, so both floors sit well under a real reading and
# well over counter noise.
$script:GfxVisualizerFloorPercent = 1.0
$script:GfxMediaFloorPercent = 0.3

# WHY 'APPLICATION FULL SCREEN' IS NEVER REPORTED AS VERIFIED.
#
# A window's placement says how big it is, not which control made it that big.
# A window maximized from its title bar and one put full screen by
# NeurOptimal's own control can both read showCmd 3, and no field capture has
# yet established what NeurOptimal's control actually leaves behind. The
# measurement this bench depends on is WINDOW AREA, which is read directly; the
# control that produced it is a separate claim, and it stays unverified rather
# than being inferred from a show state that does not carry it.
#
# ONE STRING, so the window, the report and the package cannot give three
# different accounts of the same gap.
$script:GfxAppFullScreenReason = "a window's placement does not record which control set it, so whether this is NeurOptimal's own full-screen state is not established"

# NEUROPTIMAL'S MONITOR PICKER, by the title of its own window.
#
# Captured 2026-09-18 with the dialog on screen:
#
#   hwnd 722276  LVDChild  'Zengar Shared_lib.lvlib:Select Display Monitor--dialog.vi'
#
# It is MODAL and it BLOCKS: pressing the separate visualizer full-screen
# button opens it, and the visuals do not move until a monitor is chosen and OK
# is pressed. In that capture butterchurn was still hosted by NeurOptimal's own
# panel while the dialog was up -- the detach had not happened yet.
#
# That makes the dialog an exact, passive bracket for the manual transition: it
# appears when the operator starts and is gone once they have chosen. Matched on
# the distinctive tail rather than the whole VI path, which carries a library
# prefix that is not ours to depend on -- the same shape as the
# 'Session Complete--dialog.vi' title this module already reads.
$script:GfxMonitorPickerPattern = 'Select Display Monitor--dialog\.vi'

# WHY 'THE VISUALS WERE DETACHED' IS NEVER REPORTED AS VERIFIED EITHER.
#
# Measured on NO 4.0.0.9, 2026-09-18, with nobody touching the visualizer
# control: before the session butterchurn and video.js both hung under window
# 461894; during it butterchurn moved to 397666 -- the main NeurOptimal window
# -- while video.js stayed behind. NO relocates its panes between top-level
# LabVIEW windows as a matter of course, so "the visualizer is in a different
# window from the other pane" described 13 of 13 samples of an ordinary
# session. A detector that fires on every clean run is worse than none.
#
# The window handles are recorded so the first capture taken WITH the separate
# visualizer full-screen button pressed can be compared against them. Until
# then this stays unverified, and the SCREEN -- which was never the doubtful
# part -- is what gets scored.
$script:GfxVisualizerAttachmentReason = "NeurOptimal moves its panes between windows on its own, so the window hosting the visuals does not establish whether the separate visualizer control was used"

# Audio playback has no decode engine to show up on. What it DOES show, on
# run D5E1D5C7 (MMEVOLD_06, NO 4.0.0.9, 33-minute .m4a session): the video.js
# surface's 3D engine sat at 0% through the idle arm and 1.1-1.3% for every
# minute of playback -- the player's own control bar and progress redraw. That
# step is the only passive graphics signal an audio-only session leaves, so it
# is read against its own floor, well under the reading and well over noise.
$script:GfxAudioUiFloorPercent = 0.5

# How long the idle arm should be before a session starts. Every number the
# tool reports is a difference against this stretch, so a short one makes the
# deltas noisy. Sixty seconds is sixty samples at the 1 s tick; the coverage
# line counts up to it and then SAYS 'Baseline collected', so the operator is
# never left guessing when "about a minute" has passed -- and never has to
# read a colour to know, which a screenshot, a monochrome remote session or a
# colour vision deficiency each take away.
$script:GfxIdleFloorSec = 60

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
    // text, placement (rect, show state, style bits, nearest monitor). Never
    // window content, never child controls of a LabVIEW front panel, never a
    // pixel. No window is created, moved, shown, hidden, activated or messaged.
    public static class GfxWindowScan {
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc f, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumWindowsProc f, IntPtr l);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder t, int m);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder t, int m);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")] static extern bool GetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT p);
        [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
        // MONITORINFOEX, not MONITORINFO: szDevice is the only reading that
        // says WHICH display a window is on. Matching its rect against the
        // display list instead would compare two APIs' coordinates, which a
        // mixed-DPI desktop can make disagree.
        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetMonitorInfoW")] static extern bool GetMonitorInfoEx(IntPtr m, ref MONITORINFOEX i);
        // GetWindowLongW is present on both bitnesses and the style word is
        // 32 bits wide, so the Ptr variant is not needed.
        [DllImport("user32.dll", EntryPoint = "GetWindowLongW")] static extern int GetWindowLongW(IntPtr h, int i);
        delegate bool EnumWindowsProc(IntPtr h, IntPtr l);

        [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
        [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
        [StructLayout(LayoutKind.Sequential)] public struct WINDOWPLACEMENT { public uint length, flags, showCmd; public POINT ptMin, ptMax; public RECT rcNormal; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct MONITORINFOEX { public uint cbSize; public RECT rcMonitor, rcWork; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice; }

        static string Title(IntPtr h) { System.Text.StringBuilder sb = new System.Text.StringBuilder(512); GetWindowTextW(h, sb, 512); return sb.ToString(); }
        static string Cls(IntPtr h) { System.Text.StringBuilder sb = new System.Text.StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString(); }
        static uint Pid(IntPtr h) { uint p; GetWindowThreadProcessId(h, out p); return p; }
        static string Rect(RECT r) { return r.L + "," + r.T + "," + r.R + "," + r.B; }

        // Placement of one top-level window, as one row. Every field is a
        // read; a failed read leaves its field empty rather than zero.
        static string Geom(IntPtr h, bool hasSurface) {
            string show = ""; string rect = ""; string mon = ""; string style = ""; string dev = "";
            try { WINDOWPLACEMENT wp = new WINDOWPLACEMENT(); wp.length = (uint)Marshal.SizeOf(typeof(WINDOWPLACEMENT)); if (GetWindowPlacement(h, ref wp)) { show = wp.showCmd.ToString(); } } catch { }
            try { RECT r; if (GetWindowRect(h, out r)) { rect = Rect(r); } } catch { }
            try { IntPtr m = MonitorFromWindow(h, 2 /* MONITOR_DEFAULTTONEAREST */); MONITORINFOEX mi = new MONITORINFOEX(); mi.cbSize = (uint)Marshal.SizeOf(typeof(MONITORINFOEX)); mi.szDevice = ""; if (m != IntPtr.Zero && GetMonitorInfoEx(m, ref mi)) { mon = Rect(mi.rcMonitor); dev = mi.szDevice == null ? "" : mi.szDevice.Replace("|", "/"); } } catch { }
            try { style = GetWindowLongW(h, -16 /* GWL_STYLE */).ToString("X8"); } catch { }
            return "NOGEOM|" + h.ToInt64() + "|" + show + "|" + rect + "|" + mon + "|" + style + "|" + (hasSurface ? "1" : "0") + "|" + dev;
        }

        // One pass over the host process's top-level windows plus their
        // descendants. Rows are pipe-delimited; the caller parses.
        //
        //   NOWIN|<hwnd>|<visible 0/1>|<class>|<title>
        //       every top-level window owned by hostPid
        //   SURFACE|<owningPid>|<hwnd>|<title>
        //       a Chrome_WidgetWin_1 descendant owned by ANOTHER process --
        //       this is the WebView2 visual host, and its title IS the
        //       rendered document's title
        //   SURFACETOP|<surfaceHwnd>|<topLevelHwnd>
        //       which of NO's own top-level windows that surface hangs under.
        //       A SEPARATE ROW KIND rather than a field on SURFACE, whose last
        //       field is the title and cannot have anything appended after it.
        //       This is what answers "is the visualizer on another screen?" --
        //       the surface has no window rect of its own, its host window has.
        //   D3DWIN|<owningPid>
        //       an "Intermediate D3D Window" descendant -- the compositing
        //       GPU process, corroborating process parentage
        //   NOGEOM|<hwnd>|<showCmd>|<l,t,r,b>|<monitor l,t,r,b>|<style hex>|<hasSurface 0/1>|<monitor device>
        //       placement of every VISIBLE top-level window owned by hostPid;
        //       hasSurface says a WebView2 visual host lives under it, and the
        //       monitor device (\\.\DISPLAY1) says which screen it is on. A
        //       separate row kind so the NOWIN contract is untouched; the
        //       device field was appended last so a parser written against the
        //       seven-field row still reads every field it knew.
        public static string[] Scan(int hostPid) {
            List<string> rows = new List<string>();
            EnumWindows(delegate(IntPtr top, IntPtr l) {
                if (Pid(top) != (uint)hostPid) { return true; }
                bool visible = IsWindowVisible(top);
                bool hasSurface = false;
                rows.Add("NOWIN|" + top.ToInt64() + "|" + (visible ? "1" : "0") + "|" + Cls(top) + "|" + Title(top));
                EnumChildWindows(top, delegate(IntPtr c, IntPtr l2) {
                    uint cp = Pid(c);
                    if (cp == (uint)hostPid) { return true; }
                    string cls = Cls(c);
                    if (cls == "Chrome_WidgetWin_1") { hasSurface = true; rows.Add("SURFACE|" + cp + "|" + c.ToInt64() + "|" + Title(c)); rows.Add("SURFACETOP|" + c.ToInt64() + "|" + top.ToInt64()); }
                    else if (cls == "Intermediate D3D Window") { rows.Add("D3DWIN|" + cp); }
                    return true;
                }, IntPtr.Zero);
                if (visible) { rows.Add(Geom(top, hasSurface)); }
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
        Hashtable: Surfaces (HostPid/Hwnd/DocumentTitle/Role/RoleSource/
        TopHwnd), D3DPids, NoWindows (Hwnd/Visible/Class/Title), Geometry
        (Hwnd/ShowCmd/Rect/Monitor/Style/HasSurface/MonitorDevice) for the
        visible top-level windows.
    #>
    [CmdletBinding()]
    param([string[]]$Rows)

    $surfaces = @()
    $d3d = @()
    $noWindows = @()
    $geometry = @()
    $topBySurface = @{}
    # hwnd -> @{ Title; Visible } for every top-level window, visible or not.
    # The HIDDEN ones matter: before a session the visualizer hangs under a
    # window titled 'Closed', and that is what says the pane is not on screen
    # rather than detached.
    $windowByHwnd = @{}

    # TWO PASSES. A SURFACETOP row can arrive before or after the SURFACE row
    # it belongs to depending on enumeration order, so the map is built first
    # and joined second -- a surface whose owning window is unknown keeps
    # TopHwnd $null rather than borrowing its neighbour's.
    foreach ($row in @($Rows)) {
        if ([string]::IsNullOrEmpty($row)) { continue }
        if (($row -split '\|', 2)[0] -ne 'SURFACETOP') { continue }
        $p = $row -split '\|', 3
        if ($p.Count -lt 3) { continue }
        $sh = 0L; $th = 0L
        if (-not [long]::TryParse($p[1], [ref]$sh)) { continue }
        if (-not [long]::TryParse($p[2], [ref]$th)) { continue }
        $topBySurface[$sh] = $th
    }
    foreach ($row in @($Rows)) {
        if ([string]::IsNullOrEmpty($row)) { continue }
        if (($row -split '\|', 2)[0] -ne 'NOWIN') { continue }
        $q = $row -split '\|', 5
        if ($q.Count -lt 5) { continue }
        $wh = 0L
        if (-not [long]::TryParse($q[1], [ref]$wh)) { continue }
        $windowByHwnd[$wh] = @{ Title = [string]$q[4]; Visible = ($q[2] -eq '1') }
    }

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
                $sHwnd = [long]$p[2]
                $topHwnd = $(if ($topBySurface.ContainsKey($sHwnd)) { $topBySurface[$sHwnd] } else { $null })
                $topInfo = $null
                if ($null -ne $topHwnd -and $windowByHwnd.ContainsKey([long]$topHwnd)) { $topInfo = $windowByHwnd[[long]$topHwnd] }
                $surfaces += @{
                    HostPid       = [int]$p[1]
                    Hwnd          = $sHwnd
                    TopHwnd       = $topHwnd
                    # The host window's OWN title and visibility -- what tells
                    # 'inside NeurOptimal' from 'in a window of its own' from
                    # 'not on screen'. $null when the join did not land.
                    HostWindowTitle   = $(if ($topInfo) { $topInfo.Title } else { $null })
                    HostWindowVisible = $(if ($topInfo) { $topInfo.Visible } else { $null })
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
            'NOGEOM' {
                $g = ConvertFrom-GfxGeometryRow -Row $row
                if ($g) { $geometry += $g }
            }
        }
    }

    return @{
        Surfaces  = $surfaces
        D3DPids   = @($d3d | Sort-Object -Unique)
        NoWindows = $noWindows
        Geometry  = $geometry
    }
}

function ConvertFrom-GfxGeometryRow {
    <#
    .SYNOPSIS
        Parses one NOGEOM row. Returns $null for a malformed row; a field the
        scan could not read stays $null rather than 0.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Row)

    # Split to EIGHT, accept SEVEN. The monitor-device field was appended in
    # 2026-09-18; a row recorded before it, and every fixture written against
    # the old shape, still parses and simply carries no device.
    $p = $Row -split '\|', 8
    if ($p.Count -lt 7 -or $p[0] -ne 'NOGEOM') { return $null }
    $hwnd = 0L
    if (-not [long]::TryParse($p[1], [ref]$hwnd)) { return $null }
    $rect = ConvertFrom-GfxRectText -Text $p[3]
    $mon = ConvertFrom-GfxRectText -Text $p[4]
    $show = $null
    $tmp = 0
    if ([int]::TryParse($p[2], [ref]$tmp)) { $show = $tmp }
    $style = $null
    try { if (-not [string]::IsNullOrWhiteSpace($p[5])) { $style = [Convert]::ToInt64($p[5], 16) } } catch { }
    $device = $null
    if ($p.Count -ge 8 -and -not [string]::IsNullOrWhiteSpace($p[7])) { $device = [string]$p[7] }
    return @{ Hwnd = $hwnd; ShowCmd = $show; Rect = $rect; Monitor = $mon; Style = $style; HasSurface = ($p[6] -eq '1'); MonitorDevice = $device }
}

function ConvertFrom-GfxRectText {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $q = $Text -split ','
    if ($q.Count -ne 4) { return $null }
    $v = @()
    foreach ($x in $q) { $n = 0; if (-not [int]::TryParse($x, [ref]$n)) { return $null }; $v += $n }
    return @{ L = $v[0]; T = $v[1]; R = $v[2]; B = $v[3] }
}

function Get-GfxWindowMode {
    <#
    .SYNOPSIS
        Classifies one top-level window's placement as Minimized / Maximized /
        FullScreen / Windowed, from its geometry row alone. Pure.
    .DESCRIPTION
        The GPU cost of a pane plausibly depends on how much of the screen it
        covers, and an operator can toggle that mid-session. The classes:

          Minimized   showCmd 2 (SW_SHOWMINIMIZED)
          Maximized   showCmd 3 (SW_SHOWMAXIMIZED), or a captioned window whose
                      rect exactly covers its monitor (a borderless-maximized
                      LabVIEW panel reads the same as maximized -- documented
                      edge, judged the same way)
          FullScreen  rect covers the monitor (within 1 px) and the style has
                      no WS_CAPTION -- the shape a "full screen" toggle leaves
          Windowed    anything else

        Bounds is the window's own WxH in physical pixels (the app is
        DPI-aware, and so is the monitor rect it is compared against).

        COVERSSCREEN IS A SEPARATE READING FROM MODE, and it is the one the
        test actually depends on. What confounds the measurement is window
        AREA; whether the shell calls that state "maximized" or "full screen"
        does not change a pixel of it. NeurOptimal's own pre-session full-screen
        control is a LabVIEW front panel operation whose resulting placement
        this tool has never had recorded from the field -- it may leave
        showCmd 3 (indistinguishable from the shell's Maximize) or a borderless
        rect. So the requirement is written against coverage, both readings are
        recorded, and the report NAMES the one observed. That turns an
        assumption into a field measurement instead of pinning the test to a
        guess about which of the two NO produces.

        ScreenFraction is how much of the monitor the window covers, so a
        maximized window under a taskbar (~0.95) is legible next to a genuinely
        full-screen one (1.00) without either being called the other.

        APPFULLSCREEN IS A DIFFERENT QUESTION AND IS NOT ANSWERED HERE.
        'CoversScreen' is a statement about PIXELS: this window is the size of
        that monitor. It is not a statement about which control produced that
        size. A window maximized from the title bar and a window put full screen
        by NeurOptimal's own control can both read showCmd 3, and this scan
        cannot separate them -- nothing observable in a window's placement says
        which code path set it. So AppFullScreen is 'Unverified' on every
        sample, with the reason attached, until a field package establishes what
        NeurOptimal's control actually leaves behind. Guessing it from
        showCmd 3 would be the tool reporting an inference as a reading, which
        is the one thing this module does not do.
    .OUTPUTS
        Hashtable: Mode, CoversScreen ($true/$false/$null), CoverageLabel,
        ScreenFraction, HasCaption, AppFullScreen, AppFullScreenReason,
        Bounds ('WxH'), MonitorBounds ('WxH'), MonitorDevice, Hwnd, HasSurface.
        Mode 'Unknown' and CoversScreen $null when the row carried no usable
        rect -- unread is never 'no'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Geometry)

    # THE RAW STYLE WORD IS KEPT, not just the caption bit derived from it.
    # RECORD THE IDENTIFIER, NOT THE LABEL: measured on NO 4.0.0.9, the window
    # reads 0x96070000 windowed and 0x97070000 full screen -- the ONLY
    # difference is WS_MAXIMIZE, and WS_CAPTION is absent in BOTH because
    # LVDChild never carries it. Anyone asking later which bit distinguishes
    # NeurOptimal's own full-screen control needs the whole word, not the one
    # flag this build happened to extract.
    $r = @{ Mode = 'Unknown'; CoversScreen = $null; CoverageLabel = 'not read'; ScreenFraction = $null
            HasCaption = $null; StyleHex = $null; Bounds = $null; MonitorBounds = $null
            AppFullScreen = 'Unverified'; AppFullScreenReason = $script:GfxAppFullScreenReason
            MonitorDevice = $Geometry.MonitorDevice; Hwnd = $Geometry.Hwnd; HasSurface = [bool]$Geometry.HasSurface }
    $rect = $Geometry.Rect
    $mon = $Geometry.Monitor
    if ($rect) { $r.Bounds = "$($rect.R - $rect.L)x$($rect.B - $rect.T)" }
    if ($mon) { $r.MonitorBounds = "$($mon.R - $mon.L)x$($mon.B - $mon.T)" }
    if ($null -ne $Geometry.Style) {
        $r.HasCaption = (([long]$Geometry.Style -band 0x00C00000) -eq 0x00C00000)
        $r.StyleHex = ('{0:X8}' -f [long]$Geometry.Style)
    }
    if ($rect -and $mon) {
        $monArea = [double]([math]::Max(0, $mon.R - $mon.L)) * [double]([math]::Max(0, $mon.B - $mon.T))
        if ($monArea -gt 0) {
            $winArea = [double]([math]::Max(0, $rect.R - $rect.L)) * [double]([math]::Max(0, $rect.B - $rect.T))
            $r.ScreenFraction = [math]::Round($winArea / $monArea, 3)
        }
    }

    $setCoverage = {
        param([bool]$Covers)
        $r.CoversScreen = $Covers
        $r.CoverageLabel = if ($Covers) { 'covers the whole screen' } else { 'covers part of the screen' }
    }

    if ($Geometry.ShowCmd -eq 2) { $r.Mode = 'Minimized'; & $setCoverage $false; $r.CoverageLabel = 'minimized'; return $r }
    if ($Geometry.ShowCmd -eq 3) { $r.Mode = 'Maximized'; & $setCoverage $true; return $r }
    if (-not $rect) { return $r }

    $coversMonitor = $false
    if ($mon) {
        $coversMonitor = ([math]::Abs($rect.L - $mon.L) -le 1 -and [math]::Abs($rect.T - $mon.T) -le 1 -and
                          [math]::Abs($rect.R - $mon.R) -le 1 -and [math]::Abs($rect.B - $mon.B) -le 1)
    }
    if ($coversMonitor) {
        $hasCaption = [bool]$r.HasCaption
        $r.Mode = if ($hasCaption) { 'Maximized' } else { 'FullScreen' }
        & $setCoverage $true
        return $r
    }
    $r.Mode = 'Windowed'
    & $setCoverage $false
    return $r
}

function Select-GfxPrimaryNoWindow {
    <#
    .SYNOPSIS
        Picks the one NO top-level window whose placement the run records:
        NeurOptimal's own panel when it can be named, else the window hosting
        a WebView2 surface, else the largest visible one.
    .DESCRIPTION
        THE TITLE COMES FIRST, BECAUSE THE SURFACE MOVES. Measured 2026-09-18
        with the separate visualizer control pressed: the visualizer's surface
        left NeurOptimal's panel for a new top-level window, and a selector
        that preferred 'the window hosting a surface' followed it. Everything
        the package labels 'NO window' then described the VISUALIZER's window
        instead of NeurOptimal's.
        In that capture both were maximized at the same size so nothing read
        wrong, which is precisely why it would have gone unnoticed: detach the
        visuals while NeurOptimal's own panel is a different size and the
        report describes the wrong window under the right name.
    .PARAMETER Titles
        hwnd -> title, from the scan's NOWIN rows. Without it the old
        surface-then-area order applies, which is what a caller with no title
        map can do and is right whenever the panes have not moved.
    .OUTPUTS
        The Get-GfxWindowMode record, or $null when there is no visible
        top-level window.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][array]$Geometry,
        [hashtable]$Titles = @{}
    )

    $best = $null
    $bestArea = -1L
    $bestSurface = $false
    $bestNamed = $false
    foreach ($g in @($Geometry)) {
        if ($null -eq $g) { continue }
        # A minimized window has a rect off-screen; treat its area as zero so
        # a visible sibling wins, but keep it as a last resort.
        $area = 0L
        if ($g.Rect -and $g.ShowCmd -ne 2) { $area = [long]([math]::Max(0, $g.Rect.R - $g.Rect.L)) * [long]([math]::Max(0, $g.Rect.B - $g.Rect.T)) }
        $surf = [bool]$g.HasSurface
        # Does this window name itself as NeurOptimal's panel? Matched on the
        # ASCII stem: the live title carries a registered-trademark glyph and
        # these files are read as ANSI on a field box.
        $named = $false
        if ($Titles -and $null -ne $g.Hwnd -and $Titles.ContainsKey([long]$g.Hwnd)) {
            $named = ([string]$Titles[[long]$g.Hwnd] -match 'NeurOptimal')
        }
        $better = $false
        if ($null -eq $best) { $better = $true }
        elseif ($named -and -not $bestNamed) { $better = $true }
        elseif ($named -eq $bestNamed -and $surf -and -not $bestSurface) { $better = $true }
        elseif ($named -eq $bestNamed -and $surf -eq $bestSurface -and $area -gt $bestArea) { $better = $true }
        if ($better) { $best = $g; $bestArea = $area; $bestSurface = $surf; $bestNamed = $named }
    }
    if ($null -eq $best) { return $null }
    return (Get-GfxWindowMode -Geometry $best)
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
                # AppFullScreen is fixed at 'Unverified' here as it is in
                # Get-GfxWindowMode: a placement does not record which control
                # set it, and inferring NeurOptimal's own full-screen state from
                # showCmd 3 would report a guess as a reading.
                $noWindow = @{ Mode = 'Unknown'; CoversScreen = $null; CoverageLabel = 'not read'; ScreenFraction = $null
                               HasCaption = $null; StyleHex = $null; Bounds = $null; MonitorBounds = $null; MonitorDevice = $null; Hwnd = $null
                               AppFullScreen = 'Unverified' }
                $geomBest = $null; $geomBestArea = -1; $geomBestSurface = $false; $geomBestNamed = $false
                # Geometry rows arrive before the NOWIN titles that name them,
                # so the rows are held and the pick is made after the pass --
                # the same order Select-GfxPrimaryNoWindow uses, which is the
                # point: two selectors that disagree are two answers to one
                # question.
                $geomRows = @()
                # top-level hwnd -> the display it is on, so a surface can be
                # located on a screen. The surface itself has no rect of its
                # own: it is a child window of the LabVIEW panel that hosts it.
                $monByTop = @{}
                $topBySurfaceHwnd = @{}
                # hwnd -> @{ Title; Visible } for EVERY top-level window,
                # hidden ones included: before a session the visualizer hangs
                # under a window titled 'Closed', and that is what separates
                # 'not on screen' from 'in a window of its own'.
                $winByHwnd = @{}
                if ($noPid -gt 0) {
                    $rows = @()
                    try { $rows = [WinConfigDiag.GfxWindowScan]::Scan($noPid) } catch { }
                    $seen = @{}
                    foreach ($row in $rows) {
                        $kind = ($row -split '\|', 2)[0]
                        if ($kind -eq 'SURFACETOP') {
                            $pt = $row -split '\|', 3
                            if ($pt.Count -lt 3) { continue }
                            try { $topBySurfaceHwnd[[long]$pt[1]] = [long]$pt[2] } catch { }
                            continue
                        }
                        if ($kind -eq 'NOGEOM') {
                            # Inline twin of Get-GfxWindowMode / Select-GfxPrimaryNoWindow
                            # (the runspace is self-contained by design). Prefer
                            # the window hosting a surface, then the largest.
                            $g = $row -split '\|', 8
                            if ($g.Count -lt 7) { continue }
                            $gDev = $(if ($g.Count -ge 8 -and -not [string]::IsNullOrWhiteSpace($g[7])) { [string]$g[7] } else { $null })
                            try { $monByTop[[long]$g[1]] = $gDev } catch { }
                            $rq = $g[3] -split ','; $mq = $g[4] -split ','
                            $rect = $null; $mon = $null
                            if ($rq.Count -eq 4) { try { $rect = @{ L = [int]$rq[0]; T = [int]$rq[1]; R = [int]$rq[2]; B = [int]$rq[3] } } catch { $rect = $null } }
                            if ($mq.Count -eq 4) { try { $mon = @{ L = [int]$mq[0]; T = [int]$mq[1]; R = [int]$mq[2]; B = [int]$mq[3] } } catch { $mon = $null } }
                            $show = -1; try { $show = [int]$g[2] } catch { }
                            $style = $null; try { if ($g[5]) { $style = [Convert]::ToInt64($g[5], 16) } } catch { }
                            $surf = ($g[6] -eq '1')
                            $area = 0L
                            if ($rect -and $show -ne 2) { $area = [long]([math]::Max(0, $rect.R - $rect.L)) * [long]([math]::Max(0, $rect.B - $rect.T)) }
                            $geomRows += @{ Rect = $rect; Mon = $mon; Show = $show; Style = $style; Hwnd = [long]$g[1]; Dev = $gDev; Surf = $surf; Area = $area }
                            continue
                        }
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
                            $sHwnd = $null; try { $sHwnd = [long]$p2[2] } catch { }
                            $surfaces += @{ HostPid = $hp; Hwnd = $sHwnd; DocumentTitle = $title; Role = $role; RoleSource = $(if ($role -eq 'Unknown') { 'unresolved' } else { 'window-title' }) }
                        } elseif ($kind -eq 'NOWIN') {
                            $p2 = $row -split '\|', 5
                            if ($p2.Count -lt 5) { continue }
                            try { $winByHwnd[[long]$p2[1]] = @{ Title = [string]$p2[4]; Visible = ($p2[2] -eq '1') } } catch { }
                            if ($p2[2] -eq '1' -and -not [string]::IsNullOrWhiteSpace($p2[4])) { $noWindows += [string]$p2[4] }
                        }
                    }
                    # THE PRIMARY WINDOW: NeurOptimal's own panel when a title
                    # names it, then a surface host, then the largest. The
                    # visualizer's surface LEAVES the panel for a window of its
                    # own when the separate control is used, and a surface-first
                    # pick follows it -- labelling the visualizer's window as
                    # NO's for the whole run.
                    foreach ($gr in $geomRows) {
                        $named = $false
                        if ($winByHwnd.ContainsKey($gr.Hwnd)) { $named = ([string]$winByHwnd[$gr.Hwnd].Title -match 'NeurOptimal') }
                        $better = $false
                        if ($null -eq $geomBest) { $better = $true }
                        elseif ($named -and -not $geomBestNamed) { $better = $true }
                        elseif ($named -eq $geomBestNamed -and $gr.Surf -and -not $geomBestSurface) { $better = $true }
                        elseif ($named -eq $geomBestNamed -and $gr.Surf -eq $geomBestSurface -and $gr.Area -gt $geomBestArea) { $better = $true }
                        if ($better) { $geomBest = $gr; $geomBestArea = $gr.Area; $geomBestSurface = $gr.Surf; $geomBestNamed = $named }
                    }

                    if ($geomBest) {
                        $noWindow.Hwnd = $geomBest.Hwnd
                        $noWindow.MonitorDevice = $geomBest.Dev
                        if ($null -ne $geomBest.Style) {
                            $noWindow.HasCaption = (([long]$geomBest.Style -band 0x00C00000) -eq 0x00C00000)
                            $noWindow.StyleHex = ('{0:X8}' -f [long]$geomBest.Style)
                        }
                        if ($geomBest.Rect) { $noWindow.Bounds = "$($geomBest.Rect.R - $geomBest.Rect.L)x$($geomBest.Rect.B - $geomBest.Rect.T)" }
                        if ($geomBest.Mon) { $noWindow.MonitorBounds = "$($geomBest.Mon.R - $geomBest.Mon.L)x$($geomBest.Mon.B - $geomBest.Mon.T)" }
                        if ($geomBest.Rect -and $geomBest.Mon) {
                            $ma = [double]([math]::Max(0, $geomBest.Mon.R - $geomBest.Mon.L)) * [double]([math]::Max(0, $geomBest.Mon.B - $geomBest.Mon.T))
                            if ($ma -gt 0) {
                                $wa = [double]([math]::Max(0, $geomBest.Rect.R - $geomBest.Rect.L)) * [double]([math]::Max(0, $geomBest.Rect.B - $geomBest.Rect.T))
                                $noWindow.ScreenFraction = [math]::Round($wa / $ma, 3)
                            }
                        }
                        if ($geomBest.Show -eq 2) { $noWindow.Mode = 'Minimized'; $noWindow.CoversScreen = $false; $noWindow.CoverageLabel = 'minimized' }
                        elseif ($geomBest.Show -eq 3) { $noWindow.Mode = 'Maximized'; $noWindow.CoversScreen = $true; $noWindow.CoverageLabel = 'covers the whole screen' }
                        elseif ($geomBest.Rect) {
                            $covers = $false
                            if ($geomBest.Mon) {
                                $rr = $geomBest.Rect; $mm = $geomBest.Mon
                                $covers = ([math]::Abs($rr.L - $mm.L) -le 1 -and [math]::Abs($rr.T - $mm.T) -le 1 -and [math]::Abs($rr.R - $mm.R) -le 1 -and [math]::Abs($rr.B - $mm.B) -le 1)
                            }
                            if ($covers) {
                                $noWindow.Mode = if ([bool]$noWindow.HasCaption) { 'Maximized' } else { 'FullScreen' }
                                $noWindow.CoversScreen = $true
                                $noWindow.CoverageLabel = 'covers the whole screen'
                            } else {
                                $noWindow.Mode = 'Windowed'
                                $noWindow.CoversScreen = $false
                                $noWindow.CoverageLabel = 'covers part of the screen'
                            }
                        }
                    }
                    # WHICH SCREEN EACH PANE IS ON. Joined here rather than at
                    # summary time because the mapping is only true while the
                    # windows exist -- and a visualizer that was dragged to a
                    # second display is the difference between a comparable
                    # recording and one that measured two screens at once.
                    foreach ($s in $surfaces) {
                        $s['WindowHwnd'] = $null
                        $s['MonitorDevice'] = $null
                        $s['HostWindowTitle'] = $null
                        $s['HostWindowVisible'] = $null
                        if ($null -ne $s.Hwnd -and $topBySurfaceHwnd.ContainsKey([long]$s.Hwnd)) {
                            $top = $topBySurfaceHwnd[[long]$s.Hwnd]
                            $s['WindowHwnd'] = $top
                            if ($monByTop.ContainsKey($top)) { $s['MonitorDevice'] = $monByTop[$top] }
                            if ($winByHwnd.ContainsKey($top)) {
                                $s['HostWindowTitle'] = $winByHwnd[$top].Title
                                $s['HostWindowVisible'] = $winByHwnd[$top].Visible
                            }
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
                        # The top-level NO window this pane is drawn inside and
                        # the display that window is on. Both $null when the
                        # join failed, so "not read" can never be mistaken for
                        # "same window as the other pane".
                        WindowHwnd    = $s.WindowHwnd
                        MonitorDevice = $s.MonitorDevice
                        # The host window's own title and whether it is on
                        # screen: what tells the visuals drawn INSIDE
                        # NeurOptimal from the same pane in a window of its own.
                        HostWindowTitle   = $s.HostWindowTitle
                        HostWindowVisible = $s.HostWindowVisible
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
                    NoWindow         = $noWindow
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

# The dwell rule for "NO's window set changed" lives here, in ONE place.
# The live surface announces the change and the summariser splits the arms on
# it. While only the summariser applied a dwell filter, a one-sample blip made
# the app say "Session detected" over a run the report scored 'none-detected' --
# the channel-mismatch class this repo has hit repeatedly. Both read this.
$script:GfxUiChangeDwellSamples = 3

# How far short of the test's length a session that ENDED AT SESSION COMPLETE
# may read before it is called short. See the SessionLength deviation.
$script:GfxSessionLengthToleranceSec = 15

function Get-GfxUiChangeDwellSamples {
    <#
    .SYNOPSIS
        Consecutive samples a change in NO's window set must hold to count as
        a session start. The single source for both surfaces.
    #>
    [CmdletBinding()]
    param()
    return $script:GfxUiChangeDwellSamples
}

function Get-GfxIdleFloorSec {
    <#
    .SYNOPSIS
        Seconds of idle arm the coverage line asks for before it reports
        Baseline collected.
        The single source for the live line, the Start instruction and the
        short-idle finding.
    #>
    [CmdletBinding()]
    param()
    return $script:GfxIdleFloorSec
}

# ---------------------------------------------------------------------------
# THE DISPLAY ARRANGEMENT -- which screen the run was actually made on
# ---------------------------------------------------------------------------
#
# COUNTING DISPLAYS WAS NEVER THE QUESTION. The first version of this bench
# asked for "one monitor" and checked SystemInformation.MonitorCount, which is
# satisfied identically by a 14" built-in laptop panel and by a 49" external
# monitor with the lid closed. Those two runs are not comparable in any way
# that matters: butterchurn renders the whole pane, so its cost follows the
# number of pixels, and 5120x1440 is 3.2x the area of 1920x1200. A check that
# passes both of them lets the largest confound through while reporting that it
# was controlled, which is worse than not checking at all.
#
# So the arrangement is READ, not counted: every active display with its
# identity, mode, refresh rate and scale factor, whether it is the machine's
# built-in panel, and which of them NeurOptimal is on.
#
# WHAT IS MEASURED AND WHAT IS INFERRED ARE KEPT APART. The built-in panel of a
# laptop running with its lid closed is not enumerated by Windows at all --
# measured on a Surface Laptop Studio on 2026-09-18, where neither the active
# nor the all-paths query returned an internal target. "Inactive" there is an
# INFERENCE from the machine having a battery, and it is labelled as one; it is
# never presented as a reading.

function Initialize-GfxDisplayScan {
    <#
    .SYNOPSIS
        Compiles the inline Win32 display-arrangement helper.
    .DESCRIPTION
        Same discipline as Initialize-GfxWindowScan: Add-Type assemblies are
        AppDomain-wide, the dist ships text only, and this reads metadata and
        changes nothing. No display is added, removed, moved, re-ordered,
        re-scaled, or switched on or off.
    .OUTPUTS
        [bool] whether the type is available.
    #>
    [CmdletBinding()]
    param()

    if ('WinConfigDiag.GfxDisplayScan' -as [type]) { return $true }
    try {
        $source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinConfigDiag {
    // Reads the DISPLAY ARRANGEMENT: which displays are active, what they are
    // called, whether each is the machine's built-in panel, its mode, refresh
    // rate and scale factor. Read-only throughout.
    public static class GfxDisplayScan {
        const uint QDC_ALL_PATHS = 1;
        const uint QDC_ONLY_ACTIVE_PATHS = 2;
        const int  ERROR_SUCCESS = 0;

        [DllImport("user32.dll")] static extern int GetDisplayConfigBufferSizes(uint flags, out uint numPath, out uint numMode);
        [DllImport("user32.dll")] static extern int QueryDisplayConfig(uint flags, ref uint numPath, [Out] PATH_INFO[] paths, ref uint numMode, [Out] MODE_BLOB[] modes, IntPtr topologyId);
        [DllImport("user32.dll")] static extern int DisplayConfigGetDeviceInfo(ref TARGET_DEVICE_NAME n);
        [DllImport("user32.dll")] static extern int DisplayConfigGetDeviceInfo(ref SOURCE_DEVICE_NAME n);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool EnumDisplayDevicesW(string dev, uint num, ref DISPLAY_DEVICE info, uint flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool EnumDisplaySettingsW(string dev, int mode, ref DEVMODE dm);
        [DllImport("user32.dll")] static extern IntPtr MonitorFromPoint(POINT pt, uint flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetMonitorInfoW(IntPtr m, ref MONITORINFO i);
        [DllImport("shcore.dll")] static extern int GetDpiForMonitor(IntPtr hmon, int type, out uint dpiX, out uint dpiY);

        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct RATIONAL { public uint Numerator, Denominator; }
        [StructLayout(LayoutKind.Sequential)] struct POINT { public int X, Y; }
        [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }
        [StructLayout(LayoutKind.Sequential)] struct MONITORINFO { public uint cbSize; public RECT rcMonitor, rcWork; public uint dwFlags; }
        [StructLayout(LayoutKind.Sequential)] struct PATH_SOURCE_INFO { public LUID adapterId; public uint id, modeInfoIdx, statusFlags; }
        [StructLayout(LayoutKind.Sequential)] struct PATH_TARGET_INFO {
            public LUID adapterId; public uint id, modeInfoIdx, outputTechnology, rotation, scaling;
            public RATIONAL refreshRate; public uint scanLineOrdering; public int targetAvailable; public uint statusFlags;
        }
        [StructLayout(LayoutKind.Sequential)] struct PATH_INFO { public PATH_SOURCE_INFO sourceInfo; public PATH_TARGET_INFO targetInfo; public uint flags; }
        // DISPLAYCONFIG_MODE_INFO is 64 bytes and its payload is a union this
        // scan never reads -- the refresh rate comes from the path's target and
        // the mode from EnumDisplaySettings. Declared as a blob of exactly the
        // right size so the array marshals without modelling the union.
        [StructLayout(LayoutKind.Sequential)] struct MODE_BLOB { public uint a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p; }
        [StructLayout(LayoutKind.Sequential)] struct DEVICE_INFO_HEADER { public uint type, size; public LUID adapterId; public uint id; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct TARGET_DEVICE_NAME {
            public DEVICE_INFO_HEADER header; public uint flags; public uint outputTechnology;
            public ushort edidManufactureId, edidProductCodeId; public uint connectorInstance;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string monitorFriendlyDeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string monitorDevicePath;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct SOURCE_DEVICE_NAME {
            public DEVICE_INFO_HEADER header;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string viewGdiDeviceName;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct DISPLAY_DEVICE {
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
            public uint StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct DEVMODE {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
            public ushort dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
            public uint dmFields;
            public int dmPositionX, dmPositionY; public uint dmDisplayOrientation, dmDisplayFixedOutput;
            public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
            public ushort dmLogPixels; public uint dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency;
            public uint dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2, dmPanningWidth, dmPanningHeight;
        }

        static string San(string s) {
            if (s == null) { return ""; }
            return s.Replace("|", "/").Replace("\r", " ").Replace("\n", " ").Trim();
        }

        // Rows, pipe-delimited, one kind per line; the caller parses.
        //
        //   GFXDISPERR|<stage>|<message>
        //       a stage that could not be read -- the caller renders the
        //       affected field as unread, never as a zero or as a failure
        //   GFXDISP|<gdiName>|<primary 0/1>|<w>|<h>|<hz>|<x>|<y>|<dpi>|<internal 0/1/?>|<tech>|<name>|<path>|<exactHz>|<desktopW>|<desktopH>
        //       one ACTIVE display. <w>x<h> is the PHYSICAL mode;
        //       <desktopW>x<desktopH> is the same monitor in desktop
        //       coordinates, which this process sees virtualized. Their ratio
        //       is the scale factor, and it is the only reading of it that
        //       does not depend on the caller's DPI awareness. <devString> is
        //       the adapter's own name for the display, which is what
        //       NeurOptimal's monitor picker shows.
        //   GFXDISPOFF|<internal 0/1>|<tech>|<name>|<path>
        //       one target that is CONNECTED BUT NOT ACTIVE -- on the machines
        //       that report it, this is what says the built-in panel is
        //       switched off rather than absent
        public static string[] Scan() {
            List<string> rows = new List<string>();
            Dictionary<string, string[]> bySource = new Dictionary<string, string[]>();
            Dictionary<string, bool> activeTargets = new Dictionary<string, bool>();
            try { ReadPaths(QDC_ONLY_ACTIVE_PATHS, bySource, activeTargets, rows, false); }
            catch (Exception ex) { rows.Add("GFXDISPERR|active-paths|" + San(ex.Message)); }
            try { ReadPaths(QDC_ALL_PATHS, null, activeTargets, rows, true); }
            catch (Exception ex) { rows.Add("GFXDISPERR|all-paths|" + San(ex.Message)); }

            uint n = 0;
            while (true) {
                DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
                dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                if (!EnumDisplayDevicesW(null, n, ref dd, 0)) { break; }
                n++;
                if ((dd.StateFlags & 1) == 0) { continue; } // DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
                bool primary = (dd.StateFlags & 4) != 0;    // DISPLAY_DEVICE_PRIMARY_DEVICE
                DEVMODE dm = new DEVMODE();
                dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));
                string w = "", h = "", hz = "", x = "", y = "";
                if (EnumDisplaySettingsW(dd.DeviceName, -1 /* ENUM_CURRENT_SETTINGS */, ref dm)) {
                    w = dm.dmPelsWidth.ToString(); h = dm.dmPelsHeight.ToString();
                    hz = dm.dmDisplayFrequency.ToString();
                    x = dm.dmPositionX.ToString(); y = dm.dmPositionY.ToString();
                }
                string dpi = "";
                string deskW = "", deskH = "";
                try {
                    POINT pt = new POINT(); pt.X = dm.dmPositionX + 1; pt.Y = dm.dmPositionY + 1;
                    IntPtr hm = MonitorFromPoint(pt, 2 /* MONITOR_DEFAULTTONEAREST */);
                    if (hm != IntPtr.Zero) {
                        uint dx, dy;
                        if (GetDpiForMonitor(hm, 0 /* MDT_EFFECTIVE_DPI */, out dx, out dy) == ERROR_SUCCESS) { dpi = dx.ToString(); }
                        // The monitor rect in DESKTOP coordinates. For a
                        // process that is not per-monitor DPI aware this is
                        // VIRTUALIZED -- the physical mode divided by the
                        // scale factor -- while dmPelsWidth above is the real
                        // mode. The ratio of the two IS the scale, and unlike
                        // GetDpiForMonitor it does not depend on this
                        // process's DPI awareness.
                        MONITORINFO mi = new MONITORINFO();
                        mi.cbSize = (uint)Marshal.SizeOf(typeof(MONITORINFO));
                        if (GetMonitorInfoW(hm, ref mi)) {
                            deskW = (mi.rcMonitor.R - mi.rcMonitor.L).ToString();
                            deskH = (mi.rcMonitor.B - mi.rcMonitor.T).ToString();
                        }
                    }
                } catch { }
                string isInternal = "?", tech = "", name = "", path = "", exactHz = "";
                string[] meta;
                if (bySource.TryGetValue(dd.DeviceName, out meta)) { isInternal = meta[0]; tech = meta[1]; name = meta[2]; path = meta[3]; exactHz = meta[4]; }
                // The MONITOR's own string, from the display's child device --
                // NOT the adapter's, which is the graphics card's name. These
                // are two different strings and only one of them is what
                // NeurOptimal's monitor picker shows: measured 2026-09-18, the
                // picker read 'Generic PnP Monitor' where the adapter string
                // is 'Intel(R) Iris(R) Xe Graphics'. Kept separate from the
                // EDID name ('PHL 499P9'), which is what identifies the screen.
                string devString = "";
                try {
                    DISPLAY_DEVICE mon = new DISPLAY_DEVICE();
                    mon.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                    if (EnumDisplayDevicesW(dd.DeviceName, 0, ref mon, 0)) { devString = San(mon.DeviceString); }
                } catch { }
                if (devString.Length == 0) { devString = San(dd.DeviceString); }
                if (name.Length == 0) { name = devString; }
                rows.Add("GFXDISP|" + San(dd.DeviceName) + "|" + (primary ? "1" : "0") + "|" + w + "|" + h + "|" + hz + "|" + x + "|" + y + "|" + dpi + "|" + isInternal + "|" + tech + "|" + name + "|" + path + "|" + exactHz + "|" + deskW + "|" + deskH + "|" + devString);
            }
            return rows.ToArray();
        }

        static void ReadPaths(uint flags, Dictionary<string, string[]> bySource, Dictionary<string, bool> activeTargets, List<string> rows, bool inactiveOnly) {
            uint pc = 0, mc = 0;
            int rc = GetDisplayConfigBufferSizes(flags, out pc, out mc);
            if (rc != ERROR_SUCCESS) { rows.Add("GFXDISPERR|buffer-sizes|win32 " + rc); return; }
            PATH_INFO[] paths = new PATH_INFO[pc];
            MODE_BLOB[] modes = new MODE_BLOB[mc];
            rc = QueryDisplayConfig(flags, ref pc, paths, ref mc, modes, IntPtr.Zero);
            if (rc != ERROR_SUCCESS) { rows.Add("GFXDISPERR|query|win32 " + rc); return; }
            Dictionary<string, bool> emitted = new Dictionary<string, bool>();
            for (int i = 0; i < pc; i++) {
                bool active = (paths[i].flags & 1) != 0; // DISPLAYCONFIG_PATH_ACTIVE
                if (inactiveOnly && active) { continue; }
                TARGET_DEVICE_NAME tn = new TARGET_DEVICE_NAME();
                tn.header.type = 2; // DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME
                tn.header.size = (uint)Marshal.SizeOf(typeof(TARGET_DEVICE_NAME));
                tn.header.adapterId = paths[i].targetInfo.adapterId;
                tn.header.id = paths[i].targetInfo.id;
                if (DisplayConfigGetDeviceInfo(ref tn) != ERROR_SUCCESS) { continue; }
                uint tech = tn.outputTechnology;
                // 0x80000000 INTERNAL, 11 DISPLAYPORT_EMBEDDED, 13 UDI_EMBEDDED.
                string isInternal = (tech == 0x80000000u || tech == 11u || tech == 13u) ? "1" : "0";
                string techName = TechName(tech);
                string friendly = San(tn.monitorFriendlyDeviceName);
                string devPath = San(tn.monitorDevicePath);
                if (inactiveOnly) {
                    if (paths[i].targetInfo.targetAvailable == 0) { continue; }
                    // The all-paths query returns SEVERAL inactive paths per
                    // target, including paths to a target that is currently
                    // active on another connector. Measured on the reference
                    // box: one external monitor produced three such rows while
                    // it was the only display in use, and all three would have
                    // read as "a display that is switched off".
                    if (devPath.Length > 0 && (activeTargets.ContainsKey(devPath) || emitted.ContainsKey(devPath))) { continue; }
                    if (devPath.Length > 0) { emitted[devPath] = true; }
                    rows.Add("GFXDISPOFF|" + isInternal + "|" + techName + "|" + friendly + "|" + devPath);
                    continue;
                }
                if (devPath.Length > 0) { activeTargets[devPath] = true; }
                string exactHz = "";
                if (paths[i].targetInfo.refreshRate.Denominator > 0) {
                    exactHz = ((double)paths[i].targetInfo.refreshRate.Numerator / (double)paths[i].targetInfo.refreshRate.Denominator).ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
                }
                SOURCE_DEVICE_NAME sn = new SOURCE_DEVICE_NAME();
                sn.header.type = 1; // DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME
                sn.header.size = (uint)Marshal.SizeOf(typeof(SOURCE_DEVICE_NAME));
                sn.header.adapterId = paths[i].sourceInfo.adapterId;
                sn.header.id = paths[i].sourceInfo.id;
                if (DisplayConfigGetDeviceInfo(ref sn) != ERROR_SUCCESS) { continue; }
                string gdi = San(sn.viewGdiDeviceName);
                if (gdi.Length > 0 && bySource != null && !bySource.ContainsKey(gdi)) {
                    bySource[gdi] = new string[] { isInternal, techName, friendly, devPath, exactHz };
                }
            }
        }

        static string TechName(uint t) {
            switch (t) {
                case 0x80000000u: return "Internal";
                case 0u: return "VGA";
                case 1u: return "S-Video";
                case 2u: return "Composite";
                case 3u: return "Component";
                case 4u: return "DVI";
                case 5u: return "HDMI";
                case 6u: return "LVDS";
                case 8u: return "D-Jpn";
                case 9u: return "SDI";
                case 10u: return "DisplayPort";
                case 11u: return "DisplayPort (embedded)";
                case 12u: return "UDI";
                case 13u: return "UDI (embedded)";
                case 14u: return "SDTV dongle";
                case 15u: return "Miracast";
                case 16u: return "Indirect wired";
                case 17u: return "Indirect virtual";
                default: return "unknown (" + t + ")";
            }
        }
    }
}
"@
        Add-Type -TypeDefinition $source -ErrorAction Stop
        return [bool]('WinConfigDiag.GfxDisplayScan' -as [type])
    } catch {
        return $false
    }
}

function ConvertTo-GfxMonitorKey {
    <#
    .SYNOPSIS
        The one key that joins a DisplayConfig target to its EDID record. Pure.
    .DESCRIPTION
        The two readings name the same monitor in two spellings:

          DisplayConfig  \\?\DISPLAY#PHL092A#4&218c0622&0&UID20548#{e6f07b5f-...}
          WMI            DISPLAY\PHL092A\4&218c0622&0&UID20548_0

        Both are rendered through this function so a map key and a lookup key
        can never drift apart in formatting -- the same discipline, and for the
        same reason, as ConvertTo-GfxLuidKey.

        Returns $null for anything it cannot reduce to the shared middle, which
        renders as an absent physical size rather than a wrong one.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    $t = $t -replace '^\\\\\?\\', ''       # interface prefix
    $t = $t -replace '\{[0-9A-Fa-f\-]+\}$', ''
    $t = $t -replace '#', '\'
    $t = $t -replace '_\d+$', ''           # WMI's per-instance suffix
    $t = $t.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    return $t.ToUpperInvariant()
}

function Get-GfxDisplayPhysicalSize {
    <#
    .SYNOPSIS
        Each monitor's physical panel size, from EDID, keyed by
        ConvertTo-GfxMonitorKey.
    .DESCRIPTION
        ONE CIM CALL, CACHED. A panel's physical size does not change, and the
        readiness checklist asks for the arrangement once a second -- so the
        cache is rebuilt only when the SET of attached monitors changes, which
        is exactly when the answer can have changed.

        WHAT 'RELIABLY AVAILABLE' MEANS HERE. EDID states the image size in
        whole centimetres, and a monitor that declines to state it reports 0.
        A size is kept only when both dimensions are non-zero AND the diagonal
        lands between 3 and 120 inches; anything else is dropped rather than
        printed. A wrong diagonal beside a right resolution is worse than no
        diagonal at all, and it is the kind of wrong a reader cannot detect.

        Measured on the reference box: a 49-inch Philips 499P9 reports
        119 x 34 cm -> 48.7 in, which is EDID's centimetre rounding and not an
        error. The class is unreadable without elevation on some systems, in
        which case every size is simply absent.
    .OUTPUTS
        Hashtable: key -> @{ WidthCm, HeightCm, DiagonalInch }. Empty when the
        class could not be read.
    #>
    [CmdletBinding()]
    param([string[]]$DevicePaths)

    $keys = @(@($DevicePaths) | ForEach-Object { ConvertTo-GfxMonitorKey -Text $_ } | Where-Object { $_ } | Sort-Object -Unique)
    $cacheKey = ($keys -join '|')
    if ($script:GfxPhysicalSizeCacheKey -eq $cacheKey -and $null -ne $script:GfxPhysicalSizeCache) {
        return $script:GfxPhysicalSizeCache
    }

    $map = @{}
    try {
        foreach ($m in @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'WmiMonitorBasicDisplayParams' -ErrorAction Stop)) {
            $key = ConvertTo-GfxMonitorKey -Text ([string]$m.InstanceName)
            if (-not $key) { continue }
            $w = 0; $h = 0
            try { $w = [int]$m.MaxHorizontalImageSize; $h = [int]$m.MaxVerticalImageSize } catch { continue }
            if ($w -le 0 -or $h -le 0) { continue }
            $diag = [math]::Sqrt(($w * $w) + ($h * $h)) / 2.54
            if ($diag -lt 3 -or $diag -gt 120) { continue }
            $map[$key] = @{ WidthCm = $w; HeightCm = $h; DiagonalInch = [math]::Round($diag, 1) }
        }
    } catch {
        # Unreadable -- every size stays absent, which is the honest answer and
        # never a guessed one.
        $map = @{}
    }

    $script:GfxPhysicalSizeCacheKey = $cacheKey
    $script:GfxPhysicalSizeCache = $map
    return $map
}

function ConvertFrom-GfxDisplayScanRows {
    <#
    .SYNOPSIS
        Turns GfxDisplayScan.Scan rows into the arrangement record. PURE --
        unit-testable against a fixture, with no display attached.
    .DESCRIPTION
        Every field a row left empty stays $null. A display whose mode could
        not be read is still listed, with its mode absent: that a display is
        there is a separate reading from what it is set to, and collapsing the
        two would drop a display from the arrangement because one of its
        numbers was unavailable.
    .PARAMETER Rows
        The raw pipe-delimited rows.
    .PARAMETER HasBattery
        Whether this machine has a battery, from the inventory. Used ONLY to
        say whether an unenumerated built-in panel is likely to exist; never to
        claim one is active. Omitted leaves the question open.
    .PARAMETER PhysicalSizes
        The EDID size map from Get-GfxDisplayPhysicalSize, joined on the
        monitor's device path. PASSED IN rather than read here, so this stays
        pure and testable; a display the map does not cover simply has no size,
        which is how a monitor that declines to state one renders.
    .OUTPUTS
        See Get-GfxDisplayArrangement.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Rows,
        $HasBattery,
        [hashtable]$PhysicalSizes = @{}
    )

    $displays = @()
    $inactive = @()
    $errors = @()
    $toInt = {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
        $v = 0
        if ([int]::TryParse($Text, [ref]$v)) { return $v }
        return $null
    }

    foreach ($row in @($Rows)) {
        if ([string]::IsNullOrEmpty($row)) { continue }
        $kind = ($row -split '\|', 2)[0]
        if ($kind -eq 'GFXDISPERR') {
            $p = $row -split '\|', 3
            if ($p.Count -ge 3) { $errors += "$($p[1]): $($p[2])" }
            continue
        }
        if ($kind -eq 'GFXDISPOFF') {
            $p = $row -split '\|', 5
            if ($p.Count -lt 5) { continue }
            $inactive += @{
                Internal   = ($p[1] -eq '1')
                Connection = [string]$p[2]
                Name       = $(if ([string]::IsNullOrWhiteSpace($p[3])) { $null } else { [string]$p[3] })
                DevicePath = $(if ([string]::IsNullOrWhiteSpace($p[4])) { $null } else { [string]$p[4] })
            }
            continue
        }
        if ($kind -ne 'GFXDISP') { continue }
        $p = $row -split '\|', 17
        if ($p.Count -lt 13) { continue }
        $w = & $toInt $p[3]
        $h = & $toInt $p[4]
        $dpi = & $toInt $p[8]
        $exactHz = $null
        if ($p.Count -ge 14 -and -not [string]::IsNullOrWhiteSpace($p[13])) {
            $d = 0.0
            if ([double]::TryParse($p[13], [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $exactHz = [math]::Round($d, 3) }
        }
        # THE SCALE FACTOR, DERIVED -- not taken from GetDpiForMonitor.
        #
        # MEASURED 2026-09-18: a Surface Laptop Studio panel running at 150%
        # reported dpi 96 through GetDpiForMonitor, because this process is not
        # per-monitor DPI aware and the API then answers for the caller rather
        # than for the display. Read straight, that field says '100% scaling'
        # on every machine in the fleet -- a false reading in the cohort key,
        # which is exactly what this module refuses to emit.
        #
        # The physical mode (EnumDisplaySettings, 2400x1600) against the same
        # monitor in desktop coordinates (GetMonitorInfo, 1600x1067) gives
        # 1.5 -- and that ratio does not depend on anyone's DPI awareness. The
        # reported DPI is kept beside it as an observation, never as the answer.
        $deskW = & $toInt $(if ($p.Count -ge 15) { $p[14] } else { '' })
        $deskH = & $toInt $(if ($p.Count -ge 16) { $p[15] } else { '' })
        $scale = $null
        if ($null -ne $w -and $null -ne $deskW -and $deskW -gt 0) {
            $scale = [int][math]::Round(100.0 * $w / $deskW)
        } elseif ($null -ne $dpi -and $dpi -gt 0) {
            # No desktop rect: fall back to the reported DPI, which is right
            # whenever the caller happens to be DPI aware and is all there is.
            $scale = [int][math]::Round(100.0 * $dpi / 96.0)
        }

        # '?' IS A THIRD ANSWER. A display whose connector could not be read is
        # neither internal nor external, and forcing it to $false would let a
        # built-in panel be reported as an external monitor -- the one mistake
        # this whole reader exists to prevent.
        $isInternal = switch ([string]$p[9]) { '1' { $true } '0' { $false } default { $null } }
        $devicePath = $(if ([string]::IsNullOrWhiteSpace($p[12])) { $null } else { [string]$p[12] })
        $size = $null
        if ($devicePath -and $PhysicalSizes) {
            $mk = ConvertTo-GfxMonitorKey -Text $devicePath
            if ($mk -and $PhysicalSizes.ContainsKey($mk)) { $size = $PhysicalSizes[$mk] }
        }
        $displays += @{
            GdiName      = [string]$p[1]
            Primary      = ($p[2] -eq '1')
            Width        = $w
            Height       = $h
            Bounds       = $(if ($null -ne $w -and $null -ne $h) { "${w}x${h}" } else { $null })
            RefreshHz    = & $toInt $p[5]
            RefreshExact = $exactHz
            PosX         = & $toInt $p[6]
            PosY         = & $toInt $p[7]
            Dpi          = $dpi
            ScalePercent = $scale
            # The same monitor as the desktop sees it. Kept because the window
            # rects elsewhere in the package are in THESE coordinates, and a
            # reader comparing 1614x1033 against a 2400x1600 display otherwise
            # has no way to reconcile them.
            DesktopWidth  = $deskW
            DesktopHeight = $deskH
            DesktopBounds = $(if ($null -ne $deskW -and $null -ne $deskH) { "${deskW}x${deskH}" } else { $null })
            Internal     = $isInternal
            Connection   = $(if ([string]::IsNullOrWhiteSpace($p[10])) { $null } else { [string]$p[10] })
            Name         = $(if ([string]::IsNullOrWhiteSpace($p[11])) { $null } else { [string]$p[11] })
            # WHAT NEUROPTIMAL CALLS THIS SCREEN. Its monitor picker lists
            # 'Display <n> - <adapter string> - <w> x <h>', and 'Display 1'
            # is '\.\DISPLAY1' -- confirmed 2026-09-18 by the resolution
            # matching. A tester choosing a monitor in that dialog is reading
            # these, not the EDID name this tool identifies screens by, so
            # both are carried and the guide prints both.
            DisplayNumber = $(if ([string]$p[1] -match 'DISPLAY(\d+)$') { [int]$Matches[1] } else { $null })
            DeviceString  = $(if ($p.Count -ge 17 -and -not [string]::IsNullOrWhiteSpace($p[16])) { [string]$p[16] } else { $null })
            DevicePath   = $devicePath
            # From EDID, and ABSENT rather than approximated when the monitor
            # did not state it or stated something implausible.
            PhysicalWidthCm  = $(if ($size) { $size.WidthCm } else { $null })
            PhysicalHeightCm = $(if ($size) { $size.HeightCm } else { $null })
            DiagonalInch     = $(if ($size) { $size.DiagonalInch } else { $null })
        }
    }

    return (New-GfxDisplayArrangement -Displays $displays -Inactive $inactive -Errors $errors -HasBattery $HasBattery)
}

function New-GfxDisplayArrangement {
    <#
    .SYNOPSIS
        Classifies a parsed display list into the arrangement a test asks for.
        PURE, so every layout below is testable without the hardware.
    .DESCRIPTION
        THE LAYOUT IS THE UNIT OF COMPARISON, NOT THE COUNT.

          BuiltInOnly          one active display and it is the built-in panel
          ExternalOnly         one active display and it is not the built-in
                               panel -- the lid-closed, one-big-monitor case
                               that the old "one monitor" check waved through
          BuiltInPlusExternal  the built-in panel and at least one other
          MultipleExternal     more than one, none of them built-in
          NoDisplays           nothing active
          Unknown              could not be read, or a display would not say
                               which kind it is

        A display whose connector is unreadable makes the WHOLE layout Unknown
        rather than being assumed external: a guess there is a guess about the
        one variable this check exists to control.

        THE LAYOUT IS ABOUT DISPLAYS IN USE, AND THAT IS NOT THE SAME QUESTION
        AS WHAT IS PLUGGED IN. 'BuiltInOnly' says the built-in panel is the only
        display being DRAWN TO. An external monitor that is connected and
        switched off satisfies it, and 'disconnect the external monitor' is a
        different instruction from 'stop using it'. So the connected-but-unused
        set is reported SEPARATELY, in ExternalConnected, and it has three
        answers rather than two:

          count > 0   an external target was enumerated as connected and not
                      in use -- a reading, and a definite one
          count = 0   NOTHING WAS ENUMERATED, WHICH IS NOT THE SAME AS NOTHING
                      BEING THERE. Measured on the reference box: a laptop
                      running with its lid shut enumerates no internal target
                      at all, in either query. Windows does not reliably offer
                      disconnected or sleeping displays, so absence here cannot
                      be read as proof of absence.

        ExternalConnectedKnown records which of those two it is, so a caller can
        tell 'none connected' from 'none reported'. The readiness check turns
        the second into an operator confirmation rather than a silent pass.
    .OUTPUTS
        Hashtable: Ok, ReadAtUtc, Displays[], Inactive[], Count, Layout,
        LayoutText, BuiltIn (@{ State, StateText, Display, Inferred }),
        ExternalConnected[], ExternalConnectedKnown, Primary, Signature,
        Errors[].
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][array]$Displays = @(),
        [AllowEmptyCollection()][array]$Inactive = @(),
        [AllowEmptyCollection()][array]$Errors = @(),
        $HasBattery
    )

    $dash = [string][char]0x2014
    $active = @($Displays | Where-Object { $null -ne $_ })
    $inactiveList = @($Inactive | Where-Object { $null -ne $_ })
    $errorList = @($Errors | Where-Object { $_ })
    $ok = ($active.Count -gt 0)

    $internalActive = @($active | Where-Object { $_.Internal -eq $true })
    $externalActive = @($active | Where-Object { $_.Internal -eq $false })
    $unknownKind = @($active | Where-Object { $null -eq $_.Internal })

    $layout = 'Unknown'
    if (-not $ok) {
        $layout = $(if ($errorList.Count -gt 0) { 'Unknown' } else { 'NoDisplays' })
    } elseif ($unknownKind.Count -gt 0) {
        $layout = 'Unknown'
    } elseif ($active.Count -eq 1) {
        $layout = $(if ($internalActive.Count -eq 1) { 'BuiltInOnly' } else { 'ExternalOnly' })
    } elseif ($internalActive.Count -gt 0) {
        $layout = 'BuiltInPlusExternal'
    } else {
        $layout = 'MultipleExternal'
    }

    $layoutText = switch ($layout) {
        'BuiltInOnly'         { 'Built-in screen only' }
        'ExternalOnly'        { 'External display only' }
        'BuiltInPlusExternal' { "Built-in screen plus $($externalActive.Count) external display(s)" }
        'MultipleExternal'    { "$($active.Count) external displays, no built-in screen" }
        'NoDisplays'          { 'No active display' }
        default               { 'Could not be read' }
    }

    # THE BUILT-IN PANEL. Five answers, and the difference between them is
    # whether anything was actually read.
    $builtIn = @{ State = 'Unknown'; StateText = 'Could not be read'; Display = $null; Inferred = $false }
    $internalInactive = @($inactiveList | Where-Object { $_.Internal -eq $true })
    if ($internalActive.Count -gt 0) {
        $builtIn = @{ State = 'Active'; Display = $internalActive[0]; Inferred = $false; StateText = 'Active' }
    } elseif ($internalInactive.Count -gt 0) {
        $builtIn = @{ State = 'Inactive'; Display = $null; Inferred = $false
                      StateText = 'Inactive (connected, not in use)' }
    } elseif ($HasBattery -eq $true) {
        # MEASURED ON A SURFACE LAPTOP STUDIO, 2026-09-18: with the lid closed
        # the built-in panel is absent from BOTH the active and the all-paths
        # query, so there is nothing at all to read. That the machine has one
        # is an inference from it having a battery, and the text says so.
        $builtIn = @{ State = 'NotOffered'; Display = $null; Inferred = $true
                      StateText = "Inactive $dash Windows is not offering it (lid closed, or switched off)" }
    } elseif ($HasBattery -eq $false) {
        $builtIn = @{ State = 'None'; Display = $null; Inferred = $true
                      StateText = "None $dash this machine has no built-in screen" }
    }

    # CONNECTED BUT NOT IN USE, external only. The internal panel showing up
    # here is the ordinary lid-closed case and is already reported by BuiltIn;
    # an EXTERNAL monitor here is a screen the operator believes they have
    # removed from the test and has not.
    $externalConnected = @($inactiveList | Where-Object { $_.Internal -eq $false })
    # Whether the absence of such a target is a READING. It is only a reading
    # when the all-paths query returned something -- anything -- so we know it
    # is capable of answering. With nothing enumerated at all, and no error, the
    # honest answer is that we cannot tell.
    $externalConnectedKnown = ($externalConnected.Count -gt 0 -or $inactiveList.Count -gt 0)

    $primary = @($active | Where-Object { $_.Primary }) | Select-Object -First 1

    # THE SIGNATURE is what makes two arrangements comparable or not, and it is
    # sorted so the same desktop always renders byte-identical text. Identity
    # comes first, because two 1920x1080 external monitors are still two
    # different screens and a run made on each is not the same run twice.
    $parts = @()
    foreach ($d in @($active | Sort-Object { [string]$_.GdiName })) {
        $kind = if ($d.Internal -eq $true) { 'builtin' } elseif ($d.Internal -eq $false) { 'external' } else { 'unknown' }
        $name = if ($d.Name) { $d.Name } else { 'unnamed' }
        $mode = if ($d.Bounds) { $d.Bounds } else { 'nomode' }
        $hz = if ($null -ne $d.RefreshHz) { "$($d.RefreshHz)Hz" } else { 'nohz' }
        $scale = if ($null -ne $d.ScalePercent) { "$($d.ScalePercent)pct" } else { 'noscale' }
        $parts += "$kind/$name/$mode@$hz@$scale"
    }
    $signature = if ($parts.Count -gt 0) { $parts -join ' + ' } else { $null }

    return @{
        Ok         = $ok
        ReadAtUtc  = [datetime]::UtcNow.ToString('o')
        Displays   = $active
        Inactive   = $inactiveList
        Count      = $(if ($ok -or $errorList.Count -eq 0) { $active.Count } else { $null })
        Layout     = $layout
        LayoutText = $layoutText
        BuiltIn    = $builtIn
        # Connected and NOT in use. Separate from Layout on purpose: 'in use'
        # and 'plugged in' are different questions and only one of them is
        # reliably answerable.
        ExternalConnected      = $externalConnected
        ExternalConnectedKnown = $externalConnectedKnown
        Primary    = $primary
        Signature  = $signature
        Errors     = $errorList
    }
}

function Get-GfxDisplayArrangement {
    <#
    .SYNOPSIS
        The display arrangement RIGHT NOW: every active display with its
        identity, mode, refresh rate and scale, whether the built-in panel is
        in use, and what shape the desktop is in.
    .DESCRIPTION
        The live reader the readiness checklist asks once a second while a
        tester is plugging and unplugging screens. NOTHING IS CACHED: the whole
        value of the check is that it is true at the moment Start is pressed.

        Cheap enough to ask at that rate -- measured at 12 ms for ten calls on
        the reference box, against a 1 s tick.

        Returns an arrangement with Ok = $false and an error when the helper
        could not be compiled or the query failed, which every caller renders
        as 'could not be read' -- never as a failed requirement, and never as
        zero displays.
    .PARAMETER HasBattery
        From the inventory, for the built-in-panel inference only. Omit it and
        the built-in state stays Unknown rather than being guessed.
    #>
    [CmdletBinding()]
    param($HasBattery)

    if (-not (Initialize-GfxDisplayScan)) {
        return (New-GfxDisplayArrangement -Displays @() -Inactive @() -HasBattery $HasBattery `
                    -Errors @('the display-arrangement helper could not be compiled on this machine'))
    }
    try {
        $rows = [WinConfigDiag.GfxDisplayScan]::Scan()
        # The device paths first, so the EDID lookup is only rebuilt when the
        # set of attached monitors has actually changed. At one call a second
        # an uncached CIM query here would cost more than everything else this
        # window does put together.
        $paths = @()
        foreach ($row in @($rows)) {
            if ($row -notlike 'GFXDISP|*') { continue }
            $f = $row -split '\|', 14
            if ($f.Count -ge 13 -and -not [string]::IsNullOrWhiteSpace($f[12])) { $paths += [string]$f[12] }
        }
        $sizes = Get-GfxDisplayPhysicalSize -DevicePaths $paths
        return (ConvertFrom-GfxDisplayScanRows -Rows @($rows) -HasBattery $HasBattery -PhysicalSizes $sizes)
    } catch {
        return (New-GfxDisplayArrangement -Displays @() -Inactive @() -HasBattery $HasBattery `
                    -Errors @("the display arrangement could not be read: $($_.Exception.Message)"))
    }
}

function Format-GfxDisplayLabel {
    <#
    .SYNOPSIS
        One display as a tester reads it: name, size when it is known,
        resolution, refresh, scaling.
    .DESCRIPTION
        PHYSICAL SIZE IS PRINTED ONLY WHEN IT WAS READ AND IS PLAUSIBLE -- the
        gate is in Get-GfxDisplayPhysicalSize, and a display that did not pass
        it carries no size at all, so there is nothing here to suppress. A
        wrong diagonal beside a right resolution is worse than no diagonal, and
        it is the kind of wrong a reader cannot detect.

        The NAME is what distinguishes two screens and is never omitted; the
        resolution is what explains the numbers.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Display)

    $dash = [string][char]0x2014
    if (-not $Display) { return $dash }
    $bits = @()
    $bits += $(if ($Display.Name) { [string]$Display.Name } else { 'unnamed display' })
    if ($null -ne $Display.DiagonalInch) { $bits += "$($Display.DiagonalInch) in" }
    if ($Display.Bounds) { $bits += [string]$Display.Bounds }
    if ($null -ne $Display.RefreshHz) { $bits += "$($Display.RefreshHz) Hz" }
    if ($null -ne $Display.ScalePercent) { $bits += "$($Display.ScalePercent)% scaling" }
    return ($bits -join ', ')
}

function Resolve-GfxNoDisplay {
    <#
    .SYNOPSIS
        Which of the arrangement's displays NeurOptimal's window is on.
    .DESCRIPTION
        Matched on the MONITOR DEVICE NAME the window scan reads from
        MonitorFromWindow, not on rectangle arithmetic: the two readings come
        from different APIs and a mixed-DPI desktop can make their coordinates
        disagree. A window whose monitor could not be read resolves to $null
        and renders as unread -- never as the primary display, which is exactly
        how a two-screen run would come to look like a one-screen one.
    .OUTPUTS
        The display record, or $null.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Arrangement, [AllowNull()]$NoWindow)

    if (-not $Arrangement -or -not $NoWindow) { return $null }
    $dev = [string]$NoWindow.MonitorDevice
    if ([string]::IsNullOrWhiteSpace($dev)) { return $null }
    foreach ($d in @($Arrangement.Displays)) {
        if ([string]$d.GdiName -eq $dev) { return $d }
    }
    return $null
}

function Format-GfxDisplaySetupLines {
    <#
    .SYNOPSIS
        The display block the guide and the report both print, as
        @{ Key, Text, Level } rows.
    .DESCRIPTION
        ONE renderer for the arrangement, called by the bench window and by the
        report, so the screen and the package can never describe the desktop
        differently. Nothing is decided here that the arrangement did not
        already say.
    .PARAMETER NoDisplay
        The display NeurOptimal's window is on, from Resolve-GfxNoDisplay.
        $null renders as not read, never as "the primary one".
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Arrangement,
        [AllowNull()]$NoDisplay,
        [AllowNull()][string]$NoDisplayReason
    )

    $dash = [string][char]0x2014
    if (-not $Arrangement) {
        $rows = @(@{ Key = 'Setup'; Level = 'Unknown'; Text = 'Display setup: could not be read' })
        return ,$rows
    }

    $rows = @()
    $level = switch ($Arrangement.Layout) { 'Unknown' { 'Unknown' } 'NoDisplays' { 'Unknown' } default { 'Info' } }
    $rows += @{ Key = 'Setup'; Level = $level; Text = "Display setup: $($Arrangement.LayoutText)" }

    $active = @($Arrangement.Displays)
    if ($active.Count -eq 0) {
        $rows += @{ Key = 'Active'; Level = 'Unknown'; Text = "Active display: $dash" }
    } else {
        foreach ($d in $active) {
            $kind = if ($d.Internal -eq $true) { 'built-in' } elseif ($d.Internal -eq $false) { 'external' } else { 'kind unknown' }
            $tail = if ($d.Connection -and $d.Internal -eq $false) { ", $($d.Connection)" } else { '' }
            $rows += @{ Key = 'Active'; Level = 'Info'
                        Text = "Active display: $(Format-GfxDisplayLabel -Display $d) ($kind$tail)" }
            # NEUROPTIMAL'S OWN LABEL FOR THE SAME SCREEN. Its monitor picker
            # says 'Display 1 - Generic PnP Monitor - 3840 x 1080' where this
            # tool says 'PHL 499P9'. A tester choosing a screen in that dialog
            # is reading NeurOptimal's words, so both are printed and the
            # tester is not left matching them by guesswork.
            if ($null -ne $d.DisplayNumber) {
                # THE PICKER LISTS THE PHYSICAL MODE, not the desktop size.
                # Captured verbatim 2026-09-18 with the dropdown open:
                #   Display 1 - Generic PnP Monitor - 3840 x 1080
                #   Display 2 - Surface Panel - 2400 x 1600 (Main display)
                # The second line settles it: that panel is 2400x1600 physical
                # and 1600x1067 in desktop coordinates, and the picker shows
                # the former. Printing the desktop size here would hand the
                # tester a number that appears nowhere in the dialog they are
                # looking at.
                $asNo = "Display $($d.DisplayNumber)"
                if ($d.DeviceString) { $asNo += " - $($d.DeviceString)" }
                if ($d.Bounds) { $asNo += " - $(($d.Bounds -replace 'x', ' x '))" }
                if ($d.Primary) { $asNo += ' (Main display)' }
                $rows += @{ Key = 'ActiveAsNo'; Level = 'Info'
                            Text = "   NeurOptimal calls it: $asNo" }
            }
        }
    }

    $bText = "Built-in display: $($Arrangement.BuiltIn.StateText)"
    if ($Arrangement.BuiltIn.State -eq 'Active') {
        $bText = "Built-in display: Active $dash $(Format-GfxDisplayLabel -Display $Arrangement.BuiltIn.Display)"
    }
    $rows += @{ Key = 'BuiltIn'; Level = $(if ($Arrangement.BuiltIn.State -eq 'Unknown') { 'Unknown' } else { 'Info' }); Text = $bText }

    $noText = "NeurOptimal location: $dash"
    $noLevel = 'Unknown'
    if ($NoDisplay) {
        $where = if ($NoDisplay.Internal -eq $true) { 'Built-in screen' } elseif ($NoDisplay.Internal -eq $false) { 'External display' } else { 'A display of unknown kind' }
        $noText = "NeurOptimal location: $where $dash $(Format-GfxDisplayLabel -Display $NoDisplay)"
        $noLevel = 'Info'
    } elseif ($NoDisplayReason) {
        $noText = "NeurOptimal location: $NoDisplayReason"
    }
    $rows += @{ Key = 'NoLocation'; Level = $noLevel; Text = $noText }

    foreach ($e in @($Arrangement.Errors)) {
        $rows += @{ Key = 'Error'; Level = 'Unknown'; Text = "Display arrangement, partly unread: $e" }
    }
    return ,$rows
}

function Test-GfxExternalDisconnected {
    <#
    .SYNOPSIS
        Whether any external display is still CONNECTED -- a different question
        from whether one is in use, and one Windows often cannot answer.
    .DESCRIPTION
        'Built-in screen only' is a statement about what is being DRAWN TO. An
        external monitor that is plugged in and switched off satisfies it, and
        a test whose point is to control the screen cannot let that through
        silently.

        THREE ANSWERS, AND THE MIDDLE ONE IS THE COMMON CASE.

          NotYet   an external target was enumerated as connected and unused.
                   A reading, and a definite one: unplug it.
          Ok       either nothing is connected AND the query demonstrated it can
                   answer, or the operator has confirmed it by hand.
          Unknown  nothing was enumerated and nothing proved the query could
                   have enumerated it. Measured on the reference box: a laptop
                   with its lid shut reports no internal target in EITHER query,
                   so silence here is not evidence. This is where the operator
                   confirmation belongs -- a person can see the back of the
                   machine and Windows cannot.

        The confirmation is ATTESTED, never measured, and the distinction rides
        into the package in the check's Detail so a reader can tell one from the
        other later.
    .PARAMETER OperatorConfirmed
        The tester has stated, in the window, that no external display is
        connected. Only ever upgrades Unknown to Ok; it can never overrule a
        monitor the tool actually saw.
    .OUTPUTS
        Hashtable: State, Detail, Fix, Text.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Arrangement,
        [bool]$OperatorConfirmed = $false
    )

    $text = 'No external display connected'
    if (-not $Arrangement) {
        return @{ State = 'Unknown'; Detail = 'not read'; Fix = $null; Text = $text }
    }

    $connected = @($Arrangement.ExternalConnected)
    $inUse = @(@($Arrangement.Displays) | Where-Object { $_.Internal -eq $false })

    # An external display that is IN USE is the layout check's business, not
    # this one's. Reporting it twice would put one fault in a tester's list
    # under two different instructions.
    if ($connected.Count -gt 0) {
        $names = @($connected | ForEach-Object { if ($_.Name) { $_.Name } else { 'an external display' } })
        return @{ State  = 'NotYet'
                  Detail = "$($connected.Count) connected but not in use: $($names -join ', ')"
                  Text   = $text
                  Fix    = "Unplug $($names -join ' and ') as well. It is connected but switched off, and this test compares recordings made with nothing else attached." }
    }

    if ($OperatorConfirmed) {
        return @{ State = 'Ok'; Detail = 'confirmed by the operator, not measured'; Fix = $null; Text = $text }
    }
    if ($Arrangement.ExternalConnectedKnown) {
        # The all-paths query DID return connected-but-unused targets, and none
        # of them was external. That is the one case where silence is a reading:
        # the query demonstrated it can answer and answered 'none'.
        return @{ State = 'Ok'; Detail = 'none reported connected'; Fix = $null; Text = $text }
    }
    # EVERYTHING ELSE IS UNKNOWN, including a desktop already driving an
    # external display. It is tempting to argue that a query which enumerated
    # one external target can see them all -- but the target it enumerated was
    # ACTIVE, and the question here is about targets that are not. A monitor
    # connected and asleep is exactly the thing that goes unenumerated, so the
    # argument proves nothing about the case it is being used on.
    return @{ State  = 'Unknown'
              Text   = $text
              Detail = 'Windows did not report any disconnected display, which is not the same as none being attached'
              Fix    = $null }
}

function Test-GfxDisplaySetupMatch {
    <#
    .SYNOPSIS
        Whether an arrangement is the one a test asks for, and -- when it is
        not -- the one sentence that tells a tester how to get there.
    .DESCRIPTION
        ONE PLACE, TWO CALLERS. The readiness checklist asks this before the
        run, while it can still be fixed, and the deviation pass asks it again
        afterwards from the arrangement recorded in the package. Splitting it
        would be two opinions about the same desktop, which is how a checklist
        comes to disagree with the report it produced.

        THREE ANSWERS, not two: an arrangement that could not be read is not a
        failed requirement, so State is 'Unknown' and there is no Fix -- there
        is nothing for the tester to do about a reading that did not happen.
    .PARAMETER Want
        'BuiltInOnly' or 'ExternalOnly'.
    .OUTPUTS
        Hashtable: State ('Ok' | 'NotYet' | 'Unknown'), Detail, Fix, Text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Want,
        [AllowNull()]$Arrangement
    )

    $text = switch ($Want) {
        'BuiltInOnly'  { "Built-in screen only" }
        'ExternalOnly' { "One external display, built-in screen off" }
        default        { "Display setup: $Want" }
    }

    if (-not $Arrangement -or $Arrangement.Layout -eq 'Unknown') {
        $why = 'display setup not read'
        if ($Arrangement -and @($Arrangement.Errors).Count -gt 0) { $why = 'display setup could not be read' }
        elseif ($Arrangement -and $Arrangement.Layout -eq 'Unknown' -and @($Arrangement.Displays).Count -gt 0) {
            $why = 'one display would not say whether it is the built-in screen'
        }
        return @{ State = 'Unknown'; Detail = $why; Fix = $null; Text = $text }
    }

    $have = [string]$Arrangement.Layout
    $detail = [string]$Arrangement.LayoutText
    if ($have -eq $Want) { return @{ State = 'Ok'; Detail = $detail; Fix = $null; Text = $text } }

    # The fix names the SCREEN, not the count. "Disconnect the extra monitor"
    # is unusable advice to someone running one external display with the lid
    # shut: there is no extra monitor, and the one they have is the wrong one.
    $fix = switch ($Want) {
        'BuiltInOnly' {
            switch ($have) {
                'ExternalOnly'        { "This test measures the laptop's own screen. Disconnect the external display and open the lid, so the built-in screen is the only one in use." }
                'BuiltInPlusExternal' { "Disconnect the external display, so the built-in screen is the only one in use. A recording made with two screens cannot be compared with the other baseline recordings." }
                'MultipleExternal'    { "This test measures the laptop's own screen. Disconnect every external display and open the lid." }
                'NoDisplays'          { 'No display is active. Open the lid, or switch the built-in screen back on.' }
                default               { "Use the built-in screen only for this test." }
            }
        }
        'ExternalOnly' {
            switch ($have) {
                'BuiltInOnly'         { 'This test measures an external display. Connect the external monitor and switch the built-in screen off -- close the lid, or press Windows+P and choose Second screen only.' }
                'BuiltInPlusExternal' { 'Switch the built-in screen off so the external display is the only one in use -- close the lid, or press Windows+P and choose Second screen only.' }
                'MultipleExternal'    { 'This test uses ONE external display. Disconnect the others, and leave the built-in screen off.' }
                'NoDisplays'          { 'No display is active. Connect the external display.' }
                default               { 'Use one external display, with the built-in screen off.' }
            }
        }
        default { "Set the display setup to $Want." }
    }
    return @{ State = 'NotYet'; Detail = $detail; Fix = $fix; Text = $text }
}

# ---------------------------------------------------------------------------
# TEST PROFILES -- the protocol a run was collected under
# ---------------------------------------------------------------------------
#
# The 2026-09-18 Vivobook campaign produced five runs from three boxes and only
# one of them was poolable, for reasons that had nothing to do with the tool:
#
#   * The instruction said "maximize" without saying WHEN. Every tester
#     maximized NO a few seconds AFTER pressing Start watching, so the idle
#     baseline was measured on a small pane and the session on a full-screen
#     one. The headline delta (+21 to +28 points of 3D) was then mostly window
#     AREA, not session cost: inside one session arm the same butterchurn read
#     ~16% windowed and ~40% maximized, and the reference box -- held windowed
#     throughout -- reported a session delta of exactly 0.
#   * The instruction said "single monitor". One box ran both attempts with an
#     external display attached, which changes the cohort key, so its numbers
#     could not be pooled with the other two.
#
# Neither is a measurement bug. Both are the protocol travelling in prose that
# the tool never saw. A PROFILE is that prose turned into data: the steps the
# tester is shown, the requirements the tool checks BEFORE the run, and the
# deviations it records in the package afterwards.
#
# ADDING THE NEXT TEST IS A DATA CHANGE. Append a hashtable here -- the window's
# dropdown, the console's -ProfileId, the readiness checklist, the deviation
# finding and the manifest field all read this registry and need no edit. The
# two already named for later are a dual-monitor arm (Requires.MonitorCount = 2)
# and a video arm (Requires.SessionKind = 'Video', which expects the decode
# engines to be non-zero instead of structurally zero).

function Get-GraphicsBenchProfiles {
    <#
    .SYNOPSIS
        Every test profile this bench knows.
    .DESCRIPTION
        One row per test. The PROCEDURE is the test: an ordered list of steps,
        each with the words the tester reads and the GATE that must hold before
        the window lets them past it. Steps[] is derived from it, verbatim, for
        the console and the "View all steps" list -- there is no second copy of
        the protocol in prose.

        Requires is what the tool can CHECK after the run; a requirement it
        cannot observe is left out rather than asserted.

        GATE KINDS (read by Get-GraphicsBenchStepView):
          Checks        readiness checks, by Key, that must read Ready
          Confirm       an attestation the tester ticks -- ATTESTED, never
                        measured, and recorded as such with its timestamp
          Info          nothing to verify; Next moves on
          Start         Next is Start watching; passes once the baseline is in
          SessionStart  passes when the session is detected
          Mark          Next is the typed transition mark MarkIndex
          SessionRun    the measured stretch; stops by itself at Session Complete
          FreeRun       an exploratory stretch; Stop whenever
        A step may carry Checks AND Confirm; both must hold.
    .OUTPUTS
        Array of hashtables: Id, Name, Summary, Procedure[], Steps[], Phrases,
        Requires, IsDefault.

        RETURNED ',$profiles', so a registry that ever holds one profile does
        not unroll to a bare hashtable. ASSIGN IT FIRST -- '@(Get-...Profiles)'
        yields ONE element holding the whole list, which is this repo's oldest
        trap and was caught here by the suite.
    #>
    [CmdletBinding()]
    param()

    # A middle dot, built rather than typed. These files are BOM-less UTF-8 and
    # Windows PowerShell 5.1 reads them as ANSI, so a literal non-ASCII glyph in
    # a string would arrive on a field box as mojibake.
    $dot = [string][char]0x00B7

    # THE TWO FULL-SCREEN CONTROLS ARE DIFFERENT ACTIONS and are named
    # separately everywhere below. NeurOptimal's own full-screen control is set
    # BEFORE watching starts and decides the size of the pane both arms are
    # measured at. The separate VISUALIZER full-screen button only exists once a
    # session is running, detaches the visuals onto a display of their own, and
    # is therefore a different experiment -- one whose manual transition lands
    # in the middle of the measurement. Telling a tester "put it full screen"
    # without saying which control is how a baseline recording turns into an
    # unlabelled detached-visualizer recording.
    $noFullScreenStep = "Put the NeurOptimal window full screen NOW, before the next step. The baseline and the session have to be the same size on the same screen, or the numbers measure the window instead of the session."
    $leaveVisualizerStep = "Leave the visualizer inside NeurOptimal. Do NOT use the separate visualizer full-screen button -- that is a different test, with its own entry in this list."
    $quietStep = 'Close everything else -- no browser, no screen recorder, no video call. Only NeurOptimal and this window.'
    $launchStep = 'Launch NeurOptimal and leave it on its home screen, with no session started.'
    $watchStep = 'Press Start watching, then leave NeurOptimal alone until it says Baseline collected.'
    # THE SESSION LENGTHS. NeurOptimal's Quick Session is 15:00 of audio; the
    # regular session -- the one Configure Session offers by default -- is
    # 33:00. Every scored test exists at both lengths with the same steps and
    # gates: only the session type chosen and the length it is judged against
    # differ. Each length is its own profile, and so its own protocol version,
    # because a 15-minute run and a 33-minute run do not pool.
    #
    # THE 15-MINUTE WORDS ARE THE ONES ea2cad2 SHIPPED, character for
    # character. The protocol version is a hash of them; rewording them would
    # split the baseline runs already collected from the ones still to come.
    # Type is how the session type reads inside a sentence ("the session type
    # was probably not ..."); Choose is the instruction for Configure Session.
    #
    # LISTED 33 FIRST, and the 33-minute built-in test is the default: the
    # regular session is the one NeurOptimal is normally run with, so it is
    # what the dropdown opens on (user decision, 2026-09-25). The order of
    # this list is the order of the dropdown.
    $lengths = @(
        @{ Minutes = 33; Sec = 1980; Type = 'the regular 33-minute session'; Title = 'Start a 33-minute session'
           Choose = 'leave the session type on the regular 33-minute session (the default)' }
        @{ Minutes = 15; Sec = 900; Type = 'Quick Session'; Title = 'Start a Quick Session'
           Choose = 'set the session type to "Quick Session"' }
    )

    # THE DETACHED TEST'S STEADY STRETCH IS SHORTER THAN THE SESSION. The
    # recording ends where NeurOptimal ends the session -- at the session's
    # length, counted from the music -- and the steady stretch only starts at
    # the second mark. So every second spent before that mark comes out of it,
    # and a floor equal to the session length can never be met: the first
    # field run of this test (2026-09-24, run 3C7ACD84) did everything asked
    # and would still have been failed for it. The test therefore gives the
    # tester this long after the music starts to detach the visuals, and
    # judges the steady stretch against the session length MINUS it.
    $detachWindowSec = 180
    $detachMinutes = [int]($detachWindowSec / 60)

    # THE STEPS SHARED BY EVERY SCORED TEST, as records. One definition each:
    # a gate typed twice is a gate that drifts between the two tests that are
    # supposed to be comparable.
    $stepQuiet = @{ Id = 'close-others'; Title = 'Close other programs'; Text = $quietStep
                    Gate = @{ Kind = 'Confirm'; Confirm = 'Only NeurOptimal and this window are open' } }
    $stepLaunch = @{ Id = 'launch'; Title = 'Open NeurOptimal'; Text = $launchStep
                     Gate = @{ Kind = 'Checks'; Checks = @('NoRunning'); Confirm = 'NeurOptimal is on its home screen, with no session started' } }
    # THE SESSION TYPE IS PART OF THE TEST, and it is chosen in NeurOptimal's
    # Configure Session dialog -- the dialog that starts the session. So it is
    # part of the session-start step, AFTER the baseline, not a step of its
    # own before it: opening Configure Session early is clicking through
    # NeurOptimal during the stretch the session is measured against, and
    # on SP9 (run 1A7A0385, 2026-09-23) opening it 8 s into the baseline ended
    # the baseline at 8 s. It is not ticked: the bench is behind a full-screen
    # NeurOptimal by then. It is VERIFIED instead -- only the chosen session
    # type ends with Session Complete at the test's length, and
    # EndsAtSessionComplete scores a run that did not as a departure.
    $stepWatch = @{ Id = 'baseline'; Title = 'Measure the baseline'; Text = $watchStep; Gate = @{ Kind = 'Start' } }
    $stepVisualizer = @{ Id = 'visualizer-inside'; Title = 'Leave the visualizer inside NeurOptimal'; Text = $leaveVisualizerStep; Gate = @{ Kind = 'Info' } }

    $audioPhrases = @{
        Baseline = 'Leave NeurOptimal on its home screen.'
        Ready    = 'Baseline collected. Start your audio-only session in NeurOptimal.'
        Session  = 'Keep the window and the screens unchanged.'
    }

    # SessionLengthSec and SessionType sit OUTSIDE Requires on purpose: they
    # are what the window and the reports say, not what is scored, and
    # Requires is hashed into the protocol version.
    $baselines = @()
    $detached = @()
    foreach ($len in $lengths) {
        $m = [int]$len.Minutes
        $sessionStartStep = "Open Configure Session in NeurOptimal, $($len.Choose), and start the session with audio only (a music track, no video)."
        $sessionRunStep = "Let the session run for $m minutes. Do not resize, move or minimize the NeurOptimal window, and do not connect or disconnect a screen, while it runs. When NeurOptimal shows Session Complete the recording stops by itself and the package is sent."
        $stepSessionStart = @{ Id = 'session-start'; Title = [string]$len.Title; Text = $sessionStartStep; Gate = @{ Kind = 'SessionStart' } }
        $stepSessionRun = @{ Id = 'session-run'; Title = 'Let the session run'; Text = $sessionRunStep; Gate = @{ Kind = 'SessionRun' } }
        $longer = $(if ($m -eq 15) { '' } else { " Run over NeurOptimal's regular $m-minute session." })

        $baselines += @{
            Id        = "baseline-audio-$m-builtin"
            Name      = "Audio baseline $dot $m minutes $dot Built-in screen"
            Summary   = "The first recording a laptop makes on its own screen, so results can be compared across machines.$longer"
            IsDefault = ($m -eq 33)
            SessionLengthSec = [double]$len.Sec
            SessionType      = [string]$len.Type
            Procedure = @(
                @{ Id = 'screens'; Title = 'Use the built-in screen only'
                   Text = "Disconnect every external monitor -- unplug it, do not just switch it off -- and open the lid, so the laptop's built-in screen is the only display in use."
                   Gate = @{ Kind = 'Checks'; Checks = @('DisplaySetup', 'ExternalDisconnected'); ShowDisplays = $true } }
                $stepQuiet
                $stepLaunch
                @{ Id = 'full-screen'; Title = 'Put NeurOptimal full screen'
                   Text = "$noFullScreenStep It must be full screen on the built-in screen."
                   Gate = @{ Kind = 'Checks'; Checks = @('ScreenCoverage') } }
                $stepVisualizer
                $stepWatch
                $stepSessionStart
                $stepSessionRun
            )
            # One short sentence per phase, in the tester's words. The phase
            # line on screen is composed from these plus live progress, so the
            # instruction a tester reads mid-run is never assembled in the
            # window -- the same discipline the numbers follow.
            Phrases   = @{
                Prepare  = 'Put NeurOptimal full screen on the built-in screen before starting the recording.'
                Baseline = $audioPhrases.Baseline
                Ready    = $audioPhrases.Ready
                Session  = $audioPhrases.Session
            }
            Requires  = @{
                DisplaySetup       = 'BuiltInOnly'
                ScreenCoverage     = 'Full'
                SessionKind        = 'Audio'
                SessionMinSec      = [int]$len.Sec
                # THE SESSION ENDS WHERE NEUROPTIMAL ENDS IT. A recording
                # stopped by hand ends wherever the tester happened to press,
                # and two runs of one test then end by different rules.
                EndsAtSessionComplete = $true
                VisualizerAttached    = $true
                VisualizerSameDisplay = $true
            }
        }
        $baselines += @{
            Id        = "baseline-audio-$m-external"
            Name      = "Audio baseline $dot $m minutes $dot External screen"
            Summary   = "The same recording made on one external display with the built-in screen off. A separate test, because the screen it is made on changes the numbers.$longer"
            IsDefault = $false
            SessionLengthSec = [double]$len.Sec
            SessionType      = [string]$len.Type
            Procedure = @(
                @{ Id = 'screens'; Title = 'Use one external display only'
                   Text = 'Use ONE external display, with the built-in screen off -- close the lid, or press Windows+P and choose Second screen only. Unplug any other monitor rather than leaving it connected and dark.'
                   Gate = @{ Kind = 'Checks'; Checks = @('DisplaySetup', 'ExternalDisconnected'); ShowDisplays = $true } }
                $stepQuiet
                $stepLaunch
                @{ Id = 'full-screen'; Title = 'Put NeurOptimal full screen'
                   Text = "$noFullScreenStep It must be full screen on the external display."
                   Gate = @{ Kind = 'Checks'; Checks = @('ScreenCoverage') } }
                $stepVisualizer
                $stepWatch
                $stepSessionStart
                $stepSessionRun
            )
            Phrases   = @{
                Prepare  = 'Put NeurOptimal full screen on the external display before starting the recording.'
                Baseline = $audioPhrases.Baseline
                Ready    = $audioPhrases.Ready
                Session  = $audioPhrases.Session
            }
            Requires  = @{
                DisplaySetup       = 'ExternalOnly'
                ScreenCoverage     = 'Full'
                SessionKind        = 'Audio'
                SessionMinSec      = [int]$len.Sec
                # THE SESSION ENDS WHERE NEUROPTIMAL ENDS IT. A recording
                # stopped by hand ends wherever the tester happened to press,
                # and two runs of one test then end by different rules.
                EndsAtSessionComplete = $true
                VisualizerAttached    = $true
                VisualizerSameDisplay = $true
            }
        }

        $steadyMinutes = $m - $detachMinutes
        $detached += @{
            Id        = "visualizer-detached-$m"
            Name      = "Detached visualizer $dot $m minutes"
            Summary   = "What the separate visualizer full-screen button costs. Its own test, because detaching the visuals is a manual step in the middle of the measurement -- so the recording is cut around it and only the steady stretch after the visuals settle is compared.$longer"
            IsDefault = $false
            SessionLengthSec = [double]$len.Sec
            SessionType      = [string]$len.Type
            Procedure = @(
                @{ Id = 'screens'; Title = 'Set up the screens'
                   Text = 'Set up the screens you want to test, and leave them alone for the whole recording.'
                   Gate = @{ Kind = 'Confirm'; Confirm = 'The screens are set up and will not be changed during the recording'; ShowDisplays = $true } }
                $stepQuiet
                $stepLaunch
                @{ Id = 'full-screen'; Title = 'Put NeurOptimal full screen'; Text = "$noFullScreenStep"
                   Gate = @{ Kind = 'Checks'; Checks = @('ScreenCoverage') } }
                $stepWatch
                $stepSessionStart
                @{ Id = 'mark-start'; Title = 'Detach the visualizer'
                   Text = "As soon as the music is playing, press Mark transition start, then use the separate visualizer full-screen button. NeurOptimal asks which monitor to use -- pick it by the Display number this window shows beside each screen, then press OK. Be done within $detachMinutes minutes of the music starting: the session still ends at $m minutes, and at least $steadyMinutes of them have to come after the visuals settle."
                   Gate = @{ Kind = 'Mark'; MarkIndex = 0 } }
                @{ Id = 'mark-ready'; Title = 'Mark the visuals ready'
                   Text = 'Press Mark visuals ready as soon as the visuals are settled on their display. The stretch between the two is reported on its own and is kept out of the comparison.'
                   Gate = @{ Kind = 'Mark'; MarkIndex = 1 } }
                @{ Id = 'session-run'; Title = 'Let the session run'
                   Text = "Let the session run until NeurOptimal shows Session Complete -- at least $steadyMinutes minutes after the second mark. The recording then stops by itself and the package is sent."
                   Gate = @{ Kind = 'SessionRun' } }
            )
            Phrases   = @{
                Prepare  = 'Put NeurOptimal full screen before starting the recording.'
                Baseline = $audioPhrases.Baseline
                Ready    = 'Baseline collected. Start your audio-only session, then mark and detach the visualizer as soon as the music plays.'
                Session  = 'Press Mark transition start, then detach the visualizer.'
            }
            # THE MARKERS ARE A REQUIREMENT, not a suggestion. Without them the
            # recording has no boundary between the manual transition and the
            # steady period, so the stretch it claims to measure cannot be
            # located -- which is exactly what the first version of this test
            # shipped: instructions that promised a split nothing implemented.
            #
            # SessionMinSec is checked against the STEADY arm, which the
            # summariser cuts at the second marker -- hence the session length
            # minus the detach window. No DisplaySetup and no
            # VisualizerSameDisplay: the arrangement is the POINT of this test,
            # so it is recorded rather than demanded. VisualizerDetached is the
            # one thing it does demand: a run whose visuals never left
            # NeurOptimal measured the baseline, not this.
            Requires  = @{
                ScreenCoverage     = 'Full'
                SessionKind        = 'Audio'
                SessionMinSec      = [int]$len.Sec - $detachWindowSec
                EndsAtSessionComplete = $true
                TransitionMarkers  = $true
                VisualizerDetached = $true
            }
        }
    }

    # Grouped BY LENGTH -- built-in, external, detached -- so each length's
    # tests sit together in the dropdown, in the order of $lengths.
    $scored = @($baselines) + @($detached)
    $grouped = @()
    foreach ($len in $lengths) { $grouped += @($scored | Where-Object { [double]$_.SessionLengthSec -eq [double]$len.Sec }) }
    $profiles = @($grouped) + @(
        @{
            Id        = 'exploratory'
            Name      = 'Exploratory recording'
            Summary   = 'A free-form recording. Nothing is checked before it and nothing is scored after it -- use it to reproduce something, not to add this machine to the comparison.'
            IsDefault = $false
            Procedure = @(
                @{ Id = 'baseline'; Title = 'Start watching'
                   Text = 'Press Start watching before whatever you want to observe begins, and leave NeurOptimal alone until it says Baseline collected, so the recording still has something to measure against.'
                   Gate = @{ Kind = 'Start' } }
                @{ Id = 'free-run'; Title = 'Record'
                   Text = 'Do whatever you want to observe, then press Stop and show results when you are done.'
                   Gate = @{ Kind = 'FreeRun' } }
            )
            Phrases   = @{
                Prepare  = 'Press Start watching before whatever you want to observe begins.'
                Baseline = 'Leave NeurOptimal alone while the baseline is measured.'
                Ready    = 'Baseline collected. Go ahead with whatever you wanted to observe.'
                Session  = 'Recording.'
            }
            Requires  = @{}
        }
    )

    # Steps[] is the procedure's words, in order. Derived, never typed: the
    # list a tester reads in "View all steps" and the console is the same text
    # the step-by-step window walks them through.
    foreach ($p in $profiles) {
        $p.Steps = @(@($p.Procedure) | ForEach-Object { [string]$_.Text })
    }
    return ,$profiles
}

function Get-GraphicsBenchProfileForArrangement {
    <#
    .SYNOPSIS
        The test that matches the machine's CURRENT display setup, so the
        window opens on the one the tester is already set up for.
    .DESCRIPTION
        A convenience, never a decision: the tester can pick any test in the
        dropdown, and an arrangement that matches nothing leaves the registry
        default selected rather than guessing. It exists because the two
        baseline tests differ only in the screen they are made on, and opening
        on the wrong one puts a fixable-looking failure in front of someone
        whose setup is already correct for the other test.
    .OUTPUTS
        The profile, or the registry default when nothing matches.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Arrangement)

    $all = Get-GraphicsBenchProfiles
    if ($Arrangement -and $Arrangement.Layout -and $Arrangement.Layout -ne 'Unknown') {
        foreach ($p in $all) {
            if (-not $p.Requires) { continue }
            if (-not $p.Requires.ContainsKey('DisplaySetup')) { continue }
            if ([string]$p.Requires.DisplaySetup -eq [string]$Arrangement.Layout) { return $p }
        }
    }
    return (Get-GraphicsBenchProfile)
}


function Get-GraphicsBenchProfile {
    <#
    .SYNOPSIS
        One profile by Id, or the default when Id is absent or unknown.
    .DESCRIPTION
        An unknown Id resolves to the default rather than throwing: a stale
        shortcut or a mistyped -ProfileId must never be the reason a field run
        does not happen. A caller that cares can compare the returned Id.
    #>
    [CmdletBinding()]
    param([string]$Id)

    $all = Get-GraphicsBenchProfiles
    if ($Id) {
        foreach ($p in $all) { if ($p.Id -eq $Id) { return $p } }
    }
    foreach ($p in $all) { if ($p.IsDefault) { return $p } }
    return $all[0]
}

function Test-GraphicsBenchReadiness {
    <#
    .SYNOPSIS
        Whether the machine is in the shape the selected test asks for, RIGHT
        NOW -- before the recording starts, while it can still be fixed.
    .DESCRIPTION
        Checks only what is observable without touching anything: what the
        display arrangement is, whether NeurOptimal is running, and how its
        window is placed. SessionKind cannot be known before the session
        starts, so it is not checked here; it is judged after the run from the
        decode engines. The screen the visuals land on is the same -- there is
        nothing to read until a session has drawn something.

        THE DISPLAY CHECK IS AN ARRANGEMENT, NOT A COUNT. "One monitor" is
        satisfied identically by a laptop's own 14" panel and by a 49" external
        monitor with the lid shut, and those two recordings are not comparable:
        butterchurn renders the whole pane, so its cost follows pixel count.
        The old count check therefore passed the largest confound while
        reporting it as controlled. -MonitorCount is still accepted for a
        profile that asks for a bare count, and no shipped profile does.

        EVERY INPUT IS PASSED IN AND NONE IS CACHED. The caller re-reads the
        display count and the window placement each time it asks, because both
        change while the tester is preparing: the whole value of this check is
        that it is true at the moment Start is pressed, and a cached answer is
        a check that congratulates someone for a monitor they just plugged
        back in.

        'Unknown' is a distinct state from 'NotYet'. A requirement the tool
        could not read must not render as a failed one -- the same em-dash rule
        every number in this module follows.
    .PARAMETER MonitorCount
        Displays connected right now. Prefer Get-GfxLiveDisplayCount over the
        inventory's copy, which is a snapshot from when the window opened.
    .PARAMETER Arrangement
        The display arrangement RIGHT NOW, from Get-GfxDisplayArrangement.
        Passed in for the same reason every other reading is: it changes while
        the tester is preparing, and a cached copy is a check that congratulates
        someone for a screen they just switched off.
    .PARAMETER NoWindow
        NO's primary window as Select-GfxPrimaryNoWindow returns it, or $null
        when NeurOptimal is not running yet.
    .PARAMETER NoRunning
        Whether NeurOptimal is running RIGHT NOW, from Get-GfxNoRunning. The
        inventory's PID is a snapshot from when the window opened and stays
        'running' after the tester closes NeurOptimal, which is how the guide
        came to tell someone everything was set while the thing being measured
        was gone.
    .OUTPUTS
        Hashtable: Status ('Ready' | 'NeedsAttention' | 'CouldNotVerify'), Ok
        (Status -eq 'Ready'), Checks[] (@{ Key, Text, State, Label, Detail,
        Fix }), Unmet[] (the Fix sentences), Unverified[] (what could not be
        read).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$BenchProfile,
        $Inventory,
        $NoWindow,
        $MonitorCount,
        $NoRunning,
        $Arrangement,
        # The operator has stated that nothing else is plugged in. ATTESTED,
        # never measured -- it can only upgrade a reading that did not happen,
        # never overrule a monitor the tool actually saw.
        [bool]$NoOtherDisplaysConfirmed = $false
    )

    if (-not $BenchProfile) { $BenchProfile = Get-GraphicsBenchProfile }
    $req = $BenchProfile.Requires
    if (-not $req) { $req = @{} }

    # 'Ready' / 'Needs attention' / 'Could not check'. Words, not brackets: an
    # '[x]' beside an instruction reads as a ticked checkbox to half the people
    # who see it, which is the opposite of what it means.
    $labelOf = @{ Ok = 'Ready'; NotYet = 'Needs attention'; Unknown = 'Could not check' }

    $checks = @()
    $unmet = @()
    $unverified = @()

    # THE DISPLAY ARRANGEMENT, first, because it is the one the tester has to
    # physically change and the one every other reading depends on: a window
    # cannot be full screen on the right display until the right display is the
    # one in use.
    if ($req.ContainsKey('DisplaySetup')) {
        $m = Test-GfxDisplaySetupMatch -Want ([string]$req.DisplaySetup) -Arrangement $Arrangement
        $checks += @{ Key = 'DisplaySetup'; Text = $m.Text; State = $m.State; Label = $labelOf[$m.State]
                      Detail = $m.Detail; Fix = $m.Fix }
        if ($m.Fix) { $unmet += $m.Fix }
        if ($m.State -eq 'Unknown') { $unverified += 'the display setup could not be read' }

        # WHAT IS PLUGGED IN, which the layout above does not answer. A test
        # that asks for one screen is asking about the machine, not only about
        # the desktop, and an external monitor connected-but-off satisfies the
        # layout exactly. Windows usually cannot prove absence here, so the
        # third answer is a question for the operator rather than a silent pass.
        $c = Test-GfxExternalDisconnected -Arrangement $Arrangement -OperatorConfirmed $NoOtherDisplaysConfirmed
        $checks += @{ Key = 'ExternalDisconnected'; Text = $c.Text; State = $c.State; Label = $labelOf[$c.State]
                      Detail = $c.Detail; Fix = $c.Fix
                      # The window turns this into a confirmation the operator
                      # can tick. Nothing else in the checklist can be answered
                      # by a person, so nothing else carries it.
                      OperatorCanConfirm = ($c.State -eq 'Unknown')
                      OperatorConfirmed  = ($c.State -eq 'Ok' -and $NoOtherDisplaysConfirmed) }
        if ($c.Fix) { $unmet += $c.Fix }
        if ($c.State -eq 'Unknown') { $unverified += 'whether an external display is still connected could not be read -- confirm it by hand in the window' }
    }

    if ($req.ContainsKey('MonitorCount')) {
        $want = [int]$req.MonitorCount
        $have = $null
        # A caller that PASSED -MonitorCount has spoken, even when it passed
        # $null: that means its live read failed, and the answer is 'could not
        # check', not the count from when the window opened. Falling back there
        # let a stale 1 report Ready while nothing current was known at all.
        # The inventory is only for a caller with no live reader of its own.
        if ($PSBoundParameters.ContainsKey('MonitorCount')) {
            if ($null -ne $MonitorCount) { $have = [int]$MonitorCount }
        } elseif ($Inventory -and $null -ne $Inventory.MonitorCount) {
            $have = [int]$Inventory.MonitorCount
        }
        $state = 'Unknown'
        $detail = 'display count not read'
        $fix = $null
        if ($null -ne $have) {
            $detail = "$have connected"
            $state = if ($have -eq $want) { 'Ok' } else { 'NotYet' }
            if ($state -eq 'NotYet') {
                $fix = if ($have -gt $want) {
                    "Disconnect the extra monitor -- $have are connected and this test uses $want. A recording made with $have cannot be compared with the other baseline recordings."
                } else {
                    "Connect $want monitors -- $have is connected and this test uses $want."
                }
            }
        }
        $text = if ($want -eq 1) { 'One monitor only' } else { "$want monitors connected" }
        $checks += @{ Key = 'MonitorCount'; Text = $text; State = $state; Label = $labelOf[$state]; Detail = $detail; Fix = $fix }
        if ($fix) { $unmet += $fix }
        if ($state -eq 'Unknown') { $unverified += 'the number of connected displays could not be read' }
    }

    # LIVE, when the caller can answer it. Falling back to the inventory's PID
    # is only for a caller that has no live reader -- and that fallback is
    # exactly what let the guide say 'Everything is set' after NeurOptimal had
    # been closed, so it is recorded as unverified rather than as running.
    $noState = 'Unknown'
    $noDetail = 'could not tell whether NeurOptimal is running'
    if ($null -ne $NoRunning) {
        $noState = if ([bool]$NoRunning) { 'Ok' } else { 'NotYet' }
        $noDetail = if ([bool]$NoRunning) { 'running' } else { 'not running' }
    } elseif ($NoWindow) {
        $noState = 'Ok'; $noDetail = 'running'
    } elseif ($Inventory -and $Inventory.No -and $Inventory.No.Pid) {
        $noState = 'Unknown'; $noDetail = 'last seen running when this window opened'
    }
    $noFix = if ($noState -eq 'NotYet') { 'Launch NeurOptimal and leave it on its home screen -- there is nothing to measure until it is running.' } else { $null }
    $checks += @{ Key = 'NoRunning'; Text = 'NeurOptimal is running'; State = $noState; Label = $labelOf[$noState]
                  Detail = $noDetail; Fix = $noFix }
    if ($noFix) { $unmet += $noFix }
    if ($noState -eq 'Unknown') { $unverified += 'whether NeurOptimal is running could not be confirmed' }

    if ($req.ContainsKey('WindowMode')) {
        $want = [string]$req.WindowMode
        $have = $null
        if ($NoWindow -and $NoWindow.Mode) { $have = [string]$NoWindow.Mode }
        $state = 'Unknown'
        $detail = 'window not found'
        $fix = $null
        if ($have) {
            $detail = "currently $($have.ToLower())"
            $state = if ($have -eq $want) { 'Ok' } else { 'NotYet' }
            if ($state -eq 'NotYet') {
                # The mode name is a past participle ('Maximized'); an
                # instruction needs the verb, so the two are not the same
                # string and must not be interpolated as if they were.
                $verb = switch ($want) {
                    'Maximized'  { 'Maximize' }
                    'FullScreen' { 'Put into full screen' }
                    'Windowed'   { 'Restore down' }
                    'Minimized'  { 'Minimize' }
                    default      { "Set to $want" }
                }
                $fix = "$verb the NeurOptimal window now. Doing it after the recording starts is too late: the baseline is measured at whatever size the window is when you press Start."
            }
        }
        # The check NAMES the requirement; the timing lives in the Fix, which
        # is what a tester is shown while they can still act on it. 'before you
        # start' in the check itself reads as stale eight minutes into a
        # recording, where the same line is still on screen.
        $checks += @{ Key = 'WindowMode'; Text = "NeurOptimal $($want.ToLower())"; State = $state; Label = $labelOf[$state]; Detail = $detail; Fix = $fix }
        if ($fix) { $unmet += $fix }
        if ($state -eq 'Unknown') { $unverified += "the NeurOptimal window's placement could not be read" }
    }

    # SCREEN COVERAGE, not a shell mode name. What confounds the measurement is
    # window AREA, and the requirement is written against the thing that
    # matters so it holds whichever placement NeurOptimal's own full-screen
    # control produces -- showCmd 3, which is indistinguishable from the shell's
    # Maximize, or a borderless rect, which reads as FullScreen. The observed
    # mode is carried in the DETAIL beside it, so the question of which one NO
    # actually produces is answered by field readings instead of by this check
    # having guessed.
    if ($req.ContainsKey('ScreenCoverage')) {
        $have = $null
        if ($NoWindow) {
            if ($null -ne $NoWindow.CoversScreen) {
                $have = [bool]$NoWindow.CoversScreen
            } elseif ($NoWindow.Mode -and [string]$NoWindow.Mode -ne 'Unknown') {
                # A window record from before coverage was measured -- and any
                # caller that passes a bare Mode -- still answers, from the
                # mode alone. Derived, not invented: these are exactly the two
                # modes Get-GfxWindowMode marks as covering the screen.
                $have = (@('Maximized', 'FullScreen') -contains [string]$NoWindow.Mode)
            }
        }
        $state = 'Unknown'
        $detail = 'window not found'
        $fix = $null
        if ($null -ne $have) {
            $modeText = if ($NoWindow.Mode -and [string]$NoWindow.Mode -ne 'Unknown') { [string]$NoWindow.Mode.ToLower() } else { 'unnamed placement' }
            $sizeText = ''
            if ($NoWindow.Bounds -and $NoWindow.MonitorBounds) { $sizeText = " ($($NoWindow.Bounds) of $($NoWindow.MonitorBounds))" }
            $detail = if ($have) { "currently $modeText$sizeText" } else { "currently $modeText$sizeText, not covering the screen" }
            $state = if ($have) { 'Ok' } else { 'NotYet' }
            if (-not $have) {
                $fix = 'Put the NeurOptimal window full screen now, using NeurOptimal''s own full-screen control -- not the separate visualizer one. Doing it after the recording starts is too late: the baseline is measured at whatever size the window is when you press Start.'
            }
        }
        # WHAT THIS CHECK DOES AND DOES NOT ESTABLISH, said where it is read.
        # The pixels are measured; which control produced them is not, and a
        # tester who put the window full screen from the title bar instead of
        # from NeurOptimal's own control would see the same Ready. So the
        # instruction stays explicit in the steps, and the check says plainly
        # that it cannot confirm which one was used.
        $checks += @{ Key = 'ScreenCoverage'; Text = 'NeurOptimal fills the screen'; State = $state; Label = $labelOf[$state]
                      Detail = $detail; Fix = $fix
                      Caveat = $(if ($state -eq 'Ok') { "size measured; $script:GfxAppFullScreenReason" } else { $null }) }
        if ($fix) { $unmet += $fix }
        if ($state -eq 'Unknown') { $unverified += "the NeurOptimal window's placement could not be read" }
    }

    # THREE ANSWERS, not two. 'Ok' used to mean only 'nothing explicitly
    # failed', so a check the tool could not read at all still let the guide
    # say everything was set. An unreadable requirement is not a passing one.
    $status = 'Ready'
    if ($unmet.Count -gt 0) { $status = 'NeedsAttention' }
    elseif ($unverified.Count -gt 0) { $status = 'CouldNotVerify' }

    return @{ Status = $status; Ok = ($status -eq 'Ready'); Checks = $checks
              Unmet = @($unmet); Unverified = @($unverified) }
}

function Get-GfxNoRunning {
    <#
    .SYNOPSIS
        Whether NeurOptimal is running RIGHT NOW.
    .DESCRIPTION
        One process lookup. The inventory's PID answers 'was it running when
        this window opened', which is a different question and the wrong one:
        a tester who closes NeurOptimal after opening the bench went on being
        told the setup was fine.

        Returns $null when the lookup itself failed, which renders as 'Could
        not check' rather than as 'not running'.
    #>
    [CmdletBinding()]
    param()

    try { return ([bool](@(Get-Process -Name 'NO' -ErrorAction SilentlyContinue).Count -gt 0)) }
    catch { return $null }
}

function Get-GfxLiveDisplayCount {
    <#
    .SYNOPSIS
        Displays connected RIGHT NOW.
    .DESCRIPTION
        SystemInformation.MonitorCount is GetSystemMetrics(SM_CMONITORS) and is
        never cached, unlike Screen::AllScreens, which holds its array until a
        display-change message is pumped. The readiness check is asked once a
        second while a tester is unplugging a monitor, so a cached count would
        keep telling them the thing they just fixed is still wrong.

        Returns $null when it cannot be read, which renders as 'Could not
        check' rather than as a failed requirement.
    #>
    [CmdletBinding()]
    param()

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        return [int][System.Windows.Forms.SystemInformation]::MonitorCount
    } catch { return $null }
}

function Get-GfxLiveNoWindow {
    <#
    .SYNOPSIS
        NO's primary window placement RIGHT NOW, for the readiness checklist,
        before any sampler exists.
    .DESCRIPTION
        The sampler learns NO's window mode once a second, but the check that
        matters most -- "is NO maximized BEFORE you press Start watching" --
        has to be answerable while nothing is running yet. This walks the same
        scan and the same two pure classifiers the sampler does rather than
        adding a second opinion about what 'Maximized' means.

        Read-only and cheap: one window enumeration. Returns $null when NO is
        not running or has no visible top-level window, which the readiness
        check renders as 'not read yet', never as a failed requirement.
    .OUTPUTS
        The Get-GfxWindowMode record, or $null.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Initialize-GfxWindowScan)) { return $null }
        $proc = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue | Sort-Object StartTime) | Select-Object -First 1
        if (-not $proc) { return $null }
        $rows = [WinConfigDiag.GfxWindowScan]::Scan($proc.Id)
        if (-not $rows) { return $null }
        $parsed = ConvertFrom-GfxWindowScanRows -Rows $rows
        $titles = @{}
        foreach ($nw in @($parsed.NoWindows)) { if ($null -ne $nw.Hwnd) { $titles[[long]$nw.Hwnd] = [string]$nw.Title } }
        return (Select-GfxPrimaryNoWindow -Geometry @($parsed.Geometry) -Titles $titles)
    } catch { return $null }
}

function Get-GraphicsBenchPhase {
    <#
    .SYNOPSIS
        Where the tester is in the test, and the ONE thing to do next.
    .DESCRIPTION
        Seven numbered instructions on screen at once is a reference card, not
        guidance: a tester four minutes into a baseline has to re-find their
        place in it every time they look up. This collapses the test to the
        single phase they are in and the single sentence that applies, with
        live progress where there is any. The full list stays one click away.

        THE WORDS COME FROM THE PROFILE, not from here and not from the window.
        This composes them with measured progress; it never invents an
        instruction, so a new test in the registry is guided without touching
        a renderer.

        Phases: Prepare -> Baseline -> ReadyForSession -> Recording -> Results.
    .OUTPUTS
        Hashtable: Key, Title, Instruction, Level.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$BenchProfile,
        [ValidateSet('NotStarted', 'Watching', 'Stopped')]
        [string]$RunPhase = 'NotStarted',
        $Readiness,
        $IdleSec,
        $SessionSec,
        [bool]$SessionDetected = $false,
        # NO announced the session over (its 'Session Complete' dialog). The
        # clock stops here: a progress line that keeps counting past the end
        # tells a tester the session is still running when it is not.
        [bool]$SessionEnded = $false,
        [bool]$StartedMidSession = $false,
        # For a test that brackets a manual transition: which of its two marks
        # the operator has pressed. The clock does not start until the second.
        [bool]$TransitionStarted = $false,
        [bool]$VisualsReady = $false,
        [string]$OutcomeText,
        [double]$IdleFloorSec = $script:GfxIdleFloorSec
    )

    if (-not $BenchProfile) { $BenchProfile = Get-GraphicsBenchProfile }
    $phrases = $BenchProfile.Phrases
    if (-not $phrases) { $phrases = @{} }
    $dash = [string][char]0x2014

    if ($RunPhase -eq 'Stopped') {
        $text = 'Recording complete.'
        if ($OutcomeText) { $text = "Recording complete. $OutcomeText" }
        return @{ Key = 'Results'; Title = 'RESULTS'; Level = 'Healthy'
                  Instruction = "$text Use Open run folder for the package to send." }
    }

    if ($RunPhase -eq 'NotStarted') {
        # The first thing standing in the way, in the tester's words, straight
        # from the check that failed. When nothing is in the way the phase says
        # so rather than repeating a step they have already done.
        $firstFix = $null
        if ($Readiness) { $firstFix = @($Readiness.Unmet) | Select-Object -First 1 }
        if ($firstFix) {
            return @{ Key = 'Prepare'; Title = 'PREPARE'; Level = 'Degraded'; Instruction = [string]$firstFix }
        }
        # 'Everything is set' REQUIRES Status 'Ready', not merely the absence
        # of a failure. A check the tool could not read is not a check that
        # passed, and saying so was how the guide came to reassure a tester
        # who had closed NeurOptimal.
        if ($Readiness -and $Readiness.Status -eq 'CouldNotVerify') {
            $why = @($Readiness.Unverified) | Select-Object -First 1
            $text = "Setup could not be checked"
            if ($why) { $text = "Setup could not be checked $dash $why." }
            return @{ Key = 'Prepare'; Title = 'PREPARE'; Level = 'Unknown'
                      Instruction = "$text You can still start, and what could not be checked is recorded in the package." }
        }
        $ready = [string]$phrases['Prepare']
        if ($Readiness -and $Readiness.Status -eq 'Ready') { $ready = 'Everything is set. Press Start watching, then leave NeurOptimal alone.' }
        return @{ Key = 'Prepare'; Title = 'PREPARE'; Level = 'Unknown'; Instruction = $ready }
    }

    # Watching.
    if ($StartedMidSession) {
        return @{ Key = 'Recording'; Title = 'RECORDING'; Level = 'Degraded'
                  Instruction = "NeurOptimal was already busy when the recording started, so there is no baseline to measure against $dash this recording will report totals only." }
    }

    # NO said the session is over. One instruction left, and no clock.
    if ($SessionEnded) {
        return @{ Key = 'SessionEnded'; Title = 'SESSION COMPLETE'; Level = 'Healthy'
                  Instruction = 'Session ended. Press Stop and show results.' }
    }

    # A TEST WITH A BRACKETED TRANSITION HAS THREE INSTRUCTIONS INSIDE THE
    # SESSION, not one, and the clock does not start until the last of them.
    # Showing "Session recorded: 02:14 of 15:00" while the tester is still
    # dragging a window between screens would be counting the wrong stretch --
    # which is precisely what the summariser refuses to do, so the guide must
    # not do it either.
    if ($SessionDetected -and $BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('TransitionMarkers') -and [bool]$BenchProfile.Requires.TransitionMarkers) {
        $kinds = Get-GfxTransitionMarkerKinds
        if (-not $TransitionStarted) {
            return @{ Key = 'MarkTransition'; Title = 'DETACH THE VISUALIZER'; Level = 'Unknown'
                      Instruction = [string]$kinds[0].Instruction }
        }
        if (-not $VisualsReady) {
            return @{ Key = 'InTransition'; Title = 'TRANSITION'; Level = 'Unknown'
                      Instruction = [string]$kinds[1].Instruction }
        }
        # Past the second mark: the ordinary progress line, clocked from there.
    }

    if ($SessionDetected) {
        $target = $null
        if ($BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('SessionMinSec')) { $target = [double]$BenchProfile.Requires.SessionMinSec }
        $done = 0.0
        if ($null -ne $SessionSec) { $done = [double]$SessionSec }
        $progress = if ($null -ne $target) {
            "Session recorded: {0} of {1}." -f (Format-GraphicsClock $done), (Format-GraphicsClock $target)
        } else {
            "Session recorded: {0}." -f (Format-GraphicsClock $done)
        }
        return @{ Key = 'Recording'; Title = 'RECORD SESSION'; Level = 'Healthy'
                  Instruction = ("{0} {1}" -f $progress, [string]$phrases['Session']).Trim() }
    }

    $idle = 0.0
    if ($null -ne $IdleSec) { $idle = [double]$IdleSec }
    if ($idle -ge $IdleFloorSec) {
        return @{ Key = 'ReadyForSession'; Title = 'READY FOR SESSION'; Level = 'Healthy'
                  Instruction = [string]$phrases['Ready'] }
    }
    return @{ Key = 'Baseline'; Title = 'MEASURE BASELINE'; Level = 'Unknown'
              Instruction = ("{0} Baseline: {1} of {2} seconds." -f [string]$phrases['Baseline'], [int][math]::Floor($idle), [int]$IdleFloorSec).Trim() }
}

function Get-GraphicsBenchProtocolVersion {
    <#
    .SYNOPSIS
        A short fingerprint of the procedure a run followed.
    .DESCRIPTION
        TWO RUNS ARE COMPARABLE ONLY IF THEY FOLLOWED THE SAME STEPS. The test
        Id says which test was selected; it does not change when a step's
        wording or gate does, and a reworded step is a different instruction to
        the tester. The fingerprint covers the Id, every step's words and gate,
        and the requirements, so any change to what a tester was told or
        checked on produces a new version -- and runs are pooled by it.

        Hashed from a canonical string (keys sorted), never from a serialiser
        whose field order is not promised.
    .OUTPUTS
        Twelve lowercase hex characters.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$BenchProfile)

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("id=$($BenchProfile.Id)")
    foreach ($s in @($BenchProfile.Procedure)) {
        if (-not $s) { continue }
        $g = $s.Gate
        if (-not $g) { $g = @{} }
        $gateText = (@($g.Keys | Sort-Object) | ForEach-Object { "$_=$(@($g[$_]) -join ',')" }) -join ';'
        $parts.Add("step=$($s.Id)|$($s.Text)|$gateText")
    }
    $req = $BenchProfile.Requires
    if ($req) {
        foreach ($k in @($req.Keys | Sort-Object)) { $parts.Add("req=$k=$($req[$k])") }
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    return (-join ($hash[0..5] | ForEach-Object { $_.ToString('x2') }))
}

function Get-GraphicsBenchStepView {
    <#
    .SYNOPSIS
        What the step-by-step window shows for ONE step, and whether the tester
        may move past it.
    .DESCRIPTION
        THE SAME STEPS, IN THE SAME ORDER, ON EVERY BOX. Datasets from different
        testers are only comparable if the procedure was the same, and a list of
        instructions on screen does not make it the same -- people skim, reorder
        and skip. So the window shows one step at a time, and Next stays
        disabled until that step's GATE holds:

          * what the tool can MEASURE (the display setup, NeurOptimal running,
            its window filling the screen) is checked live, and
          * what it cannot (other programs closed, the home screen) is a tick
            the tester gives -- ATTESTED, never measured, and logged with its
            time so a reader can tell the two apart.

        A gate that does not hold can still be passed with "Continue anyway",
        which the window records as an override. It asks, it does not block:
        the operator is the testing team, and the package says what departed.

        Once recording starts the gates are the run's own milestones -- the
        baseline collected, the session detected, the marks pressed -- and the
        window moves on BY ITSELF, so nobody's timing decides when a stretch
        begins. AdvanceTo says where to; it skips a milestone that has already
        happened (a session started before the baseline was in, or a recording
        started mid-session) rather than stranding the tester on it.

        PURE. Every input is passed in; the window owns no wording and no rule.
    .OUTPUTS
        Hashtable: Id, Number, Total, Stage ('Prepare'|'Recording'|'Results'),
        StepLabel, Title, Instruction, Level, Items[] (@{ Text; State }),
        ShowDisplays, Passed, ConfirmKey, ConfirmText, Confirmed, NextText,
        NextAction ('Advance'|'Start'|'Mark'|'Stop'|'Restart'), NextEnabled,
        BackEnabled, OverrideOffered, StopEarlyOffered, AdvanceTo (index or
        $null), AutoStop, Regressions[].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$BenchProfile,
        [int]$Index = 0,
        $Readiness,
        # Ticks the tester has given, by ConfirmKey.
        [hashtable]$Confirmed = @{},
        # Steps the tester chose to pass with "Continue anyway", by step Id.
        [hashtable]$Overridden = @{},
        [ValidateSet('NotStarted', 'Watching', 'Stopped')]
        [string]$RunPhase = 'NotStarted',
        $IdleSec,
        $SessionSec,
        [bool]$SessionDetected = $false,
        [bool]$SessionEnded = $false,
        [bool]$StartedMidSession = $false,
        [int]$TransitionStep = 0,
        [string]$OutcomeText,
        [string]$OutcomeLevel,
        # What happened to the package: sent, kept on this PC, or not sent
        # and why. Said on the Results step because the tester's next move
        # depends on it, and a log line nobody opens is not telling them.
        [string]$SendText,
        [string]$SendLevel,
        [double]$IdleFloorSec = $script:GfxIdleFloorSec,
        # How long past the session length to wait for Session Complete before
        # telling the tester the session type was probably not the one asked for.
        [double]$SessionCompleteGraceSec = 120,
        # How much baseline was measured before the session started, once it
        # has. Below the floor the card says so while the run can still be
        # abandoned and redone, not only in the report fifteen minutes later.
        $BaselineSec
    )

    $steps = @($BenchProfile.Procedure | Where-Object { $null -ne $_ })
    $results = @{ Id = 'results'; Title = 'Results'; Text = ''; Gate = @{ Kind = 'Results' } }
    $all = @($steps) + @($results)
    $total = $all.Count
    if ($RunPhase -eq 'Stopped') { $Index = $total - 1 }
    if ($Index -lt 0) { $Index = 0 }
    if ($Index -ge $total) { $Index = $total - 1 }
    $step = $all[$Index]
    $gate = $step.Gate
    if (-not $gate) { $gate = @{ Kind = 'Info' } }
    $kind = [string]$gate.Kind

    $checksByKey = @{}
    if ($Readiness) { foreach ($c in @($Readiness.Checks)) { if ($c -and $c.Key) { $checksByKey[[string]$c.Key] = $c } } }
    $target = $null
    if ($BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('SessionMinSec')) { $target = [double]$BenchProfile.Requires.SessionMinSec }
    $markKinds = Get-GfxTransitionMarkerKinds

    # A step's gate, judged against the readiness checks and the ticks. Used
    # for the current step AND for the earlier ones, so a setup undone after
    # its step was passed is reported rather than silently carried into the
    # recording.
    $judgePrepare = {
        param($S)
        $g = $S.Gate
        if (-not $g) { $g = @{} }
        $items = @()
        $ok = $true
        $unreadable = $false
        $fix = $null
        $firstBad = $null
        foreach ($key in @($g.Checks)) {
            if (-not $key) { continue }
            $c = $checksByKey[[string]$key]
            # A check the selected test does not declare is not this step's
            # business: the registry's Requires decides what is checked.
            if (-not $c) { continue }
            $items += @{ Text = ("{0,-16}{1}  ({2})" -f $c.Label, $c.Text, $c.Detail); State = [string]$c.State }
            if ($c.State -ne 'Ok') {
                $ok = $false
                if ($c.State -eq 'Unknown') { $unreadable = $true }
                if (-not $fix -and $c.Fix) { $fix = [string]$c.Fix }
                if (-not $firstBad) { $firstBad = "$($c.Text) -- $($c.Label.ToLower())" }
            }
        }
        $confirmKey = $null
        $confirmText = $null
        # THE ONE CHECK A PERSON CAN ANSWER AND WINDOWS CANNOT, carried by the
        # check itself: 'no external display connected' is usually unreadable,
        # and the tester can look at the back of the machine.
        $ext = $null
        if (@($g.Checks) -contains 'ExternalDisconnected') { $ext = $checksByKey['ExternalDisconnected'] }
        if ($ext -and ($ext.OperatorCanConfirm -or $ext.OperatorConfirmed)) {
            $confirmKey = 'no-other-displays'
            $confirmText = 'I have checked: no other display is plugged in'
        } elseif ($g.Confirm) {
            $confirmKey = "confirm:$($S.Id)"
            $confirmText = "I confirm: $([string]$g.Confirm)"
            if (-not [bool]$Confirmed[$confirmKey]) { $ok = $false }
        }
        return @{ Items = $items; Ok = $ok; Unreadable = $unreadable; Fix = $fix; FirstBad = $firstBad; ConfirmKey = $confirmKey; ConfirmText = $confirmText }
    }

    # Recording milestones. A step already satisfied is skipped over, so a
    # session that started while the baseline was still being measured does
    # not leave the tester staring at "Start the session".
    $satisfied = {
        param($S)
        $k = [string]$S.Gate.Kind
        switch ($k) {
            'Start'        { return ($RunPhase -eq 'Watching' -and ($StartedMidSession -or $SessionDetected -or ($null -ne $IdleSec -and [double]$IdleSec -ge $IdleFloorSec))) }
            'SessionStart' { return ($StartedMidSession -or $SessionDetected) }
            'Mark'         { return ($TransitionStep -gt [int]$S.Gate.MarkIndex) }
            default        { return $false }
        }
    }

    $view = @{
        Id = [string]$step.Id; Number = $Index + 1; Total = $total
        Title = [string]$step.Title; Instruction = [string]$step.Text; Level = 'Unknown'
        Items = @(); ShowDisplays = [bool]$gate.ShowDisplays; Passed = $false
        ConfirmKey = $null; ConfirmText = $null; Confirmed = $false
        NextText = 'Next'; NextAction = 'Advance'; NextEnabled = $false
        BackEnabled = $false; OverrideOffered = $false; StopEarlyOffered = $false
        StopEarlyKind = $null; StopEarlyText = $null
        AdvanceTo = $null; AutoStop = $false; Regressions = @()
    }
    $prepKinds = @('Checks', 'Confirm', 'Info')
    $stage = if ($kind -eq 'Results') { 'Results' } elseif ($RunPhase -eq 'Watching') { 'Recording' } else { 'Prepare' }
    $view.Stage = $stage
    $view.StepLabel = "STEP $($Index + 1) OF $total"

    if ($prepKinds -contains $kind) {
        $j = & $judgePrepare $step
        $view.Items = @($j.Items)
        $view.ConfirmKey = $j.ConfirmKey
        $view.ConfirmText = $j.ConfirmText
        if ($j.ConfirmKey) { $view.Confirmed = [bool]$Confirmed[$j.ConfirmKey] }
        $view.Passed = [bool]$j.Ok
        $view.NextEnabled = [bool]$j.Ok
        $view.BackEnabled = ($Index -gt 0)
        # Offered only when there is something to override. A tick the tester
        # has not given is not a check that failed -- it is theirs to give.
        $view.OverrideOffered = (-not $j.Ok -and @($j.Items | Where-Object { $_.State -ne 'Ok' }).Count -gt 0)
        $view.Level = if ($j.Ok) { 'Healthy' } else { 'Unknown' }
        if ($j.Fix) { $view.Items = @(@{ Text = $j.Fix; State = 'Hint' }) + @($view.Items) }

        # EARLIER STEPS THAT NO LONGER HOLD. Passing a step does not freeze the
        # machine: a tester who closes NeurOptimal on step 4 has undone step 3,
        # and the recording is about to be measured on the undone setup.
        for ($k = 0; $k -lt $Index; $k++) {
            $prev = $all[$k]
            if ($prepKinds -notcontains [string]$prev.Gate.Kind) { continue }
            if ([bool]$Overridden[[string]$prev.Id]) { continue }
            $pj = & $judgePrepare $prev
            if (-not $pj.Ok -and @($pj.Items | Where-Object { $_.State -ne 'Ok' }).Count -gt 0) {
                $what = if ($pj.Fix) { $pj.Fix } elseif ($pj.FirstBad) { $pj.FirstBad } else { 'it no longer checks out' }
                $view.Regressions += "Step $($k + 1) ($($prev.Title)) no longer holds -- $what"
            }
        }
        return $view
    }

    switch ($kind) {
        'Start' {
            if ($RunPhase -ne 'Watching') {
                # The last step before the measurement. Next IS Start watching,
                # and the window re-checks the whole setup at that press.
                $view.NextText = 'Start watching'
                $view.NextAction = 'Start'
                $view.NextEnabled = $true
                $view.BackEnabled = ($Index -gt 0)
                $unmet = @()
                if ($Readiness) { $unmet = @($Readiness.Unmet) }
                if ($unmet.Count -gt 0) {
                    $view.Items = @(@{ Text = "Not ready: $($unmet[0])"; State = 'NotYet' })
                    $view.Level = 'Degraded'
                } elseif ($Readiness -and $Readiness.Status -eq 'Ready') {
                    $view.Items = @(@{ Text = 'Every setup check is ready.'; State = 'Ok' })
                    $view.Level = 'Healthy'
                }
                $view.Instruction = [string]$step.Text
            } else {
                $view.NextEnabled = $false
                if ($null -eq $IdleSec) {
                    $view.Items = @(@{ Text = 'Waiting for NeurOptimal to appear...'; State = 'Unknown' })
                } else {
                    $view.Items = @(@{ Text = ("Baseline: {0} of {1} seconds. Do not touch anything." -f [int][math]::Floor([double]$IdleSec), [int]$IdleFloorSec); State = 'Unknown' })
                }
                $view.Instruction = 'Recording. Leave NeurOptimal on its home screen and do not touch anything while the baseline is measured.'
            }
        }
        'SessionStart' {
            $view.Items = @(@{ Text = 'Baseline collected. Waiting for the session to start...'; State = 'Ok' })
            $view.Level = 'Healthy'
        }
        'Mark' {
            $mi = [int]$gate.MarkIndex
            $view.NextText = [string]$markKinds[$mi].Label
            $view.NextAction = 'Mark'
            $view.NextEnabled = ($RunPhase -eq 'Watching')
            $view.Items = @(@{ Text = [string]$markKinds[$mi].Instruction; State = 'Unknown' })
        }
        'SessionRun' {
            $done = 0.0
            if ($null -ne $SessionSec) { $done = [double]$SessionSec }
            $reached = ($null -eq $target -or $done -ge $target)
            $progress = if ($null -ne $target) { "Session recorded: {0} of {1}." -f (Format-GraphicsClock $done), (Format-GraphicsClock $target) } else { "Session recorded: {0}." -f (Format-GraphicsClock $done) }
            $view.Items = @(@{ Text = $progress; State = $(if ($reached) { 'Ok' } else { 'Unknown' }) })
            $view.NextText = 'Stop and show results'
            $view.NextAction = 'Stop'
            $view.Level = 'Healthy'
            $waitForComplete = ($BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('EndsAtSessionComplete') -and [bool]$BenchProfile.Requires.EndsAtSessionComplete)
            if (-not $waitForComplete) {
                $view.NextEnabled = ($reached -or $SessionEnded)
                $view.StopEarlyOffered = -not $view.NextEnabled
                $view.StopEarlyKind = 'Early'
                $view.StopEarlyText = 'Stop early...'
            } elseif (-not $reached) {
                # Short of the length: stopping is possible, on the record.
                $view.StopEarlyOffered = $true
                $view.StopEarlyKind = 'Early'
                $view.StopEarlyText = 'Stop early...'
            } elseif (-not $SessionEnded) {
                # LONG ENOUGH, AND STILL NOT OVER. The end belongs to
                # NeurOptimal: a Quick Session shows Session Complete shortly
                # after this (24 s on SP9, 2026-09-23), and a hand-pressed Stop
                # would cut every run at a different moment. The one reason
                # Session Complete never comes is a session type that is not
                # Quick Session -- so that is what the way out is named for,
                # and after a grace period the card says to take it.
                $view.NextText = 'Waiting for Session Complete'
                $view.StopEarlyOffered = $true
                $view.StopEarlyKind = 'NoSessionComplete'
                $view.StopEarlyText = 'Session Complete did not appear - stop now...'
                $over = $done - [double]$target
                # A TEST WHOSE CLOCK STARTS AFTER THE MUSIC reaches its target
                # before the session is over: the detached test clocks from
                # the second mark, up to the detach window into the session.
                # That slack is added to the grace, or a tester who detached
                # promptly would be told the session type was wrong while
                # NeurOptimal was still, correctly, playing.
                $grace = $SessionCompleteGraceSec
                if ($BenchProfile.SessionLengthSec -and [double]$BenchProfile.SessionLengthSec -gt [double]$target) { $grace += [double]$BenchProfile.SessionLengthSec - [double]$target }
                $sessionType = $(if ($BenchProfile.SessionType) { [string]$BenchProfile.SessionType } else { 'the session type this test asks for' })
                $targetMinutes = [int][math]::Round([double]$target / 60)
                if ($over -ge $grace) {
                    $view.Instruction = ("Session Complete has not appeared {0} after the {1} minutes. The session type was probably not {2}: press 'Session Complete did not appear - stop now'. The recording will be kept and marked as not following the test." -f (Format-GraphicsClock $over), $targetMinutes, $sessionType)
                    $view.Level = 'Degraded'
                } else {
                    $view.Instruction = ('The {0} minutes are recorded. Leave everything alone and wait for NeurOptimal to show Session Complete -- the recording then stops by itself and the package is sent.' -f $targetMinutes)
                }
            }
            if ($SessionEnded) {
                # NO said the session is over. The recording stops itself, so
                # the end of the measured stretch is NeurOptimal's, not the
                # moment somebody noticed.
                $view.Instruction = 'NeurOptimal says the session is complete. Stopping the recording and sending the package...'
                $view.AutoStop = $true
            }
        }
        'FreeRun' {
            $done = 0.0
            if ($null -ne $SessionSec) { $done = [double]$SessionSec }
            $view.Items = @(@{ Text = ("Recording. Session recorded: {0}." -f (Format-GraphicsClock $done)); State = 'Unknown' })
            $view.NextText = 'Stop and show results'
            $view.NextAction = 'Stop'
            $view.NextEnabled = $true
        }
        'Results' {
            $view.Title = 'Results'
            # The way back to step 1 for the next recording, on the same
            # button every other step uses to move on.
            $view.NextText = 'Start a new recording'
            $view.NextAction = 'Restart'
            $view.NextEnabled = $true
            $sendLine = if ($SendText) { $SendText } else { 'Sending the package...' }
            $view.Instruction = if ($OutcomeText) { "Recording complete. $OutcomeText $sendLine" } else { "Recording complete. $sendLine" }
            $view.Level = if ($OutcomeLevel) { $OutcomeLevel } else { 'Healthy' }
            # A package that did not arrive outranks a clean result: the
            # recording is only useful once it has been sent.
            if ($SendLevel -and $SendLevel -ne 'Healthy') { $view.Level = 'Degraded' }
        }
    }

    # THE BASELINE WAS CUT SHORT. NeurOptimal left its home screen before the
    # floor -- a session started early, or Configure Session opened during the
    # baseline -- and the recording has too little to measure against. Said on
    # every recording step after it, because the tester can still stop and
    # start again; the report would only say it once the session was over.
    if ($RunPhase -eq 'Watching' -and $null -ne $BaselineSec -and @('SessionStart', 'Mark', 'SessionRun') -contains $kind -and [double]$BaselineSec -lt $IdleFloorSec) {
        $view.Regressions += ("The baseline was cut short: NeurOptimal left its home screen after {0} s, and the baseline needs {1} s. This recording will be marked as not comparable -- stop it and start a new recording, and leave NeurOptimal alone until the baseline is collected." -f [int][math]::Floor([double]$BaselineSec), [int]$IdleFloorSec)
        $view.Level = 'Degraded'
    }

    # Already past this milestone? Move to the first step that is not.
    if ($RunPhase -eq 'Watching' -and (& $satisfied $step)) {
        $to = $Index + 1
        while ($to -lt ($total - 1) -and (& $satisfied $all[$to])) { $to++ }
        $view.AdvanceTo = $to
    }
    return $view
}

function Get-GraphicsBenchProfileOutcome {
    <#
    .SYNOPSIS
        What this run is entitled to claim about the test it followed.
    .DESCRIPTION
        FOUR OUTCOMES, BECAUSE 'no deviations' IS NOT 'requirements met'. The
        first version of this printed 'Protocol followed' whenever the
        deviation list came back empty -- which it also does for an
        exploratory run that was never scored, and for a run where the window
        placement was never readable or no session ever started, so nothing
        could be checked. Three different situations reading as a pass is how
        an unusable recording gets pooled.

          Met            every requirement was checked and held
          NotMet         at least one was checked and did not hold
          CouldNotVerify nothing departed, but something could not be read
          Exploratory    the test declares no requirements
          Unscored       the run predates test profiles

        NotMet outranks CouldNotVerify: a known departure is a stronger fact
        than an unreadable one.
    .OUTPUTS
        Hashtable: Key, Text, Level, Deviations[], Unverifiable[].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Summary,
        [hashtable]$BenchProfile
    )

    $dash = [string][char]0x2014
    $devs = @($Summary.ProfileDeviations | Where-Object { $null -ne $_ })

    if (-not $Summary.ProfileId) {
        return @{ Key = 'Unscored'; Level = 'Unknown'; Deviations = @(); Unverifiable = @()
                  Text = 'No test was recorded for this run, so it was not checked against one.' }
    }

    $req = $null
    if ($BenchProfile) { $req = $BenchProfile.Requires }
    if (-not $req -or $req.Count -eq 0) {
        return @{ Key = 'Exploratory'; Level = 'Unknown'; Deviations = @(); Unverifiable = @()
                  Text = "Exploratory $dash not assessed for comparison with other baseline recordings." }
    }

    # What could not be READ, as opposed to what was read and was wrong.
    $unverifiable = @()
    if ($req.ContainsKey('MonitorCount') -and $null -eq $Summary.MonitorCount) {
        $unverifiable += 'the number of connected displays was not recorded'
    }
    if ($req.ContainsKey('DisplaySetup')) {
        $layout = $null
        if ($Summary.DisplayArrangement) { $layout = [string]$Summary.DisplayArrangement.Layout }
        if (-not $layout -or $layout -eq 'Unknown') { $unverifiable += 'the display setup was not recorded, so the screen this was measured on is unknown' }
    }
    if ($req.ContainsKey('ScreenCoverage')) {
        $cov = $null
        if ($Summary.WindowMode) { $cov = $Summary.WindowMode.SessionCoversScreen }
        if ($null -eq $cov) { $unverifiable += "the NeurOptimal window's placement could not be read during the session" }
        elseif ($Summary.WindowMode -and $null -eq $Summary.WindowMode.IdleCoversScreen) {
            $unverifiable += "the NeurOptimal window's placement could not be read while the baseline was measured"
        }
    }
    # ATTACHMENT, when it could not be read, is UNVERIFIED -- not passed, and
    # not failed. A window handle that did not come through is no evidence that
    # the tester pressed a button they were told not to press, so it never
    # becomes a deviation; and it is not a reading either, so it cannot be
    # counted as one. It blocks no recording: this is scored after the fact,
    # and the run is already on disk by the time anyone reads it.
    if ($req.ContainsKey('VisualizerAttached')) {
        $att = $null
        if ($Summary.Visualizer) { $att = [string]$Summary.Visualizer.Attachment }
        # 'NotShown' for the whole run is not a pass: the pane was never on
        # screen, so nothing was established about where it would have been.
        if (-not $att -or $att -eq 'Unknown' -or $att -eq 'NotShown') {
            $unverifiable += 'whether the visuals were left inside NeurOptimal could not be read'
        }
    }
    if ($req.ContainsKey('VisualizerSameDisplay')) {
        $od = $null
        if ($Summary.Visualizer) { $od = $Summary.Visualizer.OnOtherDisplay }
        if ($null -eq $od) { $unverifiable += 'the screen the visuals were drawn on could not be read' }
    }
    if ($req.ContainsKey('WindowMode')) {
        $dom = $null; $idle = $null
        if ($Summary.WindowMode) { $dom = [string]$Summary.WindowMode.Dominant; $idle = [string]$Summary.WindowMode.IdleMode }
        if (-not $dom -or $dom -eq 'Unknown') { $unverifiable += "the NeurOptimal window's placement could not be read during the session" }
        elseif (-not $idle -or $idle -eq 'Unknown') { $unverifiable += "the NeurOptimal window's placement could not be read while the baseline was measured" }
    }


    if ($req.ContainsKey('SessionMinSec')) {
        $sec = $null
        if ($Summary.ArmDurationSec -and $null -ne $Summary.ArmDurationSec.Session) { $sec = [double]$Summary.ArmDurationSec.Session }
        # A zero-length or absent session arm used to slip past the length
        # check, which only fired for a session longer than nothing.
        if ($null -eq $sec -or $sec -le 0) { $unverifiable += 'no session was detected, so its length could not be checked' }
    }
    if ($req.ContainsKey('SessionKind')) {
        $measured = $false
        foreach ($surf in @($Summary.Surfaces | Where-Object { $_.Role -eq 'VideoJs' })) {
            if ($surf.Engines -and $surf.Engines.ContainsKey('VideoDecode') -and $null -ne $surf.Engines['VideoDecode'].Max) { $measured = $true }
        }
        if (-not $measured) { $unverifiable += 'video decode was not measured, so audio-only could not be confirmed' }
    }

    if ($devs.Count -gt 0) {
        return @{ Key = 'NotMet'; Level = 'Degraded'; Deviations = $devs; Unverifiable = $unverifiable
                  Text = "Requirements not met $dash this recording cannot be compared with other baseline recordings." }
    }
    if ($unverifiable.Count -gt 0) {
        return @{ Key = 'CouldNotVerify'; Level = 'Degraded'; Deviations = @(); Unverifiable = $unverifiable
                  Text = "Could not verify $dash $($unverifiable -join '; ')." }
    }
    return @{ Key = 'Met'; Level = 'Healthy'; Deviations = @(); Unverifiable = @()
              Text = 'Requirements met. This recording can be compared with other baseline recordings.' }
}

function Get-GraphicsBenchProfileDeviations {
    <#
    .SYNOPSIS
        Where a finished run departed from the profile it claimed to follow.
    .DESCRIPTION
        Judged from the summary alone, after the fact, so a run collected by
        either surface is scored the same way. Each deviation carries what was
        asked, what happened, and WHY it costs the run -- the reason is the part
        a tester acts on, and leaving it out is what produced five runs in one
        morning that could not be compared.

        A profile with no Requires returns nothing: an exploratory run cannot
        deviate from a protocol it never claimed.
    .OUTPUTS
        Array of hashtables: Key, Text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Summary,
        [hashtable]$BenchProfile
    )

    $out = @()
    if (-not $BenchProfile) { return ,$out }
    $req = $BenchProfile.Requires
    if (-not $req -or $req.Count -eq 0) { return ,$out }

    # The display layout CHANGED while recording. Raised before the count
    # itself, because a run that was 1 monitor at the start and 2 at the end
    # has no single layout to be compared against anything.
    # The observed counts are a SET -- sorted and de-duplicated -- so they carry
    # no order. Writing them as 'saw 1, then 2' invented a chronology the data
    # does not have, and would have read backwards for the common case of
    # unplugging a monitor mid-run.
    # THE SCREENS CHANGED while recording. A run that started on one screen and
    # finished on another has no single arrangement to be compared against
    # anything. The signatures are a SET -- sorted, de-duplicated -- so they
    # carry no order, and the text does not invent one.
    $sigs = @($Summary.DisplaySetupsObserved | Where-Object { $_ } | Sort-Object -Unique)
    if ($sigs.Count -gt 1) {
        $out += @{ Key    = 'DisplaySetupChanged'
                   Text   = "The screens changed while recording. Setups seen: $($sigs -join ' / '). This recording cannot be compared with the other baseline recordings."
                   Detail = "Display arrangement signature changed mid-run; the cohort key describes only the arrangement observed at the start." }
    }

    # The same event, told by COUNT. Raised only when the arrangement did NOT
    # already say it: plugging a monitor in moves both readings, and two rows
    # saying one thing in two vocabularies is a deviation list a tester reads as
    # two problems. The count still stands alone for a package recorded before
    # arrangements existed, which carries no signatures at all.
    # The observed counts are a SET too -- writing them as 'saw 1, then 2'
    # invented a chronology the data does not have, and read backwards for the
    # ordinary case of unplugging a monitor part-way through.
    $seen = @($Summary.MonitorCountsObserved | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    if ($seen.Count -gt 1 -and $sigs.Count -le 1) {
        $seenText = if ($seen.Count -eq 2) { $seen -join ' and ' } else { (($seen[0..($seen.Count - 2)]) -join ', ') + ' and ' + $seen[-1] }
        $out += @{ Key    = 'MonitorCountChanged'
                   Text   = "A monitor was connected or disconnected while recording. Observed monitor counts: $seenText. This recording cannot be compared with the other baseline recordings."
                   Detail = "Display count changed mid-run; the cohort key describes only the layout observed at the start." }
    }

    if ($req.ContainsKey('DisplaySetup')) {
        $want = [string]$req.DisplaySetup
        $arr = $Summary.DisplayArrangement
        if ($arr -and $arr.Layout -and $arr.Layout -ne 'Unknown') {
            $m = Test-GfxDisplaySetupMatch -Want $want -Arrangement $arr
            if ($m.State -eq 'NotYet') {
                $wantText = switch ($want) {
                    'BuiltInOnly'  { "the laptop's built-in screen" }
                    'ExternalOnly' { 'one external display, with the built-in screen off' }
                    default        { $want }
                }
                # NAMES THE SCREEN, not the number of them. The 49-inch case is
                # the reason this deviation exists: it satisfies "one monitor"
                # and is 3.2x the pixel area of a laptop panel, so the old
                # check called it a clean baseline.
                # EVERY screen, not the first one the sort happened to return:
                # on a two-screen desktop, naming one of them tells a tester
                # nothing about which one the tool objected to.
                $labels = @(@($arr.Displays) | ForEach-Object { Format-GfxDisplayLabel -Display $_ })
                $screenText = if ($labels.Count -gt 0) { $labels -join '; ' } else { 'not recorded' }
                $out += @{ Key    = 'DisplaySetup'
                           Text   = "This was recorded with $($arr.LayoutText.ToLower()) ($screenText); this test uses $wantText. A recording made on a different screen cannot be compared with the other baseline recordings."
                           Detail = "Display arrangement was $($arr.Layout), not $want. The visuals are drawn across the whole window, so the pixel area of the screen sets the load; the cohort key carries the arrangement and this package pools with other $($arr.Layout) runs." }
            }
        }
    }

    if ($req.ContainsKey('ScreenCoverage')) {
        $wm = $Summary.WindowMode
        $sessionCovers = $null
        $idleCovers = $null
        if ($wm) { $sessionCovers = $wm.SessionCoversScreen; $idleCovers = $wm.IdleCoversScreen }
        if ($sessionCovers -eq $false) {
            $out += @{ Key    = 'ScreenCoverage'
                       Text   = "The NeurOptimal window did not fill the screen during the session (it was $($wm.Dominant.ToLower())); this test needs it full screen."
                       Detail = "Session-arm dominant placement $($wm.Dominant) does not cover the monitor." }
        }
        # Covered in BOTH arms but not by the SAME shape: a full-screen session
        # measured against a maximized baseline differs by the taskbar strip,
        # which is small -- and is still recorded, because the whole point of
        # this test is that window area is the confound and nobody should have
        # to guess whether it was held constant.
        # THE AREA ITSELF, not the label. Both arms can answer 'covers the
        # screen' and still differ by a taskbar strip: measured on NO 4.0.0.9,
        # its own full-screen control leaves the window at 0.979 of the monitor
        # because it maximizes to the WORK AREA. A one-point difference in
        # covered area is a one-point difference in how much butterchurn has to
        # draw, and that is the confound this whole test exists to control.
        $idleFrac = $wm.IdleScreenFraction
        $sessFrac = $wm.SessionScreenFraction
        if ($null -ne $idleFrac -and $null -ne $sessFrac) {
            $drift = [math]::Abs([double]$sessFrac - [double]$idleFrac)
            if ($drift -ge 0.02) {
                $out += @{ Key    = 'CoverageAreaChanged'
                           Text   = "The NeurOptimal window covered $([math]::Round([double]$idleFrac * 100))% of the screen while the baseline was measured and $([math]::Round([double]$sessFrac * 100))% during the session, so the two were not the same size."
                           Detail = "Mean covered fraction $idleFrac idle vs $sessFrac session, a $([math]::Round($drift * 100, 1)) point difference in drawn area." }
            }
        }
        if ($sessionCovers -eq $true -and $idleCovers -eq $true -and
            $wm.IdleMode -and $wm.Dominant -and $wm.IdleMode -ne 'Unknown' -and $wm.Dominant -ne 'Unknown' -and $wm.IdleMode -ne $wm.Dominant) {
            $out += @{ Key    = 'CoverageShapeChanged'
                       Text   = "The NeurOptimal window filled the screen for both the baseline and the session, but in two different ways ($($wm.IdleMode.ToLower()), then $($wm.Dominant.ToLower())), so the two are not exactly the same size."
                       Detail = "Idle arm $($wm.IdleMode), session arm $($wm.Dominant): both cover the monitor, and they differ by the window chrome and any taskbar strip." }
        }
    }

    # THE VISUALS ON A SCREEN OF THEIR OWN. Detected, not asked about: the
    # separate visualizer full-screen button moves the visuals to another
    # display, and a baseline recording made that way measured two screens at
    # once. It is a DEVIATION for the baseline tests and no part of the
    # detached-visualizer test, which declares no such requirement.
    # SCORED ON THE SCREEN, which is observable. Whether the separate
    # visualizer control was used is NOT -- see
    # $script:GfxVisualizerAttachmentReason -- so it is recorded and not
    # scored. A recording made on two screens is unusable for the baseline
    # either way, which is the thing that actually had to be caught.
    # THE VISUALS IN A WINDOW OF THEIR OWN. Captured with both controls on
    # NO 4.0.0.9: attached, the pane is hosted by the window titled after
    # NeurOptimal; detached, by a separate visible window -- and in the capture
    # that window was MAXIMIZED ON THE SAME DISPLAY, so the screen comparison
    # below read 'same screen' and would have passed the run.
    if ($req.ContainsKey('VisualizerAttached') -and [bool]$req.VisualizerAttached) {
        $v = $Summary.Visualizer
        if ($v -and [string]$v.Attachment -eq 'OwnWindow') {
            $also = if ($v.OnOtherDisplay -eq $true) { ' on another screen' } elseif ($v.OnOtherDisplay -eq $false) { ' on the same screen' } else { '' }
            $out += @{ Key    = 'VisualizerDetached'
                       Text   = "The visuals were drawn in a window of their own$also. This test asks for them to be left inside NeurOptimal -- use the separate visualizer test for that arrangement."
                       Detail = "The visualizer surface was hosted by a separate visible window titled '$($v.HostWindowTitle)' on $($v.DetachedSamples) of $($v.AttachmentSamples) readable sample(s), while NeurOptimal's own panel was visible elsewhere." }
        }
    }

    # THE MIRROR, for the detached test: visuals that never left NeurOptimal's
    # window measured the baseline arrangement, not the one this test is for.
    # Only a READ attachment is scored -- NotShown and Unknown are the sampler
    # not seeing the visuals, not the tester skipping the step.
    if ($req.ContainsKey('VisualizerDetached') -and [bool]$req.VisualizerDetached) {
        $v = $Summary.Visualizer
        if ($v -and [string]$v.Attachment -eq 'InMainWindow') {
            $out += @{ Key    = 'VisualizerNotDetached'
                       Text   = 'The visuals stayed inside NeurOptimal for the whole recording. This test measures them detached with the separate visualizer full-screen button -- use an Audio baseline test for this arrangement.'
                       Detail = 'No sample showed the visualizer surface hosted by a window of its own; the recording measured the attached arrangement.' }
        }
    }

    if ($req.ContainsKey('VisualizerSameDisplay') -and [bool]$req.VisualizerSameDisplay) {
        $v = $Summary.Visualizer
        if ($v -and $v.OnOtherDisplay -eq $true) {
            $out += @{ Key    = 'VisualizerOtherDisplay'
                       Text   = 'The visuals were drawn on a different screen from the main NeurOptimal window, so this recording measured two screens at once. This test asks for one.'
                       Detail = "Visualizer window reported monitor $($v.MonitorDevice); NO's main window reported $($v.MainMonitorDevice). Which control put it there is not established." }
        }
    }

    if ($req.ContainsKey('MonitorCount')) {
        $have = $null
        if ($null -ne $Summary.MonitorCount) { $have = [int]$Summary.MonitorCount }
        if ($null -ne $have -and $have -ne [int]$req.MonitorCount) {
            $out += @{ Key    = 'MonitorCount'
                       Text   = "$have monitors were connected; this test uses $([int]$req.MonitorCount). This recording cannot be compared with the other baseline recordings."
                       Detail = "The cohort key carries the display layout, so this package pools with other $have-monitor runs and not with the baseline corpus." }
        }
    }

    if ($req.ContainsKey('WindowMode')) {
        $want = [string]$req.WindowMode
        $dominant = $null
        $idleMode = $null
        if ($Summary.WindowMode) {
            $dominant = [string]$Summary.WindowMode.Dominant
            $idleMode = [string]$Summary.WindowMode.IdleMode
        }
        if ($dominant -and $dominant -ne 'Unknown' -and $dominant -ne $want) {
            $out += @{ Key    = 'WindowMode'
                       Text   = "NeurOptimal was $($dominant.ToLower()) during the session; this test needs it $($want.ToLower())."
                       Detail = "Session-arm dominant window mode was $dominant, not $want." }
        }
    }

    # THE CAMPAIGN DEFECT, raised for EITHER shape of window requirement. It
    # lived inside the WindowMode branch, so moving the shipped tests onto
    # ScreenCoverage silently stopped it firing -- which is the whole finding
    # the 2026-09-18 campaign was rebuilt around, and the suite caught it.
    if ($req.ContainsKey('WindowMode') -or $req.ContainsKey('ScreenCoverage')) {
        $dominant = $null
        $idleMode = $null
        if ($Summary.WindowMode) {
            $dominant = [string]$Summary.WindowMode.Dominant
            $idleMode = [string]$Summary.WindowMode.IdleMode
        }
        if ($idleMode -and $dominant -and $idleMode -ne 'Unknown' -and $dominant -ne 'Unknown' -and $idleMode -ne $dominant) {
            # A change BETWEEN two screen-covering shapes is reported by
            # CoverageShapeChanged instead, with its own, much milder wording.
            $bothCover = ($Summary.WindowMode.IdleCoversScreen -eq $true -and $Summary.WindowMode.SessionCoversScreen -eq $true)
            if (-not $bothCover) {
                $out += @{ Key    = 'BaselineMode'
                           Text   = "The NeurOptimal window was $($idleMode.ToLower()) while the baseline was measured and $($dominant.ToLower()) during the session, so the numbers below include that size change as well as the session."
                           Detail = "Idle arm dominant mode $idleMode, session arm dominant mode $dominant; every delta is the sum of the size change and the session." }
            }
        }
    }

    # THE BASELINE'S OWN LENGTH. Every number in the package is a difference
    # against it, so a short one makes every delta less certain -- and the
    # outcome used to call that 'Requirements met' while the findings list
    # carried GFX-IDLE-ARM-SHORT three lines further down.
    $idleFloor = Get-GfxIdleFloorSec
    $idleSec = $null
    if ($Summary.ArmDurationSec -and $null -ne $Summary.ArmDurationSec.Idle) { $idleSec = [double]$Summary.ArmDurationSec.Idle }
    if ($null -ne $idleSec -and $idleSec -lt [double]$idleFloor) {
        $out += @{ Key    = 'BaselineLength'
                   Text   = "The baseline was only $(Format-GraphicsClock $idleSec); this test needs $([int]$idleFloor) seconds of it before the session starts."
                   Detail = "Idle arm $(Format-GraphicsDuration $idleSec) against a $([int]$idleFloor) s floor; every delta is session minus this mean." }
    }

    # The window was RESTORED AND RE-MAXIMIZED mid-session, or otherwise moved
    # between shapes. Distinct from the session running in the wrong mode: the
    # session arm here averages two shapes of pane, and the outcome used to
    # pass it while GFX-WINDOW-MODE-CHANGED warned about it.
    if ($Summary.WindowMode -and $Summary.WindowMode.ChangedDuringSession) {
        $modes = @($Summary.WindowMode.SessionModes)
        $out += @{ Key    = 'WindowChanged'
                   Text   = "The NeurOptimal window changed size during the session ($($modes -join ' and ')), so the numbers below average two different shapes of window."
                   Detail = "Session arm spans more than one placement mode: $($modes -join ', ')." }
    }

    # THE TRANSITION THE TEST ASKED THE OPERATOR TO BRACKET. Without both
    # marks the recording has no boundary between someone dragging a window
    # between screens and the steady period, so the length check below is
    # measuring the wrong stretch and says so rather than passing quietly.
    if ($req.ContainsKey('TransitionMarkers') -and [bool]$req.TransitionMarkers) {
        $span = $Summary.TransitionSpan
        if (-not $span) {
            $out += @{ Key    = 'TransitionNotMarked'
                       Text   = 'The two marks around detaching the visualizer are missing, so the time spent detaching could not be separated from the recording. The numbers below cover both.'
                       Detail = 'No TransitionStart/VisualsReady marker pair; the session arm was not cut and every delta spans the manual transition.' }
        } elseif ($span.Applied -eq $false) {
            $out += @{ Key    = 'TransitionOutsideSession'
                       Text   = 'The two marks around detaching the visualizer fall outside the recorded session, so the recording could not be cut around them.'
                       Detail = "Transition span $($span.StartUtc) -> $($span.EndUtc) does not land inside the session arm; the arms were left uncut." }
        }
    }

    if ($req.ContainsKey('SessionMinSec')) {
        $sec = $null
        if ($Summary.ArmDurationSec -and $null -ne $Summary.ArmDurationSec.Session) { $sec = [double]$Summary.ArmDurationSec.Session }
        # A TOLERANCE, for a test that ends at Session Complete. The length is
        # then NeurOptimal's -- a Quick Session is 15:00 of audio (SP9, run
        # 062F7649: 20:04:47 -> 20:19:45) -- and the arm is bounded by two
        # detections at one-second sampling, so a full session reads a few
        # seconds either side of 15:00. Without it, every compliant run would
        # be failed for the sampling, not for the session.
        $lengthFloor = [double]$req.SessionMinSec
        if ($req.ContainsKey('EndsAtSessionComplete') -and [bool]$req.EndsAtSessionComplete -and $Summary.SessionEndSource -and [string]$Summary.SessionEndSource -ne 'none-detected') { $lengthFloor -= $script:GfxSessionLengthToleranceSec }
        if ($null -ne $sec -and $sec -gt 0 -and $sec -lt $lengthFloor) {
            # NAMES WHERE THE CLOCK STARTED. On a test with a bracketed
            # transition this is the steady period after the second mark, not
            # the whole session, and a tester who ran 15 minutes end to end
            # needs to know that is not what was measured.
            $fromText = if ($Summary.TransitionSpan -and $Summary.TransitionSpan.Applied) { ' after the visuals settled' } else { '' }
            $out += @{ Key    = 'SessionLength'
                       Text   = "The session ran $(Format-GraphicsClock $sec)$fromText; this test needs $(Format-GraphicsClock ([double]$req.SessionMinSec))."
                       Detail = "Session arm $(Format-GraphicsDuration $sec) against a $(Format-GraphicsDuration ([double]$req.SessionMinSec)) floor$(if ($fromText) { ', measured from the VisualsReady marker' }); memory growth and the visualizer's plateau are only judgeable over a full-length session." }
        }
    }

    # ENDED BY HAND, NOT BY NEUROPTIMAL. Only judged when a session was seen:
    # a run with no session is already reported as such, and a second line
    # about how it ended would be a deviation about nothing.
    if ($req.ContainsKey('EndsAtSessionComplete') -and [bool]$req.EndsAtSessionComplete) {
        $started = ($Summary.SessionStartSource -and [string]$Summary.SessionStartSource -ne 'none-detected')
        $ended = ($Summary.SessionEndSource -and [string]$Summary.SessionEndSource -ne 'none-detected')
        if ($started -and -not $ended) {
            $out += @{ Key    = 'SessionEnd'
                       Text   = "The recording was stopped by hand before NeurOptimal showed Session Complete. The session type may not have been $(if ($BenchProfile.SessionType) { [string]$BenchProfile.SessionType } else { 'the one this test asks for' }), so this recording may not be comparable with the other recordings of this test."
                       Detail = "No Session Complete dialog was seen in NO's window set; the session arm ends where the operator stopped, not where NeurOptimal ended the session." }
        }
    }

    if ($req.ContainsKey('SessionKind') -and [string]$req.SessionKind -eq 'Audio') {
        $decodeMax = $null
        foreach ($surf in @($Summary.Surfaces | Where-Object { $_.Role -eq 'VideoJs' })) {
            if ($surf.Engines -and $surf.Engines.ContainsKey('VideoDecode')) { $decodeMax = $surf.Engines['VideoDecode'].Max }
        }
        if ($null -ne $decodeMax -and [double]$decodeMax -gt 0) {
            $out += @{ Key    = 'SessionKind'
                       Text   = "Video decode reached $decodeMax%, so this session played video; this test is audio-only."
                       Detail = "The VideoDecode engine peaked at $decodeMax% on the video.js surface, which an audio-only session leaves at a structural 0." }
        }
    }

    return ,$out
}

function ConvertTo-GfxLuidKey {
    <#
    .SYNOPSIS
        Renders a 64-bit adapter LUID in the GPU Engine counter's own shape.
    .DESCRIPTION
        The performance counter names an adapter 'luid_0xHIGH_0xLOW'; the
        registry stores the same value as one QWORD. Both sides are rendered
        through this function so a map key and a measured key can never drift
        apart in formatting -- which is the only reason the map resolves.

        The mask is written as a decimal literal on purpose: PowerShell parses
        0xFFFFFFFF as Int32 -1, and [uint64]-1 throws.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][uint64]$Luid)

    $mask = [uint64]4294967295
    $high = [uint32](($Luid -shr 32) -band $mask)
    $low  = [uint32]($Luid -band $mask)
    return ('0x{0:X8}_0x{1:X8}' -f $high, $low)
}

function Get-GfxAdapterLuidMap {
    <#
    .SYNOPSIS
        Maps each adapter LUID to the adapter that owns it.
    .DESCRIPTION
        A surface's GPU cost is measured against a LUID, and on a hybrid
        laptop the whole question is WHICH adapter that LUID names. Without
        this map a package proves how much GPU was burned but not by which
        GPU, which makes it useless for a cohort keyed on GPU.

        HKLM\SOFTWARE\Microsoft\DirectX is the one place Windows publishes
        LUID alongside a description; it is a read, and it is the same value
        the counter instance carries.
    .OUTPUTS
        Hashtable keyed by LUID string -> @{ Description; VendorId; DeviceId }.
        Empty when the key cannot be read: an unresolved LUID must render as
        unresolved, never as a guess from the adapter list.
    #>
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\DirectX')

    $map = @{}
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $RegistryPath -ErrorAction Stop)) {
            try {
                $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                if ($null -eq $props.AdapterLuid) { continue }
                $luidKey = ConvertTo-GfxLuidKey -Luid ([uint64]$props.AdapterLuid)
                $map[$luidKey] = @{
                    Description = [string]$props.Description
                    VendorId    = $(if ($null -ne $props.VendorId) { ('0x{0:X4}' -f [int]$props.VendorId) } else { $null })
                    DeviceId    = $(if ($null -ne $props.DeviceId) { ('0x{0:X4}' -f [int]$props.DeviceId) } else { $null })
                }
            } catch { }
        }
    } catch { }
    return $map
}

function Resolve-GfxLuidName {
    <#
    .SYNOPSIS
        Adapter name for a measured LUID, or $null when the map cannot answer.
    #>
    [CmdletBinding()]
    param(
        [string]$Luid,
        [hashtable]$LuidMap
    )

    if (-not $LuidMap -or [string]::IsNullOrWhiteSpace($Luid)) { return $null }
    if (-not $LuidMap.ContainsKey($Luid)) { return $null }
    $desc = $LuidMap[$Luid].Description
    if ([string]::IsNullOrWhiteSpace($desc)) { return $null }
    return $desc
}

function Get-GfxCohortKey {
    <#
    .SYNOPSIS
        The comparison cohort this run belongs to: GPU set + display config.
    .DESCRIPTION
        Runs are only comparable against boxes with the same graphics story,
        so the cohort is keyed on what actually moves the numbers -- the
        adapters present and the display configuration -- NOT on machine
        model, which splits identical hardware across vendor SKU names and
        pools genuinely different GPUs under one laptop line.

        Rendered as sorted, stable text so two machines of one cohort produce
        one byte-identical key without a lookup table.

        VERSION 2 CARRIES THE ARRANGEMENT. Version 1 keyed on the display
        RESOLUTIONS and a count, which pooled a laptop's own panel with an
        external monitor of the same resolution, and pooled two different
        external monitors as one screen. The visuals are drawn across the whole
        window, so the screen they are drawn on is the largest single term in
        every number this tool reports. The key now names the arrangement
        (BuiltInOnly / ExternalOnly / ...) and, when the arrangement was read,
        the identity, mode, refresh and scale of each display.

        A KEY OF A DIFFERENT SHAPE DOES NOT POOL WITH ONE OF THE OLD SHAPE, and
        that is the correct outcome rather than a migration problem: the runs it
        would have pooled were not comparable, which is the defect.
    .PARAMETER Arrangement
        The display arrangement, from Get-GfxDisplayArrangement. Absent, the
        key falls back to the resolution list, and Version stays 1 rather than
        claiming a reading that did not happen.
    .OUTPUTS
        Hashtable: Key, Version, Adapters[], DisplayConfig, DisplaySetup,
        MonitorCount, Reason. Key is $null when the inventory could not name an
        adapter; an uncohorted run still uploads, it just cannot be pooled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Inventory,
        $Arrangement
    )

    $venDevs = @(@($Inventory.Adapters) | ForEach-Object { $_.VenDev } | Where-Object { $_ } | Sort-Object -Unique)
    if ($venDevs.Count -eq 0) {
        return @{ Key = $null; Version = 1; Adapters = @(); DisplayConfig = $null; DisplaySetup = $null
                  MonitorCount = $Inventory.MonitorCount; Reason = 'no adapter carried a VEN/DEV identifier' }
    }

    $useArrangement = ($Arrangement -and $Arrangement.Signature -and $Arrangement.Layout -and $Arrangement.Layout -ne 'Unknown')
    if ($useArrangement) {
        $key = '{0}|{1}|{2}' -f ($venDevs -join ','), [string]$Arrangement.Layout, [string]$Arrangement.Signature
        return @{
            Key           = $key
            Version       = 2
            Adapters      = $venDevs
            DisplayConfig = [string]$Arrangement.Signature
            DisplaySetup  = [string]$Arrangement.Layout
            MonitorCount  = $Arrangement.Count
            Reason        = $null
        }
    }

    $modes = @(@($Inventory.Displays) | ForEach-Object { $_.Bounds } | Where-Object { $_ } | Sort-Object)
    $displayConfig = if ($modes.Count -gt 0) { $modes -join '+' } else { 'unknown' }
    $key = '{0}|{1}|{2}mon' -f ($venDevs -join ','), $displayConfig, [int]$Inventory.MonitorCount

    return @{
        Key           = $key
        Version       = 1
        Adapters      = $venDevs
        DisplayConfig = $displayConfig
        DisplaySetup  = $null
        MonitorCount  = $Inventory.MonitorCount
        Reason        = 'the display arrangement was not read, so this run is pooled on display resolutions only'
    }
}

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
        AdapterLuidMap = @{}
        Displays       = @()
        DisplayArrangement = $null
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
        # is a real question rather than a formality. The per-surface answer
        # is the measured LUID, and the LUID map below is what turns that
        # number into an adapter name -- so the run reports which GPU
        # rendered from evidence, without inferring it from the adapter list.
        $vendors = @($inv.Adapters | ForEach-Object { $_.VenDev } | Where-Object { $_ } | ForEach-Object { ($_ -split '&')[0] } | Sort-Object -Unique)
        $inv.HybridGpu = ($vendors.Count -gt 1)
        $inv.DisplayDrivingAdapters = @($inv.Adapters | Where-Object { $_.CurrentMode } | ForEach-Object { $_.Name })
        $inv.AdapterLuidMap = Get-GfxAdapterLuidMap
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

    # The cohort this box compares against. Computed here, once, so the app,
    # the console and the package all carry the same key for one run.
    # The display ARRANGEMENT, read after Power so the built-in-panel inference
    # has the battery to reason from. This copy is a snapshot from when the
    # inventory was taken; the run records its own, read at the moment Start was
    # pressed, and the caller re-keys the cohort from that one.
    try {
        $inv.DisplayArrangement = Get-GfxDisplayArrangement -HasBattery $inv.Power.HasBattery
    } catch { $inv.Errors += "display arrangement: $($_.Exception.Message)" }

    try { $inv.Cohort = Get-GfxCohortKey -Inventory $inv -Arrangement $inv.DisplayArrangement } catch { $inv.Errors += "cohort: $($_.Exception.Message)" }

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

function Initialize-GfxRestartManager {
    <#
    .SYNOPSIS
        Compiles the inline Restart Manager helper (read-only: list, never
        shut down).
    .DESCRIPTION
        Same discipline as Initialize-GfxWindowScan: Add-Type is AppDomain
        wide, so the caller compiles once on the main thread. The dist ships
        text only, hence inline C#.
    #>
    [CmdletBinding()]
    param()

    if ('WinConfigDiag.GfxRestartManager' -as [type]) { return $true }
    try {
        $source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinConfigDiag {
    // Asks the Restart Manager which processes hold the given files open.
    // RmGetList is a QUERY; RmShutdown / RmRestart are never referenced
    // here, so nothing this type can do closes a handle or a process.
    public static class GfxRestartManager {
        [StructLayout(LayoutKind.Sequential)] struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
            public int ApplicationType; public uint AppStatus; public uint TSSessionId; [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, System.Text.StringBuilder strSessionKey);
        [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint pSessionHandle);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, IntPtr rgApplications, uint nServices, IntPtr rgsServiceNames);
        [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

        // PIDs holding ANY of the files. Per-file attribution is done by
        // the caller calling this once per file; the tree is small.
        public static int[] HoldersOf(string[] files) {
            List<int> pids = new List<int>();
            uint handle; System.Text.StringBuilder key = new System.Text.StringBuilder(33);
            if (RmStartSession(out handle, 0, key) != 0) { return pids.ToArray(); }
            try {
                if (RmRegisterResources(handle, (uint)files.Length, files, 0, IntPtr.Zero, 0, IntPtr.Zero) != 0) { return pids.ToArray(); }
                uint needed = 0, count = 0, reasons = 0;
                int rc = RmGetList(handle, out needed, ref count, null, ref reasons);
                if (rc == 234 /* ERROR_MORE_DATA */ && needed > 0) {
                    RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed];
                    count = needed;
                    rc = RmGetList(handle, out needed, ref count, info, ref reasons);
                    if (rc == 0) { for (int i = 0; i < count; i++) { pids.Add(info[i].Process.dwProcessId); } }
                }
            } finally { RmEndSession(handle); }
            return pids.ToArray();
        }
    }
}
"@
        Add-Type -TypeDefinition $source -ErrorAction Stop
        return [bool]('WinConfigDiag.GfxRestartManager' -as [type])
    } catch {
        return $false
    }
}

function Get-NoHeldMediaFiles {
    <#
    .SYNOPSIS
        Which files under the media root NO's process tree holds open RIGHT
        NOW. Passive, timestamp-free.
    .DESCRIPTION
        LastAccessTime failed on run D5E1D5C7: the 33-minute .m4a NO played
        carried an access time inside the run, yet 207 scans saw nothing,
        because a System Managed volume defers the update for a file touched
        within the previous hour -- the ordinary demo case. An open handle
        has no such lag. The Restart Manager is asked, per file, which
        processes hold it; a file held by NO.exe or one of its WebView2
        hosts is the media being played.

        Reads names under the root only (deny-list checked); registers each
        file with the Restart Manager, which does not open it. Capped so a
        pathological root cannot stall the tick.
    .OUTPUTS
        Array of @{ File; HolderPids }, only for files a listed PID holds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$MediaRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$Pids,
        [int]$MaxFiles = 200
    )

    # An empty result must be EMPTY under the caller's @(): 'return ,@()'
    # hands @() a one-element array holding an empty array.
    if ([string]::IsNullOrWhiteSpace($MediaRoot) -or @($Pids).Count -eq 0) { return @() }
    Assert-GfxPathAllowed -Path $MediaRoot
    if (-not (Test-Path -LiteralPath $MediaRoot)) { return @() }
    if (-not (Initialize-GfxRestartManager)) { return @() }

    $files = @(Get-ChildItem -LiteralPath $MediaRoot -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles | ForEach-Object { $_.FullName })
    if ($files.Count -eq 0) { return @() }

    $wanted = @{}
    foreach ($p in $Pids) { $wanted[[int]$p] = $true }
    $out = @()
    foreach ($f in $files) {
        $holders = @()
        try { $holders = @([WinConfigDiag.GfxRestartManager]::HoldersOf(@($f))) } catch { $holders = @() }
        $ours = @($holders | Where-Object { $wanted.ContainsKey([int]$_) })
        if ($ours.Count -gt 0) { $out += @{ File = $f; HolderPids = @($ours | Sort-Object -Unique) } }
    }
    # Returned plainly: every caller enumerates or wraps in @(), and a
    # ',$out' under @() would hand them ONE record that is the whole list.
    return $out
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
        AUDIO IS INVISIBLE TO THE DECODE ENGINE. A 33-minute .m4a session on
        MMEVOLD_06 (run D5E1D5C7) left VideoDecode at 0% throughout, so the
        whole session classified as the visualizer drawing at rest. What
        that session DID leave is the video.js surface's 3D engine stepping
        from 0% (idle arm) to 1.1-1.3% (every minute of playback) -- the
        player redrawing its own controls. 'AudioLikely' names exactly that
        reading: video.js is drawing with nothing decoding. It is a proxy and
        the name says so; a paused video with a visible control bar would
        read the same way.
    .OUTPUTS
        [string] Quiet | VisualizerOnly | MediaOnly | AudioLikely | Both | Unmeasured
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Sample,
        [double]$VisualizerFloorPercent = $script:GfxVisualizerFloorPercent,
        [double]$MediaFloorPercent = $script:GfxMediaFloorPercent,
        [double]$AudioUiFloorPercent = $script:GfxAudioUiFloorPercent
    )

    $anyEngines = $false
    $vis = $false
    $media = $false
    $audio = $false
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
        if ($s.Role -eq 'VideoJs' -and $decode -lt $MediaFloorPercent -and $threeD -ge $AudioUiFloorPercent) { $audio = $true }
        # An unresolved surface still counts toward media if it is decoding:
        # hardware decode is not something a visualizer does.
        if ($s.Role -eq 'Unknown' -and $decode -ge $MediaFloorPercent) { $media = $true }
    }

    if (-not $anyEngines) { return 'Unmeasured' }
    if ($vis -and $media) { return 'Both' }
    if ($media) { return 'MediaOnly' }
    if ($audio) { return 'AudioLikely' }
    if ($vis) { return 'VisualizerOnly' }
    return 'Quiet'
}

function Get-GraphicsPreRunActivity {
    <#
    .SYNOPSIS
        What NO is doing RIGHT NOW, from a short passive burst taken before a
        run starts.
    .DESCRIPTION
        The tool's whole method is "measure the idle stretch, then measure the
        session, report the difference". That is only possible if NO is idle
        when watching begins -- and the operator was previously told to leave
        it idle without anyone checking whether it already was. Starting
        mid-session yields a run with one arm and no deltas, which is only
        discovered at Stop, after the session is over and unrepeatable.

        WHAT COUNTS AS EVIDENCE. On the boxes captured so far butterchurn's
        render loop is unconditional -- it draws while NO sits idle -- so 3D
        load says nothing about whether a session is running. On a box where
        the visuals are NOT on screen until a session starts, 3D load is
        evidence of a session, but of the WRONG KIND: it would make the signal
        depend on which of the two behaviours the box has, and the tool would
        have to know that in advance. Hardware video decode is free of it: the
        video.js surface decodes only when NO is playing media, which it does
        not do at rest. So MEDIA DECODE IS THE SIGNAL and visualizer load is
        not -- and what the baseline arm actually contained is reported
        separately, from Get-GfxBaselineVisualizerState.

        This is inference from GPU engine load, not a statement out of NO, and
        the record says so. It can be wrong in one direction worth naming: a
        tech playing the explainer video outside a session decodes media too.
        That is why the result is 'likely', and why the advice is phrased as
        something to check rather than a verdict.
    .OUTPUTS
        Hashtable: State, MediaActive, VisualizerActive, SessionLikely
        (Yes/No/Unknown), SampleCount, Reason, Method.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [double]$VisualizerFloorPercent = $script:GfxVisualizerFloorPercent,
        [double]$MediaFloorPercent = $script:GfxMediaFloorPercent
    )

    $result = @{
        State            = 'Unmeasured'
        MediaActive      = $false
        VisualizerActive = $false
        SessionLikely    = 'Unknown'
        SampleCount      = @($Samples).Count
        Reason           = $null
        Method           = 'GPU engine load over a short passive burst; media decode is the signal, visualizer load is not'
    }

    if (@($Samples).Count -eq 0) {
        $result.Reason = 'no samples were collected before the run'
        return $result
    }

    $states = @()
    foreach ($s in @($Samples)) {
        $states += (Get-GraphicsActivityState -Sample $s -VisualizerFloorPercent $VisualizerFloorPercent -MediaFloorPercent $MediaFloorPercent)
    }

    $measured = @($states | Where-Object { $_ -ne 'Unmeasured' })
    if ($measured.Count -eq 0) {
        $result.Reason = 'GPU engine load could not be measured, so what NO is doing cannot be told from here'
        return $result
    }

    # ANY sample decoding counts. Media that started a second ago is still
    # media; requiring every sample would hide a session that just began.
    $result.MediaActive = [bool](@($measured | Where-Object { $_ -eq 'MediaOnly' -or $_ -eq 'Both' }).Count)
    $result.AudioLikely = [bool](@($measured | Where-Object { $_ -eq 'AudioLikely' }).Count)
    $result.VisualizerActive = [bool](@($measured | Where-Object { $_ -eq 'VisualizerOnly' -or $_ -eq 'Both' }).Count)
    $result.State = $measured[$measured.Count - 1]

    if ($result.MediaActive) {
        $result.SessionLikely = 'Yes'
        $result.Reason = 'the video.js surface is decoding video, which it does not do while NO sits at rest'
    } elseif ($result.AudioLikely) {
        # Audio-only playback: no decode, but the player is drawing its own
        # controls. Read as a session for the same reason -- video.js does
        # not draw while NO sits at rest.
        $result.SessionLikely = 'Yes'
        $result.Reason = 'the video.js surface is drawing with nothing decoding, which is what audio-only playback looks like from here'
    } else {
        $result.SessionLikely = 'No'
        $result.Reason = if ($result.VisualizerActive) {
            'the visualizer is drawing but nothing is decoding video -- butterchurn draws at rest, so this reads as idle'
        } else {
            'neither surface is doing measurable work'
        }
    }
    return $result
}

function Format-GraphicsPreRunReport {
    <#
    .SYNOPSIS
        The pre-run readout and the instruction that follows from it. ONE
        renderer, so the console and the app cannot give different advice.
    .DESCRIPTION
        The instruction is DERIVED from the measurement rather than printed
        unconditionally. Telling an operator to "leave NO idle a few seconds"
        while NO is mid-session is advice they cannot follow, and it produced
        a run that could answer nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Activity,
        [hashtable]$Inventory
    )

    $r = @()

    # THREE ANSWERS, because an absent inventory is not a reading. Without one
    # this used to print 'NO.exe is not running' -- a positive claim built from
    # a missing input, and flatly wrong next to a SessionLikely of Yes, which
    # is how it was caught.
    $noRunning = $null
    if ($Inventory -and $Inventory.No) {
        $noRunning = [bool]$Inventory.No.Pid
    }

    if ($null -eq $noRunning) {
        $r += @{ Level = 'WARN'; Text = 'Whether NeurOptimal is running could not be read here. The measurements below stand on their own; the advice that usually follows them does not.'; NoPrefix = $false }
        return $r
    }
    if (-not $noRunning) {
        $r += @{ Level = 'WARN'; Text = 'NO.exe is not running. You can still press Start watching -- the sampler picks NO up as soon as it appears, and the stretch before the session becomes the idle baseline.'; NoPrefix = $false }
        return $r
    }

    $pid_ = $Inventory.No.Pid
    switch ($Activity.SessionLikely) {
        'Yes' {
            $r += @{ Level = 'WARN'; Text = "NO.exe is running (PID $pid_) and A SESSION LOOKS LIKE IT IS ALREADY UNDER WAY -- $($Activity.Reason)."; NoPrefix = $false }
            $r += @{ Level = 'WARN'; Text = 'Starting now would measure the session against no idle baseline, so the run would report totals it cannot attribute to anything. That is only discoverable at Stop, once the session is over.'; NoPrefix = $false }
            $r += @{ Level = 'ACTION'; Text = 'Let this session finish, then press Start watching BEFORE the next one begins. If you want the totals for this session anyway, you can start now -- the run will say plainly that it has no idle arm.'; NoPrefix = $false }
        }
        'No' {
            $r += @{ Level = 'OK'; Text = "NO.exe is running (PID $pid_) and reads as idle -- $($Activity.Reason)."; NoPrefix = $false }
            $r += @{ Level = 'ACTION'; Text = "Press Start watching, leave NeurOptimal on its home screen until the line says Baseline collected (about $(Get-GfxIdleFloorSec) s), then start your session."; NoPrefix = $false }
        }
        default {
            $r += @{ Level = 'WARN'; Text = "NO.exe is running (PID $pid_), but whether a session is under way could not be determined -- $($Activity.Reason)."; NoPrefix = $false }
            $r += @{ Level = 'ACTION'; Text = 'If NeurOptimal is idle, press Start watching, leave it alone until the line says Baseline collected, then start your session. If a session is already running, let it finish first.'; NoPrefix = $false }
        }
    }
    return $r
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
        Hashtable: BaselineTitles, Changes[] (Index, AtUtc, Added, Removed,
        ReturnedToBaseline), FirstChangeIndex, FirstChangeUtc.

        EVERY sustained change is recorded, not only the first. Run D5E1D5C7
        opened a session with two dialogs that closed seven seconds later,
        and ended it with a 'Session Complete' dialog thirty-three minutes
        on; with only the first change kept, the end was seen live and lost
        from the package. A change back to the baseline set is recorded too,
        flagged ReturnedToBaseline, so 'Added = []' never has to stand for it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [int]$BaselineSamples = 3,
        [int]$MinDwellSamples = $script:GfxUiChangeDwellSamples
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

    # The confirmed signature is what the window set has been proven to look
    # like (initially: the baseline, an empty signature). A different
    # signature must hold for the dwell before it is recorded and becomes
    # the new confirmed one.
    $confirmedKey = ''
    $pendingKey = $null
    $pendingFrom = $null
    for ($i = $take; $i -lt $Samples.Count; $i++) {
        $titles = @($Samples[$i].NoVisibleWindows)
        $added = @($titles | Where-Object { $result.BaselineTitles -notcontains $_ } | Sort-Object -Unique)
        $removed = @($result.BaselineTitles | Where-Object { $titles -notcontains $_ } | Sort-Object -Unique)
        $key = (($added -join '|') + '||' + ($removed -join '|')).Trim('|')

        if ($key -eq $confirmedKey) { $pendingKey = $null; $pendingFrom = $null; continue }
        if ($key -ne $pendingKey) { $pendingKey = $key; $pendingFrom = $i }
        if ((($i - $pendingFrom) + 1) -ge $MinDwellSamples) {
            $confirmedKey = $key
            $returned = (($added.Count + $removed.Count) -eq 0)
            $result.Changes += @{ Index = $pendingFrom; AtUtc = $Samples[$pendingFrom].AtUtc; Added = $added; Removed = $removed; ReturnedToBaseline = $returned }
            if (-not $returned -and $null -eq $result.FirstChangeIndex) {
                $result.FirstChangeIndex = $pendingFrom
                $result.FirstChangeUtc = $Samples[$pendingFrom].AtUtc
            }
            $pendingKey = $null; $pendingFrom = $null
        }
    }
    return $result
}

function Get-NoSessionEndIndex {
    <#
    .SYNOPSIS
        The sample index at which NO announced the session over, or $null.
    .DESCRIPTION
        NO ends a session by opening its 'Session Complete' dialog
        (zengar_vault_Session Complete--dialog.vi on 4.0.0.9; the failed
        session variant reads 'Session Complete!'). It is a window-set
        change like any other, already dwell-filtered by Get-NoUiChangePoints;
        this only asks which sustained change after the split carries that
        title. Title text only -- the same channel the Flight Recorder reads.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$UiChangePoints,
        $SplitIndex,
        [string]$SessionEndTitlePattern = 'Session Complete'
    )
    if ($null -eq $SplitIndex) { return $null }
    foreach ($c in @($UiChangePoints.Changes)) {
        if ($null -eq $c.Index -or [int]$c.Index -le [int]$SplitIndex) { continue }
        foreach ($t in @($c.Added)) {
            if ([string]$t -imatch $SessionEndTitlePattern) { return [int]$c.Index }
        }
    }
    return $null
}

function Get-GfxPlaybackStartIndex {
    <#
    .SYNOPSIS
        The sample at which NeurOptimal's player started playing, after the
        session's first window change.
    .DESCRIPTION
        THE SESSION STARTS AT THE AUDIO, NOT AT CONFIGURE SESSION. NO's window
        set changes the moment the tester opens Configure Session -- the dialog
        where the session type is chosen -- and that used to open the session
        arm. The stretch from there to the audio is a person choosing Quick
        Session and NO loading: 14 s on SP9 (run 062F7649, 2026-09-23), and a
        different number for every tester. It is neither baseline nor session.

        Playback is read from the player surface's own engines, through
        Get-GraphicsActivityState: AudioLikely (video.js redrawing its controls
        with nothing decoding -- which is what audio playback looks like),
        MediaOnly or Both. It must HOLD for the dwell the window-set detector
        uses, so a one-sample blip cannot open the session.

        Bounded: only within -MaxWaitSec of the window change. Past that, the
        player's reading is not trusted to be this session's start, and the
        caller falls back to the window change and says so.
    .OUTPUTS
        [int] sample index, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Samples,
        $FromIndex,
        $ToIndex,
        [int]$DwellSamples = $script:GfxUiChangeDwellSamples,
        [double]$MaxWaitSec = 180,
        [double]$MediaFloorPercent = $script:GfxMediaFloorPercent,
        [double]$AudioUiFloorPercent = $script:GfxAudioUiFloorPercent
    )
    if ($null -eq $FromIndex) { return $null }
    $all = @($Samples)
    $last = $all.Count - 1
    if ($null -ne $ToIndex -and [int]$ToIndex -lt $last) { $last = [int]$ToIndex }
    $from = [int]$FromIndex
    if ($from -lt 0 -or $from -gt $last) { return $null }
    $t0 = $null
    try { $t0 = [datetime]$all[$from].AtUtc } catch { }
    $playing = @('AudioLikely', 'MediaOnly', 'Both')
    $run = 0
    $runStart = $null
    for ($i = $from; $i -le $last; $i++) {
        if ($null -ne $t0 -and $null -eq $runStart) {
            $at = $null
            try { $at = [datetime]$all[$i].AtUtc } catch { }
            if ($null -ne $at -and ($at - $t0).TotalSeconds -gt $MaxWaitSec) { return $null }
        }
        $state = Get-GraphicsActivityState -Sample $all[$i] -MediaFloorPercent $MediaFloorPercent -AudioUiFloorPercent $AudioUiFloorPercent
        if ($playing -contains $state) {
            if ($run -eq 0) { $runStart = $i }
            $run++
            if ($run -ge $DwellSamples) { return [int]$runStart }
        } else {
            $run = 0
            $runStart = $null
        }
    }
    return $null
}

function Get-NoWindowModeSummary {
    <#
    .SYNOPSIS
        How NO's window was placed across the run: dwell-filtered spans of
        Windowed / Maximized / FullScreen / Minimized / Unknown, the mode the
        session arm mostly ran in, and whether it changed DURING the session.
    .DESCRIPTION
        Reuses Get-GraphicsActivitySpans for the dwell so a one-sample
        placement blip cannot mint a span. Changes before the split are the
        operator arranging windows and are not a finding; a change inside
        the session arm means the session numbers mix two modes.
    .OUTPUTS
        Hashtable: Dominant, Bounds, Spans[], SessionModes[], ChangedDuringSession.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        $SplitIndex,
        $EndIndex,
        [int]$MinDwellSamples = $script:GfxUiChangeDwellSamples
    )

    # IdleMode is the mode the BASELINE arm was measured in. It is reported
    # beside Dominant because the pair is what makes a delta readable: the
    # 2026-09-18 campaign measured every idle arm windowed and ran every
    # session maximized, and the resulting "+21 to +28 points" was mostly the
    # pane growing. A delta across two window sizes is not a session cost, and
    # nothing downstream could say so while only the session's mode was kept.
    $r = @{ Dominant = 'Unknown'; IdleMode = 'Unknown'; Bounds = $null; Spans = @(); SessionModes = @(); ChangedDuringSession = $false
            # COVERAGE PER ARM, beside the mode names. The mode is a label; the
            # coverage is the physical fact the comparison rests on, and the two
            # are recorded separately so a test can require the fact without
            # having to guess which label NeurOptimal's own full-screen control
            # produces. $null means unread, never 'no'.
            IdleCoversScreen = $null; SessionCoversScreen = $null
            # HOW MUCH of the monitor each arm actually covered, as a mean.
            # 'Covers the screen' is a yes/no; the confound is AREA, and two
            # windows that both answer yes can differ by the taskbar strip.
            # Measured on NO 4.0.0.9: its own full-screen control leaves the
            # window at 0.979 of the monitor -- maximized to the WORK AREA,
            # with the taskbar still showing. A box with an auto-hiding taskbar
            # would read 1.000 for the same operator action, and nothing else
            # in the package would say why its numbers ran higher.
            IdleScreenFraction = $null; SessionScreenFraction = $null
            # THE QUANTITY THE NUMBERS ACTUALLY FOLLOW: the window's area in
            # DESKTOP pixels. Measured 2026-09-18 on one box, two displays,
            # same session type, same adapter:
            #
            #   external 5134x1406 desktop px (100% scale) -> butterchurn 64.0% 3D, 290 MB VRAM
            #   built-in 1614x1033 desktop px (150% scale) -> butterchurn 17.7% 3D,  85 MB VRAM
            #
            # Fitting cost = fixed + k*area to those two points:
            #   DESKTOP pixels   fixed = +3.8%   (plausible)
            #   PHYSICAL pixels  fixed = -32.4%  (impossible)
            #
            # So the render target is sized in DESKTOP pixels and upscaled by
            # the compositor, and the physical-pixel model is refuted rather
            # than merely unsupported. VRAM agrees independently: 0.294 of the
            # external reading against a desktop-area ratio of 0.231 and a
            # physical-area ratio of 0.520.
            #
            # THE CONSEQUENCE IS THAT DISPLAY SCALING CHANGES THE COST. The
            # same panel at 150% draws 2.25x fewer pixels than at 100%, which
            # is why the scale factor is in the cohort key -- and why reading it
            # wrong, as GetDpiForMonitor does for this process, would have
            # pooled two genuinely different setups.
            IdleWindowDesktopPixels = $null; SessionWindowDesktopPixels = $null
            MonitorDevice = $null; StyleHex = $null }
    if ($Samples.Count -eq 0) { return $r }

    $states = @()
    $modeSamples = @()
    for ($i = 0; $i -lt $Samples.Count; $i++) {
        $s = $Samples[$i]
        $mode = 'Unknown'
        $bounds = $null
        $covers = $null
        $fraction = $null
        $pixels = $null
        if ($s.NoWindow) {
            if ($s.NoWindow.Mode) { $mode = [string]$s.NoWindow.Mode; $bounds = $s.NoWindow.Bounds }
            if ($null -ne $s.NoWindow.CoversScreen) { $covers = [bool]$s.NoWindow.CoversScreen }
            elseif ($mode -ne 'Unknown') { $covers = (@('Maximized', 'FullScreen') -contains $mode) }
            if ($null -ne $s.NoWindow.ScreenFraction) { $fraction = [double]$s.NoWindow.ScreenFraction }
            # From the window's own WxH, which is already in desktop
            # coordinates -- the same space the monitor rect is read in.
            if ($s.NoWindow.Bounds -and [string]$s.NoWindow.Bounds -match '^(\d+)x(\d+)$') {
                $pixels = [double]$Matches[1] * [double]$Matches[2]
            }
            if (-not $r.MonitorDevice -and $s.NoWindow.MonitorDevice) { $r.MonitorDevice = [string]$s.NoWindow.MonitorDevice }
            if (-not $r.StyleHex -and $s.NoWindow.StyleHex) { $r.StyleHex = [string]$s.NoWindow.StyleHex }
        }
        $states += @{ AtUtc = $s.AtUtc; State = $mode; Index = $i }
        $modeSamples += @{ Mode = $mode; Bounds = $bounds; Covers = $covers; Fraction = $fraction; Pixels = $pixels; Index = $i }
    }

    # No @() here: the spans function returns ',$spans', and @() over that
    # yields ONE element holding every span (the 86cfa77 defect class).
    foreach ($sp in (Get-GraphicsActivitySpans -States $states -MinDwellSamples $MinDwellSamples)) {
        $sec = $null
        try { $sec = [math]::Round(([datetime]$sp.EndUtc - [datetime]$sp.StartUtc).TotalSeconds, 1) } catch { }
        # The span's bounds: the most common WxH among its samples.
        $r.Spans += @{ Mode = $sp.State; StartUtc = $sp.StartUtc; EndUtc = $sp.EndUtc; Samples = $sp.Samples; DurationSec = $sec; Source = 'window-placement' }
    }

    # Which samples are "the session"? split..end when a split exists, else
    # the whole run -- the same choice the arms make.
    $from = 0
    $to = $Samples.Count - 1
    if ($null -ne $SplitIndex) { $from = [int]$SplitIndex }
    if ($null -ne $EndIndex -and [int]$EndIndex -gt $from) { $to = [int]$EndIndex - 1 }

    $counts = @{}
    $boundsByMode = @{}
    for ($i = $from; $i -le $to; $i++) {
        $m = $modeSamples[$i].Mode
        if (-not $counts.ContainsKey($m)) { $counts[$m] = 0; $boundsByMode[$m] = @{} }
        $counts[$m]++
        $b = $modeSamples[$i].Bounds
        if ($b) { if (-not $boundsByMode[$m].ContainsKey($b)) { $boundsByMode[$m][$b] = 0 }; $boundsByMode[$m][$b]++ }
    }
    $best = $null
    foreach ($m in $counts.Keys) { if ($null -eq $best -or $counts[$m] -gt $counts[$best]) { $best = $m } }
    if ($best) {
        $r.Dominant = $best
        $bb = $null
        foreach ($b in $boundsByMode[$best].Keys) { if ($null -eq $bb -or $boundsByMode[$best][$b] -gt $boundsByMode[$best][$bb]) { $bb = $b } }
        $r.Bounds = $bb
    }

    # Modes that held (per the dwell) inside the session window. A span
    # overlaps the window if any of its samples fall inside it; spans carry
    # times, so compare on the sample timestamps at the window's edges.
    $winStart = [datetime]$Samples[$from].AtUtc
    $winEnd = [datetime]$Samples[$to].AtUtc
    $modes = @()
    foreach ($sp in $r.Spans) {
        $spStart = [datetime]$sp.StartUtc
        $spEnd = [datetime]$sp.EndUtc
        if ($spEnd -lt $winStart -or $spStart -gt $winEnd) { continue }
        $modes += $sp.Mode
    }
    $r.SessionModes = @($modes | Where-Object { $_ -ne 'Unknown' } | Sort-Object -Unique)
    $r.ChangedDuringSession = ($r.SessionModes.Count -gt 1)

    # The idle arm's own dominant mode, counted the same way over 0..split-1.
    # With no split there is no idle arm, and it stays Unknown rather than
    # borrowing the session's answer.
    if ($null -ne $SplitIndex -and [int]$SplitIndex -gt 0) {
        $idleCounts = @{}
        for ($i = 0; $i -lt [int]$SplitIndex -and $i -lt $modeSamples.Count; $i++) {
            $m = $modeSamples[$i].Mode
            if (-not $idleCounts.ContainsKey($m)) { $idleCounts[$m] = 0 }
            $idleCounts[$m]++
        }
        $idleBest = $null
        foreach ($m in $idleCounts.Keys) { if ($null -eq $idleBest -or $idleCounts[$m] -gt $idleCounts[$idleBest]) { $idleBest = $m } }
        if ($idleBest) { $r.IdleMode = $idleBest }
    }

    # Coverage per arm, by majority of the samples that HAD a reading. A sample
    # whose placement could not be read is left out of the vote rather than
    # counted as not covering: an unread window is not a small one.
    $coverVote = {
        param([int]$From, [int]$To)
        $yes = 0; $no = 0
        for ($i = $From; $i -le $To -and $i -lt $modeSamples.Count; $i++) {
            if ($i -lt 0) { continue }
            $c = $modeSamples[$i].Covers
            if ($null -eq $c) { continue }
            if ($c) { $yes++ } else { $no++ }
        }
        if ($yes -eq 0 -and $no -eq 0) { return $null }
        return ($yes -ge $no)
    }
    $r.SessionCoversScreen = & $coverVote $from $to
    if ($null -ne $SplitIndex -and [int]$SplitIndex -gt 0) {
        $r.IdleCoversScreen = & $coverVote 0 ([int]$SplitIndex - 1)
    }

    # The mean covered fraction per arm, over the samples that HAD a reading.
    # $null when none did -- an unread window is not a zero-area one.
    $fractionMean = {
        param([int]$From, [int]$To)
        $vals = @()
        for ($i = $From; $i -le $To -and $i -lt $modeSamples.Count; $i++) {
            if ($i -lt 0) { continue }
            $f = $modeSamples[$i].Fraction
            if ($null -ne $f) { $vals += [double]$f }
        }
        if ($vals.Count -eq 0) { return $null }
        return [math]::Round(($vals | Measure-Object -Average).Average, 3)
    }
    $r.SessionScreenFraction = & $fractionMean $from $to
    if ($null -ne $SplitIndex -and [int]$SplitIndex -gt 0) {
        $r.IdleScreenFraction = & $fractionMean 0 ([int]$SplitIndex - 1)
    }

    $pixelMean = {
        param([int]$From, [int]$To)
        $vals = @()
        for ($i = $From; $i -le $To -and $i -lt $modeSamples.Count; $i++) {
            if ($i -lt 0) { continue }
            $v = $modeSamples[$i].Pixels
            if ($null -ne $v) { $vals += [double]$v }
        }
        if ($vals.Count -eq 0) { return $null }
        return [int][math]::Round(($vals | Measure-Object -Average).Average)
    }
    $r.SessionWindowDesktopPixels = & $pixelMean $from $to
    if ($null -ne $SplitIndex -and [int]$SplitIndex -gt 0) {
        $r.IdleWindowDesktopPixels = & $pixelMean 0 ([int]$SplitIndex - 1)
    }

    return $r
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
            AdapterNames             = @()
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

function Get-GfxTransitionMarkerKinds {
    <#
    .SYNOPSIS
        The two typed markers that bound a manual transition, in order.
    .DESCRIPTION
        ONE DEFINITION. The window's marker button, the phase line, the arm
        split and the deviation all read this, so a marker the operator pressed
        and a marker the summariser looks for can never be two different things.

        They are KINDS, not free text. The first version of the detached test
        told the tester to type "detaching" into the marker box and the
        summariser had no way to find it again -- a marker whose meaning lives
        in prose is a marker nothing downstream can use.
    .OUTPUTS
        Array of @{ Kind, Label, Instruction }.
    #>
    [CmdletBinding()]
    param()
    $kinds = @(
        @{ Kind = 'TransitionStart'
           Label = 'Mark transition start'
           Instruction = 'Press Mark transition start, then use the separate visualizer full-screen button and choose the display for it.' }
        @{ Kind = 'VisualsReady'
           Label = 'Mark visuals ready'
           Instruction = 'Press Mark visuals ready as soon as the visuals are settled on their display. The steady recording is measured from here.' }
    )
    return ,$kinds
}

function ConvertTo-GfxUtcInstant {
    <#
    .SYNOPSIS
        A timestamp as a UTC DateTime, whether it arrived as a DateTime or as
        a round-trip string. PURE.
    .DESCRIPTION
        [datetime]'2026-09-24T20:27:00Z' IS LOCAL TIME in Windows PowerShell:
        the cast converts to the machine's zone and drops the Z. A live sample
        carries [datetime]::UtcNow (Kind Utc) while a marker carries the same
        instant as a string, and DateTime comparison ignores Kind -- so in New
        York every marker read four hours BEFORE every sample. That put both
        marks of every detached-visualizer run before the session and the test
        could not be passed anywhere west of Greenwich (run 3C7ACD84,
        2026-09-24). Every comparison between a marker and a sample goes
        through here, so both sides are the same kind of number.
    .OUTPUTS
        [datetime] with Kind Utc, or $null when the value cannot be read.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        # Unspecified is treated as UTC: every timestamp this module writes is
        # named *Utc and written as UTC.
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
    }
    return $null
}

function Get-GfxTransitionSpan {
    <#
    .SYNOPSIS
        The manual transition the operator bracketed, from the typed markers.
    .DESCRIPTION
        The stretch between 'TransitionStart' and 'VisualsReady' is someone
        dragging a window between screens. It is not steady state, it is not
        the session's cost, and averaging it into either makes both wrong. So
        it is bounded, reported on its own, and kept out of the arm the deltas
        are taken from.

        THE FIRST OF EACH KIND WINS. A tester who pressed the button twice has
        given us one transition and one accident, and taking the earliest start
        with the earliest ready after it is the reading that cannot straddle a
        second attempt.

        WITH NO MARKS, THE DIALOG ANSWERS INSTEAD. NeurOptimal's monitor
        picker is modal and blocks the detach until a screen is chosen, so the
        stretch it is on screen IS the manual transition. It is matched by the
        title of its own window and needs nothing from the operator. Captured
        2026-09-18: 'Zengar Shared_lib.lvlib:Select Display Monitor--dialog.vi',
        with the visuals still in NeurOptimal's panel the whole time it was up.

        MARKS WIN WHEN THEY EXIST. A mark is a statement of intent about what
        the operator was doing; the dialog is evidence about what the software
        was doing, and they bracket slightly different things -- the operator
        may start before the dialog opens. Preferring the marks keeps the
        recording scored on what the test asked for, and the source says which
        of the two produced the span.

        Returns $null when neither is available -- a run that did not follow
        the test, not a run with a zero-length transition.
    .OUTPUTS
        Hashtable: StartUtc, EndUtc, DurationSec, Source; or $null.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][array]$Markers = @(),
        [AllowEmptyCollection()][array]$Samples = @()
    )

    $start = $null
    $ready = $null
    foreach ($m in @($Markers | Where-Object { $_ })) {
        $kind = [string]$m.Kind
        $at = $null
        $at = ConvertTo-GfxUtcInstant $m.AtUtc
        if ($null -eq $at) { continue }
        if ($kind -eq 'TransitionStart') {
            if ($null -eq $start -or $at -lt $start) { $start = $at }
        } elseif ($kind -eq 'VisualsReady') {
            if ($null -eq $ready -or $at -lt $ready) { $ready = $at }
        }
    }
    if ($null -ne $start -and $null -ne $ready -and $ready -ge $start) {
        return @{
            StartUtc    = $start.ToUniversalTime().ToString('o')
            EndUtc      = $ready.ToUniversalTime().ToString('o')
            DurationSec = [math]::Round(($ready - $start).TotalSeconds, 1)
            Source      = 'operator-markers'
        }
    }

    # No usable pair of marks. The dialog, then -- the stretch NeurOptimal's
    # own monitor picker was on screen, which is the detach waiting on a person.
    $first = $null
    $last = $null
    foreach ($s in @($Samples)) {
        $open = $false
        foreach ($t in @($s.NoVisibleWindows)) {
            if ($t -and $t -match $script:GfxMonitorPickerPattern) { $open = $true; break }
        }
        if (-not $open) { continue }
        $at = ConvertTo-GfxUtcInstant $s.AtUtc
        if ($null -eq $at) { continue }
        if ($null -eq $first) { $first = $at }
        $last = $at
    }
    if ($null -eq $first) { return $null }
    # THE TRANSITION ENDS WHEN THE DIALOG IS GONE, not on the last sample that
    # still showed it. Ending on the last visible sample leaves that sample --
    # still mid-transition -- inside the steady arm, which pulled a measured
    # 52.0 down to 51.978. One sample is not much and it is still wrong.
    $after = $null
    foreach ($s in @($Samples)) {
        $at = ConvertTo-GfxUtcInstant $s.AtUtc
        if ($null -eq $at) { continue }
        if ($at -le $last) { continue }
        $after = $at
        break
    }
    $end = $(if ($null -ne $after) { $after } else { $last })
    return @{
        StartUtc    = $first.ToUniversalTime().ToString('o')
        EndUtc      = $end.ToUniversalTime().ToString('o')
        DurationSec = [math]::Round(($end - $first).TotalSeconds, 1)
        Source      = 'monitor-picker-dialog'
    }
}

function Get-GfxVisualizerAttachmentState {
    <#
    .SYNOPSIS
        Whether the visuals are drawn inside NeurOptimal's own window, in a
        window of their own, or not on screen at all. PURE.
    .DESCRIPTION
        CAPTURED WITH BOTH CONTROLS, NO 4.0.0.9, 2026-09-18, the operator
        stating each state as they produced it:

          before the session   host window 461894, title 'Closed', NOT visible
          session, ATTACHED    host window 397666, title
                               'NeurOptimal(R) development - VAULT', visible
          session, DETACHED    host window 3413942, title
                               'System Audio Visualizer', visible, maximized,
                               AND ON THE SAME DISPLAY as the main window

        That last line is why this function exists. The detached visualizer sat
        on the very monitor NeurOptimal was on, so the screen comparison read
        'same display' and would have called the run clean. Which WINDOW hosts
        the pane is the discriminator; which SCREEN is a separate question.

        THE RULE IS STRUCTURAL, WITH ONE TITLE MATCH AND A CONTROL.

          NotShown      the host window is not visible -- the pane exists but
                        is not on screen. This is the ordinary pre-session
                        state, not a fault.
          InMainWindow  the host window's own title names NeurOptimal, so the
                        pane is drawn inside NeurOptimal's panel.
          OwnWindow     the host is visible, is NOT the NeurOptimal panel, AND
                        a DIFFERENT visible window IS the NeurOptimal panel.
                        The control matters: without seeing the panel
                        elsewhere, 'not the panel' could just mean the panel
                        was not recognised, and a build whose title does not
                        say 'NeurOptimal' would read every run as detached.
          Unknown       anything else, including no reading at all.

        NOT matched on the detached window's own title. 'System Audio
        Visualizer' is what this build calls it; the next build may not, and a
        rule that fires only on a literal string silently stops working. The
        title is RECORDED so an unrecognised one can be read out of a package,
        the way the Bluetooth lexicon carries UnknownWindowTitles.
    .PARAMETER HostTitle
        The title of the top-level window hosting the visualizer surface.
    .PARAMETER HostVisible
        Whether that window is visible. $null when it was not read.
    .PARAMETER VisibleTitles
        Every visible top-level window title in the same sample -- the control
        that establishes NeurOptimal's own panel is on screen somewhere else.
    .OUTPUTS
        One of 'NotShown', 'InMainWindow', 'OwnWindow', 'Unknown'.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$HostTitle,
        $HostVisible,
        [AllowEmptyCollection()][string[]]$VisibleTitles = @()
    )

    if ($null -eq $HostVisible) { return 'Unknown' }
    if (-not [bool]$HostVisible) { return 'NotShown' }
    if ([string]::IsNullOrWhiteSpace($HostTitle)) { return 'Unknown' }

    # The panel's own name. Matched on the ASCII stem only: the live title
    # carries a registered-trademark glyph, and these files are BOM-less UTF-8
    # read as ANSI on a field box, so a literal (R) in the pattern would arrive
    # as mojibake and never match.
    if ($HostTitle -match 'NeurOptimal') { return 'InMainWindow' }

    $panelElsewhere = @(@($VisibleTitles) | Where-Object { $_ -and $_ -match 'NeurOptimal' })
    if ($panelElsewhere.Count -gt 0) { return 'OwnWindow' }
    return 'Unknown'
}

function Get-GfxVisualizerPlacement {
    <#
    .SYNOPSIS
        Where the visuals were drawn: which SCREEN (scored), and which window
        hosted them (recorded, not scored).
    .DESCRIPTION
        NeurOptimal has TWO full-screen controls and they are different
        actions. The first sizes NeurOptimal's own window and is used before a
        recording starts. The second appears only once a session is running,
        detaches the visualizer, and asks which display to put it on. A
        recording made with the second one is measuring two screens at once.

        WHICH WINDOW HOSTS THE VISUALIZER IS NOT A DETACHMENT SIGNAL, and this
        function used to treat it as one. MEASURED ON NO 4.0.0.9, 2026-09-18,
        nobody having touched the visualizer control:

          before the session   butterchurn -> window 461894 (hidden)
                               video.js    -> window 461894
          during the session   butterchurn -> window 397666 (the main,
                                              maximized NeurOptimal window)
                               video.js    -> window 461894 (still hidden)
                               ...and a new 'Matrix Mirror' window appeared

        NO MOVES ITS PANES BETWEEN TOP-LEVEL LABVIEW WINDOWS AS A MATTER OF
        COURSE. Comparing the visualizer's host window against video.js's
        therefore read 'Separate' on 13 of 13 samples of a perfectly ordinary
        session -- a detector that fires on every clean run is worse than no
        detector, because it trains a reader to ignore it.

        So attachment is 'Unverified' and the window handles are recorded as
        OBSERVATIONS, the same treatment AppFullScreen gets and for the same
        reason: nothing observed so far separates the detached state from a
        normal one. Establishing it needs a capture taken WITH the separate
        visualizer full-screen button pressed, which nobody has collected yet.
        HostWindowsSeen is the set that capture will be compared against.

        THE SCREEN IS STILL SCORED, and was never the doubtful part:

          OnOtherDisplay  $true   the visualizer's window reported a different
                                  display from NO's main window
                          $false  both reported the same display
                          $null   one of them did not report one; nothing is
                                  claimed
    .OUTPUTS
        Hashtable: Attachment ('Unverified'), AttachmentReason,
        HostWindowsSeen[], WindowHwnd, PeerWindowHwnd, MainWindowHwnd,
        OnOtherDisplay, MonitorDevice, MainMonitorDevice, SamplesRead.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples)

    $r = @{ Attachment = 'Unknown'; HostWindowTitle = $null; HostWindowTitlesSeen = @()
            AttachmentSamples = 0; DetachedSamples = 0
            HostWindowsSeen = @(); WindowHwnd = $null; PeerWindowHwnd = $null; MainWindowHwnd = $null
            OnOtherDisplay = $null; MonitorDevice = $null; MainMonitorDevice = $null; SamplesRead = 0 }
    $diff = 0
    $same = 0
    $hosts = @()
    $titles = @()
    $stateCounts = @{}

    foreach ($s in @($Samples)) {
        $viz = @($s.Surfaces | Where-Object { [string]$_.Role -eq 'Butterchurn' }) | Select-Object -First 1
        if (-not $viz) { continue }

        # -------- WHICH WINDOW, and what kind of window it is ---------------
        $state = Get-GfxVisualizerAttachmentState -HostTitle ([string]$viz.HostWindowTitle) `
                    -HostVisible $viz.HostWindowVisible -VisibleTitles @($s.NoVisibleWindows)
        if (-not $stateCounts.ContainsKey($state)) { $stateCounts[$state] = 0 }
        $stateCounts[$state]++
        if ($state -ne 'Unknown') { $r.AttachmentSamples++ }
        if ($state -eq 'OwnWindow') { $r.DetachedSamples++ }
        if ($viz.HostWindowTitle) {
            $t = [string]$viz.HostWindowTitle
            if ($titles -notcontains $t) { $titles += $t }
            if (-not $r.HostWindowTitle -or $state -eq 'OwnWindow') { $r.HostWindowTitle = $t }
        }
        if ($null -ne $viz.WindowHwnd) {
            $h = [long]$viz.WindowHwnd
            if ($hosts -notcontains $h) { $hosts += $h }
            if (-not $r.WindowHwnd) { $r.WindowHwnd = $h }
        }
        if (-not $r.PeerWindowHwnd) {
            $peer = @($s.Surfaces | Where-Object { [string]$_.Role -eq 'VideoJs' -and $null -ne $_.WindowHwnd }) | Select-Object -First 1
            if ($peer) { $r.PeerWindowHwnd = $peer.WindowHwnd }
        }
        if (-not $r.MainWindowHwnd -and $s.NoWindow -and $null -ne $s.NoWindow.Hwnd) { $r.MainWindowHwnd = $s.NoWindow.Hwnd }

        # -------- SCORED: which screen -------------------------------------
        $main = $null
        if ($s.NoWindow) { $main = [string]$s.NoWindow.MonitorDevice }
        if ([string]::IsNullOrWhiteSpace($main)) { continue }
        $dev = [string]$viz.MonitorDevice
        if ([string]::IsNullOrWhiteSpace($dev)) { continue }
        $r.SamplesRead++
        if (-not $r.MonitorDevice) { $r.MonitorDevice = $dev; $r.MainMonitorDevice = $main }
        if ($dev -eq $main) { $same++ } else { $diff++; $r.MonitorDevice = $dev; $r.MainMonitorDevice = $main }
    }

    $r.HostWindowsSeen = @($hosts | Sort-Object)
    $r.HostWindowTitlesSeen = @($titles | Sort-Object)
    if ($r.SamplesRead -gt 0) { $r.OnOtherDisplay = ($diff -gt 0) }

    # ANY sample in its own window makes the run a detached one: the operator
    # either pressed the button or did not, and the pane cannot be half
    # detached. 'NotShown' does not outvote a reading -- a pane that was off
    # screen for the first few samples is the ordinary way a session starts.
    if ($r.AttachmentSamples -gt 0) {
        if ($r.DetachedSamples -gt 0) { $r.Attachment = 'OwnWindow' }
        elseif ($stateCounts.ContainsKey('InMainWindow') -and $stateCounts['InMainWindow'] -gt 0) { $r.Attachment = 'InMainWindow' }
        else { $r.Attachment = 'NotShown' }
    }
    return $r
}




function Get-GfxBaselineVisualizerState {
    <#
    .SYNOPSIS
        Whether the visuals were already drawing during the idle baseline, or
        only appeared when the session started.
    .DESCRIPTION
        THE DELTA'S SCOPE, MEASURED RATHER THAN ASSUMED. This report has said
        since it shipped that "butterchurn draws even while NO is idle, so the
        absolute percentage answers nothing and the delta does". That was read
        off one box. On a machine where the visuals are not on screen until a
        session starts, the same sentence is false, and it invites a reader to
        take the delta as the session's own extra cost when it is the cost of
        the visualization APPEARING plus the session.

        Both are legitimate; they are different quantities, and the report has
        to say which one it is printing. So the idle arm is asked directly.

        WHAT IT IS ASKED IS GPU LOAD, AND THAT IS ALL THE TEXT CLAIMS. An
        engine reading below the floor does not establish that the visuals were
        invisible, or stopped, or not being composited -- it establishes that
        the GPU work attributed to that surface was below the floor. A pane can
        be on screen and cheap. So the states are named for the measurement and
        the sentences say "GPU activity", never "was not drawing" or "was not
        on screen":

          AboveFloor   the visualizer's 3D load during the baseline was at or
                       above the floor, so the delta is what the session cost
                       ON TOP of whatever that was
          BelowFloor   it was below the floor. The comparison MAY include the
                       visualization starting; that is a statement about what
                       the delta can contain, not about what was on screen
          NoSurface    no visualizer surface existed during the baseline at all
                       -- a presence reading, and a definite one
          NotMeasured  no reading either way, and nothing is claimed
    .OUTPUTS
        Hashtable: State, IdleMean, SessionMean, Text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Summary,
        [double]$VisualizerFloorPercent = $script:GfxVisualizerFloorPercent
    )

    $idle = @($Summary.Arms.Idle | Where-Object { $_ -and $_.Role -eq 'Butterchurn' }) | Select-Object -First 1
    $sess = @($Summary.Arms.Session | Where-Object { $_ -and $_.Role -eq 'Butterchurn' }) | Select-Object -First 1
    $idleMean = $null
    $sessMean = $null
    if ($idle -and $idle.Engines -and $idle.Engines.ContainsKey('3D')) { $idleMean = $idle.Engines['3D'].Mean }
    if ($sess -and $sess.Engines -and $sess.Engines.ContainsKey('3D')) { $sessMean = $sess.Engines['3D'].Mean }

    $r = @{ State = 'NotMeasured'; IdleMean = $idleMean; SessionMean = $sessMean; Text = $null }
    if (-not $idle) {
        if (@($Summary.Arms.Idle).Count -eq 0) { return $r }
        # PRESENCE is a different reading from load, and this one is definite:
        # the surface did not exist, so there was nothing to measure.
        $r.State = 'NoSurface'
        $r.Text = 'No visualizer surface was present during the baseline. The session comparison may include visualization startup.'
        return $r
    }
    if ($null -eq $idleMean) { return $r }
    $pct = [math]::Round([double]$idleMean, 1)
    if ([double]$idleMean -ge $VisualizerFloorPercent) {
        $r.State = 'AboveFloor'
        $r.Text = "Visualizer GPU activity during baseline: $pct%. The session comparison is the cost above that."
        return $r
    }
    $r.State = 'BelowFloor'
    $r.Text = "Visualizer GPU activity during baseline: $pct%. The session comparison may include visualization startup."
    return $r
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

        The idle arm is the control: the same box, driver, NO launch, window
        size and screen, minutes earlier. WHAT THE CONTROL CONTAINED IS
        MEASURED, NOT ASSUMED -- see Get-GfxBaselineVisualizerState. Whether
        the visuals were already drawing during it decides whether the delta is
        the session's extra cost on top of them or includes them appearing, and
        the two are different quantities.
    .PARAMETER Samples
        Every 'Sample' record drained from the sampler, in time order.
    .PARAMETER Markers
        Operator markers: @{ AtUtc, Text }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Samples,
        [array]$Markers = @(),
        [double]$VisualizerFloorPercent = $script:GfxVisualizerFloorPercent,
        [double]$MediaFloorPercent = $script:GfxMediaFloorPercent,
        [hashtable]$AdapterLuidMap = @{},
        # The test profile the operator selected, so the package records the
        # protocol a run CLAIMED to follow next to what it actually did. Absent
        # means the run predates profiles; it is not scored against one.
        [hashtable]$BenchProfile,
        # Displays connected, VERIFIED AT THE MOMENT RECORDING STARTED -- not
        # the inventory's snapshot from when the window opened. The readiness
        # check and the report have to agree, and they only can if they are
        # reading the same number.
        $MonitorCount,
        # Every count seen during the run, so a display change mid-recording is
        # a finding rather than a silent difference from the cohort key.
        [array]$MonitorCountsObserved = @(),
        # THE DISPLAY ARRANGEMENT AT THE MOMENT RECORDING STARTED, from
        # Get-GfxDisplayArrangement. This is what says WHICH screen the run was
        # made on -- the question a display count cannot answer, and the one
        # that decides whether two packages can be pooled.
        $DisplayArrangement,
        # Every distinct arrangement signature seen while recording, as a set.
        [array]$DisplaySetupsObserved = @()
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
        # Where the session ENDED, when NO said so (its 'Session Complete'
        # dialog). Samples after it are the operator reading the result, not
        # the session, and are kept out of the session arm.
        SessionEndUtc      = $null
        SessionEndSource   = 'none-detected'
        # How the run BEGAN. A run with no split has two very different
        # causes -- nothing ever happened, or a session was already running
        # when watching started -- and they take opposite remedies.
        StartActivity      = $null
        StartedMidSession  = $false
        NoUiBaselineTitles = @()
        NoUiChanges        = @()
        Arms               = @{ Idle = @(); Session = @(); After = @(); Transition = @() }
        # The manual transition the operator bracketed with typed markers, when
        # the test asked for one. Reported on its own; NEVER inside the session
        # arm the deltas are taken from.
        TransitionSpan     = $null
        ArmDurationSec     = @{ Idle = $null; Session = $null; After = $null; Transition = $null }
        Deltas             = @()
        # How NO's window was placed (Windowed / Maximized / FullScreen), as
        # spans, because the cost of a pane plausibly follows its size and
        # an operator can toggle it mid-session.
        WindowMode         = @{ Dominant = 'Unknown'; IdleMode = 'Unknown'; Bounds = $null; Spans = @(); SessionModes = @(); ChangedDuringSession = $false }
        # The protocol this run claimed, and where it departed from it. Both
        # are recorded even when there are no deviations, so a reader can tell
        # "followed the baseline" apart from "was never scored against one".
        ProfileId          = $(if ($BenchProfile) { $BenchProfile.Id } else { $null })
        ProfileName        = $(if ($BenchProfile) { $BenchProfile.Name } else { $null })
        ProfileDeviations  = @()
        # Whether the test ASKED for the visuals in a window of their own. The
        # findings read it so the detached test is not warned for doing what
        # it asked (run 3C7ACD84, 2026-09-24: the tester was told to "use the
        # Detached visualizer test" while running it).
        VisualizerDetachExpected = [bool]($BenchProfile -and $BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('VisualizerDetached') -and [bool]$BenchProfile.Requires.VisualizerDetached)
        MonitorCount       = $(if ($null -ne $MonitorCount) { [int]$MonitorCount } else { $null })
        # Every distinct display count seen WHILE RECORDING. The cohort key is
        # written from the layout at the start, so a monitor plugged in halfway
        # through would otherwise leave no trace at all.
        MonitorCountsObserved = @($MonitorCountsObserved | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        # WHICH SCREEN THIS WAS MEASURED ON. Carried whole, so the package can
        # be re-read later against a question nobody has asked yet -- the
        # monitor's name, its refresh rate and its scale factor are all in it.
        DisplayArrangement    = $DisplayArrangement
        DisplaySetupsObserved = @($DisplaySetupsObserved | Where-Object { $_ } | Sort-Object -Unique)
        # Where the visuals were drawn, and what the baseline contained.
        Visualizer            = @{ OnOtherDisplay = $null; MonitorDevice = $null; MainMonitorDevice = $null; SamplesRead = 0 }
        BaselineVisualizer    = @{ State = 'NotMeasured'; IdleMean = $null; SessionMean = $null; Text = $null }
    }
    if ($Samples.Count -eq 0) { return $summary }

    # A SAMPLE THAT IS ITSELF AN ARRAY is the 'return ,$x' trap arriving from a
    # caller: '@(fn)' over a function that returns ',$samples' yields ONE
    # element holding the whole array, and concatenating two of those hands
    # this function a list of lists. Every read below then coerces an array to
    # a double and fails hundreds of lines from the cause -- which is what it
    # did, in this module's own suite. Caught here, named here.
    for ($i = 0; $i -lt $Samples.Count; $i++) {
        if ($Samples[$i] -is [System.Collections.IEnumerable] -and $Samples[$i] -isnot [string] -and $Samples[$i] -isnot [System.Collections.IDictionary]) {
            throw "Sample $i is a collection, not a sample. A caller has passed a list of lists -- assign the result of each sample-producing call to a variable before combining them, because '@(fn)' over a function returning ',`$samples' yields one element holding the whole array."
        }
    }

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

    # Read the opening of the run from the same classifier the pre-run check
    # uses, over the first few samples, so "was NO already busy when we
    # started?" is answered by the capture itself rather than by whether the
    # operator remembered what they did.
    $openingStates = @(@($states | Select-Object -First 3) | ForEach-Object { $_.State })
    $measuredOpening = @($openingStates | Where-Object { $_ -ne 'Unmeasured' })
    if ($measuredOpening.Count -gt 0) {
        $summary.StartActivity = $measuredOpening[0]
        $summary.StartedMidSession = [bool](@($measuredOpening | Where-Object { $_ -eq 'MediaOnly' -or $_ -eq 'Both' }).Count)
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

    $endIndex = Get-NoSessionEndIndex -UiChangePoints $ui -SplitIndex $splitIndex
    if ($null -ne $endIndex) {
        $summary.SessionEndUtc = $Samples[$endIndex].AtUtc
        $summary.SessionEndSource = 'no-window-set-change'
    }

    $idleSamples = @()
    $sessionSamples = @()
    $afterSamples = @()
    $transitionSamples = @()
    $setupSamples = @()
    $summary.SetupSpan = $null
    if ($null -ne $splitIndex -and $splitIndex -gt 0) {
        $idleSamples = @($Samples[0..($splitIndex - 1)])
        $sessionLast = $Samples.Count - 1
        if ($null -ne $endIndex -and $endIndex -gt $splitIndex) {
            $sessionLast = $endIndex - 1
            $afterSamples = @($Samples[$endIndex..($Samples.Count - 1)])
        }
        # THE SESSION STARTS AT THE AUDIO. The window change that ended the
        # baseline is the tester opening Configure Session; the session arm
        # opens where the player starts playing, and the stretch between is
        # SETUP -- in neither arm. When no playback is seen, the window change
        # stays the start and SessionStartSource says so.
        $sessionFirst = $splitIndex
        $playIndex = Get-GfxPlaybackStartIndex -Samples $Samples -FromIndex $splitIndex -ToIndex $sessionLast -MediaFloorPercent $MediaFloorPercent
        if ($null -ne $playIndex) {
            # Named only when it MOVED the start: playback on the very sample
            # the window changed is the old split, and says so.
            if ($playIndex -gt $splitIndex) {
                $summary.SessionStartSource = 'playback-start'
                $sessionFirst = $playIndex
                $setupSamples = @($Samples[$splitIndex..($playIndex - 1)])
                $summary.SessionStartUtc = $Samples[$playIndex].AtUtc
                $setupSec = $null
                try { $setupSec = [math]::Round(([datetime]$Samples[$playIndex].AtUtc - [datetime]$Samples[$splitIndex].AtUtc).TotalSeconds, 1) } catch { }
                $summary.SetupSpan = @{ StartUtc = $Samples[$splitIndex].AtUtc; EndUtc = $Samples[$playIndex].AtUtc; DurationSec = $setupSec; Samples = $setupSamples.Count }
            }
        }
        $sessionSamples = @($Samples[$sessionFirst..$sessionLast])

        # THE MANUAL TRANSITION COMES OUT OF THE SESSION ARM.
        #
        # When the operator bracketed a transition with the two typed markers,
        # the stretch between them is someone dragging a window between screens.
        # Averaging it into the session makes the session wrong and hides the
        # transition; leaving it in and calling the whole thing 'session' is
        # what the detached test used to do, and its instructions promised
        # otherwise. So the session arm becomes the STEADY period after the
        # second marker, the transition is its own arm, and every delta
        # downstream is steady-minus-idle without a single line changing.
        $summary.TransitionSpan = Get-GfxTransitionSpan -Markers $Markers -Samples $Samples
        if ($summary.TransitionSpan) {
            $tStart = ConvertTo-GfxUtcInstant $summary.TransitionSpan.StartUtc
            $tEnd = ConvertTo-GfxUtcInstant $summary.TransitionSpan.EndUtc
            $tFrom = $null
            $tTo = $null
            for ($i = $sessionFirst; $i -le $sessionLast; $i++) {
                $at = ConvertTo-GfxUtcInstant $Samples[$i].AtUtc
                if ($null -eq $at) { continue }
                if ($at -ge $tStart -and $null -eq $tFrom) { $tFrom = $i }
                if ($at -ge $tEnd -and $null -eq $tTo) { $tTo = $i; break }
            }
            # Both edges must land INSIDE the session arm. Markers pressed
            # before the session started, or after it ended, describe something
            # this run cannot cut on, and the span is kept as a record while the
            # arms stay as they were.
            if ($null -ne $tFrom -and $null -ne $tTo -and $tTo -gt $tFrom) {
                $transitionSamples = @($Samples[$tFrom..($tTo - 1)])
                $sessionSamples = @($Samples[$tTo..$sessionLast])
                $summary.TransitionSpan.Applied = $true
            } else {
                $summary.TransitionSpan.Applied = $false
            }
        }
    }

    $transitionSec = $null
    if ($transitionSamples.Count -ge 2) { try { $transitionSec = [math]::Round(([datetime]$transitionSamples[$transitionSamples.Count - 1].AtUtc - [datetime]$transitionSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $summary.ArmDurationSec.Transition = $transitionSec
    $summary.ArmDurationSec.Setup = $(if ($summary.SetupSpan) { $summary.SetupSpan.DurationSec } else { $null })

    $idleSec = $null
    if ($idleSamples.Count -ge 2) { try { $idleSec = [math]::Round(([datetime]$idleSamples[$idleSamples.Count - 1].AtUtc - [datetime]$idleSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $sessionSec = $null
    if ($sessionSamples.Count -ge 2) { try { $sessionSec = [math]::Round(([datetime]$sessionSamples[$sessionSamples.Count - 1].AtUtc - [datetime]$sessionSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $afterSec = $null
    if ($afterSamples.Count -ge 2) { try { $afterSec = [math]::Round(([datetime]$afterSamples[$afterSamples.Count - 1].AtUtc - [datetime]$afterSamples[0].AtUtc).TotalSeconds, 1) } catch { } }
    $summary.ArmDurationSec.Idle = $idleSec
    $summary.ArmDurationSec.Session = $sessionSec
    $summary.ArmDurationSec.After = $afterSec

    $summary.WindowMode = Get-NoWindowModeSummary -Samples $Samples -SplitIndex $splitIndex -EndIndex $endIndex

    $wholeSec = 0.0
    if ($null -ne $summary.DurationSec) { $wholeSec = [double]$summary.DurationSec }
    $idleSecArg = 0.0
    if ($null -ne $idleSec) { $idleSecArg = [double]$idleSec }
    $sessionSecArg = 0.0
    if ($null -ne $sessionSec) { $sessionSecArg = [double]$sessionSec }

    $afterSecArg = 0.0
    if ($null -ne $afterSec) { $afterSecArg = [double]$afterSec }

    $summary.Surfaces = Get-GfxRoleAggregate -Samples $Samples -DurationSec $wholeSec
    $summary.Arms.Idle = Get-GfxRoleAggregate -Samples $idleSamples -DurationSec $idleSecArg
    $summary.Arms.Session = Get-GfxRoleAggregate -Samples $sessionSamples -DurationSec $sessionSecArg
    $summary.Arms.After = Get-GfxRoleAggregate -Samples $afterSamples -DurationSec $afterSecArg
    $transitionSecArg = 0.0
    if ($null -ne $transitionSec) { $transitionSecArg = [double]$transitionSec }
    $summary.Arms.Transition = Get-GfxRoleAggregate -Samples $transitionSamples -DurationSec $transitionSecArg

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

    # Name the adapter each surface actually rendered on. The LUID is the
    # measurement; the name is a lookup on top of it, and stays absent when
    # the map cannot answer rather than being inferred from the adapter list.
    foreach ($surf in @($summary.Surfaces)) {
        $names = @()
        foreach ($luid in @($surf.AdapterLuids)) {
            $name = Resolve-GfxLuidName -Luid $luid -LuidMap $AdapterLuidMap
            if ($name) { $names += $name }
        }
        $surf.AdapterNames = @($names | Sort-Object -Unique)
    }

    # Which screen the visuals were drawn on, and what the baseline actually
    # contained. Both read from the arms above, so the report never has to
    # assert either one from a box someone once looked at.
    $summary.Visualizer = Get-GfxVisualizerPlacement -Samples $Samples
    $summary.BaselineVisualizer = Get-GfxBaselineVisualizerState -Summary $summary -VisualizerFloorPercent $VisualizerFloorPercent

    # A host or GPU pid changing mid-run means the process was replaced --
    # the pane-goes-blank failure class. Report the identities, not a count.
    foreach ($surf in @($summary.Surfaces)) {
        if (@($surf.HostPids).Count -gt 1 -or @($surf.GpuPids).Count -gt 1) {
            $summary.Restarts += @{ Role = $surf.Role; HostPids = $surf.HostPids; GpuPids = $surf.GpuPids }
        }
    }

    # Scored LAST: every deviation reads a field the walk above has already
    # filled in, and scoring against the profile from the finished summary --
    # rather than from live state -- is what keeps the app and the console
    # harness from growing two answers to the same question.
    #
    # Assigned WITHOUT an @() wrapper. The function returns ',$out' so a
    # single deviation cannot unroll, and wrapping that in @() produces one
    # element holding the whole list -- the same 'return ,@()' trap that cost
    # 86cfa77, caught here by replaying the 2026-09-18 captures, where a
    # two-deviation run rendered as one row with both keys jammed together.
    if ($BenchProfile) {
        $summary.ProfileDeviations = Get-GraphicsBenchProfileDeviations -Summary $summary -BenchProfile $BenchProfile
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
        [double]$MemoryGrowthWarnMBPerMin = 15,
        [double]$MemoryGrowthMinSeconds = 180,
        [double]$IdleFloorSec = $script:GfxIdleFloorSec
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

    # Memory growth is judged on the RATE, and only over a run long enough for
    # a rate to mean anything. Judging it on absolute MB made the finding a
    # function of run length: a short run could never trip it however fast the
    # leak, and a long one trips on ordinary warm-up. Below the minimum the
    # run is declared unable to answer, never quietly scored as clean.
    $memoryJudged = ($null -ne $Summary.DurationSec -and [double]$Summary.DurationSec -ge $MemoryGrowthMinSeconds)
    if ($memoryJudged) {
        foreach ($surf in @($Summary.Surfaces)) {
            $rate = $surf.WorkingSetGrowthMBPerMin
            if ($null -ne $rate -and [double]$rate -ge $MemoryGrowthWarnMBPerMin -and
                $null -ne $surf.WorkingSetGrowthMB -and [double]$surf.WorkingSetGrowthMB -ge $MemoryGrowthWarnMB) {
                $candidates += @{
                    Rank       = 3
                    Id         = 'GFX-MEMORY-GROWTH'
                    Title      = "$($surf.Role) host tree grew $([int]$surf.WorkingSetGrowthMB) MB during the run"
                    Result     = 'WARN'
                    AppliesTo  = 'Memory'
                    Evidence   = @(
                        "Working set went from $($surf.WorkingSetFirstMB) MB to $($surf.WorkingSetLastMB) MB over $($Summary.DurationSec) s ($rate MB/min).",
                        "Sustained above both gates: $MemoryGrowthWarnMBPerMin MB/min and $MemoryGrowthWarnMB MB total.",
                        "Host PIDs $($surf.HostPids -join ', ')."
                    )
                    ActionHint = 'Re-run for a full-length session on the same box; sustained growth at this rate is the 8 GB-machine failure mode.'
                }
            }
        }
    }

    $videoSurfaces = @($Summary.Surfaces | Where-Object { $_.Role -eq 'VideoJs' })
    foreach ($surf in $videoSurfaces) {
        $decodeMax = $null
        if ($surf.Engines -and $surf.Engines.ContainsKey('VideoDecode')) { $decodeMax = $surf.Engines['VideoDecode'].Max }
        # 'MediaOnly' is the classifier's word; this used to look for 'Media'
        # and so could never fire.
        $mediaSpans = @($Summary.Spans | Where-Object { $_.State -eq 'MediaOnly' -or $_.State -eq 'Both' })
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

    # THE BASELINE WAS MEASURED AT A DIFFERENT WINDOW SIZE THAN THE SESSION.
    # Ranked above the mid-session change because it is worse and quieter: the
    # mode can be perfectly steady for the whole session arm and every delta
    # still be meaningless, because the thing it is subtracted from was a
    # smaller pane. Measured on 2026-09-18 across three boxes -- inside ONE
    # session arm butterchurn read ~16% windowed and ~40% maximized, while the
    # box that stayed windowed end to end reported a session delta of 0.
    if ($Summary.WindowMode -and
        $Summary.WindowMode.IdleMode -and $Summary.WindowMode.IdleMode -ne 'Unknown' -and
        $Summary.WindowMode.Dominant -and $Summary.WindowMode.Dominant -ne 'Unknown' -and
        $Summary.WindowMode.IdleMode -ne $Summary.WindowMode.Dominant) {
        $candidates += @{
            Rank       = 3
            Id         = 'GFX-BASELINE-MODE-MISMATCH'
            Title      = "Idle baseline was measured $($Summary.WindowMode.IdleMode) but the session ran $($Summary.WindowMode.Dominant)"
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "The idle arm held $($Summary.WindowMode.IdleMode); the session arm was mostly $($Summary.WindowMode.Dominant).",
                'Butterchurn renders the whole pane, so its load follows window AREA. A delta taken across two window sizes is that size change plus the session, and the size change is the larger half of it.'
            )
            ActionHint = "Re-run with NO already $($Summary.WindowMode.Dominant.ToLower()) BEFORE you press Start watching, so both arms are the same shape."
        }
    }

    # The window's placement changed while the session was running, so the
    # session arm averages two shapes of pane. Changes before the split are
    # the operator arranging the screen and are not raised.
    if ($Summary.WindowMode -and $Summary.WindowMode.ChangedDuringSession) {
        $spanLines = @()
        foreach ($sp in @($Summary.WindowMode.Spans)) {
            $spanLines += ("{0} for {1}" -f $sp.Mode, (Format-GraphicsDuration $sp.DurationSec))
        }
        $candidates += @{
            Rank       = 4
            Id         = 'GFX-WINDOW-MODE-CHANGED'
            Title      = "NO's window changed between $(@($Summary.WindowMode.SessionModes) -join ' and ') during the session"
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "Placement spans: $($spanLines -join '; ').",
                'The session numbers above average across those shapes, so they are not comparable with a run held in one mode.'
            )
            # The operator maximizes NO by hand; NO does not do it. So the fix
            # is a step, not a re-run: do it before Start watching, while the
            # baseline has not been measured yet.
            ActionHint = 'Next run, set NO to its final window size BEFORE pressing Start watching, and leave it alone until the session ends.'
        }
    }

    # THE VISUALS ON A SCREEN OF THEIR OWN. Ranked with the window-mode
    # findings because it is the same defect class and worse: a second screen
    # drawing the visuals is a second GPU load the delta silently contains, and
    # nothing before this could see it. Raised for ANY run, not only one that
    # declared a profile -- an exploratory recording made this way is just as
    # unreadable, it simply is not a protocol departure.
    # THE VISUALS IN A WINDOW OF THEIR OWN. Raised for ANY run: a recording
    # made this way measures a different arrangement whether or not a profile
    # asked about it.
    # NOT RAISED WHEN THE TEST ASKED FOR IT: on the detached test this
    # arrangement is the measurement, and a WARN telling the tester to go and
    # run the test they are running reads as a failure they did not commit.
    if ($Summary.Visualizer -and [string]$Summary.Visualizer.Attachment -eq 'OwnWindow' -and -not $Summary.VisualizerDetachExpected) {
        $v = $Summary.Visualizer
        $screenLine = switch ($v.OnOtherDisplay) {
            $true   { "It was also on a different screen ($($v.MonitorDevice)) from the main window ($($v.MainMonitorDevice))." }
            $false  { 'It was on the SAME screen as the main window, so a check that only compared screens would have passed this run.' }
            default { 'Which screen it was on could not be read.' }
        }
        $candidates += @{
            Rank       = 3
            Id         = 'GFX-VISUALIZER-DETACHED'
            Title      = 'The visuals were drawn in a window of their own, not inside NeurOptimal'
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "The visualizer surface was hosted by a separate visible window titled '$($v.HostWindowTitle)' on $($v.DetachedSamples) of $($v.AttachmentSamples) readable sample(s), while NeurOptimal's own panel was visible elsewhere.",
                $screenLine,
                'This is what the separate visualizer full-screen button does, and it makes the numbers the cost of that arrangement rather than of the session alone.'
            )
            ActionHint = 'For a baseline recording, leave the visuals inside NeurOptimal and do not use the separate visualizer full-screen button. To measure this arrangement on purpose, use the Detached visualizer test.'
        }
    }

    if ($Summary.Visualizer -and $Summary.Visualizer.OnOtherDisplay -eq $true -and [string]$Summary.Visualizer.Attachment -ne 'OwnWindow') {
        $v = $Summary.Visualizer
        $candidates += @{
            Rank       = 3
            Id         = 'GFX-VISUALIZER-OTHER-DISPLAY'
            Title      = 'The visuals were drawn on a different screen from the NeurOptimal window'
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "The window hosting the visualizer reported display $($v.MonitorDevice); NeurOptimal's main window reported $($v.MainMonitorDevice).",
                'Two screens were drawing at once, so the numbers are the cost of that arrangement and not of the session alone.',
                "Which control put it there is not established: $($v.AttachmentReason)."
            )
            ActionHint = 'Put NeurOptimal and its visuals on one screen for a baseline recording, or use the Detached visualizer test to measure this arrangement on purpose.'
        }
    }

    # THE DISPLAY ARRANGEMENT CHANGED WHILE RECORDING. Same rank as the window
    # change and for the same reason: half the run measured a different screen,
    # so the deltas average two setups.
    $seenSetups = @($Summary.DisplaySetupsObserved | Where-Object { $_ } | Sort-Object -Unique)
    if ($seenSetups.Count -gt 1) {
        $candidates += @{
            Rank       = 4
            Id         = 'GFX-DISPLAY-SETUP-CHANGED'
            Title      = 'The screens changed while the recording was running'
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "Setups seen during the run: $($seenSetups -join ' / ').",
                'The visuals are drawn across the whole window, so their load follows the pixel area of the screen. A run spanning two setups has no single screen for its numbers to belong to.'
            )
            ActionHint = 'Set the screens up before pressing Start watching and leave them alone until the session ends, then re-run.'
        }
    }

    # Departures from the selected profile that no finding above already
    # names. The two window-mode keys are excluded on purpose: they each have
    # a dedicated finding with its own evidence, and the list is capped at
    # three, so letting them in twice would push a real defect off the screen.
    #
    # The $null test is load-bearing, not defensive: a summary from before
    # profiles existed has no ProfileDeviations key at all, @() over that
    # absent value yields ONE element holding $null, and $null.Key passes any
    # -ne filter. Without it this finding fires on every legacy capture --
    # which is exactly what the suite caught.
    $covered = @('WindowMode', 'BaselineMode', 'WindowChanged', 'BaselineLength',
                 'VisualizerOtherDisplay', 'VisualizerDetached', 'DisplaySetupChanged')
    $deviations = @($Summary.ProfileDeviations | Where-Object { $null -ne $_ -and $covered -notcontains $_.Key })
    if ($deviations.Count -gt 0) {
        $profileLabel = $Summary.ProfileName
        if ([string]::IsNullOrWhiteSpace($profileLabel)) { $profileLabel = $Summary.ProfileId }
        $candidates += @{
            Rank       = 5
            Id         = 'GFX-PROTOCOL-DEVIATION'
            Title      = "Run departed from the '$profileLabel' protocol in $($deviations.Count) way(s)"
            Result     = 'WARN'
            AppliesTo  = 'Protocol'
            Evidence   = @(@($deviations | ForEach-Object { [string]$_.Text }))
            ActionHint = 'The numbers in this package are real; they just do not belong in the same pool as runs that followed the profile. Re-run following the steps on the bench window to add this box to the corpus.'
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

    # A run with no idle stretch cannot answer the question the tool exists to
    # answer. It is reported as SKIP, not as a clean PASS: the whole-run
    # numbers are real, but nothing in them is attributable to the session.
    #
    # The two causes are distinguished because their remedies are opposite. If
    # NO was already busy when watching began, the operator did nothing wrong
    # and simply started too late; telling them to "start watching first" is
    # the advice they already followed.
    if ($Summary.SessionStartSource -eq 'none-detected') {
        if ($Summary.StartedMidSession) {
            $candidates += @{
                Rank       = 5
                Id         = 'GFX-STARTED-MID-SESSION'
                Title      = 'Watching began while NO was already busy, so there is no idle baseline'
                Result     = 'SKIP'
                AppliesTo  = 'Measurement'
                Evidence   = @(
                    "The very first samples of this run were already '$($Summary.StartActivity)' -- the video surface was decoding before watching started.",
                    'The session cost is a difference against an idle stretch on this same box. With no idle stretch there is nothing to subtract, so this run reports totals only.'
                )
                ActionHint = 'Wait for the current session to end, then press Start watching BEFORE the next one begins. The totals below are still valid for the corpus.'
            }
        } else {
            $candidates += @{
                Rank       = 5
                Id         = 'GFX-NO-SESSION-SPLIT'
                Title      = 'No session start seen, so nothing is attributable to the session'
                Result     = 'SKIP'
                AppliesTo  = 'Measurement'
                Evidence   = @(
                    "NO's window set never changed for $(Get-GfxUiChangeDwellSamples) consecutive samples, so the run has one arm and no deltas.",
                    'A whole-run percentage cannot be read as a session cost: it mixes whatever NO was doing before the session with the session itself, and nothing here separates them.'
                )
                ActionHint = 'Start watching FIRST, leave NeurOptimal alone until the line says Baseline collected, and only then start the session.'
            }
        }
    } elseif ($null -ne $Summary.ArmDurationSec.Idle -and [double]$Summary.ArmDurationSec.Idle -lt $IdleFloorSec) {
        # A split exists but the idle arm is shorter than the floor the live
        # line asks for. The deltas are real; their baseline is thin.
        $candidates += @{
            Rank       = 5
            Id         = 'GFX-IDLE-ARM-SHORT'
            Title      = "Idle baseline was only $(Format-GraphicsDuration $Summary.ArmDurationSec.Idle), under the $([int]$IdleFloorSec) s floor"
            Result     = 'WARN'
            AppliesTo  = 'Measurement'
            Evidence   = @(
                "The session started $(Format-GraphicsDuration $Summary.ArmDurationSec.Idle) after watching began; the floor is $([int]$IdleFloorSec) s.",
                'Every delta is session minus this idle mean, so a short idle arm makes every delta less certain.'
            )
            ActionHint = 'Next run, wait until the guide says Baseline collected before starting the session.'
        }
    }

    if ($candidates.Count -eq 0) {
        $memoryLine = if ($memoryJudged) {
            "No memory growth above $MemoryGrowthWarnMBPerMin MB/min."
        } else {
            "Run shorter than $MemoryGrowthMinSeconds s, so memory growth was not judged either way."
        }
        $evidence = @(
            "$($Summary.SampleCount) samples over $($Summary.DurationSec) s.",
            "No host restart, no counter loss. $memoryLine"
        )
        if ($Summary.ProfileId) { $evidence += "Followed the '$($Summary.ProfileName)' protocol with no deviations, so this run pools directly with the corpus." }
        $candidates += @{
            Rank       = 9
            Id         = 'GFX-RUN-CLEAN'
            Title      = 'Graphics run completed with no anomalies detected'
            Result     = 'PASS'
            AppliesTo  = 'Graphics'
            Evidence   = $evidence
            # The package is sent by the run itself when it stops; whether it
            # arrived is on the Results step. An instruction to upload it by
            # hand was left over from when sending was manual.
            ActionHint = 'Nothing to fix. This recording can be compared with the other baseline recordings.'
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
        [array]$ReportRecords = @(),
        [switch]$NoZip
    )

    $Session | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Run.SessionPath -Encoding UTF8

    # The full report goes in the package as text. The screen shows only what
    # a tech acts on; everything trimmed off it has to survive somewhere a
    # reader can open without parsing JSON, or trimming the screen would be
    # deleting evidence rather than moving it.
    $artifacts = @('events.jsonl', 'bench-session.json')
    if (@($ReportRecords).Count -gt 0) {
        try {
            $reportPath = Join-Path $Run.RunFolder 'report.txt'
            $lines = @(@($ReportRecords) | ForEach-Object { [string]$_.Text })
            [System.IO.File]::WriteAllLines($reportPath, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
            $artifacts += 'report.txt'
        } catch { }
    }

    $cohort = $null
    try { $cohort = $Session.inventory.Cohort } catch { }

    $manifest = @{
        toolId        = 'graphics-bench'
        runId         = $Run.RunId
        runMode       = $Session.runMode
        createdUtc    = [datetime]::UtcNow.ToString('o')
        artifacts     = $artifacts
        sampleCount   = $Session.summary.SampleCount
        durationSec   = $Session.summary.DurationSec
        countersOk    = $Session.summary.CountersOk
        # The cohort rides in the manifest so the ingest side can pool a
        # package without opening the session file.
        cohortKey     = $(if ($cohort) { $cohort.Key } else { $null })
        cohort        = $cohort
        # WHICH KEY SHAPE. Version 2 keys on the display ARRANGEMENT; version 1
        # keyed on resolutions and a count and pooled a built-in panel with an
        # external monitor of the same size. The ingest side needs to know which
        # it is holding, because the two do not pool with each other -- and
        # should not.
        cohortVersion = $(if ($cohort -and $cohort.Version) { $cohort.Version } else { 1 })
        # Window placement rides along for the same reason: a pool of runs
        # should be split by it without opening every session file. Additive;
        # schemaVersion stays 1.
        windowMode        = $(try { $Session.summary.WindowMode.Dominant } catch { $null })
        windowModeChanged = $(try { [bool]$Session.summary.WindowMode.ChangedDuringSession } catch { $null })
        # Which arm the baseline was measured in. A pool that ignores this
        # compares deltas taken across different window sizes.
        idleWindowMode    = $(try { $Session.summary.WindowMode.IdleMode } catch { $null })
        # The protocol the run claimed and whether it held to it, so the ingest
        # side can pool by test without opening the session file. Additive;
        # schemaVersion stays 1. A run with no profileId predates profiles and
        # is unscored, which is not the same as having deviated.
        profileId             = $(try { $Session.summary.ProfileId } catch { $null })
        profileDeviationCount = $(try { @($Session.summary.ProfileDeviations).Count } catch { $null })
        monitorCount          = $(try { $Session.summary.MonitorCount } catch { $null })
        # WHICH SCREEN, in the manifest, for the same reason the window mode is:
        # a pool should be split by it without opening every session file, and
        # a 49-inch external display and a 14-inch built-in panel are not the
        # same measurement however alike their display COUNTS look. Additive;
        # schemaVersion stays 1.
        displaySetup          = $(try { $Session.summary.DisplayArrangement.Layout } catch { $null })
        displaySignature      = $(try { $Session.summary.DisplayArrangement.Signature } catch { $null })
        displaySetupChanged   = $(try { (@($Session.summary.DisplaySetupsObserved).Count -gt 1) } catch { $null })
        builtInDisplayState   = $(try { $Session.summary.DisplayArrangement.BuiltIn.State } catch { $null })
        # The SCREEN is scored; the WINDOW is recorded and not scored, because
        # NO relocates its panes between windows on its own. visualizerHostWindows
        # is the evidence the first capture taken with the separate visualizer
        # control pressed will be compared against.
        visualizerOnOtherDisplay = $(try { $Session.summary.Visualizer.OnOtherDisplay } catch { $null })
        visualizerAttachment     = $(try { $Session.summary.Visualizer.Attachment } catch { $null })
        visualizerHostWindowTitle = $(try { $Session.summary.Visualizer.HostWindowTitle } catch { $null })
        # Every host-window title seen, so an unrecognised one can be read out
        # of a package and taught to the classifier -- the same way the
        # Bluetooth lexicon carries UnknownWindowTitles.
        visualizerHostWindowTitles = $(try { @($Session.summary.Visualizer.HostWindowTitlesSeen) } catch { $null })
        visualizerHostWindows    = $(try { @($Session.summary.Visualizer.HostWindowsSeen) } catch { $null })
        baselineVisualizer    = $(try { $Session.summary.BaselineVisualizer.State } catch { $null })
        # Whether the SESSION arm was cut at the operator's second mark, and how
        # long the manual transition it excluded took. A pool that ignores this
        # compares a steady period against a whole session.
        transitionSec         = $(try { $Session.summary.TransitionSpan.DurationSec } catch { $null })
        transitionApplied     = $(try { [bool]$Session.summary.TransitionSpan.Applied } catch { $null })
        # 'Unverified' on every run so far, on purpose: a window's placement
        # does not record which control set it. The field answers this, not the
        # tool -- read it beside windowMode across packages.
        appFullScreen         = 'Unverified'
        # How much of the monitor the window actually covered, per arm. Two
        # runs that both say 'maximized' can differ by a taskbar strip, and
        # that difference is drawn area.
        idleScreenFraction    = $(try { $Session.summary.WindowMode.IdleScreenFraction } catch { $null })
        sessionScreenFraction = $(try { $Session.summary.WindowMode.SessionScreenFraction } catch { $null })
        # The area the visuals were actually drawn into, in DESKTOP pixels --
        # the quantity the numbers follow. Measured across two displays on one
        # box: a physical-pixel model of the cost needs a negative fixed term
        # and is refuted; this one does not.
        idleWindowDesktopPixels    = $(try { $Session.summary.WindowMode.IdleWindowDesktopPixels } catch { $null })
        sessionWindowDesktopPixels = $(try { $Session.summary.WindowMode.SessionWindowDesktopPixels } catch { $null })
        # The raw style word, so the question of which control set the window
        # can be re-asked of an old package without a new build.
        windowStyleHex        = $(try { $Session.summary.WindowMode.StyleHex } catch { $null })
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

function Format-GraphicsClock {
    <#
    .SYNOPSIS
        Elapsed time as mm:ss, for progress a tester reads against a target.
    .DESCRIPTION
        Distinct from Format-GraphicsDuration, which writes '8m32s' and is what
        a report says. '08:32 of 15:00' is what a clock says, and a phase line
        counting toward a target reads as a clock.
    #>
    [CmdletBinding()]
    param($Seconds)
    if ($null -eq $Seconds) { return [string][char]0x2014 }
    $ts = [TimeSpan]::FromSeconds([math]::Max(0, [double]$Seconds))
    # FLOOR, not [int]. A PowerShell cast rounds, so 512 s rendered as '09:32'
    # -- a clock a full minute ahead of itself for most of every minute, and
    # the number a tester reads to decide the session has run long enough.
    if ($ts.TotalHours -ge 1) { return ('{0}:{1:00}:{2:00}' -f [int][math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds) }
    return ('{0:00}:{1:00}' -f [int][math]::Floor($ts.TotalMinutes), $ts.Seconds)
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
        [hashtable]$Nomp,
        [switch]$Compact
    )

    # COMPACT is what a tech reads on screen: the four facts that decide
    # whether this run is comparable at all -- what the box is, which GPU is
    # driving, whether it is on battery, and which cohort it will be pooled
    # into. Everything else is in the package, which is where a number is
    # looked up rather than glanced at.
    if ($Compact) {
        $r = @()
        $machine = ("$($Inventory.System.Manufacturer) $($Inventory.System.Model)").Trim()
        $onBattery = ($Inventory.Power.HasBattery -and $Inventory.Power.OnBattery)
        $powerText = if (-not $Inventory.Power.HasBattery) { 'desktop' } elseif ($onBattery) { 'ON BATTERY' } else { 'on AC' }
        $r += @{ Level = 'INFO'; Text = ("  {0,-10}{1}  |  {2} build {3}  |  NO {4}  |  {5}" -f 'SYSTEM', (Format-GraphicsValue $machine), (Format-GraphicsValue $Inventory.System.OsCaption), (Format-GraphicsValue $Inventory.System.OsBuild), (Format-GraphicsValue $Inventory.No.Version), $powerText); NoPrefix = $true }

        $driving = @($Inventory.DisplayDrivingAdapters)
        $drivingText = if ($driving.Count -gt 0) { $driving -join ', ' } else { [string][char]0x2014 }
        $r += @{ Level = 'INFO'; Text = ("  {0,-10}display driven by {1}  |  WebView2 {2}" -f 'GRAPHICS', $drivingText, (Format-GraphicsValue $Inventory.WebView2.Version)); NoPrefix = $true }
        # THE ARRANGEMENT, not the count. A resolution list beside "1
        # monitor(s)" reads as a controlled setup on a laptop running one
        # 5120x1440 external screen with the lid shut, which is the case this
        # whole block exists to make visible.
        foreach ($line in (Format-GfxDisplaySetupLines -Arrangement $Inventory.DisplayArrangement -NoDisplay $null -NoDisplayReason $null)) {
            if ($line.Key -eq 'NoLocation') { continue }
            $r += @{ Level = $(if ($line.Level -eq 'Unknown') { 'WARN' } else { 'DIM' }); Text = ("  {0,-10}{1}" -f '', $line.Text); NoPrefix = $true }
        }

        if ($Inventory.HybridGpu) {
            # Which adapter each pane used is in the grid's own column, so the
            # panel only has to say that there is more than one to choose from.
            $r += @{ Level = 'DIM'; Text = ("  {0,-10}hybrid GPU: {1}" -f '', ((@($Inventory.Adapters) | ForEach-Object { $_.Name }) -join ' + ')); NoPrefix = $true }
        }
        if ($onBattery) {
            $r += @{ Level = 'WARN'; Text = ("  {0,-10}on battery -- GPU and CPU are throttled, so this run is NOT comparable." -f ''); NoPrefix = $true }
        }
        $cohortText = if ($Inventory.Cohort -and $Inventory.Cohort.Key) { $Inventory.Cohort.Key } else { 'unknown -- this run cannot be pooled' }
        $r += @{ Level = 'DIM'; Text = ("  {0,-10}{1}" -f 'COHORT', $cohortText); NoPrefix = $true }
        return $r
    }

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
    # THE ARRANGEMENT, in full: identity, mode, refresh and scale per display,
    # so two runs made on two different external monitors stay distinguishable
    # in the package without anyone having to remember which room they were in.
    $arr = $Inventory.DisplayArrangement
    if ($arr) {
        $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'Display setup', $arr.LayoutText); NoPrefix = $true }
        foreach ($d in @($arr.Displays)) {
            $kind = if ($d.Internal -eq $true) { 'built-in' } elseif ($d.Internal -eq $false) { 'external' } else { 'kind unknown' }
            $primary = if ($d.Primary) { ', primary' } else { '' }
            $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  ({2}{3})" -f 'Display', (Format-GfxDisplayLabel -Display $d), $kind, $primary); NoPrefix = $true }
            $hz = if ($null -ne $d.RefreshExact) { "$($d.RefreshExact) Hz exact" } else { [string][char]0x2014 }
            $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  |  {2}  |  {3}" -f '', (Format-GraphicsValue $d.GdiName), (Format-GraphicsValue $d.Connection), $hz); NoPrefix = $true }
            if ($d.DevicePath) { $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}" -f '', $d.DevicePath); NoPrefix = $true } }
        }
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}" -f 'Built-in', $arr.BuiltIn.StateText); NoPrefix = $true }
        if ($arr.BuiltIn.Inferred) {
            $r += @{ Level = 'DIM'; Text = ("  {0,-14}INFERRED from this machine having a battery -- Windows enumerated no built-in panel" -f ''); NoPrefix = $true }
        }
        foreach ($e in @($arr.Errors)) {
            $r += @{ Level = 'WARN'; Text = ("  {0,-14}partly unread: {1}" -f '', $e); NoPrefix = $true }
        }
    } else {
        foreach ($d in @($Inventory.Displays)) {
            $primary = if ($d.Primary) { '  (primary)' } else { '' }
            $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  {2}{3}" -f 'Display', (Format-GraphicsValue $d.DeviceName), (Format-GraphicsValue $d.Bounds), $primary); NoPrefix = $true }
        }
    }
    $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}  (NO fixed-version runtime)" -f 'WebView2', (Format-GraphicsValue $Inventory.WebView2.Version)); NoPrefix = $true }

    # The LUID map is what lets a measured surface name its adapter. Printing
    # it makes the resolution auditable instead of a claim.
    foreach ($luid in @($Inventory.AdapterLuidMap.Keys | Sort-Object)) {
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}  ->  {2}" -f 'LUID', $luid, (Format-GraphicsValue $Inventory.AdapterLuidMap[$luid].Description)); NoPrefix = $true }
    }
    if (@($Inventory.AdapterLuidMap.Keys).Count -eq 0) {
        $r += @{ Level = 'WARN'; Text = ("  {0,-14}adapter LUID map unavailable -- surfaces will report a LUID with no adapter name" -f 'LUID'); NoPrefix = $true }
    }
    if ($Inventory.Cohort) {
        $cohortText = if ($Inventory.Cohort.Key) { $Inventory.Cohort.Key } else { "unpooled ($($Inventory.Cohort.Reason))" }
        $r += @{ Level = 'INFO'; Text = ("  {0,-14}{1}" -f 'Cohort', $cohortText); NoPrefix = $true }
    }
    if ($Nomp) {
        $nompText = if ($Nomp.Exists) { "schema only: $(@($Nomp.SchemaKeysPresent).Count) known fields declared, no values stored" } else { 'not found' }
        $r += @{ Level = 'DIM'; Text = ("  {0,-14}{1}" -f 'NOMP config', $nompText); NoPrefix = $true }
    }
    return $r
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
        [hashtable]$MediaFile,
        [ValidateSet('Full', 'Compact')]
        [string]$Detail = 'Full',
        # The test the run claimed, so the status line can tell 'nothing
        # departed' apart from 'nothing could be checked'. Absent falls back
        # to the profile's own id, which still yields a correct outcome for
        # every registry-known test.
        [hashtable]$BenchProfile
    )

    $dash = [string][char]0x2014
    $compact = ($Detail -eq 'Compact')
    $r = @()

    $r += @{ Level = 'STEP'; Text = ("RESULTS   {0}   {1} samples" -f (Format-GraphicsDuration $Summary.DurationSec), $Summary.SampleCount); NoPrefix = $true }

    # WHICH TEST THIS WAS, immediately under the duration. A package that does
    # not say which protocol it followed cannot be pooled by anything except a
    # human remembering what they told the tester, which is the failure the
    # 2026-09-18 campaign ran into five times in one morning.
    if ($Summary.ProfileId) {
        $prof = $BenchProfile
        if (-not $prof) { $prof = Get-GraphicsBenchProfile -Id $Summary.ProfileId }
        $outcome = Get-GraphicsBenchProfileOutcome -Summary $Summary -BenchProfile $prof
        $r += @{ Level = 'DIM'; Text = ("  Test          {0}" -f $Summary.ProfileName); NoPrefix = $true }
        $level = if ($outcome.Level -eq 'Healthy') { 'DIM' } else { 'WARN' }
        $r += @{ Level = $level; Text = ("  Status        {0}" -f $outcome.Text); NoPrefix = $true }
        foreach ($d in @($outcome.Deviations)) {
            $r += @{ Level = 'WARN'; Text = ("                  - {0}" -f $d.Text); NoPrefix = $true }
            # The technical phrasing rides UNDER the tester's, never instead
            # of it: 'cohort key' and 'session arm' are what an engineer needs
            # to act on the package and what a tester has no use for.
            if ($d.Detail) { $r += @{ Level = 'DIM'; Text = ("                    {0}" -f $d.Detail); NoPrefix = $true } }
        }
    }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }

    # --- the headline: session minus this box's own idle arm ---
    $r += @{ Level = 'STEP'; Text = 'WHAT THE SESSION COST'; NoPrefix = $true }
    if (-not $compact) {
        $r += @{ Level = 'DIM'; Text = '  Session mean minus this box own idle baseline, measured minutes earlier on the'; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = '  same hardware, driver, NO launch, window size and screen. The absolute'; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = '  percentage answers nothing on its own -- the delta does, and only against a'; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = '  baseline whose contents are stated. What this baseline contained is below.'; NoPrefix = $true }
    }

    if ($Summary.SessionStartSource -eq 'none-detected') {
        if ($Summary.StartedMidSession) {
            $r += @{ Level = 'WARN'; Text = "  NO was ALREADY BUSY when watching began (first samples read '$($Summary.StartActivity)'),"; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  so this run has no idle baseline to subtract and reports totals only.'; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  Next time: wait for the session to end, then Start watching before the next one.'; NoPrefix = $true }
        } else {
            $r += @{ Level = 'WARN'; Text = '  No session start was seen, so this run has no idle/session split and no deltas.'; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  The table above is the whole run and is still valid, but none of it is'; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  attributable to the session. Re-run: Start watching, leave NO idle until the'; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  line says Baseline collected, then start the session.'; NoPrefix = $true }
        }
    } else {
        $r += @{ Level = 'DIM'; Text = ("  {0,-13}{1,-17}{2,10}{3,12}{4,12}" -f 'surface', 'engine', 'idle', 'session', 'delta'); NoPrefix = $true }
        # On screen, an engine a surface never touched contributes three
        # zeroes and no information. The package keeps every row; the compact
        # rendering keeps the ones that moved.
        $shown = @($Summary.Deltas)
        if ($compact) {
            $shown = @($shown | Where-Object {
                ($null -ne $_.SessionMean -and [math]::Abs([double]$_.SessionMean) -ge 0.05) -or
                ($null -ne $_.IdleMean -and [math]::Abs([double]$_.IdleMean) -ge 0.05)
            })
        }
        if (@($shown).Count -eq 0) {
            $r += @{ Level = 'INFO'; Text = "  $dash"; NoPrefix = $true }
        }
        foreach ($d in @($shown | Sort-Object Role, Engine)) {
            $deltaText = if ($null -eq $d.DeltaMean) { $dash } else { ('{0}{1}%' -f $(if ($d.DeltaMean -ge 0) { '+' } else { '' }), [math]::Round($d.DeltaMean, 1)) }
            $level = if ($null -eq $d.DeltaMean) { 'DIM' } elseif ($d.DeltaMean -ge 1) { 'WARN' } else { 'INFO' }
            $r += @{ Level = $level; Text = ("  {0,-13}{1,-17}{2,10}{3,12}{4,12}" -f $d.Role, $d.Engine, (Format-GraphicsValue $d.IdleMean '%'), (Format-GraphicsValue $d.SessionMean '%'), $deltaText); NoPrefix = $true }
        }
        $split = $dash
        try { $split = ([datetime]$Summary.SessionStartUtc).ToLocalTime().ToString('HH:mm:ss') } catch { }
        $endText = 'ran to Stop'
        if ($Summary.SessionEndSource -and $Summary.SessionEndSource -ne 'none-detected') {
            $endAt = $dash
            try { $endAt = ([datetime]$Summary.SessionEndUtc).ToLocalTime().ToString('HH:mm:ss') } catch { }
            $endText = "ended at $endAt (Session Complete)"
        }
        $r += @{ Level = 'DIM'; Text = ("  idle arm {0}  |  session arm {1}, {2}  |  split at {3} ({4})" -f (Format-GraphicsDuration $Summary.ArmDurationSec.Idle), (Format-GraphicsDuration $Summary.ArmDurationSec.Session), $endText, $split, $Summary.SessionStartSource); NoPrefix = $true }
        # THE MANUAL TRANSITION, ON ITS OWN LINE. It is deliberately not in the
        # table above: it is someone dragging a window between screens, which
        # is neither the baseline nor the steady period, and averaging it into
        # either makes both wrong.
        if ($Summary.TransitionSpan) {
            $ts = $Summary.TransitionSpan
            if ($ts.Applied) {
                $r += @{ Level = 'DIM'; Text = ("  transition {0} (marked by the operator) is EXCLUDED from the session arm; the numbers above start when the visuals settled." -f (Format-GraphicsDuration $ts.DurationSec)); NoPrefix = $true }
            } else {
                $r += @{ Level = 'WARN'; Text = ("  transition {0} was marked but falls outside the recorded session, so the arms were not cut around it." -f (Format-GraphicsDuration $ts.DurationSec)); NoPrefix = $true }
            }
        } elseif ($BenchProfile -and $BenchProfile.Requires -and $BenchProfile.Requires.ContainsKey('TransitionMarkers')) {
            $r += @{ Level = 'WARN'; Text = '  This test asks for the detach to be marked at both ends. It was not, so the numbers above span the manual transition.'; NoPrefix = $true }
        }
        if ($Summary.WindowMode) {
            $wm = $Summary.WindowMode
            $wmText = "  NO window: {0}" -f (Format-GraphicsValue $wm.Dominant)
            if ($wm.Bounds) { $wmText += " $($wm.Bounds)" }
            # HOW MUCH OF THE SCREEN, beside the label. 'Maximized' is not a
            # quantity; the fraction is, and it is what the numbers follow.
            # [math]::Round, written out: a bare [int] cast ROUNDS in
            # PowerShell rather than truncating, so 0.979 renders 98 and not
            # 97. Stating the intent stops the next reader assuming the other.
            if ($null -ne $wm.SessionScreenFraction) { $wmText += (", covering {0}% of the screen" -f [math]::Round([double]$wm.SessionScreenFraction * 100)) }
            # THE NUMBER TO COMPARE ACROSS BOXES. The visuals are drawn into a
            # target sized in DESKTOP pixels, so this -- not the monitor's
            # resolution and not the covered fraction -- is what the deltas
            # follow. Two machines are comparable on the visualizer when this
            # matches; a 150% display gives 2.25x fewer of them than the same
            # panel at 100%.
            if ($null -ne $wm.SessionWindowDesktopPixels) { $wmText += (" = {0:N0} desktop pixels drawn" -f $wm.SessionWindowDesktopPixels) }
            if ($wm.ChangedDuringSession) { $wmText += "  CHANGED during the session ($(@($wm.SessionModes) -join ' / '))" }
            $r += @{ Level = $(if ($wm.ChangedDuringSession) { 'WARN' } else { 'DIM' }); Text = $wmText; NoPrefix = $true }
            # Both arms' modes on one line, because the delta above is only a
            # session cost when they match. Printed whenever they differ, even
            # if the session itself never changed shape.
            if ($wm.IdleMode -and $wm.IdleMode -ne 'Unknown' -and $wm.Dominant -ne 'Unknown' -and $wm.IdleMode -ne $wm.Dominant) {
                $r += @{ Level = 'WARN'; Text = ("  Baseline was measured {0} and the session ran {1} {2} the deltas above include that size change." -f $wm.IdleMode, $wm.Dominant, $dash); NoPrefix = $true }
            }
        }

        # WHICH SCREEN, AND WHAT THE BASELINE CONTAINED. Both printed with the
        # numbers rather than in a footnote, because both change what the
        # numbers mean and a reader who does not scroll is the common case.
        if ($Summary.DisplayArrangement) {
            $arr = $Summary.DisplayArrangement
            $screens = @(@($arr.Displays) | ForEach-Object { Format-GfxDisplayLabel -Display $_ })
            $screenText = if ($screens.Count -gt 0) { $screens -join '; ' } else { $dash }
            $r += @{ Level = 'DIM'; Text = ("  Measured on: {0} {1} {2}" -f $arr.LayoutText, $dash, $screenText); NoPrefix = $true }
        }
        if ($Summary.Visualizer -and $Summary.Visualizer.OnOtherDisplay -eq $true) {
            $r += @{ Level = 'WARN'; Text = '  The visuals were drawn on a DIFFERENT SCREEN from the main NeurOptimal window,'; NoPrefix = $true }
            $r += @{ Level = 'WARN'; Text = '  so the numbers above are the cost of two screens drawing at once.'; NoPrefix = $true }
        }
        # THE CORRECTION THIS BLOCK EXISTS FOR. It used to be asserted, from one
        # box, that the visuals draw while NO is idle -- which makes the delta
        # read as the session's own extra cost. On a machine where the visuals
        # are not on screen until a session starts, the same delta is the cost
        # of the visualization APPEARING plus the session, and nothing said so.
        # It is now read off the idle arm and printed either way.
        if ($Summary.BaselineVisualizer -and $Summary.BaselineVisualizer.Text) {
            $lvl = if ($Summary.BaselineVisualizer.State -eq 'AboveFloor') { 'DIM' } else { 'WARN' }
            $r += @{ Level = $lvl; Text = ("  {0}" -f $Summary.BaselineVisualizer.Text); NoPrefix = $true }
        }

        # AUDIO-ONLY IS NOT A FAULT. An audio session draws butterchurn and
        # nothing else, so the decode engines read a structural zero. Saying so
        # here stops a reader treating the run's largest block of zeroes as a
        # missing hardware decode path.
        $audioSpans = @($Summary.Spans | Where-Object { $_.State -eq 'AudioLikely' })
        $decodeSpans = @($Summary.Spans | Where-Object { $_.State -eq 'MediaOnly' -or $_.State -eq 'Both' })
        if ($audioSpans.Count -gt 0 -and $decodeSpans.Count -eq 0) {
            $r += @{ Level = 'DIM'; Text = '  Zero video decode activity is expected for this audio-only test.'; NoPrefix = $true }
        }
        $addedTitles = @()
        foreach ($c in @($Summary.NoUiChanges)) { $addedTitles += @($c.Added) }
        if ($addedTitles.Count -gt 0) {
            $r += @{ Level = 'DIM'; Text = ("  NO opened: {0}" -f (@($addedTitles | Sort-Object -Unique) -join ', ')); NoPrefix = $true }
        }
    }
    $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }

    # --- media file, when the run could be labelled ---
    if ($MediaFile -and $compact -and $MediaFile.file) {
        $r += @{ Level = 'INFO'; Text = ("  Media opened by NO: {0}" -f (Split-Path $MediaFile.file -Leaf)); NoPrefix = $true }
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    }
    if ($MediaFile -and -not $compact) {
        $mediaText = if ($MediaFile.file) { "$(Split-Path $MediaFile.file -Leaf)" } else { 'Unknown -- no media file was opened under the watched root' }
        $r += @{ Level = 'INFO'; Text = ("  Media opened by NO: {0}" -f $mediaText); NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = ("  watched root {0} ({1})" -f (Format-GraphicsValue $MediaFile.root), (Format-GraphicsValue $MediaFile.rootSource)); NoPrefix = $true }
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
    }

    # --- time in each state (package only: the live grid already shows it) ---
    if (-not $compact) {
        $r += @{ Level = 'STEP'; Text = 'TIME IN EACH STATE'; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = '  Quiet / VisualizerOnly / MediaOnly / AudioLikely / Both, inferred from GPU engine load.'; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = '  AudioLikely = video.js drawing its controls with nothing decoding: what audio-only playback looks like from here.'; NoPrefix = $true }
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

        # --- window placement, as spans ---
        if ($Summary.WindowMode) {
            $r += @{ Level = 'STEP'; Text = 'WINDOW MODE'; NoPrefix = $true }
            $r += @{ Level = 'DIM'; Text = '  How NO''s window was placed, read from its placement each sample (not from NO).'; NoPrefix = $true }
            if (@($Summary.WindowMode.Spans).Count -eq 0) { $r += @{ Level = 'INFO'; Text = "  $dash"; NoPrefix = $true } }
            foreach ($sp in @($Summary.WindowMode.Spans)) {
                $from = $dash
                try { $from = ([datetime]$sp.StartUtc).ToLocalTime().ToString('HH:mm:ss') } catch { }
                $r += @{ Level = 'INFO'; Text = ("  {0,-12}{1,-10}from {2}" -f $sp.Mode, (Format-GraphicsDuration $sp.DurationSec), $from); NoPrefix = $true }
            }
            $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
        }

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
            $adapterText = if (@($surf.AdapterNames).Count -gt 0) { @($surf.AdapterNames) -join ', ' } else { 'unresolved LUID' }
            $r += @{ Level = 'DIM'; Text = ("  {0,-13}rendered on {1} (LUID {2}) | host PID(s) {3} | GPU PID(s) {4} | present in {5} of samples" -f '', $adapterText, $luidText, ($surf.HostPids -join ', '), ($surf.GpuPids -join ', '), $presence); NoPrefix = $true }
            $r += @{ Level = 'DIM'; Text = ("  {0,-13}CPU mean {1} | working set {2} -> {3} MB (growth {4} MB, {5} MB/min) | VRAM mean {6} MB" -f '', (Format-GraphicsValue $surf.Cpu.Mean '%'), (Format-GraphicsValue $surf.WorkingSetFirstMB), (Format-GraphicsValue $surf.WorkingSetLastMB), (Format-GraphicsValue $surf.WorkingSetGrowthMB), (Format-GraphicsValue $surf.WorkingSetGrowthMBPerMin), (Format-GraphicsValue $surf.GpuMemoryMB.Mean)); NoPrefix = $true }
            $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
        }
    }

    # --- operator markers ---
    if (-not $compact -and @($Summary.Markers).Count -gt 0) {
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
    if (-not $compact) {
        $r += @{ Level = 'INFO'; Text = ''; NoPrefix = $true }
        $r += @{ Level = 'DIM'; Text = ("  Sampler cost: tick mean {0} ms, p95 {1} ms, max {2} ms." -f (Format-GraphicsValue $Summary.TickMs.Mean '' 0), (Format-GraphicsValue $Summary.TickMs.P95 '' 0), (Format-GraphicsValue $Summary.TickMs.Max '' 0)); NoPrefix = $true }
    }

    return ,$r
}

function Get-GfxGridScalar {
    <#
    .SYNOPSIS
        One reading out of a surface record, whichever arm it came from.
    .DESCRIPTION
        The two arms carry the same quantity in two SHAPES. A live sample holds
        the raw reading ($surf.Engines['3D'] is a double, $surf.CpuPercent is a
        double); an aggregated surface holds a Get-GfxStats table and the
        reading wanted is its Mean. Every caller that reached into one shape
        directly is a caller that could only ever render one arm, which is how
        the live grid and the result grid ended up as two renderers of one
        contract.

        Absent stays absent. A missing engine, an empty stats table and a
        surface with no counters all return $null, and Format-GraphicsValue
        turns that into an em dash -- never into a measured zero.
    #>
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return $null }
    # Aggregated arm: a Get-GfxStats table. Its Mean is $null for an empty
    # series, and that $null is the honest answer, not a reason to look further.
    if ($Value -is [hashtable]) {
        if ($Value.ContainsKey('Mean')) { return $Value['Mean'] }
        return $null
    }
    return $Value
}

function Get-GfxGridEngine {
    <#
    .SYNOPSIS
        One engine's reading off a surface, in either arm's shape.
    #>
    [CmdletBinding()]
    param($Engines, [Parameter(Mandatory)][string]$Name)

    if ($null -eq $Engines) { return $null }
    if ($Engines -isnot [hashtable]) { return $null }
    if (-not $Engines.ContainsKey($Name)) { return $null }
    return Get-GfxGridScalar -Value $Engines[$Name]
}

function Get-GraphicsBenchGridRows {
    <#
    .SYNOPSIS
        The surface grid as ordered rows. THE one place a grid row is decided,
        for BOTH the live tick and the finished result.
    .DESCRIPTION
        The app paints these into a ListView and the package carries the same
        values; neither surface computes a cell of its own.

        TWO ARMS, ONE CONTRACT. -Summary renders whole-run means, because the
        grid IS the on-screen summary once a run has stopped and the last live
        sample is not a result. -Sample renders the latest reading while a run
        is under way. Both emit the same nine cells in the same order with the
        same em-dash rule and the same unresolved flag, so the grid a tech
        watches during a session and the grid they screenshot afterwards can
        never disagree about what a column means.

        This used to be one function plus a hand-rolled copy of it inside the
        window's tick handler. The copy resolved the adapter name differently
        (first LUID that answered, rather than every name the surface rendered
        on) and reached into the live shape directly, so it could never have
        been pointed at a summary. Two renderers of one contract is this
        repo's channel-mismatch bug class; it is deleted here rather than
        guarded against.
    .PARAMETER Summary
        A Get-GraphicsBenchSessionSummary result. Whole-run means.
    .PARAMETER Sample
        One 'Sample' record from the sampler. $null yields no rows -- a tick
        before the first sample has nothing to show, which is not an error.
    .PARAMETER AdapterLuidMap
        LUID -> adapter map from Get-GraphicsInventory, used only by -Sample:
        a summary has already had its AdapterNames resolved.
    .OUTPUTS
        Array of @{ Cells[]; Unresolved; Role; Level } in column order:
        surface, state, adapter, 3D, decode, videoproc, CPU, working set,
        VRAM, present.

        STATE IS A COLUMN, NOT A COLOUR. The numbers say what a surface cost;
        the state word says what it was doing, which is the question answered
        at a glance and the one a phone screenshot has to survive. It carries
        a text marker as well as a level for the same reason every Flight
        Recorder panel does: roughly one man in twelve cannot separate this
        palette's green from its amber.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Summary')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Summary')][hashtable]$Summary,
        [Parameter(Mandatory, ParameterSetName = 'Sample')][AllowNull()]$Sample,
        [Parameter(ParameterSetName = 'Sample')][hashtable]$AdapterLuidMap
    )

    $rows = @()
    $surfaces = @()
    if ($PSCmdlet.ParameterSetName -eq 'Summary') {
        $surfaces = @($Summary.Surfaces)
    } elseif ($null -ne $Sample) {
        $surfaces = @($Sample.Surfaces)
    }

    foreach ($surf in $surfaces) {
        if ($null -eq $surf) { continue }

        # Adapter names. On a hybrid box this column is the whole question, so
        # it names EVERY adapter the surface was measured on rather than the
        # first LUID that happened to resolve -- and stays an em dash when the
        # map cannot answer, rather than naming a guess.
        $names = @()
        if ($PSCmdlet.ParameterSetName -eq 'Summary') {
            $names = @($surf.AdapterNames)
        } else {
            foreach ($luid in @($surf.AdapterLuids)) {
                $n = Resolve-GfxLuidName -Luid $luid -LuidMap $AdapterLuidMap
                if ($n) { $names += $n }
            }
            $names = @($names | Sort-Object -Unique)
        }
        $adapter = if (@($names).Count -gt 0) { @($names) -join ', ' } else { [string][char]0x2014 }

        if ($PSCmdlet.ParameterSetName -eq 'Summary') {
            $cpu      = Get-GfxGridScalar -Value $surf.Cpu
            $ws       = Get-GfxGridScalar -Value $surf.WorkingSetMB
            $vram     = Get-GfxGridScalar -Value $surf.GpuMemoryMB
            # Presence is a whole-run property: it has no meaning for a single
            # tick, where the surface is present by definition.
            $presence = if ($null -eq $surf.PresenceRatio) { [string][char]0x2014 } else { "$([math]::Round(100 * $surf.PresenceRatio, 0))%" }
        } else {
            $cpu      = Get-GfxGridScalar -Value $surf.CpuPercent
            $ws       = Get-GfxGridScalar -Value $surf.WorkingSetMB
            $vram     = Get-GfxGridScalar -Value $surf.GpuMemoryMB
            $presence = 'live'
        }

        $state = Get-GfxSurfaceState -Surface $surf

        $rows += @{
            Cells = @(
                (Format-GraphicsValue $surf.Role)
                ("{0} {1}" -f $state.Marker, $state.State)
                $adapter
                (Format-GraphicsValue (Get-GfxGridEngine -Engines $surf.Engines -Name '3D') '%')
                (Format-GraphicsValue (Get-GfxGridEngine -Engines $surf.Engines -Name 'VideoDecode') '%')
                (Format-GraphicsValue (Get-GfxGridEngine -Engines $surf.Engines -Name 'VideoProcessing') '%')
                (Format-GraphicsValue $cpu '%')
                (Format-GraphicsValue $ws)
                (Format-GraphicsValue $vram)
                $presence
            )
            # An unresolved surface is FLAGGED, never relabelled: its numbers
            # are real, only its identity is unproven.
            Unresolved = ($surf.RoleSource -eq 'unresolved')
            Role       = $surf.Role
            Level      = $state.Level
        }
    }
    # An empty result must be EMPTY. 'return ,$rows' over an empty array hands
    # the caller a one-element array whose single element is the empty array,
    # and a painter's foreach then draws one blank row -- a surface that does
    # not exist, on the grid the tool is read from. The comma is only needed to
    # stop a SINGLE row unwrapping to a bare hashtable.
    if ($rows.Count -eq 0) { return @() }
    return ,$rows
}

function Get-GraphicsBenchFloors {
    <#
    .SYNOPSIS
        The engine-load floors every classifier in this module uses.
    .DESCRIPTION
        ONE PLACE. The floors separate "this surface is drawing" from "this
        surface is present but quiet", and they were previously a literal in
        each function that needed them plus each of the two harnesses. A floor
        that lives in four places is a floor that will one day differ between
        the live screen and the report -- the same class of split this module
        already paid for in the grid.
    .OUTPUTS
        Hashtable: VisualizerFloorPercent, MediaFloorPercent, AudioUiFloorPercent.
    #>
    [CmdletBinding()]
    param()
    return @{
        VisualizerFloorPercent = $script:GfxVisualizerFloorPercent
        MediaFloorPercent      = $script:GfxMediaFloorPercent
        AudioUiFloorPercent    = $script:GfxAudioUiFloorPercent
    }
}

function Get-GfxSurfaceState {
    <#
    .SYNOPSIS
        What one surface is DOING, as a word plus a level and a text marker.
    .DESCRIPTION
        The grid's numbers say what a surface cost. This says what it was
        doing, which is the categorical question a tech answers at a glance
        and the one a screenshot has to survive: colour is never the only
        signal, so every state carries a marker ([ok] / [~] / [!] / [ ]) and a
        WORD as well as a level.

        The floors are the module's, not this function's -- see
        Get-GraphicsBenchFloors. Butterchurn's 3D is judged against the
        visualizer floor and video.js's decode against the media floor,
        exactly as Get-GraphicsActivityState judges the whole sample, so a
        surface can never read 'Drawing' on the grid while the run's activity
        state reads Quiet.

        UNMEASURED IS NOT IDLE. A surface whose GPU process could not be bound
        to a counter set has no engine table at all; it returns 'Not measured'
        and a level of Unknown, never 'Idle'. Grey is what a reader takes for
        "fine, nothing happening", and an unread sensor must not look like a
        reading.
    .PARAMETER Surface
        One surface record: a live sample's surface, or an aggregated surface
        from a summary. Both shapes are read through Get-GfxGridEngine.
    .OUTPUTS
        Hashtable: State, Level, Marker.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Surface,
        [double]$VisualizerFloorPercent = $script:GfxVisualizerFloorPercent,
        [double]$MediaFloorPercent = $script:GfxMediaFloorPercent
    )

    if ($null -eq $Surface) { return @{ State = 'Not measured'; Level = 'Unknown'; Marker = '[ ]' } }

    $threeD  = Get-GfxGridEngine -Engines $Surface.Engines -Name '3D'
    $decode  = Get-GfxGridEngine -Engines $Surface.Engines -Name 'VideoDecode'
    $vidproc = Get-GfxGridEngine -Engines $Surface.Engines -Name 'VideoProcessing'

    if ($null -eq $threeD -and $null -eq $decode -and $null -eq $vidproc) {
        return @{ State = 'Not measured'; Level = 'Unknown'; Marker = '[ ]' }
    }

    $decodeTotal = 0.0
    if ($null -ne $decode)  { $decodeTotal += [double]$decode }
    if ($null -ne $vidproc) { $decodeTotal += [double]$vidproc }

    $drawing  = ($null -ne $threeD -and [double]$threeD -ge $VisualizerFloorPercent)
    $decoding = ($decodeTotal -ge $MediaFloorPercent)

    # An unidentified surface keeps its measured state and is flagged on top of
    # it. Its numbers are real; only its identity is unproven, and relabelling
    # the reading would be the tool inventing a fact.
    $unresolved = ($Surface.RoleSource -eq 'unresolved')

    $state = if ($drawing -and $decoding) { 'Drawing+decoding' }
             elseif ($decoding)           { 'Decoding' }
             elseif ($drawing)            { 'Drawing' }
             else                         { 'Quiet' }

    $level = if ($unresolved) { 'Degraded' }
             elseif ($state -eq 'Quiet') { 'Idle' }
             else { 'Healthy' }

    $marker = if ($unresolved) { '[!]' }
              elseif ($state -eq 'Quiet') { '[~]' }
              else { '[ok]' }

    if ($unresolved) { $state = "$state (unidentified)" }

    return @{ State = $state; Level = $level; Marker = $marker }
}

function Get-GraphicsBenchCoverage {
    <#
    .SYNOPSIS
        Whether this run can answer the question it exists to answer.
    .DESCRIPTION
        THE SECOND QUESTION, KEPT SEPARATE FROM THE VERDICT. The verdict says
        what the numbers mean; this says whether the run is entitled to a
        verdict at all. The Flight Recorder keeps the same two lines apart for
        the same reason: capture 8E39860E4AF2 was confident about the headset
        and wrong about whether it was watching one.

        The graphics analogue is sharper. Every number this tool reports is a
        difference against an idle stretch on the same box. With no idle arm
        there is nothing to subtract, so a run without one reports totals and
        answers nothing about what the SESSION cost -- and that fact used to
        surface only at Stop, after the session was over and unrepeatable.

        The two ways to lose the baseline are distinguished because their
        remedies are opposite, exactly as in Get-GraphicsBenchFindings: an
        operator who started watching mid-session did nothing wrong and simply
        started too late.
    .OUTPUTS
        Hashtable: State, Marker, Text, Level.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('NotStarted', 'Watching', 'Stopped')]
        [string]$Phase = 'NotStarted',
        $IdleSec,
        $SessionSec,
        [bool]$SessionDetected = $false,
        [bool]$StartedMidSession = $false,
        $CountersOk,
        # Whether NO.exe exists yet. The idle clock only means something once
        # there is a NO to be idle; before that the line says so.
        [bool]$NoRunning = $true,
        [double]$IdleFloorSec = $script:GfxIdleFloorSec
    )

    $dash = [string][char]0x2014
    $floorText = "$([int]$IdleFloorSec) s"
    $shortClause = ''
    if ($null -ne $IdleSec -and [double]$IdleSec -lt $IdleFloorSec) { $shortClause = " (shorter than the $floorText floor $dash deltas are less certain)" }

    $r = switch ($Phase) {
        'NotStarted' {
            @{ State = 'NotStarted'; Marker = '[ ]'; Level = 'Idle'
               Text = 'Not watching yet. Nothing is being measured.' }
        }
        'Watching' {
            if ($StartedMidSession) {
                @{ State = 'MidSession'; Marker = '[!]'; Level = 'Degraded'
                   Text = "NO was already busy when watching began $dash no idle baseline, so this run will report totals only." }
            } elseif ($SessionDetected) {
                @{ State = 'SessionUnderWay'; Marker = '[ok]'; Level = 'Healthy'
                   Text = "Session under way. Idle baseline held: $(Format-GraphicsDuration $IdleSec)$shortClause." }
            } elseif (-not $NoRunning) {
                @{ State = 'WaitingForNo'; Marker = '[~]'; Level = 'Unknown'
                   Text = "NO.exe is not running yet $dash the idle clock starts when it appears." }
            } elseif ($null -ne $IdleSec -and [double]$IdleSec -ge $IdleFloorSec) {
                # The cue "about a minute" never gave. Named, not coloured:
                # "when the line turns green" is unusable to a tester reading a
                # screenshot, a monochrome remote session, or with a colour
                # vision deficiency.
                @{ State = 'BaselineReady'; Marker = '[ok]'; Level = 'Healthy'
                   Text = "Baseline collected ($(Format-GraphicsDuration $IdleSec)) $dash start your session now, then press Stop when it ends." }
            } else {
                $so = 0
                if ($null -ne $IdleSec) { $so = [int][math]::Floor([double]$IdleSec) }
                @{ State = 'BaselineBuilding'; Marker = '[~]'; Level = 'Unknown'
                   Text = "Baseline: $so s of $floorText. Leave NeurOptimal on its home screen $dash this line says Baseline collected when it is done." }
            }
        }
        'Stopped' {
            if ($SessionDetected) {
                @{ State = 'Complete'; Marker = '[ok]'; Level = 'Healthy'
                   Text = "Both arms measured: idle $(Format-GraphicsDuration $IdleSec)$shortClause, session $(Format-GraphicsDuration $SessionSec)." }
            } elseif ($StartedMidSession) {
                @{ State = 'MidSessionComplete'; Marker = '[!]'; Level = 'Degraded'
                   Text = "Totals only. Watching began mid-session, so there is no idle arm to subtract." }
            } else {
                @{ State = 'NoSplit'; Marker = '[!]'; Level = 'Degraded'
                   Text = "Totals only. No session start was seen, so nothing here is attributable to a session." }
            }
        }
    }

    # Counters are a separate loss and are ADDED to the line rather than
    # replacing it: a run can have a perfect idle/session split and still be
    # unable to say anything about the GPU.
    if ($CountersOk -eq $false) {
        $r.Text = "$($r.Text)  GPU engine counters UNAVAILABLE $dash GPU load is absent, not zero."
        $r.Marker = '[!]'
        if ($r.Level -ne 'Failed') { $r.Level = 'Degraded' }
    }

    return $r
}

function Get-GraphicsBenchVerdict {
    <#
    .SYNOPSIS
        The one-line conclusion, its next action, and the standing caveat.
    .DESCRIPTION
        A RENDERER OF THE FINDINGS, NOT A SECOND OPINION. The top finding IS
        the verdict; this maps its sealed Result onto a level and lifts its
        ActionHint into the context line. Nothing here judges a number.

        It exists because the conclusion used to be written into the scrolling
        log at Stop and then pushed up the box by the package block and the
        send banner. The Flight Recorder puts its boundary sentence full width
        under the diagram and leaves the working underneath, because the
        conclusion is what a clinic tech acts on and what a remote assistant
        triages from a screenshot.

        THE FOOTNOTE IS PERMANENT, for the same reason the recorder's EEG
        footnote is: it limits every conclusion this tool can draw, and a
        caveat shown only when it applies is a caveat that is absent exactly
        when someone is drawing the conclusion it qualifies.
    .OUTPUTS
        Hashtable: Text, Context, Footnote, Level, Marker.
    #>
    [CmdletBinding()]
    param(
        [array]$Findings = @(),
        [ValidateSet('NotStarted', 'Watching', 'Stopped')]
        [string]$Phase = 'NotStarted'
    )

    # THE FOOTNOTE STATES A LIMIT, IT DOES NOT ASSERT A READING. It used to say
    # "butterchurn draws even while NO is idle", which was true of the box it
    # was written on and false on a machine where the visuals only appear when
    # a session starts -- and on that machine it told the reader the delta was
    # the session's own extra cost when it was the visuals appearing as well.
    # What the baseline actually contained is MEASURED per run and printed with
    # the numbers; the permanent caveat is the one thing true of every run.
    $footnote = "A percentage is a session cost only as a difference against this box's own baseline, and only when the baseline was measured at the same window size on the same screen."

    if ($Phase -eq 'NotStarted') {
        return @{ Text = 'No run yet.'; Context = 'Press Start watching before the session begins.'
                  Footnote = $footnote; Level = 'Idle'; Marker = '[ ]' }
    }
    if ($Phase -eq 'Watching') {
        return @{ Text = 'Collecting. No conclusion yet.'; Context = 'Press Stop when the session ends.'
                  Footnote = $footnote; Level = 'Unknown'; Marker = '[ ]' }
    }

    $top = @($Findings) | Select-Object -First 1
    if (-not $top) {
        # Get-GraphicsBenchFindings always yields at least one row, so an empty
        # list means the findings pass did not run. That is unknown, never clean.
        return @{ Text = 'No findings were produced for this run.'
                  Context = 'The run stopped before it was scored; the raw samples in the package are still valid.'
                  Footnote = $footnote; Level = 'Unknown'; Marker = '[ ]' }
    }

    $level = switch ([string]$top.Result) {
        'FAIL' { 'Failed' }
        'WARN' { 'Degraded' }
        'SKIP' { 'Unscoped' }
        'PASS' { 'Clean' }
        default { 'Unknown' }
    }
    $marker = switch ($level) {
        'Failed'   { '[!]' }
        'Degraded' { '[!]' }
        'Unscoped' { '[~]' }
        'Clean'    { '[ok]' }
        default    { '[ ]' }
    }

    $context = [string]$top.ActionHint
    $more = @($Findings).Count - 1
    if ($more -gt 0) {
        $context = "$context  (+$more more finding$(if ($more -gt 1) { 's' } else { '' }) in the report below.)"
    }

    return @{ Text = [string]$top.Title; Context = $context; Footnote = $footnote
              Level = $level; Marker = $marker }
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
    'Get-GfxUiChangeDwellSamples'
    'Get-GfxIdleFloorSec'
    'ConvertFrom-GfxGeometryRow'
    'Get-GfxWindowMode'
    'Select-GfxPrimaryNoWindow'
    'Get-NoSessionEndIndex'
    'Get-NoWindowModeSummary'
    'Initialize-GfxRestartManager'
    'Get-NoHeldMediaFiles'
    'ConvertTo-GfxLuidKey'
    'Get-GfxAdapterLuidMap'
    'Resolve-GfxLuidName'
    'Get-GfxCohortKey'
    'Get-NompConfigSnapshot'
    'Get-NoOpenedMediaFile'
    'Get-GraphicsActivityState'
    'Get-GraphicsActivitySpans'
    'Get-GraphicsPreRunActivity'
    'Format-GraphicsPreRunReport'
    'Get-NoUiChangePoints'
    'Get-GfxRoleAggregate'
    'Get-GraphicsBenchSessionSummary'
    'Get-GraphicsBenchFindings'
    'Get-GraphicsBenchProfiles'
    'Get-GraphicsBenchProfile'
    'Get-GraphicsBenchProfileForArrangement'
    'Get-GfxVisualizerPlacement'
    'Get-GfxVisualizerAttachmentState'
    'Get-GfxBaselineVisualizerState'
    'Get-GfxTransitionMarkerKinds'
    'Get-GfxTransitionSpan'
    'Test-GfxExternalDisconnected'
    'Test-GraphicsBenchReadiness'
    'Get-GfxLiveNoWindow'
    'Get-GfxLiveDisplayCount'
    'Get-GfxNoRunning'
    'Initialize-GfxDisplayScan'
    'ConvertFrom-GfxDisplayScanRows'
    'New-GfxDisplayArrangement'
    'Get-GfxDisplayArrangement'
    'Format-GfxDisplayLabel'
    'Format-GfxDisplaySetupLines'
    'ConvertTo-GfxMonitorKey'
    'Get-GfxDisplayPhysicalSize'
    'Resolve-GfxNoDisplay'
    'Test-GfxDisplaySetupMatch'
    'Get-GraphicsBenchPhase'
    'Get-GraphicsBenchStepView'
    'Get-GfxPlaybackStartIndex'
    'ConvertTo-GfxUtcInstant'
    'Get-GraphicsBenchProtocolVersion'
    'Get-GraphicsBenchProfileOutcome'
    'Format-GraphicsClock'
    'Get-GraphicsBenchProfileDeviations'
    'Test-GraphicsBenchPreconditions'
    'New-GraphicsBenchRunFolder'
    'Write-GraphicsBenchEvent'
    'Save-GraphicsBenchRun'
    'Get-GfxGridScalar'
    'Get-GfxGridEngine'
    'Get-GfxSurfaceState'
    'Get-GraphicsBenchFloors'
    'Get-GraphicsBenchCoverage'
    'Get-GraphicsBenchVerdict'
    'Get-GraphicsBenchGridRows'
    'Format-GraphicsValue'
    'Format-GraphicsDuration'
    'Format-GraphicsInventoryReport'
    'Format-GraphicsBenchReport'
)

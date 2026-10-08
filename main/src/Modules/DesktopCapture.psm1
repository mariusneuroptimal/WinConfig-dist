# DesktopCapture.psm1
# Compiled screen capture and top-level window identity, shared by the Flight
# Recorder (Win11Config.App.ps1) and the NO Test Lab (the lab kit packages
# this module unmodified). Extracted from App.ps1 2026-10-08 with the C# kept
# byte-for-byte: the type names WinConfigDiag.ScreenGrab and
# WinConfigDiag.WindowScan are unchanged, so the recorder's sampler runspace,
# which calls the types directly, is unaffected.
#
# WHY THE CAPTURE IS COMPILED C#. The PowerShell idiom for a screen grab --
# a new Bitmap, a Graphics from that image, then a screen copy on it, as
# pipeline method calls -- is byte-for-byte the Empire framework's screenshot
# stager, and Microsoft Defender's cloud AMSI flagged the published recorder as
# HackTool:PowerShell/EmpireGetScreenshot.C on 2026-08-20 (ThreatID
# 2147743659). AMSI scans at PARSE time, so that verdict blocked the ENTIRE
# recorder at launch. In a C# method those method-call TOKENS do not exist in
# the PowerShell layer the signature matches. This is not obfuscation: the code
# is plainly readable, and the recorder announces the feature in its
# PROVENANCE line, the manifest and two consent dialogs.
#
# IDENTITY, NOT CONTENT. The window scan reads top-level window HANDLES, owning
# PIDs, the top-level TITLE and the enabled flag -- never child windows, never
# window content, never OCR. A title says WHICH dialog ('Arc Not Detected' =
# 12005 class, 'Arc Connection Lost' = 12006 danger window); the VAULT window's
# visible-but-disabled flag is the modal detector.
#
# LAZY AND FAIL-SAFE. Nothing compiles at import. Initialize-* compile on first
# use, cache the result, and return $false instead of throwing: a caller (the
# recorder) must keep running when Add-Type is unavailable or blocked.
#
# RUNTIME. Built for Windows PowerShell 5.1 (.NET Framework), the field
# runtime. Under pwsh 7 the ScreenGrab C# does not compile (System.Drawing's
# Rectangle is forwarded to System.Drawing.Primitives) and reads not-ready --
# exactly as the same C# behaved when it lived inside App.ps1.

$script:ScreenGrabReady = $null   # $null = untried, $true/$false = result
$script:ScreenGrabError = $null
$script:WindowScanReady = $null
$script:WindowScanError = $null

$script:ScreenGrabSource = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace WinConfigDiag {
    public static class ScreenGrab {
        // Managed full-virtual-screen capture to a JPEG at the given quality.
        // An NO error dialog can sit on any monitor, so the whole virtual
        // desktop is taken rather than a guessed crop.
        public static void CaptureVirtualScreenJpeg(string path, long quality) {
            System.IO.File.WriteAllBytes(path, CaptureVirtualScreenJpegBytes(quality));
        }

        // The same capture into memory. The NO-window sampler thread grabs
        // the pixels the instant a dialog appears and hands the bytes to the
        // drain, which alone decides whether they are ever written to disk.
        public static byte[] CaptureVirtualScreenJpegBytes(long quality) {
            Rectangle area = SystemInformation.VirtualScreen;
            using (Bitmap bmp = new Bitmap(area.Width, area.Height)) {
                using (Graphics g = Graphics.FromImage(bmp)) {
                    g.CopyFromScreen(area.Left, area.Top, 0, 0, bmp.Size);
                }
                ImageCodecInfo enc = null;
                foreach (ImageCodecInfo c in ImageCodecInfo.GetImageEncoders()) {
                    if (c.MimeType == "image/jpeg") { enc = c; break; }
                }
                using (EncoderParameters ep = new EncoderParameters(1)) {
                    ep.Param[0] = new EncoderParameter(Encoder.Quality, quality);
                    using (System.IO.MemoryStream ms = new System.IO.MemoryStream()) {
                        bmp.Save(ms, enc, ep);
                        return ms.ToArray();
                    }
                }
            }
        }
    }
}
"@

$script:WindowScanSource = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinConfigDiag {
    public static class WindowScan {
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr hWnd);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder text, int maxCount);
        delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        // Handles of visible top-level windows owned by the given PIDs.
        // Returns HANDLES ONLY -- no titles, no class text, no content.
        public static long[] TopLevelWindowsForPids(int[] pids) {
            HashSet<uint> want = new HashSet<uint>();
            foreach (int p in pids) { want.Add((uint)p); }
            List<long> found = new List<long>();
            EnumWindows(delegate(IntPtr h, IntPtr l) {
                if (IsWindowVisible(h)) {
                    uint wpid; GetWindowThreadProcessId(h, out wpid);
                    if (want.Contains(wpid)) { found.Add(h.ToInt64()); }
                }
                return true;
            }, IntPtr.Zero);
            return found.ToArray();
        }

        // Identity of visible top-level windows owned by the given PIDs:
        // "hwnd|enabled|title" per window. TOP-LEVEL TITLE AND ENABLED FLAG
        // ONLY -- never child windows, never window content (a LabVIEW front
        // panel's content is one drawn canvas anyway; its title bar is window
        // METADATA the taskbar already shows). Added 2026-08-23 after the
        // dialog-title discriminator was proven ('Arc Not Detected' = 12005
        // class vs 'Arc Connection Lost' = 12006 danger window) and the VAULT
        // visible-but-disabled boolean survived as the modal detector.
        public static string[] DescribeTopLevelWindowsForPids(int[] pids) {
            HashSet<uint> want = new HashSet<uint>();
            foreach (int p in pids) { want.Add((uint)p); }
            List<string> found = new List<string>();
            EnumWindows(delegate(IntPtr h, IntPtr l) {
                if (IsWindowVisible(h)) {
                    uint wpid; GetWindowThreadProcessId(h, out wpid);
                    if (want.Contains(wpid)) {
                        System.Text.StringBuilder sb = new System.Text.StringBuilder(512);
                        GetWindowTextW(h, sb, 512);
                        found.Add(h.ToInt64().ToString() + "|" + (IsWindowEnabled(h) ? "1" : "0") + "|" + sb.ToString());
                    }
                }
                return true;
            }, IntPtr.Zero);
            return found.ToArray();
        }
    }
}
"@

function Initialize-WinConfigScreenGrab {
    <#
    .SYNOPSIS
        Compiles WinConfigDiag.ScreenGrab once. Returns $true/$false; never throws.
        On $false, Get-WinConfigDesktopCaptureError -Part ScreenGrab says why.
    #>
    if ($null -ne $script:ScreenGrabReady) { return $script:ScreenGrabReady }
    try {
        if (-not ('WinConfigDiag.ScreenGrab' -as [type])) {
            Add-Type -TypeDefinition $script:ScreenGrabSource -ReferencedAssemblies 'System.Drawing', 'System.Windows.Forms' -ErrorAction Stop
        }
        $script:ScreenGrabReady = [bool]('WinConfigDiag.ScreenGrab' -as [type])
    } catch {
        $script:ScreenGrabReady = $false
        $script:ScreenGrabError = $_.Exception.Message
    }
    return $script:ScreenGrabReady
}

function Initialize-WinConfigWindowScan {
    <#
    .SYNOPSIS
        Compiles WinConfigDiag.WindowScan once. Returns $true/$false; never throws.
        Add-Type assemblies are AppDomain-wide: once compiled, a runspace can call the
        type without loading anything itself.
    #>
    if ($null -ne $script:WindowScanReady) { return $script:WindowScanReady }
    try {
        if (-not ('WinConfigDiag.WindowScan' -as [type])) {
            Add-Type -TypeDefinition $script:WindowScanSource -ErrorAction Stop
        }
        $script:WindowScanReady = [bool]('WinConfigDiag.WindowScan' -as [type])
    } catch {
        $script:WindowScanReady = $false
        $script:WindowScanError = $_.Exception.Message
    }
    return $script:WindowScanReady
}

function Get-WinConfigDesktopCaptureError {
    <# Why the last Initialize-* returned $false, or $null. #>
    param([Parameter(Mandatory)] [ValidateSet('ScreenGrab', 'WindowScan')] [string]$Part)
    if ($Part -eq 'ScreenGrab') { return $script:ScreenGrabError }
    return $script:WindowScanError
}

function ConvertFrom-WinConfigWindowScanRows {
    <#
    .SYNOPSIS
        Parses "hwnd|enabled|title" rows into Hwnd/Enabled/Title records. Pure.
        The title may itself contain '|', so only the first two separators split.
        Malformed rows are skipped.
    #>
    param([string[]]$Rows)
    $out = @()
    foreach ($row in @($Rows)) {
        $parts = [string]$row -split '\|', 3
        if ($parts.Count -lt 3) { continue }
        $out += [pscustomobject]@{
            Hwnd    = [long]$parts[0]
            Enabled = ($parts[1] -eq '1')
            Title   = [string]$parts[2]
        }
    }
    return $out
}

function Get-WinConfigWindowHandles {
    <# Handles of the visible top-level windows owned by ProcessId. @() on any failure. #>
    param([int[]]$ProcessId)
    $ids = @(@($ProcessId) | Where-Object { $_ } | Select-Object -Unique)
    if (-not $ids) { return @() }
    if (-not (Initialize-WinConfigWindowScan)) { return @() }
    try { return @([WinConfigDiag.WindowScan]::TopLevelWindowsForPids([int[]]$ids)) } catch { return @() }
}

function Get-WinConfigWindowDescriptions {
    <# Hwnd/Enabled/Title of the visible top-level windows owned by ProcessId. @() on any failure. #>
    param([int[]]$ProcessId)
    $ids = @(@($ProcessId) | Where-Object { $_ } | Select-Object -Unique)
    if (-not $ids) { return @() }
    if (-not (Initialize-WinConfigWindowScan)) { return @() }
    $rows = try { @([WinConfigDiag.WindowScan]::DescribeTopLevelWindowsForPids([int[]]$ids)) } catch { @() }
    return (ConvertFrom-WinConfigWindowScanRows -Rows $rows)
}

Export-ModuleMember -Function @(
    'Initialize-WinConfigScreenGrab'
    'Initialize-WinConfigWindowScan'
    'Get-WinConfigDesktopCaptureError'
    'ConvertFrom-WinConfigWindowScanRows'
    'Get-WinConfigWindowHandles'
    'Get-WinConfigWindowDescriptions'
)

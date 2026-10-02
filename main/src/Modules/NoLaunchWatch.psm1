# NoLaunchWatch.psm1
# NO-LAUNCH-001: watch NeurOptimal launches -- how long NO.exe takes to become
# ready, and, when it never does ("stuck on Refreshing Licensing Information",
# FI-022 / LIC-68), capture what it was doing.
#
# ONE MEASUREMENT, TWO USES. Every launch gets a time from process start to
# "ready". A healthy launch is launch-time data AND the same-box control the
# licensing hunt has been missing; a stuck launch is one that never gets there.
#
# WHAT IS READ. NO's own process (CPU, threads, its top-level window TITLES and
# visibility -- window metadata, never screen content: no OCR of NO, hard rule),
# and an ETW trace started BEFORE NO exists, filtered to NO's process id.
#   Light (default): process/image loads, TCP/UDP, DNS -- cheap enough that
#                    launch times stay comparable.
#   Full (opt-in):   adds file opens and registry access, system-wide. Launch
#                    times recorded under Full are flagged and not comparable.
#
# WHAT IS NEVER DONE. NO is never launched, killed or written to by this module.
# The operator launches NO; WinConfig runs elevated and a NO it started would
# inherit that (NO must not run as admin).
#
# THE READY RULE IS PROVISIONAL. NO is LabVIEW (UI unautomatable); the only
# ready signal is its window set. Until a labelled healthy and stuck launch
# confirm which window means "ready", the rule below is a best guess and every
# summary says which rule version scored it. The full window timeline ships in
# every package, so launches can be re-scored when the rule is confirmed.

$script:NoLaunchSchema          = 'no-launch/1'
$script:NoLaunchReadyRuleVersion = 'provisional-2'
$script:NoLaunchStuckAfterSec   = 180
$script:NoLaunchSessionPrefix   = 'WinConfigNoLaunch'

#region Native helpers (window enumeration, minidump)

if (-not ('WinConfigNoLaunchNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class WinConfigNoLaunchNative {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeFileHandle hFile, uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);
    // Top-level windows of one process: "hwnd|1/0|class|title". GetWindowText on
    // another process's window reads the cached title; it does not send
    // WM_GETTEXT, so a hung NO cannot hang the caller.
    public static List<string> ListWindows(uint target) {
        var rows = new List<string>();
        EnumWindows((h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid == target) {
                var t = new StringBuilder(512); GetWindowText(h, t, 512);
                var c = new StringBuilder(256); GetClassName(h, c, 256);
                rows.Add(string.Format("{0}|{1}|{2}|{3}", h.ToInt64(), IsWindowVisible(h) ? 1 : 0, c, t));
            }
            return true;
        }, IntPtr.Zero);
        return rows;
    }
}
'@
}

#endregion

#region ETW session

function Get-NoLaunchEtwProviders {
    <#
    .SYNOPSIS
        Provider lines (logman -pf format: {GUID} keywords level) for a trace level.
    #>
    [CmdletBinding()]
    param([ValidateSet('Light', 'Full')] [string]$Level = 'Light')
    $lines = @(
        '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 0x50 0x5'                # Kernel-Process: process + image loads
        '{7DD42A49-5329-4832-8DFD-43D979153A88} 0x30 0x5'                # Kernel-Network: TCP/UDP, IPv4 + IPv6
        '{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} 0xFFFFFFFFFFFFFFFF 0x5'  # DNS-Client
    )
    if ($Level -eq 'Full') {
        $lines += '{EDD08927-9CC4-4E65-B970-C2560FB5C289} 0x1CD0 0x5'    # Kernel-File: create (+name, op end, delete/rename)
        $lines += '{70EB4F03-C1DE-4F73-A051-33D13D5413BD} 0xFF30 0x5'    # Kernel-Registry: open/create/query/set/enum, no CloseKey
    }
    return $lines
}

function Start-NoLaunchEtwSession {
    <#
    .SYNOPSIS
        Starts a circular ETW session (requires elevation). Returns @{ Ok; SessionName; EtlPath; Error }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SessionName,
        [Parameter(Mandatory)] [string]$EtlPath,
        [ValidateSet('Light', 'Full')] [string]$Level = 'Light',
        [int]$MaxMB = 1024
    )
    $pf = "$EtlPath.providers.txt"
    Set-Content -LiteralPath $pf -Encoding Ascii -Value (Get-NoLaunchEtwProviders -Level $Level)
    & logman stop $SessionName -ets 2>&1 | Out-Null
    $out = & logman start $SessionName -ets -o $EtlPath -pf $pf -bs 1024 -nb 64 256 -f bincirc -max $MaxMB 2>&1
    $ok = ($LASTEXITCODE -eq 0)
    return @{ Ok = $ok; SessionName = $SessionName; EtlPath = $EtlPath; Level = $Level; Error = $(if ($ok) { $null } else { ($out | Out-String).Trim() }) }
}

function Stop-NoLaunchEtwSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$SessionName)
    $out = & logman stop $SessionName -ets 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Stop-NoLaunchStaleEtwSessions {
    <#
    .SYNOPSIS
        Stops sessions this tool left running (WinConfig closed or crashed mid-watch).
        A kernel trace left behind keeps writing until reboot.
    #>
    [CmdletBinding()]
    param()
    $stopped = @()
    $list = & logman query -ets 2>$null
    foreach ($line in @($list)) {
        if ($line -match "^\s*($([regex]::Escape($script:NoLaunchSessionPrefix))\S*)") {
            & logman stop $Matches[1] -ets 2>&1 | Out-Null
            $stopped += $Matches[1]
        }
    }
    return $stopped
}

function Get-NoLaunchRules {
    <# The thresholds the window and the summaries share. #>
    return [pscustomobject]@{ ReadyRuleVersion = $script:NoLaunchReadyRuleVersion; StuckAfterSeconds = $script:NoLaunchStuckAfterSec; PostReadySeconds = 5 }
}

function Get-NoLaunchSessionName {
    param([int]$Sequence)
    return ('{0}-{1}-{2}' -f $script:NoLaunchSessionPrefix, $PID, $Sequence)
}

#endregion

#region Sampling NO

function ConvertFrom-NoLaunchWindowList {
    <#
    .SYNOPSIS
        Parses "hwnd|visible|class|title" rows from the native enumerator. Pure.
    #>
    param([string[]]$Rows)
    $out = foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        # [char[]] + count: on .NET Framework there is no Split(char, int), and
        # PowerShell would bind Split(params char[]) -- making the 4 a separator.
        $p = $r.Split([char[]]@('|'), 4)
        if ($p.Count -lt 4) { continue }
        [pscustomobject]@{ Hwnd = [int64]$p[0]; Visible = ($p[1] -eq '1'); Class = $p[2]; Title = $p[3] }
    }
    return @($out)
}

function Get-NoLaunchWindows {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int]$ProcessId)
    $rows = [WinConfigNoLaunchNative]::ListWindows([uint32]$ProcessId)
    return (ConvertFrom-NoLaunchWindowList -Rows @($rows))
}

function Get-NoLaunchWindowSignature {
    <# Order-independent text of the window set; changes only when NO's windows change. Pure. #>
    param([object[]]$Windows)
    return ((@($Windows) | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Hwnd, $(if ($_.Visible) { 1 } else { 0 }), $_.Class, $_.Title } | Sort-Object) -join ' || ')
}

function Test-NoLaunchReady {
    <#
    .SYNOPSIS
        Scores one window set against the ready rule. Pure.
    .DESCRIPTION
        provisional-2: ready = a VISIBLE top-level window whose title contains
        "NeurOptimal" (the main panel: "NeurOptimal® ... - <name>") AND no visible
        startup dialog ("Refreshing Licensing Information", NO's progress bar).
        Why the second half: the first healthy launch on record (MMEVOLD_06,
        4.0.0.10, 2026-10-02) showed the main panel at 25 s with "Refreshing
        Licensing Information" still up on top of it until ~27 s. provisional-1
        (main panel alone) scored that as ready -- and would score a launch stuck
        on that dialog the same way. Still provisional until a stuck launch is seen.
    #>
    param([object[]]$Windows)
    $visible = @(@($Windows) | Where-Object { $_.Visible })
    $hit = $visible | Where-Object { $_.Title -match 'NeurOptimal' } | Select-Object -First 1
    $blocker = $visible | Where-Object { $_.Title -match 'Refreshing Licensing|Progress Bar' } | Select-Object -First 1
    return [pscustomobject]@{
        Ready       = [bool]($hit -and -not $blocker)
        Title       = $(if ($hit) { $hit.Title } else { $null })
        BlockedBy   = $(if ($hit -and $blocker) { $blocker.Title } else { $null })
        RuleVersion = $script:NoLaunchReadyRuleVersion
    }
}

function Get-NoLaunchProcessSample {
    <#
    .SYNOPSIS
        One per-second sample of NO. Runs on the UI thread, so it reads only cheap counters:
        never Process.Responding (SendMessageTimeout, up to 5 s against a hung NO) and never
        Get-NetTCPConnection (slow CIM; the trace records NO's network traffic instead).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Diagnostics.Process]$Process, [Parameter(Mandatory)] [datetime]$LaunchStart)
    $Process.Refresh()
    if ($Process.HasExited) { return $null }
    return [pscustomobject]@{
        T            = [math]::Round(((Get-Date) - $LaunchStart).TotalSeconds, 1)
        CpuSec       = [math]::Round($Process.TotalProcessorTime.TotalSeconds, 2)
        WorkingSetMB = [int]($Process.WorkingSet64 / 1MB)
        Threads      = $Process.Threads.Count
        Handles      = $Process.HandleCount
    }
}

function Get-NoLaunchThreadSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int]$ProcessId)
    $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $p) { return @() }
    $rows = foreach ($t in $p.Threads) {
        [pscustomobject]@{
            Id           = $t.Id
            ThreadState  = "$($t.ThreadState)"
            WaitReason   = $(if ($t.ThreadState -eq 'Wait') { "$($t.WaitReason)" } else { '' })
            CpuMs        = [int]$t.TotalProcessorTime.TotalMilliseconds
            StartAddress = ('0x{0:X}' -f [int64]$t.StartAddress)
        }
    }
    return @($rows)
}

function Get-NoLaunchBusyThreads {
    <# Threads ranked by CPU used between two snapshots. Pure. #>
    param([object[]]$Before, [object[]]$After, [int]$Top = 5)
    $start = @{}
    foreach ($t in @($Before)) { $start[[int]$t.Id] = [int]$t.CpuMs }
    $rows = foreach ($t in @($After)) {
        if (-not $start.ContainsKey([int]$t.Id)) { continue }
        [pscustomobject]@{ Id = [int]$t.Id; DeltaMs = [int]$t.CpuMs - $start[[int]$t.Id]; State = "$($t.ThreadState)/$($t.WaitReason)"; StartAddress = $t.StartAddress }
    }
    return @($rows | Sort-Object DeltaMs -Descending | Select-Object -First $Top)
}

function Save-NoLaunchDump {
    <#
    .SYNOPSIS
        Synchronous full-memory dump of a process. Returns @{ Ok; Path; Bytes; Error }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int]$ProcessId, [Parameter(Mandatory)] [string]$Path)
    $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $p) { return @{ Ok = $false; Path = $Path; Bytes = 0; Error = 'process has exited' } }
    $fs = $null
    try {
        $fs = [System.IO.File]::Create($Path)
        # FullMemory | HandleData | UnloadedModules | FullMemoryInfo | ThreadInfo
        $ok = [WinConfigNoLaunchNative]::MiniDumpWriteDump($p.Handle, [uint32]$p.Id, $fs.SafeFileHandle, [uint32]0x1826, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } catch {
        return @{ Ok = $false; Path = $Path; Bytes = 0; Error = $_.Exception.Message }
    } finally {
        if ($fs) { $fs.Close() }
    }
    $size = (Get-Item -LiteralPath $Path).Length
    if ($ok -and $size -gt 0) { return @{ Ok = $true; Path = $Path; Bytes = $size; Error = $null } }
    return @{ Ok = $false; Path = $Path; Bytes = $size; Error = ('MiniDumpWriteDump failed, error 0x{0:X8} (antivirus may block dumping)' -f $err) }
}

function Get-NoLaunchContext {
    <#
    .SYNOPSIS
        What else was true at launch -- the confounders of a launch time.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Diagnostics.Process]$Process, [int]$PriorLaunchesThisWatch = -1)
    $ctx = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ctx.BootTime = $os.LastBootUpTime.ToString('o')
        $ctx.UptimeMinutesAtLaunch = [math]::Round(($Process.StartTime - $os.LastBootUpTime).TotalMinutes, 1)
        $ctx.OsBuild = "$($os.BuildNumber)"
    } catch { $ctx.BootTime = $null }
    $ctx.PriorLaunchesThisWatch = $PriorLaunchesThisWatch
    # Path reads MainModule, which throws once the process has exited.
    try { $ctx.NoExePath = $Process.Path } catch { $ctx.NoExePath = $null }
    try { $ctx.NoExeVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ctx.NoExePath).FileVersion } catch { $ctx.NoExeVersion = $null }
    try {
        $mysql = Get-CimInstance Win32_Service -Filter "Name LIKE 'MySQL%'" -ErrorAction Stop | Select-Object -First 1
        if ($mysql) {
            $ctx.MySqlService = $mysql.Name
            $ctx.MySqlState = $mysql.State
            if ($mysql.ProcessId) {
                $mp = Get-Process -Id $mysql.ProcessId -ErrorAction SilentlyContinue
                if ($mp) { $ctx.MySqlStartedSecondsBeforeNo = [math]::Round(($Process.StartTime - $mp.StartTime).TotalSeconds, 1) }
            }
        }
    } catch { }
    try { $ctx.AntivirusProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { $ctx.AntivirusProducts = @() }
    return $ctx
}

#endregion

#region Decoding the trace

function Get-NoLaunchEtwRows {
    <#
    .SYNOPSIS
        Events from the trace that belong to one process, with T = seconds since launch.
    .DESCRIPTION
        Header PID for in-process events; payload PID/ProcessID for kernel network and
        image events logged from System.

        SPEED. Rendering every matched event to XML and parsing it back cost ~3 ms an
        event -- minutes for a Full trace (~41k NO events). Field NAMES and how the XML
        renders each value depend only on the event's provider/id/version/opcode, so they
        are learned from the first event of each kind (one ToXml) and reused (~0.6 ms an
        event). A field whose rendering cannot be reproduced from the raw value makes that
        kind fall back to ToXml, so rows are identical to the XML reader's (checked on 22k
        events of a real Full trace, 2026-10-02: 0 differences).
        Unchanged: the filter visits every event in the file, ~150 s per GB of Full trace
        whatever the XPath -- read time follows trace SIZE.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$EtlPath, [Parameter(Mandatory)] [int]$ProcessId, [Parameter(Mandatory)] [datetime]$LaunchStart, [int]$MaxEvents = 0)
    $xp = "*[System/Execution[@ProcessID='{0}'] or EventData/Data[@Name='PID']='{0}' or EventData/Data[@Name='ProcessID']='{0}']" -f $ProcessId
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($EtlPath, [System.Diagnostics.Eventing.Reader.PathType]::FilePath, $xp)
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $kinds = @{}
    $rows = New-Object System.Collections.ArrayList
    # Candidate renderings of a raw value, in the order XML tends to use them.
    $render = @(
        { param($v) [string]$v }
        { param($v) ('0x{0:X}' -f $v) }
        { param($v) ('0x{0:x}' -f $v) }
        { param($v) ([string]$v).ToLowerInvariant() }
        { param($v) ('{' + ([string]$v).ToUpperInvariant() + '}') }
        { param($v) ('{' + [string]$v + '}') }
    )
    try {
        while ($true) {
            if ($MaxEvents -gt 0 -and $rows.Count -ge $MaxEvents) { break }
            $e = $reader.ReadEvent()
            if (-not $e) { break }
            try {
                $key = '{0}|{1}|{2}|{3}' -f $e.ProviderName, $e.Id, $e.Version, $e.Opcode
                $kind = $kinds[$key]
                $props = $e.Properties
                if (-not $kind) {
                    $x = [xml]$e.ToXml()
                    $data = @($x.Event.EventData.Data | Where-Object { $_ })
                    $fmt = New-Object 'int[]' $data.Count
                    $usable = ($data.Count -eq $props.Count)
                    for ($i = 0; $usable -and $i -lt $data.Count; $i++) {
                        $text = [string]$data[$i].'#text'
                        $v = $props[$i].Value
                        $fmt[$i] = -1
                        if (-not $text) { $fmt[$i] = 0; continue }
                        for ($k = 0; $k -lt $render.Count; $k++) {
                            $r = $null; try { $r = & $render[$k] $v } catch { }
                            if ($r -ceq $text) { $fmt[$i] = $k; break }
                        }
                        if ($fmt[$i] -lt 0) { $usable = $false }
                    }
                    $kind = @{ Names = @($data | ForEach-Object { $_.Name }); Fmt = $fmt; Usable = $usable; Op = $e.OpcodeDisplayName; Provider = ($e.ProviderName -replace '^Microsoft-Windows-', '') }
                    $kinds[$key] = $kind
                }
                $fields = [ordered]@{}
                if ($kind.Usable) {
                    for ($i = 0; $i -lt $kind.Names.Count; $i++) {
                        $v = $props[$i].Value
                        if ($null -eq $v) { continue }
                        $t = & $render[$kind.Fmt[$i]] $v
                        if ($t) { $fields[$kind.Names[$i]] = $t }
                    }
                } else {
                    $x = [xml]$e.ToXml()
                    foreach ($d in @($x.Event.EventData.Data)) { if ($d -and $d.'#text') { $fields[$d.Name] = $d.'#text' } }
                }
                [void]$rows.Add([pscustomobject]@{
                    T        = [math]::Round(($e.TimeCreated - $LaunchStart).TotalSeconds, 3)
                    Provider = $kind.Provider
                    Id       = $e.Id
                    Op       = $kind.Op
                    Fields   = $fields
                })
            } finally { $e.Dispose() }
        }
    } finally { $reader.Dispose() }
    return $rows.ToArray()
}

function ConvertFrom-NoLaunchNetAddress {
    <# Kernel-Network IPv4 daddr is a network-order uint32; IPv6 arrives as text. Pure. #>
    param([string]$Value)
    if ($Value -match '^\d+$') { return ([System.Net.IPAddress][int64]$Value).ToString() }
    return $Value
}

function ConvertFrom-NoLaunchNetPort {
    <# Kernel-Network ports are byte-swapped (47873 -> 443). Pure. #>
    param([string]$Value)
    if ($Value -match '^\d+$') { $p = [int]$Value; return (($p -band 0xFF) -shl 8) -bor ($p -shr 8) }
    return $Value
}

function Get-NoLaunchEtwRowName {
    <# The one human-readable thing an event touched. Pure. #>
    param([object]$Row)
    $f = $Row.Fields
    switch ($Row.Provider) {
        'Kernel-Network' { if ($f['daddr']) { return ('{0} {1}:{2}' -f $Row.Op, (ConvertFrom-NoLaunchNetAddress $f['daddr']), (ConvertFrom-NoLaunchNetPort $f['dport'])) } }
        'DNS-Client'     { if ($f['QueryName']) { return "DNS $($f['QueryName'])" } }
        'Kernel-Process' { if ($f['ImageName']) { return "load $($f['ImageName'])" } }
        default          { foreach ($k in 'FileName', 'RelativeName', 'KeyName', 'ValueName') { if ($f[$k]) { return $f[$k] } } }
    }
    return $null
}

function Get-NoLaunchEtwDigest {
    <#
    .SYNOPSIS
        Summary of NO's trace events: DNS, peers, when it went quiet, what it touched last. Pure.
    #>
    param([object[]]$Rows, [double]$EndT = -1)
    $rows = @($Rows)
    $byProvider = [ordered]@{}
    foreach ($g in ($rows | Group-Object Provider)) { $byProvider[$g.Name] = $g.Count }
    # Each name once, at the time it was FIRST looked up.
    $dns = @($rows | Where-Object { $_.Provider -eq 'DNS-Client' -and $_.Fields['QueryName'] } | Group-Object { $_.Fields['QueryName'] } | ForEach-Object { [pscustomobject]@{ T = [math]::Round(($_.Group | Measure-Object T -Minimum).Minimum, 1); Name = $_.Name } } | Sort-Object T)
    $peers = @($rows | Where-Object { $_.Provider -eq 'Kernel-Network' -and $_.Fields['daddr'] } | ForEach-Object { '{0}:{1}' -f (ConvertFrom-NoLaunchNetAddress $_.Fields['daddr']), (ConvertFrom-NoLaunchNetPort $_.Fields['dport']) } | Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Peer = $_.Name; Events = $_.Count } })
    $activity = @($rows | Where-Object { $_.Provider -ne 'Kernel-Process' })
    $named = @($activity | ForEach-Object { $n = Get-NoLaunchEtwRowName $_; if ($n) { [pscustomobject]@{ T = $_.T; Provider = $_.Provider; Name = $n } } })
    $lastT = $(if ($activity.Count) { ($activity | Measure-Object T -Maximum).Maximum } else { $null })
    $perTen = [ordered]@{}
    foreach ($g in ($rows | Group-Object { [int]([math]::Floor($_.T / 10) * 10) } | Sort-Object { [int]$_.Name })) { $perTen["$($g.Name)"] = $g.Count }
    return [ordered]@{
        EventCount         = $rows.Count
        ByProvider         = $byProvider
        DnsLookups         = $dns
        RemotePeers        = $peers
        ImageLoads         = @($rows | Where-Object { $_.Provider -eq 'Kernel-Process' -and $_.Fields['ImageName'] }).Count
        LastActivityT      = $lastT
        QuietForSecAtEnd   = $(if ($EndT -ge 0 -and $null -ne $lastT) { [math]::Round($EndT - $lastT, 1) } else { $null })
        LastTouched        = @($named | Select-Object -Last 15)
        EventsPerTenSec    = $perTen
    }
}

#endregion

#region Scoring and packaging

function Get-NoLaunchSummary {
    <#
    .SYNOPSIS
        The record of one launch. Pure: everything it reads is in -Launch.
    .PARAMETER Launch
        Hashtable: LaunchId, Computer, ProcessId, LaunchStart (datetime), TraceLevel,
        Outcome (Ready | Stuck | Exited | WatchStopped), ReadyT, ReadyTitle,
        Samples, WindowTimeline, Context, EtwDigest, StuckCapture, MarkedStuckByOperator.
    #>
    param([Parameter(Mandatory)] [hashtable]$Launch)
    $samples = @($Launch.Samples)
    $timeline = @($Launch.WindowTimeline)
    $firstWin = @($timeline | Where-Object { $_.Title -ne '(no windows)' } | Select-Object -First 1)
    $firstVis = @($timeline | Where-Object { $_.Visible -eq $true } | Select-Object -First 1)
    $atReady = $null
    if ($null -ne $Launch.ReadyT) { $atReady = @($samples | Where-Object { $_.T -le $Launch.ReadyT } | Select-Object -Last 1) }
    $comparable = ($Launch.TraceLevel -ne 'Full')
    return [ordered]@{
        Schema                  = $script:NoLaunchSchema
        LaunchId                = $Launch.LaunchId
        Computer                = $Launch.Computer
        ProcessId               = $Launch.ProcessId
        LaunchStartLocal        = $Launch.LaunchStart.ToString('o')
        Outcome                 = $Launch.Outcome
        ReadyRuleVersion        = $script:NoLaunchReadyRuleVersion
        LaunchSeconds           = $(if ($null -ne $Launch.ReadyT) { [math]::Round([double]$Launch.ReadyT, 1) } else { $null })
        ReadyWindowTitle        = $Launch.ReadyTitle
        StuckAfterSeconds       = $script:NoLaunchStuckAfterSec
        MarkedStuckByOperator   = [bool]$Launch.MarkedStuckByOperator
        FirstWindowSeconds      = $(if ($firstWin) { $firstWin[0].T } else { $null })
        FirstVisibleWindowSeconds = $(if ($firstVis) { $firstVis[0].T } else { $null })
        CpuSecondsToReady       = $(if ($atReady) { $atReady[0].CpuSec } else { $null })
        PeakWorkingSetMB        = $(if ($samples.Count) { ($samples | Measure-Object WorkingSetMB -Maximum).Maximum } else { $null })
        SampleCount             = $samples.Count
        TraceLevel              = $Launch.TraceLevel
        LaunchTimeComparable    = $comparable
        WindowTitlesSeen        = @($timeline | ForEach-Object { $_.Title } | Where-Object { $_ -and $_ -ne '(no windows)' } | Select-Object -Unique)
        Context                 = $Launch.Context
        Trace                   = $Launch.EtwDigest
        StuckCapture            = $Launch.StuckCapture
    }
}

function New-NoLaunchLaunchId {
    param([datetime]$LaunchStart, [string]$Computer = $env:COMPUTERNAME)
    $safe = ($Computer -replace '[^A-Za-z0-9_\-]', '_')
    return ('{0}_{1}' -f $safe, $LaunchStart.ToString('yyyyMMdd-HHmmss'))
}

function Get-NoLaunchRemotePrefix {
    <# R2 key prefix: no-launch/<computer>/<launchId>-<outcome>. Pure. #>
    param([Parameter(Mandatory)] [string]$Computer, [Parameter(Mandatory)] [string]$LaunchId, [Parameter(Mandatory)] [string]$Outcome)
    $c = ($Computer -replace '[^A-Za-z0-9_\-]', '_')
    $o = ($Outcome -replace '[^A-Za-z0-9_\-]', '_')
    return "no-launch/$c/$LaunchId-$o"
}

function Compress-NoLaunchFile {
    <# Streams a file to <path>.gz (dumps compress well; never held in memory). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Path)
    $gz = "$Path.gz"
    $in = [System.IO.File]::OpenRead($Path)
    try {
        $out = [System.IO.File]::Create($gz)
        try {
            $z = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
            try { $in.CopyTo($z, 1MB) } finally { $z.Dispose() }
        } finally { $out.Dispose() }
    } finally { $in.Dispose() }
    return $gz
}

function New-NoLaunchPackage {
    <#
    .SYNOPSIS
        Writes summary.json and zips the small files of a launch folder (not dumps or the raw trace).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Folder, [Parameter(Mandatory)] $Summary)
    $Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Folder 'summary.json') -Encoding UTF8
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zipPath = Join-Path $Folder ("NO-launch_{0}.zip" -f $Summary.LaunchId)
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Get-ChildItem -LiteralPath $Folder -File | Where-Object { $_.Extension -notin '.dmp', '.etl', '.gz', '.zip' } | ForEach-Object {
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $_.Name)
        }
    } finally { $zip.Dispose() }
    return $zipPath
}

function Get-NoLaunchHeavyFiles {
    <# The files that only a stuck launch uploads: dumps and the raw trace. #>
    param([Parameter(Mandatory)] [string]$Folder)
    return @(Get-ChildItem -LiteralPath $Folder -File | Where-Object { $_.Extension -in '.dmp', '.etl' } | ForEach-Object { $_.FullName })
}

function Invoke-NoLaunchFinalize {
    <#
    .SYNOPSIS
        Everything after the watch decides an outcome: stuck capture, stop the trace,
        decode, score, package. Runs in a background runspace; returns the summary.
    .PARAMETER Launch
        As for Get-NoLaunchSummary, plus Folder, SessionName, EtlPath (EtlPath may be $null:
        no trace when WinConfig is not elevated).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable]$Launch, [int]$StuckWatchSeconds = 30, [scriptblock]$OnStage = $null)
    $stage = { param($s) if ($OnStage) { try { & $OnStage $s } catch { } } }
    $folder = $Launch.Folder
    if ($Launch.Outcome -eq 'Stuck') {
        $cap = [ordered]@{}
        & $stage 'Stuck: recording thread states and a memory dump'
        $before = Get-NoLaunchThreadSnapshot -ProcessId $Launch.ProcessId
        $before | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'threads-start.csv')
        $d1 = Save-NoLaunchDump -ProcessId $Launch.ProcessId -Path (Join-Path $folder 'NO-stuck-1.dmp')
        $cap.Dump1 = @{ Ok = $d1.Ok; Bytes = $d1.Bytes; Error = $d1.Error }
        & $stage "Stuck: watching $StuckWatchSeconds s more"
        Start-Sleep -Seconds $StuckWatchSeconds
        $after = Get-NoLaunchThreadSnapshot -ProcessId $Launch.ProcessId
        $after | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'threads-end.csv')
        $cap.BusiestThreads = Get-NoLaunchBusyThreads -Before $before -After $after
        $cap.ThreadStates = @($after | Group-Object ThreadState, WaitReason | ForEach-Object { "$($_.Name)=$($_.Count)" })
        & $stage 'Stuck: second memory dump'
        $d2 = Save-NoLaunchDump -ProcessId $Launch.ProcessId -Path (Join-Path $folder 'NO-stuck-2.dmp')
        $cap.Dump2 = @{ Ok = $d2.Ok; Bytes = $d2.Bytes; Error = $d2.Error }
        $Launch.StuckCapture = $cap
    }
    $endT = [math]::Round(((Get-Date) - $Launch.LaunchStart).TotalSeconds, 1)
    if ($Launch.SessionName) { [void](Stop-NoLaunchEtwSession -SessionName $Launch.SessionName) }

    @($Launch.Samples) | Select-Object T, CpuSec, WorkingSetMB, Threads, Handles | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'samples.csv')
    @($Launch.WindowTimeline) | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'windows.csv')

    if ($Launch.EtlPath -and (Test-Path -LiteralPath $Launch.EtlPath)) {
        & $stage 'Reading the trace'
        try {
            $rows = @(Get-NoLaunchEtwRows -EtlPath $Launch.EtlPath -ProcessId $Launch.ProcessId -LaunchStart $Launch.LaunchStart)
            $rows | ForEach-Object { [pscustomobject]@{ T = $_.T; Provider = $_.Provider; Id = $_.Id; Op = $_.Op; Name = (Get-NoLaunchEtwRowName $_); Detail = (($_.Fields.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' | ') } } | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'trace-NO.csv')
            $Launch.EtwDigest = Get-NoLaunchEtwDigest -Rows $rows -EndT $endT
        } catch {
            $Launch.EtwDigest = [ordered]@{ Error = $_.Exception.Message }
        }
    } else {
        $Launch.EtwDigest = [ordered]@{ Error = $(if ($Launch.TraceError) { $Launch.TraceError } else { 'no trace for this launch' }) }
    }

    $summary = Get-NoLaunchSummary -Launch $Launch
    $zip = New-NoLaunchPackage -Folder $folder -Summary $summary
    return @{ Summary = $summary; ZipPath = $zip; Folder = $folder }
}

function Send-NoLaunchPackage {
    <#
    .SYNOPSIS
        Uploads a launch: the small package always; dumps + raw trace (gzipped) when stuck.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable]$Finalized, [switch]$IncludeHeavy, [scriptblock]$OnStage = $null)
    $stage = { param($s) if ($OnStage) { try { & $OnStage $s } catch { } } }
    $s = $Finalized.Summary
    $prefix = Get-NoLaunchRemotePrefix -Computer $s.Computer -LaunchId $s.LaunchId -Outcome $s.Outcome
    $config = Get-WinConfigDiagnosticsUploadConfig -Channel Support
    $result = [ordered]@{ Package = $null; Heavy = @() }
    & $stage 'Sending the launch summary'
    $result.Package = Send-WinConfigDiagnosticPackage -PackagePath $Finalized.ZipPath -Config $config -Metadata @{ ToolId = 'no-launch-watch'; LaunchId = $s.LaunchId; Outcome = $s.Outcome } -FolderPrefix $prefix
    if ($IncludeHeavy) {
        $cloud = ($config.Enabled -and $config.Provider -eq 'R2' -and $config.R2)
        foreach ($f in @(Get-NoLaunchHeavyFiles -Folder $Finalized.Folder)) {
            $name = Split-Path $f -Leaf
            if (-not $cloud) {
                # Never spend minutes compressing gigabytes that cannot be sent.
                $result.Heavy += [pscustomobject]@{ File = $name; Status = 'Skipped'; Bytes = (Get-Item -LiteralPath $f).Length; Error = 'Cloud upload is not configured in this build' }
                continue
            }
            & $stage "Compressing $name"
            $gz = Compress-NoLaunchFile -Path $f
            & $stage "Sending $name"
            $up = Send-WinConfigLargeFile -FilePath $gz -Config $config -ObjectKey "$prefix/$(Split-Path $gz -Leaf)"
            $result.Heavy += [pscustomobject]@{ File = $name; Status = $up.Status; Bytes = $up.Bytes; Error = $up.Error }
            # The original stays on the PC either way; the .gz is only a transport copy.
            Remove-Item -LiteralPath $gz -Force -ErrorAction SilentlyContinue
        }
    }
    return $result
}

#endregion

#region Local cleanup
#
# A stuck capture is 1.5-2.5 GB. Once EVERYTHING a launch had to send is in the
# bucket, its folder is deleted -- but only when WinConfig closes, so the tester
# can still open the files while WinConfig runs. Anything not confirmed sent
# stays on the PC. The upload marker is the only evidence the sweep trusts.

function Write-NoLaunchUploadMarker {
    <#
    .SYNOPSIS
        Records what reached the bucket in <folder>\upload.json. AllSent is true only when the
        package was uploaded and, for a stuck launch, every dump and the raw trace were too.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable]$Finalized, [Parameter(Mandatory)] $Send, [int]$OwnerPid = $PID)
    $heavy = @($Send.Heavy)
    $heavySent = @($heavy | Where-Object { $_.Status -eq 'Uploaded' }).Count
    $allSent = ([string]$Send.Package.Status -eq 'Uploaded')
    if ($Finalized.Summary.Outcome -eq 'Stuck') {
        # Every heavy file on disk must have been sent, not just the ones attempted.
        $onDisk = @(Get-NoLaunchHeavyFiles -Folder $Finalized.Folder).Count
        $allSent = $allSent -and $heavySent -eq $heavy.Count -and $heavy.Count -ge $onDisk
    }
    $marker = [ordered]@{
        AllSent       = [bool]$allSent
        PackageStatus = [string]$Send.Package.Status
        HeavySent     = $heavySent
        HeavyTotal    = $heavy.Count
        OwnerPid      = $OwnerPid
        WrittenAt     = (Get-Date).ToString('o')
    }
    $marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Finalized.Folder 'upload.json') -Encoding UTF8
    return $marker
}

function Remove-NoLaunchSentFolders {
    <#
    .SYNOPSIS
        Called when WinConfig closes: deletes launch folders whose upload.json says AllSent,
        and folders holding only a raw trace with no launch record (nothing to send or read).
    .DESCRIPTION
        Kept: anything not confirmed sent (failed or interrupted upload, uploads not
        configured), and folders owned by another WinConfig that is still running.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Root, [int]$CurrentPid = $PID)
    $result = [ordered]@{ Removed = @(); Kept = @(); FreedBytes = [long]0 }
    if (-not (Test-Path -LiteralPath $Root)) { return $result }
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -Filter 'launch-*')) {
        $files = @(Get-ChildItem -LiteralPath $dir.FullName -File -Recurse -ErrorAction SilentlyContinue)
        $bytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
        $markerPath = Join-Path $dir.FullName 'upload.json'
        $remove = $false
        if (Test-Path -LiteralPath $markerPath) {
            $m = $null
            try { $m = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json } catch { }
            if ($m -and $m.AllSent -eq $true) {
                $owner = [int]$m.OwnerPid
                # Another WinConfig still running may need its files; a dead owner (crash) does not.
                $remove = ($owner -eq $CurrentPid -or -not (Get-Process -Id $owner -ErrorAction SilentlyContinue))
            }
        } elseif (@($files | Where-Object { $_.Name -notmatch '\.etl(\.providers\.txt)?$' }).Count -eq 0) {
            # Only a raw trace (and its providers list), no launch record: armed and never launched, or a launch WinConfig closed on
            # before it was packaged (its record lived in memory). Finalize always writes windows.csv.
            $remove = $true
        }
        if (-not $remove) { $result.Kept += $dir.Name; continue }
        try {
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
            $result.Removed += $dir.Name
            $result.FreedBytes += $bytes
        } catch {
            $result.Kept += $dir.Name
        }
    }
    return $result
}

#endregion

Export-ModuleMember -Function @(
    'Get-NoLaunchEtwProviders'
    'Start-NoLaunchEtwSession'
    'Stop-NoLaunchEtwSession'
    'Stop-NoLaunchStaleEtwSessions'
    'Get-NoLaunchSessionName'
    'Get-NoLaunchRules'
    'ConvertFrom-NoLaunchWindowList'
    'Get-NoLaunchWindows'
    'Get-NoLaunchWindowSignature'
    'Test-NoLaunchReady'
    'Get-NoLaunchProcessSample'
    'Get-NoLaunchThreadSnapshot'
    'Get-NoLaunchBusyThreads'
    'Save-NoLaunchDump'
    'Get-NoLaunchContext'
    'ConvertFrom-NoLaunchNetAddress'
    'ConvertFrom-NoLaunchNetPort'
    'Get-NoLaunchEtwRows'
    'Get-NoLaunchEtwRowName'
    'Get-NoLaunchEtwDigest'
    'Get-NoLaunchSummary'
    'New-NoLaunchLaunchId'
    'Get-NoLaunchRemotePrefix'
    'Compress-NoLaunchFile'
    'New-NoLaunchPackage'
    'Get-NoLaunchHeavyFiles'
    'Invoke-NoLaunchFinalize'
    'Send-NoLaunchPackage'
    'Write-NoLaunchUploadMarker'
    'Remove-NoLaunchSentFolders'
)

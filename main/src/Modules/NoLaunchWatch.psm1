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
#   From Start watching:    process/image loads, TCP/UDP, DNS (light), so the
#                           very start of NO is never missed.
#   From the moment NO.exe appears: file opens and registry access. These are
#                           kernel providers -- a process filter does not apply
#                           to them (ETW enables PID-scoped providers in user
#                           mode only) -- so this trace is system-wide. Started
#                           at launch, not at Start watching: on MM06 the Event
#                           Log service alone filled 1 GB in ~3 min, which wrapped
#                           a Full trace started at arming before a stuck launch
#                           ended. From launch, a stuck launch (90 s + 30 s
#                           capture) stays well inside the 2 GB circular file.
# Every launch is traced the same way, so launch times compare with each other
# (not with records made before trace setup 2).
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
$script:NoLaunchStuckAfterSec   = 90
$script:NoLaunchSessionPrefix   = 'WinConfigNoLaunch'
$script:NoLaunchTraceSetup      = 'light-at-watch+file-registry-at-launch/2'

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

if (-not ('WinConfigNoLaunchEtl' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

// Reads one process's events from an .etl file with the native ETW consumer
// (OpenTrace/ProcessTrace). Events of other processes are skipped by header PID
// before any decoding, which is what makes a system-wide trace cheap to read.
// Matched events are decoded with TDH and rendered the way the Windows event
// XML renders them, so rows equal the EventLogReader ones.
public static class WinConfigNoLaunchEtl
{
    public sealed class Row
    {
        public double T { get; set; }                  // seconds since launch start
        public string Provider { get; set; }           // without "Microsoft-Windows-"
        public int Id { get; set; }
        public string Op { get; set; }                 // opcode name ('' when none)
        public System.Collections.Specialized.OrderedDictionary Fields { get; set; }
        public string Name { get; set; }               // the one human-readable thing it touched
    }

    // Same rules as Get-NoLaunchEtwRowName.
    static string RowName(Row r)
    {
        var f = r.Fields;
        switch (r.Provider)
        {
            case "Kernel-Network":
                if (f.Contains("daddr")) return r.Op + " " + NetAddress((string)f["daddr"]) + ":" + NetPort(f.Contains("dport") ? (string)f["dport"] : "");
                return null;
            case "DNS-Client": return f.Contains("QueryName") ? "DNS " + f["QueryName"] : null;
            case "Kernel-Process": return f.Contains("ImageName") ? "load " + f["ImageName"] : null;
            default:
                foreach (var k in new[] { "FileName", "RelativeName", "KeyName", "ValueName" }) if (f.Contains(k)) return (string)f[k];
                return null;
        }
    }
    static bool Digits(string v) { if (string.IsNullOrEmpty(v)) return false; foreach (var c in v) if (c < '0' || c > '9') return false; return true; }
    static string NetAddress(string v) { return Digits(v) ? new System.Net.IPAddress(long.Parse(v, CultureInfo.InvariantCulture)).ToString() : v; }
    static string NetPort(string v) { if (!Digits(v)) return v; int p = int.Parse(v, CultureInfo.InvariantCulture); return (((p & 0xFF) << 8) | (p >> 8)).ToString(CultureInfo.InvariantCulture); }

    static string Q(string v) { return "\"" + (v ?? "").Replace("\"", "\"\"") + "\""; }
    // trace-NO.csv, same columns and quoting as Export-Csv -NoTypeInformation.
    public static void WriteCsv(IEnumerable<Row> rows, string path)
    {
        using (var w = new System.IO.StreamWriter(path, false, new UTF8Encoding(true)))
        {
            w.WriteLine("\"T\",\"Provider\",\"Id\",\"Op\",\"Name\",\"Detail\"");
            var sb = new StringBuilder();
            foreach (var r in rows)
            {
                sb.Length = 0;
                bool first = true;
                foreach (System.Collections.DictionaryEntry e in r.Fields) { if (!first) sb.Append(" | "); sb.Append(e.Key).Append('=').Append(e.Value); first = false; }
                w.Write(Q(r.T.ToString(CultureInfo.InvariantCulture))); w.Write(',');
                w.Write(Q(r.Provider)); w.Write(','); w.Write(Q(r.Id.ToString(CultureInfo.InvariantCulture))); w.Write(',');
                w.Write(Q(r.Op)); w.Write(','); w.Write(Q(r.Name)); w.Write(','); w.WriteLine(Q(sb.ToString()));
            }
        }
    }

    public sealed class Result
    {
        public List<Row> Rows = new List<Row>();
        public string Error;
        public int Undecoded;          // NO's events whose fields could not be decoded (row kept, no fields)
    }

    // Client session files (C:\zengar\sessions\<client>\<session>) are clinical data:
    // keep that NO touched the sessions folder, never which client or session.
    static readonly Regex SessionPath = new Regex(@"(\\zengar\\sessions\\)[^|]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    public static string Redact(string v) { return (v != null && v.IndexOf("sessions", StringComparison.OrdinalIgnoreCase) >= 0) ? SessionPath.Replace(v, "$1<redacted>") : v; }

    // Reads several traces, merges them in time order (stable: file order breaks ties).
    public static Result ReadAll(string[] paths, int processId, long launchStartFileTimeUtc)
    {
        var all = new Result();
        foreach (var p in paths)
        {
            var r = Read(p, processId, launchStartFileTimeUtc);
            all.Rows.AddRange(r.Rows);
            all.Undecoded += r.Undecoded;
            if (r.Error != null) all.Error = (all.Error == null ? "" : all.Error + "; ") + System.IO.Path.GetFileName(p) + ": " + r.Error;
        }
        all.Rows = all.Rows.OrderBy(x => x.T).ToList();
        return all;
    }

    sealed class Prop
    {
        public string Name;
        public ushort InType, OutType;
        public ushort Flags;           // PROPERTY_FLAGS
        public ushort Length;          // fixed length, or index of the length property
        public ushort Count;           // fixed count, or index of the count property
    }

    sealed class Kind
    {
        public string Provider, Op;
        public Prop[] Props;           // null = cannot decode by hand
        public bool HasPid;            // template carries PID / ProcessID
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct EVENT_TRACE_HEADER
    {
        public ushort Size, FieldTypeFlags; public uint Version, ThreadId, ProcessId; public long TimeStamp; public Guid Guid; public uint KernelTime, UserTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct EVENT_TRACE
    {
        public EVENT_TRACE_HEADER Header; public uint InstanceId, ParentInstanceId; public Guid ParentGuid; public IntPtr MofData; public uint MofLength, ClientContext;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SYSTEMTIME { public ushort a, b, c, d, e, f, g, h; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TIME_ZONE_INFORMATION
    {
        public int Bias; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string StandardName; public SYSTEMTIME StandardDate; public int StandardBias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DaylightName; public SYSTEMTIME DaylightDate; public int DaylightBias;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TRACE_LOGFILE_HEADER
    {
        public uint BufferSize, Version, ProviderVersion, NumberOfProcessors; public long EndTime; public uint TimerResolution, MaximumFileSize, LogFileMode, BuffersWritten;
        public Guid LogInstanceGuid; public IntPtr LoggerName, LogFileName; public TIME_ZONE_INFORMATION TimeZone; public long BootTime, PerfFreq, StartTime; public uint ReservedFlags, BuffersLost;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct EVENT_TRACE_LOGFILE
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string LogFileName; [MarshalAs(UnmanagedType.LPWStr)] public string LoggerName;
        public long CurrentTime; public uint BuffersRead, ProcessTraceMode; public EVENT_TRACE CurrentEvent; public TRACE_LOGFILE_HEADER LogfileHeader;
        public IntPtr BufferCallback; public uint BufferSize, Filled, EventsLost; public IntPtr EventRecordCallback; public uint IsKernelTrace; public IntPtr Context;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate void EventRecordCallback(IntPtr record);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint BufferCallback(IntPtr logfile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logfile);
    [DllImport("advapi32.dll")] static extern uint ProcessTrace(ulong[] handles, uint count, IntPtr start, IntPtr end);
    [DllImport("advapi32.dll")] static extern uint CloseTrace(ulong handle);
    [DllImport("tdh.dll")] static extern uint TdhGetEventInformation(IntPtr evt, uint tdhContextCount, IntPtr tdhContext, IntPtr buffer, ref uint size);

    const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
    const ushort EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20;

    // EVENT_RECORD offsets (EVENT_HEADER is 80 bytes on both bitnesses).
    const int OffFlags = 4, OffPid = 12, OffTime = 16, OffProvider = 24, OffId = 40, OffVersion = 42, OffOpcode = 45, OffUserDataLength = 86;
    static int OffUserData { get { return IntPtr.Size == 8 ? 96 : 92; } }

    public static Result Read(string path, int processId, long launchStartFileTimeUtc)
    {
        var result = new Result();
        var kinds = new Dictionary<string, Kind>();
        string err = null;
        EventRecordCallback cb = delegate (IntPtr rec)
        {
            try { OnEvent(rec, processId, launchStartFileTimeUtc, kinds, result); }
            catch (Exception ex) { if (err == null) err = ex.Message; }
        };
        BufferCallback bcb = delegate (IntPtr lf) { return 1; };
        var log = new EVENT_TRACE_LOGFILE();
        log.LogFileName = path;
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = Marshal.GetFunctionPointerForDelegate(cb);
        log.BufferCallback = Marshal.GetFunctionPointerForDelegate(bcb);
        ulong h = OpenTraceW(ref log);
        bool invalid = (IntPtr.Size == 8) ? (h == 0xFFFFFFFFFFFFFFFFUL) : (h == 0x00000000FFFFFFFFUL || h == 0xFFFFFFFFFFFFFFFFUL);
        if (invalid) { result.Error = "OpenTrace failed: " + Marshal.GetLastWin32Error(); return result; }
        try
        {
            uint rc = ProcessTrace(new ulong[] { h }, 1, IntPtr.Zero, IntPtr.Zero);
            if (rc != 0 && rc != 1223) err = err ?? ("ProcessTrace returned " + rc);
        }
        finally { CloseTrace(h); GC.KeepAlive(cb); GC.KeepAlive(bcb); }
        result.Error = err;
        return result;
    }

    static void OnEvent(IntPtr rec, int target, long launchStart, Dictionary<string, Kind> kinds, Result result)
    {
        int pid = Marshal.ReadInt32(rec, OffPid);
        byte[] g = new byte[16]; Marshal.Copy(IntPtr.Add(rec, OffProvider), g, 0, 16);
        var provider = new Guid(g);
        ushort id = (ushort)Marshal.ReadInt16(rec, OffId);
        byte version = Marshal.ReadByte(rec, OffVersion);
        byte opcode = Marshal.ReadByte(rec, OffOpcode);
        string key = provider.ToString() + "|" + id + "|" + version + "|" + opcode;
        Kind kind;
        if (!kinds.TryGetValue(key, out kind))
        {
            kind = Describe(rec);
            kinds[key] = kind;
        }
        // Cheap skip: another process's event whose template cannot name a PID.
        if (pid != target && !kind.HasPid) return;
        List<KeyValuePair<string, string>> fields = null;
        if (kind.Props != null)
        {
            ushort flags = (ushort)Marshal.ReadInt16(rec, OffFlags);
            int ptrSize = (flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4 : 8;
            IntPtr data = Marshal.ReadIntPtr(rec, OffUserData);
            int len = (ushort)Marshal.ReadInt16(rec, OffUserDataLength);
            fields = Decode(kind.Props, data, len, ptrSize);
        }
        if (fields == null)
        {
            // Undecodable: keep NO's event (counts and timing stay right), without fields.
            if (pid != target) return;
            result.Undecoded++;
            fields = new List<KeyValuePair<string, string>>();
        }
        if (pid != target)
        {
            bool hit = false;
            foreach (var f in fields) { if ((f.Key == "PID" || f.Key == "ProcessID") && f.Value == target.ToString(CultureInfo.InvariantCulture)) { hit = true; break; } }
            if (!hit) return;
        }
        var row = new Row();
        // Same arithmetic as (TimeCreated - LaunchStart).TotalSeconds rounded to ms.
        row.T = Math.Round((Marshal.ReadInt64(rec, OffTime) - launchStart) * 1e-7, 3);
        row.Provider = kind.Provider.StartsWith("Microsoft-Windows-", StringComparison.Ordinal) ? kind.Provider.Substring(18) : kind.Provider;
        row.Id = id; row.Op = kind.Op;
        row.Fields = new System.Collections.Specialized.OrderedDictionary();
        foreach (var f in fields) if (!string.IsNullOrEmpty(f.Value) && !row.Fields.Contains(f.Key)) row.Fields.Add(f.Key, Redact(f.Value));
        row.Name = RowName(row);
        result.Rows.Add(row);
    }

    static Kind Describe(IntPtr rec)
    {
        var kind = new Kind { Provider = "", Op = "" };
        uint size = 0;
        TdhGetEventInformation(rec, 0, IntPtr.Zero, IntPtr.Zero, ref size);
        if (size == 0) return kind;
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (TdhGetEventInformation(rec, 0, IntPtr.Zero, buf, ref size) != 0) return kind;
            // TRACE_EVENT_INFO: ProviderGuid(16) EventGuid(16) EventDescriptor(16) DecodingSource(4)
            // ProviderNameOffset@52 LevelNameOffset@56 ChannelNameOffset@60 KeywordsNameOffset@64 TaskNameOffset@68
            // OpcodeNameOffset@72 EventMessageOffset@76 ProviderMessageOffset@80 BinaryXMLOffset@84 BinaryXMLSize@88
            // ActivityIDNameOffset@92 RelatedActivityIDNameOffset@96 PropertyCount@100 TopLevelPropertyCount@104 Flags@108
            // EventPropertyInfoArray@112, 24 bytes each.
            kind.Provider = Str(buf, Marshal.ReadInt32(buf, 52));
            kind.Op = Str(buf, Marshal.ReadInt32(buf, 72)).Trim();
            if (kind.Op.Length == 0 && Marshal.ReadByte(buf, 32 + 5) == 0) kind.Op = "Info";   // EventDescriptor.Opcode @ 32+5
            int count = Marshal.ReadInt32(buf, 100);
            int top = Marshal.ReadInt32(buf, 104);
            if (count != top) return kind;      // structs: not decoded by hand
            var props = new Prop[top];
            for (int i = 0; i < top; i++)
            {
                IntPtr p = IntPtr.Add(buf, 112 + i * 24);
                // EVENT_PROPERTY_INFO: Flags(4) NameOffset(4) union{InType(2) OutType(2) MapNameOffset(4)}
                // union{count(2)|countPropertyIndex(2)} union{length(2)|lengthPropertyIndex(2)} Reserved(4)
                var pr = new Prop();
                pr.Flags = (ushort)Marshal.ReadInt32(p, 0);
                pr.Name = Str(buf, Marshal.ReadInt32(p, 4));
                pr.InType = (ushort)Marshal.ReadInt16(p, 8);
                pr.OutType = (ushort)Marshal.ReadInt16(p, 10);
                pr.Count = (ushort)Marshal.ReadInt16(p, 16);
                pr.Length = (ushort)Marshal.ReadInt16(p, 18);
                if ((pr.Flags & 0x1) != 0) return kind;       // PropertyStruct
                if ((pr.Flags & 0x4) != 0 || pr.Count > 1) return kind;   // arrays
                props[i] = pr;
                if (pr.Name == "PID" || pr.Name == "ProcessID") kind.HasPid = true;
            }
            kind.Props = props;
        }
        finally { Marshal.FreeHGlobal(buf); }
        return kind;
    }

    static string Str(IntPtr buf, int off) { return off > 0 ? Marshal.PtrToStringUni(IntPtr.Add(buf, off)) : ""; }

    static List<KeyValuePair<string, string>> Decode(Prop[] props, IntPtr data, int len, int ptrSize)
    {
        var res = new List<KeyValuePair<string, string>>(props.Length);
        var raw = new long[props.Length];
        int off = 0;
        for (int i = 0; i < props.Length; i++)
        {
            var p = props[i];
            string v = null;
            if (off > len) return null;
            int lenParam = ((p.Flags & 0x2) != 0) ? (int)raw[p.Length] : p.Length;   // PropertyParamLength
            switch (p.InType)
            {
                case 1: // UNICODESTRING
                    {
                        if ((p.Flags & 0x2) != 0 || p.Length > 0) { int n = lenParam; v = Marshal.PtrToStringUni(IntPtr.Add(data, off), n); off += n * 2; }
                        else { int n = 0; while (off + n * 2 + 1 < len && Marshal.ReadInt16(data, off + n * 2) != 0) n++; v = Marshal.PtrToStringUni(IntPtr.Add(data, off), n); off += (n + 1) * 2; }
                        break;
                    }
                case 2: // ANSISTRING
                    {
                        int n = 0; while (off + n < len && Marshal.ReadByte(data, off + n) != 0) n++;
                        var b = new byte[n]; Marshal.Copy(IntPtr.Add(data, off), b, 0, n); v = Encoding.Default.GetString(b); off += n + 1; break;
                    }
                case 3: { sbyte x = (sbyte)Marshal.ReadByte(data, off); raw[i] = x; v = Num(x, p.OutType, 1); off += 1; break; }
                case 4: { byte x = Marshal.ReadByte(data, off); raw[i] = x; v = Num(x, p.OutType, 1); off += 1; break; }
                case 5: { short x = Marshal.ReadInt16(data, off); raw[i] = x; v = Num(x, p.OutType, 2); off += 2; break; }
                case 6: { ushort x = (ushort)Marshal.ReadInt16(data, off); raw[i] = x; v = Num(x, p.OutType, 2); off += 2; break; }
                case 7: { int x = Marshal.ReadInt32(data, off); raw[i] = x; v = Num(x, p.OutType, 4); off += 4; break; }
                case 8: { uint x = (uint)Marshal.ReadInt32(data, off); raw[i] = x; v = Num(x, p.OutType, 4); off += 4; break; }
                case 9: { long x = Marshal.ReadInt64(data, off); raw[i] = x; v = Num(x, p.OutType, 8); off += 8; break; }
                case 10: { ulong x = (ulong)Marshal.ReadInt64(data, off); raw[i] = (long)x; v = Num(x, p.OutType, 8); off += 8; break; }
                case 13: { int x = Marshal.ReadInt32(data, off); v = x != 0 ? "true" : "false"; off += 4; break; }
                case 15: { var b = new byte[16]; Marshal.Copy(IntPtr.Add(data, off), b, 0, 16); v = "{" + new Guid(b).ToString().ToUpperInvariant() + "}"; off += 16; break; }
                case 16: // POINTER
                    {
                        ulong x = ptrSize == 8 ? (ulong)Marshal.ReadInt64(data, off) : (uint)Marshal.ReadInt32(data, off);
                        raw[i] = (long)x; v = "0x" + x.ToString("x", CultureInfo.InvariantCulture); off += ptrSize; break;
                    }
                case 17: // FILETIME
                    {
                        long x = Marshal.ReadInt64(data, off); off += 8;
                        v = DateTime.FromFileTimeUtc(x).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
                        break;
                    }
                case 20: { uint x = (uint)Marshal.ReadInt32(data, off); raw[i] = x; v = x.ToString(CultureInfo.InvariantCulture); off += 4; break; }
                case 21: { ulong x = (ulong)Marshal.ReadInt64(data, off); raw[i] = (long)x; v = x.ToString(CultureInfo.InvariantCulture); off += 8; break; }
                case 14: // BINARY
                    {
                        int n = lenParam; var b = new byte[n]; Marshal.Copy(IntPtr.Add(data, off), b, 0, n); off += n;
                        var sb = new StringBuilder(n * 2); foreach (var x in b) sb.Append(x.ToString("X2", CultureInfo.InvariantCulture)); v = sb.ToString(); break;
                    }
                case 19: // SID
                    {
                        // SID: revision(1) subCount(1) authority(6) subs(4*n)
                        int sub = Marshal.ReadByte(data, off + 1); int n = 8 + 4 * sub;
                        var b = new byte[n]; Marshal.Copy(IntPtr.Add(data, off), b, 0, n); off += n;
                        v = new System.Security.Principal.SecurityIdentifier(b, 0).Value; break;
                    }
                default: return null;   // unknown type: caller drops the row (parity test catches it)
            }
            res.Add(new KeyValuePair<string, string>(p.Name, v));
        }
        return res;
    }

    static string Num(long x, ushort outType, int size) { return Hex(outType) ? "0x" + ((ulong)x & Mask(size)).ToString("X", CultureInfo.InvariantCulture) : x.ToString(CultureInfo.InvariantCulture); }
    static string Num(ulong x, ushort outType, int size) { return Hex(outType) ? "0x" + x.ToString("X", CultureInfo.InvariantCulture) : x.ToString(CultureInfo.InvariantCulture); }
    static ulong Mask(int size) { return size >= 8 ? ulong.MaxValue : ((1UL << (size * 8)) - 1); }
    // HEXBINARY and HEXINT8/16/32/64 render in hex in event XML; NTSTATUS/HRESULT/WIN32ERROR stay decimal.
    static bool Hex(ushort t) { return false; }
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
    param([ValidateSet('Light', 'Full', 'FileRegistry')] [string]$Level = 'Light')
    $lines = @()
    if ($Level -ne 'FileRegistry') {
        $lines += '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 0x50 0x5'                # Kernel-Process: process + image loads
        $lines += '{7DD42A49-5329-4832-8DFD-43D979153A88} 0x30 0x5'                # Kernel-Network: TCP/UDP, IPv4 + IPv6
        $lines += '{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} 0xFFFFFFFFFFFFFFFF 0x5'  # DNS-Client
    }
    if ($Level -ne 'Light') {
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
        [ValidateSet('Light', 'Full', 'FileRegistry')] [string]$Level = 'Light',
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
    return [pscustomobject]@{ ReadyRuleVersion = $script:NoLaunchReadyRuleVersion; StuckAfterSeconds = $script:NoLaunchStuckAfterSec; PostReadySeconds = 5; TraceSetup = $script:NoLaunchTraceSetup; FileTraceMaxMB = 2048 }
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
        One process's events from one or more traces, merged in time order, T = seconds since launch.
    .DESCRIPTION
        Native ETW consumer (WinConfigNoLaunchEtl): other processes' events are skipped by
        header PID before decoding, so a system-wide trace costs ~5 s per GB instead of
        ~150 s (MM06 2026-10-02: 238 MB file/registry trace 57 s -> 1.0 s; 1 GB Full trace
        128 s -> 4.3 s; rows identical to the event-log reader except Op, which the event-log
        reader got WRONG -- every Kernel-Network event carried the label of the first one
        seen). Session file paths are redacted inside the reader.
        If the native reader fails outright, falls back to the event-log reader per file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]]$EtlPath, [Parameter(Mandatory)] [int]$ProcessId, [Parameter(Mandatory)] [datetime]$LaunchStart, [hashtable]$Stats = $null)
    $paths = @($EtlPath | ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath })
    $r = [WinConfigNoLaunchEtl]::ReadAll([string[]]$paths, $ProcessId, $LaunchStart.ToFileTime())
    if ($Stats) { $Stats.Reader = 'native'; $Stats.Undecoded = $r.Undecoded; $Stats.ReaderError = $r.Error }
    if ($r.Error -and $r.Rows.Count -eq 0) {
        if ($Stats) { $Stats.Reader = 'eventlog (native failed)' }
        return @($paths | ForEach-Object { Get-NoLaunchEtwRowsEventLog -EtlPath $_ -ProcessId $ProcessId -LaunchStart $LaunchStart } | Sort-Object T)
    }
    return $r.Rows.ToArray()
}

function Get-NoLaunchEtwRowsEventLog {
    <#
    .SYNOPSIS
        Fallback reader (event-log API). Events from the trace that belong to one process, with T = seconds since launch.
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
                        if ($t) { $fields[$kind.Names[$i]] = [WinConfigNoLaunchEtl]::Redact($t) }
                    }
                } else {
                    $x = [xml]$e.ToXml()
                    foreach ($d in @($x.Event.EventData.Data)) { if ($d -and $d.'#text') { $fields[$d.Name] = [WinConfigNoLaunchEtl]::Redact($d.'#text') } }
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
    <# The one human-readable thing an event touched. Pure. (Native rows carry it already.) #>
    param([object]$Row)
    if ($Row -is [WinConfigNoLaunchEtl+Row]) { return $Row.Name }
    $f = $Row.Fields
    switch ($Row.Provider) {
        'Kernel-Network' { if ($f['daddr']) { return ('{0} {1}:{2}' -f $Row.Op, (ConvertFrom-NoLaunchNetAddress $f['daddr']), (ConvertFrom-NoLaunchNetPort $f['dport'])) } }
        'DNS-Client'     { if ($f['QueryName']) { return "DNS $($f['QueryName'])" } }
        'Kernel-Process' { if ($f['ImageName']) { return "load $($f['ImageName'])" } }
        default          { foreach ($k in 'FileName', 'RelativeName', 'KeyName', 'ValueName') { if ($f[$k]) { return $f[$k] } } }
    }
    return $null
}

function Write-NoLaunchTraceCsv {
    <#
    .SYNOPSIS
        trace-NO.csv: T, Provider, Id, Op, Name, Detail -- same columns and quoting as Export-Csv, ~10x faster.
    #>
    [CmdletBinding()]
    param([object[]]$Rows, [Parameter(Mandatory)] [string]$Path)
    $native = @($Rows | Where-Object { $_ -isnot [WinConfigNoLaunchEtl+Row] }).Count -eq 0
    if ($native) { [WinConfigNoLaunchEtl]::WriteCsv([WinConfigNoLaunchEtl+Row[]]@($Rows), $Path); return }
    # Fallback rows (event-log reader): same file, PowerShell speed.
    $q = { param($v) '"' + ([string]$v).Replace('"', '""') + '"' }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('"T","Provider","Id","Op","Name","Detail"')
    foreach ($r in @($Rows)) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($k in $r.Fields.Keys) { $parts.Add("$k=$($r.Fields[$k])") }
        [void]$sb.Append((& $q ([double]$r.T).ToString($inv))).Append(',').Append((& $q $r.Provider)).Append(',').Append((& $q $r.Id)).Append(',').Append((& $q $r.Op)).Append(',').Append((& $q (Get-NoLaunchEtwRowName $r))).Append(',').AppendLine((& $q ($parts -join ' | ')))
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

function Get-NoLaunchEtwDigest {
    <#
    .SYNOPSIS
        Summary of NO's trace events: DNS, peers, when it went quiet, what it touched last. Pure.
    .DESCRIPTION
        Plain loops, not pipelines: a Full launch is ~40k rows, and Where-Object/Group-Object
        over them cost ~7 s. Output is unchanged.
    #>
    param([object[]]$Rows, [double]$EndT = -1)
    $rows = @($Rows)
    $byProvider = [ordered]@{}
    $dnsFirst = [ordered]@{}
    $peerKeys = New-Object System.Collections.Generic.List[string]
    $perTenCount = @{}
    $images = 0
    $lastT = $null
    foreach ($r in $rows) {
        $prov = $r.Provider
        if ($byProvider.Contains($prov)) { $byProvider[$prov]++ } else { $byProvider[$prov] = 1 }
        $f = $r.Fields
        if ($prov -eq 'DNS-Client' -and $f['QueryName']) {
            $q = [string]$f['QueryName']
            if (-not $dnsFirst.Contains($q) -or $r.T -lt $dnsFirst[$q]) { $dnsFirst[$q] = $r.T }
        } elseif ($prov -eq 'Kernel-Network' -and $f['daddr']) {
            $peerKeys.Add(('{0}:{1}' -f (ConvertFrom-NoLaunchNetAddress $f['daddr']), (ConvertFrom-NoLaunchNetPort $f['dport'])))
        } elseif ($prov -eq 'Kernel-Process' -and $f['ImageName']) {
            $images++
        }
        if ($prov -ne 'Kernel-Process' -and ($null -eq $lastT -or $r.T -gt $lastT)) { $lastT = [double]$r.T }
        $bucket = [int]([math]::Floor($r.T / 10) * 10)
        $perTenCount[$bucket] = 1 + [int]$perTenCount[$bucket]
    }
    # Each name once, at the time it was FIRST looked up.
    $dns = @($dnsFirst.GetEnumerator() | ForEach-Object { [pscustomobject]@{ T = [math]::Round([double]$_.Value, 1); Name = $_.Key } } | Sort-Object T)
    $peers = @($peerKeys | Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Peer = $_.Name; Events = $_.Count } })
    # The last 15 named activity rows, oldest first.
    $named = New-Object System.Collections.Generic.List[object]
    for ($i = $rows.Count - 1; $i -ge 0 -and $named.Count -lt 15; $i--) {
        $r = $rows[$i]
        if ($r.Provider -eq 'Kernel-Process') { continue }
        $n = Get-NoLaunchEtwRowName $r
        if ($n) { $named.Insert(0, [pscustomobject]@{ T = $r.T; Provider = $r.Provider; Name = $n }) }
    }
    $perTen = [ordered]@{}
    foreach ($k in ($perTenCount.Keys | Sort-Object)) { $perTen["$k"] = $perTenCount[$k] }
    # Built key by key: PS 5.1 fails to compile this as an [ordered] literal with these
    # loop-typed locals ("Argument types do not match").
    $out = [ordered]@{}
    $out.EventCount = $rows.Count
    $out.ByProvider = $byProvider
    $out.DnsLookups = $dns
    $out.RemotePeers = $peers
    $out.ImageLoads = $images
    $out.LastActivityT = $lastT
    $out.QuietForSecAtEnd = $null
    if ($EndT -ge 0 -and $null -ne $lastT) { $out.QuietForSecAtEnd = [math]::Round([double]$EndT - [double]$lastT, 1) }
    $out.LastTouched = $named.ToArray()
    $out.EventsPerTenSec = $perTen
    return $out
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
    # Comparable = traced the standard way (light from watch + file/registry from launch).
    # A launch whose file trace failed, or with no trace, ran under different load.
    $comparable = ($Launch.TraceLevel -eq 'Full')
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
        TraceSetup              = $script:NoLaunchTraceSetup
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
    if ($Launch.FileSessionName) { [void](Stop-NoLaunchEtwSession -SessionName $Launch.FileSessionName) }

    @($Launch.Samples) | Select-Object T, CpuSec, WorkingSetMB, Threads, Handles | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'samples.csv')
    @($Launch.WindowTimeline) | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $folder 'windows.csv')

    $etls = @(@($Launch.EtlPath, $Launch.FileEtlPath) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($etls.Count) {
        & $stage 'Reading the trace'
        try {
            $readStats = @{}
            $rows = @(Get-NoLaunchEtwRows -EtlPath $etls -ProcessId $Launch.ProcessId -LaunchStart $Launch.LaunchStart -Stats $readStats)
            Write-NoLaunchTraceCsv -Rows $rows -Path (Join-Path $folder 'trace-NO.csv')
            $Launch.EtwDigest = Get-NoLaunchEtwDigest -Rows $rows -EndT $endT
            $Launch.EtwDigest.Reader = $readStats.Reader
            $Launch.EtwDigest.UndecodedEvents = $readStats.Undecoded
            if ($readStats.ReaderError) { $Launch.EtwDigest.ReaderError = $readStats.ReaderError }
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
    'Get-NoLaunchEtwRowsEventLog'
    'Write-NoLaunchTraceCsv'
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

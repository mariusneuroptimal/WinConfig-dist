# SupportBundle.psm1
# SUPPORT-PROBE-001: "Collect Support Bundle" — general-purpose escalation collector.
#
# CONTRACT (docs/SUPPORT-PROBE-001.md):
# - FACTS, NOT DIAGNOSES: no severity, no PASS/WARN/FAIL, no ActionHints (§3.4)
# - ISOLATED COLLECTORS: every collector runs in its own runspace with its own
#   timeout; a collector that throws or hangs becomes an Error/Timeout entry in
#   the manifest and the run continues. The bundle ALWAYS ships (§3.1)
# - NO SILENT TRUNCATION: every cap that trims appends an explicit marker and
#   is recorded in manifest truncations[] (§3.2)
# - DEGRADE ON MISSING ELEVATION: admin collectors record Skipped, never fail (§3.3)
# - EPHEMERAL PATHS ONLY: writes only under the run folder the caller provides,
#   which lives under Get-WinConfigExportsPath (§3.5)
# - HARD DENY-LIST: no collector may reach C:\zengar\sessions or C:\zengar\BLT_data;
#   enforced centrally in Add-WinConfigSupportBundleFile and Test-WinConfigSupportPathAllowed,
#   not per-collector (§6)
# - REDACTION: maintenancetool.ini is NEVER copied verbatim — only whitelisted
#   parsed fields are emitted and the repo password is always '<redacted>'.
#   network.xml credential elements are blanked before packaging (§6)
#
# BOUNDARY: This module owns collection. Packaging (DiagnosticsPackage.psm1) and
# upload (DiagnosticsUpload.psm1) are invoked by New-WinConfigSupportBundle /
# the App.ps1 button handler; this module must not import DiagnosticsUpload.psm1.

Set-StrictMode -Off

# =============================================================================
# CONSTANTS (SUPPORT-PROBE-001 §11) — single block; do not scatter endpoints
# =============================================================================
# Bump on ANY collector-semantics change (new/removed collector, changed facts
# shape, new transform) — the analyzer reads this to know which collector
# behavior produced a bundle's facts. Pinned by a test in SupportBundle.Tests.ps1.
# 1.1.0 (2026-07-23): RedactInstallationLog transform (FI-007), maintenancetool
#   facts in ZEN-VERSION-001, WIN-VISA-001 + WIN-ODBC-001 collectors,
#   zengar.repositoryChannels manifest fact.
# 1.1.1 (2026-07-23): RedactInstallationLog also redacts /LICENSECODE= values
#   (FI-011 — QtIFW echoes the G-Force installer argv, license code included,
#   into InstallationLog.txt when the component's Execute operation fails).
# 1.2.0 (2026-07-28): ZEN-PROCESS-001 collector (FI-013 — processes and services
#   whose image lives inside the install root; QtIFW refuses every component
#   operation while one is running, which no earlier collector could see).
# 1.3.0 (2026-07-28): ZEN-EXTCOMPONENT-001 collector — components.xml can record a
#   component as installed when the third-party installer its Execute operation
#   shells out to never wrote anything. Six bundles across two boxes agreed with
#   that false record because nothing checked the product's own disk footprint.
# 1.4.0 (2026-07-31): WIN-NIPKG-001 collector (FI-016 — NI Package Manager feeds
#   outlive the install root and make a reinstall fail -125006); maintenancetool
#   sha256 + Authenticode status and installer.dat facts in ZEN-VERSION-001, and
#   the live runtime root's mtime in ZEN-WEBVIEW2-001 (FI-015 — a maintenancetool
#   that cannot initialize, where "is the binary damaged?" was unanswerable from
#   the bundle and the gutted WebView2 tree was undatable).
# 1.5.0 (2026-08-11): ZEN-INSTALLLOG-001 gains lastWriteTime (FI-018 — QtIFW
#   does not flush a run's operations until it ends, so a WEDGED installer looks
#   like a clean one: MCAJOLAIS_05 sat 12 minutes with maintenancetool alive and
#   no rule could see it, because nothing recorded how old the log was);
#   RedactInstallationLog also redacts the mysql client's attached '-p<value>'
#   argv (FI-017 — same secret as FI-007 through a syntax the key=value pattern
#   cannot see, shipped in the clear on adjacent lines of one bundle).
# 1.6.0 (2026-08-21): WIN-VISA-002 collector (FI-012 — NO reaches the Arc's COM
#   ports through NI-VISA, so visaconf.ini is a THIRD COM identity table beside
#   Windows SERIALCOMM/PnP and NO's own device record. Measured on SP6 holding 9
#   stale ASRL resources while the box had ZERO COM ports, with ASRL11::INSTR
#   and ASRL3::INSTR both mapped to COM3. Nothing collected that layer, and the
#   existing COM-arbiter/BTHENUM remedies do not clean it).
# 1.7.0 (2026-09-25): ZEN-NOLIVE-001 collector (FI-022 — NO.exe sat on
#   "Refreshing Licensing Information" through three force-closes and two
#   reboots on SP7P_I5_8GB_TES; the bundle proved the network healthy but could
#   not say whether NO was busy, idle, or talking to anything, nor whether
#   MySQL was up — it took three hand-run rounds and two memory dumps).
#   WIN-WER-001 now actually emits the Sig values: its '-like "Sig[0].Value=*"'
#   match treated [0] as a wildcard class and never matched a real line, so no
#   bundle ever carried a hang/crash signature. ZEN-INI-001 withholds binary
#   content (splashscreen.ini was an 800 KB non-text blob on that box) and
#   ships size/mtime/sha256 in its place.
# 1.8.0 (2026-10-15): HS-134 — NO 4.0.0.11 failed to start with 'Bad Image'
#   0xc0e90002 on C:\Zengar\data\HeadsetConnectionDiagnostics.dll plus a
#   Windows Security toast for libcrypto-3-ni.dll: Smart App Control refusing
#   code it cannot attribute to a publisher. The bundle captured the CI events
#   but could not say WHICH policy blocked, whether Smart App Control was on,
#   or that the DLL ships unsigned. WIN-CODEINT-001 now carries the event's
#   fileName/processName/policyName/policyGuid/status from the event XML;
#   WIN-SECURITY-001 carries smartAppControlState; new ZEN-BINSIG-001 records
#   the Authenticode status of every .exe/.dll under C:\zengar (deny-list
#   pruned) and the NI '*-ni.dll' set in System32.
# 1.9.0 (2026-10-20): the post-26H2 component reinstall on SP9-I5-8GB-HS-T died
#   extracting registryconfig.7z with an opaque E_FAIL: a windowless background
#   SystemSettings.exe held C:\zengar\NO_Desktop_Wallpaper.png, which that
#   archive overwrites. Nothing collected who holds FILES inside the root
#   (ZEN-PROCESS-001 sees only process IMAGES there). New ZEN-FILELOCK-001 asks
#   the Restart Manager (query only) for holders of every file under C:\zengar
#   (deny-list pruned) and whether each held file can still be renamed.
# 1.10.0 (2026-10-27): two Surface Pro 9s lost BOTH USB-C ports after the 26H2
#   feature update — no device enumerated, USB-C charging stopped, Surface Connect
#   still charged, controllers showed no error, and an OS rollback did not help (it
#   does not revert firmware). Nothing in the bundle could show that nothing was
#   enumerating or what firmware had just been flashed. New WIN-USB-001 (any model):
#   platform, UEFI ESRT firmware versions + last update attempt, USB host/connector
#   state, every USB device node with last arrival/removal and built-in flag, power
#   source, firmware/feature-update history, USB warnings/errors.
# 1.11.0 (2026-10-27): WIN-USB-001 gains uncleanRestarts[] (Kernel-Power 41 event
#   data: bugcheck, long power-button press, press time). The dead-port remediation
#   starts with a forced restart, and no bundle could confirm a tech had done one:
#   WIN-EVENTS-001 clips the message text, which cannot tell a held power button
#   from a crash.
$script:SupportBundleProbeVersion = '1.11.0'
$script:SupportBundleToolId       = 'support-bundle-collect'

$script:ZengarRootDefault = 'C:\zengar'
$script:ZengarDenyList    = @('sessions', 'BLT_data')        # HARD deny — §6 (clinical data)

# FI-001: components stage into C:\ProgramData\<AnyName>\ and the uninstaller does
# not clean them. Folder names are NOT uniformly '*_Installer' (observed in the
# field: 'NO WebView2 Runtime', 'NeurOptimal', 'RepoTool', 'NODatabaseBackup') —
# the only reliable marker is an installerResources\com.zengar.* child.
$script:StagingRootDefault     = $(if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' })
$script:StagingComponentPrefix = 'com.zengar.'

# FI-008: NO.exe hosts its visualizer in a WebView2 loaded from a FIXED-VERSION
# runtime staged under ProgramData — NOT the machine-wide Evergreen runtime.
# Evergreen msedgewebview2 processes exist on every Win11 box (SearchHost, Teams,
# Outlook, Copilot) and are pure noise; only this tree matters to NO.exe.
# If these binaries are gone the visualizer pane renders blank while the rest of
# the app works perfectly — and components.xml still reports the component
# installed, so nothing else in the bundle contradicts it.
$script:WebView2RuntimeDirName = 'NO WebView2 Runtime'
$script:WebView2KeyBinaries    = @(
    'libs\x64\WebView2Loader.dll',                          # loaded by NO.exe itself
    'runtime\x64\EBWebView\x64\EmbeddedBrowserWebView.dll',  # loaded by NO.exe itself
    'runtime\x64\msedgewebview2.exe'                         # the browser process
)
# Some components never install into C:\zengar at all: their QtIFW 'Execute'
# operation shells out to a third-party installer that writes elsewhere. G-Force
# is the observed case — QtIFW runs
#   cmd /c <staging>\G-Force_NeurOptimal.exe /LICENSECODE=<code> /S
# and that child performs an ONLINE license check before writing anything. Where
# the check cannot reach SoundSpectrum the child aborts (exit 2); if anyone then
# clicks Ignore, QtIFW records the component installed regardless. The result is a
# components.xml entry for a product that is not on disk, and NOTHING else in the
# bundle contradicts it (INST013255 + LDANDREA_01, 2026-07-28 — six bundles across
# two boxes all agreed with the false record).
#
# installerResources\<component>\*.txt cannot close this gap: for these components
# it lists the STAGED payload (@RELOCATABLE_PATH@ = the ProgramData staging dir),
# which is present precisely when the real install failed.
#
# So the check is table-driven, exactly like ZEN-WEBVIEW2-001's key-binary list.
# Admission criterion (§5): add an entry only for a component we have actually
# watched install out-of-root, and record the evidence. No install path is
# hardcoded — InstallLocation is read from the product's own uninstall entry.
$script:ExternalComponentTargets = @(
    @{
        ComponentId = 'com.zengar.no.gforce'
        DisplayName = 'G-Force for NeurOptimal'   # Uninstall entry DisplayName (32-bit view)
        Evidence    = 'INST013255 2026-07-28: components.xml recorded 5.8.1.5 installed while Program Files held nothing'
    }
)
# HKLM Uninstall is world-readable, so both views resolve unelevated.
$script:UninstallRegPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

$script:ZampLoaderRelDir  = 'zAmpLoader\driver'
$script:ZengarLeafThumb   = 'E2DF802CEF9C3C3EE6DCF4842812DB03E0E5C00F'
$script:SectigoE46Thumb   = 'BBEF5C4C11489770F586FB307D143291307F119A'
$script:ZampVidMatch      = '*VID_1167*'

# Mined from App.ps1:2594-2615 — do not invent new endpoints, add them here
$script:SupportDomains    = @('zengar.com', 'neuroptimal.com', 'noreleases.neuroptimal.com',
                              'connectwise.com', 'screenconnect.com', 'zengarinst.beyondtrustcloud.com')
$script:BltLicensingHost  = 'blt-server.neuroptimal.com'
$script:BltLicensingPorts = @(7000, 7001, 7002)   # CRITICAL for licensing
$script:TrustFetchHosts   = @('ctldl.windowsupdate.com', 'crt.sectigo.com')  # KI-001

# FI-022: live state of the running app and its local database. NO.exe keeps a
# connection to the bundled MySQL server on loopback; the service installs as
# 'MySQL56' (5.6.19) OUTSIDE C:\zengar, so ZEN-PROCESS-001 never sees it.
$script:NoProcessName      = 'NO'
$script:DbServiceNameLike  = 'MySQL%'   # WQL LIKE pattern
$script:DbPort             = 3306
$script:LiveSampleSeconds  = 5          # two samples this far apart give a CPU delta

# FI-004 (2026-07-22): NO 4.x drives the zAmp through WinUSB + NI-VISA, and
# ZEN-ZAMP-001 inspects zAmpLoader\driver — a directory that does not exist on
# a healthy 4.x box. These are the load-bearing VISA DLLs NO.exe loads from
# System32; their presence/versions are the 4.x amp-stack facts.
$script:VisaSystemDlls = @('nivisa64.dll', 'NiViSv64.dll', 'visa64.dll', 'visaUtilities.dll', 'visaConfMgr.dll')

# FI-012 (2026-08-21, measured on SP6): NO reaches the Arc's COM ports THROUGH
# NI-VISA, not a raw Win32 serial open — NO.exe carries nivisa64.dll and the
# NiViAsrl.dll serial passport, and LabVIEW's serial VIs are VISA. So
# visaconf.ini holds a THIRD COM identity table, independent of both Windows
# SERIALCOMM/PnP and NO's own 'NO Device Manager.config', and nothing collected
# it. On SP6 that table was STALE (9 ASRL resources persisting while the box
# had ZERO COM ports, empty SERIALCOMM, every BTHENUM node Present=False) and
# self-inconsistent: ASRL11::INSTR and ASRL3::INSTR BOTH mapped to COM3, and
# the ASRL number is not the COM number. FI-012 is a COM-IDENTITY fault, so a
# duplicate mapping sitting in the layer NO addresses ports through belongs in
# the bundle. It also explains a gap in the remedies: a COM-arbiter reset or
# BTHENUM ghost removal cleans the Windows layer and leaves this one untouched.
#
# ⚠️ MECHANISM HYPOTHESIS, NOT A MEASURED FAULT. No capture yet shows the
# duplicate causing a failure. This collector exists to make it testable and
# must report only what the file says — never a verdict that it caused anything.
# ⛔ READ ONLY. Never write visaconf.ini: it is on the path NO uses to reach the
# Arc, and repairing it blind is a write to the command channel in all but name.
$script:VisaConfIniPath = Join-Path $env:ProgramData 'National Instruments\NIvisa\visaconf.ini'
$script:NiVisaRegPaths = @(
    @{ view = '64-bit'; path = 'HKLM:\SOFTWARE\National Instruments\NI-VISA' }
    @{ view = '32-bit'; path = 'HKLM:\SOFTWARE\WOW6432Node\National Instruments\NI-VISA' }
)
$script:NiServiceNames = @('niauth', 'NIDomainService', 'NiSvcLoc', 'nimDNSResponder', 'niLXIDiscovery')

# MsiInstaller 1918 field lesson: ODBC "driver could not be loaded" events were
# falsely escalated; the documented triage move is checking the CURRENT ODBC
# registration, both registry views. HKLM ODBCINST.INI is world-readable.
$script:OdbcInstRegPaths = @(
    @{ view = '64-bit'; path = 'HKLM:\SOFTWARE\ODBC\ODBCINST.INI' }
    @{ view = '32-bit'; path = 'HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI' }
)

# FI-016: NI Package Manager's feed list is GLOBAL state that lives outside
# C:\zengar, so wiping the install root does not clear it. The lvrte/nivisa
# components run `nipkg feed-add` unconditionally; a surviving feed of the same
# name makes that fail (-125006) and blocks the whole install behind a dialog.
$script:NipkgPath = Join-Path $env:ProgramFiles 'National Instruments\NI Package Manager\nipkg.exe'

# WIN-USB-001 (SP9 USB-C field reports, 2026-10-27). Providers that write USB
# warnings/errors to the System log; UCMUCSICX writes only to its own Operational
# log, which was EMPTY on two healthy Surfaces, so it is not read. The title match
# selects the update-history rows that can change what sits under the ports:
# firmware (OEM capsules are titled '<Vendor> - Firmware - <ver>' or, on Surface,
# 'Surface Firmware Driver Update'), Surface drivers, and feature updates.
$script:UsbEventProviders = @(
    'Microsoft-Windows-USB-USBHUB3', 'Microsoft-Windows-USB-USBXHCI', 'Microsoft-Windows-USB-USB4DeviceRouter-EventLogs',
    'Microsoft-Windows-USB-USBHUB', 'Microsoft-Windows-USB-USBPORT', 'usbehci'
)
$script:UpdateHistoryTitleMatch = 'Firmware|BIOS|UEFI|Surface|Thunderbolt|USB|Windows 1[01], version|Feature update'

# Caps (size target for the whole bundle: < 10 MB — §7)
$script:InstallLogTailLines  = 2000
$script:SetupApiTailLines    = 3000
$script:EventSliceMax        = 250
$script:TreeListingMaxItems  = 5000
$script:BinarySigMaxFiles    = 400
$script:FileLockMaxFiles     = 5000
$script:StagingMaxDirs       = 200
$script:WebView2MaxSiblings  = 20
$script:UsbDeviceMax         = 150
$script:UpdateHistoryScanMax = 1000
$script:UpdateHistoryMax     = 60
$script:UsbEventMax          = 100
$script:UsbEventWindowDays   = 30
$script:RestartEventMax      = 20
$script:DefaultCollectorTimeoutSeconds = 45

# Repo URL is parsed at runtime from maintenancetool.ini DefaultRepositories.
# Do NOT hardcode it — it may differ per client.

# =============================================================================
# CASE ID (§12.5) — becomes an R2 object-key path segment; sanitize hard
# =============================================================================
function ConvertTo-WinConfigSupportCaseId {
    <#
    .SYNOPSIS
        Sanitizes an operator-entered case ID for use as an R2 object-key segment.
    .DESCRIPTION
        Strips path separators, '..', control characters; collapses whitespace to '-';
        caps at 64 chars. Empty (before or after sanitization) falls back to
        <hostname>-<yyyyMMdd> so a key is ALWAYS produced (§12.5).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$CaseId
    )

    $fallback = "$($env:COMPUTERNAME)-$([datetime]::Now.ToString('yyyyMMdd'))"

    if ([string]::IsNullOrWhiteSpace($CaseId)) { return $fallback }

    $clean = $CaseId
    $clean = $clean -replace '\.\.', ''            # no traversal
    $clean = $clean -replace '[\\/]', ''           # no path separators
    $clean = $clean -replace '[\x00-\x1f\x7f]', '' # no control chars
    $clean = $clean -replace '\s+', '-'            # whitespace runs -> single dash
    $clean = $clean.Trim('-', '.')

    if ([string]::IsNullOrWhiteSpace($clean)) { return $fallback }
    if ($clean.Length -gt 64) { $clean = $clean.Substring(0, 64) }
    return $clean
}

function Get-WinConfigSupportCaseIdPrefill {
    <#
    .SYNOPSIS
        Machine-identifying case ID prefill: <hostname>-<model>-<biosSerial>-<yyyyMMdd>.
    .DESCRIPTION
        Zero-typing escalation: the tech should only have to click Start
        Collection. Model + BIOS serial let support staff map the bundle to a
        customer system without a follow-up question (a DESKTOP-xxxx hostname
        alone cannot). OEM placeholder values ("To be filled by O.E.M.",
        "System Product Name", ...) are dropped rather than shipped. Segments
        are capped so the trailing date always survives the sanitizer's 64-char
        cap: hostname(<=15) + model(<=16) + serial(<=20) + date(8) + dashes = 62.
    .OUTPUTS
        Sanitized case ID string (via ConvertTo-WinConfigSupportCaseId).
    #>
    [CmdletBinding()]
    param(
        # Test injection points — production callers pass nothing
        [AllowEmptyString()][string]$Model,
        [AllowEmptyString()][string]$BiosSerial,
        [string]$Stamp
    )

    if (-not $PSBoundParameters.ContainsKey('Model')) {
        try { $Model = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Model } catch { $Model = '' }
    }
    if (-not $PSBoundParameters.ContainsKey('BiosSerial')) {
        try { $BiosSerial = [string](Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber } catch { $BiosSerial = '' }
    }
    if (-not $Stamp) { $Stamp = [datetime]::Now.ToString('yyyyMMdd') }

    # OEM placeholder junk — worse than absent
    $junk = 'To be filled|System Product|System Serial|Default string|O\.E\.M\.|^Unknown$|^None$|^INVALID$|^\s*$'
    if ($Model -match $junk)      { $Model = '' }
    if ($BiosSerial -match $junk) { $BiosSerial = '' }

    $Model = $Model -replace '[^A-Za-z0-9]', ''            # "Surface Pro 6" -> SurfacePro6
    if ($Model.Length -gt 16) { $Model = $Model.Substring(0, 16) }
    $BiosSerial = $BiosSerial -replace '[^A-Za-z0-9-]', ''
    if ($BiosSerial.Length -gt 20) { $BiosSerial = $BiosSerial.Substring(0, 20) }

    $raw = (@($env:COMPUTERNAME, $Model, $BiosSerial, $Stamp) | Where-Object { $_ }) -join '-'
    return ConvertTo-WinConfigSupportCaseId -CaseId $raw
}

# =============================================================================
# DENY-LIST (§6) — central path filter; a carelessly-added collector cannot
# reach clinical data because every file copy funnels through here
# =============================================================================
function Test-WinConfigSupportPathAllowed {
    <#
    .SYNOPSIS
        Returns $false for any path under the hard deny-list (sessions, BLT_data).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$ZengarRoot = $script:ZengarRootDefault
    )

    $full = try { [System.IO.Path]::GetFullPath($Path) } catch { $Path }
    foreach ($deny in $script:ZengarDenyList) {
        $denyRoot = [System.IO.Path]::GetFullPath((Join-Path $ZengarRoot $deny))
        if ($full.TrimEnd('\') -eq $denyRoot.TrimEnd('\')) { return $false }
        if ($full -like "$($denyRoot.TrimEnd('\'))\*") { return $false }
    }
    return $true
}

# =============================================================================
# FILE ADDER (§3.2, §6) — the single choke point for raw file artifacts:
# deny-list enforcement, tail caps with explicit truncation markers, redaction
# =============================================================================
function Add-WinConfigSupportBundleFile {
    <#
    .SYNOPSIS
        Copies a raw file into the bundle's files/ folder with deny-list
        enforcement, optional tail cap (explicit truncation marker), and
        optional named redaction transform.
    .OUTPUTS
        Hashtable: Added, TargetName, Reason (when not added),
                   Truncation (@{ artifact; droppedLines } when trimmed)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RunFolder,
        [Parameter(Mandatory)] [string]$SourcePath,
        [Parameter(Mandatory)] [string]$TargetName,

        [int]$TailLines = 0,

        # Named transforms only — collectors cannot inject arbitrary scriptblocks
        [ValidateSet('None', 'RedactNetworkXml', 'RedactInstallationLog')]
        [string]$Transform = 'None',

        [string]$ZengarRoot = $script:ZengarRootDefault
    )

    $result = @{ Added = $false; TargetName = $TargetName; Reason = $null; Truncation = $null }

    if (-not (Test-WinConfigSupportPathAllowed -Path $SourcePath -ZengarRoot $ZengarRoot)) {
        $result.Reason = "Denied: path is on the hard deny-list"
        return $result
    }
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        $result.Reason = "Source not found: $SourcePath"
        return $result
    }

    $filesDir = Join-Path $RunFolder 'files'
    if (-not (Test-Path $filesDir)) { New-Item -ItemType Directory -Path $filesDir -Force | Out-Null }
    # Target name is a leaf name only — never a path
    $safeName = Split-Path $TargetName -Leaf
    $target   = Join-Path $filesDir $safeName
    $result.TargetName = $safeName

    if ($Transform -eq 'RedactNetworkXml') {
        # Blank credential elements before the file enters the bundle (§6)
        $xmlText = Get-Content -LiteralPath $SourcePath -Raw
        $xmlText = $xmlText -replace '(<Username>)[^<]*(</Username>)', '${1}<redacted>${2}'
        $xmlText = $xmlText -replace '(<Password>)[^<]*(</Password>)', '${1}<redacted>${2}'
        $xmlText | Out-File -FilePath $target -Encoding UTF8 -Force
        $result.Added = $true
        return $result
    }

    # FI-007: the QtIFW installer echoes the MySQL configuration argv into
    # InstallationLog.txt, password included, on every install. Redact the
    # VALUES only — the surrounding lines are diagnostically load-bearing
    # (FI-001 and FI-002 were both root-caused from this log). Values stop at
    # ';' because the MySQL config argv uses ';' as its own separator, so the
    # tokens after it (autostart, ports) stay readable. Composes with the tail
    # cap below, unlike RedactNetworkXml which never tails.
    # FI-011: a failed component Execute (seen: com.zengar.no.gforce, exit
    # code 2) makes QtIFW log the full child argv — including the customer's
    # /LICENSECODE= value. Same value-only strategy: the command line and the
    # /S flag after it stay readable.
    # FI-017: the SAME MySQL root password also reaches this log through a
    # SECOND syntax the key=value pattern above cannot see — the mysql/mysqldump
    # client's attached '-p<value>' argv form, emitted by the backup and restore
    # Execute operations on com.zengar.no.mysql.server. MCAJOLAIS_05 2026-08-11
    # shipped 'passwd=<redacted>' and '-p<cleartext>' on adjacent lines of one
    # bundle. FI-007's residual-risk note reserved exactly this case ("add to the
    # pattern if one ever is [observed]"); one now has been.
    # Anchored on a mysql* token within the same line so a bare '-p' in some
    # other tool's argv is never touched, and value-only so the '-u root' and
    # '--all-databases' context a reader needs stays intact. The space-separated
    # form ('-p secret') is deliberately NOT matched: to the mysql clients that
    # spelling means "prompt me", so the following token is an argument, not a
    # secret, and eating it would corrupt the line for no gain.
    $lines = $null
    if ($Transform -eq 'RedactInstallationLog') {
        $lines = @(Get-Content -LiteralPath $SourcePath -ErrorAction Stop) -replace `
            '(?i)((?:passwd|password)\s*=\s*)(?:"[^"]*"|''[^'']*''|[^;\s"'']+)', '$1<redacted>' -replace `
            '(?i)(licensecode\s*=\s*)(?:"[^"]*"|''[^'']*''|[^;\s"'']+)', '$1<redacted>' -replace `
            '(?i)((?:mysql|mysqldump|mysqladmin)(?:\.exe)?\b[^\r\n]{0,400}?[\s,]-p)(?:"[^"]*"|''[^'']*''|[^\s,;"'']+)', '$1<redacted>'
    }

    if ($TailLines -gt 0) {
        $all = if ($null -ne $lines) { $lines } else { @(Get-Content -LiteralPath $SourcePath -ErrorAction Stop) }
        if ($all.Count -gt $TailLines) {
            $dropped = $all.Count - $TailLines
            $kept = $all[$dropped..($all.Count - 1)]
            # Explicit marker at both ends of the story: what was kept, what was dropped
            $body = @("[Support bundle tail: kept last $TailLines of $($all.Count) lines]") + $kept + @("...truncated ($dropped more lines)")
            $body | Out-File -FilePath $target -Encoding UTF8 -Force
            $result.Added = $true
            $result.Truncation = @{ artifact = $safeName; droppedLines = $dropped }
            return $result
        }
    }

    if ($null -ne $lines) {
        $lines | Out-File -FilePath $target -Encoding UTF8 -Force
        $result.Added = $true
        return $result
    }

    Copy-Item -LiteralPath $SourcePath -Destination $target -Force
    $result.Added = $true
    return $result
}

# =============================================================================
# QT INI HELPERS — shared by the repository/variables parsers
# =============================================================================
function ConvertFrom-QtIniEscapes {
    <#
    .SYNOPSIS
        Unescapes Qt QSettings INI escaping (\xHH, \0, \', \", ...) to raw chars.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Text)

    $sb = New-Object System.Text.StringBuilder
    $j = 0
    while ($j -lt $Text.Length) {
        $ch = $Text[$j]
        if ($ch -ne '\') { [void]$sb.Append($ch); $j++; continue }
        $j++
        if ($j -ge $Text.Length) { break }
        $e = $Text[$j]
        if ($e -eq 'x') {
            $hex = ''
            $j++
            while ($j -lt $Text.Length -and $Text[$j] -match '[0-9a-fA-F]' -and $hex.Length -lt 2) {
                $hex += $Text[$j]; $j++
            }
            if ($hex) { [void]$sb.Append([char][Convert]::ToInt32($hex, 16)) }
        } elseif ($e -eq '0') {
            [void]$sb.Append([char]0); $j++
        } else {
            [void]$sb.Append($e); $j++
        }
    }
    return $sb.ToString()
}

function Get-QtVariantStringValue {
    <#
    .SYNOPSIS
        Extracts one QString value by key from an unescaped Qt QDataStream blob
        (QHash<QString,QVariant> layout: [len][key UTF-16BE][variant header][len][value UTF-16BE]).
    .DESCRIPTION
        The key search is anchored by the key's own 4-byte big-endian QString
        byte-length prefix, so a key name cannot match inside a longer key
        (e.g. 'TargetDir' inside 'RemoveTargetDir'). Returns $null when the key
        is absent or the value does not decode as a plausible string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Unescaped,
        [Parameter(Mandatory)] [string]$Key
    )

    # Key as length-prefixed UTF-16BE: 4-byte BE byte count, then \0<char> pairs
    $byteLen = 2 * $Key.Length
    $needle = [string][char](($byteLen -shr 24) -band 0xFF) +
              [string][char](($byteLen -shr 16) -band 0xFF) +
              [string][char](($byteLen -shr 8) -band 0xFF) +
              [string][char]($byteLen -band 0xFF) +
              (-join ($Key.ToCharArray() | ForEach-Object { "$([char]0)$_" }))

    $idx = $Unescaped.IndexOf($needle)
    if ($idx -lt 0) { return $null }

    # After the key comes a QVariant type header, then the QString value:
    # 4-byte BE byte count + UTF-16BE data. The header width varies with the
    # Qt/QDataStream version (observed 4 bytes on a real QtIFW 4.x box; classic
    # Qt5 format is 4-byte type + 1-byte isNull = 5). Try both; accept the one
    # that yields a sane length and a printable decode.
    foreach ($headerLen in 4, 5) {
        $p = $idx + $needle.Length + $headerLen
        if ($p + 4 -gt $Unescaped.Length) { continue }
        $n = ([int][char]$Unescaped[$p] -shl 24) -bor ([int][char]$Unescaped[$p + 1] -shl 16) -bor
             ([int][char]$Unescaped[$p + 2] -shl 8) -bor ([int][char]$Unescaped[$p + 3])
        $p += 4
        if ($n -le 0 -or ($n % 2) -ne 0 -or $n -gt 4096 -or ($p + $n) -gt $Unescaped.Length) { continue }

        $chars = for ($i = 0; $i -lt $n; $i += 2) {
            [char](([int][char]$Unescaped[$p + $i] -shl 8) -bor [int][char]$Unescaped[$p + $i + 1])
        }
        $value = -join $chars
        if ($value -match '^[\x20-\x7e]+$') { return $value }
    }
    return $null
}

# =============================================================================
# REPOSITORY PARSER (§6) — maintenancetool.ini is NEVER copied verbatim.
# WHITELIST emission: even if parsing misidentifies fields, nothing beyond the
# repo URL and username can leave this function. Password is always '<redacted>'.
# =============================================================================
function Get-WinConfigSupportRepositoryInfo {
    <#
    .SYNOPSIS
        Parses whitelisted fields from maintenancetool.ini: ProductVersion,
        FrameworkVersion, InstallerFilePath, TargetDir, and the update
        repository URL + username from the DefaultRepositories Qt @Variant blob.
    .DESCRIPTION
        The blob is a Qt-escaped QDataStream serialization of
        QInstaller::Repository. String fields appear as base64 runs in the order
        url, username, password, display name. Strategy:
          1. Unescape Qt INI escapes (\xHH, \0, \', \") to raw characters
          2. Extract base64-charset runs; length-prefix bytes can glue onto a
             run, so try trimming 0-3 leading chars until a clean decode
          3. URL = first run decoding to ^https?://  (userinfo stripped if present)
          4. Username = the run immediately after the URL run, only if it looks
             like an account name. NO OTHER DECODED RUN IS EVER EMITTED.
    .OUTPUTS
        Hashtable: Present, ProductVersion, FrameworkVersion, InstallerFilePath,
        TargetDir, RepositoryUrl, RepositoryUsername, RepositoryPassword ('<redacted>'),
        ParseStatus
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IniPath
    )

    $info = @{
        Present            = $false
        ProductVersion     = $null
        FrameworkVersion   = $null
        InstallerFilePath  = $null
        TargetDir          = $null
        RepositoryUrl      = $null
        RepositoryUsername = $null
        RepositoryPassword = '<redacted>'
        Repositories       = @()
        ParseStatus        = 'IniNotFound'
    }

    if (-not (Test-Path -LiteralPath $IniPath)) { return $info }
    $info.Present = $true
    $info.ParseStatus = 'Parsed'

    $lines = Get-Content -LiteralPath $IniPath -ErrorAction Stop

    # Simple whitelisted scalar keys (plain key=value form; some installer
    # versions write these as top-level keys)
    foreach ($line in $lines) {
        if ($line -match '^\s*ProductVersion\s*=\s*(.+)$')    { $info.ProductVersion    = $Matches[1].Trim() }
        elseif ($line -match '^\s*FrameworkVersion\s*=\s*(.+)$')  { $info.FrameworkVersion  = $Matches[1].Trim() }
        elseif ($line -match '^\s*InstallerFilePath\s*=\s*(.+)$') { $info.InstallerFilePath = $Matches[1].Trim() }
        elseif ($line -match '^\s*TargetDir\s*=\s*(.+)$')         { $info.TargetDir         = $Matches[1].Trim() }
    }

    # On real boxes these live inside the Variables Qt @Variant blob instead
    # (QHash<QString,QVariant>, strings UTF-16BE). Decode ONLY whitelisted keys,
    # anchored by each key's QString length prefix so e.g. 'TargetDir' cannot
    # match inside 'RemoveTargetDir'.
    $variablesLine = ($lines | Where-Object { $_ -match '^\s*Variables\s*=' }) -join ''
    if ($variablesLine) {
        $unescapedVars = ConvertFrom-QtIniEscapes -Text $variablesLine
        foreach ($pair in @(
            @{ Key = 'ProductVersion';    Prop = 'ProductVersion' },
            @{ Key = 'FrameworkVersion';  Prop = 'FrameworkVersion' },
            @{ Key = 'InstallerFilePath'; Prop = 'InstallerFilePath' },
            @{ Key = 'TargetDir';         Prop = 'TargetDir' }
        )) {
            if ($null -eq $info[$pair.Prop]) {
                $value = Get-QtVariantStringValue -Unescaped $unescapedVars -Key $pair.Key
                if ($value) { $info[$pair.Prop] = $value }
            }
        }
    }

    # DefaultRepositories blob (may wrap; QSettings keeps it on one line)
    $repoLine = ($lines | Where-Object { $_ -match 'DefaultRepositories' }) -join ''
    if (-not $repoLine) {
        $info.ParseStatus = 'NoRepositoriesKey'
        return $info
    }

    # --- 1. Unescape Qt INI escaping to raw chars ---
    $unescaped = ConvertFrom-QtIniEscapes -Text $repoLine

    # --- 2./3./4. Base64 runs with offset-trim fallback ---
    $decoded = @()   # ordered list of @{ Index; Value }
    $runs = [regex]::Matches($unescaped, '[A-Za-z0-9+/]{8,}={0,2}')
    foreach ($run in $runs) {
        $value = $null
        for ($off = 0; $off -lt 4; $off++) {
            if ($off -ge $run.Value.Length) { break }
            $candidate = $run.Value.Substring($off)
            if ($candidate.Length -lt 8 -or ($candidate.Length % 4) -ne 0) { continue }
            try {
                $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($candidate))
                if ($text -match '^[\x20-\x7e]+$') { $value = $text; break }
            } catch { }
        }
        if ($null -ne $value) { $decoded += ,@{ Index = $decoded.Count; Value = $value } }
    }

    # EVERY repository, not just the first. A box can carry several lines
    # (dev / staging / released are separate environments and the set follows
    # whichever installer was run). Reporting only the first made a reordered
    # list read as a rewritten one during the 2026-07-22 triage and produced a
    # confident wrong conclusion — see FI-009.
    $urlEntries = @($decoded | Where-Object { $_.Value -match '^https?://' })
    $repositories = @()
    foreach ($entry in $urlEntries) {
        # Strip userinfo if the URL embeds credentials (https://user:pass@host/...)
        $repo = @{ url = ($entry.Value -replace '^(https?://)[^/@]+@', '$1'); username = $null }
        # Username = the very next decoded run, if it looks like an account name.
        # Runs beyond that (password, display name) are NEVER emitted.
        $next = $decoded | Where-Object { $_.Index -eq ($entry.Index + 1) } | Select-Object -First 1
        if ($next -and $next.Value -match '^[A-Za-z0-9._@-]{1,64}$' -and $next.Value -notmatch '^https?://') {
            $repo.username = $next.Value
        }
        $repositories += ,$repo
    }
    $info.Repositories = @($repositories)

    if ($urlEntries.Count -gt 0) {
        # First entry retained under the original names for backward compatibility:
        # existing signatures and the manifest header read these.
        $info.RepositoryUrl      = $repositories[0].url
        $info.RepositoryUsername = $repositories[0].username
    } else {
        $info.ParseStatus = 'RepositoryUrlNotFound'
    }

    return $info
}

# =============================================================================
# ELEVATION
# =============================================================================
function Test-WinConfigSupportElevation {
    [CmdletBinding()]
    param()
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# =============================================================================
# COLLECTOR SET (§5) — each entry: Id, Ring, RequiresAdmin, RequiresZengar,
# TimeoutSeconds, Script (scriptblock taking $Context; runs in its own runspace).
# Collectors return @{ Facts = <hashtable>; Files = @(<file requests>) }.
# File requests are executed by the orchestrator through Add-WinConfigSupportBundleFile
# so the deny-list and truncation rules apply centrally.
# =============================================================================
function Get-WinConfigSupportCollectors {
    [CmdletBinding()]
    param()

    return @(
        # ---------------- Ring 1 — Zengar layer ----------------
        @{
            Id = 'ZEN-INSTALL-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                $xmlPath = Join-Path $Context.ZengarRoot 'components.xml'
                if (-not (Test-Path $xmlPath)) {
                    # Absence is a fact, not a failure (field lesson: partial installs exist)
                    return @{ Facts = @{ present = $false; path = $xmlPath } }
                }
                [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                $packages = @()
                foreach ($pkg in $xml.SelectNodes('//Package')) {
                    $packages += @{
                        name        = "$($pkg.Name)"
                        version     = "$($pkg.Version)"
                        installDate = "$($pkg.InstallDate)"
                    }
                }
                @{
                    Facts = @{ packageCount = $packages.Count; packages = $packages }
                    Files = @(@{ SourcePath = $xmlPath; TargetName = 'components.xml' })
                }
            }
        }
        @{
            # RequiresZengar = $true: without components.xml there is no
            # installed-claim to falsify, so this collector has nothing to say on a
            # wiped box. That is the opposite of ZEN-STAGING-001's FI-005 reasoning
            # and is deliberate -- here the CLAIM is the subject, not the leftovers.
            Id = 'ZEN-EXTCOMPONENT-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # Does a component QtIFW installs OUT OF ROOT actually exist on disk?
                #
                # FACTS ONLY (§3.4): what components.xml claims, what the product's
                # uninstall entry says, and what is on disk. Never a verdict -- the
                # comparison belongs to SIG-ZEN-COMPONENT-PHANTOM. Counts and sizes
                # only; no file names from the product tree enter the bundle.
                $facts = @{}
                $xmlPath = Join-Path $Context.ZengarRoot 'components.xml'
                $facts.componentsXmlPresent = [bool](Test-Path -LiteralPath $xmlPath)

                $claims = @{}
                if ($facts.componentsXmlPresent) {
                    try {
                        [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                        foreach ($pkg in $xml.SelectNodes('//Package')) {
                            $claims["$($pkg.Name)"] = @{
                                version     = "$($pkg.Version)"
                                installDate = "$($pkg.InstallDate)"
                            }
                        }
                    } catch {
                        # A components.xml we cannot parse is a fact, not a collector
                        # failure -- the bundle should still ship everything else.
                        $facts.componentsXmlError = "$($_.Exception.Message)"
                    }
                }

                # Uninstall inventory, both registry views. Only the entries we are
                # asked about are emitted; the full list would bloat the bundle and
                # is none of our business.
                $installed = @{}
                foreach ($root in $Context.UninstallRegPaths) {
                    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                        $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                        if (-not $p -or -not $p.DisplayName) { continue }
                        $name = "$($p.DisplayName)"
                        if (-not $installed.ContainsKey($name)) {
                            $installed[$name] = @{
                                displayVersion  = "$($p.DisplayVersion)"
                                publisher       = "$($p.Publisher)"
                                installLocation = "$($p.InstallLocation)"
                            }
                        }
                    }
                }
                $facts.uninstallEntryCount = $installed.Count

                $checked = [System.Collections.ArrayList]::new()
                foreach ($target in $Context.ExternalComponents) {
                    $entry = @{
                        componentId = "$($target.ComponentId)"
                        displayName = "$($target.DisplayName)"
                        claimed     = [bool]$claims.ContainsKey($target.ComponentId)
                    }
                    if ($entry.claimed) {
                        $entry.claimedVersion     = $claims[$target.ComponentId].version
                        $entry.claimedInstallDate = $claims[$target.ComponentId].installDate
                    }
                    $reg = $installed["$($target.DisplayName)"]
                    $entry.registryPresent = [bool]$reg
                    if ($reg) {
                        $entry.registryVersion  = $reg.displayVersion
                        $entry.publisher        = $reg.publisher
                        $entry.installLocation  = $reg.installLocation
                    }
                    # Disk truth. The path comes from the product's own uninstall
                    # entry, so nothing is hardcoded here -- and when that entry is
                    # missing there is nothing to measure, which is itself the signal.
                    # Guard against a drive root or a one-segment path: a bad
                    # InstallLocation must not turn into a recursive walk of C:\.
                    $dir = "$($entry.installLocation)".TrimEnd('\')
                    if ($dir -and $dir -match '^[A-Za-z]:\\[^\\]+\\[^\\]') {
                        $entry.dirPresent = [bool](Test-Path -LiteralPath $dir)
                        if ($entry.dirPresent) {
                            $files = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue)
                            $entry.fileCount  = $files.Count
                            $entry.totalBytes = [int64](($files | Measure-Object -Property Length -Sum).Sum)
                        }
                    } elseif ($dir) {
                        $entry.installLocationRejected = $true
                    }
                    [void]$checked.Add($entry)
                }
                $facts.checked = @($checked)
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'ZEN-VERSION-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # ProductVersion in maintenancetool.ini reflects the ORIGINAL offline
                # installer, not post-update state. Collect all three identities and
                # let the engineer reconcile (§5 ZEN-VERSION-001).
                $noExe = Join-Path $Context.ZengarRoot 'NO.exe'
                $exeFacts = @{ present = (Test-Path $noExe) }
                if ($exeFacts.present) {
                    $item = Get-Item -LiteralPath $noExe
                    $exeFacts.fileVersion    = "$($item.VersionInfo.FileVersion)"
                    $exeFacts.productVersion = "$($item.VersionInfo.ProductVersion)"
                    $exeFacts.sha256         = (Get-FileHash -LiteralPath $noExe -Algorithm SHA256).Hash
                    $exeFacts.lastWriteTime  = $item.LastWriteTime.ToString('o')
                    $exeFacts.sizeBytes      = $item.Length
                }
                # The maintenancetool BINARY's own version is a third identity to
                # reconcile: the ini ProductVersion is the original offline
                # installer's, and the tool self-updates between releases
                # (a staged maintenancetool.exe.new completes on a later launch).
                $mtExe = Join-Path $Context.ZengarRoot 'maintenancetool.exe'
                $mtFacts = @{ present = (Test-Path $mtExe) }
                if ($mtFacts.present) {
                    $item = Get-Item -LiteralPath $mtExe
                    $mtFacts.fileVersion    = "$($item.VersionInfo.FileVersion)"
                    $mtFacts.productVersion = "$($item.VersionInfo.ProductVersion)"
                    $mtFacts.lastWriteTime  = $item.LastWriteTime.ToString('o')
                    $mtFacts.sizeBytes      = $item.Length
                    # FI-015: when the tool will not start, "is the binary damaged?" has to
                    # be answerable from the bundle. NO.exe already shipped a hash; this did
                    # not, and the gap cost a field round-trip. Authenticode is the fact that
                    # actually settles it — Valid means the bytes are what Zengar signed, so
                    # the fault is state or appended payload, never file damage. (Authenticode
                    # does NOT cover data appended after the signature block, which is exactly
                    # where QtIFW keeps its resource payload — see installerDat below.)
                    $mtFacts.sha256 = (Get-FileHash -LiteralPath $mtExe -Algorithm SHA256).Hash
                    try {
                        $mtFacts.signatureStatus = "$((Get-AuthenticodeSignature -LiteralPath $mtExe -ErrorAction Stop).Status)"
                    } catch {
                        $mtFacts.signatureStatus = "Unavailable: $($_.Exception.Message)"
                    }
                }
                # installer.dat holds QtIFW's binary-layout markers. It is a SEPARATE file
                # that no signature vouches for, so it can be wrong while maintenancetool.exe
                # verifies clean. Metadata only — never contents (§3.4).
                $datPath  = Join-Path $Context.ZengarRoot 'installer.dat'
                $datFacts = @{ present = (Test-Path $datPath) }
                if ($datFacts.present) {
                    $dat = Get-Item -LiteralPath $datPath
                    $datFacts.sizeBytes     = $dat.Length
                    $datFacts.lastWriteTime = $dat.LastWriteTime.ToString('o')
                    $datFacts.sha256        = (Get-FileHash -LiteralPath $datPath -Algorithm SHA256).Hash
                }
                $latestInstall = $null
                $xmlPath = Join-Path $Context.ZengarRoot 'components.xml'
                if (Test-Path $xmlPath) {
                    [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                    $dates = @($xml.SelectNodes('//Package') | ForEach-Object { "$($_.InstallDate)" } | Where-Object { $_ })
                    if ($dates.Count -gt 0) { $latestInstall = ($dates | Sort-Object -Descending | Select-Object -First 1) }
                }
                @{
                    Facts = @{
                        productVersionIni = $Context.Repository.ProductVersion
                        frameworkVersion  = $Context.Repository.FrameworkVersion
                        noExe             = $exeFacts
                        maintenancetool   = $mtFacts
                        installerDat      = $datFacts
                        latestInstallDate = $latestInstall
                    }
                }
            }
        }
        @{
            Id = 'ZEN-INSTALLLOG-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                $logPath = Join-Path $Context.ZengarRoot 'InstallationLog.txt'
                if (-not (Test-Path $logPath)) {
                    # Absence is itself a fact worth shipping (some installs never write
                    # this log) — a healthy box must not score a collector Error for it
                    return @{ Facts = @{ present = $false; path = $logPath } }
                }
                $lineCount = 0
                try { $lineCount = @(Get-Content -LiteralPath $logPath).Count } catch { }
                # FI-018: how OLD the log is, not just how long it is. QtIFW does
                # not flush a run's operations until that run ends, so on a box
                # where the installer is WEDGED the newest line can be many
                # minutes older than collection time -- the only in-bundle signal
                # that an install is stuck rather than working. Explicit $null
                # when unreadable: an unmeasured age must read as unmeasured, never
                # as a timestamp a reader would difference against.
                $lastWrite = $null
                try { $lastWrite = (Get-Item -LiteralPath $logPath -ErrorAction Stop).LastWriteTime.ToString('o') } catch { }
                @{
                    # transform is a fact, not a verdict: it tells the engineer the
                    # shipped file is post-redaction (FI-007), so a '<redacted>'
                    # token in it is our doing, not the installer's.
                    Facts = @{ present = $true; totalLines = $lineCount; lastWriteTime = $lastWrite; tailCap = $Context.Caps.InstallLogTailLines; transform = 'RedactInstallationLog' }
                    Files = @(@{ SourcePath = $logPath; TargetName = 'InstallationLog.txt'; TailLines = $Context.Caps.InstallLogTailLines; Transform = 'RedactInstallationLog' })
                }
            }
        }
        @{
            Id = 'ZEN-REPO-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # Parsed up front by the orchestrator (whitelist emission, §6).
                # URL and username only — password is always '<redacted>'.
                @{
                    Facts = @{
                        parseStatus        = $Context.Repository.ParseStatus
                        repositoryUrl      = $Context.Repository.RepositoryUrl
                        repositoryUsername = $Context.Repository.RepositoryUsername
                        repositoryPassword = '<redacted>'
                        # ALL configured repositories, not just the first (FI-009).
                        # dev/staging/released are separate environments and the set
                        # follows whichever installer was run, so a single value
                        # cannot tell you whether a box's channels are consistent.
                        repositories       = @($Context.Repository.Repositories)
                        repositoryCount    = @($Context.Repository.Repositories).Count
                        installerFilePath  = $Context.Repository.InstallerFilePath
                        targetDir          = $Context.Repository.TargetDir
                    }
                }
            }
        }
        @{
            Id = 'ZEN-NETXML-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                $xmlPath = Join-Path $Context.ZengarRoot 'network.xml'
                if (-not (Test-Path $xmlPath)) {
                    # Absence is a fact, not a failure (confirmed on a media-only install)
                    return @{ Facts = @{ present = $false; path = $xmlPath } }
                }
                $facts = @{ present = $true }
                try {
                    [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                    $proxy = $xml.SelectSingleNode('//ProxyType')
                    if ($proxy) { $facts.proxyType = "$($proxy.InnerText)" }
                    foreach ($node in @('HttpProxyHost', 'HttpProxyPort', 'FtpProxyHost', 'FtpProxyPort')) {
                        $n = $xml.SelectSingleNode("//$node")
                        if ($n) { $facts[$node] = "$($n.InnerText)" }
                    }
                    $repoNodes = $xml.SelectNodes('//Repository')
                    $facts.repositoryElementCount = $repoNodes.Count
                } catch {
                    $facts.parseError = $_.Exception.Message
                }
                @{
                    Facts = $facts
                    Files = @(@{ SourcePath = $xmlPath; TargetName = 'network.xml'; Transform = 'RedactNetworkXml' })
                }
            }
        }
        @{
            Id = 'ZEN-TREE-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # Listing only (path, size, mtime — never contents). Deny-list dirs are
                # PRUNED (never entered), not walked-then-filtered: sessions/ can be huge
                # and its contents must not even be enumerated.
                $denyRoots = @($Context.DenyListAbsolute | ForEach-Object { $_.TrimEnd('\') })
                $entries = [System.Collections.ArrayList]::new()
                $truncated = 0
                $max = $Context.Caps.TreeListingMaxItems
                $stack = New-Object System.Collections.Stack
                $stack.Push($Context.ZengarRoot)
                while ($stack.Count -gt 0) {
                    $dir = $stack.Pop()
                    foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
                        $full = $item.FullName.TrimEnd('\')
                        if ($item.PSIsContainer -and ($denyRoots -contains $full)) { continue }
                        if ($entries.Count -ge $max) { $truncated++; continue }
                        [void]$entries.Add(@{
                            path  = $item.FullName.Substring($Context.ZengarRoot.Length).TrimStart('\')
                            size  = if ($item.PSIsContainer) { $null } else { $item.Length }
                            mtime = $item.LastWriteTime.ToString('o')
                            dir   = [bool]$item.PSIsContainer
                        })
                        if ($item.PSIsContainer) { $stack.Push($item.FullName) }
                    }
                }
                $facts = @{ entryCount = $entries.Count; entries = @($entries) }
                if ($truncated -gt 0) { $facts.truncationMarker = "...truncated ($truncated more entries)" }
                @{ Facts = $facts }
            }
        }
        @{
            # RequiresZengar = $false ON PURPOSE — this collector breaks the Ring-1
            # pattern deliberately (FI-005). Installer rollback wipes C:\zengar, so
            # during the exact failure this exists to diagnose there is often no
            # install left at all. Gating on Zengar would blind it precisely when it
            # matters: all three bundles of the 2026-07-22 escalation were collected
            # with C:\zengar empty or absent while the real evidence sat here.
            Id = 'ZEN-STAGING-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-001: uninstall does not remove C:\ProgramData\<Component>\ staging
                # trees. On reinstall QtIFW renames each pre-existing file aside before
                # overwriting; the rename is denied, the write is then denied, and
                # extraction aborts with an opaque E_FAIL -- component by component,
                # with no path or reason shown to the tech.
                #
                # FACTS ONLY (§3.4): staleness and ACL shape are reported, never judged.
                # Listing only -- names, sizes, mtimes, ACL metadata; never contents.
                $root = $Context.StagingRoot
                $prefix = $Context.StagingPrefix
                $facts = @{ stagingRoot = $root; rootPresent = (Test-Path -LiteralPath $root) }
                if (-not $facts.rootPresent) { return @{ Facts = $facts } }

                $entries = [System.Collections.ArrayList]::new()
                $truncated = 0
                # Cap comes from $Context.Caps, NOT $script: — module scope is not
                # available inside a collector scriptblock, and `$n -ge $null` is TRUE
                # in PowerShell, which silently truncates every entry.
                $max = $Context.Caps.StagingMaxDirs
                foreach ($dir in (Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
                    $irPath = Join-Path $dir.FullName 'installerResources'
                    if (-not (Test-Path -LiteralPath $irPath)) { continue }
                    $components = @(Get-ChildItem -LiteralPath $irPath -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "$prefix*" })
                    # No com.zengar.* child => not ours (e.g. BeyondTrust_Installer, which
                    # is the remote-access path into the box and must never be touched).
                    if ($components.Count -eq 0) { continue }
                    if ($entries.Count -ge $max) { $truncated++; continue }

                    $entry = @{
                        name         = $dir.Name
                        path         = $dir.FullName
                        mtime        = $dir.LastWriteTime.ToString('o')
                        componentIds = @($components | ForEach-Object { $_.Name })
                    }
                    # Newest per-component manifest .txt dates the last time this component
                    # actually completed an install here -- the sharpest staleness signal.
                    $manifests = @(Get-ChildItem -LiteralPath $irPath -File -Recurse -ErrorAction SilentlyContinue)
                    if ($manifests.Count -gt 0) {
                        $entry.manifestNewestMtime = ($manifests | Sort-Object LastWriteTime -Descending |
                            Select-Object -First 1).LastWriteTime.ToString('o')
                    }
                    $children = @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)
                    $entry.childCount = $children.Count
                    $entry.readOnlyChildCount = @($children | Where-Object {
                        $_.Attributes -band [System.IO.FileAttributes]::ReadOnly }).Count
                    try {
                        $acl = Get-Acl -LiteralPath $dir.FullName -ErrorAction Stop
                        $entry.owner        = "$($acl.Owner)"
                        # Inheritance blocked on a ProgramData child is abnormal and is the
                        # shape most likely to deny the installer's rename-aside.
                        $entry.aclProtected = [bool]$acl.AreAccessRulesProtected
                        $entry.aclDenyCount = @($acl.Access | Where-Object {
                            "$($_.AccessControlType)" -eq 'Deny' }).Count
                    } catch {
                        $entry.aclError = $_.Exception.Message
                    }
                    [void]$entries.Add($entry)
                }
                $facts.entries    = @($entries)
                $facts.entryCount = $entries.Count
                if ($truncated -gt 0) { $facts.truncationMarker = "...truncated ($truncated more staging dirs)" }
                @{ Facts = $facts }
            }
        }
        @{
            # RequiresZengar = $false for the same reason as ZEN-STAGING-001 (FI-005):
            # this evidence lives outside C:\zengar, which is exactly what installer
            # rollback wipes. Gating on Zengar would blind it when it matters most.
            Id = 'ZEN-WEBVIEW2-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-008: the fixed-version WebView2 runtime NO.exe actually loads.
                # Known-good shape, measured on MMEVOLD_06 (healthy NO 4.0.0.5):
                #   339 files / ~998.7 MB; msedgewebview2.exe 122.0.2365.92
                # Observed failure: the directory PRESENT but holding 0 files, after the
                # FI-001 staging sweep renamed the real tree to '<name>.bak'. NO.exe then
                # silently gets no WebView2 and the visualizer pane paints blank.
                #
                # FACTS ONLY (§3.4): counts, sizes, versions and sibling names. No verdict
                # about whether the runtime "should" be there. Metadata only, never contents.
                $root = Join-Path $Context.StagingRoot $Context.WebView2DirName
                $facts = @{ runtimeRoot = $root; present = [bool](Test-Path -LiteralPath $root) }

                if ($facts.present) {
                    # mtime of the LIVE root, not just of siblings. On MCAJOLAIS_05 the
                    # gutted directory's mtime matched components.xml to the SECOND, which
                    # is what pinned the emptying to one component batch instead of leaving
                    # it undated and unattributable (FI-015).
                    $facts.mtime = (Get-Item -LiteralPath $root).LastWriteTime.ToString('o')
                    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)
                    $facts.fileCount  = $files.Count
                    $facts.totalBytes = [int64](($files | Measure-Object -Property Length -Sum).Sum)
                    # The three binaries whose absence is the actual failure. Reported
                    # individually so triage says WHICH one is gone, not just "incomplete".
                    $facts.binaries = @($Context.WebView2Binaries | ForEach-Object {
                        $rel  = $_
                        $full = Join-Path $root $rel
                        $b    = @{ rel = $rel; present = [bool](Test-Path -LiteralPath $full) }
                        if ($b.present) {
                            $item = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
                            if ($item) {
                                $b.size    = $item.Length
                                $b.version = "$($item.VersionInfo.ProductVersion)"
                            }
                        }
                        $b
                    })
                }

                # Sibling '<name>.bak' / '.bak.bak' / '.empty' trees. When the live tree is
                # broken, a sibling holding a full copy turns remediation from a reinstall
                # into a rename — so it is worth knowing before anyone re-downloads 1 GB.
                # Cap from $Context.Caps, NOT $script: — module scope is invisible inside a
                # collector scriptblock, and `$n -ge $null` is TRUE in PowerShell.
                $max = $Context.Caps.WebView2MaxSiblings
                $siblings = [System.Collections.ArrayList]::new()
                $truncated = 0
                if (Test-Path -LiteralPath $Context.StagingRoot) {
                    foreach ($dir in (Get-ChildItem -LiteralPath $Context.StagingRoot -Directory -Force -ErrorAction SilentlyContinue |
                                      Where-Object { $_.Name -like "$($Context.WebView2DirName).*" })) {
                        if ($siblings.Count -ge $max) { $truncated++; continue }
                        [void]$siblings.Add(@{
                            name      = $dir.Name
                            mtime     = $dir.LastWriteTime.ToString('o')
                            fileCount = @(Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -Force -ErrorAction SilentlyContinue).Count
                        })
                    }
                }
                $facts.siblings = @($siblings)
                if ($truncated -gt 0) { $facts.truncationMarker = "...truncated ($truncated more sibling dirs)" }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'ZEN-ZAMP-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # Read-only zAmp trust surface — deliberate duplicate of the trust-repair
                # tool's discovery phase (~40 lines); coupling to a twice-hotfixed tool
                # was rejected in the spec (§8). FACTS ONLY: no verdicts, no repair.
                # System.Security is NOT auto-loaded in PS 5.1 (the PR #12 lesson).
                Add-Type -AssemblyName System.Security -ErrorAction Stop
                $dir = $Context.ZampLoaderDir
                $facts = @{ loaderDirPresent = (Test-Path $dir) }
                if ($facts.loaderDirPresent) {
                    $files = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)
                    $facts.files = @($files | ForEach-Object { @{ name = $_.Name; size = $_.Length; mtime = $_.LastWriteTime.ToString('o') } })
                    $signatures = @{}
                    foreach ($file in $files | Where-Object { $_.Extension -in '.cat', '.inf', '.sys', '.dll' }) {
                        $signatures[$file.Name] = $(try { "$((Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop).Status)" } catch { "Error: $($_.Exception.Message)" })
                    }
                    $facts.signatures = $signatures
                    $embedded = @()
                    $leafCert = $null
                    foreach ($cat in $files | Where-Object { $_.Extension -eq '.cat' }) {
                        try {
                            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                            $cms.Decode([System.IO.File]::ReadAllBytes($cat.FullName))
                            foreach ($c in $cms.Certificates) {
                                $role = if ($c.Subject -eq $c.Issuer) { 'Root' } elseif ($c.Subject -like '*Zengar*') { 'Leaf' } else { 'Intermediate' }
                                $embedded += @{ catalog = $cat.Name; role = $role; subject = $c.Subject; thumbprint = $c.Thumbprint; notAfter = $c.NotAfter.ToString('o') }
                                if ($c.Thumbprint -eq $Context.ZengarLeafThumb) { $leafCert = $c }
                            }
                            if (-not $leafCert -and $cms.SignerInfos.Count -gt 0) { $leafCert = $cms.SignerInfos[0].Certificate }
                        } catch {
                            $embedded += @{ catalog = $cat.Name; parseError = $_.Exception.Message }
                        }
                    }
                    $facts.embeddedCerts = $embedded
                    if ($leafCert) {
                        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                        $facts.chainBuilds = $chain.Build($leafCert)
                        $facts.chainStatus = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" })
                    }
                }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'ZEN-BINSIG-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # HS-134: Authenticode status of every binary NO ships, so an unsigned
                # DLL is visible BEFORE Smart App Control / App Control blocks it.
                # Pruned walk: deny-list dirs are never entered. Pruned by NAME at the
                # root as well as by full path — Get-ChildItem returns long-form
                # FullNames, so a root given in 8.3 form ('ZENGAR~1') never matches
                # the joined deny paths (caught by the Pester fixture under %TEMP%).
                # Paths are tracked relative while walking for the same reason.
                # NI's '*-ni.dll' OpenSSL/zlib set lives in System32 but loads into
                # NO.exe (libcrypto-3-ni.dll raised the HS-134 toast), so it is listed too.
                $denyRoots = @($Context.DenyListAbsolute | ForEach-Object { $_.TrimEnd('\') })
                $denyNames = @($Context.DenyListAbsolute | ForEach-Object { Split-Path -Leaf $_.TrimEnd('\') })
                $max = $Context.Caps.BinarySigMaxFiles
                $found = [System.Collections.ArrayList]::new()
                $stack = New-Object System.Collections.Stack
                $stack.Push(@{ path = $Context.ZengarRoot; rel = '' })
                while ($stack.Count -gt 0) {
                    $dir = $stack.Pop()
                    foreach ($item in (Get-ChildItem -LiteralPath $dir.path -Force -ErrorAction SilentlyContinue)) {
                        $rel = if ($dir.rel) { "$($dir.rel)\$($item.Name)" } else { $item.Name }
                        if ($item.PSIsContainer) {
                            $denied = ($denyRoots -contains $item.FullName.TrimEnd('\')) -or (-not $dir.rel -and $denyNames -contains $item.Name)
                            if (-not $denied) { $stack.Push(@{ path = $item.FullName; rel = $rel }) }
                        } elseif ($item.Extension -in '.exe', '.dll') {
                            [void]$found.Add(@{ item = $item; scope = 'zengar'; rel = $rel })
                        }
                    }
                }
                $system32 = if ($Context.System32Dir) { $Context.System32Dir } else { Join-Path $env:SystemRoot 'System32' }
                foreach ($item in @(Get-ChildItem -LiteralPath $system32 -Filter '*-ni.dll' -File -ErrorAction SilentlyContinue)) {
                    [void]$found.Add(@{ item = $item; scope = 'system32-ni' })
                }
                $files = @()
                foreach ($entry in @($found | Select-Object -First $max)) {
                    $item = $entry.item
                    $status = $null
                    $signer = $null
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
                        $status = "$($sig.Status)"
                        if ($sig.SignerCertificate) { $signer = if ($sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $Matches[1].Trim('"') } else { $sig.SignerCertificate.Subject } }
                    } catch { $status = "Error: $($_.Exception.Message)" }
                    $files += @{ path = $(if ($entry.rel) { $entry.rel } else { $item.FullName }); scope = $entry.scope; status = $status; signer = $signer; fileVersion = "$($item.VersionInfo.FileVersion)"; size = $item.Length; mtime = $item.LastWriteTime.ToString('o') }
                }
                $facts = @{ fileCount = $files.Count; files = $files; unsignedCount = @($files | Where-Object { $_.status -ne 'Valid' }).Count }
                if ($found.Count -gt $max) { $facts.truncationMarker = "...truncated ($($found.Count - $max) more binaries)" }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'ZEN-INI-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # NO.ini + splashscreen.ini ship verbatim (LabVIEW config corruption is a
                # live failure class). maintenancetool.ini is NEVER copied — its whitelisted
                # fields ship via ZEN-REPO-001 / ZEN-VERSION-001 (§6).
                # FI-022: on SP7P_I5_8GB_TES splashscreen.ini was an 800 KB NON-TEXT
                # blob — most of the bundle, none of it readable. Binary content is
                # withheld and described instead; a UTF-16 BOM still counts as text.
                $files    = @()
                $withheld = @()
                foreach ($name in @('NO.ini', 'splashscreen.ini')) {
                    $p = Join-Path $Context.ZengarRoot $name
                    if (-not (Test-Path -LiteralPath $p)) { continue }
                    $head = New-Object byte[] 8192
                    $read = 0
                    $fs = [System.IO.File]::OpenRead($p)
                    try { $read = $fs.Read($head, 0, $head.Length) } finally { $fs.Dispose() }
                    $utf16Bom = ($read -ge 2) -and (($head[0] -eq 0xFF -and $head[1] -eq 0xFE) -or ($head[0] -eq 0xFE -and $head[1] -eq 0xFF))
                    $hasNul   = ($read -gt 0) -and ([Array]::IndexOf($head, [byte]0, 0, $read) -ge 0)
                    if ($hasNul -and -not $utf16Bom) {
                        $item = Get-Item -LiteralPath $p
                        $withheld += @{
                            name      = $name
                            reason    = 'binary content'
                            sizeBytes = $item.Length
                            mtime     = $item.LastWriteTime.ToString('o')
                            sha256    = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
                        }
                    } else {
                        $files += @{ SourcePath = $p; TargetName = $name }
                    }
                }
                $facts = @{
                    collected                 = @($files | ForEach-Object { $_.TargetName })
                    withheld                  = @($withheld)
                    maintenancetoolIniPolicy  = 'never-copied-verbatim; whitelisted fields in ZEN-REPO-001'
                }
                @{ Facts = $facts; Files = $files }
            }
        }
        @{
            Id = 'ZEN-REGCONFIG-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # NORegistryConfig.exe --install runs elevated as the FINAL update step;
                # if it failed the app is installed but misconfigured (§5).
                $exeDir = Join-Path $Context.ZengarRoot 'NORegistryConfig'
                $facts = @{ dirPresent = (Test-Path $exeDir) }
                if ($facts.dirPresent) {
                    $facts.files = @(Get-ChildItem -LiteralPath $exeDir -File -ErrorAction SilentlyContinue |
                        ForEach-Object { @{ name = $_.Name; size = $_.Length; mtime = $_.LastWriteTime.ToString('o') } })
                }
                $regFacts = @{}
                foreach ($hivePath in @('HKLM:\SOFTWARE\Zengar', 'HKLM:\SOFTWARE\WOW6432Node\Zengar', 'HKCU:\SOFTWARE\Zengar')) {
                    if (Test-Path $hivePath) {
                        $values = @{}
                        Get-ChildItem -Path $hivePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $key = $_
                            $key.GetValueNames() | ForEach-Object { $values["$($key.Name)\$_"] = "$($key.GetValue($_))" }
                        }
                        $root = Get-Item -Path $hivePath -ErrorAction SilentlyContinue
                        if ($root) { $root.GetValueNames() | ForEach-Object { $values["$($root.Name)\$_"] = "$($root.GetValue($_))" } }
                        $regFacts[$hivePath] = $values
                    } else {
                        $regFacts[$hivePath] = 'absent'
                    }
                }
                $facts.registry = $regFacts
                @{ Facts = $facts }
            }
        }
        @{
            # RequiresZengar = $false deliberately (same reasoning as ZEN-STAGING-001):
            # a service registration survives the install directory being removed, and a
            # service still pointing into a missing root is itself a finding. Gating on
            # Zengar would blind this exactly when it matters.
            Id = 'ZEN-PROCESS-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-013: QtIFW refuses EVERY component operation while any process runs
                # from the installation root ("Critical: Running processes found").
                # zengardriver 2.0.0.0 installs zamp_svc.exe as an always-on service
                # INSIDE C:\zengar\zAmpLoader, so an affected box can never install or
                # update ANY component -- including NO's own update path -- silently and
                # permanently. Four bundles could not see this because nothing collected
                # running processes; it took a hand-run CLI to find.
                #
                # Services are the load-bearing half: Win32_Service.PathName is readable
                # unelevated, whereas Process.Path is access-denied for other users'
                # processes -- and the blocker runs as SYSTEM.
                $root       = "$($Context.ZengarRoot)".TrimEnd('\')
                $rootPrefix = "$root\"

                $procs      = @()
                $unresolved = 0
                foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
                    $path = $null
                    try { $path = $p.Path } catch { $path = $null }
                    if (-not $path) { $unresolved++; continue }
                    if ($path -like "$rootPrefix*") {
                        $procs += @{ name = "$($p.ProcessName)"; id = $p.Id; path = "$path" }
                    }
                }

                # PathName is a full command line ('"C:\a b\x.exe" -k net'). Take the
                # quoted image when quoted, otherwise everything through the first
                # '.exe' so unquoted paths containing spaces still resolve. Matching the
                # raw string would false-positive on an argument that merely mentions
                # the root.
                $svcs = @()
                foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
                    $raw = "$($s.PathName)"
                    if (-not $raw) { continue }
                    $image = $null
                    if ($raw.StartsWith('"')) {
                        $close = $raw.IndexOf('"', 1)
                        if ($close -gt 1) { $image = $raw.Substring(1, $close - 1) }
                    }
                    if (-not $image) {
                        $idx   = $raw.ToLowerInvariant().IndexOf('.exe')
                        $image = if ($idx -ge 0) { $raw.Substring(0, $idx + 4) } else { $raw }
                    }
                    if ($image -like "$rootPrefix*") {
                        $svcs += @{
                            name        = "$($s.Name)"
                            displayName = "$($s.DisplayName)"
                            state       = "$($s.State)"
                            startMode   = "$($s.StartMode)"
                            imagePath   = "$image"
                            pathName    = $raw
                        }
                    }
                }

                @{ Facts = @{
                    installRoot           = $root
                    processes             = @($procs)
                    processCount          = @($procs).Count
                    services              = @($svcs)
                    serviceCount          = @($svcs).Count
                    processPathUnresolved = $unresolved
                    enumerationLimited    = (-not $Context.Elevated)
                } }
            }
        }
        @{
            Id = 'ZEN-FILELOCK-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # SP9-I5-8GB-HS-T 2026-10-20: the post-26H2 component reinstall died on
                # 'Error while extracting archive ... registryconfig.7z: internal code:
                # E_FAIL'. The archive overwrites C:\zengar\NO_Desktop_Wallpaper.png, and
                # a windowless, suspended SystemSettings.exe (started by DcomLaunch, never
                # opened by the user) held it open, so QtIFW could not rename it aside.
                # ZEN-PROCESS-001 only sees processes whose IMAGE is inside the root; a
                # foreign process holding a FILE inside it was invisible, and the bundle's
                # top finding pointed at the zAmp service instead.
                #
                # Asks the Restart Manager which processes hold any file under the
                # install root. RmGetList is a QUERY; RmShutdown / RmRestart are never
                # referenced, so nothing here closes a handle or a process. Per-file
                # attribution is by bisection: one query for the whole tree (the common
                # case is zero holders), then halves only where something is held.
                # renameBlocked opens each held file for DELETE access with full
                # sharing -- the access QtIFW's rename-aside needs -- and closes it
                # untouched: a sharing violation means some handle lacks FILE_SHARE_DELETE.
                if (-not ('WinConfigSupport.FileLockQuery' -as [type])) {
                    Add-Type -ErrorAction Stop -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinConfigSupport {
    public static class FileLockQuery {
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
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);

        // One row per holder: pid|appName|serviceShortName|applicationType|sessionId.
        // Throws on a Restart Manager error so the caller records it, never as "no holders".
        public static string[] Holders(string[] files) {
            List<string> rows = new List<string>();
            uint handle; System.Text.StringBuilder key = new System.Text.StringBuilder(33);
            int rc = RmStartSession(out handle, 0, key);
            if (rc != 0) { throw new InvalidOperationException("RmStartSession failed: " + rc); }
            try {
                rc = RmRegisterResources(handle, (uint)files.Length, files, 0, IntPtr.Zero, 0, IntPtr.Zero);
                if (rc != 0) { throw new InvalidOperationException("RmRegisterResources failed: " + rc); }
                uint needed = 0, count = 0, reasons = 0;
                rc = RmGetList(handle, out needed, ref count, null, ref reasons);
                if (rc == 234 /* ERROR_MORE_DATA */ && needed > 0) {
                    RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed];
                    count = needed;
                    rc = RmGetList(handle, out needed, ref count, info, ref reasons);
                    if (rc != 0) { throw new InvalidOperationException("RmGetList failed: " + rc); }
                    for (int i = 0; i < count; i++) {
                        rows.Add(info[i].Process.dwProcessId + "|" + info[i].strAppName + "|" + info[i].strServiceShortName + "|" + info[i].ApplicationType + "|" + info[i].TSSessionId);
                    }
                } else if (rc != 0) { throw new InvalidOperationException("RmGetList failed: " + rc); }
            } finally { RmEndSession(handle); }
            return rows.ToArray();
        }

        // true = sharing violation on a DELETE-access open (rename/overwrite blocked);
        // false = opened and closed; null = could not tell (access denied, gone, ...).
        public static bool? RenameBlocked(string path) {
            IntPtr h = CreateFileW(path, 0x00010000 /* DELETE */, 7 /* share read|write|delete */, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0, IntPtr.Zero);
            if (h == new IntPtr(-1)) { return Marshal.GetLastWin32Error() == 32 ? (bool?)true : null; }
            CloseHandle(h);
            return false;
        }
    }
}
"@
                }

                $root      = "$($Context.ZengarRoot)".TrimEnd('\')
                $denyRoots = @($Context.DenyListAbsolute | ForEach-Object { $_.TrimEnd('\') })
                $denyNames = @($Context.DenyListAbsolute | ForEach-Object { Split-Path -Leaf $_.TrimEnd('\') })
                $max       = $Context.Caps.FileLockMaxFiles

                # Same pruned walk as ZEN-BINSIG-001: deny-list dirs are never entered,
                # pruned by name at the root too so an 8.3 root cannot bypass them.
                $found = [System.Collections.ArrayList]::new()
                $stack = New-Object System.Collections.Stack
                $stack.Push(@{ path = $root; rel = '' })
                while ($stack.Count -gt 0) {
                    $dir = $stack.Pop()
                    foreach ($item in (Get-ChildItem -LiteralPath $dir.path -Force -ErrorAction SilentlyContinue)) {
                        $rel = if ($dir.rel) { "$($dir.rel)\$($item.Name)" } else { $item.Name }
                        if ($item.PSIsContainer) {
                            $denied = ($denyRoots -contains $item.FullName.TrimEnd('\')) -or (-not $dir.rel -and $denyNames -contains $item.Name)
                            if (-not $denied) { $stack.Push(@{ path = $item.FullName; rel = $rel }) }
                        } else {
                            [void]$found.Add(@{ full = $item.FullName; rel = $rel })
                        }
                    }
                }
                $checked = @($found | Select-Object -First $max)

                $facts = @{ installRoot = $root; checkedCount = $checked.Count; heldFiles = @(); holders = @(); heldCount = 0 }
                if ($found.Count -gt $max) { $facts.truncationMarker = "...truncated ($($found.Count - $max) more files not checked)" }

                # Bisection: a slice is split only while it has holders, so a tree with
                # nothing held costs one query.
                $held = [System.Collections.ArrayList]::new()
                $work = New-Object System.Collections.Stack
                if ($checked.Count -gt 0) { $work.Push(@($checked)) }
                try {
                    while ($work.Count -gt 0) {
                        $slice = @($work.Pop())
                        $rows = @([WinConfigSupport.FileLockQuery]::Holders([string[]]@($slice | ForEach-Object { $_.full })))
                        if ($rows.Count -eq 0) { continue }
                        if ($slice.Count -eq 1) { [void]$held.Add(@{ entry = $slice[0]; rows = $rows }); continue }
                        $half = [int][Math]::Floor($slice.Count / 2)
                        $work.Push(@($slice[0..($half - 1)]))
                        $work.Push(@($slice[$half..($slice.Count - 1)]))
                    }
                } catch {
                    # Partial attribution is still evidence; the error says it is partial.
                    $facts.restartManagerError = "$($_.Exception.Message)"
                }

                $holders = @{}
                $heldFiles = @()
                foreach ($h in $held) {
                    $pids = @()
                    foreach ($row in $h.rows) {
                        $parts = "$row" -split '\|', 5
                        $holderPid = [int]$parts[0]
                        $pids += $holderPid
                        if (-not $holders.ContainsKey($holderPid)) {
                            $holders[$holderPid] = @{ pid = $holderPid; appName = $parts[1]; serviceShortName = $parts[2]; applicationType = [int]$parts[3]; sessionId = [int]$parts[4] }
                        }
                    }
                    $heldFiles += @{ path = $h.entry.rel; holderPids = @($pids | Sort-Object -Unique); renameBlocked = [WinConfigSupport.FileLockQuery]::RenameBlocked($h.entry.full) }
                }

                # Holder identity. Image paths of other users' processes need elevation;
                # null is recorded, never guessed. hasWindow is only meaningful for a
                # process in the collecting user's session.
                $rootPrefix = "$root\"
                foreach ($holderPid in @($holders.Keys)) {
                    $row = $holders[$holderPid]
                    $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$holderPid" -ErrorAction SilentlyContinue
                    $row.name = if ($cim) { "$($cim.Name)" } else { $null }
                    $row.imagePath = if ($cim -and $cim.ExecutablePath) { "$($cim.ExecutablePath)" } else { $null }
                    # A SYSTEM service's ExecutablePath is unreadable unelevated, but its
                    # Win32_Service.PathName is not (same reasoning as ZEN-PROCESS-001).
                    if (-not $row.imagePath -and $row.serviceShortName) {
                        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($row.serviceShortName -replace "'", '')'" -ErrorAction SilentlyContinue
                        $raw = "$($svc.PathName)"
                        if ($raw.StartsWith('"')) { $close = $raw.IndexOf('"', 1); if ($close -gt 1) { $row.imagePath = $raw.Substring(1, $close - 1) } }
                        elseif ($raw) { $idx = $raw.ToLowerInvariant().IndexOf('.exe'); $row.imagePath = if ($idx -ge 0) { $raw.Substring(0, $idx + 4) } else { $raw } }
                    }
                    $row.startTime = if ($cim -and $cim.CreationDate) { $cim.CreationDate.ToString('o') } else { $null }
                    $row.parentPid = if ($cim) { [int]$cim.ParentProcessId } else { $null }
                    # Only the svchost '-k <group>' is kept from the parent's command
                    # line ('DcomLaunch' = started by COM, not by the user); a full
                    # command line can carry credentials.
                    $row.parentName = $null
                    $row.parentServiceGroup = $null
                    if ($cim) {
                        $parent = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($cim.ParentProcessId)" -ErrorAction SilentlyContinue
                        if ($parent) {
                            $row.parentName = "$($parent.Name)"
                            if ("$($parent.CommandLine)" -match '\s-k\s+(\S+)') { $row.parentServiceGroup = $Matches[1] }
                        }
                    }
                    $row.insideInstallRoot = if ($row.imagePath) { $row.imagePath -like "$rootPrefix*" } else { $null }
                    $proc = Get-Process -Id $holderPid -ErrorAction SilentlyContinue
                    $row.hasWindow = if ($proc) { $proc.MainWindowHandle -ne [IntPtr]::Zero } else { $null }
                }

                $facts.heldFiles = @($heldFiles)
                $facts.heldCount = @($heldFiles).Count
                $facts.holders = @($holders.Values)
                @{ Facts = $facts }
            }
        }
        @{
            # RequiresZengar = $false: the database service lives outside the install
            # root and its state is a fact even when the root is damaged or gone.
            Id = 'ZEN-NOLIVE-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 45
            Script = {
                param($Context)
                # FI-022 (SP7P_I5_8GB_TES, 2026-09-25): NO.exe sat on "Refreshing
                # Licensing Information" through three force-closes and two reboots.
                # The bundle proved DNS/TLS/proxy/licensing ports healthy but could not
                # answer the three questions that mattered: is NO busy or idle, is it
                # talking to any remote host, and is its database up? Answering them
                # took three hand-run rounds and two memory dumps. Two samples a few
                # seconds apart turn "CPU seconds" into "is it doing anything".
                #
                # Facts only. No window titles (a title can carry a client name), no
                # command lines, no process memory. Remote endpoints are server
                # addresses, not client data.
                $sampleSec = [int]$Context.Caps.LiveSampleSeconds
                $licPorts  = @($Context.BltLicensingPorts | ForEach-Object { [int]$_ })
                $dbPort    = [int]$Context.DbPort

                $readProc = {
                    param([int]$ProcId)
                    $p = $null
                    try { $p = Get-Process -Id $ProcId -ErrorAction Stop } catch { return $null }
                    $s = @{ at = (Get-Date).ToString('o') }
                    # Each property can be access-denied on another user's process (MySQL
                    # runs as a service account) — a null is "unreadable", never zero.
                    try { $s.cpuSeconds = [math]::Round($p.TotalProcessorTime.TotalSeconds, 3) } catch { $s.cpuSeconds = $null }
                    try { $s.responding = [bool]$p.Responding } catch { $s.responding = $null }
                    try { $s.threadCount = $p.Threads.Count } catch { $s.threadCount = $null }
                    try { $s.handleCount = $p.HandleCount } catch { $s.handleCount = $null }
                    try { $s.workingSetBytes = $p.WorkingSet64 } catch { $s.workingSetBytes = $null }
                    return $s
                }

                # Get-NetTCPConnection THROWS when a process owns no sockets; that is
                # an empty answer, not an error. Keyed on the category, not the
                # message text, which is localized on non-English boxes.
                $readConns = {
                    param([int]$ProcId, [string]$State)
                    try {
                        if ($State) { return @(Get-NetTCPConnection -OwningProcess $ProcId -State $State -ErrorAction Stop) }
                        return @(Get-NetTCPConnection -OwningProcess $ProcId -ErrorAction Stop)
                    } catch {
                        if ("$($_.CategoryInfo.Category)" -eq 'ObjectNotFound') { return @() }
                        throw
                    }
                }

                $classify = {
                    param($Rows)
                    $ownPorts = @{}
                    foreach ($r in $Rows) { $ownPorts[[int]$r.LocalPort] = $true }
                    $out = @()
                    foreach ($r in $Rows) {
                        $state = "$($r.State)"
                        if ($state -eq 'Bound' -or $state -eq 'Listen') { continue }
                        $remote = "$($r.RemoteAddress)"
                        $rport  = [int]$r.RemotePort
                        $loop   = ($remote -like '127.*') -or ($remote -eq '::1')
                        $peer = if ($loop) {
                            if ($rport -eq $dbPort) { 'database' }
                            elseif ($ownPorts.ContainsKey($rport)) { 'self' }
                            else { 'local-other' }
                        } elseif ($licPorts -contains $rport) { 'licensing-port' } else { 'remote' }
                        $out += @{
                            localPort     = [int]$r.LocalPort
                            remoteAddress = $remote
                            remotePort    = $rport
                            state         = $state
                            kind          = $(if ($loop) { 'loopback' } else { 'remote' })
                            peer          = $peer
                        }
                    }
                    return ,$out
                }

                $facts = @{
                    sampleIntervalSeconds = $sampleSec
                    elevated              = [bool]$Context.Elevated
                    processName           = "$($Context.NoProcessName)"
                    connectionsError      = $null
                }

                # --- sample 1 ---
                $noIds = @(Get-Process -Name $Context.NoProcessName -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
                $dbSvcs = @(Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE '$($Context.DbServiceNameLike)'" -ErrorAction SilentlyContinue)

                $noState = @{}
                foreach ($id in $noIds) {
                    $e = @{ id = $id; samples = @(); connectionSamples = @() }
                    try {
                        $p = Get-Process -Id $id -ErrorAction Stop
                        try { $e.path = "$($p.Path)" } catch { $e.path = $null }
                        try { $e.startTime = $p.StartTime.ToString('o'); $e.uptimeSeconds = [int]((Get-Date) - $p.StartTime).TotalSeconds } catch { $e.startTime = $null }
                    } catch { }
                    $noState[$id] = $e
                }
                $dbState = @()
                foreach ($s in $dbSvcs) {
                    $d = @{
                        name      = "$($s.Name)"
                        state     = "$($s.State)"
                        startMode = "$($s.StartMode)"
                        processId = [int]$s.ProcessId
                        pathName  = "$($s.PathName)"
                        samples   = @()
                    }
                    if ($d.processId -gt 0) {
                        try { $d.startTime = (Get-Process -Id $d.processId -ErrorAction Stop).StartTime.ToString('o') } catch { $d.startTime = $null }
                        try {
                            $d.listenPorts = @(& $readConns $d.processId 'Listen' | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique)
                        } catch { $facts.connectionsError = "$($_.Exception.Message)" }
                    }
                    $dbState += $d
                }

                $takeSample = {
                    foreach ($e in $noState.Values) {
                        $s = & $readProc $e.id
                        if ($s) { $e.samples += $s }
                        try {
                            $rows = & $readConns $e.id ''
                            $e.connectionSamples += @{ at = (Get-Date).ToString('o'); connections = (& $classify $rows) }
                        } catch { $facts.connectionsError = "$($_.Exception.Message)" }
                    }
                    foreach ($d in $dbState) {
                        if ($d.processId -gt 0) { $s = & $readProc $d.processId; if ($s) { $d.samples += $s } }
                    }
                }

                . $takeSample
                if ($sampleSec -gt 0 -and ($noState.Count -gt 0 -or $dbState.Count -gt 0)) {
                    Start-Sleep -Seconds $sampleSec
                    . $takeSample
                }

                # Deltas and summaries: the analyzer should not have to re-derive them
                $delta = {
                    param($Samples)
                    $sm = @($Samples)
                    if ($sm.Count -lt 2) { return $null }
                    $a = $sm[0].cpuSeconds; $b = $sm[$sm.Count - 1].cpuSeconds
                    if ($null -eq $a -or $null -eq $b) { return $null }
                    return [math]::Round($b - $a, 3)
                }
                $noOut = @()
                foreach ($e in $noState.Values) {
                    $e.cpuDeltaSeconds = & $delta $e.samples
                    $all = @($e.connectionSamples | ForEach-Object { $_.connections } | ForEach-Object { $_ })
                    $e.remoteEndpoints   = @($all | Where-Object { $_.kind -eq 'remote' } | ForEach-Object { "$($_.remoteAddress):$($_.remotePort)" } | Sort-Object -Unique)
                    $e.databaseConnected = [bool](@($all | Where-Object { $_.peer -eq 'database' }).Count -gt 0)
                    $noOut += $e
                }
                foreach ($d in $dbState) { $d.cpuDeltaSeconds = & $delta $d.samples }

                $facts.noProcesses       = @($noOut)
                $facts.noProcessCount    = @($noOut).Count
                $facts.databaseServices  = @($dbState)
                $facts.databaseServiceCount = @($dbState).Count
                @{ Facts = $facts }
            }
        }

        # ---------------- Ring 2 — Windows layer ----------------
        @{
            Id = 'WIN-BASE-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
                    ForEach-Object { @{ drive = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1) } })
                @{
                    Facts = @{
                        osCaption   = "$($os.Caption)"
                        osVersion   = "$($os.Version)"
                        osBuild     = "$($os.BuildNumber)"
                        locale      = "$((Get-Culture).Name)"
                        uiLanguage  = "$((Get-UICulture).Name)"
                        lastBoot    = $os.LastBootUpTime.ToString('o')
                        uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
                        timeZone    = "$((Get-TimeZone).Id)"
                        elevated    = $Context.Elevated
                        computer    = $env:COMPUTERNAME
                        userName    = $env:USERNAME
                        psVersion   = "$($PSVersionTable.PSVersion)"
                        volumes     = $volumes   # disk pressure signal — replaces walking sessions/ (§6)
                    }
                }
            }
        }
        @{
            Id = 'WIN-SETUPAPI-001'; Ring = 2; RequiresAdmin = $true; RequiresZengar = $false
            Script = {
                param($Context)
                $logPath = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
                if (-not (Test-Path $logPath)) {
                    # Absence is a fact, not a failure
                    return @{ Facts = @{ present = $false; path = $logPath } }
                }
                $size = (Get-Item -LiteralPath $logPath).Length
                @{
                    Facts = @{ sizeBytes = $size; tailCap = $Context.Caps.SetupApiTailLines }
                    Files = @(@{ SourcePath = $logPath; TargetName = 'setupapi.dev.log.tail'; TailLines = $Context.Caps.SetupApiTailLines })
                }
            }
        }
        @{
            Id = 'WIN-CODEINT-001'; Ring = 2; RequiresAdmin = $true; RequiresZengar = $false
            Script = {
                param($Context)
                # TRIAGE-GUIDE §1: 3077 = App Control deny, 3033 = signing level, 3004 = unsigned
                # HS-134: the message alone cannot say WHICH policy blocked (Smart App
                # Control vs an org App Control policy need different fixes) and its
                # 500-char clip can cut the file path. The event XML carries both.
                $toFact = {
                    param($e)
                    $fact = @{ id = $e.Id; time = $e.TimeCreated.ToString('o'); message = "$($e.Message)".Substring(0, [Math]::Min(500, "$($e.Message)".Length)) }
                    try {
                        $data = @{}
                        foreach ($n in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($n.Name) { $data["$($n.Name)"] = "$($n.'#text')" } }
                        if ($data['FileNameBuffer'])    { $fact.fileName    = $data['FileNameBuffer'] }
                        if ($data['ProcessNameBuffer']) { $fact.processName = $data['ProcessNameBuffer'] }
                        $policyName = if ($data['PolicyNameBuffer']) { $data['PolicyNameBuffer'] } else { $data['PolicyName'] }
                        if ($policyName)          { $fact.policyName = $policyName }
                        if ($data['PolicyGUID'])  { $fact.policyGuid = $data['PolicyGUID'] }
                        if ($data['Status'] -match '^\d+$') { $fact.status = '0x{0:X8}' -f [uint32][int64]$data['Status'] }
                    } catch { }
                    $fact
                }
                $events = @()
                try {
                    $raw = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
                        Id      = @(3077, 3033, 3004)
                    } -MaxEvents $Context.Caps.EventSliceMax -ErrorAction Stop
                    $events = @($raw | ForEach-Object { & $toFact $_ })
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { throw }
                }
                # 3076 = audit-only: the image failed policy but WAS allowed to load. Kept
                # out of `events` (signatures treat those as blocks) and queried separately
                # so an audit flood cannot push real 3077 denies out of the slice.
                $auditEvents = @()
                try {
                    $rawAudit = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
                        Id      = 3076
                    } -MaxEvents $Context.Caps.EventSliceMax -ErrorAction Stop
                    $auditEvents = @($rawAudit | ForEach-Object { & $toFact $_ })
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { throw }
                }
                @{ Facts = @{ eventCount = $events.Count; events = $events; auditEventCount = $auditEvents.Count; auditEvents = $auditEvents; cap = $Context.Caps.EventSliceMax } }
            }
        }
        @{
            Id = 'WIN-CERT-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # KI-001 root-cause surface. chainStatus distinguishes PartialChain
                # (root missing) from UntrustedRoot (present, untrusted) — facts only.
                $leaf = Get-ChildItem 'Cert:\LocalMachine\TrustedPublisher' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $Context.ZengarLeafThumb } | Select-Object -First 1
                $facts = @{
                    zengarLeafInTrustedPublisher = [bool]$leaf
                    sectigoE46InRoot             = [bool](Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue |
                                                       Where-Object { $_.Thumbprint -eq $Context.SectigoE46Thumb })
                    sectigoE46InCA               = [bool](Get-ChildItem 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue |
                                                       Where-Object { $_.Thumbprint -eq $Context.SectigoE46Thumb })
                }
                if ($leaf) {
                    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $facts.chainBuilds = $chain.Build($leaf)
                    $facts.chainStatus = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" })
                }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'WIN-ROOTPOLICY-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # Named in KI-001 as a direct cause of chain-fetch failure. One read.
                $keyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
                $value = $null
                if (Test-Path $keyPath) {
                    $value = (Get-ItemProperty -Path $keyPath -Name DisableRootAutoUpdate -ErrorAction SilentlyContinue).DisableRootAutoUpdate
                }
                @{ Facts = @{ keyPresent = (Test-Path $keyPath); disableRootAutoUpdate = $value } }
            }
        }
        @{
            Id = 'WIN-DRIVERS-001'; Ring = 2; RequiresAdmin = $true; RequiresZengar = $false
            Script = {
                param($Context)
                $enumOutput = & pnputil /enum-drivers 2>&1 | Out-String
                $exit = $LASTEXITCODE
                $devices = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                    Where-Object { $_.InstanceId -like $Context.ZampVidMatch } |
                    ForEach-Object { @{ instanceId = $_.InstanceId; status = "$($_.Status)"; class = "$($_.Class)"; problem = "$($_.Problem)"; friendlyName = "$($_.FriendlyName)" } })
                @{
                    Facts = @{
                        pnputilExitCode = @{ dec = $exit; hex = ('0x{0:X8}' -f $exit) }
                        zampInfMatches  = @([regex]::Matches($enumOutput, '(?im)zamp\S*\.inf') | ForEach-Object { $_.Value } | Select-Object -Unique)
                        stagedDriverCount = @([regex]::Matches($enumOutput, '(?im)^Published Name\s*:')).Count
                        vid1167Devices  = $devices
                    }
                }
            }
        }
        @{
            Id = 'WIN-EVENTS-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # Errors/warnings from the last 48h, capped — crash/install evidence
                $facts = @{}
                foreach ($log in @('Application', 'System')) {
                    $events = @()
                    try {
                        $raw = Get-WinEvent -FilterHashtable @{
                            LogName   = $log
                            Level     = @(1, 2, 3)
                            StartTime = (Get-Date).AddHours(-48)
                        } -MaxEvents $Context.Caps.EventSliceMax -ErrorAction Stop
                        $events = @($raw | ForEach-Object {
                            @{ id = $_.Id; provider = "$($_.ProviderName)"; level = $_.Level; time = $_.TimeCreated.ToString('o')
                               message = "$($_.Message)".Substring(0, [Math]::Min(300, "$($_.Message)".Length)) }
                        })
                    } catch {
                        if ($_.Exception.Message -notmatch 'No events were found') { throw }
                    }
                    $facts[$log] = @{ count = $events.Count; cap = $Context.Caps.EventSliceMax; windowHours = 48; events = $events }
                }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'WIN-WER-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # WER report METADATA for NO.exe only — never dump contents (§5)
                $reports = @()
                # READ-ONLY enumeration of the OS WER store — nothing is written to
                # ProgramData/AppData (zero-footprint contract concerns writes)
                $roots = @(
                    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
                    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
                    "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive",
                    "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue"
                )
                # AppCrash: Sig[3] fault module, Sig[6] exception code, Sig[7] offset.
                # AppHang:  Sig[3] hang signature, Sig[4] hang type.
                $metaKeys = @('AppName', 'AppPath', 'EventType', 'EventTime', 'ReportStatus',
                              'Sig[0].Value', 'Sig[1].Value', 'Sig[2].Value', 'Sig[3].Value', 'Sig[4].Value',
                              'Sig[5].Value', 'Sig[6].Value', 'Sig[7].Value')
                foreach ($root in $roots) {
                    if (-not (Test-Path $root)) { continue }
                    $dirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match 'NO\.exe' -or $_.Name -match '_NO\.exe_' }
                    foreach ($dir in $dirs | Select-Object -First 20) {
                        $wer = Join-Path $dir.FullName 'Report.wer'
                        $meta = @{ reportDir = $dir.Name; mtime = $dir.LastWriteTime.ToString('o') }
                        if (Test-Path $wer) {
                            # Ordinal prefix match, NOT -like: '[0]' in a -like pattern is a
                            # character class, so 'Sig[0].Value=*' never matched a real line
                            # and every bundle before probe 1.7.0 shipped without Sig values.
                            $sigNames = @{}
                            foreach ($line in (Get-Content -LiteralPath $wer -ErrorAction SilentlyContinue)) {
                                foreach ($k in $metaKeys) {
                                    if ($line.StartsWith("$k=", [System.StringComparison]::Ordinal)) { $meta[$k] = $line.Substring($k.Length + 1) }
                                }
                                if ($line -match '^(Sig\[\d+\])\.Name=(.*)$') { $sigNames[$Matches[1]] = $Matches[2] }
                            }
                            # The Sig slots mean different things per EventType — ship their labels
                            if ($sigNames.Count -gt 0) { $meta.sigNames = $sigNames }
                        }
                        $reports += $meta
                    }
                }
                @{ Facts = @{ reportCount = $reports.Count; reports = $reports } }
            }
        }
        @{
            Id = 'WIN-SECURITY-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # Top cause of blocked installs / blocked driver staging (§5)
                $av = @()
                try {
                    $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
                        ForEach-Object { @{ name = "$($_.displayName)"; state = $_.productState; path = "$($_.pathToSignedProductExe)" } })
                } catch { }
                $facts = @{ antivirusProducts = $av }
                try {
                    $mp = Get-MpPreference -ErrorAction Stop
                    $facts.defenderExclusions = @{
                        paths      = @($mp.ExclusionPath)
                        processes  = @($mp.ExclusionProcess)
                        extensions = @($mp.ExclusionExtension)
                    }
                } catch {
                    $facts.defenderExclusions = "Unavailable: $($_.Exception.Message)"
                }
                # HS-134: Smart App Control blocks code it cannot attribute to a
                # publisher (0 = Off, 1 = On/enforcing, 2 = Evaluation). Absent on
                # builds without it; recorded as null, never as Off.
                $sac = $null
                try {
                    $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
                } catch { }
                $facts.smartAppControlState = $sac
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'WIN-PENDING-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # The NO update ends with shutdown.exe /r /t 30 — a machine that never
                # rebooted is half-updated and presents as "the update didn't work" (§5)
                $pendingFileRename = $null
                try {
                    $pendingFileRename = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                } catch { }
                @{
                    Facts = @{
                        cbsRebootPending       = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                        wuRebootRequired       = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                        pendingFileRenameCount = @($pendingFileRename).Count
                        pendingComputerRename  = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName -ne
                                                  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName)
                    }
                }
            }
        }
        @{
            Id = 'WIN-VISA-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-004: NO 4.x drives the zAmp through WinUSB + NI-VISA, but the
                # bundle only inspected zAmpLoader\driver — a directory a healthy
                # 4.x box does not have. These are the 4.x amp-stack facts:
                # the VISA DLLs NO.exe loads, and whether VID_1167 device nodes
                # are bound to the WinUSB service.
                $sys32 = Join-Path $env:SystemRoot 'System32'
                $dlls = @(foreach ($name in $Context.VisaSystemDlls) {
                    $p = Join-Path $sys32 $name
                    $d = @{ name = $name; path = $p; present = (Test-Path -LiteralPath $p) }
                    if ($d.present) {
                        $item = Get-Item -LiteralPath $p
                        $d.fileVersion   = "$($item.VersionInfo.FileVersion)"
                        $d.sizeBytes     = $item.Length
                        $d.lastWriteTime = $item.LastWriteTime.ToString('o')
                    }
                    $d
                })
                $facts = @{
                    dlls           = $dlls
                    anyVisaPresent = (@($dlls | Where-Object { $_.present }).Count -gt 0)
                    winusbVid1167  = @()
                    enumStatus     = 'Ok'
                }
                try {
                    $devices = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -like $Context.ZampVidMatch })
                    $facts.winusbVid1167 = @(foreach ($dev in $devices) {
                        $service = $null
                        try {
                            $service = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_Service' -ErrorAction Stop).Data
                        } catch { }
                        @{
                            instanceId   = "$($dev.InstanceId)"
                            friendlyName = "$($dev.FriendlyName)"
                            class        = "$($dev.Class)"
                            status       = "$($dev.Status)"
                            service      = "$service"
                            winUsbBound  = ("$service" -eq 'WINUSB')
                        }
                    })
                } catch {
                    # Enumeration unavailability is a fact, not a failure (§3.1)
                    $facts.enumStatus = "Unavailable: $($_.Exception.Message)"
                }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'WIN-VISA-002'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-012: the THIRD COM identity table. See the note on
                # $script:VisaConfIniPath. Facts only — this reads a plain INI
                # and reports what it says, INCLUDING where it contradicts
                # itself. It does not decide that a contradiction caused
                # anything, and it never writes to the file.
                #
                # Only the two identity sections are kept. The file also carries
                # 256 TULIP Interface<n> lines that say nothing about COM
                # identity and would burn the bundle's size budget.
                $iniPath = $Context.VisaConfIniPath
                $facts = @{
                    visaConfPath = $iniPath
                    present      = (Test-Path -LiteralPath $iniPath)
                    # $null, not @(): "not read" must never render as "read, and
                    # there were none" — an empty alias table is a real finding.
                    asrlResources = $null
                    aliases       = $null
                    declared      = $null
                    anomalies     = $null
                    parseStatus   = 'NotAttempted'
                }
                if ($facts.present) {
                    try {
                        $item = Get-Item -LiteralPath $iniPath -ErrorAction Stop
                        $facts.sizeBytes     = $item.Length
                        $facts.lastWriteTime = $item.LastWriteTime.ToString('o')

                        $section         = ''
                        $asrl            = @{}
                        $aliasList       = @()
                        $declaredAsrl    = $null
                        $declaredAliases = $null

                        foreach ($line in (Get-Content -LiteralPath $iniPath -ErrorAction Stop)) {
                            $trimmed = $line.Trim()
                            if ($trimmed -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
                            # Keys are letters then an OPTIONAL trailing index:
                            # SystemName0 -> SystemName/0, NumAliases -> NumAliases/''.
                            if ($trimmed -notmatch '^([A-Za-z]+)(\d*)\s*=\s*(.*)$') { continue }
                            $key = $Matches[1]
                            $idx = $Matches[2]
                            $val = $Matches[3].Trim().Trim('"')

                            if ($section -eq 'ASRL-RSRC-ALIAS') {
                                # NumOfResources is section-scoped: TCPIP-RSRCS
                                # carries a key of the same name.
                                if ($key -eq 'NumOfResources') { $declaredAsrl = [int]$val; continue }
                                if ($idx -eq '') { continue }
                                if (-not $asrl.ContainsKey($idx)) { $asrl[$idx] = @{ index = [int]$idx } }
                                switch ($key) {
                                    'Name'       { $asrl[$idx].resourceName = $val }
                                    'SystemName' { $asrl[$idx].systemName   = $val }
                                    'Enabled'    { $asrl[$idx].enabled      = ($val -eq '1') }
                                    'Static'     { $asrl[$idx].static       = ($val -eq '1') }
                                }
                            } elseif ($section -eq 'ALIASES') {
                                if ($key -eq 'NumAliases') { $declaredAliases = [int]$val; continue }
                                if ($key -eq 'Alias') { $aliasList += @{ index = [int]$idx; value = $val } }
                            }
                        }

                        $resources = @($asrl.Values | Sort-Object { $_.index })
                        $facts.asrlResources = $resources
                        $facts.aliases       = @($aliasList | Sort-Object { $_.index })
                        $facts.declared      = @{ numOfResources = $declaredAsrl; numAliases = $declaredAliases }

                        # Two VISA resource names resolving to one system port.
                        $dupes = @($resources | Where-Object { $_.systemName } |
                            Group-Object -Property { $_.systemName } | Where-Object { $_.Count -gt 1 } |
                            ForEach-Object {
                                @{
                                    systemName    = "$($_.Name)"
                                    count         = $_.Count
                                    resourceNames = @($_.Group | ForEach-Object { "$($_.resourceName)" })
                                }
                            })

                        # ASRL11::INSTR -> COM3 is legal and load-bearing: the
                        # ASRL number is NOT the COM number, so anything that
                        # infers one from the other is reading a label as an id.
                        $mismatch = @(foreach ($res in $resources) {
                            $asrlNum = $null; $comNum = $null
                            if ("$($res.resourceName)" -match '(\d+)') { $asrlNum = [int]$Matches[1] }
                            if ("$($res.systemName)"   -match '(\d+)') { $comNum  = [int]$Matches[1] }
                            if ($null -ne $asrlNum -and $null -ne $comNum -and $asrlNum -ne $comNum) {
                                @{ resourceName = "$($res.resourceName)"; systemName = "$($res.systemName)"; asrlNumber = $asrlNum; comNumber = $comNum }
                            }
                        })

                        $facts.anomalies = @{
                            duplicateSystemNames   = $dupes
                            asrlNumberNotComNumber = $mismatch
                            declaredCountsDisagree = ($null -ne $declaredAsrl -and $null -ne $declaredAliases -and $declaredAsrl -ne $declaredAliases)
                            parsedVsDeclaredAsrl   = @{ declared = $declaredAsrl; parsed = $resources.Count }
                        }
                        $facts.parseStatus = 'Ok'
                    } catch {
                        # Unreadable is a fact, not a failure (§3.1)
                        $facts.parseStatus = "Unavailable: $($_.Exception.Message)"
                    }
                } else {
                    $facts.parseStatus = 'Absent'
                }

                $facts.niVisaVersions = @(foreach ($entry in $Context.NiVisaRegPaths) {
                    $view = @{ view = $entry.view; regPath = $entry.path; present = (Test-Path $entry.path) }
                    if ($view.present) {
                        try { $view.currentVersion = "$((Get-ItemProperty -LiteralPath $entry.path -ErrorAction Stop).CurrentVersion)" } catch { }
                    }
                    $view
                })

                $facts.niServices = @(foreach ($svcName in $Context.NiServiceNames) {
                    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($svc) { @{ name = $svcName; present = $true; status = "$($svc.Status)"; startType = "$($svc.StartType)" } }
                    else      { @{ name = $svcName; present = $false } }
                })

                @{ Facts = $facts }
            }
        }
        @{
            Id = 'WIN-ODBC-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # MsiInstaller 1918 field lesson: ODBC "driver could not be loaded"
                # events read as failures but are often stale; the triage move is
                # checking the CURRENT registration. Facts per registry view:
                # driver name, registered DLL path, whether that DLL exists, version.
                $views = @(foreach ($v in $Context.OdbcInstRegPaths) {
                    $view = @{ view = $v.view; regPath = $v.path; present = (Test-Path $v.path); drivers = @() }
                    if ($view.present) {
                        try {
                            $listKey = Join-Path $v.path 'ODBC Drivers'
                            $names = @()
                            if (Test-Path $listKey) { $names = @((Get-Item $listKey).Property) }
                            $view.drivers = @(foreach ($n in $names) {
                                $drv = @{ name = "$n" }
                                try { $drv.state = "$((Get-ItemProperty $listKey -ErrorAction Stop).$n)" } catch { }
                                $dk = Join-Path $v.path $n
                                if (Test-Path $dk) {
                                    $props = Get-ItemProperty $dk -ErrorAction SilentlyContinue
                                    if ($props -and $props.PSObject.Properties['Driver']) {
                                        $drv.driverDll = "$($props.Driver)"
                                        $drv.driverDllPresent = ($drv.driverDll -and (Test-Path -LiteralPath $drv.driverDll))
                                        if ($drv.driverDllPresent) {
                                            $drv.fileVersion = "$((Get-Item -LiteralPath $drv.driverDll).VersionInfo.FileVersion)"
                                        }
                                    }
                                }
                                $drv
                            })
                        } catch {
                            $view.parseStatus = "Unavailable: $($_.Exception.Message)"
                        }
                    }
                    $view
                })
                @{ Facts = @{ views = $views } }
            }
        }
        @{
            # RequiresZengar = $false deliberately: NI Package Manager survives a wipe of
            # C:\zengar, and its stale state is exactly what breaks the REINSTALL. Gating
            # on Zengar would blind this collector on the box that needs it most (FI-005).
            Id = 'WIN-NIPKG-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # FI-016: `com.zengar.no.lvrte` and `com.zengar.no.nivisa` install by
                # running `nipkg feed-add --name=<name> <local staging path>`. NI Package
                # Manager's feed list is global and OUTLIVES the install root, so on a
                # reinstall the name is already taken, feed-add returns -125006, and the
                # QtIFW dialog blocks the entire install. Observed MCAJOLAIS_05 2026-07-31.
                #
                # FACTS ONLY (§3.4): the feed table plus whether each LOCAL feed's target
                # still exists. A local feed whose target is gone is the precondition —
                # the signature decides what that means, not this collector.
                $facts = @{ nipkgPath = $Context.NipkgPath; present = [bool](Test-Path -LiteralPath $Context.NipkgPath) }
                if (-not $facts.present) { return @{ Facts = $facts } }

                $raw = ''
                try {
                    $raw = & $Context.NipkgPath feed-list 2>&1 | Out-String
                    $facts.exitCode = $LASTEXITCODE
                } catch {
                    $facts.enumStatus = "Unavailable: $($_.Exception.Message)"
                    return @{ Facts = $facts }
                }

                # Output is '<name><TAB><uri>'. Feed names may contain spaces
                # ('ni-labview-2024-runtime-engine-2024 Q3-released'), so never split on
                # single whitespace — prefer the tab, and fall back to the LAST token.
                $feeds = @(foreach ($line in ($raw -split "`r?`n")) {
                    if (-not $line.Trim()) { continue }
                    $name = $null; $uri = $null
                    if ($line -match "`t") {
                        $parts = @($line -split "`t+", 2)
                        $name = $parts[0].Trim(); $uri = $parts[1].Trim()
                    } elseif ($line -match '^(?<n>.*\S)\s+(?<u>\S+)$') {
                        $name = $Matches['n'].Trim(); $uri = $Matches['u'].Trim()
                    }
                    if (-not $name -or -not $uri) { continue }
                    $isLocal = ($uri -notmatch '^[a-z][a-z0-9+.-]*://')
                    $feed = @{ name = $name; uri = $uri; isLocal = $isLocal }
                    if ($isLocal) { $feed.targetPresent = [bool](Test-Path -LiteralPath $uri -ErrorAction SilentlyContinue) }
                    $feed
                })
                $facts.feeds     = @($feeds)
                $facts.feedCount = @($feeds).Count
                @{ Facts = $facts }
            }
        }

        @{
            Id = 'WIN-USB-001'; Ring = 2; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # SP9 field reports 2026-10-27: after the 26H2 feature update two Surface
                # Pro 9s lost BOTH USB-C ports — the zAmp, flash drives, a phone and a hub
                # never appeared in Device Manager and USB-C charging stopped, while Surface
                # Connect charging still worked. The controllers showed no error, rolling
                # back 26H2 did not help, and nothing in the bundle could show that NOTHING
                # was enumerating, when the last USB device ever arrived, or which firmware
                # had just been flashed (an OS rollback does not revert firmware).
                #
                # Model-agnostic FACTS: the platform, the UEFI ESRT firmware table (version
                # + last update attempt), USB host/connector infrastructure state, every USB
                # device node (present or not) with its last arrival/removal and whether it
                # is built in, the power source, firmware/feature-update history, and USB
                # warnings/errors. Read-only: nothing is installed, reset or restarted.
                #
                # Cost discipline (measured SP9 2026-10-27): per-device Get-PnpDeviceProperty
                # is ~0.5 s EACH and Win32_Battery up to 1.6 s, which made a naive version
                # 13-15 s. Here: one Get-PnpDevice, ONE batched property query, registry for
                # platform + ESRT, SystemInformation for power — 1.1-2.6 s on that box.
                $facts = @{}

                $bios = Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' -ErrorAction SilentlyContinue
                $facts.platform = @{
                    manufacturer    = "$($bios.SystemManufacturer)"
                    model           = "$($bios.SystemProductName)"
                    sku             = "$($bios.SystemSKU)"
                    biosVersion     = "$($bios.BIOSVersion)"
                    biosReleaseDate = "$($bios.BIOSReleaseDate)"
                }

                $all = @(Get-PnpDevice -ErrorAction Stop)
                $byId = @{}
                foreach ($d in $all) { $byId["$($d.InstanceId)"] = $d }

                # ESRT: one subkey per updatable firmware resource; the matching PnP node is
                # UEFI\RES_{GUID}\0 and carries the friendly name. Values are REG_DWORD and
                # vendor-encoded, so they ship as hex. LastAttemptStatus 0 = success.
                $esrtRoot = 'HKLM:\HARDWARE\UEFI\ESRT'
                $facts.esrtPresent = [bool](Test-Path -LiteralPath $esrtRoot)
                $facts.firmware = @(if ($facts.esrtPresent) {
                    Get-ChildItem -LiteralPath $esrtRoot -ErrorAction SilentlyContinue | ForEach-Object {
                        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                        $node = $byId["UEFI\RES_$($_.PSChildName)\0"]
                        @{
                            guid                   = "$($_.PSChildName)"
                            name                   = $(if ($node) { "$($node.FriendlyName)" } else { $null })
                            deviceStatus           = $(if ($node) { "$($node.Status)" } else { $null })
                            type                   = $(if ($null -ne $p.Type) { [int]$p.Type } else { $null })
                            version                = $(if ($null -ne $p.Version) { '0x{0:X8}' -f $p.Version } else { $null })
                            lowestSupportedVersion = $(if ($null -ne $p.LowestSupportedVersion) { '0x{0:X8}' -f $p.LowestSupportedVersion } else { $null })
                            lastAttemptVersion     = $(if ($null -ne $p.LastAttemptVersion) { '0x{0:X8}' -f $p.LastAttemptVersion } else { $null })
                            lastAttemptStatus      = $(if ($null -ne $p.LastAttemptStatus) { [int]$p.LastAttemptStatus } else { $null })
                        }
                    }
                })

                # Host controllers, root hubs, USB4 routers and USB-C connector managers.
                # These stayed "OK" on the failed SP9 — recorded so that is visible, too.
                $facts.infrastructure = @($all | Where-Object {
                    "$($_.InstanceId)" -notlike 'USB\VID*' -and
                    ("$($_.Class)" -in @('USB', 'UCM', 'UCMCLIENT') -or "$($_.FriendlyName)" -match 'USB4|UCSI|Type-C|USB Connector Manager')
                } | ForEach-Object {
                    @{ instanceId = "$($_.InstanceId)"; friendlyName = "$($_.FriendlyName)"; class = "$($_.Class)"; present = [bool]$_.Present; status = "$($_.Status)"; problem = "$($_.Problem)" }
                })

                # Every USB device node Windows remembers (interfaces of composite devices
                # excluded). A non-present node is history: its last arrival says when that
                # device last enumerated on this machine.
                $usb = @($all | Where-Object { "$($_.InstanceId)" -like 'USB\VID*' -and "$($_.InstanceId)" -notmatch '&MI_' } |
                    Sort-Object -Property @{ Expression = { [bool]$_.Present }; Descending = $true }, InstanceId)
                $facts.usbDeviceTotal = $usb.Count
                $max = $Context.Caps.UsbDeviceMax
                if ($usb.Count -gt $max) {
                    $facts.truncationMarker = "...truncated ($($usb.Count - $max) more USB device nodes)"
                    $usb = @($usb | Select-Object -First $max)
                }
                # The batched query intermittently returns NO rows for some devices (SP9,
                # 2026-10-27: 3 of 6 runs dropped a present zAmp and/or flash drive), so
                # unanswered devices get one more batch, then present ones one at a time.
                # Whatever is still unanswered is listed, never left to read as "unknown".
                $props = @{}
                $answered = @{}
                $keyNames = @('DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate', 'DEVPKEY_Device_InLocalMachineContainer')
                $fetch = {
                    param([string[]]$List)
                    foreach ($pr in @(Get-PnpDeviceProperty -InstanceId $List -KeyName $keyNames -ErrorAction Stop)) {
                        $props["$($pr.InstanceId)|$($pr.KeyName)"] = $pr.Data
                        $answered["$($pr.InstanceId)"] = $true
                    }
                }
                if ($usb.Count -gt 0) {
                    try {
                        & $fetch @($usb | ForEach-Object { "$($_.InstanceId)" })
                        $retry = @($usb | Where-Object { -not $answered["$($_.InstanceId)"] } | ForEach-Object { "$($_.InstanceId)" })
                        $facts.devicePropertyRetried = $retry.Count
                        if ($retry.Count -gt 0) { & $fetch $retry }
                        foreach ($d in @($usb | Where-Object { $_.Present -and -not $answered["$($_.InstanceId)"] })) { & $fetch @("$($d.InstanceId)") }
                    } catch {
                        $facts.devicePropertyError = $_.Exception.Message
                    }
                    $facts.devicePropertyUnanswered = @($usb | Where-Object { -not $answered["$($_.InstanceId)"] } | ForEach-Object { "$($_.InstanceId)" })
                }
                $isoOrNull = { param($v) if ($v -is [datetime]) { $v.ToString('o') } else { $null } }
                $facts.usbDevices = @($usb | ForEach-Object {
                    $id = "$($_.InstanceId)"
                    $builtIn = $props["$id|DEVPKEY_Device_InLocalMachineContainer"]
                    @{
                        instanceId   = $id
                        friendlyName = "$($_.FriendlyName)"
                        class        = "$($_.Class)"
                        present      = [bool]$_.Present
                        status       = "$($_.Status)"
                        problem      = "$($_.Problem)"
                        builtIn      = $(if ($builtIn -is [bool]) { $builtIn } else { $null })
                        lastArrival  = (& $isoOrNull $props["$id|DEVPKEY_Device_LastArrivalDate"])
                        lastRemoval  = (& $isoOrNull $props["$id|DEVPKEY_Device_LastRemovalDate"])
                    }
                })

                # Power source. Cannot tell USB-C from a proprietary barrel/dock connector.
                try {
                    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
                    $pw = [System.Windows.Forms.SystemInformation]::PowerStatus
                    $facts.power = @{
                        acLine         = "$($pw.PowerLineStatus)"
                        chargeStatus   = "$($pw.BatteryChargeStatus)"
                        batteryPercent = $(if ($pw.BatteryLifePercent -le 1) { [int][math]::Round($pw.BatteryLifePercent * 100) } else { $null })
                    }
                } catch {
                    $facts.power = @{ error = $_.Exception.Message }
                }

                # Firmware / feature-update history. IUpdateHistoryEntry.Date is UTC with
                # Kind=Unspecified: on SP9 (Eastern) KB5127648 read 22:55 while its
                # WindowsUpdateClient event 19 fired at 19:41-04:00 (23:41Z) — only UTC fits.
                try {
                    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
                    $total = [int]$searcher.GetTotalHistoryCount()
                    $facts.updateHistoryTotal = $total
                    $scan = [Math]::Min($total, [int]$Context.Caps.UpdateHistoryScanMax)
                    $hits = @(if ($scan -gt 0) {
                        $searcher.QueryHistory(0, $scan) | Where-Object { "$($_.Title)" -match $Context.UpdateHistoryTitleMatch }
                    })
                    if ($hits.Count -gt $Context.Caps.UpdateHistoryMax) {
                        $facts.updateHistoryTruncationMarker = "...truncated ($($hits.Count - $Context.Caps.UpdateHistoryMax) more matching entries)"
                        $hits = @($hits | Select-Object -First $Context.Caps.UpdateHistoryMax)
                    }
                    $facts.updateHistory = @($hits | ForEach-Object {
                        @{ dateUtc = ([datetime]$_.Date).ToString('yyyy-MM-ddTHH:mm:ssZ'); title = "$($_.Title)"; resultCode = [int]$_.ResultCode; operation = [int]$_.Operation }
                    })
                } catch {
                    $facts.updateHistoryError = $_.Exception.Message
                }

                # USB warnings/errors in System. XPath, not -FilterHashtable: a provider
                # name that does not exist on this machine must not fail the query.
                # USBHUB3 196 ("USB device draining system power when system is idle") is
                # excluded: it was 18/18 and 63/63 of these events on two healthy Surfaces
                # and would starve the cap.
                $provXPath = (@($Context.UsbEventProviders) | ForEach-Object { "@Name='$_'" }) -join ' or '
                $windowMs = [long]$Context.Caps.UsbEventWindowDays * 86400000
                $xpath = "*[System[Provider[$provXPath] and (Level=1 or Level=2 or Level=3) and EventID!=196 and TimeCreated[timediff(@SystemTime) <= $windowMs]]]"
                try {
                    $facts.usbEvents = @(Get-WinEvent -LogName 'System' -FilterXPath $xpath -MaxEvents $Context.Caps.UsbEventMax -ErrorAction Stop | ForEach-Object {
                        $msg = "$($_.Message)"
                        @{ time = $_.TimeCreated.ToString('o'); provider = "$($_.ProviderName)"; id = $_.Id; level = $_.Level; message = $msg.Substring(0, [Math]::Min(200, $msg.Length)) }
                    })
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { $facts.usbEventsError = $_.Exception.Message }
                    $facts.usbEvents = @()
                }
                $facts.usbEventWindowDays = $Context.Caps.UsbEventWindowDays
                $facts.usbEventCap = $Context.Caps.UsbEventMax

                # Unclean restarts (Kernel-Power 41), same window. The remediation for dead
                # ports starts with a forced restart, and a tech's "I did that" must be
                # checkable: the message text (which WIN-EVENTS-001 clips) cannot tell a held
                # power button from a crash, the event data can. Measured on SP9 2026-10-27
                # after a user-held restart: LongPowerButtonPressDetected=true, BugcheckCode=0,
                # PowerButtonTimestamp = the press (FILETIME UTC), ~27 s before the boot.
                $restartXPath = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41 and TimeCreated[timediff(@SystemTime) <= $windowMs]]]"
                try {
                    $facts.uncleanRestarts = @(Get-WinEvent -LogName 'System' -FilterXPath $restartXPath -MaxEvents $Context.Caps.RestartEventMax -ErrorAction Stop | ForEach-Object {
                        $data = @{}
                        foreach ($n in @(([xml]$_.ToXml()).Event.EventData.Data)) { $data["$($n.Name)"] = "$($n.'#text')" }
                        $pressRaw = 0L
                        [void][long]::TryParse("$($data['PowerButtonTimestamp'])", [ref]$pressRaw)
                        @{
                            time                         = $_.TimeCreated.ToString('o')
                            bugcheckCode                 = $(if ("$($data['BugcheckCode'])" -match '^\d+$') { [long]$data['BugcheckCode'] } else { $null })
                            longPowerButtonPressDetected = $(if ($data.ContainsKey('LongPowerButtonPressDetected')) { "$($data['LongPowerButtonPressDetected'])" -eq 'true' } else { $null })
                            powerButtonPressUtc          = $(if ($pressRaw -gt 0) { [datetime]::FromFileTimeUtc($pressRaw).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null })
                            sleepInProgress              = $(if ("$($data['SleepInProgress'])" -match '^\d+$') { [int]$data['SleepInProgress'] } else { $null })
                            connectedStandbyInProgress   = $(if ($data.ContainsKey('ConnectedStandbyInProgress')) { "$($data['ConnectedStandbyInProgress'])" -eq 'true' } else { $null })
                        }
                    })
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { $facts.uncleanRestartsError = $_.Exception.Message }
                    $facts.uncleanRestarts = @()
                }

                @{ Facts = $facts }
            }
        }

        # ---------------- Ring 3 — Network layer (targeted, §5) ----------------
        @{
            Id = 'NET-REPO-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 60
            Script = {
                param($Context)
                # The single most valuable network check: reachability of the client's
                # OWN authenticated repo URL. MUST NOT authenticate — 401 proves
                # reachability without putting credentials in flight (§6).
                $url = $Context.Repository.RepositoryUrl
                if (-not $url) {
                    # No URL to probe is itself the finding (e.g. maintenancetool.ini
                    # absent on partial installs) — record why, don't fail
                    return @{ Facts = @{ repoUrlParsed = $false; parseStatus = "$($Context.Repository.ParseStatus)" } }
                }
                $uri = [Uri]$url
                $facts = @{ repoUrlParsed = $true; url = $url; host = $uri.Host }
                try {
                    $addrs = [System.Net.Dns]::GetHostAddresses($uri.Host)
                    $facts.dns = @{ resolved = $true; addresses = @($addrs | ForEach-Object { "$_" }) }
                } catch {
                    $facts.dns = @{ resolved = $false; error = $_.Exception.Message }
                }
                try {
                    # Unauthenticated status probe. 401 = reachable+auth required (expected).
                    $req = [System.Net.HttpWebRequest]::Create("$($uri.Scheme)://$($uri.Host)$($uri.PathAndQuery.TrimEnd('/'))/Updates.xml")
                    $req.Method = 'GET'
                    $req.Timeout = 15000
                    $req.AllowAutoRedirect = $false
                    try {
                        $resp = $req.GetResponse()
                        $facts.http = @{ statusCode = [int]$resp.StatusCode; statusDescription = "$($resp.StatusDescription)" }
                        $resp.Close()
                    } catch [System.Net.WebException] {
                        $resp = $_.Exception.Response
                        if ($resp) {
                            $facts.http = @{ statusCode = [int]$resp.StatusCode; statusDescription = "$($resp.StatusDescription)" }
                            $resp.Close()
                        } else {
                            $facts.http = @{ statusCode = $null; error = $_.Exception.Message; webExceptionStatus = "$($_.Exception.Status)" }
                        }
                    }
                } catch {
                    $facts.http = @{ statusCode = $null; error = $_.Exception.Message }
                }
                @{ Facts = $facts }
            }
        }
        @{
            Id = 'NET-DNS-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 60
            Script = {
                param($Context)
                $results = @()
                foreach ($domain in $Context.SupportDomains) {
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        $addrs = [System.Net.Dns]::GetHostAddresses($domain)
                        $sw.Stop()
                        $results += @{ domain = $domain; resolved = $true; ms = $sw.ElapsedMilliseconds
                                       addresses = @($addrs | ForEach-Object { "$_" }) }
                    } catch {
                        $sw.Stop()
                        $results += @{ domain = $domain; resolved = $false; ms = $sw.ElapsedMilliseconds; error = $_.Exception.Message }
                    }
                }
                @{ Facts = @{ results = $results } }
            }
        }
        @{
            Id = 'NET-TLS-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 90
            Script = {
                param($Context)
                # Issuer reveals TLS interception (corporate MITM) — a known blocker.
                # Facts only: no judgment about whether interception is "bad".
                $results = @()
                foreach ($domain in $Context.SupportDomains) {
                    $entry = @{ domain = $domain }
                    $client = $null
                    $ssl = $null
                    try {
                        $client = New-Object System.Net.Sockets.TcpClient
                        $iar = $client.BeginConnect($domain, 443, $null, $null)
                        if (-not $iar.AsyncWaitHandle.WaitOne(8000)) { throw "TCP connect timeout (8s)" }
                        $client.EndConnect($iar)
                        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, { $true })
                        $ssl.AuthenticateAsClient($domain)
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                        $entry.handshake  = $true
                        $entry.protocol   = "$($ssl.SslProtocol)"
                        $entry.cipher     = "$($ssl.CipherAlgorithm)"
                        $entry.certSubject    = $cert.Subject
                        $entry.certIssuer     = $cert.Issuer
                        $entry.certThumbprint = $cert.Thumbprint
                        $entry.certNotAfter   = $cert.NotAfter.ToString('o')
                    } catch {
                        $entry.handshake = $false
                        $entry.error = $_.Exception.Message
                    } finally {
                        if ($ssl) { $ssl.Dispose() }
                        if ($client) { $client.Close() }
                    }
                    $results += $entry
                }
                @{ Facts = @{ results = $results } }
            }
        }
        @{
            Id = 'NET-PORT-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 60
            Script = {
                param($Context)
                # BLT licensing ports — a licensing failure is one of the most common
                # escalations and is invisible without this (§5)
                $results = @()
                foreach ($port in $Context.BltLicensingPorts) {
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $client = New-Object System.Net.Sockets.TcpClient
                    try {
                        $iar = $client.BeginConnect($Context.BltLicensingHost, $port, $null, $null)
                        $connected = $iar.AsyncWaitHandle.WaitOne(8000)
                        $sw.Stop()
                        if ($connected -and $client.Connected) {
                            $client.EndConnect($iar)
                            $results += @{ server = $Context.BltLicensingHost; port = $port; tcpConnect = $true; ms = $sw.ElapsedMilliseconds }
                        } else {
                            $results += @{ server = $Context.BltLicensingHost; port = $port; tcpConnect = $false; ms = $sw.ElapsedMilliseconds; error = 'Connect timeout (8s)' }
                        }
                    } catch {
                        $sw.Stop()
                        $results += @{ server = $Context.BltLicensingHost; port = $port; tcpConnect = $false; ms = $sw.ElapsedMilliseconds; error = $_.Exception.Message }
                    } finally {
                        $client.Close()
                    }
                }
                @{ Facts = @{ results = $results } }
            }
        }
        @{
            Id = 'NET-TRUSTFETCH-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false; TimeoutSeconds = 60
            Script = {
                param($Context)
                # KI-001: these hosts are load-bearing for driver cert-chain building.
                # Blocked here -> 0x800B010A later.
                $results = @()
                foreach ($targetHost in $Context.TrustFetchHosts) {
                    $entry = @{ host = $targetHost }
                    try {
                        $addrs = [System.Net.Dns]::GetHostAddresses($targetHost)
                        $entry.dnsResolved = $true
                        $entry.addresses = @($addrs | ForEach-Object { "$_" })
                    } catch {
                        $entry.dnsResolved = $false
                        $entry.dnsError = $_.Exception.Message
                    }
                    try {
                        $req = [System.Net.HttpWebRequest]::Create("http://$targetHost/")
                        $req.Method = 'HEAD'
                        $req.Timeout = 10000
                        $req.AllowAutoRedirect = $false
                        try {
                            $resp = $req.GetResponse()
                            $entry.httpStatus = [int]$resp.StatusCode
                            $resp.Close()
                        } catch [System.Net.WebException] {
                            if ($_.Exception.Response) {
                                $entry.httpStatus = [int]$_.Exception.Response.StatusCode
                                $_.Exception.Response.Close()
                            } else {
                                $entry.httpStatus = $null
                                $entry.httpError = $_.Exception.Message
                            }
                        }
                    } catch {
                        $entry.httpError = $_.Exception.Message
                    }
                    $results += $entry
                }
                @{ Facts = @{ results = $results } }
            }
        }
        @{
            Id = 'NET-PROXY-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # WinHTTP and WinINET differ, and the elevated QtIFW server process may
                # not inherit the user's proxy — this one has bitten people (§5)
                $winhttpOut = & netsh winhttp show proxy 2>&1 | Out-String
                $winhttpExit = $LASTEXITCODE
                $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
                @{
                    Facts = @{
                        winhttp = @{
                            output   = $winhttpOut.Trim()
                            exitCode = @{ dec = $winhttpExit; hex = ('0x{0:X8}' -f $winhttpExit) }
                        }
                        wininet = @{
                            proxyEnable   = $inet.ProxyEnable
                            proxyServer   = "$($inet.ProxyServer)"
                            proxyOverride = "$($inet.ProxyOverride)"
                            autoConfigURL = "$($inet.AutoConfigURL)"
                        }
                    }
                }
            }
        }
        @{
            Id = 'NET-ADAPTER-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # Context facts only — the severity contract classifies VPN/Wi-Fi as
                # INFO-only; we emit no severity at all (§3.4)
                $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                    @{ name = $_.Name; description = "$($_.InterfaceDescription)"; status = "$($_.Status)"
                       linkSpeed = "$($_.LinkSpeed)"; mediaType = "$($_.MediaType)" }
                })
                $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                    ForEach-Object { @{ interface = $_.InterfaceAlias; ip = $_.IPAddress; prefix = $_.PrefixLength } })
                $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.ServerAddresses } |
                    ForEach-Object { @{ interface = $_.InterfaceAlias; servers = @($_.ServerAddresses) } })
                $vpn = @()
                try { $vpn = @(Get-VpnConnection -ErrorAction Stop | ForEach-Object { @{ name = $_.Name; status = "$($_.ConnectionStatus)" } }) } catch { }
                $ipv6 = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                    ForEach-Object { @{ adapter = $_.Name; enabled = $_.Enabled } })
                @{ Facts = @{ adapters = $adapters; ipv4 = $ips; dnsServers = $dns; vpnConnections = $vpn; ipv6Bindings = $ipv6 } }
            }
        }
        @{
            Id = 'NET-TIME-001'; Ring = 3; RequiresAdmin = $false; RequiresZengar = $false
            Script = {
                param($Context)
                # Clock skew breaks TLS and cert validation — named in KI-001 (§5)
                $svc = Get-Service W32Time -ErrorAction SilentlyContinue
                $statusOut = & w32tm /query /status 2>&1 | Out-String
                $statusExit = $LASTEXITCODE
                @{
                    Facts = @{
                        systemTimeUtc   = [datetime]::UtcNow.ToString('o')
                        systemTimeLocal = [datetime]::Now.ToString('o')
                        timeZone        = "$((Get-TimeZone).Id)"
                        w32TimeService  = if ($svc) { "$($svc.Status)" } else { 'NotFound' }
                        w32tmStatus     = @{
                            output   = $statusOut.Trim()
                            exitCode = @{ dec = $statusExit; hex = ('0x{0:X8}' -f $statusExit) }
                        }
                    }
                }
            }
        }
    )
}

# =============================================================================
# ORCHESTRATOR (§3.1) — runs every collector in isolation; NEVER throws.
# =============================================================================
function Invoke-WinConfigSupportCollection {
    <#
    .SYNOPSIS
        Runs all collectors into an existing run folder. Never throws: every
        collector failure becomes a manifest entry and the run continues.
    .OUTPUTS
        Hashtable: Manifest (ordered), ManifestPath, Counts, Truncations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RunFolder,
        [Parameter(Mandatory)] [string]$RunId,

        [string]$CaseId = '',

        # Overridable for tests: collector injection, fake root, fake elevation
        [object[]]$Collectors = $null,
        [string]$ZengarRoot = $script:ZengarRootDefault,
        [nullable[bool]]$ElevatedOverride = $null,

        [int]$DefaultTimeoutSeconds = $script:DefaultCollectorTimeoutSeconds,

        # Called as & $ProgressCallback -CollectorId <id> -Status <Running|Ok|Error|Timeout|Skipped> -Index <n> -Total <n>
        [scriptblock]$ProgressCallback = $null
    )

    if ($null -eq $Collectors) { $Collectors = Get-WinConfigSupportCollectors }
    $elevated = if ($null -ne $ElevatedOverride) { [bool]$ElevatedOverride } else { Test-WinConfigSupportElevation }
    $zengarPresent = Test-Path -LiteralPath $ZengarRoot

    foreach ($dir in @((Join-Path $RunFolder 'collectors'), (Join-Path $RunFolder 'files'))) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    # Parse repo info ONCE up front (whitelist emission — §6). Never let a parse
    # failure kill the run.
    $repoInfo = $null
    try {
        $repoInfo = Get-WinConfigSupportRepositoryInfo -IniPath (Join-Path $ZengarRoot 'maintenancetool.ini')
    } catch {
        $repoInfo = @{ Present = $false; ParseStatus = "ParseError: $($_.Exception.Message)"; RepositoryUrl = $null; RepositoryUsername = $null; RepositoryPassword = '<redacted>'; Repositories = @(); ProductVersion = $null; FrameworkVersion = $null; InstallerFilePath = $null; TargetDir = $null }
    }

    $context = @{
        ZengarRoot       = $ZengarRoot
        StagingRoot      = $StagingRoot
        StagingPrefix    = $script:StagingComponentPrefix
        WebView2DirName  = $script:WebView2RuntimeDirName
        WebView2Binaries = $script:WebView2KeyBinaries
        ZampLoaderDir    = Join-Path $ZengarRoot $script:ZampLoaderRelDir
        DenyListAbsolute = @($script:ZengarDenyList | ForEach-Object { [System.IO.Path]::GetFullPath((Join-Path $ZengarRoot $_)) })
        Elevated         = $elevated
        Repository       = $repoInfo
        SupportDomains   = $script:SupportDomains
        BltLicensingHost = $script:BltLicensingHost
        BltLicensingPorts = $script:BltLicensingPorts
        TrustFetchHosts  = $script:TrustFetchHosts
        ZengarLeafThumb  = $script:ZengarLeafThumb
        SectigoE46Thumb  = $script:SectigoE46Thumb
        ZampVidMatch     = $script:ZampVidMatch
        VisaSystemDlls   = $script:VisaSystemDlls
        VisaConfIniPath  = $script:VisaConfIniPath
        NiVisaRegPaths   = $script:NiVisaRegPaths
        NiServiceNames   = $script:NiServiceNames
        OdbcInstRegPaths = $script:OdbcInstRegPaths
        ExternalComponents = $script:ExternalComponentTargets
        UninstallRegPaths  = $script:UninstallRegPaths
        NipkgPath          = $script:NipkgPath
        NoProcessName      = $script:NoProcessName
        DbServiceNameLike  = $script:DbServiceNameLike
        DbPort             = $script:DbPort
        UsbEventProviders  = $script:UsbEventProviders
        UpdateHistoryTitleMatch = $script:UpdateHistoryTitleMatch
        Caps             = @{
            LiveSampleSeconds   = $script:LiveSampleSeconds
            InstallLogTailLines = $script:InstallLogTailLines
            SetupApiTailLines   = $script:SetupApiTailLines
            EventSliceMax       = $script:EventSliceMax
            TreeListingMaxItems = $script:TreeListingMaxItems
            BinarySigMaxFiles   = $script:BinarySigMaxFiles
            FileLockMaxFiles    = $script:FileLockMaxFiles
            StagingMaxDirs      = $script:StagingMaxDirs
            WebView2MaxSiblings = $script:WebView2MaxSiblings
            UsbDeviceMax        = $script:UsbDeviceMax
            UpdateHistoryScanMax = $script:UpdateHistoryScanMax
            UpdateHistoryMax    = $script:UpdateHistoryMax
            UsbEventMax         = $script:UsbEventMax
            UsbEventWindowDays  = $script:UsbEventWindowDays
            RestartEventMax     = $script:RestartEventMax
        }
    }

    $collectorEntries = @()
    $truncations      = @()
    $index = 0
    $total = @($Collectors).Count

    foreach ($collector in $Collectors) {
        $index++
        $id = "$($collector.Id)"
        $entry = @{ id = $id; status = $null }
        $collectorResult = $null

        try {
            if ($collector.RequiresZengar -and -not $zengarPresent) {
                $entry.status = 'Skipped'
                $entry.reason = "Zengar installation not found at $ZengarRoot"
            } elseif ($collector.RequiresAdmin -and -not $elevated) {
                # §3.3: elevation improves the bundle; it is not a precondition
                $entry.status = 'Skipped'
                $entry.reason = 'Requires elevation'
            } else {
                if ($ProgressCallback) { try { & $ProgressCallback -CollectorId $id -Status 'Running' -Index $index -Total $total } catch { } }

                $timeoutSec = if ($collector.TimeoutSeconds) { [int]$collector.TimeoutSeconds } else { $DefaultTimeoutSeconds }
                $sw = [System.Diagnostics.Stopwatch]::StartNew()

                # Isolated runspace per collector: a hang is killed by timeout and
                # cannot take the run (or the UI thread) down with it (§3.1)
                $ps = [powershell]::Create()
                try {
                    [void]$ps.AddScript($collector.Script.ToString()).AddArgument($context)
                    $handle = $ps.BeginInvoke()
                    $deadline = [datetime]::UtcNow.AddSeconds($timeoutSec)
                    while (-not $handle.IsCompleted -and [datetime]::UtcNow -lt $deadline) {
                        [void]$handle.AsyncWaitHandle.WaitOne(200)
                        if ($ProgressCallback) { try { & $ProgressCallback -CollectorId $id -Status 'Running' -Index $index -Total $total } catch { } }
                    }
                    if (-not $handle.IsCompleted) {
                        $ps.Stop()
                        $sw.Stop()
                        $entry.status = 'Timeout'
                        $entry.timeoutSeconds = $timeoutSec
                        $entry.ms = $sw.ElapsedMilliseconds
                    } else {
                        $output = $ps.EndInvoke($handle)
                        $sw.Stop()
                        if ($ps.Streams.Error.Count -gt 0 -and -not $output) {
                            throw $ps.Streams.Error[0].Exception
                        }
                        $collectorResult = if ($output -and $output.Count -gt 0) { $output[$output.Count - 1] } else { $null }
                        $entry.status = 'Ok'
                        $entry.ms = $sw.ElapsedMilliseconds
                    }
                } finally {
                    $ps.Dispose()
                }
            }
        } catch {
            $entry.status = 'Error'
            $entry.error = $_.Exception.Message
            if ($_.Exception.HResult) { $entry.hresult = ('0x{0:X8}' -f $_.Exception.HResult) }
            if (-not $entry.ContainsKey('ms') -and (Get-Variable sw -ErrorAction SilentlyContinue) -and $sw) { $entry.ms = $sw.ElapsedMilliseconds }
        }

        # Persist the per-collector artifact — ALWAYS, even for failures, so an
        # absent artifact and an empty artifact are never indistinguishable (§3.2)
        try {
            $artifact = [ordered]@{
                id     = $id
                status = $entry.status
                ms     = $entry.ms
            }
            if ($entry.reason)  { $artifact.reason = $entry.reason }
            if ($entry.error)   { $artifact.error = $entry.error }
            if ($entry.hresult) { $artifact.hresult = $entry.hresult }
            if ($entry.ContainsKey('timeoutSeconds')) { $artifact.timeoutSeconds = $entry.timeoutSeconds }
            if ($collectorResult -and $collectorResult.Facts) { $artifact.facts = $collectorResult.Facts }
            $artifact | ConvertTo-Json -Depth 12 | Out-File -FilePath (Join-Path $RunFolder "collectors\$id.json") -Encoding UTF8 -Force
        } catch {
            # Even artifact persistence must not kill the run
            $entry.artifactError = $_.Exception.Message
        }

        # Execute file requests through the central deny-list/truncation choke point (§6)
        if ($collectorResult -and $collectorResult.Files) {
            $fileOutcomes = @()
            foreach ($request in @($collectorResult.Files)) {
                try {
                    $addArgs = @{
                        RunFolder  = $RunFolder
                        SourcePath = "$($request.SourcePath)"
                        TargetName = "$($request.TargetName)"
                        ZengarRoot = $ZengarRoot
                    }
                    if ($request.TailLines) { $addArgs.TailLines = [int]$request.TailLines }
                    if ($request.Transform) { $addArgs.Transform = "$($request.Transform)" }
                    $outcome = Add-WinConfigSupportBundleFile @addArgs
                    $fileOutcomes += $outcome
                    if ($outcome.Truncation) { $truncations += $outcome.Truncation }
                } catch {
                    $fileOutcomes += @{ Added = $false; TargetName = "$($request.TargetName)"; Reason = $_.Exception.Message }
                }
            }
            $entry.files = @($fileOutcomes | ForEach-Object { @{ name = $_.TargetName; added = $_.Added; reason = $_.Reason } })
        }

        $collectorEntries += $entry
        if ($ProgressCallback) { try { & $ProgressCallback -CollectorId $id -Status $entry.status -Index $index -Total $total } catch { } }
    }

    # ---- Manifest (§7): triage starts at the header ----
    $counts = @{ ok = 0; skipped = 0; error = 0; timeout = 0 }
    foreach ($entry in $collectorEntries) {
        switch ($entry.status) {
            'Ok'      { $counts.ok++ }
            'Skipped' { $counts.skipped++ }
            'Error'   { $counts.error++ }
            'Timeout' { $counts.timeout++ }
            default   { $counts.error++ }
        }
    }

    $zengarBlock = @{ present = $zengarPresent }
    if ($zengarPresent) {
        # Install-completeness fact (field lesson: media-only/partial installs exist,
        # and missing core files are a classic corrupt-install signature). Stating
        # WHICH expected files are absent is a fact; the engineer-side triage tooling
        # turns a non-empty list into the incomplete-install flag.
        $zengarBlock.coreFilesMissing = @(
            foreach ($core in @('NO.exe', 'components.xml', 'maintenancetool.ini', 'network.xml')) {
                if (-not (Test-Path (Join-Path $ZengarRoot $core))) { $core }
            }
        )
        $zengarBlock.productVersionIni = $repoInfo.ProductVersion
        # Derived environment fact (FI-009): the repo path segments
        # 'neuroptimal_v<N>/<Channel>' identify the box's product line and
        # backend channel (dev/staging/released). Triage starts at the header —
        # this answers "which environment is this box" without opening a
        # collector file. A derived string is a fact, not a verdict (§3.4).
        try {
            $zengarBlock.repositoryChannels = @(
                @($repoInfo.Repositories) | ForEach-Object { "$($_.url)" } |
                    ForEach-Object { if ($_ -match 'repository/(neuroptimal_v\d+/[^/\s]+)') { $matches[1] } } |
                    Where-Object { $_ } | Sort-Object -Unique
            )
        } catch { }
        try {
            $noExe = Join-Path $ZengarRoot 'NO.exe'
            if (Test-Path $noExe) {
                $zengarBlock.noExeVersion = "$((Get-Item -LiteralPath $noExe).VersionInfo.FileVersion)"
                $zengarBlock.noExeSha256  = (Get-FileHash -LiteralPath $noExe -Algorithm SHA256).Hash
            }
        } catch { }
        try {
            $xmlPath = Join-Path $ZengarRoot 'components.xml'
            if (Test-Path $xmlPath) {
                [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                $pkgs = $xml.SelectNodes('//Package')
                $zengarBlock.packageCount = $pkgs.Count
                $dates = @($pkgs | ForEach-Object { "$($_.InstallDate)" } | Where-Object { $_ })
                if ($dates.Count -gt 0) { $zengarBlock.latestInstallDate = ($dates | Sort-Object -Descending | Select-Object -First 1) }
            }
        } catch { }
    }

    $osBuild = try { "$((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber)" } catch { "$([System.Environment]::OSVersion.Version.Build)" }

    $manifest = [ordered]@{
        report       = 'SUPPORT-BUNDLE'
        v            = 1
        ts           = [datetime]::Now.ToString('o')
        runId        = $RunId
        caseId       = $CaseId
        computer     = $env:COMPUTERNAME
        osBuild      = $osBuild
        elevated     = $elevated
        probeVersion = $script:SupportBundleProbeVersion
        zengar       = $zengarBlock
        collectors   = @($collectorEntries | ForEach-Object {
            $row = [ordered]@{ id = $_.id; status = $_.status }
            if ($_.ContainsKey('ms') -and $null -ne $_.ms) { $row.ms = $_.ms }
            if ($_.reason)  { $row.reason = $_.reason }
            if ($_.error)   { $row.error = $_.error }
            if ($_.hresult) { $row.hresult = $_.hresult }
            if ($_.ContainsKey('timeoutSeconds')) { $row.timeoutSeconds = $_.timeoutSeconds }
            if ($_.files)   { $row.files = $_.files }
            $row
        })
        counts       = $counts
        truncations  = @($truncations)
    }

    $manifestPath = Join-Path $RunFolder 'manifest.json'
    try {
        $manifest | ConvertTo-Json -Depth 12 | Out-File -FilePath $manifestPath -Encoding UTF8 -Force
    } catch {
        # Last-ditch: a bundle without a manifest is still better than no bundle
        "{ `"report`": `"SUPPORT-BUNDLE`", `"v`": 1, `"error`": `"manifest serialization failed`" }" |
            Out-File -FilePath $manifestPath -Encoding UTF8 -Force
    }

    return @{
        Manifest     = $manifest
        ManifestPath = $manifestPath
        Counts       = $counts
        Truncations  = @($truncations)
    }
}

# =============================================================================
# BUNDLE COMPOSER — run folder + collection + ZIP. Never throws; the ZIP is
# written and returned no matter how many collectors failed (§3.1). Upload is
# the CALLER's job (App.ps1 handler) via DiagnosticsUpload -Channel Support.
# =============================================================================
function New-WinConfigSupportBundle {
    <#
    .SYNOPSIS
        Creates a run, executes all collectors, and compresses the bundle ZIP:
        support_<host>_<yyyyMMdd-HHmmss>_<runid>.zip
    .OUTPUTS
        Hashtable: RunId, RunFolder, ZipPath (null only if packaging itself failed),
        SizeBytes, CaseId, Manifest, Counts, Error
    #>
    [CmdletBinding()]
    param(
        [string]$CaseId = '',
        [object[]]$Collectors = $null,
        [string]$ZengarRoot = $script:ZengarRootDefault,
        [string]$StagingRoot = $script:StagingRootDefault,
        [nullable[bool]]$ElevatedOverride = $null,
        [scriptblock]$ProgressCallback = $null
    )

    $result = @{
        RunId = $null; RunFolder = $null; ZipPath = $null; SizeBytes = $null
        CaseId = $null; Manifest = $null; Counts = $null; Error = $null
    }

    try {
        $result.CaseId = ConvertTo-WinConfigSupportCaseId -CaseId $CaseId

        if (-not (Get-Command New-WinConfigDiagnosticRun -ErrorAction SilentlyContinue)) {
            $pkgModule = Join-Path $PSScriptRoot 'DiagnosticsPackage.psm1'
            if (Test-Path $pkgModule) { Import-Module $pkgModule -Force -Global }
        }
        if (-not (Get-Command New-WinConfigDiagnosticRun -ErrorAction SilentlyContinue)) {
            $result.Error = 'DiagnosticsPackage.psm1 not available; cannot create run folder'
            return $result
        }

        $run = New-WinConfigDiagnosticRun -ToolId $script:SupportBundleToolId
        $result.RunId = $run.RunId
        $result.RunFolder = $run.RunFolder

        $collection = Invoke-WinConfigSupportCollection `
            -RunFolder $run.RunFolder `
            -RunId $run.RunId `
            -CaseId $result.CaseId `
            -Collectors $Collectors `
            -ZengarRoot $ZengarRoot `
            -ElevatedOverride $ElevatedOverride `
            -ProgressCallback $ProgressCallback

        $result.Manifest = $collection.Manifest
        $result.Counts   = $collection.Counts

        $stamp = [datetime]::Now.ToString('yyyyMMdd-HHmmss')
        $pkg = Compress-WinConfigDiagnosticRun `
            -RunFolder $run.RunFolder `
            -ExportsRoot $run.ExportsRoot `
            -Label "$($env:COMPUTERNAME)_$stamp" `
            -Prefix 'support'
        $result.ZipPath   = $pkg.ZipPath
        $result.SizeBytes = $pkg.SizeBytes
    } catch {
        # §3.1: never throw. Report the failure; if collection succeeded but
        # compression failed, the run folder path is still in the result.
        $result.Error = $_.Exception.Message
    }

    return $result
}

Export-ModuleMember -Function @(
    'ConvertTo-WinConfigSupportCaseId'
    'Get-WinConfigSupportCaseIdPrefill'
    'Test-WinConfigSupportPathAllowed'
    'Add-WinConfigSupportBundleFile'
    'Get-WinConfigSupportRepositoryInfo'
    'Test-WinConfigSupportElevation'
    'Get-WinConfigSupportCollectors'
    'Invoke-WinConfigSupportCollection'
    'New-WinConfigSupportBundle'
)

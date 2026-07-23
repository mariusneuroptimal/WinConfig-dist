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
$script:SupportBundleProbeVersion = '1.1.1'
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

# FI-004 (2026-07-22): NO 4.x drives the zAmp through WinUSB + NI-VISA, and
# ZEN-ZAMP-001 inspects zAmpLoader\driver — a directory that does not exist on
# a healthy 4.x box. These are the load-bearing VISA DLLs NO.exe loads from
# System32; their presence/versions are the 4.x amp-stack facts.
$script:VisaSystemDlls = @('nivisa64.dll', 'NiViSv64.dll', 'visa64.dll', 'visaUtilities.dll', 'visaConfMgr.dll')

# MsiInstaller 1918 field lesson: ODBC "driver could not be loaded" events were
# falsely escalated; the documented triage move is checking the CURRENT ODBC
# registration, both registry views. HKLM ODBCINST.INI is world-readable.
$script:OdbcInstRegPaths = @(
    @{ view = '64-bit'; path = 'HKLM:\SOFTWARE\ODBC\ODBCINST.INI' }
    @{ view = '32-bit'; path = 'HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI' }
)

# Caps (size target for the whole bundle: < 10 MB — §7)
$script:InstallLogTailLines  = 2000
$script:SetupApiTailLines    = 3000
$script:EventSliceMax        = 250
$script:TreeListingMaxItems  = 5000
$script:StagingMaxDirs       = 200
$script:WebView2MaxSiblings  = 20
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
    $lines = $null
    if ($Transform -eq 'RedactInstallationLog') {
        $lines = @(Get-Content -LiteralPath $SourcePath -ErrorAction Stop) -replace `
            '(?i)((?:passwd|password)\s*=\s*)(?:"[^"]*"|''[^'']*''|[^;\s"'']+)', '$1<redacted>' -replace `
            '(?i)(licensecode\s*=\s*)(?:"[^"]*"|''[^'']*''|[^;\s"'']+)', '$1<redacted>'
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
                @{
                    # transform is a fact, not a verdict: it tells the engineer the
                    # shipped file is post-redaction (FI-007), so a '<redacted>'
                    # token in it is our doing, not the installer's.
                    Facts = @{ present = $true; totalLines = $lineCount; tailCap = $Context.Caps.InstallLogTailLines; transform = 'RedactInstallationLog' }
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
            Id = 'ZEN-INI-001'; Ring = 1; RequiresAdmin = $false; RequiresZengar = $true
            Script = {
                param($Context)
                # NO.ini + splashscreen.ini ship verbatim (LabVIEW config corruption is a
                # live failure class). maintenancetool.ini is NEVER copied — its whitelisted
                # fields ship via ZEN-REPO-001 / ZEN-VERSION-001 (§6).
                $files = @()
                foreach ($name in @('NO.ini', 'splashscreen.ini')) {
                    $p = Join-Path $Context.ZengarRoot $name
                    if (Test-Path $p) { $files += @{ SourcePath = $p; TargetName = $name } }
                }
                $facts = @{
                    collected                 = @($files | ForEach-Object { $_.TargetName })
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
                $events = @()
                try {
                    $raw = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
                        Id      = @(3077, 3033, 3004)
                    } -MaxEvents $Context.Caps.EventSliceMax -ErrorAction Stop
                    $events = @($raw | ForEach-Object {
                        @{ id = $_.Id; time = $_.TimeCreated.ToString('o'); message = "$($_.Message)".Substring(0, [Math]::Min(500, "$($_.Message)".Length)) }
                    })
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { throw }
                }
                @{ Facts = @{ eventCount = $events.Count; events = $events; cap = $Context.Caps.EventSliceMax } }
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
                $metaKeys = @('AppName', 'AppPath', 'EventType', 'EventTime', 'ReportStatus',
                              'Sig[0].Value', 'Sig[1].Value', 'Sig[2].Value', 'Sig[3].Value', 'Sig[6].Value', 'Sig[7].Value')
                foreach ($root in $roots) {
                    if (-not (Test-Path $root)) { continue }
                    $dirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match 'NO\.exe' -or $_.Name -match '_NO\.exe_' }
                    foreach ($dir in $dirs | Select-Object -First 20) {
                        $wer = Join-Path $dir.FullName 'Report.wer'
                        $meta = @{ reportDir = $dir.Name; mtime = $dir.LastWriteTime.ToString('o') }
                        if (Test-Path $wer) {
                            foreach ($line in (Get-Content -LiteralPath $wer -ErrorAction SilentlyContinue)) {
                                foreach ($k in $metaKeys) {
                                    if ($line -like "$k=*") { $meta[$k] = $line.Substring($k.Length + 1) }
                                }
                            }
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
        OdbcInstRegPaths = $script:OdbcInstRegPaths
        Caps             = @{
            InstallLogTailLines = $script:InstallLogTailLines
            SetupApiTailLines   = $script:SetupApiTailLines
            EventSliceMax       = $script:EventSliceMax
            TreeListingMaxItems = $script:TreeListingMaxItems
            StagingMaxDirs      = $script:StagingMaxDirs
            WebView2MaxSiblings = $script:WebView2MaxSiblings
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

# PpfFingerprint.psm1 - Problem Pattern Fingerprint generator for WinConfig
# Produces a deterministic, low-entropy fingerprint for clustering and correlation
#
# CONTRACT:
# - PPF MUST be generated exactly ONCE per session (at finalization)
# - PPF computation MUST be <1ms overhead
# - PPF payload MUST be <200 bytes
# - PPF MUST be deterministic across runs (same inputs → same hash)
# - PPF MUST be stable across noisy fields (timestamp excluded)
# - This module is PURE (no mutations, no network calls)
#
# LIFECYCLE:
# - Called by Finalize-Session AFTER diagnostic results are frozen
# - Called BEFORE session ledger is sealed
# - NEVER recomputed after finalization

# Direct execution guard
if ($MyInvocation.InvocationName -like "*.psm1" -or $MyInvocation.InvocationName -like "*\*") {
    throw "FATAL: PSM1 files must never be executed directly. Use Import-Module instead."
}

# =============================================================================
# PPF SCHEMA CONSTANTS
# =============================================================================

$script:PPF_SCHEMA_VERSION = 1

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Get-LatencyBucket {
    <#
    .SYNOPSIS
        Buckets latency into Normal/Elevated/Severe categories.
    .PARAMETER LatencyMs
        Latency value in milliseconds.
    #>
    param([double]$LatencyMs)

    if ($LatencyMs -le 100) { return "Normal" }
    elseif ($LatencyMs -le 300) { return "Elevated" }
    else { return "Severe" }
}

function Get-OsBucket {
    <#
    .SYNOPSIS
        Creates a bucketed OS identity string.
    .DESCRIPTION
        Format: OSName|SKU|MajorBuild (e.g., Windows11|Pro|22631)
    #>
    param(
        [string]$OsName = $null,
        [string]$OsSku = $null,
        [int]$OsBuild = 0
    )

    # Get OS info if not provided
    if (-not $OsName -or -not $OsSku -or $OsBuild -eq 0) {
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            if (-not $OsName) {
                # Normalize OS name
                $caption = $osInfo.Caption
                if ($caption -match "Windows 11") { $OsName = "Windows11" }
                elseif ($caption -match "Windows 10") { $OsName = "Windows10" }
                elseif ($caption -match "Windows Server") { $OsName = "WindowsServer" }
                else { $OsName = "Windows" }
            }
            if (-not $OsSku) {
                # Get SKU (Pro, Home, Enterprise, etc.)
                $sku = $osInfo.OperatingSystemSKU
                $OsSku = switch ($sku) {
                    48 { "Pro" }
                    49 { "ProN" }
                    4  { "Enterprise" }
                    27 { "EnterpriseN" }
                    1  { "Home" }
                    101 { "Home" }
                    default { "Unknown" }
                }
            }
            if ($OsBuild -eq 0) {
                $OsBuild = [int]$osInfo.BuildNumber
            }
        }
        catch {
            # Fallback values
            if (-not $OsName) { $OsName = "Windows" }
            if (-not $OsSku) { $OsSku = "Unknown" }
            if ($OsBuild -eq 0) { $OsBuild = 0 }
        }
    }

    return "$OsName|$OsSku|$OsBuild"
}

function Build-CanonicalString {
    <#
    .SYNOPSIS
        Constructs the canonical string for PPF hashing.
    .DESCRIPTION
        Builds a deterministic string with explicit section headers and ordering.
        NetworkClass is a single opinionated value: wired|wifi|vpn|cellular|unknown
        Includes NO_DIAGNOSTICS_RUN flag for sessions without test operations.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$PpfData
    )

    $sb = [System.Text.StringBuilder]::new()

    # Schema version
    [void]$sb.AppendLine("PPF_SCHEMA=$($script:PPF_SCHEMA_VERSION)")

    # Session state flag (NO_DIAGNOSTICS_RUN if no tests were executed)
    if ($PpfData.NoDiagnosticsRun) {
        [void]$sb.AppendLine("STATE=NO_DIAGNOSTICS_RUN")
    }

    # Failures section (sorted lexicographically)
    [void]$sb.AppendLine("FAILURES=")
    $sortedFailures = $PpfData.Failures | Sort-Object
    foreach ($failure in $sortedFailures) {
        [void]$sb.AppendLine("  $failure")
    }

    # OS section
    [void]$sb.AppendLine("OS=")
    [void]$sb.AppendLine("  $($PpfData.OsBucket)")

    # Network section - single opinionated class + flags
    [void]$sb.AppendLine("NETWORK=")
    [void]$sb.AppendLine("  Class=$($PpfData.NetworkClass)")
    [void]$sb.AppendLine("  IPv6=$($PpfData.Network.IPv6Enabled.ToString().ToLower())")
    [void]$sb.AppendLine("  Latency=$($PpfData.Network.LatencyBucket)")

    # Software section
    [void]$sb.AppendLine("SOFTWARE=")
    [void]$sb.AppendLine("  ThirdPartyAV=$($PpfData.Software.ThirdPartyAV.ToString().ToLower())")
    [void]$sb.AppendLine("  OEMBluetoothStack=$($PpfData.Software.OEMBluetoothStack.ToString().ToLower())")

    return $sb.ToString()
}

function Get-PpfHash {
    <#
    .SYNOPSIS
        Computes SHA-256 hash and truncates to 8 hex bytes (32 bits).
    .PARAMETER CanonicalString
        The canonical string to hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalString
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($CanonicalString)
        $hashBytes = $sha256.ComputeHash($bytes)
        # Take first 4 bytes (8 hex chars)
        $truncated = $hashBytes[0..3]
        $hexString = ($truncated | ForEach-Object { $_.ToString("X2") }) -join ""
        return "PPF-$hexString"
    }
    finally {
        $sha256.Dispose()
    }
}

# =============================================================================
# CORE FUNCTION
# =============================================================================

function New-ProblemPatternFingerprint {
    <#
    .SYNOPSIS
        Generates a Problem Pattern Fingerprint from session operations.
    .DESCRIPTION
        Computes a deterministic fingerprint by analyzing:
        - Failing diagnostic checks (FAIL + WARN only)
        - OS identity (bucketed)
        - Network characteristics (class-based)
        - Installed software signals (boolean flags)

        The fingerprint is a SHA-256 hash truncated to 8 hex bytes.
        This function is PURE (no mutations, no side effects).
    .PARAMETER Operations
        Array of session operations from the ledger.
    .PARAMETER OsName
        Optional OS name override (for testing).
    .PARAMETER OsSku
        Optional OS SKU override (for testing).
    .PARAMETER OsBuild
        Optional OS build number override (for testing).
    .PARAMETER NetworkEvidence
        Optional hashtable with network characteristics (for testing).
    .PARAMETER SoftwareEvidence
        Optional hashtable with software signals (for testing).
    .OUTPUTS
        PSCustomObject with PPF data:
        - Id: PPF-XXXXXXXX format
        - Schema: Schema version
        - FailureCount: Number of failures
        - Failures: Array of failure strings
        - OsBucket: OS identity string
        - NetworkClass: Network characteristics string
        - CanonicalString: The string that was hashed
        - Markdown: Copy-paste ready markdown block
    .EXAMPLE
        $ppf = New-ProblemPatternFingerprint -Operations $ops
        Write-Host "PPF ID: $($ppf.Id)"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Operations = @(),

        [Parameter(Mandatory = $false)]
        [string]$OsName = $null,

        [Parameter(Mandatory = $false)]
        [string]$OsSku = $null,

        [Parameter(Mandatory = $false)]
        [int]$OsBuild = 0,

        [Parameter(Mandatory = $false)]
        [hashtable]$NetworkEvidence = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$SoftwareEvidence = $null
    )

    # ==========================================================================
    # 0. Detect NO_DIAGNOSTICS_RUN condition
    # A session without diagnostic tests gets PPF-EMPTY sentinel
    # ==========================================================================
    $diagnosticOps = @($Operations | Where-Object { $_.OperationType -eq "Test" })
    $noDiagnosticsRun = ($null -eq $Operations -or $Operations.Count -eq 0 -or $diagnosticOps.Count -eq 0)

    # ==========================================================================
    # 1. Extract Failures (FAIL + WARN only, sorted lexicographically)
    # ==========================================================================
    $failures = [System.Collections.Generic.List[string]]::new()

    foreach ($op in $Operations) {
        if ($op.Result -eq "Failed") {
            # Format: FAIL:Category.Name
            $failureId = "FAIL:$($op.Category).$($op.Name -replace '\s+', '')"
            if (-not $failures.Contains($failureId)) {
                $failures.Add($failureId)
            }
        }
        elseif ($op.Result -eq "Warning") {
            # Format: WARN:Category.Name
            $warnId = "WARN:$($op.Category).$($op.Name -replace '\s+', '')"
            if (-not $failures.Contains($warnId)) {
                $failures.Add($warnId)
            }
        }
    }

    # ==========================================================================
    # 2. Get OS Identity (bucketed)
    # ==========================================================================
    $osBucket = Get-OsBucket -OsName $OsName -OsSku $OsSku -OsBuild $OsBuild

    # ==========================================================================
    # 3. Extract Network Characteristics
    # ==========================================================================
    $networkData = @{
        IPv6Enabled    = $false
        VpnDetected    = $false
        ProxyDetected  = $false
        LatencyBucket  = "Normal"
        ConnectionType = $null   # wired | wifi | vpn | cellular | unknown
    }

    if ($NetworkEvidence) {
        # Use provided evidence (for testing)
        if ($null -ne $NetworkEvidence.IPv6Enabled) { $networkData.IPv6Enabled = [bool]$NetworkEvidence.IPv6Enabled }
        if ($null -ne $NetworkEvidence.VpnDetected) { $networkData.VpnDetected = [bool]$NetworkEvidence.VpnDetected }
        if ($null -ne $NetworkEvidence.ProxyDetected) { $networkData.ProxyDetected = [bool]$NetworkEvidence.ProxyDetected }
        if ($null -ne $NetworkEvidence.LatencyMs) { $networkData.LatencyBucket = Get-LatencyBucket -LatencyMs $NetworkEvidence.LatencyMs }
        if ($null -ne $NetworkEvidence.LatencyBucket) { $networkData.LatencyBucket = $NetworkEvidence.LatencyBucket }
        if ($null -ne $NetworkEvidence.ConnectionType) { $networkData.ConnectionType = $NetworkEvidence.ConnectionType }
    }
    else {
        # Extract from operations evidence
        foreach ($op in $Operations) {
            if ($op.Evidence) {
                if ($null -ne $op.Evidence.IPv6Enabled) { $networkData.IPv6Enabled = [bool]$op.Evidence.IPv6Enabled }
                if ($null -ne $op.Evidence.VpnDetected) { $networkData.VpnDetected = [bool]$op.Evidence.VpnDetected }
                if ($null -ne $op.Evidence.ProxyDetected) { $networkData.ProxyDetected = [bool]$op.Evidence.ProxyDetected }
                if ($null -ne $op.Evidence.LatencyMs) { $networkData.LatencyBucket = Get-LatencyBucket -LatencyMs $op.Evidence.LatencyMs }
                if ($null -ne $op.Evidence.ConnectionType) { $networkData.ConnectionType = $op.Evidence.ConnectionType }
            }
        }
    }

    # ==========================================================================
    # 4. Extract Software Signals (boolean flags only)
    # ==========================================================================
    $softwareData = @{
        ThirdPartyAV      = $false
        OEMBluetoothStack = $false
    }

    if ($SoftwareEvidence) {
        # Use provided evidence (for testing)
        if ($null -ne $SoftwareEvidence.ThirdPartyAV) { $softwareData.ThirdPartyAV = [bool]$SoftwareEvidence.ThirdPartyAV }
        if ($null -ne $SoftwareEvidence.OEMBluetoothStack) { $softwareData.OEMBluetoothStack = [bool]$SoftwareEvidence.OEMBluetoothStack }
    }
    else {
        # Extract from operations evidence
        foreach ($op in $Operations) {
            if ($op.Evidence) {
                if ($null -ne $op.Evidence.ThirdPartyAV) { $softwareData.ThirdPartyAV = [bool]$op.Evidence.ThirdPartyAV }
                if ($null -ne $op.Evidence.OEMBluetoothStack) { $softwareData.OEMBluetoothStack = [bool]$op.Evidence.OEMBluetoothStack }
            }
        }
    }

    # ==========================================================================
    # 5. Derive Network Class (opinionated single value)
    # Priority: vpn > cellular > wired > wifi > unknown
    # VPN takes priority because it affects all routing regardless of underlying transport
    # Wired (Ethernet) takes priority over wifi when both are present (dual-connection)
    # Must happen BEFORE canonical string generation
    # ==========================================================================
    $networkClass = if ($networkData.VpnDetected) {
        "vpn"
    }
    elseif ($networkData.ConnectionType -match "Cellular|LTE|5G|4G|WWAN") {
        "cellular"
    }
    elseif ($networkData.ConnectionType -match "Ethernet|Wired") {
        # Ethernet takes priority over Wi-Fi in dual-connection scenarios
        "wired"
    }
    elseif ($networkData.ConnectionType -match "Wi-Fi|Wireless") {
        "wifi"
    }
    elseif ($networkData.ConnectionType) {
        # Have connection type but doesn't match known patterns
        "unknown"
    }
    else {
        # No connection type data available
        "unknown"
    }

    # ==========================================================================
    # 6. Build Canonical String and Hash
    # ==========================================================================
    # Sort failures for determinism BEFORE building canonical string and output
    $sortedFailures = @($failures | Sort-Object)

    $ppfData = @{
        NoDiagnosticsRun = $noDiagnosticsRun
        Failures         = $sortedFailures
        OsBucket         = $osBucket
        NetworkClass     = $networkClass
        Network          = $networkData
        Software         = $softwareData
    }

    $canonicalString = Build-CanonicalString -PpfData $ppfData

    # Generate PPF ID - use sentinel for no-diagnostics sessions
    $ppfId = if ($noDiagnosticsRun) {
        "PPF-EMPTY"
    }
    else {
        Get-PpfHash -CanonicalString $canonicalString
    }

    # ==========================================================================
    # 7. Generate Markdown Summary
    # ==========================================================================
    $mdBuilder = [System.Text.StringBuilder]::new()
    [void]$mdBuilder.AppendLine("## Problem Pattern Fingerprint")
    [void]$mdBuilder.AppendLine("")
    [void]$mdBuilder.AppendLine("**PPF:** ``$ppfId``  ")
    [void]$mdBuilder.AppendLine("**Schema:** v$($script:PPF_SCHEMA_VERSION)  ")
    if ($noDiagnosticsRun) {
        [void]$mdBuilder.AppendLine("**State:** NO_DIAGNOSTICS_RUN  ")
    }
    [void]$mdBuilder.AppendLine("")

    # Failure Signature
    [void]$mdBuilder.AppendLine("### Failure Signature")
    if ($noDiagnosticsRun) {
        [void]$mdBuilder.AppendLine("- No diagnostics were executed")
    }
    elseif ($sortedFailures.Count -eq 0) {
        [void]$mdBuilder.AppendLine("- No failures detected")
    }
    else {
        foreach ($f in $sortedFailures) {
            if ($f.StartsWith("FAIL:")) {
                $name = $f -replace '^FAIL:', ''
                [void]$mdBuilder.AppendLine("- [X] $name")
            }
            elseif ($f.StartsWith("WARN:")) {
                $name = $f -replace '^WARN:', ''
                [void]$mdBuilder.AppendLine("- [!] $name")
            }
        }
    }
    [void]$mdBuilder.AppendLine("")

    # Environment
    [void]$mdBuilder.AppendLine("### Environment")

    # Parse OS bucket for display
    $osParts = $osBucket -split '\|'
    $osDisplay = if ($osParts.Count -ge 3) {
        "$($osParts[0] -replace 'Windows', 'Windows ') $($osParts[1]) ($($osParts[2]))"
    }
    else {
        $osBucket
    }
    [void]$mdBuilder.AppendLine("- OS: $osDisplay")

    # Network summary
    $networkSummary = @()
    if ($networkData.IPv6Enabled) { $networkSummary += "IPv6 enabled" } else { $networkSummary += "IPv4 only" }
    if ($networkData.VpnDetected) { $networkSummary += "VPN detected" } else { $networkSummary += "no VPN" }
    if ($networkData.ProxyDetected) { $networkSummary += "proxy detected" }
    if ($networkData.LatencyBucket -ne "Normal") { $networkSummary += "$($networkData.LatencyBucket.ToLower()) latency" }
    [void]$mdBuilder.AppendLine("- Network: $($networkSummary -join ', ')")

    # Software summary
    $softwareSummary = @()
    if ($softwareData.ThirdPartyAV) { $softwareSummary += "Third-party AV detected" }
    if ($softwareData.OEMBluetoothStack) { $softwareSummary += "OEM Bluetooth stack" }
    if ($softwareSummary.Count -eq 0) { $softwareSummary += "Standard configuration" }
    [void]$mdBuilder.AppendLine("- Software: $($softwareSummary -join ', ')")
    [void]$mdBuilder.AppendLine("")

    $markdown = $mdBuilder.ToString()

    # ==========================================================================
    # 8. Return PPF Object
    # ==========================================================================
    return [PSCustomObject]@{
        Id               = $ppfId
        Schema           = $script:PPF_SCHEMA_VERSION
        NoDiagnosticsRun = $noDiagnosticsRun
        FailureCount     = $sortedFailures.Count
        Failures         = $sortedFailures
        OsBucket         = $osBucket
        NetworkClass     = $networkClass
        Network          = $networkData
        Software         = $softwareData
        CanonicalString  = $canonicalString
        Markdown         = $markdown
    }
}

# =============================================================================
# MODULE EXPORTS
# =============================================================================

Export-ModuleMember -Function @(
    'New-ProblemPatternFingerprint'
)

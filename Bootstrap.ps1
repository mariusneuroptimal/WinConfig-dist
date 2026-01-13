#Requires -Version 5.1
<#
.SYNOPSIS
    Hardened bootstrap launcher for WinConfig.

.DESCRIPTION
    Downloads WinConfig files from the public distribution repository,
    verifies integrity via SHA-256 hash pinning, stages to a temp
    directory, and executes.

.NOTES
    TRUST MODEL:
    - Source repo (private): mariusneuroptimal/WinConfig
    - Dist repo (public): mariusneuroptimal/WinConfig-dist
    - Bootstrap fetches from dist repo (unauthenticated)
    - CI publishes verified artifacts from source to dist

    ENVIRONMENT MODEL:
    - Branch = environment (main=production, develop=staging)
    - Default is main (press Enter at prompt)

    STAGING MODEL:
    - Files are staged to %TEMP%\winconfig-<guid>\
    - Directory structure is preserved (src/, src/Logging/, etc.)
    - $PSScriptRoot works correctly for module imports
    - Cleanup occurs on exit

    PREREQUISITES:
    - PowerShell 5.1 or later
    - Internet access to raw.githubusercontent.com

    SECURITY CONTROLS:
    - Branch allow-list (fail-closed)
    - Per-file SHA-256 hash verification from manifest.json
    - TLS 1.2+ enforced
    - No embedded credentials required
    - Staged execution (not in-memory)
    - Explicit ExecutionPolicy bypass for staged scripts

.PARAMETER Environment
    Optional. Specify 'staging' or 'production' to skip interactive prompt.
    If not provided, prompts for input (legacy behavior).

.PARAMETER Verbose
    Show detailed verification output (file-by-file hashes, dependency checks).
    Also enabled by: WINCONFIG_DIAGNOSTICS=1 environment variable.

.PARAMETER Debug
    Superset of -Verbose. Adds timing information (elapsed ms per phase) and
    call-site info for each status line. Enable with WINCONFIG_DIAGNOSTICS=2.

.PARAMETER Quiet
    Suppress all output including compact summary. Silent launch mode.
    Errors still show. Useful for scripted/automated launches.

.PARAMETER SelfCheck
    Verify-only mode. Downloads, verifies integrity and dependencies, then
    exits without launching the application. Use for installation verification.
    Returns explicit exit codes for scripting:
      0  - All checks passed
      10 - Manifest fetch failed
      11 - Hash verification failed
      12 - Dependency validation failed
      13 - Environment authorization failed
      14 - Module loader failed

.EXAMPLE
    # Basic usage (production) - compact output
    .\Bootstrap.ps1

.EXAMPLE
    # Staging environment
    .\Bootstrap.ps1 -Environment staging

.EXAMPLE
    # Verbose mode - show all verification details
    .\Bootstrap.ps1 -Verbose

.EXAMPLE
    # Debug mode - verbose + timing + call-site info
    .\Bootstrap.ps1 -Debug

.EXAMPLE
    # Silent launch - no output unless error
    .\Bootstrap.ps1 -Environment production -Quiet

.EXAMPLE
    # Self-check mode - verify without launching
    .\Bootstrap.ps1 -SelfCheck
#>
param(
    [Parameter()]
    [ValidateSet('staging', 'production', '')]
    [string]$Environment = '',

    [Parameter()]
    [switch]$SimulateProd,  # CI mode: download, verify, import modules, exit before GUI

    [Parameter()]
    [switch]$Verbose,       # Show detailed verification output

    [Parameter()]
    [switch]$Debug,         # Superset of Verbose: adds timing + call-site info

    [Parameter()]
    [switch]$Quiet,         # Suppress even compact summary (silent launch)

    [Parameter()]
    [switch]$SelfCheck      # Verify-only mode, don't launch
)

# ============================================================================
# CONFIGURATION - TRUST ANCHORS
# ============================================================================

# Bootstrap version - update when Bootstrap.ps1 changes
$BootstrapVersion = "2.2.0"

# GitHub owner - HARDCODED TRUST ANCHOR (do not parameterize)
$GitHubOwner = "mariusneuroptimal"

# Distribution repository - PUBLIC (unauthenticated access)
$DistRepoName = "WinConfig-dist"

# Allowed branches (case-sensitive)
$AllowedBranches = @(
    "main"
    "develop"
)

# Entry point (executed after staging)
$EntryPoint = "Win11Config.ps1"

# ============================================================================
# VERBOSITY CONTROL - Progressive Disclosure
# ============================================================================
# Levels: Silent (0), Normal (1), Verbose (2), Debug (3)
# Default: Normal (compact output)
# Auto-escalates on any failure
#
# Exit Codes (for scripting):
#   0  - Success
#   1  - General/unknown failure
#   10 - Manifest fetch failed
#   11 - Hash verification failed
#   12 - Dependency validation failed
#   13 - Environment authorization failed
#   14 - Module loader failed

$script:VerbosityLevel = 1  # Normal by default
$script:BootstrapStartTime = [System.Diagnostics.Stopwatch]::StartNew()
$script:PhaseStartTime = $null

# Check for quiet mode (suppresses even compact summary)
if ($Quiet) {
    $script:VerbosityLevel = 0
}

# Check for explicit verbose/debug request (overrides quiet)
if ($Verbose -or $SelfCheck -or $SimulateProd) {
    $script:VerbosityLevel = 2
}
if ($Debug) {
    $script:VerbosityLevel = 3  # Debug is superset of Verbose
}

# Check environment variable override
if ($env:WINCONFIG_DIAGNOSTICS -eq '1') {
    $script:VerbosityLevel = 2
}
if ($env:WINCONFIG_DIAGNOSTICS -eq '2') {
    $script:VerbosityLevel = 3
}

# Log buffer for deferred output (shown on failure)
$script:LogBuffer = [System.Collections.ArrayList]::new()
$script:LogBufferMaxLines = 5000
$script:LogBufferTruncated = $false
$script:HasError = $false
$script:FailureDumped = $false
$script:BufferFrozen = $false

# ============================================================================
# SECURITY SETUP
# ============================================================================

# Enforce TLS 1.2 or higher
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-Sha256Hash {
    param([string]$Content)
    # Normalize line endings to LF for consistent hashing
    $normalizedContent = $Content -replace "`r`n", "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalizedContent)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Start-Phase {
    <#
    .SYNOPSIS
        Marks the start of a timed phase (Debug mode).
    #>
    param([string]$PhaseName)
    $script:CurrentPhase = $PhaseName
    $script:PhaseStartTime = [System.Diagnostics.Stopwatch]::StartNew()
}

function Get-DebugPrefix {
    <#
    .SYNOPSIS
        Returns timing and call-site info for Debug mode.
    #>
    $elapsed = $script:BootstrapStartTime.ElapsedMilliseconds
    $phaseMs = if ($script:PhaseStartTime) { $script:PhaseStartTime.ElapsedMilliseconds } else { 0 }

    # Get caller info (skip this function and Write-Status/Write-BufferedLog)
    $caller = (Get-PSCallStack)[2]
    $callerInfo = if ($caller.FunctionName -and $caller.FunctionName -ne '<ScriptBlock>') {
        $caller.FunctionName
    } else {
        "line:$($caller.ScriptLineNumber)"
    }

    return "[${elapsed}ms +${phaseMs}ms] [$callerInfo]"
}

function Add-ToBuffer {
    <#
    .SYNOPSIS
        Adds entry to log buffer with size cap enforcement.
    #>
    param([hashtable]$Entry)

    # Don't add to frozen buffer
    if ($script:BufferFrozen) { return }

    # Enforce buffer cap
    if ($script:LogBuffer.Count -ge $script:LogBufferMaxLines) {
        if (-not $script:LogBufferTruncated) {
            # Remove oldest entries (first 10%)
            $removeCount = [math]::Max(1, [int]($script:LogBufferMaxLines * 0.1))
            $script:LogBuffer.RemoveRange(0, $removeCount)
            [void]$script:LogBuffer.Insert(0, @{
                Line = "[TRUNCATED - oldest $removeCount entries removed]"
                Color = "DarkYellow"
                Type = "WARN"
            })
            $script:LogBufferTruncated = $true
        } else {
            # Already truncated, just remove oldest
            $script:LogBuffer.RemoveAt(1)  # Keep truncation notice at [0]
        }
    }

    [void]$script:LogBuffer.Add($Entry)
}

function Write-Status {
    <#
    .SYNOPSIS
        Verbosity-aware status output with log buffering.
    .DESCRIPTION
        Respects VerbosityLevel setting:
        - Level 1 (Normal): Buffers non-error output, shows on failure
        - Level 2 (Verbose): Shows immediately
        - Level 3 (Debug): Shows with timing and call-site info
        - Errors always shown immediately and set HasError flag
    #>
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [switch]$Force  # Always show regardless of verbosity
    )

    $color = switch ($Type) {
        "INFO"  { "Cyan" }
        "OK"    { "Green" }
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        default { "White" }
    }

    # Build line with optional debug prefix
    $debugPrefix = if ($script:VerbosityLevel -ge 3) { "$(Get-DebugPrefix) " } else { "" }
    $line = "$debugPrefix[$Type] $Message"
    $bufferLine = "[$Type] $Message"  # Buffer without debug prefix for cleaner dumps

    # Add to buffer (respects frozen state and cap)
    Add-ToBuffer @{ Line = $bufferLine; Color = $color; Type = $Type }

    # Errors always show immediately, flag failure, and freeze buffer
    if ($Type -eq "ERROR") {
        $script:HasError = $true
        $script:BufferFrozen = $true
        Write-Host $line -ForegroundColor $color
        return
    }

    # Show immediately if verbose/debug mode or forced
    if ($script:VerbosityLevel -ge 2 -or $Force) {
        Write-Host $line -ForegroundColor $color
    }
}

function Write-BufferedLog {
    <#
    .SYNOPSIS
        Writes a line to buffer (and optionally screen if verbose).
    #>
    param(
        [string]$Message,
        [string]$Color = "Gray",
        [switch]$NoNewline
    )

    # Add to buffer (respects frozen state and cap)
    Add-ToBuffer @{ Line = $Message; Color = $Color; NoNewline = $NoNewline }

    if ($script:VerbosityLevel -ge 2) {
        $debugPrefix = if ($script:VerbosityLevel -ge 3 -and -not $NoNewline) { "$(Get-DebugPrefix) " } else { "" }
        if ($NoNewline) {
            Write-Host $Message -ForegroundColor $Color -NoNewline
        } else {
            Write-Host "$debugPrefix$Message" -ForegroundColor $Color
        }
    }
}

function Show-FailureDump {
    <#
    .SYNOPSIS
        Dumps the full log buffer when an error occurs (auto-escalation).
        Single-shot: can only run once, buffer is frozen after first error.
    #>
    # Guard: single-shot only
    if ($script:FailureDumped) { return }
    $script:FailureDumped = $true
    $script:BufferFrozen = $true

    # Only show dump if we weren't already in verbose mode
    if ($script:VerbosityLevel -lt 2) {
        Write-Host ""
        Write-Host "--- Verification Log (auto-expanded due to error) ---" -ForegroundColor Yellow
        foreach ($entry in $script:LogBuffer) {
            if ($entry.NoNewline) {
                Write-Host $entry.Line -ForegroundColor $entry.Color -NoNewline
            } else {
                Write-Host $entry.Line -ForegroundColor $entry.Color
            }
        }
        Write-Host "--- End Log ---" -ForegroundColor Yellow
    }
}

function Get-RawGitHubContent {
    <#
    .SYNOPSIS
        Fetches raw file content from GitHub via raw.githubusercontent.com.
    .DESCRIPTION
        Uses unauthenticated access to the public distribution repository.
        Strips UTF-8 BOM if present for compatibility.
    #>
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Branch,
        [string]$Path
    )

    $url = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch/$Path"
    $ProgressPreference = 'SilentlyContinue'

    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        $content = $response.Content

        # Strip UTF-8 BOM if present (EF BB BF)
        if ($content.Length -ge 3) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
            if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                $content = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
            }
        }

        return $content
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        throw "Failed to fetch $Path (HTTP $statusCode)"
    }
}

function Get-DistManifest {
    <#
    .SYNOPSIS
        Fetches and parses manifest.json from the distribution repository.
    .DESCRIPTION
        Dist repo structure: main branch contains main/ and develop/ directories.
        URL: raw.githubusercontent.com/{owner}/{repo}/main/{environment}/manifest.json
    #>
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Environment  # "main" or "develop" (directory in dist repo)
    )

    # Dist repo uses single 'main' branch with environment directories
    $manifestContent = Get-RawGitHubContent -Owner $Owner -Repo $Repo -Branch "main" -Path "$Environment/manifest.json"
    return $manifestContent | ConvertFrom-Json
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Banner - only in verbose mode
if ($script:VerbosityLevel -ge 2) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  NeurOptimal Support Tool Launcher" -ForegroundColor Cyan
    Write-Host "  Bootstrap v$BootstrapVersion" -ForegroundColor DarkCyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# --- Step 1: Select Environment ---
Start-Phase "Environment Selection"
if ([string]::IsNullOrWhiteSpace($Environment)) {
    # Mask input for confidentiality (displays asterisks)
    $SecureInput = Read-Host -Prompt "Repository name" -AsSecureString
    $InputValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureInput)
    )
} else {
    $InputValue = $Environment
}

if ([string]::IsNullOrWhiteSpace($InputValue) -or $InputValue.Trim().ToLowerInvariant() -in @('winconfig', 'production')) {
    $Branch = "main"
    $EnvironmentLabel = "production"
}
elseif ($InputValue.Trim().ToLowerInvariant() -eq "staging") {
    $Branch = "develop"
    $EnvironmentLabel = "staging"
}
else {
    Write-Status "Invalid repository." "ERROR"
    exit 13  # Environment authorization failed
}

Write-Status "Running $EnvironmentLabel version" "INFO"

# --- Step 2: Validate Against Branch Allow-List ---
if ($Branch -notin $AllowedBranches) {
    Write-Status "Internal error: invalid branch mapping." "ERROR"
    exit 13  # Environment authorization failed
}

Write-Status "Environment authorized." "OK"

# --- Step 3: Fetch Manifest from Distribution Repo ---
Start-Phase "Manifest Fetch"
Write-BufferedLog ""
Write-Status "Fetching manifest from distribution repository..." "INFO"

try {
    $manifest = Get-DistManifest -Owner $GitHubOwner -Repo $DistRepoName -Environment $Branch
    Write-Status "Manifest loaded (commit: $($manifest.commit.Substring(0, 7)))" "OK"
} catch {
    Write-Status "Failed to fetch manifest: $($_.Exception.Message)" "ERROR"
    Show-FailureDump
    Write-Host ""
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Distribution repository not yet set up" -ForegroundColor Gray
    Write-Host "  - Network connectivity issues" -ForegroundColor Gray
    Write-Host "  - Branch '$Branch' not published to dist repo" -ForegroundColor Gray
    exit 10  # Manifest fetch failed
}

# Build file manifest hashtable from JSON
$FileManifest = @{}
foreach ($prop in $manifest.files.PSObject.Properties) {
    $FileManifest[$prop.Name] = $prop.Value
}

Write-Status "Found $($FileManifest.Count) files in manifest" "INFO"

# --- Step 4: Create Staging Directory ---
$stagingId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$stagingRoot = Join-Path $env:TEMP "winconfig-$stagingId"

Write-Status "Temp directory: $stagingRoot" "INFO"

try {
    New-Item -Path $stagingRoot -ItemType Directory -Force | Out-Null
} catch {
    Write-Status "Failed to create temp directory: $($_.Exception.Message)" "ERROR"
    Show-FailureDump
    exit 1
}

# --- Step 5: Download, Verify, and Stage Each File ---
Start-Phase "Download and Verify"
$allFilesValid = $true
$stagedFiles = @()
$filesVerified = 0
$filesFailed = 0

Write-BufferedLog ""
Write-Status "Downloading and verifying $($FileManifest.Count) files..." "INFO"

foreach ($filePath in $FileManifest.Keys) {
    $expectedHash = $FileManifest[$filePath]
    $shortHash = $expectedHash.Substring(0, 12)

    Write-BufferedLog "  $filePath ... " -Color "Gray" -NoNewline

    try {
        # Download file content from distribution repo
        # Dist repo structure: main branch with environment directories (main/, develop/)
        $content = Get-RawGitHubContent -Owner $GitHubOwner -Repo $DistRepoName -Branch "main" -Path "$Branch/$filePath"

        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-BufferedLog "EMPTY" -Color "Red"
            $allFilesValid = $false
            $filesFailed++
            continue
        }

        # Verify hash
        $actualHash = Get-Sha256Hash -Content $content

        if ($actualHash -ne $expectedHash) {
            Write-BufferedLog "HASH MISMATCH" -Color "Red"
            Write-BufferedLog "    Expected: $expectedHash" -Color "Yellow"
            Write-BufferedLog "    Actual:   $actualHash" -Color "Red"
            $allFilesValid = $false
            $filesFailed++
            continue
        }

        # Stage file to disk
        $localPath = Join-Path $stagingRoot ($filePath -replace '/', '\')
        $localDir = Split-Path $localPath -Parent

        if (-not (Test-Path $localDir)) {
            New-Item -Path $localDir -ItemType Directory -Force | Out-Null
        }

        # Write with UTF-8 encoding (no BOM for PS compatibility)
        [System.IO.File]::WriteAllText($localPath, $content, [System.Text.UTF8Encoding]::new($false))

        $stagedFiles += $localPath
        $filesVerified++
        Write-BufferedLog "OK ($shortHash...)" -Color "Green"

    } catch {
        Write-BufferedLog "FAILED ($($_.Exception.Message))" -Color "Red"
        $allFilesValid = $false
        $filesFailed++
    }
}

Write-BufferedLog ""

# --- Step 6: Fail Closed if Any File Invalid ---
if (-not $allFilesValid) {
    Write-Status "INTEGRITY CHECK FAILED - $filesFailed file(s) invalid" "ERROR"
    Show-FailureDump
    Write-Host ""
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Distribution repo out of sync" -ForegroundColor Gray
    Write-Host "  - Network or download issues" -ForegroundColor Gray
    Write-Host "  - Manifest corruption" -ForegroundColor Gray
    Write-Host ""
    Write-Status "Refusing to execute. Cleaning up..." "ERROR"

    # Cleanup staging directory
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 11  # Hash verification failed
}

Write-Status "All $filesVerified files verified and staged." "OK"

# --- Step 6b: Extract App Version from VERSION.psd1 ---
$versionFilePath = Join-Path $stagingRoot "src\VERSION.psd1"
$appVersion = "unknown"
$appName = "NeurOptimal Support Tool"
if (Test-Path $versionFilePath) {
    try {
        $versionData = Import-PowerShellDataFile $versionFilePath
        $appVersion = $versionData.Version
        if ($versionData.AppName) { $appName = $versionData.AppName }
    } catch {
        # Fail gracefully - continue with defaults
    }
}

# Version summary - only in verbose mode
if ($script:VerbosityLevel -ge 2) {
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Bootstrap:   v$BootstrapVersion" -ForegroundColor Gray
    Write-Host "  App:         v$appVersion ($EnvironmentLabel)" -ForegroundColor Gray
    Write-Host "  Manifest:    $($FileManifest.Count) files verified" -ForegroundColor Gray
    Write-Host "  Commit:      $($manifest.commit.Substring(0, 7))" -ForegroundColor Gray
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
}

# --- Step 6c: Validate Runtime Dependencies ---
Start-Phase "Dependency Validation"
$runtimeDepsPath = Join-Path $stagingRoot "src\RUNTIME_DEPENDENCIES.psd1"
$depsValid = $true
$depsCount = 0

if (Test-Path $runtimeDepsPath) {
    Write-BufferedLog ""
    Write-Status "Validating runtime dependencies..." "INFO"

    try {
        $runtimeDeps = Import-PowerShellDataFile $runtimeDepsPath
        $allModulesValid = $true

        # Assert all RequiredModules exist in staging AND are in manifest
        if ($runtimeDeps.RequiredModules) {
            foreach ($reqModule in $runtimeDeps.RequiredModules) {
                $modulePath = Join-Path $stagingRoot ($reqModule -replace '/', '\')
                $depsCount++

                if (-not (Test-Path $modulePath)) {
                    Write-BufferedLog "  [REQ] $reqModule ... " -Color "Gray" -NoNewline
                    Write-BufferedLog "MISSING" -Color "Red"
                    $allModulesValid = $false
                } elseif (-not $FileManifest.ContainsKey($reqModule)) {
                    Write-BufferedLog "  [REQ] $reqModule ... " -Color "Gray" -NoNewline
                    Write-BufferedLog "NOT IN MANIFEST" -Color "Red"
                    $allModulesValid = $false
                } else {
                    Write-BufferedLog "  [REQ] $reqModule ... " -Color "Gray" -NoNewline
                    Write-BufferedLog "OK" -Color "Green"
                }
            }
        }

        # Warn on missing optional modules
        if ($runtimeDeps.OptionalModules) {
            foreach ($optModule in $runtimeDeps.OptionalModules) {
                $modulePath = Join-Path $stagingRoot ($optModule -replace '/', '\')

                if (-not (Test-Path $modulePath)) {
                    Write-BufferedLog "  [OPT] $optModule ... " -Color "Gray" -NoNewline
                    Write-BufferedLog "MISSING (graceful)" -Color "Yellow"
                } else {
                    Write-BufferedLog "  [OPT] $optModule ... " -Color "Gray" -NoNewline
                    Write-BufferedLog "OK" -Color "Gray"
                }
            }
        }

        if (-not $allModulesValid) {
            Write-BufferedLog ""
            Write-Status "DEPENDENCY VALIDATION FAILED" "ERROR"
            Show-FailureDump
            Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
            exit 12  # Dependency validation failed
        }

        $depsValid = $true
        Write-Status "Runtime dependencies validated." "OK"
    } catch {
        Write-Status "Failed to load RUNTIME_DEPENDENCIES.psd1: $($_.Exception.Message)" "WARN"
    }
}

# --- Step 6d: Simulation Mode (CI) ---
if ($SimulateProd) {
    Write-Host ""
    Write-Status "SIMULATION MODE - Importing modules without GUI launch" "INFO"

    # Load runtime dependencies
    $runtimeDepsPath = Join-Path $stagingRoot "src\RUNTIME_DEPENDENCIES.psd1"
    if (-not (Test-Path $runtimeDepsPath)) {
        Write-Status "RUNTIME_DEPENDENCIES.psd1 not found in staging" "ERROR"
        Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        exit 12  # Dependency validation failed
    }

    $runtimeDeps = Import-PowerShellDataFile $runtimeDepsPath

    # Import all required modules to verify they load
    if ($runtimeDeps.RequiredModules) {
        foreach ($reqModule in $runtimeDeps.RequiredModules) {
            $modulePath = Join-Path $stagingRoot ($reqModule -replace '/', '\')
            Write-Host "  [IMPORT] $reqModule ... " -NoNewline

            if (-not (Test-Path $modulePath)) {
                Write-Host "NOT FOUND" -ForegroundColor Red
                Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
                exit 14  # Module loader failed
            }

            try {
                Import-Module $modulePath -Force -ErrorAction Stop
                Write-Host "OK" -ForegroundColor Green
            } catch {
                Write-Host "FAILED" -ForegroundColor Red
                Write-Host "    $($_.Exception.Message)" -ForegroundColor Gray
                Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
                exit 14  # Module loader failed
            }
        }
    }

    # Import optional modules (warn on failure)
    if ($runtimeDeps.OptionalModules) {
        foreach ($optModule in $runtimeDeps.OptionalModules) {
            $modulePath = Join-Path $stagingRoot ($optModule -replace '/', '\')

            if (Test-Path $modulePath) {
                Write-Host "  [IMPORT] $optModule ... " -NoNewline
                try {
                    Import-Module $modulePath -Force -ErrorAction Stop
                    Write-Host "OK" -ForegroundColor Gray
                } catch {
                    Write-Host "WARN" -ForegroundColor Yellow
                    Write-Host "    $($_.Exception.Message)" -ForegroundColor Gray
                }
            }
        }
    }

    Write-Host ""
    Write-Status "Simulation complete. All modules imported successfully." "OK"
    Write-Status "Skipping GUI launch (simulation mode)." "INFO"

    # Cleanup and exit
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 0  # Success
}

# --- Preload core module loader (required for entry point) ---
Start-Phase "Module Loading"
$moduleLoaderPath = Join-Path $stagingRoot "src\Modules\ModuleLoader.psm1"

if (-not (Test-Path $moduleLoaderPath)) {
    Write-Status "ModuleLoader.psm1 not found in staging." "ERROR"
    Show-FailureDump
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 14  # Module loader failed
}

Import-Module $moduleLoaderPath -Force -ErrorAction Stop

# --- Assert loader contract (fail fast if functions missing) ---
foreach ($fn in @("Import-RequiredModule", "Import-OptionalModule")) {
    if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
        Write-Status "Missing loader function: $fn" "ERROR"
        Show-FailureDump
        Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        exit 14  # Module loader failed
    }
}

# --- Step 6e: Self-Check Mode ---
if ($SelfCheck) {
    Write-Host ""
    Write-Host "WinConfig v$appVersion ($EnvironmentLabel)" -ForegroundColor Green
    Write-Host "$([char]0x2714) Integrity verified ($filesVerified files)" -ForegroundColor Green
    Write-Host "$([char]0x2714) Dependencies OK" -ForegroundColor Green
    Write-Host "$([char]0x2714) Environment authorized" -ForegroundColor Green
    Write-Host ""
    Write-Status "Self-check passed. Exiting without launch." "OK"
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}

# --- Compact Success Summary (Normal Mode) ---
# Level 0 (Quiet): No output
# Level 1 (Normal): Compact summary
# Level 2+ (Verbose/Debug): Full trace (already shown above)
if ($script:VerbosityLevel -eq 1) {
    Write-Host ""
    Write-Host "WinConfig v$appVersion ($EnvironmentLabel)" -ForegroundColor Cyan
    Write-Host "$([char]0x2714) Integrity verified" -ForegroundColor Green
    Write-Host "$([char]0x2714) Dependencies OK" -ForegroundColor Green
    Write-Host "$([char]0x2714) Environment authorized" -ForegroundColor Green
    Write-Host "$([char]0x2192) Launching..." -ForegroundColor DarkGray
    Write-Host ""
}

# --- Step 7: Execute Entry Point from Staging Directory ---
$entryPointPath = Join-Path $stagingRoot $EntryPoint

if ($script:VerbosityLevel -ge 2) {
    Write-Host ""
    Write-Status "Launching $EnvironmentLabel version..." "INFO"
    Write-Host ""
}

try {
    # Normalize iteration to canonical values before setting env var
    $iterationValue = switch ($EnvironmentLabel.ToLower()) {
        "prod"        { "production" }
        "production"  { "production" }
        "stage"       { "staging" }
        "staging"     { "staging" }
        "dev"         { "dev" }
        "develop"     { "dev" }
        "development" { "dev" }
        default       { $EnvironmentLabel }
    }

    # Set environment variable so entry point knows which iteration it's running as
    # (inherits to child process)
    $env:WINCONFIG_ITERATION = $iterationValue

    # Execute the entry point script
    # ExecutionPolicy is already bypassed (user ran Bootstrap.ps1 with -ExecutionPolicy Bypass)
    # Using & preserves loaded modules (ModuleLoader) in the current session
    & $entryPointPath
} catch {
    Write-Host ""
    Write-Status "Execution error: $($_.Exception.Message)" "ERROR"
    Show-FailureDump
} finally {
    # Clean up environment variable
    $env:WINCONFIG_ITERATION = $null
}

# --- Step 8: Cleanup ---
if ($script:VerbosityLevel -ge 2) {
    Write-Host ""
    Write-Status "Cleaning up temp directory..." "INFO"
}

try {
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction Stop
    if ($script:VerbosityLevel -ge 2) {
        Write-Status "Cleanup complete." "OK"
    }
} catch {
    Write-Status "Cleanup failed (manual removal may be needed): $stagingRoot" "WARN"
}

if ($script:VerbosityLevel -ge 2) {
    Write-Host ""
    Write-Status "Bootstrap complete." "OK"
}

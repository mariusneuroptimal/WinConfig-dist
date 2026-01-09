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

.EXAMPLE
    # Basic usage (production)
    .\Bootstrap.ps1

.EXAMPLE
    # Staging environment
    .\Bootstrap.ps1 -Environment staging
#>
param(
    [Parameter()]
    [ValidateSet('staging', 'production', '')]
    [string]$Environment = '',

    [Parameter()]
    [switch]$SimulateProd  # CI mode: download, verify, import modules, exit before GUI
)

# ============================================================================
# CONFIGURATION - TRUST ANCHORS
# ============================================================================

# Bootstrap version - update when Bootstrap.ps1 changes
$BootstrapVersion = "2.0.0"

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

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $color = switch ($Type) {
        "INFO"  { "Cyan" }
        "OK"    { "Green" }
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        default { "White" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
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

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NeurOptimal Support Tool Launcher" -ForegroundColor Cyan
Write-Host "  Bootstrap v$BootstrapVersion" -ForegroundColor DarkCyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Select Environment ---
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
    exit 1
}

Write-Status "Running $EnvironmentLabel version" "INFO"

# --- Step 2: Validate Against Branch Allow-List ---
if ($Branch -notin $AllowedBranches) {
    Write-Status "Internal error: invalid branch mapping." "ERROR"
    exit 1
}

Write-Status "Environment authorized." "OK"

# --- Step 3: Fetch Manifest from Distribution Repo ---
Write-Host ""
Write-Status "Fetching manifest from distribution repository..." "INFO"

try {
    $manifest = Get-DistManifest -Owner $GitHubOwner -Repo $DistRepoName -Environment $Branch
    Write-Status "Manifest loaded (commit: $($manifest.commit.Substring(0, 7)))" "OK"
} catch {
    Write-Status "Failed to fetch manifest: $($_.Exception.Message)" "ERROR"
    Write-Host ""
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Distribution repository not yet set up" -ForegroundColor Gray
    Write-Host "  - Network connectivity issues" -ForegroundColor Gray
    Write-Host "  - Branch '$Branch' not published to dist repo" -ForegroundColor Gray
    exit 1
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
    exit 1
}

# --- Step 5: Download, Verify, and Stage Each File ---
$allFilesValid = $true
$stagedFiles = @()

Write-Host ""
Write-Status "Downloading and verifying $($FileManifest.Count) files..." "INFO"

foreach ($filePath in $FileManifest.Keys) {
    $expectedHash = $FileManifest[$filePath]
    $shortHash = $expectedHash.Substring(0, 12)

    Write-Host "  $filePath ... " -NoNewline

    try {
        # Download file content from distribution repo
        # Dist repo structure: main branch with environment directories (main/, develop/)
        $content = Get-RawGitHubContent -Owner $GitHubOwner -Repo $DistRepoName -Branch "main" -Path "$Branch/$filePath"

        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Host "EMPTY" -ForegroundColor Red
            $allFilesValid = $false
            continue
        }

        # Verify hash
        $actualHash = Get-Sha256Hash -Content $content

        if ($actualHash -ne $expectedHash) {
            Write-Host "HASH MISMATCH" -ForegroundColor Red
            Write-Host "    Expected: $expectedHash" -ForegroundColor Yellow
            Write-Host "    Actual:   $actualHash" -ForegroundColor Red
            $allFilesValid = $false
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
        Write-Host "OK ($shortHash...)" -ForegroundColor Green

    } catch {
        Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
        $allFilesValid = $false
    }
}

Write-Host ""

# --- Step 6: Fail Closed if Any File Invalid ---
if (-not $allFilesValid) {
    Write-Status "INTEGRITY CHECK FAILED - One or more files invalid" "ERROR"
    Write-Host ""
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Distribution repo out of sync" -ForegroundColor Gray
    Write-Host "  - Network or download issues" -ForegroundColor Gray
    Write-Host "  - Manifest corruption" -ForegroundColor Gray
    Write-Host ""
    Write-Status "Refusing to execute. Cleaning up..." "ERROR"

    # Cleanup staging directory
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Status "All files verified and staged." "OK"

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

Write-Host ""
Write-Host "----------------------------------------" -ForegroundColor DarkGray
Write-Host "  Bootstrap:   v$BootstrapVersion" -ForegroundColor Gray
Write-Host "  App:         v$appVersion ($EnvironmentLabel)" -ForegroundColor Gray
Write-Host "  Manifest:    $($FileManifest.Count) files verified" -ForegroundColor Gray
Write-Host "  Commit:      $($manifest.commit.Substring(0, 7))" -ForegroundColor Gray
Write-Host "----------------------------------------" -ForegroundColor DarkGray

# --- Step 6c: Validate Runtime Dependencies ---
$runtimeDepsPath = Join-Path $stagingRoot "src\RUNTIME_DEPENDENCIES.psd1"
if (Test-Path $runtimeDepsPath) {
    Write-Host ""
    Write-Status "Validating runtime dependencies..." "INFO"

    try {
        $runtimeDeps = Import-PowerShellDataFile $runtimeDepsPath
        $allModulesValid = $true

        # Assert all RequiredModules exist in staging AND are in manifest
        if ($runtimeDeps.RequiredModules) {
            foreach ($reqModule in $runtimeDeps.RequiredModules) {
                $modulePath = Join-Path $stagingRoot ($reqModule -replace '/', '\')

                if (-not (Test-Path $modulePath)) {
                    Write-Host "  [REQ] $reqModule ... " -NoNewline
                    Write-Host "MISSING" -ForegroundColor Red
                    $allModulesValid = $false
                } elseif (-not $FileManifest.ContainsKey($reqModule)) {
                    Write-Host "  [REQ] $reqModule ... " -NoNewline
                    Write-Host "NOT IN MANIFEST" -ForegroundColor Red
                    $allModulesValid = $false
                } else {
                    Write-Host "  [REQ] $reqModule ... " -NoNewline
                    Write-Host "OK" -ForegroundColor Green
                }
            }
        }

        # Warn on missing optional modules
        if ($runtimeDeps.OptionalModules) {
            foreach ($optModule in $runtimeDeps.OptionalModules) {
                $modulePath = Join-Path $stagingRoot ($optModule -replace '/', '\')

                if (-not (Test-Path $modulePath)) {
                    Write-Host "  [OPT] $optModule ... " -NoNewline
                    Write-Host "MISSING (graceful)" -ForegroundColor Yellow
                } else {
                    Write-Host "  [OPT] $optModule ... " -NoNewline
                    Write-Host "OK" -ForegroundColor Gray
                }
            }
        }

        if (-not $allModulesValid) {
            Write-Host ""
            Write-Status "DEPENDENCY VALIDATION FAILED" "ERROR"
            Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }

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
        exit 1
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
                exit 1
            }

            try {
                Import-Module $modulePath -Force -ErrorAction Stop
                Write-Host "OK" -ForegroundColor Green
            } catch {
                Write-Host "FAILED" -ForegroundColor Red
                Write-Host "    $($_.Exception.Message)" -ForegroundColor Gray
                Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
                exit 1
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
$moduleLoaderPath = Join-Path $stagingRoot "src\Modules\ModuleLoader.psm1"

if (-not (Test-Path $moduleLoaderPath)) {
    Write-Status "ModuleLoader.psm1 not found in staging." "ERROR"
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

Import-Module $moduleLoaderPath -Force -ErrorAction Stop

# --- Assert loader contract (fail fast if functions missing) ---
foreach ($fn in @("Import-RequiredModule", "Import-OptionalModule")) {
    if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
        Write-Status "Missing loader function: $fn" "ERROR"
        Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# --- Step 7: Execute Entry Point from Staging Directory ---
$entryPointPath = Join-Path $stagingRoot $EntryPoint

Write-Host ""
Write-Status "Launching $EnvironmentLabel version..." "INFO"
Write-Host ""

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

    # Execute the entry point script with explicit ExecutionPolicy bypass
    # This ensures scripts run regardless of system ExecutionPolicy settings
    $exitCode = 0
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$entryPointPath`"" `
        -Wait -PassThru -NoNewWindow
    $exitCode = $proc.ExitCode
} catch {
    Write-Host ""
    Write-Status "Execution error: $($_.Exception.Message)" "ERROR"
} finally {
    # Clean up environment variable
    $env:WINCONFIG_ITERATION = $null
}

# --- Step 8: Cleanup ---
Write-Host ""
Write-Status "Cleaning up temp directory..." "INFO"

try {
    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction Stop
    Write-Status "Cleanup complete." "OK"
} catch {
    Write-Status "Cleanup failed (manual removal may be needed): $stagingRoot" "WARN"
}

Write-Host ""
Write-Status "Bootstrap complete." "OK"

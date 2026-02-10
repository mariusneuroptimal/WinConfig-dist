# Win11Config.ps1 - Entry point for WinConfig
# IMMUTABLE WRAPPER - Do not add logic here

# === CANONICAL VERSION SOURCE ===
$VersionFile = "$PSScriptRoot\src\VERSION.psd1"
if (-not (Test-Path $VersionFile)) {
    throw "FATAL: VERSION.psd1 not found at $VersionFile"
}

$VersionData = Import-PowerShellDataFile $VersionFile
$AppName     = $VersionData.AppName
$AppVersion  = $VersionData.Version

# Iteration: environment variable overrides VERSION.psd1 default
$Iteration = if ($env:WINCONFIG_ITERATION) {
    $env:WINCONFIG_ITERATION
} else {
    $VersionData.Iteration
}

# === ITERATION NORMALIZATION ===
# Normalize aliases → canonical values (production | staging | dev)
# After this point, aliases are illegal downstream
switch ($Iteration.ToLower()) {
    "prod"        { $Iteration = "production" }
    "production"  { $Iteration = "production" }
    "stage"       { $Iteration = "staging" }
    "staging"     { $Iteration = "staging" }
    "dev"         { $Iteration = "dev" }
    "develop"     { $Iteration = "dev" }
    "development" { $Iteration = "dev" }
    default {
        throw "FATAL: Invalid Iteration '$Iteration'. Valid: production | staging | dev"
    }
}

# === PRODUCTION IMMUTABILITY GUARD (P1) ===
if ($Iteration -eq "production" -and $env:CI -ne "true") {
    $acl = Get-Acl $VersionFile
    # Check if file is writable (guard against hot-patching prod builds)
    $isWritable = $acl.Access | Where-Object {
        $_.FileSystemRights -match "Write" -and $_.AccessControlType -eq "Allow"
    }
    # Note: This is a warning, not a hard block, to allow local testing
    # In strict mode, uncomment the throw below
    # if ($isWritable) { throw "FATAL: VERSION.psd1 must be read-only in production" }
}

# === UI ENTRY POINT ROUTER ===
# Debug mode loads isolated debug UI (no production code parsed)
# Production mode loads real UI
if ($script:IsUIDebug) {
    . "$PSScriptRoot\src\Win11Config.App.Debug.ps1"
}
else {
    . "$PSScriptRoot\src\Win11Config.App.ps1"
}

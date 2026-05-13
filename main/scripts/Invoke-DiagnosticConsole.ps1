# Invoke-DiagnosticConsole.ps1 - Launch wrapper for button-triggered diagnostic windows
# Ensures consistent console styling and context headers across all spawned windows

# CONTRACT:
# 1. Import Console module (REQUIRED)
# 2. Initialize-Console (REQUIRED)
# 3. Write-ConsoleHeader (REQUIRED)
# 4. Execute payload script
# Anything else is a contract violation.

<#
.SYNOPSIS
    Launches a diagnostic operation in a styled console window.
.DESCRIPTION
    This script provides a standardized way to open console windows from button clicks.
    It imports the Console module, applies canonical colors, displays a context header,
    and executes the specified script block or script file.

    MANDATORY: All button-triggered console windows MUST use this wrapper.
    Direct powershell.exe calls are forbidden.

    Contract order:
    1. Import Console module
    2. Initialize-Console
    3. Write-ConsoleHeader
    4. Execute payload

.PARAMETER Title
    The operation title displayed in the header (e.g., "Network Diagnostics")
.PARAMETER SessionId
    Session identifier for correlation (optional - auto-generated if omitted)
.PARAMETER Mode
    Operating mode description (e.g., "Read-only diagnostics")
.PARAMETER ScriptPath
    Path to a script file to execute after initialization
.PARAMETER ScriptBlock
    Script block to execute after initialization (alternative to ScriptPath)
.PARAMETER KeepOpen
    If specified, keeps the console window open after execution

.EXAMPLE
    # From a button click handler:
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$RepoRoot\scripts\Invoke-DiagnosticConsole.ps1`" -Title 'Network Test' -SessionId '$sessionId' -ScriptPath `"$RepoRoot\scripts\test-network.ps1`""

.EXAMPLE
    # Direct invocation for testing:
    .\Invoke-DiagnosticConsole.ps1 -Title "Network Diagnostics" -Mode "Read-only" -KeepOpen
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Title,

    [Parameter(Mandatory = $false)]
    [string]$SessionId = "",

    [Parameter(Mandatory = $false)]
    [string]$Mode = "",

    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = "",

    [Parameter(Mandatory = $false)]
    [scriptblock]$ScriptBlock = $null,

    [Parameter(Mandatory = $false)]
    [switch]$KeepOpen
)

# --- STEP 1: Import Console module (REQUIRED) ---
$RepoRoot = Split-Path $PSScriptRoot -Parent
$ConsoleModulePath = Join-Path $RepoRoot "src\Modules\Console.psm1"

if (-not (Test-Path $ConsoleModulePath)) {
    throw "Console module not found at: $ConsoleModulePath - wrapper contract violated"
}

Import-Module $ConsoleModulePath -Force -ErrorAction Stop

# --- STEP 2: Initialize-Console (REQUIRED) ---
Initialize-Console

# Verify initialization succeeded
if (-not (Test-ConsoleInitialized)) {
    throw "Console not initialized - wrapper contract violated"
}

# --- STEP 3: Write-ConsoleHeader (REQUIRED) ---
# Generate session ID if not provided
if (-not $SessionId) {
    $SessionId = [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
}

Write-ConsoleHeader -Title $Title -SessionId $SessionId -Mode $Mode
Write-Host ""

# --- STEP 4: Execute payload script ---
if ($ScriptPath -and (Test-Path $ScriptPath)) {
    try {
        & $ScriptPath
    }
    catch {
        Write-Diagnostic FAIL "Script execution failed: $_"
    }
}
elseif ($ScriptBlock) {
    try {
        & $ScriptBlock
    }
    catch {
        Write-Diagnostic FAIL "Script block execution failed: $_"
    }
}

# Keep window open if requested
if ($KeepOpen) {
    Write-Host ""
    Write-Diagnostic DIM "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

<#
.SYNOPSIS
    Canonical module import helpers with explicit required/optional semantics.

.DESCRIPTION
    ModuleLoader.psm1 is execution-critical and participates in bootstrap verification.
    It provides standardized import functions that make dependency semantics explicit.

    CONTRACT:
    - All module imports in App.ps1 MUST use these helpers
    - Raw Import-Module is banned in App.ps1 (enforced by static analysis)
    - Required modules throw on failure
    - Optional modules return $true/$false and warn on failure

    LOAD ORDER:
    ModuleLoader.psm1 MUST be loaded via dot-sourcing (. $path) before other modules,
    since it provides the functions used to import other modules.

.NOTES
    This module is hash-verified by Bootstrap.ps1.
    If a module can prevent, allow, or alter execution → it belongs in the manifest.
#>

# === SAFETY GUARD: Prevent direct execution of .psm1 files ===
# PSM1 files are IMPORT-ONLY artifacts. Direct execution (double-click, powershell.exe file.psm1)
# differs from Import-Module/dot-sourcing by invocation name.
# - Direct execution: InvocationName = full path or filename
# - Import-Module: InvocationName = "Import-Module" or "&"
# - Dot-source: InvocationName = "."
$invocationName = $MyInvocation.InvocationName
if ($invocationName -like "*.psm1" -or $invocationName -like "*\*" -or $invocationName -like "*/*") {
    throw "FATAL: PSM1 files must never be executed directly. Use Import-Module instead."
}

function Import-RequiredModule {
    <#
    .SYNOPSIS
        Imports a module that MUST load successfully. Throws on failure.

    .DESCRIPTION
        Use this for modules that the application cannot function without.
        If the module fails to load, a terminating error is thrown.

    .PARAMETER Path
        Full path to the module file (.psm1)

    .PARAMETER Prefix
        Optional prefix for exported functions (e.g., 'WinConfig' makes Write-Log become Write-WinConfigLog)

    .EXAMPLE
        Import-RequiredModule -Path "$PSScriptRoot\Modules\ExecutionIntent.psm1"

    .EXAMPLE
        Import-RequiredModule -Path "$PSScriptRoot\Modules\Console.psm1" -Prefix WinConfig
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Prefix
    )

    if (-not (Test-Path $Path)) {
        throw "FATAL: Required module not found: $Path"
    }

    $importParams = @{
        Name               = $Path
        Force              = $true
        ErrorAction        = 'Stop'
        Global             = $true
        DisableNameChecking = $true
    }
    if ($Prefix) {
        $importParams.Prefix = $Prefix
    }

    try {
        Import-Module @importParams
    } catch {
        throw "FATAL: Required module failed to load: $Path - $($_.Exception.Message)"
    }
}

function Import-OptionalModule {
    <#
    .SYNOPSIS
        Imports a module that may gracefully fail. Returns $true/$false.

    .DESCRIPTION
        Use this for modules that enhance functionality but are not critical.
        If the module fails to load, a warning is issued and $false is returned.

    .PARAMETER Path
        Full path to the module file (.psm1)

    .PARAMETER Prefix
        Optional prefix for exported functions

    .OUTPUTS
        [bool] $true if loaded successfully, $false otherwise

    .EXAMPLE
        if (Import-OptionalModule -Path "$PSScriptRoot\Logging\Logger.psm1" -Prefix WinConfig) {
            Initialize-WinConfigLogger
        }

    .EXAMPLE
        $null = Import-OptionalModule -Path "$PSScriptRoot\Modules\Bluetooth.psm1" -Prefix WinConfig
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Prefix
    )

    if (-not (Test-Path $Path)) {
        if ($env:WINCONFIG_ITERATION -ne "production") {
            Write-Warning "Optional module not found: $Path"
        }
        return $false
    }

    $importParams = @{
        Name               = $Path
        Force              = $true
        ErrorAction        = 'Stop'
        Global             = $true
        DisableNameChecking = $true
    }
    if ($Prefix) {
        $importParams.Prefix = $Prefix
    }

    try {
        Import-Module @importParams
        return $true
    } catch {
        if ($env:WINCONFIG_ITERATION -ne "production") {
            Write-Warning "Optional module failed to load: $Path - $($_.Exception.Message)"
        }
        return $false
    }
}

function Import-RuntimeManifest {
    <#
    .SYNOPSIS
        Manifest-driven module loader. Reads RUNTIME_DEPENDENCIES.psd1 and imports all declared modules.

    .DESCRIPTION
        Single entry point for loading all application modules from the manifest.
        Replaces hardcoded Import-RequiredModule/Import-OptionalModule calls in App.ps1.

        - RequiredModules: loaded in manifest order, throw on failure
        - OptionalModules: loaded in manifest order, warn on failure
        - Deferred modules (Deferred=$true): skipped, returned for lazy-loading
        - ModuleLoader.psm1 itself: skipped (bootstrap-preloaded)
        - GlobalForce modules: get a second Import-Module -Force -Global pass

    .PARAMETER ManifestPath
        Full path to RUNTIME_DEPENDENCIES.psd1

    .PARAMETER SourceRoot
        Root directory for resolving relative module paths (typically $PSScriptRoot from App.ps1)

    .OUTPUTS
        [hashtable] with keys:
            Required  - [string[]] paths of loaded required modules
            Optional  - [hashtable] keyed by module name, value = $true/$false
            Deferred  - [hashtable[]] manifest entries for modules marked Deferred=$true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestPath,

        [Parameter(Mandatory)]
        [string]$SourceRoot
    )

    if (-not (Test-Path $ManifestPath)) {
        throw "FATAL: RUNTIME_DEPENDENCIES.psd1 not found: $ManifestPath"
    }

    $deps = Import-PowerShellDataFile $ManifestPath

    $result = @{
        Required = [System.Collections.Generic.List[string]]::new()
        Optional = @{}
        Deferred = @()
    }

    # --- Required modules (fail-closed) ---
    foreach ($entry in $deps.RequiredModules) {
        $relPath = $entry.Path
        $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($relPath)

        # ModuleLoader is bootstrap-preloaded — verify, don't re-import
        if ($moduleName -eq 'ModuleLoader') { continue }

        # Resolve to absolute path: manifest uses forward-slash repo-relative paths
        # Strip leading "src/" since SourceRoot is already the src directory
        $localRel = ($relPath -replace '^src/', '') -replace '/', '\'
        $fullPath = Join-Path $SourceRoot $localRel

        $importArgs = @{ Path = $fullPath }
        if ($entry.Prefix) { $importArgs.Prefix = $entry.Prefix }

        Import-RequiredModule @importArgs
        $result.Required.Add($fullPath)

        # GlobalForce: second import for WinForms runspace visibility
        if ($entry.GlobalForce) {
            Import-Module $fullPath -Force -Global
        }
    }

    # --- Optional modules (graceful degradation) ---
    foreach ($entry in $deps.OptionalModules) {
        $relPath = $entry.Path
        $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($relPath)

        # Deferred modules are not loaded at startup
        if ($entry.Deferred) {
            $result.Deferred += @($entry)
            continue
        }

        $localRel = ($relPath -replace '^src/', '') -replace '/', '\'
        $fullPath = Join-Path $SourceRoot $localRel

        $importArgs = @{ Path = $fullPath }
        if ($entry.Prefix) { $importArgs.Prefix = $entry.Prefix }

        $loaded = Import-OptionalModule @importArgs
        $result.Optional[$moduleName] = $loaded
    }

    return $result
}

function Test-ModuleLoaded {
    <#
    .SYNOPSIS
        Tests if a module is currently loaded.

    .PARAMETER Name
        Name of the module (without path or extension)

    .OUTPUTS
        [bool] $true if module is loaded, $false otherwise

    .EXAMPLE
        if (Test-ModuleLoaded -Name "ExecutionIntent") {
            # Safe to use ExecutionIntent functions
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $module = Get-Module -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $module
}

Export-ModuleMember -Function @(
    'Import-RequiredModule'
    'Import-OptionalModule'
    'Import-RuntimeManifest'
    'Test-ModuleLoaded'
)

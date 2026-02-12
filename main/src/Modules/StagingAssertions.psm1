# =====================================================
# STAGING ASSERTIONS - Non-Negotiable Tripwires
# =====================================================
# These assertions fail HARD if violated.
# No logs. No warnings. Immediate termination.
#
# PURPOSE:
# Prevent debug artifacts from reaching staging/production.
# If it cannot exist in prod, it must not exist anywhere near prod.
# =====================================================

$ErrorActionPreference = "Stop"

# Load outcome manifest for validation
$script:OutcomeManifestPath = Join-Path $PSScriptRoot "..\Manifest\WinConfig.Outcomes.psd1"
$script:ParityManifestPath = Join-Path $PSScriptRoot "..\Manifest\WinConfig.Parity.psd1"

<#
.SYNOPSIS
    Asserts no debug modules are loaded. Fails hard if violated.
.DESCRIPTION
    Checks for presence of debug-only modules that must never exist in staging/prod.
    This is a tripwire, not a log.
#>
function Assert-NoDebugModulesLoaded {
    [CmdletBinding()]
    param()

    $debugModules = @(
        "Inject-FakeRunPayload"
        "Win11Config.App.Debug"
    )

    foreach ($moduleName in $debugModules) {
        $loaded = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
        if ($loaded) {
            throw "STAGING ASSERTION FAILED: Debug module '$moduleName' is loaded. This must never happen in staging/prod."
        }
    }

    # Also check if any module path contains "Debug"
    $allModules = Get-Module
    foreach ($mod in $allModules) {
        if ($mod.Path -match '[\\/]Debug[\\/]') {
            throw "STAGING ASSERTION FAILED: Module from Debug path loaded: $($mod.Path)"
        }
    }
}

<#
.SYNOPSIS
    Asserts no debug-only controls exist in the visual tree. Fails hard if violated.
.DESCRIPTION
    Scans the form's control hierarchy for debug-tagged controls.
    This is a tripwire, not a log.
#>
function Assert-NoDebugControlsInVisualTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.Form]$Form
    )

    $debugTags = @(
        "debug-overlay"
        "debug-checklist"
        "slow-op-simulator"
        "fake-result"
        "layout-test"
    )

    function Scan-Controls {
        param([System.Windows.Forms.Control]$Control)

        if ($Control.Tag) {
            $tagStr = $Control.Tag.ToString().ToLower()
            foreach ($debugTag in $debugTags) {
                if ($tagStr -match $debugTag) {
                    throw "STAGING ASSERTION FAILED: Debug control found in visual tree. Tag: '$($Control.Tag)', Control: $($Control.GetType().Name)"
                }
            }
        }

        foreach ($child in $Control.Controls) {
            Scan-Controls -Control $child
        }
    }

    Scan-Controls -Control $Form
}

<#
.SYNOPSIS
    Asserts outcome value is from the sealed taxonomy. Fails hard on unknown values.
.DESCRIPTION
    Validates that an outcome value is one of the sealed, centrally-defined values.
    This prevents silent entropy from unknown outcome values.
#>
function Assert-ValidOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Outcome,

        [Parameter()]
        [string]$Context = "Unknown"
    )

    # Load manifest if not cached
    if (-not $script:ValidOutcomes) {
        if (-not (Test-Path $script:OutcomeManifestPath)) {
            throw "STAGING ASSERTION FAILED: Outcome manifest not found at $script:OutcomeManifestPath"
        }
        $manifest = Import-PowerShellDataFile $script:OutcomeManifestPath
        $script:ValidOutcomes = @($manifest.Outcomes | ForEach-Object { $_.Value })
    }

    if ($Outcome -notin $script:ValidOutcomes) {
        throw "STAGING ASSERTION FAILED: Unknown outcome value '$Outcome' in context '$Context'. Valid outcomes: $($script:ValidOutcomes -join ', ')"
    }
}

<#
.SYNOPSIS
    Asserts manifest parity at runtime. Fails hard on mismatch.
.DESCRIPTION
    Verifies that runtime categories/tools match the parity manifest.
    This catches drift between code and manifest.
#>
function Assert-ManifestParity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$RuntimeCategories,

        [Parameter(Mandatory)]
        [hashtable]$RuntimeCategoryTools
    )

    if (-not (Test-Path $script:ParityManifestPath)) {
        throw "STAGING ASSERTION FAILED: Parity manifest not found at $script:ParityManifestPath"
    }

    $manifest = Import-PowerShellDataFile $script:ParityManifestPath

    # Check category count
    if ($RuntimeCategories.Count -ne $manifest.Categories.Count) {
        throw "STAGING ASSERTION FAILED: Category count mismatch. Runtime: $($RuntimeCategories.Count), Manifest: $($manifest.Categories.Count)"
    }

    # Check category names and order
    for ($i = 0; $i -lt $manifest.Categories.Count; $i++) {
        if ($RuntimeCategories[$i] -ne $manifest.Categories[$i]) {
            throw "STAGING ASSERTION FAILED: Category[$i] mismatch. Runtime: '$($RuntimeCategories[$i])', Manifest: '$($manifest.Categories[$i])'"
        }
    }

    # Check tools per category
    foreach ($cat in $manifest.Categories) {
        $manifestTools = $manifest.CategoryTools[$cat]
        $runtimeTools = $RuntimeCategoryTools[$cat]

        if (-not $runtimeTools) {
            throw "STAGING ASSERTION FAILED: Category '$cat' missing from runtime CategoryTools"
        }

        if ($manifestTools.Count -ne $runtimeTools.Count) {
            throw "STAGING ASSERTION FAILED: Tool count for '$cat' mismatch. Runtime: $($runtimeTools.Count), Manifest: $($manifestTools.Count)"
        }

        for ($i = 0; $i -lt $manifestTools.Count; $i++) {
            if ($runtimeTools[$i] -ne $manifestTools[$i]) {
                throw "STAGING ASSERTION FAILED: Tool[$i] in '$cat' mismatch. Runtime: '$($runtimeTools[$i])', Manifest: '$($manifestTools[$i])'"
            }
        }
    }
}

<#
.SYNOPSIS
    Asserts the script is not running in UI Debug Mode. Fails hard if it is.
.DESCRIPTION
    Final tripwire to ensure debug mode didn't leak through.
#>
function Assert-NotDebugMode {
    [CmdletBinding()]
    param()

    if ($script:UIDebugMode -or $script:IsUIDebug -or $env:WINCONFIG_UI_DEBUG) {
        throw "STAGING ASSERTION FAILED: Debug mode is active. This must never happen in staging/prod."
    }
}

<#
.SYNOPSIS
    Runs all staging assertions. Call this during production startup.
.DESCRIPTION
    Comprehensive staging validation that fails hard on any violation.
    This should be called early in the production startup sequence.
#>
function Invoke-StagingAssertions {
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Windows.Forms.Form]$Form,

        [Parameter()]
        [string[]]$Categories,

        [Parameter()]
        [hashtable]$CategoryTools
    )

    Write-Verbose "Running staging assertions..."

    # Assert 1: No debug mode
    Assert-NotDebugMode

    # Assert 2: No debug modules loaded
    Assert-NoDebugModulesLoaded

    # Assert 3: No debug controls (if form provided)
    if ($Form) {
        Assert-NoDebugControlsInVisualTree -Form $Form
    }

    # Assert 4: Manifest parity (if categories provided)
    if ($Categories -and $CategoryTools) {
        Assert-ManifestParity -RuntimeCategories $Categories -RuntimeCategoryTools $CategoryTools
    }

    Write-Verbose "All staging assertions passed."
}

# Export functions
Export-ModuleMember -Function @(
    'Assert-NoDebugModulesLoaded'
    'Assert-NoDebugControlsInVisualTree'
    'Assert-ValidOutcome'
    'Assert-ManifestParity'
    'Assert-NotDebugMode'
    'Invoke-StagingAssertions'
)

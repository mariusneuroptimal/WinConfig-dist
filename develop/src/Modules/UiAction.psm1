<#
.SYNOPSIS
    Provides self-bootstrapping wrapper for WinForms delegates.

.DESCRIPTION
    WinForms delegates (Add_Click, BeginInvoke, etc.) execute in isolated runspaces
    that do NOT inherit imported modules from the parent scope.

    This module provides New-UiAction which wraps scriptblocks with the necessary
    module imports, ensuring UI code always has access to required functions.

.NOTES
    CONTRACT-001: Delegate Self-Bootstrapping
    See docs/CONTRACT.md for full specification.
#>

# Capture module paths at load time (when PSScriptRoot is valid)
$script:DiagnosticTypesPath = Join-Path $PSScriptRoot 'DiagnosticTypes.psm1'
$script:RegistryPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Diagnostics\Registry.psm1'

function New-UiAction {
    <#
    .SYNOPSIS
        Wraps a scriptblock for safe execution in WinForms delegates.

    .DESCRIPTION
        Creates a self-bootstrapping scriptblock that imports required modules
        before executing the provided action. Use this for all WinForms event
        handlers that need access to diagnostic functions.

    .PARAMETER Action
        The scriptblock to execute. Will have access to Switch-DiagnosticResult,
        $DiagnosticResult, and other DiagnosticTypes exports.

    .PARAMETER SkipRuntimeGuard
        If set, skips the runtime assertion. Only use for performance-critical
        paths where you've verified imports work correctly.

    .EXAMPLE
        $button.Add_Click((New-UiAction {
            $icon = Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS' = { [System.Windows.Forms.MessageBoxIcon]::Information }
                'FAIL' = { [System.Windows.Forms.MessageBoxIcon]::Error }
            }
        }))

    .NOTES
        CONTRACT-001 enforcement. Raw Add_Click({ }) is banned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$Action,

        [Parameter()]
        [switch]$SkipRuntimeGuard
    )

    # Capture paths in closure (these are resolved at module load time)
    $diagnosticTypesPath = $script:DiagnosticTypesPath
    $skipGuard = $SkipRuntimeGuard.IsPresent

    # Return a new scriptblock that self-bootstraps
    return {
        # Import required modules in delegate runspace
        Import-Module $diagnosticTypesPath -Force -ErrorAction Stop

        # Runtime guard (CONTRACT-001 enforcement)
        if (-not $skipGuard) {
            if (-not (Get-Command Switch-DiagnosticResult -ErrorAction SilentlyContinue)) {
                throw "UI RUNSPACE CONTRACT VIOLATION: DiagnosticTypes not imported. See CONTRACT-001."
            }
        }

        # Execute the user's action
        & $Action
    }.GetNewClosure()
}

function New-UiActionWithRegistry {
    <#
    .SYNOPSIS
        Wraps a scriptblock that also needs Registry.psm1 (Invoke-RegisteredDiagnostic).

    .DESCRIPTION
        Like New-UiAction but also imports the diagnostic Registry module.
        Use when the delegate needs to invoke diagnostics directly.

    .PARAMETER Action
        The scriptblock to execute.

    .EXAMPLE
        $button.Add_Click((New-UiActionWithRegistry {
            $result = Invoke-RegisteredDiagnostic -DiagnosticId 'NET-TLS-001'
        }))
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$Action
    )

    $diagnosticTypesPath = $script:DiagnosticTypesPath
    $registryPath = $script:RegistryPath

    return {
        Import-Module $diagnosticTypesPath -Force -ErrorAction Stop
        Import-Module $registryPath -Force -ErrorAction Stop

        if (-not (Get-Command Switch-DiagnosticResult -ErrorAction SilentlyContinue)) {
            throw "UI RUNSPACE CONTRACT VIOLATION: DiagnosticTypes not imported. See CONTRACT-001."
        }
        if (-not (Get-Command Invoke-RegisteredDiagnostic -ErrorAction SilentlyContinue)) {
            throw "UI RUNSPACE CONTRACT VIOLATION: Registry not imported. See CONTRACT-001."
        }

        & $Action
    }.GetNewClosure()
}

# Export functions
Export-ModuleMember -Function @(
    'New-UiAction',
    'New-UiActionWithRegistry'
)

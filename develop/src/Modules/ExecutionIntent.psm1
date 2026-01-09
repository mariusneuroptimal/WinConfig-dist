# ExecutionIntent.psm1 - Non-Mutating Diagnostic Contract
#
# CONTRACT:
# - Default intent is DIAGNOSTIC (safe, read-only)
# - Mutations require explicit ADMIN_ACTION intent
# - Intent must be scoped via Invoke-WithExecutionIntent (auto-reverts in finally)
# - Tests hard-block on admin context
#
# INVARIANTS:
# - Intent defaults to DIAGNOSTIC on module load
# - Invoke-WithExecutionIntent always reverts intent in finally block
# - SAFE_ACTION cannot escalate to ADMIN_ACTION without -AllowEscalation
# - Assert-ExecutionIntent throws on mismatch (never silent failure)

# Global execution intent - defaults to DIAGNOSTIC (safe)
$script:ExecutionIntent = 'DIAGNOSTIC'

# Wrapper depth tracking for non-reentrancy enforcement
$script:IntentDepth = 0

# Valid intents (exported constant)
$script:ValidIntents = @('DIAGNOSTIC', 'SAFE_ACTION', 'ADMIN_ACTION')

function Get-ExecutionIntent {
    <#
    .SYNOPSIS
        Returns the current execution intent.
    .OUTPUTS
        String: DIAGNOSTIC, SAFE_ACTION, or ADMIN_ACTION
    #>
    [CmdletBinding()]
    param()
    return $script:ExecutionIntent
}

function Set-ExecutionIntent {
    <#
    .SYNOPSIS
        Sets the execution intent. Prefer Invoke-WithExecutionIntent for scoped changes.
    .PARAMETER Intent
        The intent to set: DIAGNOSTIC, SAFE_ACTION, or ADMIN_ACTION
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DIAGNOSTIC', 'SAFE_ACTION', 'ADMIN_ACTION')]
        [string]$Intent
    )
    $script:ExecutionIntent = $Intent
}

function Assert-ExecutionIntent {
    <#
    .SYNOPSIS
        Asserts that the current intent matches the required intent. Throws on mismatch.
    .PARAMETER Required
        The required intent for the operation to proceed.
    .EXAMPLE
        Assert-ExecutionIntent -Required 'ADMIN_ACTION'
        # Throws if current intent is not ADMIN_ACTION
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SAFE_ACTION', 'ADMIN_ACTION')]
        [string]$Required
    )
    if ($script:ExecutionIntent -ne $Required) {
        # Include caller context for debugging/supportability
        $caller = (Get-PSCallStack)[1].Command
        if (-not $caller) { $caller = '<unknown>' }
        throw "Mutation blocked in ${caller}: current intent='$($script:ExecutionIntent)', required='$Required'"
    }
}

function Invoke-WithExecutionIntent {
    <#
    .SYNOPSIS
        Executes a scriptblock with a specific execution intent, auto-reverting in finally.
    .DESCRIPTION
        This is the ONLY safe way to change intent for mutations. It guarantees:
        - Intent is reverted even if the scriptblock throws
        - No sticky global state
        - No accidental escalation from SAFE_ACTION to ADMIN_ACTION
        - Non-reentrancy enforcement (nested calls with different intent require -AllowNested)
    .PARAMETER Intent
        The intent to set for the duration of the scriptblock.
    .PARAMETER Script
        The scriptblock to execute.
    .PARAMETER AllowEscalation
        Required to escalate from SAFE_ACTION to ADMIN_ACTION.
    .PARAMETER AllowNested
        Required for nested wrapper calls with a different intent than the outer scope.
    .EXAMPLE
        Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
            Invoke-BluetoothServiceReset
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DIAGNOSTIC', 'SAFE_ACTION', 'ADMIN_ACTION')]
        [string]$Intent,

        [Parameter(Mandatory)]
        [scriptblock]$Script,

        [switch]$AllowEscalation,  # Required to escalate from SAFE_ACTION to ADMIN_ACTION
        [switch]$AllowNested       # Required for nested calls with different intent
    )

    # Fail fast: validate scriptblock is not null
    if ($null -eq $Script) {
        throw "Invoke-WithExecutionIntent: Script parameter cannot be null"
    }

    $prev = Get-ExecutionIntent

    # Non-reentrancy: nested calls with different intent require explicit flag
    if ($script:IntentDepth -gt 0 -and $Intent -ne $prev -and -not $AllowNested) {
        throw "Nested Invoke-WithExecutionIntent with different intent requires -AllowNested (current=$prev, requested=$Intent)"
    }

    # No-nested-escalation rule: SAFE_ACTION cannot escalate to ADMIN_ACTION without explicit flag
    if ($prev -eq 'SAFE_ACTION' -and $Intent -eq 'ADMIN_ACTION' -and -not $AllowEscalation) {
        throw "Cannot escalate from SAFE_ACTION to ADMIN_ACTION without -AllowEscalation"
    }

    $script:IntentDepth++
    try {
        Set-ExecutionIntent -Intent $Intent
        & $Script
    } finally {
        $script:IntentDepth--
        Set-ExecutionIntent -Intent $prev
    }
}

function Test-IsDryRunMode {
    <#
    .SYNOPSIS
        Returns true if running in dev/CI/test environment where mutations should be no-op.
    .DESCRIPTION
        Dry-run mode is determined by WINCONFIG_ENV environment variable.
        Valid dry-run values: dev, ci, test
    .OUTPUTS
        Boolean: $true if dry-run mode is active
    #>
    [CmdletBinding()]
    param()
    return $env:WINCONFIG_ENV -in @('dev', 'ci', 'test')
}

function Assert-NotRunningAsAdmin {
    <#
    .SYNOPSIS
        Hard block for test runner: throws if running as admin.
    .DESCRIPTION
        Tests must never run as admin to prevent accidental system mutations.
        This is a safety requirement, not a permission check.
    #>
    [CmdletBinding()]
    param()
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        throw "FATAL: Tests must not run as admin. This is a safety requirement."
    }
}

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Returns true if running with administrator privileges.
    .OUTPUTS
        Boolean: $true if running as admin
    #>
    [CmdletBinding()]
    param()
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Export functions
Export-ModuleMember -Function @(
    'Get-ExecutionIntent',
    'Set-ExecutionIntent',
    'Assert-ExecutionIntent',
    'Invoke-WithExecutionIntent',
    'Test-IsDryRunMode',
    'Assert-NotRunningAsAdmin',
    'Test-IsAdmin'
) -Variable @(
    'ValidIntents'
)

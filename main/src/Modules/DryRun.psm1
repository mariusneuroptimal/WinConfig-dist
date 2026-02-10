# DryRun.psm1 - Dry Run Infrastructure for WinConfig
#
# CONTRACT:
#   - Dry Run is not a mode. It is not a simulation. It records intent with the same
#     fidelity that execution records effect.
#   - All Dry-Run-capable tools MUST follow PLAN -> EXECUTE semantics
#   - Dry Runs MUST write ledger entries with Executed = $false
#   - Dry Runs MUST NOT produce side effects
#   - Dry Runs MUST export normally, traverse the pipeline, and appear on dashboard
#
# ARCHITECTURAL INVARIANTS:
#   - No global flags. No environment variables for dry run invocation.
#   - Dry Run is explicit per-invocation: -DryRun switch
#   - PLAN phase is pure and deterministic
#   - EXECUTE phase is the only place side effects are allowed
#   - Plan must be identical to what Execute would do (no shortcuts)
#
# ERROR SEMANTICS:
#   - New-DryRunPlan: Returns plan object, never throws
#   - Invoke-DryRunGuarded: THROWS if side effects detected in dry run
#   - Assert-NoDryRunSideEffects: THROWS if violations found
#   - Complete-DryRunOperation: Returns ledger entry, THROWS if recording fails

# Direct execution guard
if ($MyInvocation.InvocationName -like "*.psm1" -or $MyInvocation.InvocationName -like "*\*") {
    throw "FATAL: PSM1 files must never be executed directly. Use Import-Module instead."
}

# =============================================================================
# SCRIPT-SCOPED STATE
# =============================================================================

# Side effect tracking for guardrail enforcement
$script:DryRunSideEffectLog = [System.Collections.Generic.List[object]]::new()
$script:DryRunActive = $false
$script:DryRunLock = [System.Object]::new()

# Curated list of commands that must NEVER execute during dry-run plan phase.
# Breakpoints are set for these commands during plan execution to detect violations.
# This list covers the mutation surface of WinConfig tools.
$script:DryRunGuardedCommands = @(
    # Service lifecycle
    'Stop-Service', 'Start-Service', 'Restart-Service', 'Set-Service',
    # Filesystem mutations
    'Remove-Item', 'Move-Item', 'Rename-Item',
    'Set-Content', 'Add-Content', 'Clear-Content',
    # Registry mutations
    'Set-ItemProperty', 'Remove-ItemProperty', 'New-ItemProperty',
    # Device mutations
    'Remove-PnpDevice', 'Disable-PnpDevice', 'Enable-PnpDevice',
    # Driver mutations
    'Remove-WindowsDriver',
    # Process execution (side effects)
    'Start-Process',
    # Dangerous meta-commands
    'Invoke-Expression'
)

# =============================================================================
# PLAN CREATION
# =============================================================================

function New-DryRunPlan {
    <#
    .SYNOPSIS
        Creates a Dry Run plan object describing intended changes.
    .DESCRIPTION
        The plan object describes exactly what the EXECUTE phase would do.
        This is not a "best effort" description - it must be identical to
        what execution would actually perform.
    .PARAMETER ToolId
        The tool identifier from WinConfig.Tools.psd1
    .PARAMETER ToolName
        Human-readable tool name
    .PARAMETER Steps
        Array of step descriptions (strings) in execution order
    .PARAMETER AffectedResources
        Array of resources that would be modified (services, files, registry keys, etc.)
    .PARAMETER RequiresAdmin
        Boolean indicating if execution requires administrator privileges
    .PARAMETER Reversible
        Boolean indicating if the operation can be undone
    .PARAMETER EstimatedImpact
        Impact classification: None, Low, Medium, High, Critical
    .PARAMETER Preconditions
        Array of precondition checks that must pass before execution
    .PARAMETER Evidence
        Additional structured evidence about the planned operation
    .OUTPUTS
        PSCustomObject: The plan object
    .EXAMPLE
        $plan = New-DryRunPlan -ToolId "bluetooth-service-restart" `
            -ToolName "Restart Bluetooth Service" `
            -Steps @("Stop bthserv service", "Wait for service stop", "Start bthserv service") `
            -AffectedResources @("Service:bthserv") `
            -RequiresAdmin $true `
            -Reversible $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId,

        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $true)]
        [string[]]$Steps,

        [Parameter(Mandatory = $true)]
        [string[]]$AffectedResources,

        [Parameter(Mandatory = $true)]
        [bool]$RequiresAdmin,

        [Parameter(Mandatory = $false)]
        [bool]$Reversible = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Low", "Medium", "High", "Critical", "Unknown")]
        [string]$EstimatedImpact = "Medium",

        [Parameter(Mandatory = $false)]
        [string[]]$Preconditions = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{}
    )

    # Validate steps are not empty
    if ($Steps.Count -eq 0) {
        throw "Plan must have at least one step"
    }

    # Validate affected resources are not empty for mutating operations
    if ($AffectedResources.Count -eq 0) {
        throw "Plan must declare affected resources"
    }

    return [PSCustomObject]@{
        PSTypeName        = 'WinConfig.DryRunPlan'
        ToolId            = $ToolId
        ToolName          = $ToolName
        Steps             = @($Steps)
        StepCount         = $Steps.Count
        AffectedResources = @($AffectedResources)
        ResourceCount     = $AffectedResources.Count
        RequiresAdmin     = $RequiresAdmin
        Reversible        = $Reversible
        EstimatedImpact   = $EstimatedImpact
        Preconditions     = @($Preconditions)
        Evidence          = $Evidence
        CreatedAtUtc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# =============================================================================
# PLAN STEP CREATION
# =============================================================================

function New-DryRunStep {
    <#
    .SYNOPSIS
        Creates a canonical dry-run plan step with a WOULD_* verb prefix.
    .DESCRIPTION
        Every plan step must begin with a canonical verb prefix for action transparency.
        This function enforces the verb contract and returns a structured step object
        with Verb, Target, Detail, and Summary fields.
        Use .Summary to get the human-readable string for New-DryRunPlan -Steps.
    .PARAMETER Verb
        The canonical action verb (WOULD_CREATE, WOULD_DELETE, etc.)
    .PARAMETER Target
        The resource or operation target (service name, file path, command, etc.)
    .PARAMETER Detail
        Optional additional context (provider name, arguments, etc.)
    .OUTPUTS
        PSCustomObject (WinConfig.DryRunStep) with Verb, Target, Detail, Summary
    .EXAMPLE
        $step = New-DryRunStep -Verb WOULD_DELETE -Target "driver package: oem12.inf" -Detail "Intel SST"
        # $step.Summary → "WOULD_DELETE driver package: oem12.inf (Intel SST)"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'WOULD_CREATE', 'WOULD_DELETE', 'WOULD_MOVE', 'WOULD_EXEC',
            'WOULD_SET', 'WOULD_DISABLE', 'WOULD_ENABLE', 'WOULD_RESTART'
        )]
        [string]$Verb,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$Detail = ''
    )

    $summary = if ($Detail) { "$Verb $Target ($Detail)" } else { "$Verb $Target" }

    return [PSCustomObject]@{
        PSTypeName = 'WinConfig.DryRunStep'
        Verb       = $Verb
        Target     = $Target
        Detail     = $Detail
        Summary    = $summary
    }
}

# =============================================================================
# REFUSAL (tools that do not support Dry Run)
# =============================================================================

function New-DryRunRefusal {
    <#
    .SYNOPSIS
        Creates a canonical refusal result for tools that do not support Dry Run.
    .DESCRIPTION
        Returns a machine-readable DryRunResult with Outcome = 'Refused'.
        Every tool invocation emits a DryRunResult, even when SupportsDryRun = $false.
        This normalizes output so the UI, telemetry, and ledger never need special-case logic.
    .PARAMETER ToolId
        The tool identifier from WinConfig.Tools.psd1
    .PARAMETER ToolName
        Human-readable tool name
    .PARAMETER FailureCode
        Machine-readable refusal code (default: DRYRUN_NOT_IMPLEMENTED)
    .PARAMETER FailureReason
        Human-readable refusal reason
    .OUTPUTS
        PSCustomObject (WinConfig.DryRunResult) with Outcome = 'Refused'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId,

        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $false)]
        [string]$FailureCode = 'DRYRUN_NOT_IMPLEMENTED',

        [Parameter(Mandatory = $false)]
        [string]$FailureReason = 'This tool does not yet support Dry Run.'
    )

    # Resolve intent for metadata consistency
    $resolution = $null
    try { $resolution = Resolve-DryRunIntent } catch { }
    $dryRunSource = if ($resolution) { $resolution.Source } else { 'Unknown' }
    $dryRunDetail = if ($resolution) { $resolution.Detail } else { 'Refusal path - resolution unavailable' }

    return [PSCustomObject]@{
        PSTypeName     = 'WinConfig.DryRunResult'
        OperationId    = $null
        ToolId         = $ToolId
        Executed       = $false
        Outcome        = 'Refused'
        FailureCode    = $FailureCode
        FailureReason  = $FailureReason
        Summary        = "[DRY RUN] Refused: $FailureReason"
        Plan           = $null
        SideEffects    = @()
        IsDryRun       = $true
        DryRunSource   = $dryRunSource
        DryRunDetail   = $dryRunDetail
    }
}

# =============================================================================
# DRY-RUN TRUTH SOURCE (Single authority for dry-run resolution)
# =============================================================================
#
# PRECEDENCE CONTRACT (strict, no disagreement allowed):
#   1. Explicit -DryRun switch → DryRun, always.
#   2. Legacy $env:WINCONFIG_ENV in (dev, ci, test) → DryRun (adapter shim).
#   3. Legacy $env:WINCONFIG_ENV in (prod, production) → Live.
#   4. ExecutionIntent = DIAGNOSTIC → DryRun (safe default).
#   5. ExecutionIntent = SAFE_ACTION or ADMIN_ACTION → Live (caller set intent).
#   6. Ambiguous (no signal at all) → THROW (fail-closed).
#
# RULES:
#   - -DryRun switch is the ONLY authoritative signal for new code paths.
#   - Legacy env var is allowed ONLY as a shim that maps to the new signal.
#   - $WhatIf / SupportsShouldProcess is an implementation detail inside
#     mutating cmdlets, NOT a mode controller. It does not participate here.
#

function Resolve-DryRunIntent {
    <#
    .SYNOPSIS
        Single truth source for whether dry-run mode is active.
    .DESCRIPTION
        Resolves the strict precedence contract for dry-run determination.
        This is the ONLY function that should be consulted to decide
        "am I in dry-run mode?" All other checks are shims that delegate here.

        Returns a structured object so callers can distinguish WHY dry-run
        is active (explicit switch vs. env var vs. intent fallback).
    .PARAMETER DryRun
        Explicit -DryRun switch from the caller. Takes absolute precedence.
    .OUTPUTS
        PSCustomObject with:
          - IsDryRun [bool]: Whether dry-run mode is active
          - Source [string]: Why (ExplicitSwitch, LegacyEnvVar, ExecutionIntent, FailClosed)
          - Detail [string]: Human-readable explanation
    #>
    [CmdletBinding()]
    param(
        [switch]$DryRun
    )

    # Precedence 1: Explicit -DryRun switch (absolute authority)
    if ($DryRun) {
        return [PSCustomObject]@{
            IsDryRun = $true
            Source   = 'ExplicitSwitch'
            Detail   = '-DryRun switch provided by caller'
        }
    }

    # Precedence 2-3: Legacy env var (adapter shim)
    if ($env:WINCONFIG_ENV -in @('dev', 'ci', 'test')) {
        return [PSCustomObject]@{
            IsDryRun = $true
            Source   = 'LegacyEnvVar'
            Detail   = "`$env:WINCONFIG_ENV='$env:WINCONFIG_ENV' maps to dry-run"
        }
    }
    if ($env:WINCONFIG_ENV -in @('prod', 'production')) {
        return [PSCustomObject]@{
            IsDryRun = $false
            Source   = 'LegacyEnvVar'
            Detail   = "`$env:WINCONFIG_ENV='$env:WINCONFIG_ENV' maps to live execution"
        }
    }

    # Precedence 4-5: ExecutionIntent system
    $intent = $null
    if (Get-Command Get-ExecutionIntent -ErrorAction SilentlyContinue) {
        $intent = Get-ExecutionIntent
    }
    if ($intent -eq 'DIAGNOSTIC') {
        return [PSCustomObject]@{
            IsDryRun = $true
            Source   = 'ExecutionIntent'
            Detail   = "ExecutionIntent='DIAGNOSTIC' defaults to dry-run"
        }
    }
    if ($intent -in @('SAFE_ACTION', 'ADMIN_ACTION')) {
        return [PSCustomObject]@{
            IsDryRun = $false
            Source   = 'ExecutionIntent'
            Detail   = "ExecutionIntent='$intent' permits live execution"
        }
    }

    # Precedence 6: Ambiguous — fail closed
    throw "FAIL-CLOSED: Cannot resolve dry-run intent. No -DryRun switch, no recognized `$env:WINCONFIG_ENV, and no ExecutionIntent active. This is a safety violation."
}

# =============================================================================
# GUARDED EXECUTION
# =============================================================================

function Invoke-DryRunGuarded {
    <#
    .SYNOPSIS
        Executes a tool with Dry Run support and side effect detection.
    .DESCRIPTION
        This is the canonical entry point for Dry-Run-capable tools.
        It enforces PLAN -> EXECUTE semantics and side effect detection.
    .PARAMETER ToolId
        The tool identifier from WinConfig.Tools.psd1
    .PARAMETER DryRun
        If specified, only creates a plan without executing
    .PARAMETER PlanScript
        Scriptblock that creates the plan (MUST be pure/deterministic)
    .PARAMETER ExecuteScript
        Scriptblock that performs the actual execution (side effects allowed)
    .OUTPUTS
        PSCustomObject: Ledger entry with operation result
    .EXAMPLE
        Invoke-DryRunGuarded -ToolId "bluetooth-service-restart" -DryRun -PlanScript {
            New-DryRunPlan -ToolId "bluetooth-service-restart" -ToolName "Restart Bluetooth" `
                -Steps @("Stop service", "Start service") `
                -AffectedResources @("Service:bthserv") -RequiresAdmin $true
        } -ExecuteScript {
            param($Plan)
            Restart-Service -Name bthserv
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $true)]
        [scriptblock]$PlanScript,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ExecuteScript,

        [Parameter(Mandatory = $false)]
        [string]$Category = "System",

        [Parameter(Mandatory = $false)]
        [string]$ToolCategory = "Other",

        [Parameter(Mandatory = $false)]
        [string]$Source = "Tool"
    )

    $plan = $null
    $result = $null
    $executed = $false
    $outcome = "Skipped"
    $summary = ""
    $sideEffects = @()
    $sideEffectBreakpoints = @()

    # Resolve dry-run intent for mode banner + ledger tagging
    $dryRunResolution = Resolve-DryRunIntent -DryRun:$DryRun

    try {
        # === PHASE 1: PLAN (Pure, deterministic) ===
        # Plan phase must NEVER produce side effects
        [System.Threading.Monitor]::Enter($script:DryRunLock)
        try {
            $script:DryRunActive = $true
            $script:DryRunSideEffectLog.Clear()
        }
        finally {
            [System.Threading.Monitor]::Exit($script:DryRunLock)
        }

        # === SIDE-EFFECT DETECTION: Intercept mutating commands during plan phase ===
        # Breakpoints fire if any guarded command is invoked, logging the violation.
        # Detection is active for dry-run plans; violations fail the plan via Assert below.
        if ($DryRun) {
            foreach ($cmd in $script:DryRunGuardedCommands) {
                $bp = Set-PSBreakpoint -Command $cmd -Action {
                    Register-DryRunSideEffect `
                        -Type "MutatingCommand" `
                        -Target $_.Command `
                        -Details "Invoked during dry-run plan phase"
                } -ErrorAction SilentlyContinue
                if ($bp) { $sideEffectBreakpoints += $bp }
            }
        }

        try {
            # Run PlanScript with & invocation (not dot-sourcing)
            # Dot-sourcing causes 'return' to exit the enclosing function, not return a value
            $plan = & $PlanScript
        }
        finally {
            # Clean up side-effect detection breakpoints immediately
            if ($sideEffectBreakpoints.Count -gt 0) {
                $sideEffectBreakpoints | Remove-PSBreakpoint -ErrorAction SilentlyContinue
            }

            [System.Threading.Monitor]::Enter($script:DryRunLock)
            try {
                $script:DryRunActive = $false
            }
            finally {
                [System.Threading.Monitor]::Exit($script:DryRunLock)
            }
        }

        # === SIDE-EFFECT ASSERTION: Fail plan if any mutating command was invoked ===
        if ($DryRun) {
            Assert-NoDryRunSideEffects
        }

        # Validate plan object
        if ($null -eq $plan) {
            throw "PlanScript must return a plan object"
        }
        # PSTypeName is stored in the pstypenames collection, not as a property
        if (-not ($plan.pstypenames -contains 'WinConfig.DryRunPlan')) {
            throw "PlanScript must return a WinConfig.DryRunPlan object (use New-DryRunPlan)"
        }

        # === DRY RUN PATH ===
        if ($DryRun) {
            $executed = $false

            # Check if PLAN phase itself failed (returned structured failure)
            # A plan with Evidence.PlanFailed = $true means planning could not complete
            if ($plan.Evidence -and $plan.Evidence.PlanFailed -eq $true) {
                $outcome = "Failed"
                $failReason = if ($plan.Evidence.FailureReason) { $plan.Evidence.FailureReason } else { "Planning preconditions not met" }
                $summary = "[DRY RUN] Plan failed: $failReason"
            } else {
                $outcome = "Skipped"
                $summary = "[DRY RUN] Plan created for: $($plan.ToolName)"
            }

            # Record in ledger with Executed = $false
            return Complete-DryRunOperation `
                -ToolId $ToolId `
                -Plan $plan `
                -Executed $false `
                -Outcome $outcome `
                -Summary $summary `
                -Category $Category `
                -ToolCategory $ToolCategory `
                -Source $Source `
                -SideEffects @() `
                -DryRunResolution $dryRunResolution
        }

        # === PHASE 2: EXECUTE (Side effects allowed) ===
        $executed = $true

        try {
            # Run ExecuteScript in module scope with plan parameter
            $result = . $ExecuteScript $plan
            $outcome = "Success"
            $summary = "Executed: $($plan.ToolName)"

            # Check for explicit result from execute script
            # Handle both hashtable and PSCustomObject
            if ($null -ne $result) {
                if ($result.Outcome) { $outcome = $result.Outcome }
                if ($result.Summary) { $summary = $result.Summary }
            }
        }
        catch {
            $outcome = "Failed"
            $summary = "Execution failed: $($_.Exception.Message)"
        }

        # Record in ledger with Executed = $true
        return Complete-DryRunOperation `
            -ToolId $ToolId `
            -Plan $plan `
            -Executed $true `
            -Outcome $outcome `
            -Summary $summary `
            -Category $Category `
            -ToolCategory $ToolCategory `
            -Source $Source `
            -SideEffects @() `
            -DryRunResolution $dryRunResolution
    }
    catch {
        # Planning phase failure (includes side-effect assertion violations)
        return Complete-DryRunOperation `
            -ToolId $ToolId `
            -Plan $plan `
            -Executed $false `
            -Outcome "Failed" `
            -Summary "Planning failed: $($_.Exception.Message)" `
            -Category $Category `
            -ToolCategory $ToolCategory `
            -Source $Source `
            -SideEffects @(Get-DryRunSideEffects) `
            -DryRunResolution $dryRunResolution
    }
}

# =============================================================================
# LEDGER INTEGRATION
# =============================================================================

function Complete-DryRunOperation {
    <#
    .SYNOPSIS
        Records a Dry Run or execution result in the session ledger.
    .DESCRIPTION
        Creates a ledger entry with the Executed and Plan fields required
        for Dry Run semantics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId,

        [Parameter(Mandatory = $false)]
        $Plan,

        [Parameter(Mandatory = $true)]
        [bool]$Executed,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Success", "Warning", "Failed", "Skipped", "Refused")]
        [string]$Outcome,

        [Parameter(Mandatory = $true)]
        [string]$Summary,

        [Parameter(Mandatory = $false)]
        [string]$Category = "System",

        [Parameter(Mandatory = $false)]
        [string]$ToolCategory = "Other",

        [Parameter(Mandatory = $false)]
        [string]$Source = "Tool",

        [Parameter(Mandatory = $false)]
        [array]$SideEffects = @(),

        [Parameter(Mandatory = $false)]
        $DryRunResolution = $null
    )

    # Extract resolution metadata for ledger + UI
    # Use resolution as truth source (not just !Executed, since a failed live execution has Executed=$false but IsDryRun=$false)
    $isDryRun = if ($DryRunResolution) { $DryRunResolution.IsDryRun } else { -not $Executed }
    $dryRunSource = if ($DryRunResolution) { $DryRunResolution.Source } else { 'Unknown' }
    $dryRunDetail = if ($DryRunResolution) { $DryRunResolution.Detail } else { 'Resolution not available' }

    # Map category to ledger category
    $ledgerCategory = switch ($Category) {
        "Diagnostics"   { "Other" }
        "Configuration" { "Other" }
        "AdminChange"   { "System" }
        "Maintenance"   { "Maintenance" }
        "Network"       { "Network" }
        "Bluetooth"     { "Bluetooth" }
        "Audio"         { "Audio" }
        "System"        { "System" }
        default         { "Other" }
    }

    # Build evidence with plan and dry run metadata
    $evidence = @{
        ToolId         = $ToolId
        Executed       = $Executed
        IsDryRun       = $isDryRun
        DryRunSource   = $dryRunSource
        DryRunDetail   = $dryRunDetail
        Outcome        = $Outcome
        SideEffects    = @($SideEffects)
        SideEffectCount = $SideEffects.Count
    }

    # Include plan in evidence if available
    if ($null -ne $Plan) {
        $evidence.Plan = @{
            Steps             = @($Plan.Steps)
            StepCount         = $Plan.StepCount
            AffectedResources = @($Plan.AffectedResources)
            ResourceCount     = $Plan.ResourceCount
            RequiresAdmin     = $Plan.RequiresAdmin
            Reversible        = $Plan.Reversible
            EstimatedImpact   = $Plan.EstimatedImpact
            Preconditions     = @($Plan.Preconditions)
        }
    }

    # Write to session operation ledger if available
    $writeSessionOp = Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue
    if (-not $writeSessionOp) {
        $writeSessionOp = Get-Command Write-SessionOperation -ErrorAction SilentlyContinue
    }

    if ($writeSessionOp) {
        $toolName = if ($Plan) { $Plan.ToolName } else { $ToolId }
        $operationId = & $writeSessionOp `
            -Category $ledgerCategory `
            -OperationType "Action" `
            -Name $toolName `
            -Source "$Source`:$ToolId" `
            -MutatesSystem $Executed `
            -Result $Outcome `
            -Summary $Summary `
            -Evidence $evidence

        return [PSCustomObject]@{
            PSTypeName     = 'WinConfig.DryRunResult'
            OperationId    = $operationId
            ToolId         = $ToolId
            Executed       = $Executed
            Outcome        = $Outcome
            Summary        = $Summary
            Plan           = $Plan
            SideEffects    = @($SideEffects)
            IsDryRun       = $isDryRun
            DryRunSource   = $dryRunSource
            DryRunDetail   = $dryRunDetail
        }
    }

    # Return result even if ledger not available
    return [PSCustomObject]@{
        PSTypeName     = 'WinConfig.DryRunResult'
        OperationId    = $null
        ToolId         = $ToolId
        Executed       = $Executed
        Outcome        = $Outcome
        Summary        = $Summary
        Plan           = $Plan
        SideEffects    = @($SideEffects)
        IsDryRun       = $isDryRun
        DryRunSource   = $dryRunSource
        DryRunDetail   = $dryRunDetail
    }
}

# =============================================================================
# GUARDRAILS
# =============================================================================

function Register-DryRunSideEffect {
    <#
    .SYNOPSIS
        Registers a side effect during Dry Run (used by instrumented APIs).
    .DESCRIPTION
        This function is called by instrumented system APIs to detect
        when side effects occur during what should be a pure planning phase.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$Details = ""
    )

    [System.Threading.Monitor]::Enter($script:DryRunLock)
    try {
        if ($script:DryRunActive) {
            $script:DryRunSideEffectLog.Add([PSCustomObject]@{
                Type      = $Type
                Target    = $Target
                Details   = $Details
                Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            })
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:DryRunLock)
    }
}

function Assert-NoDryRunSideEffects {
    <#
    .SYNOPSIS
        Asserts that no side effects were logged during Dry Run planning.
    .DESCRIPTION
        THROWS if any side effects were detected. Used by CI and runtime guards.
    #>
    [CmdletBinding()]
    param()

    [System.Threading.Monitor]::Enter($script:DryRunLock)
    try {
        if ($script:DryRunSideEffectLog.Count -gt 0) {
            $effects = $script:DryRunSideEffectLog | ForEach-Object {
                "$($_.Type): $($_.Target)"
            }
            throw "GUARDRAIL VIOLATION: Side effects detected during Dry Run planning:`n$($effects -join "`n")"
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:DryRunLock)
    }
}

function Test-DryRunActive {
    <#
    .SYNOPSIS
        Returns $true if currently in Dry Run planning phase.
    #>
    [CmdletBinding()]
    param()

    return $script:DryRunActive
}

function Get-DryRunSideEffects {
    <#
    .SYNOPSIS
        Returns logged side effects from the current or last Dry Run.
    #>
    [CmdletBinding()]
    param()

    return @($script:DryRunSideEffectLog)
}

# =============================================================================
# MUTATION BYPASS GATE
# =============================================================================

# Script-scoped registry of tool IDs that have been entered via a guarded path.
# Set by Invoke-DryRunGuarded (and future Invoke-ToolGuarded) before executing.
# Checked by Assert-MutationGuarded at the button dispatch layer.
$script:GuardedToolInvocations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Register-GuardedInvocation {
    <#
    .SYNOPSIS
        Marks a tool ID as currently executing through a guarded entrypoint.
    .DESCRIPTION
        Called by Invoke-DryRunGuarded at entry. The paired Clear-GuardedInvocation
        is called in the finally block. This prevents bypass detection from
        false-positiving during legitimate guarded execution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ToolId
    )
    [void]$script:GuardedToolInvocations.Add($ToolId)
}

function Clear-GuardedInvocation {
    <#
    .SYNOPSIS
        Removes a tool ID from the guarded invocation registry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ToolId
    )
    [void]$script:GuardedToolInvocations.Remove($ToolId)
}

function Assert-MutationGuarded {
    <#
    .SYNOPSIS
        Blocks mutating tool invocation that bypasses the guarded execution path.
    .DESCRIPTION
        Must be called at the tool dispatch boundary (UI button click handler)
        for any tool where MutatesSystem = $true.

        If a WinConfig.ExecutionContext is not provided, or the context was not
        created by a guarded entrypoint, this function throws MUTATION_BYPASS_BLOCKED.

        This eliminates the "live by accident" class of bugs where a developer calls
        a mutating function directly without going through Invoke-DryRunGuarded.
    .PARAMETER ToolId
        The tool identifier from WinConfig.Tools.psd1
    .PARAMETER ToolName
        Human-readable tool name (for error messages)
    .PARAMETER ExecutionContext
        A WinConfig.ExecutionContext object created by the guarded entrypoint.
        Must include: ExecutionIntent, IsDryRun, DryRunSource
    .EXAMPLE
        Assert-MutationGuarded -ToolId "bluetooth-service-restart" -ToolName "Restart Bluetooth" `
            -ExecutionContext $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ToolId,

        [Parameter(Mandatory)]
        [string]$ToolName,

        [Parameter(Mandatory = $false)]
        $ExecutionContext = $null
    )

    # Check: ExecutionContext must be provided
    if ($null -eq $ExecutionContext) {
        throw "MUTATION_BYPASS_BLOCKED: Mutating tool '$ToolName' ($ToolId) invoked without ExecutionContext. All mutating tools must be called through a guarded entrypoint (Invoke-DryRunGuarded or equivalent)."
    }

    # Check: ExecutionContext must have required fields
    $requiredFields = @('ExecutionIntent', 'IsDryRun', 'DryRunSource')
    foreach ($field in $requiredFields) {
        if ($null -eq $ExecutionContext.$field -and $ExecutionContext.$field -ne $false) {
            throw "MUTATION_BYPASS_BLOCKED: ExecutionContext for '$ToolName' ($ToolId) missing required field '$field'. Context must be created by a guarded entrypoint."
        }
    }

    # Check: ExecutionContext must be typed (prevents ad-hoc hashtable spoofing)
    if ($ExecutionContext -is [hashtable]) {
        if (-not $ExecutionContext.ContainsKey('_GuardedEntrypoint')) {
            throw "MUTATION_BYPASS_BLOCKED: ExecutionContext for '$ToolName' ($ToolId) was not created by a guarded entrypoint. Use New-ExecutionContext to create valid contexts."
        }
    }
}

function New-ExecutionContext {
    <#
    .SYNOPSIS
        Creates a WinConfig.ExecutionContext for mutation-guarded tool dispatch.
    .DESCRIPTION
        This is the ONLY function that should create execution contexts.
        The _GuardedEntrypoint field acts as a seal proving the context
        was created through the proper code path.
    .PARAMETER ToolId
        The tool identifier
    .PARAMETER IsDryRun
        Whether this is a dry-run invocation
    .PARAMETER DryRunSource
        Source of dry-run resolution (ExplicitSwitch, LegacyEnvVar, ExecutionIntent)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ToolId,

        [Parameter(Mandatory)]
        [bool]$IsDryRun,

        [Parameter(Mandatory)]
        [string]$DryRunSource
    )

    $intent = 'DIAGNOSTIC'
    if (Get-Command Get-ExecutionIntent -ErrorAction SilentlyContinue) {
        $intent = Get-ExecutionIntent
    }

    return @{
        _GuardedEntrypoint = $true
        ToolId             = $ToolId
        ExecutionIntent    = $intent
        IsDryRun           = $IsDryRun
        DryRunSource       = $DryRunSource
        CreatedAtUtc       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# =============================================================================
# TOOL MANIFEST VALIDATION
# =============================================================================

function Get-ToolManifest {
    <#
    .SYNOPSIS
        Returns the tool manifest from WinConfig.Tools.psd1.
    #>
    [CmdletBinding()]
    param()

    $manifestPath = Join-Path $PSScriptRoot "..\Manifest\WinConfig.Tools.psd1"
    if (-not (Test-Path $manifestPath)) {
        throw "Tool manifest not found at: $manifestPath"
    }

    return Import-PowerShellDataFile -Path $manifestPath
}

function Get-ToolDefinition {
    <#
    .SYNOPSIS
        Returns the tool definition for a specific tool ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId
    )

    $manifest = Get-ToolManifest
    $tool = $manifest.tools | Where-Object { $_.Id -eq $ToolId }

    if (-not $tool) {
        throw "Tool not found in manifest: $ToolId"
    }

    return $tool
}

function Assert-ToolSupportsDryRun {
    <#
    .SYNOPSIS
        Asserts that a tool supports Dry Run (CI guardrail).
    .DESCRIPTION
        THROWS if the tool mutates system state but does not support Dry Run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolId
    )

    $tool = Get-ToolDefinition -ToolId $ToolId

    if ($tool.MutatesSystem -eq $true -and $tool.SupportsDryRun -ne $true) {
        throw "GUARDRAIL B VIOLATION: Tool '$ToolId' mutates system state but SupportsDryRun != `$true"
    }
}

function Test-ToolManifestCompliance {
    <#
    .SYNOPSIS
        Validates all tools in the manifest for Dry Run compliance.
    .DESCRIPTION
        Returns validation results for CI enforcement.
    .OUTPUTS
        PSCustomObject with Passed, Failed, and Violations arrays.
    #>
    [CmdletBinding()]
    param()

    $manifest = Get-ToolManifest
    $passed = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    $violations = [System.Collections.Generic.List[object]]::new()

    foreach ($tool in $manifest.tools) {
        # Guardrail B: MutatesSystem = $true requires SupportsDryRun = $true
        if ($tool.MutatesSystem -eq $true) {
            if ($tool.SupportsDryRun -ne $true) {
                $failed.Add($tool.Id)
                $violations.Add([PSCustomObject]@{
                    ToolId    = $tool.Id
                    ToolName  = $tool.Name
                    Guardrail = "B"
                    Rule      = "MutatesSystem=true requires SupportsDryRun=true"
                    Actual    = "SupportsDryRun=$($tool.SupportsDryRun)"
                })
            }
            else {
                $passed.Add($tool.Id)
            }
        }
        else {
            # Non-mutating tools pass by default
            $passed.Add($tool.Id)
        }

        # Check for missing required fields
        if ($null -eq $tool.SupportsDryRun) {
            $failed.Add($tool.Id)
            $violations.Add([PSCustomObject]@{
                ToolId    = $tool.Id
                ToolName  = $tool.Name
                Guardrail = "A"
                Rule      = "SupportsDryRun must be explicitly declared"
                Actual    = "SupportsDryRun is null/missing"
            })
        }
    }

    return [PSCustomObject]@{
        TotalTools = $manifest.tools.Count
        Passed     = @($passed)
        PassedCount = $passed.Count
        Failed     = @($failed)
        FailedCount = $failed.Count
        Violations = @($violations)
        Success    = ($failed.Count -eq 0)
    }
}

# =============================================================================
# CONTRACT AUDIT (Ops debug tool)
# =============================================================================

function Invoke-DryRunContractAudit {
    <#
    .SYNOPSIS
        Prints a one-page Dry Run contract scoreboard from the live codebase.
    .DESCRIPTION
        Reads the sealed tool manifest, scans for plan generators, counts
        refusal adapters, lists guarded commands, and shows the last 10 ledger
        entries. Intended as a single ops command for verifying contract health.
    .OUTPUTS
        Formatted console output (not a return object).
    #>
    [CmdletBinding()]
    param()

    # --- Load manifest ---
    $manifest = Get-ToolManifest
    $tools = $manifest.tools

    $totalTools     = $tools.Count
    $mutatingTools  = @($tools | Where-Object { $_.MutatesSystem -eq $true })
    $dryRunCapable  = @($mutatingTools | Where-Object { $_.SupportsDryRun -eq $true })
    $dryRunExempt   = @($mutatingTools | Where-Object { $_.DryRunExempt -eq $true })
    $dryRunPlanned  = @($mutatingTools | Where-Object { $_.SupportsDryRun -ne $true -and $_.DryRunExempt -ne $true })
    $readOnlyTools  = @($tools | Where-Object { $_.MutatesSystem -eq $false })

    # --- Scan for plan generators in Win11Config.App.ps1 ---
    $appPath = Join-Path $PSScriptRoot "..\Win11Config.App.ps1"
    $missingPlanGenerators = @()
    if (Test-Path $appPath) {
        $appContent = Get-Content $appPath -Raw
        foreach ($tool in $dryRunCapable) {
            $escapedId = [regex]::Escape("`"$($tool.Id)`"")
            if ($appContent -notmatch $escapedId) {
                $missingPlanGenerators += $tool.Id
            }
        }
    } else {
        $missingPlanGenerators = @("(cannot scan: App.ps1 not found)")
    }

    # --- Count legacy refusal adapters (New-DryRunRefusal calls in Bluetooth.psm1) ---
    $refusalCount = 0
    $btModulePath = Join-Path $PSScriptRoot "Bluetooth.psm1"
    if (Test-Path $btModulePath) {
        $btContent = Get-Content $btModulePath -Raw
        $refusalMatches = [regex]::Matches($btContent, 'New-DryRunRefusal')
        $refusalCount = $refusalMatches.Count
    }

    # --- Guarded commands ---
    $guardedCmds = $script:DryRunGuardedCommands

    # --- Ledger entries (last 10) ---
    $ledgerEntries = @()
    if (Get-Command Get-LedgerOperations -ErrorAction SilentlyContinue) {
        try {
            $allOps = Get-LedgerOperations
            if ($allOps -and $allOps.Count -gt 0) {
                $ledgerEntries = @($allOps | Select-Object -Last 10)
            }
        } catch { }
    }

    # === RENDER SCOREBOARD ===
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   DRY RUN CONTRACT SCOREBOARD" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Section 1: Tool counts
    Write-Host "TOOL MANIFEST" -ForegroundColor Yellow
    Write-Host "  Total tools:               $totalTools"
    Write-Host "  Read-only:                 $($readOnlyTools.Count)"
    Write-Host "  Mutating (total):          $($mutatingTools.Count)"
    Write-Host "  Mutating + SupportsDryRun: $($dryRunCapable.Count)" -ForegroundColor Green
    Write-Host "  Planned (awaiting DR):     $($dryRunPlanned.Count)" -ForegroundColor $(if ($dryRunPlanned.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Exempt (frozen policy):    $($dryRunExempt.Count)" -ForegroundColor DarkGray
    Write-Host ""

    # Section 2: Planned debt
    if ($dryRunPlanned.Count -gt 0) {
        Write-Host "PLANNED (high-blast, awaiting plan generators)" -ForegroundColor Yellow
        foreach ($d in $dryRunPlanned) {
            Write-Host "  - $($d.Id)" -ForegroundColor DarkYellow
        }
        Write-Host ""
    }

    # Section 2b: Exempt tools
    if ($dryRunExempt.Count -gt 0) {
        Write-Host "EXEMPT (frozen policy, low-blast hygiene)" -ForegroundColor DarkGray
        foreach ($e in $dryRunExempt) {
            Write-Host "  - $($e.Id): $($e.DryRunExemptReason)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Section 3: Plan generator coverage
    Write-Host "PLAN GENERATORS" -ForegroundColor Yellow
    Write-Host "  Required (MutatesSystem + SupportsDryRun): $($dryRunCapable.Count)"
    Write-Host "  Missing plan generators:                   $($missingPlanGenerators.Count)" -ForegroundColor $(if ($missingPlanGenerators.Count -gt 0) { 'Red' } else { 'Green' })
    if ($missingPlanGenerators.Count -gt 0) {
        foreach ($m in $missingPlanGenerators) {
            Write-Host "    MISSING: $m" -ForegroundColor Red
        }
    }
    Write-Host ""

    # Section 4: Legacy adapters
    Write-Host "REFUSAL ADAPTERS" -ForegroundColor Yellow
    Write-Host "  New-DryRunRefusal calls (Bluetooth.psm1): $refusalCount"
    Write-Host ""

    # Section 5: Guarded commands
    Write-Host "GUARDED COMMANDS ($($guardedCmds.Count) intercepted during plan phase)" -ForegroundColor Yellow
    $guardedLines = @()
    for ($i = 0; $i -lt $guardedCmds.Count; $i += 4) {
        $chunk = $guardedCmds[$i..([math]::Min($i + 3, $guardedCmds.Count - 1))]
        $guardedLines += "  " + ($chunk -join ", ")
    }
    foreach ($line in $guardedLines) {
        Write-Host $line
    }
    Write-Host ""

    # Section 6: Last 10 ledger entries
    Write-Host "LAST 10 LEDGER ENTRIES" -ForegroundColor Yellow
    if ($ledgerEntries.Count -eq 0) {
        Write-Host "  (no ledger entries in current session)"
    } else {
        Write-Host "  ToolId                     | IsDryRun | Source          | Outcome  | SideEffects"
        Write-Host "  ---------------------------+----------+-----------------+----------+-----------"
        foreach ($entry in $ledgerEntries) {
            $toolId      = if ($entry.Evidence.ToolId)      { $entry.Evidence.ToolId }      else { $entry.Name }
            $isDryRun    = if ($null -ne $entry.Evidence.IsDryRun) { $entry.Evidence.IsDryRun } else { -not $entry.Executed }
            $source      = if ($entry.Evidence.DryRunSource) { $entry.Evidence.DryRunSource } else { "-" }
            $outcome     = if ($entry.Result) { $entry.Result } else { "-" }
            $sideEffects = if ($null -ne $entry.Evidence.SideEffectCount) { $entry.Evidence.SideEffectCount } else { 0 }

            $toolIdPad   = $toolId.PadRight(28).Substring(0, 28)
            $isDryRunPad = "$isDryRun".PadRight(8).Substring(0, 8)
            $sourcePad   = "$source".PadRight(15).Substring(0, 15)
            $outcomePad  = "$outcome".PadRight(8).Substring(0, 8)

            $color = switch ($outcome) {
                'Failed'  { 'Red' }
                'Refused' { 'Yellow' }
                'Skipped' { 'DarkGray' }
                default   { 'White' }
            }
            Write-Host "  $toolIdPad | $isDryRunPad | $sourcePad | $outcomePad | $sideEffects" -ForegroundColor $color
        }
    }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
}

# =============================================================================
# MODULE EXPORTS
# =============================================================================

Export-ModuleMember -Function @(
    # Plan step creation
    'New-DryRunStep',

    # Plan creation
    'New-DryRunPlan',

    # Refusal (tools without dry-run support)
    'New-DryRunRefusal',

    # Truth source (single authority for dry-run resolution)
    'Resolve-DryRunIntent',

    # Guarded execution
    'Invoke-DryRunGuarded',

    # Ledger integration
    'Complete-DryRunOperation',

    # Guardrails
    'Register-DryRunSideEffect',
    'Assert-NoDryRunSideEffects',
    'Test-DryRunActive',
    'Get-DryRunSideEffects',

    # Mutation bypass gate
    'Assert-MutationGuarded',
    'New-ExecutionContext',

    # Manifest validation
    'Get-ToolManifest',
    'Get-ToolDefinition',
    'Assert-ToolSupportsDryRun',
    'Test-ToolManifestCompliance',

    # Contract audit (ops debug tool)
    'Invoke-DryRunContractAudit'
)

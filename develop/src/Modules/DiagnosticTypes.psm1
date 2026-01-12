<#
.SYNOPSIS
    Closed type system for diagnostic results - Windows PowerShell 5.1 compatible.

.DESCRIPTION
    This module defines the ONLY valid result types for all diagnostics:
    - DiagnosticResult: PASS, WARN, FAIL, NOT_RUN (simulated enum)
    - PreconditionResult: PASS, FAIL, SKIP (simulated enum)
    - DiagnosticOutcome: Validated PSCustomObject with immutable-like semantics

    CONTRACT:
    - No string-based results allowed anywhere in the codebase
    - All diagnostics must return DiagnosticOutcome via harness
    - NOT_RUN requires Evidence.Preconditions with typed values
    - Attempted flag is set by harness, not diagnostic

.NOTES
    Version: 1.0.0
    Contract: DIAGNOSTIC-TYPE-2026-01-12
    Compatible: Windows PowerShell 5.1+, PowerShell 7+
#>

# =============================================================================
# SIMULATED ENUMS - Closed sets via ValidateSet
# =============================================================================

# DiagnosticResult "enum" - valid values
$script:DiagnosticResultValues = @('PASS', 'WARN', 'FAIL', 'NOT_RUN')

# PreconditionResult "enum" - valid values
$script:PreconditionResultValues = @('PASS', 'FAIL', 'SKIP')

# Export as module variables for external validation
$DiagnosticResult = @{
    PASS    = 'PASS'
    WARN    = 'WARN'
    FAIL    = 'FAIL'
    NOT_RUN = 'NOT_RUN'
}

$PreconditionResult = @{
    PASS = 'PASS'
    FAIL = 'FAIL'
    SKIP = 'SKIP'
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

function Test-DiagnosticResult {
    <#
    .SYNOPSIS
        Validates a value is a valid DiagnosticResult.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value
    )

    return ($Value -in $script:DiagnosticResultValues)
}

function Test-PreconditionResult {
    <#
    .SYNOPSIS
        Validates a value is a valid PreconditionResult.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value
    )

    return ($Value -in $script:PreconditionResultValues)
}

# =============================================================================
# DIAGNOSTIC OUTCOME FACTORY (Replaces class constructor)
# =============================================================================

function New-DiagnosticOutcome {
    <#
    .SYNOPSIS
        Creates a validated DiagnosticOutcome object.

    .DESCRIPTION
        Factory function that creates a DiagnosticOutcome with full validation.
        Throws on any invariant violation. All invariants are checked at creation time.

    .PARAMETER Result
        The diagnostic result (PASS, WARN, FAIL, NOT_RUN).

    .PARAMETER Reason
        Human-readable explanation of the result. Required, cannot be empty.

    .PARAMETER Evidence
        Hashtable of supporting evidence. If Result is NOT_RUN, must contain
        'Preconditions' key with hashtable of PreconditionResult values.

    .PARAMETER Attempted
        Whether the diagnostic logic was actually invoked. Set by harness, not diagnostic.
        If false, Result must be NOT_RUN.

    .PARAMETER DiagnosticId
        Optional identifier for the diagnostic that produced this outcome.

    .OUTPUTS
        [PSCustomObject] representing DiagnosticOutcome

    .EXAMPLE
        New-DiagnosticOutcome -Result 'PASS' -Reason "DNS resolved successfully" -Evidence @{ ResolvedIPs = @("1.2.3.4") } -Attempted $true

    .EXAMPLE
        New-DiagnosticOutcome -Result 'NOT_RUN' -Reason "Network unavailable" -Evidence @{ Preconditions = @{ Network = 'FAIL' } } -Attempted $false
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'NOT_RUN')]
        [string]$Result,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason,

        [Parameter()]
        [hashtable]$Evidence = @{},

        [Parameter(Mandatory)]
        [bool]$Attempted,

        [Parameter()]
        [string]$DiagnosticId
    )

    # Invariant: Evidence cannot be null
    if ($null -eq $Evidence) {
        throw "CONSTRUCTION VIOLATION: Evidence cannot be null (use empty hashtable @{})"
    }

    # Invariant: NOT_RUN requires precondition evidence
    if ($Result -eq 'NOT_RUN') {
        if (-not $Evidence.ContainsKey('Preconditions')) {
            throw "CONSTRUCTION VIOLATION: NOT_RUN requires Evidence.Preconditions hashtable"
        }
        $preconditions = $Evidence['Preconditions']
        if ($preconditions -isnot [hashtable]) {
            throw "CONSTRUCTION VIOLATION: Evidence.Preconditions must be a hashtable"
        }
        foreach ($key in $preconditions.Keys) {
            $val = $preconditions[$key]
            if (-not (Test-PreconditionResult -Value $val)) {
                throw "CONSTRUCTION VIOLATION: Evidence.Preconditions['$key'] must be a valid PreconditionResult (PASS/FAIL/SKIP), got '$val'"
            }
        }
    }

    # Invariant: If not attempted, result must be NOT_RUN
    if (-not $Attempted -and $Result -ne 'NOT_RUN') {
        throw "CONSTRUCTION VIOLATION: Attempted=`$false requires Result='NOT_RUN'"
    }

    # All checks passed - create immutable-like object
    $outcome = [PSCustomObject]@{
        PSTypeName   = 'DiagnosticOutcome'
        Result       = $Result
        Reason       = $Reason
        Evidence     = $Evidence
        Attempted    = $Attempted
        Timestamp    = [datetime]::UtcNow
        DiagnosticId = $DiagnosticId
    }

    # Note: PSCustomObject properties cannot be made truly immutable in PS 5.1
    # The validation at construction time provides the contract guarantee

    return $outcome
}

# =============================================================================
# RUNTIME INVARIANT GUARD
# =============================================================================

function Assert-ValidDiagnosticOutcome {
    <#
    .SYNOPSIS
        Runtime invariant guard - throws on invalid outcome.

    .DESCRIPTION
        Validates that a DiagnosticOutcome object meets all contracts:
        - Is correct type (PSCustomObject with DiagnosticOutcome typename)
        - Has valid DiagnosticResult value
        - Has non-empty Reason
        - Has non-null Evidence
        - If NOT_RUN, has typed Preconditions evidence
        - If Attempted=false, Result must be NOT_RUN

        Defense in depth - New-DiagnosticOutcome already validates, but this
        provides an additional checkpoint at API boundaries.

    .PARAMETER Outcome
        The DiagnosticOutcome to validate.

    .PARAMETER Context
        Optional context string for error messages (e.g., function name).

    .OUTPUTS
        Returns the outcome if valid; throws if invalid.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Outcome,

        [Parameter()]
        [string]$Context = "Unknown"
    )

    process {
        # Type check
        if ($Outcome.PSTypeName -ne 'DiagnosticOutcome') {
            if ($Outcome.PSObject.TypeNames -notcontains 'DiagnosticOutcome') {
                throw "INVARIANT VIOLATION [$Context]: Expected DiagnosticOutcome, got $($Outcome.GetType().Name)"
            }
        }

        # Result validity
        if (-not (Test-DiagnosticResult -Value $Outcome.Result)) {
            throw "INVARIANT VIOLATION [$Context]: Invalid DiagnosticResult '$($Outcome.Result)'"
        }

        # Reason check
        if ([string]::IsNullOrWhiteSpace($Outcome.Reason)) {
            throw "INVARIANT VIOLATION [$Context]: DiagnosticOutcome.Reason cannot be null or empty"
        }

        # Evidence check
        if ($null -eq $Outcome.Evidence) {
            throw "INVARIANT VIOLATION [$Context]: DiagnosticOutcome.Evidence cannot be null"
        }

        # NOT_RUN precondition evidence check (defense in depth)
        if ($Outcome.Result -eq 'NOT_RUN') {
            if (-not $Outcome.Evidence.ContainsKey('Preconditions')) {
                throw "INVARIANT VIOLATION [$Context]: NOT_RUN requires Evidence.Preconditions"
            }
            $preconditions = $Outcome.Evidence['Preconditions']
            if ($preconditions -isnot [hashtable]) {
                throw "INVARIANT VIOLATION [$Context]: Evidence.Preconditions must be hashtable"
            }
            foreach ($key in $preconditions.Keys) {
                $val = $preconditions[$key]
                if (-not (Test-PreconditionResult -Value $val)) {
                    throw "INVARIANT VIOLATION [$Context]: Preconditions['$key'] must be valid PreconditionResult, got '$val'"
                }
            }
        }

        # Attempted consistency check
        if (-not $Outcome.Attempted -and $Outcome.Result -ne 'NOT_RUN') {
            throw "INVARIANT VIOLATION [$Context]: Attempted=`$false requires Result='NOT_RUN'"
        }

        return $Outcome
    }
}

# =============================================================================
# EXHAUSTIVE SWITCH HELPER
# =============================================================================

function Switch-DiagnosticResult {
    <#
    .SYNOPSIS
        Exhaustive switch on DiagnosticResult - throws if any case missing.

    .DESCRIPTION
        Enforces exhaustive pattern matching on DiagnosticResult.
        All four cases (PASS, WARN, FAIL, NOT_RUN) MUST be provided.

    .PARAMETER Result
        The DiagnosticResult value to switch on.

    .PARAMETER Cases
        Hashtable mapping result values to scriptblocks.
        Keys: 'PASS', 'WARN', 'FAIL', 'NOT_RUN'
        Values: Scriptblocks to execute for each case.

    .OUTPUTS
        Result of executing the matching case's scriptblock.

    .EXAMPLE
        $color = Switch-DiagnosticResult -Result $outcome.Result -Cases @{
            'PASS'    = { "Green" }
            'WARN'    = { "Orange" }
            'FAIL'    = { "Red" }
            'NOT_RUN' = { "Gray" }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'NOT_RUN')]
        [string]$Result,

        [Parameter(Mandatory)]
        [hashtable]$Cases
    )

    # Exhaustiveness check
    foreach ($required in $script:DiagnosticResultValues) {
        if (-not $Cases.ContainsKey($required)) {
            throw "EXHAUSTIVENESS VIOLATION: Switch-DiagnosticResult missing case for '$required'"
        }
        if ($Cases[$required] -isnot [scriptblock]) {
            throw "EXHAUSTIVENESS VIOLATION: Case '$required' must be a scriptblock, got $($Cases[$required].GetType().Name)"
        }
    }

    # Execute the matching case
    return & $Cases[$Result]
}

function Switch-PreconditionResult {
    <#
    .SYNOPSIS
        Exhaustive switch on PreconditionResult - throws if any case missing.

    .DESCRIPTION
        Same pattern as Switch-DiagnosticResult but for PreconditionResult.

    .PARAMETER Result
        The PreconditionResult value to switch on.

    .PARAMETER Cases
        Hashtable mapping result values to scriptblocks.

    .OUTPUTS
        Result of executing the matching case's scriptblock.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'SKIP')]
        [string]$Result,

        [Parameter(Mandatory)]
        [hashtable]$Cases
    )

    foreach ($required in $script:PreconditionResultValues) {
        if (-not $Cases.ContainsKey($required)) {
            throw "EXHAUSTIVENESS VIOLATION: Switch-PreconditionResult missing case for '$required'"
        }
        if ($Cases[$required] -isnot [scriptblock]) {
            throw "EXHAUSTIVENESS VIOLATION: Case '$required' must be a scriptblock"
        }
    }

    return & $Cases[$Result]
}

# =============================================================================
# SERIALIZATION BOUNDARY HELPERS
# =============================================================================

function ConvertTo-DiagnosticOutcomeJson {
    <#
    .SYNOPSIS
        Serializes DiagnosticOutcome to JSON.

    .DESCRIPTION
        Converts DiagnosticOutcome to JSON string for logging and artifacts.

    .PARAMETER Outcome
        The DiagnosticOutcome to serialize.

    .OUTPUTS
        JSON string representation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Outcome
    )

    process {
        $jsonObj = @{
            Result       = $Outcome.Result
            Reason       = $Outcome.Reason
            Evidence     = $Outcome.Evidence
            Attempted    = $Outcome.Attempted
            Timestamp    = $Outcome.Timestamp.ToString("o")
            DiagnosticId = $Outcome.DiagnosticId
        }

        return $jsonObj | ConvertTo-Json -Depth 10 -Compress
    }
}

function ConvertFrom-DiagnosticOutcomeJson {
    <#
    .SYNOPSIS
        Deserializes JSON to DiagnosticOutcome.

    .DESCRIPTION
        Strictly parses JSON back to validated DiagnosticOutcome.
        Throws on any invalid value (fail-fast).

    .PARAMETER Json
        JSON string to parse.

    .OUTPUTS
        [PSCustomObject] DiagnosticOutcome
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Json
    )

    process {
        $data = $Json | ConvertFrom-Json

        # Validate Result
        if (-not (Test-DiagnosticResult -Value $data.Result)) {
            throw "DESERIALIZATION VIOLATION: Invalid DiagnosticResult '$($data.Result)'"
        }

        # Convert Evidence back to hashtable
        $evidence = @{}
        if ($data.Evidence) {
            foreach ($prop in $data.Evidence.PSObject.Properties) {
                if ($prop.Name -eq 'Preconditions' -and $prop.Value) {
                    $preconditions = @{}
                    foreach ($preconProp in $prop.Value.PSObject.Properties) {
                        if (-not (Test-PreconditionResult -Value $preconProp.Value)) {
                            throw "DESERIALIZATION VIOLATION: Invalid PreconditionResult '$($preconProp.Value)'"
                        }
                        $preconditions[$preconProp.Name] = $preconProp.Value
                    }
                    $evidence['Preconditions'] = $preconditions
                } else {
                    $evidence[$prop.Name] = $prop.Value
                }
            }
        }

        return New-DiagnosticOutcome `
            -Result $data.Result `
            -Reason $data.Reason `
            -Evidence $evidence `
            -Attempted $data.Attempted `
            -DiagnosticId $data.DiagnosticId
    }
}

# =============================================================================
# EXPORTS
# =============================================================================

Export-ModuleMember -Function @(
    'New-DiagnosticOutcome',
    'Assert-ValidDiagnosticOutcome',
    'Test-DiagnosticResult',
    'Test-PreconditionResult',
    'Switch-DiagnosticResult',
    'Switch-PreconditionResult',
    'ConvertTo-DiagnosticOutcomeJson',
    'ConvertFrom-DiagnosticOutcomeJson'
) -Variable @(
    'DiagnosticResult',
    'PreconditionResult'
)

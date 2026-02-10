# Logger.psm1 - Session-scoped JSONL logging for WinConfig
# Phase 2A: Deterministic audit trail for client systems and forensic debugging
#
# EPHEMERAL CONTRACT:
# - All logs are written to session-scoped temp directory
# - Logs are deleted on application exit
# - No persistent artifacts remain after termination

# CONTRACT:
# Every session action MUST end with PASS/WARN/FAIL/NOT_RUN.
# PENDING is transitional only - never a valid final state.
# Unresolved actions (PENDING at render time) are auto-coerced to FAIL.
# NOT_RUN indicates preconditions not met (replaces INSUFFICIENT_SIGNAL).
# Tier constraints: PASS=0, WARN≥1, FAIL≥2, NOT_RUN≥1
# ActionId (GUID) ensures deterministic completion of concurrent/retried actions.

# Import Paths module for ephemeral temp root
# CRITICAL: Use -Global to preserve already-imported module in global scope
# Without -Global, -Force would remove the global module and re-import locally
$script:PathsModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\Paths.psm1"
if (Test-Path $script:PathsModulePath) {
    Import-Module $script:PathsModulePath -Force -ErrorAction SilentlyContinue -Global
}

# Import type definitions for result validation
# CRITICAL: Use -Global to preserve already-imported module in global scope
$script:DiagnosticsTypesPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules\DiagnosticTypes.psm1"
if (Test-Path $script:DiagnosticsTypesPath) {
    Import-Module $script:DiagnosticsTypesPath -Force -ErrorAction SilentlyContinue -Global
}

# Script-scoped state
$script:SessionId = $null
$script:LogDirectory = $null
$script:LogFilePath = $null
$script:LoggerInitialized = $false
$script:AppVersion = "unknown"
$script:Iteration = "unknown"
$script:SessionActions = @()

# SAFETY: Track logging failures for audit trail integrity
$script:LoggingBroken = $false
$script:LastLogError = $null
$script:LogWriteFailureCount = 0

function Initialize-Logger {
    <#
    .SYNOPSIS
        Initializes the logging system with a new session ID.
    .DESCRIPTION
        Creates session ID, ensures log directory exists, and prepares for JSONL logging.
        Must be called once at application startup.
    .PARAMETER Version
        Application version string (e.g., "2026.01.06")
    .PARAMETER Iteration
        Application iteration (production, staging, dev). Alias: Channel (deprecated)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Version = "unknown",

        [Parameter(Mandatory = $false)]
        [Alias("Channel")]
        [string]$Iteration = "unknown"
    )

    # Guard against double-initialization
    if ($script:LoggerInitialized) {
        return
    }

    # Store version and iteration
    $script:AppVersion = $Version
    $script:Iteration = $Iteration

    # Generate session ID: yyyyMMdd-HHmmss-<8charGuid>
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $guidPart = ([guid]::NewGuid().ToString("N")).Substring(0, 8)
    $script:SessionId = "$timestamp-$guidPart"

    # Set log directory: ephemeral session-scoped temp path
    # Uses Paths.psm1 for session-scoped temp root (zero-footprint)
    if (Get-Command Get-WinConfigLogsPath -ErrorAction SilentlyContinue) {
        $script:LogDirectory = Get-WinConfigLogsPath
    }
    else {
        # Fallback to temp if Paths module not loaded
        $script:LogDirectory = Join-Path $env:TEMP "WinConfig-logs-$($script:SessionId)"
    }

    # Attempt to create directory if missing
    try {
        if (-not (Test-Path $script:LogDirectory)) {
            New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
        }

        # Set log file path for this session
        $logFileName = "winconfig-$($script:SessionId).jsonl"
        $script:LogFilePath = Join-Path $script:LogDirectory $logFileName

        $script:LoggerInitialized = $true
    }
    catch {
        # Fail gracefully - logging will be disabled but app continues
        $script:LoggerInitialized = $false
        $script:LogFilePath = $null
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a structured log entry in JSONL format.
    .DESCRIPTION
        Appends a single JSON object (one line) to the session log file.
        Includes timestamp, level, session ID, user, machine, version, channel, action, message,
        and outcome fields (result, tier, summary).
    .PARAMETER Level
        Log level: INFO, WARN, or ERROR
    .PARAMETER Action
        Short action identifier (e.g., "Startup", "DriverRemoval", "GPOWrite")
    .PARAMETER Message
        Human-readable description of the event
    .PARAMETER Result
        Action outcome: PASS, WARN, FAIL, or PENDING
    .PARAMETER Tier
        Escalation tier (0-5)
    .PARAMETER Summary
        Operator-readable summary of the outcome
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO",

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Result = "",

        [Parameter(Mandatory = $false)]
        [int]$Tier = 0,

        [Parameter(Mandatory = $false)]
        [string]$Summary = ""
    )

    # Skip if logger not initialized or no valid log path
    if (-not $script:LoggerInitialized -or -not $script:LogFilePath) {
        return
    }

    # Build log entry object
    $logEntry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        level     = $Level
        sessionId = $script:SessionId
        user      = $env:USERNAME
        machine   = $env:COMPUTERNAME
        version   = $script:AppVersion
        iteration = $script:Iteration
        action    = $Action
        message   = $Message
    }

    # Add outcome fields if result is provided
    if ($Result -ne "") {
        $logEntry.result = $Result
        $logEntry.tier = $Tier
        $logEntry.summary = $Summary
    }

    # Convert to JSON (single line) and append to file
    try {
        $jsonLine = $logEntry | ConvertTo-Json -Compress
        Add-Content -Path $script:LogFilePath -Value $jsonLine -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # CRITICAL: Logging failure - track for audit trail integrity warning
        $script:LoggingBroken = $true
        $script:LastLogError = $_.Exception.Message
        $script:LogWriteFailureCount++

        # Attempt fallback to Windows Event Log (best-effort)
        try {
            # Register event source if needed (will fail silently if no admin rights)
            if (-not [System.Diagnostics.EventLog]::SourceExists("WinConfig")) {
                [System.Diagnostics.EventLog]::CreateEventSource("WinConfig", "Application")
            }
            Write-EventLog -LogName Application -Source "WinConfig" `
                -EventId 9001 -EntryType Warning `
                -Message "WinConfig logging failed: $($_.Exception.Message). Action: $Action"
        } catch {
            # Event log fallback also failed - nothing more we can do
        }
    }
}

function Get-CurrentSessionId {
    <#
    .SYNOPSIS
        Returns the current session ID.
    .DESCRIPTION
        Returns the session ID generated during Initialize-Logger.
        Returns $null if logger has not been initialized.
    #>
    [CmdletBinding()]
    param()

    return $script:SessionId
}

function Get-LogPath {
    <#
    .SYNOPSIS
        Returns the current log file path with status context.
    .DESCRIPTION
        Returns a hashtable with 'Status' and 'Path' keys.
        Status can be: 'Active', 'Initialized', 'Disabled'
    #>
    [CmdletBinding()]
    param()

    if (-not $script:LoggerInitialized) {
        return @{
            Status = "Disabled"
            Path   = $null
        }
    }

    if (-not $script:LogFilePath -or -not (Test-Path $script:LogFilePath)) {
        return @{
            Status = "Initialized"
            Path   = $script:LogFilePath
        }
    }

    return @{
        Status = "Active"
        Path   = $script:LogFilePath
    }
}

function Register-SessionAction {
    <#
    .SYNOPSIS
        Registers an action in the session action timeline with outcome tracking.
    .DESCRIPTION
        Adds an action to the in-memory session action registry and optionally logs it.
        Use this to track meaningful operator-visible actions for the diagnostics panel.

        Invariant: An action without a recorded outcome is a failed action.
    .PARAMETER Action
        Short action identifier (e.g., "Network Test", "Disk Health Check")
    .PARAMETER Detail
        Human-readable description of what happened
    .PARAMETER Category
        Action category for filtering/grouping:
        - Diagnostics: Tests, checks, information gathering
        - Configuration: Settings changes, branding, UI customization
        - AdminChange: Privileged operations (GPO, drivers, policies)
        - Maintenance: Cleanup, optimization, disk operations
    .PARAMETER Result
        Action outcome: PASS, WARN, FAIL, or PENDING (for async operations)
    .PARAMETER Tier
        Escalation tier (0-5) per ActionTiers model:
        0=No Action, 1=Local User, 2=Alternate Context, 3=Guided Technical,
        4=Local IT/Admin, 5=External Escalation
    .PARAMETER Summary
        Operator-readable summary of the outcome (e.g., "All domains reachable")
    .PARAMETER Evidence
        Optional structured evidence hashtable for machine-readable data
    .PARAMETER ToolCategory
        Tool domain for grouping (Bluetooth, Network, Audio, System, Maintenance).
        Used by ledger for run grouping and export semantics. If not specified,
        falls back to pattern-matching on Action name.
    .PARAMETER LogAction
        If $true (default), also writes to the JSONL log via Write-Log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Detail,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Diagnostics", "Configuration", "AdminChange", "Maintenance")]
        [string]$Category = "Diagnostics",

        [Parameter(Mandatory = $false)]
        [ValidateSet("PASS", "WARN", "FAIL", "PENDING", "NOT_RUN", "CANCELLED")]
        [string]$Result = "PENDING",

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 5)]
        [int]$Tier = 0,

        [Parameter(Mandatory = $false)]
        [string]$Summary = "",

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{},

        [Parameter(Mandatory = $false)]
        [ValidateSet("Bluetooth", "Network", "Audio", "System", "Maintenance", "Other", "")]
        [string]$ToolCategory = "",

        [Parameter(Mandatory = $false)]
        [bool]$LogAction = $true
    )

    # Generate unique ActionId for deterministic completion
    $actionId = [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()

    $actionEntry = [PSCustomObject]@{
        ActionId     = $actionId
        Timestamp    = Get-Date
        Action       = $Action
        Detail       = $Detail
        Category     = $Category
        ToolCategory = $ToolCategory  # Phase 5: explicit tool domain for grouping
        Result       = $Result
        Tier         = $Tier
        Summary      = $Summary
        Evidence     = $Evidence
    }

    $script:SessionActions += $actionEntry

    # ==========================================================================
    # BRIDGE TO LEDGER: Diagnostic actions must populate ledger with Test ops
    # This ensures PPF generation sees diagnostic runs (PPF-EMPTY fix)
    # ==========================================================================
    if ($Category -eq "Diagnostics" -and $Result -ne "PENDING") {
        # Check if ledger system is available and initialized
        # Note: SessionOperationLedger exports Write-SessionOperation, which becomes
        # Write-WinConfigSessionOperation when loaded with -Prefix "WinConfig"
        $ledgerAvailable = (Get-Command Test-WinConfigLedgerInitialized -ErrorAction SilentlyContinue) -and
                           (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) -and
                           (Test-WinConfigLedgerInitialized)

        if ($ledgerAvailable) {
            try {
                # Map session action result to ledger result
                $ledgerResult = switch ($Result) {
                    "PASS"      { "Success" }
                    "WARN"      { "Warning" }
                    "FAIL"      { "Failed" }
                    "NOT_RUN"   { "Skipped" }
                    "CANCELLED" { "Skipped" }  # Cancelled = user-initiated skip
                    default     { "Success" }  # Safe default for unknown states
                }

                # Phase 5: Use explicit ToolCategory if provided, else fall back to pattern matching
                $ledgerCategory = if ($ToolCategory -and $ToolCategory -ne "") {
                    $ToolCategory
                } else {
                    # Legacy fallback: pattern-match on Action name
                    switch -Wildcard ($Action) {
                        "*Network*"      { "Network" }
                        "*DNS*"          { "Network" }
                        "*TCP*"          { "Network" }
                        "*HTTPS*"        { "Network" }
                        "*Connectivity*" { "Network" }
                        "*BT*"           { "Bluetooth" }
                        "*Bluetooth*"    { "Bluetooth" }
                        "*Audio*"        { "Audio" }
                        default          { "Other" }  # Changed from Network to Other for clarity
                    }
                }

                # Register to ledger with OperationType="Test"
                # Uses Write-WinConfigSessionOperation (the ledger's write function)
                Write-WinConfigSessionOperation `
                    -Category $ledgerCategory `
                    -OperationType "Test" `
                    -Name $Action `
                    -Source "SessionAction-Bridge" `
                    -MutatesSystem $false `
                    -Result $ledgerResult `
                    -Summary $Summary `
                    -Evidence $Evidence
            }
            catch {
                # Non-fatal: ledger bridge failure should not break session action
                # PPF will fall back to build-time computation if needed
            }
        }
    }

    if ($LogAction) {
        Write-Log -Action $Action -Message $Detail -Result $Result -Tier $Tier -Summary $Summary
    }

    # Return ActionId for use with Complete-SessionAction
    return $actionId
}

function Get-SessionActions {
    <#
    .SYNOPSIS
        Returns all registered session actions with PENDING auto-coerced to FAIL.
    .DESCRIPTION
        Returns the array of actions registered via Register-SessionAction.
        Each action includes: ActionId, Timestamp, Action, Detail, Category, Result, Tier, Summary, Evidence.

        IMPORTANT: Any action with Result=PENDING is auto-coerced to FAIL with Tier=3
        (Guided Technical Step). This enforces the invariant that PENDING is never
        a valid final state.
    .PARAMETER Raw
        If specified, returns actions without auto-coercion (for internal use only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Raw
    )

    if ($Raw) {
        return $script:SessionActions
    }

    # Auto-coerce PENDING → FAIL for display/export
    $resolvedActions = @()
    foreach ($action in $script:SessionActions) {
        $resolved = [PSCustomObject]@{
            ActionId  = $action.ActionId
            Timestamp = $action.Timestamp
            Action    = $action.Action
            Detail    = $action.Detail
            Category  = $action.Category
            Result    = $action.Result
            Tier      = $action.Tier
            Summary   = $action.Summary
            Evidence  = $action.Evidence
        }

        # Coerce PENDING to FAIL (Tier 3 = Guided Technical Step minimum)
        # Uses typed constant from DiagnosticTypes.psm1
        if ($resolved.Result -eq "PENDING") {
            $resolved.Result = $DiagnosticResult.FAIL
            $resolved.Tier = [Math]::Max($resolved.Tier, 3)
            if ([string]::IsNullOrEmpty($resolved.Summary)) {
                $resolved.Summary = "Action did not complete (auto-failed)"
            }
        }

        $resolvedActions += $resolved
    }

    return $resolvedActions
}

function Complete-SessionAction {
    <#
    .SYNOPSIS
        Updates the result of a previously registered session action by ActionId.
    .DESCRIPTION
        Finds the action matching the given ActionId and updates its Result, Tier,
        and Summary. Use this for async operations that start as PENDING and
        complete later.

        Tier constraints enforced:
        - PASS: Tier must be 0
        - WARN: Tier must be >= 1
        - FAIL: Tier must be >= 2
    .PARAMETER ActionId
        The unique ActionId returned by Register-SessionAction
    .PARAMETER Result
        The final result: PASS, WARN, FAIL, or NOT_RUN
    .PARAMETER Tier
        The escalation tier (0-5). Auto-adjusted to meet constraints.
    .PARAMETER Summary
        Operator-readable summary of the outcome
    .PARAMETER Evidence
        Optional structured evidence hashtable
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "WARN", "FAIL", "NOT_RUN")]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 5)]
        [int]$Tier = 0,

        [Parameter(Mandatory = $false)]
        [string]$Summary = "",

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{}
    )

    # Enforce tier constraints: PASS=0, WARN>=1, FAIL>=2, NOT_RUN>=1
    # NOTE: This switch is internal infrastructure for tier validation, not consumer branching
    $validatedTier = switch ($Result) {
        "PASS"    { 0 }
        "WARN"    { [Math]::Max($Tier, 1) }
        "FAIL"    { [Math]::Max($Tier, 2) }
        "NOT_RUN" { [Math]::Max($Tier, 1) }
    }

    # Find action by ActionId
    for ($i = 0; $i -lt $script:SessionActions.Count; $i++) {
        if ($script:SessionActions[$i].ActionId -eq $ActionId) {
            $actionName = $script:SessionActions[$i].Action
            $script:SessionActions[$i].Result = $Result
            $script:SessionActions[$i].Tier = $validatedTier
            $script:SessionActions[$i].Summary = $Summary
            if ($Evidence.Count -gt 0) {
                $script:SessionActions[$i].Evidence = $Evidence
            }

            # Log the completion
            Write-Log -Action "$actionName.Complete" -Message $Summary -Result $Result -Tier $validatedTier -Summary $Summary
            return $true
        }
    }

    # ActionId not found - log warning but don't fail
    return $false
}

# =============================================================================
# AUDIT TRAIL INTEGRITY FUNCTIONS
# =============================================================================

function Test-LoggingHealthy {
    <#
    .SYNOPSIS
        Returns $true if logging is functioning correctly.
    .DESCRIPTION
        Check this before critical operations to ensure audit trail is intact.
        If $false, warn the user that actions may not have been recorded.
    .OUTPUTS
        Boolean: $true if logging is healthy, $false if failures have occurred
    #>
    [CmdletBinding()]
    param()

    return -not $script:LoggingBroken
}

function Get-LastLogError {
    <#
    .SYNOPSIS
        Returns the last logging error message, if any.
    .DESCRIPTION
        Returns $null if no logging errors have occurred.
        Use with Test-LoggingHealthy to surface audit trail issues to operators.
    .OUTPUTS
        String: Error message or $null
    #>
    [CmdletBinding()]
    param()

    return $script:LastLogError
}

function Get-LogWriteFailureCount {
    <#
    .SYNOPSIS
        Returns the count of failed log writes in this session.
    .DESCRIPTION
        Use this to determine severity of audit trail issues.
        A high count indicates persistent disk/permission problems.
    .OUTPUTS
        Integer: Number of failed log write attempts
    #>
    [CmdletBinding()]
    param()

    return $script:LogWriteFailureCount
}

# =============================================================================
# COMBINED AUDIT TRAIL ENFORCEMENT
# =============================================================================

function Test-AuditTrailHealthy {
    <#
    .SYNOPSIS
        Returns $true if BOTH logging AND ledger are functioning correctly.
    .DESCRIPTION
        Combined health check for the entire audit trail system.
        Checks Logger health AND SessionOperationLedger health.
        Use this before critical operations to ensure full audit trail integrity.

        IMPORTANT: This is a FAIL-SAFE check. If we cannot determine health
        (e.g., module not loaded), we return $false to block mutations.
    .OUTPUTS
        Hashtable with: Healthy (bool), LoggerOk (bool), LedgerOk (bool), Reason (string)
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Healthy   = $true
        LoggerOk  = $true
        LedgerOk  = $true
        Reason    = $null
    }

    # Check Logger health
    if ($script:LoggingBroken) {
        $result.Healthy = $false
        $result.LoggerOk = $false
        $result.Reason = "Logger failure: $($script:LastLogError)"
    }

    # Check Ledger health (if available)
    # FAIL-SAFE: If we can't check ledger, assume it's broken
    try {
        if (Get-Command Get-LedgerWriteFailureCount -ErrorAction SilentlyContinue) {
            $ledgerFailures = Get-LedgerWriteFailureCount
            if ($ledgerFailures -gt 0) {
                $result.Healthy = $false
                $result.LedgerOk = $false
                $ledgerError = if (Get-Command Get-LedgerLastWriteError -ErrorAction SilentlyContinue) {
                    Get-LedgerLastWriteError
                } else { "Unknown ledger error" }
                if ($result.Reason) {
                    $result.Reason += "; Ledger failure: $ledgerError"
                } else {
                    $result.Reason = "Ledger failure: $ledgerError"
                }
            }
        }
    }
    catch {
        # FAIL-SAFE: Can't check ledger = treat as broken
        $result.Healthy = $false
        $result.LedgerOk = $false
        if ($result.Reason) {
            $result.Reason += "; Ledger check failed: $($_.Exception.Message)"
        } else {
            $result.Reason = "Ledger check failed: $($_.Exception.Message)"
        }
    }

    return $result
}

function Assert-AuditTrailHealthyForMutation {
    <#
    .SYNOPSIS
        BLOCKS system mutations if audit trail is broken. Shows MessageBox and returns $false.
    .DESCRIPTION
        Use this guard before ANY system-mutating operation (driver removal, reboot, etc.).
        If audit trail is broken, shows a warning dialog explaining why the operation
        is blocked and returns $false so the caller can exit early.

        CRITICAL: This enforces the invariant that NO system mutations occur
        without a functioning audit trail. This is a safety requirement, not a
        usability feature.

        Usage:
            if (-not (Assert-AuditTrailHealthyForMutation)) { return }
    .OUTPUTS
        Boolean: $true if audit trail is healthy and mutation can proceed, $false if blocked
    #>
    [CmdletBinding()]
    param()

    $healthCheck = Test-AuditTrailHealthy

    if (-not $healthCheck.Healthy) {
        [System.Windows.Forms.MessageBox]::Show(
            "OPERATION BLOCKED: Audit trail is not functioning.`n`n" +
            "Reason: $($healthCheck.Reason)`n`n" +
            "System-modifying operations are disabled when session recording is broken. " +
            "This ensures all actions are properly logged for accountability.`n`n" +
            "Please restart the application. If the problem persists, contact support.",
            "Audit Trail Failure - Operation Blocked",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Stop
        ) | Out-Null
        return $false
    }

    return $true
}

# Export public functions
Export-ModuleMember -Function Initialize-Logger, Write-Log, Get-CurrentSessionId, Get-LogPath, Register-SessionAction, Get-SessionActions, Complete-SessionAction, Test-LoggingHealthy, Get-LastLogError, Get-LogWriteFailureCount, Test-AuditTrailHealthy, Assert-AuditTrailHealthyForMutation

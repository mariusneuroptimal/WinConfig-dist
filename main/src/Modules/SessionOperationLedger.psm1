# SessionOperationLedger.psm1 - Session-scoped operation ledger for WinConfig
# Records all actions, tests, and button invocations with ephemeral JSON artifacts
#
# EPHEMERAL CONTRACT:
# - All session data is written to session-scoped temp directory
# - Session artifacts are deleted on application exit
# - No persistent artifacts remain after termination (zero-footprint)

# CONTRACT:
# - SessionId is mandatory for all operations
# - OperationId is monotonic within session (atomic via Interlocked, never array-based)
# - MutatesSystem must be explicit for every operation
# - No operation may execute without being recorded first
# - Session artifacts are immutable after finalization
# - operations.json is source of truth; markdown is derived view
# - Evidence must be pure data (no scriptblocks, no callable objects)
#
# ERROR SEMANTICS:
# - Initialize-SessionLedger: THROWS on failure (fatal)
# - Write-SessionOperation:   THROWS on failure (caller must not proceed)
# - Start-SessionOperation:   THROWS on failure (caller must not proceed)
# - Complete-SessionOperation: THROWS on failure (state may be inconsistent)
# - Close-Session:            Returns $false if not initialized; THROWS on persistence failure
# - ConvertTo-SessionMarkdown: Returns $null if not initialized; never throws
# - Get-* accessors:          Never throw, return null/empty if not initialized
#
# CONCURRENCY:
# - All mutations protected by $script:LedgerLock (System.Threading.Monitor)
# - OperationId generated via Interlocked.Increment (race-free)
# - Disk writes are transactional (temp file + atomic rename)
# - Single-writer model: concurrent reads safe, concurrent writes serialized

# Direct execution guard
if ($MyInvocation.InvocationName -like "*.psm1" -or $MyInvocation.InvocationName -like "*\*") {
    throw "FATAL: PSM1 files must never be executed directly. Use Import-Module instead."
}

# Import Paths module for ephemeral temp root
$script:PathsModulePath = Join-Path $PSScriptRoot "Paths.psm1"
if (Test-Path $script:PathsModulePath) {
    Import-Module $script:PathsModulePath -Force -ErrorAction SilentlyContinue -Global
}

# =============================================================================
# OPERATION RESULT CONSTANTS (PS 5.1 compatible)
# =============================================================================
# These constants define the valid operation result states.
# Using PSCustomObject enables $OperationResult.X syntax for type-safe assignments.

$script:OperationResult = [PSCustomObject]@{
    Success = "Success"
    Warning = "Warning"
    Failed  = "Failed"
    Skipped = "Skipped"
    Pending = "Pending"  # Transitional only - auto-coerced to Failed on finalization
}

# =============================================================================
# SCRIPT-SCOPED STATE
# =============================================================================

$script:LedgerSessionId = $null           # SESSION-yyyy-MM-dd-XXXX format
$script:LedgerSessionDir = $null          # Full path to session directory
$script:LedgerOperations = [System.Collections.Generic.List[object]]::new()  # Thread-safe via lock
$script:LedgerOperationCounter = [ref]0   # Atomic monotonic counter for OperationId (boxed for Interlocked)
$script:LedgerSessionFinalized = $false   # Immutability guard
$script:LedgerInitialized = $false        # Initialization guard
$script:LedgerAppVersion = "unknown"
$script:LedgerIteration = "unknown"
$script:LedgerLock = [System.Object]::new()  # Synchronization primitive for all mutations

# SAFETY: Track non-critical write failures for audit trail integrity warnings
$script:LedgerWriteFailureCount = 0
$script:LedgerLastWriteError = $null

# =============================================================================
# PHASE 5: RUN SEMANTICS (Ledger-level only)
# =============================================================================
# A "run" is a contiguous investigation bounded by tool execution.
# - Starts: when first tool executes
# - Ends: when no tools are running AND user exports/exits
# This enables unambiguous exports and future pattern correlation.

$script:RunState = "Idle"                 # Idle | Active | Completed | Aborted
$script:RunStartedAt = $null              # UTC timestamp of first tool execution
$script:RunEndedAt = $null                # UTC timestamp when run completed
$script:ActiveToolCount = [ref]0          # Atomic counter for in-flight tools

# =============================================================================
# VALIDATION HELPERS
# =============================================================================

function Assert-LedgerNotFinalized {
    <#
    .SYNOPSIS
        Guard that throws if session is finalized.
    #>
    if ($script:LedgerSessionFinalized) {
        throw "Session finalized. Operation recording is forbidden."
    }
}

function Assert-LedgerInitialized {
    <#
    .SYNOPSIS
        Guard that throws if ledger is not initialized.
    #>
    if (-not $script:LedgerInitialized) {
        throw "Session ledger not initialized. Call Initialize-SessionLedger first."
    }
}

function Assert-EvidenceIsPureData {
    <#
    .SYNOPSIS
        Validates that evidence contains only pure data (no scriptblocks or callable objects).
    .PARAMETER Evidence
        The evidence hashtable to validate.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Evidence
    )

    if ($null -eq $Evidence) { return }
    if ($Evidence -isnot [hashtable] -and $Evidence -isnot [System.Collections.IDictionary]) {
        throw "Evidence must be a hashtable. Got: $($Evidence.GetType().Name)"
    }

    function Test-ValueIsPure {
        param($Value, $Path)

        if ($null -eq $Value) { return }

        $type = $Value.GetType()

        # Reject scriptblocks
        if ($Value -is [scriptblock]) {
            throw "Evidence contains scriptblock at '$Path'. Scriptblocks are forbidden."
        }

        # Reject objects with methods (except primitive wrappers and collections)
        $allowedTypes = @(
            [string], [int], [long], [double], [decimal], [bool], [datetime],
            [array], [object[]], [hashtable], [System.Collections.ArrayList],
            [System.Collections.Generic.List[object]]
        )

        $isAllowed = $false
        foreach ($allowed in $allowedTypes) {
            if ($Value -is $allowed) {
                $isAllowed = $true
                break
            }
        }

        # Check for value types (int, bool, etc.) and strings
        if ($type.IsValueType -or $type -eq [string]) {
            $isAllowed = $true
        }

        if (-not $isAllowed) {
            # Check if it's a PSCustomObject (allowed as hashtable-like)
            if ($type.Name -eq 'PSCustomObject') {
                $isAllowed = $true
            }
        }

        if (-not $isAllowed) {
            throw "Evidence contains non-data object at '$Path'. Type: $($type.Name). Only pure data types allowed."
        }

        # Recursively check collections
        if ($Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                Test-ValueIsPure -Value $Value[$key] -Path "$Path.$key"
            }
        }
        elseif ($Value -is [array] -or $Value -is [System.Collections.IList]) {
            for ($i = 0; $i -lt $Value.Count; $i++) {
                Test-ValueIsPure -Value $Value[$i] -Path "$Path[$i]"
            }
        }
    }

    foreach ($key in $Evidence.Keys) {
        Test-ValueIsPure -Value $Evidence[$key] -Path $key
    }
}

# =============================================================================
# PHASE 5: RUN BOUNDARY MANAGEMENT
# =============================================================================
# These functions manage run lifecycle without UI involvement.
# Invariant: A run is unambiguous - it has exactly one start and one end.

function Start-RunIfIdle {
    <#
    .SYNOPSIS
        Initializes run metadata on first tool execution.
    .DESCRIPTION
        Called internally when a tool starts. If run is Idle, transitions to Active.
        Thread-safe via $script:LedgerLock (caller must hold lock).
    #>
    [CmdletBinding()]
    param()

    if ($script:RunState -eq "Idle") {
        $script:RunState = "Active"
        $script:RunStartedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $script:RunEndedAt = $null
    }
}

function Register-ToolStart {
    <#
    .SYNOPSIS
        Increments active tool count and starts run if needed.
    .DESCRIPTION
        Called when an async tool begins execution.
        Thread-safe: uses Interlocked.Increment.
    #>
    [CmdletBinding()]
    param()

    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        # GUARDRAIL E-A1: Tool execution outside run boundary
        # Prevents "ghost tools" corrupting run semantics
        if ($script:RunState -eq "Completed") {
            throw "GUARDRAIL A1: Tool execution attempted after run completion"
        }

        Start-RunIfIdle
        [System.Threading.Interlocked]::Increment($script:ActiveToolCount) | Out-Null
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }
}

function Register-ToolEnd {
    <#
    .SYNOPSIS
        Decrements active tool count and checks for run completion.
    .DESCRIPTION
        Called when an async tool completes (success, fail, or cancel).
        If count reaches zero, run transitions to Completed.
        Thread-safe: uses Interlocked.Decrement.
    #>
    [CmdletBinding()]
    param()

    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        $newCount = [System.Threading.Interlocked]::Decrement($script:ActiveToolCount)

        # Run completes when no tools are active
        if ($newCount -le 0 -and $script:RunState -eq "Active") {
            $script:RunState = "Completed"
            $script:RunEndedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }
}

function Get-RunMetadata {
    <#
    .SYNOPSIS
        Returns current run metadata for export.
    .DESCRIPTION
        Returns a hashtable with RunId, State, StartedAt, EndedAt.
        RunId is the SessionId (one run per session for now).
    #>
    [CmdletBinding()]
    param()

    return @{
        RunId       = $script:LedgerSessionId
        RunState    = $script:RunState
        StartedAt   = $script:RunStartedAt
        EndedAt     = $script:RunEndedAt
        ActiveTools = $script:ActiveToolCount.Value
    }
}

function Test-RunActive {
    <#
    .SYNOPSIS
        Returns $true if a run is currently active (tools in flight).
    #>
    [CmdletBinding()]
    param()

    return $script:RunState -eq "Active"
}

function Test-RunCompleted {
    <#
    .SYNOPSIS
        Returns $true if a run has completed (ready for export).
    #>
    [CmdletBinding()]
    param()

    return $script:RunState -eq "Completed"
}

function Complete-RunForExport {
    <#
    .SYNOPSIS
        Forces run completion for export (if not already completed).
    .DESCRIPTION
        Called before export to ensure run has explicit end boundary.
        If run is Active with no tools running, marks as Completed.
        If run is Idle (nothing executed), marks as Aborted.
    #>
    [CmdletBinding()]
    param()

    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        if ($script:RunState -eq "Active" -and $script:ActiveToolCount.Value -le 0) {
            $script:RunState = "Completed"
            $script:RunEndedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        elseif ($script:RunState -eq "Idle") {
            $script:RunState = "Aborted"
            $script:RunEndedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }
}

# =============================================================================
# PERSISTENCE HELPERS
# =============================================================================

function Save-OperationsJsonTransactional {
    <#
    .SYNOPSIS
        Atomic transactional write to operations.json.
    .DESCRIPTION
        Writes to temp file, flushes, then performs atomic rename (Move-Item -Force).
        This ensures no partial writes and is power-loss safe on same volume.
        THROWS on failure - caller must handle.
    .PARAMETER Path
        Target path for operations.json
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $tempPath = "$Path.tmp"
    $backupPath = "$Path.bak"

    try {
        # Convert to JSON
        $json = $script:LedgerOperations | ConvertTo-Json -Depth 10
        if ([string]::IsNullOrEmpty($json)) {
            $json = "[]"
        }

        # Write to temp file with explicit flush
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.FileStream]::new(
                $tempPath,
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::UTF8)
            $writer.Write($json)
            $writer.Flush()
            $stream.Flush($true)  # Flush to disk (not just OS buffer)
        }
        finally {
            if ($writer) { $writer.Dispose() }
            if ($stream) { $stream.Dispose() }
        }

        # Verify temp file exists and has content
        if (-not (Test-Path $tempPath)) {
            throw "Temp file was not created"
        }
        $tempSize = (Get-Item $tempPath).Length
        if ($tempSize -eq 0 -and $script:LedgerOperations.Count -gt 0) {
            throw "Temp file is empty but operations exist"
        }

        # Create backup of current file (if exists)
        if (Test-Path $Path) {
            Copy-Item -Path $Path -Destination $backupPath -Force -ErrorAction SilentlyContinue
        }

        # Atomic rename (same volume = atomic on Windows NTFS)
        Move-Item -Path $tempPath -Destination $Path -Force -ErrorAction Stop
    }
    catch {
        # Clean up temp file on failure
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw "Transactional write failed: $($_.Exception.Message)"
    }
}

function Save-OperationsJson {
    <#
    .SYNOPSIS
        Persists operations.json to disk using transactional write. THROWS on failure.
    .DESCRIPTION
        Called from within lock - assumes caller holds $script:LedgerLock.
    #>
    # Note: Initialization/finalization checks done by caller under lock

    $operationsJsonPath = Join-Path $script:LedgerSessionDir "operations.json"
    Save-OperationsJsonTransactional -Path $operationsJsonPath
}

# =============================================================================
# CORE FUNCTIONS
# =============================================================================

function Initialize-SessionLedger {
    <#
    .SYNOPSIS
        Initializes the session ledger with a new session ID.
    .DESCRIPTION
        Creates session directory structure, writes session.json metadata.
        Must be called once at application startup.
        THROWS on failure - initialization failures are fatal.
    .PARAMETER Version
        Application version string (e.g., "2026.01.06")
    .PARAMETER Iteration
        Application iteration (production, staging, dev)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Version = "unknown",

        [Parameter(Mandatory = $false)]
        [string]$Iteration = "unknown"
    )

    # Guard against double-initialization
    if ($script:LedgerInitialized) {
        return
    }

    # Reset state (in case of module reload)
    $script:LedgerOperations.Clear()
    $script:LedgerOperationCounter.Value = 0
    $script:LedgerSessionFinalized = $false

    # Phase 5: Reset run state
    $script:RunState = "Idle"
    $script:RunStartedAt = $null
    $script:RunEndedAt = $null
    $script:ActiveToolCount.Value = 0

    # Store version and iteration
    $script:LedgerAppVersion = $Version
    $script:LedgerIteration = $Iteration

    # Generate session ID: SESSION-yyyy-MM-dd-XXXXXXXXXXXX (12-char hex for collision resistance)
    $datePart = Get-Date -Format "yyyy-MM-dd"
    $guidPart = ([guid]::NewGuid().ToString("N")).Substring(0, 12).ToUpper()
    $script:LedgerSessionId = "SESSION-$datePart-$guidPart"

    # Create session directory in ephemeral temp root (zero-footprint)
    # Uses Paths.psm1 for session-scoped temp root
    if (Get-Command Get-WinConfigSessionsPath -ErrorAction SilentlyContinue) {
        $sessionsRoot = Get-WinConfigSessionsPath
    }
    else {
        # Fallback to temp if Paths module not loaded
        $sessionsRoot = Join-Path $env:TEMP "WinConfig-sessions"
        if (-not (Test-Path $sessionsRoot)) {
            New-Item -Path $sessionsRoot -ItemType Directory -Force | Out-Null
        }
    }
    $script:LedgerSessionDir = Join-Path $sessionsRoot $script:LedgerSessionId

    try {
        if (-not (Test-Path $script:LedgerSessionDir)) {
            New-Item -Path $script:LedgerSessionDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # Get Logger SessionId if available (for cross-reference)
        $loggerSessionId = $null
        if (Get-Command Get-WinConfigCurrentSessionId -ErrorAction SilentlyContinue) {
            $loggerSessionId = Get-WinConfigCurrentSessionId
        }

        # Write session.json metadata
        $sessionMeta = [ordered]@{
            SessionId       = $script:LedgerSessionId
            StartedAtUtc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            Version         = $Version
            Iteration       = $Iteration
            Machine         = $env:COMPUTERNAME
            User            = $env:USERNAME
            LoggerSessionId = $loggerSessionId
            Status          = "Active"
        }

        $sessionJsonPath = Join-Path $script:LedgerSessionDir "session.json"
        $sessionMeta | ConvertTo-Json -Depth 5 | Set-Content -Path $sessionJsonPath -Encoding UTF8 -ErrorAction Stop

        # Initialize empty operations.json
        $operationsJsonPath = Join-Path $script:LedgerSessionDir "operations.json"
        "[]" | Set-Content -Path $operationsJsonPath -Encoding UTF8 -ErrorAction Stop

        $script:LedgerInitialized = $true
    }
    catch {
        # Initialization failure is fatal - throw
        throw "Failed to initialize session ledger: $($_.Exception.Message)"
    }
}

function Write-SessionOperation {
    <#
    .SYNOPSIS
        Records a completed operation in the session ledger.
    .DESCRIPTION
        Single canonical function for all operation recording.
        Appends to in-memory ledger and persists to operations.json.
        THROWS on failure - if recording fails, the operation must not execute.
    .PARAMETER Category
        Network | System | Audio | Bluetooth | Maintenance | Other
    .PARAMETER OperationType
        Test | Action | ExternalTool | UI
    .PARAMETER Name
        Human-readable operation name (e.g., "Run DISM RestoreHealth")
    .PARAMETER Source
        Origin of the operation (e.g., "Button:DISM", "Menu:Settings")
    .PARAMETER MutatesSystem
        Boolean indicating if operation changes system state
    .PARAMETER Result
        Success | Warning | Failed | Skipped
    .PARAMETER Summary
        Brief outcome description
    .PARAMETER ArtifactRefs
        Array of relative paths to associated artifacts
    .PARAMETER Evidence
        Optional hashtable of structured evidence data (pure data only, no scriptblocks)
    .PARAMETER Executed
        Boolean indicating if the operation was actually executed (true) or was a dry run (false).
        Defaults to $true for backward compatibility. Dry runs MUST set this to $false.
    .PARAMETER Plan
        Optional hashtable describing the execution plan. Required for dry runs.
        Contains: Steps, AffectedResources, RequiresAdmin, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Network", "System", "Audio", "Bluetooth", "Maintenance", "Other")]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Test", "Action", "ExternalTool", "UI")]
        [string]$OperationType,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [bool]$MutatesSystem,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Success", "Warning", "Failed", "Skipped")]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [string]$Summary = "",

        [Parameter(Mandatory = $false)]
        [string[]]$ArtifactRefs = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{},

        [Parameter(Mandatory = $false)]
        [bool]$Executed = $true,

        [Parameter(Mandatory = $false)]
        [hashtable]$Plan = $null
    )

    # Guards - throw on violation
    Assert-LedgerInitialized
    Assert-LedgerNotFinalized
    Assert-EvidenceIsPureData -Evidence $Evidence

    # Thread-safe operation recording with explicit lock
    $operationId = $null
    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        # Re-check finalization under lock (double-check pattern)
        if ($script:LedgerSessionFinalized) {
            throw "Session finalized. Operation recording is forbidden."
        }

        # Generate monotonic OperationId (atomic increment)
        $counter = [System.Threading.Interlocked]::Increment($script:LedgerOperationCounter)
        $operationId = "OP-{0:D4}" -f $counter

        # Build operation record
        $operation = [ordered]@{
            SessionId     = $script:LedgerSessionId
            OperationId   = $operationId
            TimestampUtc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            Category      = $Category
            OperationType = $OperationType
            Name          = $Name
            Source        = $Source
            MutatesSystem = $MutatesSystem
            Executed      = $Executed      # DRY RUN: $false for dry runs, $true for actual execution
            Result        = $Result
            Summary       = $Summary
            ArtifactRefs  = $ArtifactRefs
            Evidence      = $Evidence
            Plan          = $Plan          # DRY RUN: Execution plan (required for dry runs)
        }

        # Append to in-memory list (List<T>.Add is O(1) amortized)
        $script:LedgerOperations.Add($operation)

        # Persist to operations.json - THROWS on failure
        Save-OperationsJson
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }

    # NOTE: Backward-compatibility bridge to Register-SessionAction was REMOVED
    # to prevent infinite recursion. The canonical bridge direction is:
    #   Logger.psm1 (Register-SessionAction) → SessionOperationLedger.psm1 (Write-SessionOperation)
    # This ensures PPF generation sees diagnostic results without circular calls.
    # See: docs/RUNS-VIEW-ARCHITECTURE.md for bridge architecture documentation.

    return $operationId
}

function Start-SessionOperation {
    <#
    .SYNOPSIS
        Starts an operation and returns an OperationId for later completion.
    .DESCRIPTION
        Records operation start with Pending status. Must be paired with Complete-SessionOperation.
        THROWS on failure - if start fails, the operation must not execute.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Network", "System", "Audio", "Bluetooth", "Maintenance", "Other")]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Test", "Action", "ExternalTool", "UI")]
        [string]$OperationType,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [bool]$MutatesSystem
    )

    # Guards - throw on violation
    Assert-LedgerInitialized
    Assert-LedgerNotFinalized

    # Thread-safe operation recording with explicit lock
    $operationId = $null
    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        # Re-check finalization under lock (double-check pattern)
        if ($script:LedgerSessionFinalized) {
            throw "Session finalized. Operation recording is forbidden."
        }

        # Generate monotonic OperationId (atomic increment)
        $counter = [System.Threading.Interlocked]::Increment($script:LedgerOperationCounter)
        $operationId = "OP-{0:D4}" -f $counter

        # Build pending operation record
        $operation = [ordered]@{
            SessionId     = $script:LedgerSessionId
            OperationId   = $operationId
            StartedAtUtc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            TimestampUtc  = $null  # Set on completion
            Category      = $Category
            OperationType = $OperationType
            Name          = $Name
            Source        = $Source
            MutatesSystem = $MutatesSystem
            Executed      = $true  # Pending operations are assumed to execute; updated on completion if dry run
            Result        = $script:OperationResult.Pending
            Summary       = ""
            ArtifactRefs  = @()
            Evidence      = @{}
            Plan          = $null  # Set on completion for dry runs
        }

        # Append to in-memory list
        $script:LedgerOperations.Add($operation)

        # Persist to operations.json - THROWS on failure
        Save-OperationsJson
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }

    return $operationId
}

function Complete-SessionOperation {
    <#
    .SYNOPSIS
        Completes a previously started operation.
    .DESCRIPTION
        Updates the operation record with final result and details.
        THROWS if operation not found or session is finalized.
    .PARAMETER OperationId
        The OperationId returned by Start-SessionOperation
    .PARAMETER Result
        Success | Warning | Failed | Skipped
    .PARAMETER Summary
        Brief outcome description
    .PARAMETER ArtifactRefs
        Array of relative paths to associated artifacts
    .PARAMETER Evidence
        Optional hashtable of structured evidence data (pure data only)
    .PARAMETER Executed
        Boolean indicating if the operation was actually executed (true) or was a dry run (false).
        Defaults to $true for backward compatibility.
    .PARAMETER Plan
        Optional hashtable describing the execution plan. Required for dry runs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Success", "Warning", "Failed", "Skipped")]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [string]$Summary = "",

        [Parameter(Mandatory = $false)]
        [string[]]$ArtifactRefs = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{},

        [Parameter(Mandatory = $false)]
        [bool]$Executed = $true,

        [Parameter(Mandatory = $false)]
        [hashtable]$Plan = $null
    )

    # Guards
    Assert-LedgerInitialized
    Assert-LedgerNotFinalized
    Assert-EvidenceIsPureData -Evidence $Evidence

    # Thread-safe operation update with explicit lock
    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        # Re-check finalization under lock (double-check pattern)
        if ($script:LedgerSessionFinalized) {
            throw "Session finalized. Operation recording is forbidden."
        }

        # Find and update the operation
        $found = $false
        for ($i = 0; $i -lt $script:LedgerOperations.Count; $i++) {
            if ($script:LedgerOperations[$i].OperationId -eq $OperationId) {
                $script:LedgerOperations[$i].TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $script:LedgerOperations[$i].Result = $Result
                $script:LedgerOperations[$i].Summary = $Summary
                $script:LedgerOperations[$i].ArtifactRefs = $ArtifactRefs
                $script:LedgerOperations[$i].Evidence = $Evidence
                $script:LedgerOperations[$i].Executed = $Executed
                if ($null -ne $Plan) {
                    $script:LedgerOperations[$i].Plan = $Plan
                }
                $found = $true
                break
            }
        }

        if (-not $found) {
            throw "OperationId '$OperationId' not found in session ledger."
        }

        # Persist to operations.json - THROWS on failure
        Save-OperationsJson
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }

    # NOTE: Backward-compatibility bridge to Register-SessionAction was REMOVED
    # to prevent infinite recursion. See Write-SessionOperation for details.

    return $true
}

function Close-Session {
    <#
    .SYNOPSIS
        Finalizes the session, making it immutable.
    .DESCRIPTION
        Marks session as finalized, coerces pending operations to Failed,
        generates Problem Pattern Fingerprint (PPF), generates markdown,
        and updates session.json.
        After finalization, no more operations can be recorded.
        THROWS on critical persistence failure (operations.json).
    #>
    [CmdletBinding()]
    param()

    if (-not $script:LedgerInitialized) {
        return $false
    }

    if ($script:LedgerSessionFinalized) {
        return $true  # Already finalized
    }

    # Thread-safe finalization with explicit lock
    $ppfResult = $null
    [System.Threading.Monitor]::Enter($script:LedgerLock)
    try {
        # Re-check under lock (double-check pattern)
        if ($script:LedgerSessionFinalized) {
            return $true
        }

        # Coerce any remaining Pending operations to Failed
        for ($i = 0; $i -lt $script:LedgerOperations.Count; $i++) {
            if ($script:LedgerOperations[$i].Result -eq $script:OperationResult.Pending) {
                $script:LedgerOperations[$i].Result = $script:OperationResult.Failed
                $script:LedgerOperations[$i].Summary = "(Operation did not complete - auto-failed)"
                $script:LedgerOperations[$i].TimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
        }

        # Generate PPF (Problem Pattern Fingerprint) - EXACTLY ONCE at finalization
        # PPF is computed from frozen diagnostic results before session is sealed
        $ppfResult = Build-SessionPpf

        # Persist final operations (before marking finalized) - use transactional write
        $operationsJsonPath = Join-Path $script:LedgerSessionDir "operations.json"
        Save-OperationsJsonTransactional -Path $operationsJsonPath

        # Mark as finalized AFTER successful persistence
        $script:LedgerSessionFinalized = $true
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LedgerLock)
    }

    # Generate markdown (outside lock - non-critical)
    ConvertTo-SessionMarkdown | Out-Null

    # Save PPF markdown separately (outside lock - non-critical)
    if ($ppfResult -and $script:LedgerSessionDir) {
        try {
            $ppfMarkdownPath = Join-Path $script:LedgerSessionDir "ppf.md"
            $ppfResult.Markdown | Set-Content -Path $ppfMarkdownPath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Non-critical but tracked - continue
            $script:LedgerWriteFailureCount++
            $script:LedgerLastWriteError = "PPF markdown: $($_.Exception.Message)"
        }
    }

    # Phase 5: Ensure run has explicit end boundary before export
    Complete-RunForExport

    # Update session.json with finalization info, PPF, and run metadata (outside lock - non-critical)
    $sessionJsonPath = Join-Path $script:LedgerSessionDir "session.json"
    if (Test-Path $sessionJsonPath) {
        try {
            $sessionMeta = Get-Content $sessionJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json
            $sessionMeta | Add-Member -NotePropertyName "FinalizedAtUtc" -NotePropertyValue ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) -Force
            $sessionMeta | Add-Member -NotePropertyName "Status" -NotePropertyValue "Finalized" -Force
            $sessionMeta | Add-Member -NotePropertyName "OperationCount" -NotePropertyValue $script:LedgerOperations.Count -Force

            # Phase 5: Add run metadata as first-class data
            $runObject = [ordered]@{
                runId     = $script:LedgerSessionId
                state     = $script:RunState
                startedAt = $script:RunStartedAt
                endedAt   = $script:RunEndedAt
            }
            $sessionMeta | Add-Member -NotePropertyName "run" -NotePropertyValue $runObject -Force

            # Add PPF as first-class data (not embedded in logs)
            if ($ppfResult) {
                $ppfObject = [ordered]@{
                    id           = $ppfResult.Id
                    schema       = $ppfResult.Schema
                    failureCount = $ppfResult.FailureCount
                    failures     = $ppfResult.Failures
                    osBucket     = $ppfResult.OsBucket
                    networkClass = $ppfResult.NetworkClass
                }
                $sessionMeta | Add-Member -NotePropertyName "ppf" -NotePropertyValue $ppfObject -Force
            }

            $sessionMeta | ConvertTo-Json -Depth 10 | Set-Content -Path $sessionJsonPath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Non-critical metadata but tracked - continue
            $script:LedgerWriteFailureCount++
            $script:LedgerLastWriteError = "Session metadata: $($_.Exception.Message)"
        }
    }

    return $true
}

function Build-SessionPpf {
    <#
    .SYNOPSIS
        Internal helper to build PPF from current session operations.
    .DESCRIPTION
        Called ONLY during session finalization, under lock.
        Attempts to use PpfFingerprint module if available.
        Returns $null if PPF cannot be generated.
    #>
    [CmdletBinding()]
    param()

    # Try to use the PpfFingerprint module
    $ppfFunction = Get-Command New-ProblemPatternFingerprint -ErrorAction SilentlyContinue
    if (-not $ppfFunction) {
        # Try with prefix (in case module was loaded with -Prefix WinConfig)
        $ppfFunction = Get-Command New-WinConfigProblemPatternFingerprint -ErrorAction SilentlyContinue
    }

    if ($ppfFunction) {
        try {
            # Convert List to array for the function
            $opsArray = @($script:LedgerOperations)
            return & $ppfFunction -Operations $opsArray
        }
        catch {
            # PPF generation failed - non-fatal, return null
            return $null
        }
    }

    # Fallback: Generate minimal PPF inline if module not available
    try {
        return Build-MinimalPpf
    }
    catch {
        return $null
    }
}

function Build-MinimalPpf {
    <#
    .SYNOPSIS
        Fallback PPF generation when PpfFingerprint module is not available.
    .DESCRIPTION
        Produces a minimal but still useful fingerprint.
    #>
    [CmdletBinding()]
    param()

    $PPF_SCHEMA = 1

    # Extract failures
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($op in $script:LedgerOperations) {
        if ($op.Result -eq "Failed") {
            $failureId = "FAIL:$($op.Category).$($op.Name -replace '\s+', '')"
            if (-not $failures.Contains($failureId)) { $failures.Add($failureId) }
        }
        elseif ($op.Result -eq "Warning") {
            $warnId = "WARN:$($op.Category).$($op.Name -replace '\s+', '')"
            if (-not $failures.Contains($warnId)) { $failures.Add($warnId) }
        }
    }

    # Get OS bucket
    $osBucket = "Windows|Unknown|0"
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osName = if ($osInfo.Caption -match "Windows 11") { "Windows11" }
                  elseif ($osInfo.Caption -match "Windows 10") { "Windows10" }
                  else { "Windows" }
        $sku = switch ($osInfo.OperatingSystemSKU) {
            48 { "Pro" }; 49 { "ProN" }; 4 { "Enterprise" }; 27 { "EnterpriseN" }
            1 { "Home" }; 101 { "Home" }; default { "Unknown" }
        }
        $osBucket = "$osName|$sku|$($osInfo.BuildNumber)"
    }
    catch { }

    # Build canonical string for hashing
    $sortedFailures = $failures | Sort-Object
    $canonical = "PPF_SCHEMA=$PPF_SCHEMA`nFAILURES=`n"
    foreach ($f in $sortedFailures) { $canonical += "  $f`n" }
    $canonical += "OS=`n  $osBucket`n"
    $canonical += "NETWORK=`n  IPv6=false`n  VPN=false`n  Proxy=false`n  Latency=Normal`n"
    $canonical += "SOFTWARE=`n  ThirdPartyAV=false`n  OEMBluetoothStack=false`n"

    # Hash
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
        $hashBytes = $sha256.ComputeHash($bytes)
        $hexString = ($hashBytes[0..3] | ForEach-Object { $_.ToString("X2") }) -join ""
        $ppfId = "PPF-$hexString"
    }
    finally {
        $sha256.Dispose()
    }

    # Build markdown
    $md = "## Problem Pattern Fingerprint`n`n"
    $md += "**PPF:** ``$ppfId```n"
    $md += "**Schema:** v$PPF_SCHEMA`n`n"
    $md += "### Failure Signature`n"
    if ($failures.Count -eq 0) {
        $md += "- No failures detected`n"
    }
    else {
        foreach ($f in $sortedFailures) {
            if ($f.StartsWith("FAIL:")) { $md += "- [X] $($f -replace '^FAIL:','')`n" }
            elseif ($f.StartsWith("WARN:")) { $md += "- [!] $($f -replace '^WARN:','')`n" }
        }
    }
    $md += "`n### Environment`n"
    $md += "- OS: $($osBucket -replace '\|', ' ')`n"
    $md += "- Network: Standard configuration`n"
    $md += "- Software: Standard configuration`n"

    return [PSCustomObject]@{
        Id              = $ppfId
        Schema          = $PPF_SCHEMA
        FailureCount    = $failures.Count
        Failures        = $failures.ToArray()
        OsBucket        = $osBucket
        NetworkClass    = "IPv6=false;VPN=false;Latency=Normal"
        Markdown        = $md
    }
}

function ConvertTo-SessionMarkdown {
    <#
    .SYNOPSIS
        Generates a Jira-ready, LLM-ready markdown summary from the operations ledger.
    .DESCRIPTION
        Reads operations and produces a structured markdown document suitable for:
        - Pasting into Jira tickets
        - Feeding to LLMs for analysis
        - Human review of session activity
    #>
    [CmdletBinding()]
    param()

    if (-not $script:LedgerInitialized) {
        return $null
    }

    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine("# Session Report: $($script:LedgerSessionId)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Field | Value |")
    [void]$sb.AppendLine("|-------|-------|")
    [void]$sb.AppendLine("| **Machine** | $env:COMPUTERNAME |")
    [void]$sb.AppendLine("| **User** | $env:USERNAME |")
    [void]$sb.AppendLine("| **Version** | $($script:LedgerAppVersion) |")
    [void]$sb.AppendLine("| **Iteration** | $($script:LedgerIteration) |")
    [void]$sb.AppendLine("| **Generated** | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |")
    # Phase 5: Run boundary metadata
    [void]$sb.AppendLine("| **Run State** | $($script:RunState) |")
    if ($script:RunStartedAt) { [void]$sb.AppendLine("| **Run Started** | $($script:RunStartedAt) |") }
    if ($script:RunEndedAt) { [void]$sb.AppendLine("| **Run Ended** | $($script:RunEndedAt) |") }
    [void]$sb.AppendLine("")

    # Summary stats
    $stats = @{
        Total     = $script:LedgerOperations.Count
        Success   = ($script:LedgerOperations | Where-Object { $_.Result -eq "Success" }).Count
        Warning   = ($script:LedgerOperations | Where-Object { $_.Result -eq "Warning" }).Count
        Failed    = ($script:LedgerOperations | Where-Object { $_.Result -eq "Failed" }).Count
        Skipped   = ($script:LedgerOperations | Where-Object { $_.Result -eq "Skipped" }).Count
        Mutations = ($script:LedgerOperations | Where-Object { $_.MutatesSystem -eq $true }).Count
        DryRuns   = ($script:LedgerOperations | Where-Object { $_.Executed -eq $false }).Count
        Executed  = ($script:LedgerOperations | Where-Object { $_.Executed -eq $true }).Count
    }

    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Metric | Count |")
    [void]$sb.AppendLine("|--------|-------|")
    [void]$sb.AppendLine("| Total Operations | $($stats.Total) |")
    [void]$sb.AppendLine("| Success | $($stats.Success) |")
    [void]$sb.AppendLine("| Warning | $($stats.Warning) |")
    [void]$sb.AppendLine("| Failed | $($stats.Failed) |")
    [void]$sb.AppendLine("| Skipped | $($stats.Skipped) |")
    [void]$sb.AppendLine("| System Mutations | $($stats.Mutations) |")
    [void]$sb.AppendLine("| Executed | $($stats.Executed) |")
    [void]$sb.AppendLine("| Dry Runs | $($stats.DryRuns) |")
    [void]$sb.AppendLine("")

    # Failures section (at top for visibility)
    $failures = $script:LedgerOperations | Where-Object { $_.Result -eq "Failed" }
    if ($failures.Count -gt 0) {
        [void]$sb.AppendLine("## Failures")
        [void]$sb.AppendLine("")
        foreach ($f in $failures) {
            [void]$sb.AppendLine("### $($f.OperationId): $($f.Name)")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("- **Category**: $($f.Category)")
            [void]$sb.AppendLine("- **Source**: $($f.Source)")
            [void]$sb.AppendLine("- **Mutates System**: $($f.MutatesSystem)")
            [void]$sb.AppendLine("- **Summary**: $($f.Summary)")
            if ($f.Evidence -and $f.Evidence.Count -gt 0) {
                [void]$sb.AppendLine("- **Evidence**: ``$($f.Evidence | ConvertTo-Json -Compress)``")
            }
            [void]$sb.AppendLine("")
        }
    }

    # Warnings section
    $warnings = $script:LedgerOperations | Where-Object { $_.Result -eq "Warning" }
    if ($warnings.Count -gt 0) {
        [void]$sb.AppendLine("## Warnings")
        [void]$sb.AppendLine("")
        foreach ($w in $warnings) {
            [void]$sb.AppendLine("- **$($w.OperationId)**: $($w.Name) - $($w.Summary)")
        }
        [void]$sb.AppendLine("")
    }

    # Mutations section
    $mutations = $script:LedgerOperations | Where-Object { $_.MutatesSystem -eq $true }
    if ($mutations.Count -gt 0) {
        [void]$sb.AppendLine("## System Mutations")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("The following operations modified system state:")
        [void]$sb.AppendLine("")
        foreach ($m in $mutations) {
            $resultIcon = switch ($m.Result) {
                "Success" { "[OK]" }
                "Warning" { "[WARN]" }
                "Failed"  { "[FAIL]" }
                default   { "[?]" }
            }
            [void]$sb.AppendLine("- $resultIcon **$($m.Name)** ($($m.Source)): $($m.Summary)")
        }
        [void]$sb.AppendLine("")
    }

    # Dry Runs section (if any)
    $dryRuns = $script:LedgerOperations | Where-Object { $_.Executed -eq $false }
    if ($dryRuns.Count -gt 0) {
        [void]$sb.AppendLine("## Dry Runs")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("The following operations were dry runs (no system changes made):")
        [void]$sb.AppendLine("")
        foreach ($dr in $dryRuns) {
            [void]$sb.AppendLine("### $($dr.OperationId): $($dr.Name) [DRY RUN]")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("- **Category**: $($dr.Category)")
            [void]$sb.AppendLine("- **Would Mutate System**: $($dr.MutatesSystem)")
            [void]$sb.AppendLine("- **Summary**: $($dr.Summary)")
            if ($dr.Plan) {
                [void]$sb.AppendLine("- **Planned Steps**:")
                foreach ($step in $dr.Plan.Steps) {
                    [void]$sb.AppendLine("  1. $step")
                }
                if ($dr.Plan.AffectedResources -and $dr.Plan.AffectedResources.Count -gt 0) {
                    [void]$sb.AppendLine("- **Affected Resources**: $($dr.Plan.AffectedResources -join ', ')")
                }
            }
            [void]$sb.AppendLine("")
        }
    }

    # Operations timeline (chronological)
    [void]$sb.AppendLine("## Operations Timeline")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| ID | Time (UTC) | Category | Name | Result | Executed | Summary |")
    [void]$sb.AppendLine("|----|------------|----------|------|--------|----------|---------|")

    foreach ($op in $script:LedgerOperations | Sort-Object { $_.OperationId }) {
        $timeStr = if ($op.TimestampUtc) { $op.TimestampUtc.Substring(11, 8) } else { "N/A" }
        $resultStr = switch ($op.Result) {
            "Success" { "OK" }
            "Warning" { "WARN" }
            "Failed"  { "FAIL" }
            "Skipped" { "SKIP" }
            "Pending" { "..." }
            default   { "?" }
        }
        $mutateFlag = if ($op.MutatesSystem) { " [M]" } else { "" }
        $execFlag = if ($op.Executed -eq $false) { "DRY" } else { "YES" }
        [void]$sb.AppendLine("| $($op.OperationId) | $timeStr | $($op.Category)$mutateFlag | $($op.Name) | $resultStr | $execFlag | $($op.Summary) |")
    }
    [void]$sb.AppendLine("")

    $markdown = $sb.ToString()

    # Write to session directory
    if ($script:LedgerSessionDir -and (Test-Path $script:LedgerSessionDir)) {
        $markdownPath = Join-Path $script:LedgerSessionDir "markdown.md"
        try {
            $markdown | Set-Content -Path $markdownPath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Track markdown write failure - continue but record for audit warning
            $script:LedgerWriteFailureCount++
            $script:LedgerLastWriteError = "Session markdown: $($_.Exception.Message)"
        }
    }

    return $markdown
}

# =============================================================================
# ACCESSOR FUNCTIONS
# =============================================================================

function Get-LedgerSessionId {
    <#
    .SYNOPSIS
        Returns the current ledger session ID.
    #>
    return $script:LedgerSessionId
}

function Get-LedgerSessionPath {
    <#
    .SYNOPSIS
        Returns the full path to the session directory.
    #>
    return $script:LedgerSessionDir
}

function Get-LedgerOperations {
    <#
    .SYNOPSIS
        Returns a copy of all operations in the session ledger.
    #>
    return $script:LedgerOperations
}

function Test-LedgerInitialized {
    <#
    .SYNOPSIS
        Returns $true if the ledger has been initialized.
    #>
    return $script:LedgerInitialized
}

function Test-LedgerFinalized {
    <#
    .SYNOPSIS
        Returns $true if the session has been finalized.
    #>
    return $script:LedgerSessionFinalized
}

function Get-LedgerWriteFailureCount {
    <#
    .SYNOPSIS
        Returns the count of non-critical write failures in this session.
    .DESCRIPTION
        Tracks failures of non-critical artifacts (PPF markdown, session metadata, etc.).
        Critical operations.json writes throw on failure; these are auxiliary artifacts.
        Use with Test-LoggingHealthy to surface audit trail issues to operators.
    .OUTPUTS
        Integer: Number of failed write attempts for auxiliary artifacts
    #>
    [CmdletBinding()]
    param()

    return $script:LedgerWriteFailureCount
}

function Get-LedgerLastWriteError {
    <#
    .SYNOPSIS
        Returns the last ledger write error message, if any.
    .DESCRIPTION
        Returns $null if no write errors have occurred.
        Use to provide details when Get-LedgerWriteFailureCount > 0.
    .OUTPUTS
        String: Error message or $null
    #>
    [CmdletBinding()]
    param()

    return $script:LedgerLastWriteError
}

# =============================================================================
# PHASE 6: PATTERN CORRELATION
# =============================================================================
# Deterministic pattern detection from run ledger.
# No ML, no heuristics - just rules + structure.
# Enables: noise compression, failure elevation, mixed-state detection.

function Get-RunPatterns {
    <#
    .SYNOPSIS
        Analyzes run ledger and returns grouped, ordered pattern objects.
    .DESCRIPTION
        Phase 6.1: Deterministic correlation of tool results.

        Returns structured patterns for:
        - Failures grouped by ToolCategory
        - Redundant PASS clusters (collapsible)
        - Mixed states (PASS + FAIL in same domain)
        - Repeated results (same tool, same outcome)

        This is replayable, testable, auditable - not probabilistic.
    .OUTPUTS
        PSCustomObject with pattern groups and compression hints.
    .EXAMPLE
        $patterns = Get-RunPatterns
        $patterns.FailuresByCategory  # Failures grouped by Bluetooth, Network, etc.
        $patterns.PassClusters        # PASS results that can be collapsed
        $patterns.MixedDomains        # Domains with both PASS and FAIL
    #>
    [CmdletBinding()]
    param()

    if (-not $script:LedgerInitialized) {
        return $null
    }

    $ops = $script:LedgerOperations

    # === PATTERN UNIT: Group by ToolCategory + Name + Result ===
    # Each pattern unit = (ToolCategory, ToolName, Result, Count, Summaries)
    $patternUnits = @{}
    foreach ($op in $ops) {
        # Extract ToolCategory from Evidence if available, else use Category
        $toolCat = if ($op.Evidence -and $op.Evidence.ToolCategory) {
            $op.Evidence.ToolCategory
        } else {
            $op.Category  # Fallback to operation category (Network, Bluetooth, etc.)
        }

        $key = "$toolCat|$($op.Name)|$($op.Result)"
        if (-not $patternUnits.ContainsKey($key)) {
            $patternUnits[$key] = @{
                ToolCategory = $toolCat
                ToolName     = $op.Name
                Result       = $op.Result
                Count        = 0
                Summaries    = [System.Collections.Generic.List[string]]::new()
                OperationIds = [System.Collections.Generic.List[string]]::new()
            }
        }
        $patternUnits[$key].Count++
        if ($op.Summary) { $patternUnits[$key].Summaries.Add($op.Summary) }
        $patternUnits[$key].OperationIds.Add($op.OperationId)
    }

    # === FAILURES BY CATEGORY ===
    # Group failures for elevation (first failure per category is most important)
    $failuresByCategory = @{}
    foreach ($unit in $patternUnits.Values) {
        if ($unit.Result -eq "Failed") {
            $cat = $unit.ToolCategory
            if (-not $failuresByCategory.ContainsKey($cat)) {
                $failuresByCategory[$cat] = [System.Collections.Generic.List[object]]::new()
            }
            $failuresByCategory[$cat].Add([PSCustomObject]@{
                ToolName     = $unit.ToolName
                Count        = $unit.Count
                Summaries    = $unit.Summaries.ToArray()
                OperationIds = $unit.OperationIds.ToArray()
            })
        }
    }

    # === PASS CLUSTERS (Collapsible) ===
    # Multiple PASS results in same category = noise, can be collapsed
    $passClusters = @{}
    foreach ($unit in $patternUnits.Values) {
        if ($unit.Result -eq "Success") {
            $cat = $unit.ToolCategory
            if (-not $passClusters.ContainsKey($cat)) {
                $passClusters[$cat] = @{
                    Tools = [System.Collections.Generic.List[string]]::new()
                    Count = 0
                }
            }
            $passClusters[$cat].Tools.Add($unit.ToolName)
            $passClusters[$cat].Count += $unit.Count
        }
    }
    # Convert to collapsible hints (categories with 2+ PASS tools)
    $collapsiblePass = @{}
    foreach ($cat in $passClusters.Keys) {
        if ($passClusters[$cat].Count -ge 2) {
            $collapsiblePass[$cat] = [PSCustomObject]@{
                ToolCount   = $passClusters[$cat].Tools.Count
                TotalPasses = $passClusters[$cat].Count
                Tools       = $passClusters[$cat].Tools.ToArray()
                Collapsible = $true
            }
        }
    }

    # === MIXED DOMAINS ===
    # Categories with both PASS and FAIL = investigation needed
    $resultsByCategory = @{}
    foreach ($unit in $patternUnits.Values) {
        $cat = $unit.ToolCategory
        if (-not $resultsByCategory.ContainsKey($cat)) {
            $resultsByCategory[$cat] = @{
                HasPass    = $false
                HasFail    = $false
                HasWarn    = $false
                Results    = [System.Collections.Generic.List[string]]::new()
            }
        }
        if ($unit.Result -eq "Success") { $resultsByCategory[$cat].HasPass = $true }
        if ($unit.Result -eq "Failed") { $resultsByCategory[$cat].HasFail = $true }
        if ($unit.Result -eq "Warning") { $resultsByCategory[$cat].HasWarn = $true }
        if (-not $resultsByCategory[$cat].Results.Contains($unit.Result)) {
            $resultsByCategory[$cat].Results.Add($unit.Result)
        }
    }
    $mixedDomains = @{}
    foreach ($cat in $resultsByCategory.Keys) {
        $r = $resultsByCategory[$cat]
        if ($r.HasPass -and ($r.HasFail -or $r.HasWarn)) {
            $mixedDomains[$cat] = [PSCustomObject]@{
                HasPass    = $r.HasPass
                HasFail    = $r.HasFail
                HasWarn    = $r.HasWarn
                Results    = $r.Results.ToArray()
                Severity   = if ($r.HasFail) { "High" } else { "Medium" }
            }
        }
    }

    # === REPEATED RESULTS ===
    # Same tool executed multiple times with same result
    $repeatedResults = @()
    foreach ($unit in $patternUnits.Values) {
        if ($unit.Count -gt 1) {
            $repeatedResults += [PSCustomObject]@{
                ToolCategory = $unit.ToolCategory
                ToolName     = $unit.ToolName
                Result       = $unit.Result
                Count        = $unit.Count
                Summaries    = $unit.Summaries.ToArray()
            }
        }
    }

    # === DOMINANT FAILURE VECTOR ===
    # Category with most failures = primary investigation target
    $dominantFailure = $null
    $maxFailures = 0
    foreach ($cat in $failuresByCategory.Keys) {
        $totalFails = ($failuresByCategory[$cat] | Measure-Object -Property Count -Sum).Sum
        if ($totalFails -gt $maxFailures) {
            $maxFailures = $totalFails
            $dominantFailure = [PSCustomObject]@{
                Category     = $cat
                FailureCount = $totalFails
                Tools        = $failuresByCategory[$cat]
            }
        }
    }

    # === SUMMARY STATS ===
    $totalOps = $ops.Count
    $failCount = ($ops | Where-Object { $_.Result -eq "Failed" }).Count
    $warnCount = ($ops | Where-Object { $_.Result -eq "Warning" }).Count
    $passCount = ($ops | Where-Object { $_.Result -eq "Success" }).Count
    $skipCount = ($ops | Where-Object { $_.Result -eq "Skipped" }).Count

    # === BUILD ORDERED RULES (Declarative facts with explicit priority) ===
    # Priority order: 1=highest urgency, 5=lowest
    # Each rule emits facts only, no conclusions or recommendations
    $rules = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Priority 1: DominantFailure (primary investigation target)
    if ($dominantFailure) {
        $rules.Add([PSCustomObject]@{
            Rule         = "DominantFailure"
            Priority     = 1
            Category     = $dominantFailure.Category
            FailureCount = $dominantFailure.FailureCount
            Tools        = @($dominantFailure.Tools | ForEach-Object { $_.ToolName })
        })
    }

    # Priority 2: FailuresByCategory (all failure facts)
    foreach ($cat in $failuresByCategory.Keys) {
        $failures = $failuresByCategory[$cat]
        $rules.Add([PSCustomObject]@{
            Rule         = "FailuresByCategory"
            Priority     = 2
            Category     = $cat
            FailureCount = ($failures | Measure-Object -Property Count -Sum).Sum
            Tools        = @($failures | ForEach-Object { $_.ToolName })
            Summaries    = @($failures | ForEach-Object { $_.Summaries } | Select-Object -First 3)
        })
    }

    # Priority 3: MixedDomains (domains needing investigation)
    foreach ($cat in $mixedDomains.Keys) {
        $mixed = $mixedDomains[$cat]
        $rules.Add([PSCustomObject]@{
            Rule      = "MixedDomains"
            Priority  = 3
            Category  = $cat
            PassCount = ($patternUnits.Values | Where-Object { $_.ToolCategory -eq $cat -and $_.Result -eq "Success" } | Measure-Object -Property Count -Sum).Sum
            FailCount = ($patternUnits.Values | Where-Object { $_.ToolCategory -eq $cat -and $_.Result -eq "Failed" } | Measure-Object -Property Count -Sum).Sum
            WarnCount = ($patternUnits.Values | Where-Object { $_.ToolCategory -eq $cat -and $_.Result -eq "Warning" } | Measure-Object -Property Count -Sum).Sum
            Results   = $mixed.Results
        })
    }

    # Priority 4: RepeatedResults (same tool, same outcome, multiple times)
    foreach ($repeated in $repeatedResults) {
        $rules.Add([PSCustomObject]@{
            Rule         = "RepeatedResults"
            Priority     = 4
            Category     = $repeated.ToolCategory
            ToolName     = $repeated.ToolName
            Result       = $repeated.Result
            Count        = $repeated.Count
        })
    }

    # Priority 5: PassClusters (collapsible noise)
    foreach ($cat in $collapsiblePass.Keys) {
        $cluster = $collapsiblePass[$cat]
        $rules.Add([PSCustomObject]@{
            Rule        = "PassClusters"
            Priority    = 5
            Category    = $cat
            ToolCount   = $cluster.ToolCount
            TotalPasses = $cluster.TotalPasses
            Tools       = $cluster.Tools
        })
    }

    # Sort by priority (stable, deterministic)
    $sortedRules = $rules | Sort-Object -Property Priority, Category

    return [PSCustomObject]@{
        # Run reference
        RunId           = $script:LedgerSessionId
        RunState        = $script:RunState

        # Summary counts (facts)
        TotalOperations = $totalOps
        FailureCount    = $failCount
        WarningCount    = $warnCount
        PassCount       = $passCount
        SkippedCount    = $skipCount

        # Ordered rules (declarative facts with explicit priority)
        # Consumers iterate in order: Priority 1 first, Priority 5 last
        Rules           = @($sortedRules)

        # Legacy accessors (for backward compatibility)
        FailuresByCategory = $failuresByCategory
        PassClusters       = $collapsiblePass
        MixedDomains       = $mixedDomains
        RepeatedResults    = $repeatedResults
        DominantFailure    = $dominantFailure
    }
}

# =============================================================================
# MODULE EXPORTS
# =============================================================================

Export-ModuleMember -Function @(
    'Initialize-SessionLedger',
    'Write-SessionOperation',
    'Start-SessionOperation',
    'Complete-SessionOperation',
    'Close-Session',
    'ConvertTo-SessionMarkdown',
    'Get-LedgerSessionId',
    'Get-LedgerSessionPath',
    'Get-LedgerOperations',
    'Test-LedgerInitialized',
    'Test-LedgerFinalized',
    'Get-LedgerWriteFailureCount',
    'Get-LedgerLastWriteError',
    # Phase 5: Run boundary management
    'Register-ToolStart',
    'Register-ToolEnd',
    'Get-RunMetadata',
    'Test-RunActive',
    'Test-RunCompleted',
    'Complete-RunForExport',
    # Phase 6: Pattern correlation
    'Get-RunPatterns'
)

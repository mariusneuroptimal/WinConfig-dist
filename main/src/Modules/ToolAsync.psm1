# ToolAsync.psm1 - Async execution wrapper for Tools tab actions
#
# PHASE 4 CONTRACT:
#   1. Clicking any tool must never block the UI
#   2. Must show progress within 100ms
#   3. Must be cancellable
#   4. Must deterministically report outcome to Details tab
#
# PHASE 7 CONTRACT (DRY RUN):
#   1. Tools may accept -DryRun switch for preview mode
#   2. Dry runs MUST record in ledger with Executed = $false
#   3. Dry runs MUST NOT produce side effects
#   4. Dry runs appear on dashboard as first-class entries
#   5. UI shows [DRY RUN] badge for dry run operations
#
# PATTERN:
#   - Background runspace for work
#   - Timer-based completion polling (avoids blocking UI thread)
#   - No EndInvoke() on UI thread during work
#   - No polling loops on UI thread

# Script-scoped state for active operations
$script:ActiveOperations = @{}

function Invoke-ToolActionAsync {
    <#
    .SYNOPSIS
        Executes a tool action asynchronously with inline status feedback.

    .DESCRIPTION
        Wraps a scriptblock for background execution with:
        - Immediate UI feedback (button disabled, "Running..." shown)
        - Cancellation support
        - Automatic session action registration on completion
        - Timer-based completion detection (non-blocking)

    .PARAMETER ActionName
        Display name for the action (used in session ledger).

    .PARAMETER Category
        Category for session action (Network, Audio, Bluetooth, etc.).

    .PARAMETER ActionButton
        The button control that triggered this action.

    .PARAMETER StatusLabel
        The inline status label (shows "Running...", hidden by default).

    .PARAMETER CancelButton
        The inline cancel button (hidden by default).

    .PARAMETER Work
        Scriptblock containing the actual work to perform.
        Must return a hashtable with: Result (PASS/WARN/FAIL), Summary, Evidence (optional).
        For dry run support, the scriptblock receives $DryRun as a parameter.

    .PARAMETER DryRun
        If specified, the operation runs in dry run mode:
        - MUST NOT produce side effects
        - MUST return a Plan in the result
        - Records in ledger with Executed = $false

    .PARAMETER ToolId
        Optional tool identifier from WinConfig.Tools.psd1 manifest.
        Required for dry run compliance validation.

    .EXAMPLE
        Invoke-ToolActionAsync -ActionName "Bluetooth Diagnostics" -Category "Bluetooth" `
            -ActionButton $btn -StatusLabel $statusLabel -CancelButton $cancelBtn `
            -Work {
                $diag = Get-WinConfigBluetoothDiagnostics
                @{ Result = $diag.Verdict.Status; Summary = $diag.Verdict.Summary; Evidence = $diag }
            }

    .EXAMPLE
        # Dry run example
        Invoke-ToolActionAsync -ActionName "Restart Bluetooth" -Category "AdminChange" `
            -ToolId "bluetooth-service-restart" -DryRun `
            -ActionButton $btn -StatusLabel $statusLabel -CancelButton $cancelBtn `
            -Work {
                param($DryRun)
                if ($DryRun) {
                    @{
                        Result = "SKIP"
                        Summary = "[DRY RUN] Would restart Bluetooth Support Service"
                        Executed = $false
                        Plan = @{
                            Steps = @("Stop bthserv service", "Wait for stop", "Start bthserv service")
                            AffectedResources = @("Service:bthserv")
                        }
                    }
                } else {
                    Restart-Service -Name bthserv -Force
                    @{ Result = "PASS"; Summary = "Bluetooth service restarted"; Executed = $true }
                }
            }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ActionName,

        [Parameter(Mandatory)]
        [ValidateSet("Diagnostics", "Configuration", "AdminChange", "Maintenance")]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Bluetooth", "Network", "Audio", "System", "Maintenance", "Other", "")]
        [string]$ToolCategory = "",

        [Parameter(Mandatory)]
        [System.Windows.Forms.Button]$ActionButton,

        [Parameter(Mandatory)]
        [System.Windows.Forms.Label]$StatusLabel,

        [Parameter(Mandatory)]
        [System.Windows.Forms.Button]$CancelButton,

        [Parameter(Mandatory)]
        [scriptblock]$Work,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [string]$ToolId = ""
    )

    # Generate unique operation ID
    $operationId = [guid]::NewGuid().ToString()

    # === PHASE 1: Immediate UI update (must complete within 100ms) ===
    $ActionButton.Enabled = $false
    $StatusLabel.Text = if ($DryRun) { "[DRY RUN] Planning..." } else { "Running..." }
    $StatusLabel.Visible = $true
    $CancelButton.Visible = $true
    $CancelButton.Enabled = $true

    # Create cancellation flag (simple boolean - runspaces share this via reference)
    $cancelFlag = [ref]$false

    # Store operation state in script scope
    $script:ActiveOperations[$operationId] = @{
        ActionName = $ActionName
        Category = $Category
        ToolCategory = $ToolCategory  # Phase 5: explicit tool domain for grouping
        ToolId = $ToolId              # Phase 7: tool manifest identifier
        DryRun = $DryRun.IsPresent    # Phase 7: dry run mode flag
        Button = $ActionButton
        StatusLabel = $StatusLabel
        CancelButton = $CancelButton
        CancelFlag = $cancelFlag
        StartTime = [datetime]::UtcNow
        PowerShell = $null
        AsyncResult = $null
        Completed = $false
        Result = $null
    }

    # === PHASE 5: Register tool start for run boundaries ===
    if (Get-Command Register-WinConfigToolStart -ErrorAction SilentlyContinue) {
        Register-WinConfigToolStart
    }

    # === Wire cancel button ===
    $CancelButton.Tag = $operationId
    $CancelButton.Add_Click({
        param($sender, $e)
        $opId = $sender.Tag
        if ($script:ActiveOperations.ContainsKey($opId)) {
            $op = $script:ActiveOperations[$opId]
            $op.CancelFlag.Value = $true
            $op.StatusLabel.Text = "Cancelling..."
            $sender.Enabled = $false
        }
    })

    # === PHASE 2: Start background execution ===
    $ps = [powershell]::Create()

    # Capture module path for import in runspace
    $modulesPath = $PSScriptRoot
    $isDryRun = $DryRun.IsPresent

    $ps.AddScript({
        param($WorkScript, $CancelFlagRef, $ModulesPath, $IsDryRun)

        $result = @{
            Success = $false
            Cancelled = $false
            Result = "FAIL"
            Summary = "Unknown error"
            Evidence = $null
            Error = $null
            Executed = -not $IsDryRun  # Phase 7: Dry runs have Executed = $false
            Plan = $null               # Phase 7: Plan object for dry runs
        }

        try {
            # Check cancellation before starting
            if ($CancelFlagRef.Value) {
                $result.Cancelled = $true
                $result.Result = "CANCELLED"
                $result.Summary = "Operation cancelled before start"
                return $result
            }

            # Import Bluetooth module if available
            $btModule = Join-Path $ModulesPath "Bluetooth.psm1"
            if (Test-Path $btModule) {
                Import-Module $btModule -Force -ErrorAction SilentlyContinue -Prefix WinConfig
            }

            # Import DryRun module if available (for dry run infrastructure)
            $dryRunModule = Join-Path $ModulesPath "DryRun.psm1"
            if (Test-Path $dryRunModule) {
                Import-Module $dryRunModule -Force -ErrorAction SilentlyContinue -Prefix WinConfig
            }

            # Execute the actual work, passing DryRun flag
            # Work scriptblock can accept $DryRun parameter for conditional execution
            $workResult = & $WorkScript $IsDryRun

            # Check cancellation after work
            if ($CancelFlagRef.Value) {
                $result.Cancelled = $true
                $result.Result = "CANCELLED"
                $result.Summary = "Operation cancelled"
                return $result
            }

            # Merge work result
            if ($workResult) {
                $result.Success = $true
                $result.Result = if ($workResult.Result) { $workResult.Result } else { "PASS" }
                $result.Summary = if ($workResult.Summary) { $workResult.Summary } else { "Completed" }
                $result.Evidence = $workResult.Evidence

                # Phase 7: Extract Executed and Plan from work result
                if ($workResult.ContainsKey('Executed')) {
                    $result.Executed = $workResult.Executed
                }
                if ($workResult.ContainsKey('Plan')) {
                    $result.Plan = $workResult.Plan
                }
            } else {
                $result.Success = $true
                $result.Result = "PASS"
                $result.Summary = "Completed"
            }

            # Dry run enforcement: ensure Executed is false for dry runs
            if ($IsDryRun) {
                $result.Executed = $false
                if (-not $result.Summary.StartsWith("[DRY RUN]")) {
                    $result.Summary = "[DRY RUN] $($result.Summary)"
                }
            }
        }
        catch {
            $result.Error = $_.Exception.Message
            $result.Summary = "Error: $($_.Exception.Message)"
            $result.Result = "FAIL"
        }

        return $result
    })

    $ps.AddArgument($Work)
    $ps.AddArgument($cancelFlag)
    $ps.AddArgument($modulesPath)
    $ps.AddArgument($isDryRun)

    # Start async
    $asyncResult = $ps.BeginInvoke()

    $script:ActiveOperations[$operationId].PowerShell = $ps
    $script:ActiveOperations[$operationId].AsyncResult = $asyncResult

    # === PHASE 3: Timer-based completion check ===
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100
    $timer.Tag = $operationId

    $timer.Add_Tick({
        param($sender, $e)

        $opId = $sender.Tag
        if (-not $script:ActiveOperations.ContainsKey($opId)) {
            $sender.Stop()
            $sender.Dispose()
            return
        }

        $op = $script:ActiveOperations[$opId]

        # Check if PowerShell invocation is complete
        if ($op.AsyncResult.IsCompleted) {
            # Stop timer immediately
            $sender.Stop()

            # === CORRECT PATTERN: Use BeginInvoke for UI-safe completion ===
            # EndInvoke must NOT run on UI thread directly
            # BeginInvoke marshals to UI thread and returns immediately
            $uiControl = $op.Button
            $uiControl.BeginInvoke([Action[object, object, string]]{
                param($operation, $asyncResult, $operationId)

                try {
                    # === CANCEL SHORT-CIRCUIT (Issue C) ===
                    # Cancellation is a UI contract, not a worker courtesy
                    # Do not interpret results from cancelled work
                    if ($operation.CancelFlag.Value) {
                        $operation.Button.Enabled = $true
                        $operation.StatusLabel.Visible = $false
                        $operation.CancelButton.Visible = $false

                        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                            Register-WinConfigSessionAction -Action $operation.ActionName `
                                -Detail "User cancelled operation" `
                                -Category $operation.Category `
                                -ToolCategory $operation.ToolCategory `
                                -Result "CANCELLED" `
                                -Tier 0 `
                                -Summary "Cancelled"
                        }
                        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) {
                            Update-ResultsDiagnosticsView
                        }
                        return  # Do not interpret worker result
                    }

                    # Get result inside BeginInvoke callback (safe)
                    $result = $null
                    try {
                        $result = $operation.PowerShell.EndInvoke($asyncResult)
                        if ($result -is [System.Collections.IList] -and $result.Count -gt 0) {
                            $result = $result[0]
                        }
                    }
                    catch {
                        $result = @{
                            Success = $false
                            Cancelled = $false
                            Result = "FAIL"
                            Summary = "Failed to get result: $($_.Exception.Message)"
                            Evidence = $null
                        }
                    }

                    # === UI updates (now safe - we're on UI thread) ===
                    $operation.Button.Enabled = $true
                    $operation.StatusLabel.Visible = $false
                    $operation.CancelButton.Visible = $false

                    # Determine final status
                    $finalResult = if ($result.Cancelled) { "CANCELLED" }
                                   elseif ($result.Success) { $result.Result }
                                   else { "FAIL" }

                    $finalSummary = if ($result.Summary) { $result.Summary } else { "Completed" }

                    # Register session action
                    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                        $tier = switch ($finalResult) {
                            "PASS" { 0 }
                            "WARN" { 1 }
                            "FAIL" { 2 }
                            "SKIP" { 0 }  # Phase 7: Dry runs use SKIP
                            "CANCELLED" { 0 }
                            default { 2 }
                        }

                        # Phase 7: Build evidence with Executed and Plan for dry run support
                        $evidence = if ($result.Evidence) { $result.Evidence } else { @{} }
                        if ($result.Executed -ne $null) {
                            $evidence['Executed'] = $result.Executed
                        }
                        if ($result.Plan) {
                            $evidence['Plan'] = $result.Plan
                        }
                        if ($operation.DryRun) {
                            $evidence['DryRun'] = $true
                        }
                        if ($operation.ToolId) {
                            $evidence['ToolId'] = $operation.ToolId
                        }

                        # Determine detail text
                        $detailText = if ($operation.DryRun) {
                            "[DRY RUN] $($operation.ActionName) - plan created"
                        } else {
                            "$($operation.ActionName) completed"
                        }

                        Register-WinConfigSessionAction -Action $operation.ActionName `
                            -Detail $detailText `
                            -Category $operation.Category `
                            -ToolCategory $operation.ToolCategory `
                            -Result $finalResult `
                            -Tier $tier `
                            -Summary $finalSummary `
                            -Evidence $evidence
                    }

                    # Update Details tab view
                    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) {
                        Update-ResultsDiagnosticsView
                    }
                }
                catch {
                    # Fallback error registration
                    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                        Register-WinConfigSessionAction -Action $operation.ActionName `
                            -Detail "Completion error" `
                            -Category $operation.Category `
                            -ToolCategory $operation.ToolCategory `
                            -Result "FAIL" `
                            -Tier 2 `
                            -Summary "Error: $($_.Exception.Message)"
                    }
                }
                finally {
                    # Cleanup (always runs)
                    $operation.PowerShell.Dispose()
                    $script:ActiveOperations.Remove($operationId)

                    # === PHASE 5: Register tool end for run boundaries ===
                    if (Get-Command Register-WinConfigToolEnd -ErrorAction SilentlyContinue) {
                        Register-WinConfigToolEnd
                    }
                }
            }, @($op, $op.AsyncResult, $opId))

            # === TIMER CLEANUP (Issue B - memory hygiene) ===
            # Stop then dispose - Dispose() handles event cleanup
            # ActiveOperations removal in finally block breaks closure references
            $sender.Stop()
            $sender.Dispose()
        }
    })

    $timer.Start()

    return $operationId
}

function Stop-ToolAction {
    <#
    .SYNOPSIS
        Cancels a running tool action by ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OperationId
    )

    if ($script:ActiveOperations.ContainsKey($OperationId)) {
        $op = $script:ActiveOperations[$OperationId]
        $op.CancelFlag.Value = $true
        $op.StatusLabel.Text = "Cancelling..."
        $op.CancelButton.Enabled = $false
    }
}

function Get-ActiveToolActions {
    <#
    .SYNOPSIS
        Returns currently running tool actions.
    #>
    [CmdletBinding()]
    param()

    $script:ActiveOperations.Keys | ForEach-Object {
        $op = $script:ActiveOperations[$_]
        [PSCustomObject]@{
            OperationId = $_
            ActionName = $op.ActionName
            Category = $op.Category
            StartTime = $op.StartTime
            ElapsedSeconds = ([datetime]::UtcNow - $op.StartTime).TotalSeconds
        }
    }
}

Export-ModuleMember -Function @(
    'Invoke-ToolActionAsync',
    'Stop-ToolAction',
    'Get-ActiveToolActions'
)

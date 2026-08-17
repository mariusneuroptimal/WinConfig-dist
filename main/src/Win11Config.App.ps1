# Re-entry guard (prevents double-execution when dot-sourced)
# Note: Uses Get-Variable to avoid StrictMode error on unset variable
if (Get-Variable -Name '__WINCONFIG_LOADED' -Scope Script -ValueOnly -ErrorAction SilentlyContinue) { return }
$script:__WINCONFIG_LOADED = $true

# ===== UI MODE FLAGS (STRICTMODE SAFE) =====
$script:IsUIDebug = $false

# =============================================================================
# ARCHITECTURE GUARD: Production UI must NEVER load in UI Debug Mode
# =============================================================================
# If $script:IsUIDebug is true, Bootstrap should have routed to App.Debug.ps1
# If we reach this file with debug mode active, routing failed - hard stop
if ($script:IsUIDebug) {
    throw "ARCHITECTURE VIOLATION: Production UI loaded in UI Debug Mode. Check Win11Config.ps1 routing."
}

# Load Windows Forms early (needed for MessageBox in error handling)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# System.Security is NOT loaded by default in PowerShell 5.1 — required for
# SignedCms catalog parsing (zamp-driver-trust-repair plan + execute phases).
Add-Type -AssemblyName System.Security

# === STA ENFORCEMENT (Phase 4 requirement) ===
# WinForms requires STA apartment state for proper async behavior
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-Warning "WinForms should run in STA mode. Use: powershell -sta -File Bootstrap.ps1"
    # Continue anyway - ShowDialog can work in MTA but async may misbehave
}

# WinForms visual styles
[System.Windows.Forms.Application]::EnableVisualStyles()
try {
    [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
} catch {
    # Already set in this session - safe to ignore
}

# ============================================================================
# MODULE LOADING - Manifest-driven (RUNTIME_DEPENDENCIES.psd1)
# ============================================================================
# Bootstrap preloads ModuleLoader.psm1 - verify it's available
if (-not (Get-Command 'Resolve-RuntimeManifest' -ErrorAction SilentlyContinue)) {
    throw "FATAL: ModuleLoader not loaded. Resolve-RuntimeManifest function missing. Run via Bootstrap.ps1."
}

# Resolve manifest → import specs (paths, prefixes, deferred flags)
# Actual imports happen in THIS scope to preserve -Global module visibility
$script:ManifestResult = Resolve-RuntimeManifest `
    -ManifestPath (Join-Path $PSScriptRoot "RUNTIME_DEPENDENCIES.psd1") `
    -SourceRoot $PSScriptRoot

# --- Import required modules (fail-closed) ---
foreach ($spec in $script:ManifestResult.Required) {
    $importArgs = @{ Path = $spec.Path }
    if ($spec.Prefix) { $importArgs.Prefix = $spec.Prefix }
    Import-RequiredModule @importArgs

    # GlobalForce: second import for WinForms runspace visibility
    if ($spec.GlobalForce) {
        Import-Module $spec.Path -Force -Global
    }
}

# --- Import optional modules (graceful degradation) ---
$script:OptionalLoaded = @{}
foreach ($spec in $script:ManifestResult.Optional) {
    $importArgs = @{ Path = $spec.Path }
    if ($spec.Prefix) { $importArgs.Prefix = $spec.Prefix }
    $loaded = Import-OptionalModule @importArgs
    $script:OptionalLoaded[$spec.ModuleName] = $loaded
}

# --- POST-IMPORT HOOKS (app-level initialization) ---

# Paths: initialize ephemeral temp root
Initialize-WinConfigPaths | Out-Null

# Logger: initialize JSONL session logging (if loaded)
if ($script:OptionalLoaded['Logger']) {
    Initialize-WinConfigLogger -Version $AppVersion -Iteration $Iteration
    Write-WinConfigLog -Action "Startup" -Message "WinConfig application initialized"
    $tempRoot = Get-WinConfigTempRoot
    Write-WinConfigLog -Action "Startup" -Message "Session temp root: $tempRoot"
}

# SessionOperationLedger: initialize session ledger (if loaded)
if ($script:OptionalLoaded['SessionOperationLedger']) {
    Initialize-WinConfigSessionLedger -Version $AppVersion -Iteration $Iteration
}

# ============================================================================
# DEFERRED MODULE LOADING - Performance optimization (PERF-001)
# Deferred modules are declared in manifest (Deferred=$true).
# They are NOT loaded at startup. They load on first use.
# ============================================================================


# Network.Diagnostics module - NOT loaded in prod (only used by tests)
# Tests import it directly when needed. No runtime dependency.

# Generate session ID for diagnostics (operator support)
$script:SessionId = [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
$script:SessionStartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Get log path info (if logger is available) - used by diagnostics panel
$script:LogPathInfo = if (Get-Command Get-WinConfigLogPath -ErrorAction SilentlyContinue) {
    Get-WinConfigLogPath
} else {
    @{ Status = "Disabled"; Path = $null }
}

# Container for real-time actions display refresh (used by diagnostics panel)
$script:DiagActionsContainer = $null
$script:DiagActionsLabel = $null
$script:DiagTabColor = $null

# --- Diagnostics ingest (Cloudflare R2 only) ---
$script:DiagnosticsIngestUrl = "https://ingest.dashboards.work/diagnostics"

# Zero-config token acquisition from ingest worker
# Fetches short-lived JWT at runtime - no local configuration required
function Get-NoSupportIngestToken {
    try {
        $resp = Invoke-RestMethod `
            -Uri "https://ingest.dashboards.work/ingest-token" `
            -Method GET `
            -TimeoutSec 5
        return $resp.token
    }
    catch {
        Write-Warning "Failed to retrieve ingest token: $_"
        return $null
    }
}

# Function to create a collapsible diagnostic section
function New-DiagnosticSection {
    param(
        [string]$Title,
        [array]$Actions,
        [bool]$Expanded = $false
    )

    $section = New-Object System.Windows.Forms.Panel
    $section.AutoSize = $true
    $section.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $section.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)

    $sectionFlow = New-Object System.Windows.Forms.FlowLayoutPanel
    $sectionFlow.AutoSize = $true
    $sectionFlow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $sectionFlow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
    $sectionFlow.WrapContents = $false
    $section.Controls.Add($sectionFlow)

    # Count results for this section
    $passCount = ($Actions | Where-Object { $_.Result -eq "PASS" }).Count
    $warnCount = ($Actions | Where-Object { $_.Result -eq "WARN" }).Count
    $failCount = ($Actions | Where-Object { $_.Result -eq "FAIL" }).Count

    # Determine section status color
    $statusColor = if ($failCount -gt 0) { [System.Drawing.Color]::Crimson }
                   elseif ($warnCount -gt 0) { [System.Drawing.Color]::DarkOrange }
                   elseif ($passCount -gt 0) { [System.Drawing.Color]::ForestGreen }
                   else { [System.Drawing.Color]::Gray }

    # Header button
    $prefix = if ($Expanded) { "-" } else { "+" }
    $statusSummary = @()
    if ($failCount -gt 0) { $statusSummary += "$failCount FAIL" }
    if ($warnCount -gt 0) { $statusSummary += "$warnCount WARN" }
    if ($passCount -gt 0) { $statusSummary += "$passCount PASS" }
    $summaryText = if ($statusSummary.Count -gt 0) { " (" + ($statusSummary -join ", ") + ")" } else { "" }

    $header = New-Object System.Windows.Forms.Button
    $header.Text = "$prefix $Title$summaryText"
    $header.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $header.FlatAppearance.BorderSize = 1
    $header.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $header.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $header.ForeColor = $statusColor
    $header.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $header.AutoSize = $true
    $header.Cursor = [System.Windows.Forms.Cursors]::Hand
    $header.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $header.Padding = New-Object System.Windows.Forms.Padding(5, 3, 10, 3)
    $sectionFlow.Controls.Add($header)

    # Content panel
    $content = New-Object System.Windows.Forms.FlowLayoutPanel
    $content.AutoSize = $true
    $content.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $content.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
    $content.WrapContents = $false
    $content.BackColor = [System.Drawing.Color]::FromArgb(252, 252, 252)
    $content.Padding = New-Object System.Windows.Forms.Padding(15, 8, 10, 8)
    $content.Visible = $Expanded
    $sectionFlow.Controls.Add($content)

    # Populate content with actions
    foreach ($action in $Actions) {
        $result = if ($action.Result) { $action.Result } else { "PENDING" }
        $summary = if ($action.Summary) { $action.Summary } else { $action.Detail }

        $resultColor = switch ($result) {
            "PASS" { [System.Drawing.Color]::ForestGreen }
            "WARN" { [System.Drawing.Color]::DarkOrange }
            "FAIL" { [System.Drawing.Color]::Crimson }
            default { [System.Drawing.Color]::Gray }
        }

        $itemPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $itemPanel.AutoSize = $true
        $itemPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $itemPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $itemPanel.WrapContents = $false
        $itemPanel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)

        $resultLabel = New-Object System.Windows.Forms.Label
        $resultLabel.Text = "[$result]"
        $resultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $resultLabel.ForeColor = $resultColor
        $resultLabel.AutoSize = $true
        $resultLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
        $itemPanel.Controls.Add($resultLabel)

        $actionLabel = New-Object System.Windows.Forms.Label
        $actionLabel.Text = "$($action.Action): $summary"
        $actionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $actionLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $actionLabel.AutoSize = $true
        $itemPanel.Controls.Add($actionLabel)

        $content.Controls.Add($itemPanel)
    }

    # Toggle handler
    $header.Add_Click({
        param($sender, $e)
        $content.Visible = -not $content.Visible
        $currentText = $header.Text
        if ($content.Visible) {
            $header.Text = $currentText -replace '^\+', '-'
        } else {
            $header.Text = $currentText -replace '^-', '+'
        }
    }.GetNewClosure())

    return $section
}

# Function to update the full Results/Diagnostics view
function Update-ResultsDiagnosticsView {
    # Get all session actions from the ledger (single source of truth)
    $sessionActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
        @(Get-WinConfigSessionActions)
    } else {
        @()
    }

    # Update summary badges
    if ($script:ResultsSummaryPass) {
        $passCount = ($sessionActions | Where-Object { $_.Result -eq "PASS" }).Count
        $warnCount = ($sessionActions | Where-Object { $_.Result -eq "WARN" }).Count
        $failCount = ($sessionActions | Where-Object { $_.Result -eq "FAIL" }).Count

        $script:ResultsSummaryPass.Text = "$passCount PASS"
        $script:ResultsSummaryWarn.Text = "$warnCount WARN"
        $script:ResultsSummaryFail.Text = "$failCount FAIL"

        # Dim badges with zero count
        $script:ResultsSummaryPass.BackColor = if ($passCount -gt 0) { [System.Drawing.Color]::ForestGreen } else { [System.Drawing.Color]::FromArgb(180, 180, 180) }
        $script:ResultsSummaryWarn.BackColor = if ($warnCount -gt 0) { [System.Drawing.Color]::DarkOrange } else { [System.Drawing.Color]::FromArgb(180, 180, 180) }
        $script:ResultsSummaryFail.BackColor = if ($failCount -gt 0) { [System.Drawing.Color]::Crimson } else { [System.Drawing.Color]::FromArgb(180, 180, 180) }
    }

    # === PHASE 6: Update Pattern Insights Banner ===
    # Get patterns from ledger (read-only, no recompute) - used by both insights panel AND badges
    $patterns = if (Get-Command Get-WinConfigRunPatterns -ErrorAction SilentlyContinue) {
        Get-WinConfigRunPatterns
    } else {
        $null
    }

    if ($script:PatternInsightsPanel) {
        $script:PatternInsightsPanel.Controls.Clear()
        $script:PatternInsightsPanel.Visible = $false

        if ($patterns -and $patterns.Rules.Count -gt 0) {
            # Filter to priority 1-3 rules only (actionable signals)
            $significantRules = @($patterns.Rules | Where-Object { $_.Priority -le 3 })

            if ($significantRules.Count -gt 0) {
                $script:PatternInsightsPanel.Visible = $true

                # Header
                $headerLabel = New-Object System.Windows.Forms.Label
                $headerLabel.Text = "Patterns Detected"
                $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $headerLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 80, 60)
                $headerLabel.AutoSize = $true
                $headerLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
                $script:PatternInsightsPanel.Controls.Add($headerLabel)

                # Display rules in priority order (declarative facts only)
                foreach ($rule in $significantRules) {
                    $ruleText = switch ($rule.Rule) {
                        "DominantFailure" {
                            # Fact: Category X has Y failures in tools A, B, C
                            "$($rule.Category): $($rule.FailureCount) failure(s) in $($rule.Tools -join ', ')"
                        }
                        "FailuresByCategory" {
                            # Fact: Category X has failures
                            "$($rule.Category): $($rule.FailureCount) failed - $($rule.Summaries | Select-Object -First 1)"
                        }
                        "MixedDomains" {
                            # Fact: Category X has mixed results (P pass, F fail, W warn)
                            "$($rule.Category): mixed results ($($rule.PassCount) pass, $($rule.FailCount) fail, $($rule.WarnCount) warn)"
                        }
                        default { $null }
                    }

                    if ($ruleText) {
                        $ruleLabel = New-Object System.Windows.Forms.Label
                        $ruleLabel.Text = [char]0x2022 + " " + $ruleText  # Bullet point
                        $ruleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                        $ruleLabel.ForeColor = switch ($rule.Priority) {
                            1 { [System.Drawing.Color]::Crimson }       # DominantFailure = red
                            2 { [System.Drawing.Color]::DarkOrange }    # FailuresByCategory = orange
                            3 { [System.Drawing.Color]::FromArgb(180, 130, 70) }  # MixedDomains = amber
                            default { [System.Drawing.Color]::Gray }
                        }
                        $ruleLabel.AutoSize = $true
                        $ruleLabel.Margin = New-Object System.Windows.Forms.Padding(8, 2, 0, 2)
                        $script:PatternInsightsPanel.Controls.Add($ruleLabel)
                    }
                }
            }
        }
    }

    # === PHASE 7.2: Update Category Attention Badges ===
    # Shows badge on Tools tab when a category has DominantFailure pattern
    # Updates both detail panel badges AND category list badges
    if ($script:CategoryBadges -and $script:CategoryBadges.Count -gt 0) {
        # First, hide all detail badges
        foreach ($badge in $script:CategoryBadges.Values) {
            if ($badge) { $badge.Visible = $false }
        }
        # Hide all list badges
        if ($script:CategoryListBadges) {
            foreach ($listBadge in $script:CategoryListBadges.Values) {
                if ($listBadge) { $listBadge.Visible = $false }
            }
        }

        # Then show badges for categories with DominantFailure
        if ($patterns -and $patterns.Rules.Count -gt 0) {
            $dominantFailures = @($patterns.Rules | Where-Object { $_.Rule -eq "DominantFailure" })
            foreach ($rule in $dominantFailures) {
                $category = $rule.Category
                # Show detail badge
                if ($script:CategoryBadges.ContainsKey($category)) {
                    $badge = $script:CategoryBadges[$category]
                    if ($badge) { $badge.Visible = $true }
                }
                # Show list badge
                if ($script:CategoryListBadges -and $script:CategoryListBadges.ContainsKey($category)) {
                    $listBadge = $script:CategoryListBadges[$category]
                    if ($listBadge) { $listBadge.Visible = $true }
                }
            }
        }
    }

    # === PHASE 7.3: Update Re-run Failed Tools Button Visibility ===
    if ($script:RerunFailedPanel) {
        # Count unique failed tools that can be re-run
        $failedTools = @($sessionActions | Where-Object { $_.Result -eq "FAIL" } | ForEach-Object { $_.Action } | Select-Object -Unique)
        $rerunableCount = @($failedTools | Where-Object { $script:ToolButtonRegistry.ContainsKey($_) }).Count

        if ($rerunableCount -gt 0) {
            $script:RerunFailedPanel.Visible = $true
            $script:RerunFailedCountLabel.Text = "($rerunableCount tool$(if($rerunableCount -gt 1){'s'}))"
        } else {
            $script:RerunFailedPanel.Visible = $false
        }
    }

    # Update diagnostic sections (simplified for form-style layout)
    if ($script:DiagSectionsContainer) {
        $script:DiagSectionsContainer.Controls.Clear()

        if ($sessionActions.Count -eq 0) {
            $noActionsLabel = New-Object System.Windows.Forms.Label
            $noActionsLabel.Text = "(No actions executed yet)"
            $noActionsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $noActionsLabel.ForeColor = [System.Drawing.Color]::Gray
            $noActionsLabel.AutoSize = $true
            $noActionsLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 5)
            $script:DiagSectionsContainer.Controls.Add($noActionsLabel)
        } else {
            # Simple list of actions with results
            foreach ($action in $sessionActions) {
                $result = if ($action.Result) { $action.Result } else { "PENDING" }
                $summary = if ($action.Summary) { $action.Summary } else { $action.Detail }

                $resultColor = switch ($result) {
                    "PASS" { [System.Drawing.Color]::ForestGreen }
                    "WARN" { [System.Drawing.Color]::DarkOrange }
                    "FAIL" { [System.Drawing.Color]::Crimson }
                    default { [System.Drawing.Color]::Gray }
                }

                $actionPanel = New-Object System.Windows.Forms.FlowLayoutPanel
                $actionPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
                $actionPanel.WrapContents = $false
                $actionPanel.AutoSize = $true
                $actionPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                $actionPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)

                $resultLabel = New-Object System.Windows.Forms.Label
                $resultLabel.Text = "[$result]"
                $resultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $resultLabel.ForeColor = $resultColor
                $resultLabel.AutoSize = $true
                $resultLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
                $actionPanel.Controls.Add($resultLabel)

                $actionLabel = New-Object System.Windows.Forms.Label
                $actionLabel.Text = "$($action.Action): $summary"
                $actionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $actionLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                $actionLabel.AutoSize = $true
                $actionPanel.Controls.Add($actionLabel)

                $script:DiagSectionsContainer.Controls.Add($actionPanel)
            }
        }
    }
}

# Function to refresh the actions display (called on tab switch to Results)
function Update-DiagActionsDisplay {
    if ($null -eq $script:DiagActionsContainer) { return }

    $script:DiagActionsContainer.Controls.Clear()

    $sessionActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
        Get-WinConfigSessionActions
    } else {
        @()
    }

    # --- Actions Table (Phase 3: TableLayoutPanel, no absolute positioning) ---
    if ($sessionActions.Count -eq 0) {
        $noActionsLabel = New-Object System.Windows.Forms.Label
        $noActionsLabel.Text = "  (No actions executed yet)"
        $noActionsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $noActionsLabel.ForeColor = [System.Drawing.Color]::Gray
        $noActionsLabel.AutoSize = $true
        $noActionsLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 5)
        $script:DiagActionsContainer.Controls.Add($noActionsLabel)
    } else {
        # Create TableLayoutPanel for actions table
        $actionsTable = New-Object System.Windows.Forms.TableLayoutPanel
        $actionsTable.Dock = [System.Windows.Forms.DockStyle]::Top
        $actionsTable.AutoSize = $true
        $actionsTable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $actionsTable.ColumnCount = 4
        $actionsTable.RowCount = 0
        $actionsTable.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 0)
        $actionsTable.CellBorderStyle = [System.Windows.Forms.TableLayoutPanelCellBorderStyle]::None
        # Column styles: Time (Auto), Result (Auto), Action (Auto), Summary (Fill)
        [void]$actionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$actionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$actionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$actionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

        # Header row
        $actionsTable.RowCount++
        [void]$actionsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

        $colTime = New-Object System.Windows.Forms.Label
        $colTime.Text = "Time"
        $colTime.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $colTime.AutoSize = $true
        $colTime.Margin = New-Object System.Windows.Forms.Padding(5, 3, 10, 3)
        $actionsTable.Controls.Add($colTime, 0, 0)

        $colResult = New-Object System.Windows.Forms.Label
        $colResult.Text = "Result"
        $colResult.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $colResult.AutoSize = $true
        $colResult.Margin = New-Object System.Windows.Forms.Padding(0, 3, 10, 3)
        $actionsTable.Controls.Add($colResult, 1, 0)

        $colAction = New-Object System.Windows.Forms.Label
        $colAction.Text = "Action"
        $colAction.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $colAction.AutoSize = $true
        $colAction.Margin = New-Object System.Windows.Forms.Padding(0, 3, 10, 3)
        $actionsTable.Controls.Add($colAction, 2, 0)

        $colSummary = New-Object System.Windows.Forms.Label
        $colSummary.Text = "Summary"
        $colSummary.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $colSummary.AutoSize = $true
        $colSummary.Margin = New-Object System.Windows.Forms.Padding(0, 3, 5, 3)
        $actionsTable.Controls.Add($colSummary, 3, 0)

        # Data rows
        foreach ($action in $sessionActions) {
            $timeStr = $action.Timestamp.ToString("HH:mm:ss")
            $result = if ($action.Result) { $action.Result } else { "PENDING" }
            $summary = if ($action.Summary) { $action.Summary } else { $action.Detail }

            # Result color
            $resultColor = switch ($result) {
                "PASS" { [System.Drawing.Color]::ForestGreen }
                "WARN" { [System.Drawing.Color]::DarkOrange }
                "FAIL" { [System.Drawing.Color]::Crimson }
                default { [System.Drawing.Color]::Gray }
            }

            $rowIndex = $actionsTable.RowCount
            $actionsTable.RowCount++
            [void]$actionsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

            # Time column
            $timeLabel = New-Object System.Windows.Forms.Label
            $timeLabel.Text = $timeStr
            $timeLabel.Font = New-Object System.Drawing.Font("Consolas", 8)
            $timeLabel.ForeColor = [System.Drawing.Color]::Black
            $timeLabel.AutoSize = $true
            $timeLabel.Margin = New-Object System.Windows.Forms.Padding(5, 2, 10, 2)
            $actionsTable.Controls.Add($timeLabel, 0, $rowIndex)

            # Result column
            $resultLabel = New-Object System.Windows.Forms.Label
            $resultLabel.Text = $result
            $resultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
            $resultLabel.ForeColor = $resultColor
            $resultLabel.AutoSize = $true
            $resultLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 10, 2)
            $actionsTable.Controls.Add($resultLabel, 1, $rowIndex)

            # Action column
            $actionLabel = New-Object System.Windows.Forms.Label
            $actionLabel.Text = $action.Action
            $actionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $actionLabel.ForeColor = [System.Drawing.Color]::Black
            $actionLabel.AutoSize = $true
            $actionLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 10, 2)
            $actionsTable.Controls.Add($actionLabel, 2, $rowIndex)

            # Summary column - full text, no truncation (audit surface)
            $summaryLabel = New-Object System.Windows.Forms.Label
            $summaryLabel.Text = $summary
            $summaryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $summaryLabel.ForeColor = [System.Drawing.Color]::DimGray
            $summaryLabel.AutoSize = $true
            $summaryLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 5, 2)
            $actionsTable.Controls.Add($summaryLabel, 3, $rowIndex)
        }

        $script:DiagActionsContainer.Controls.Add($actionsTable)
    }
}

# Phase 2C: Env and Paths already loaded by manifest-driven loader (top of file)
# No redundant re-import needed.

# Configure GitHub authentication (optional - only needed for some features)
# Backward compatibility: alias GITHUB_TOKEN to WINCONFIG_GITHUB_TOKEN
if (-not $env:WINCONFIG_GITHUB_TOKEN -and $env:GITHUB_TOKEN) {
    $env:WINCONFIG_GITHUB_TOKEN = $env:GITHUB_TOKEN
}

$GitHubToken = $env:WINCONFIG_GITHUB_TOKEN
# Token is optional - features requiring it will check and prompt if needed

# Enable DPI awareness
if (-not ("DPIAware" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DPIAware {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
"@
}
[DPIAware]::SetProcessDPIAware() | Out-Null

$cleanmgrPath = "$env:SystemRoot\System32\cleanmgr.exe"


# Define colors
$backgroundColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$tabColor = [System.Drawing.Color]::FromArgb(76, 121, 155)
$textColor = [System.Drawing.Color]::White

# Create main form
$form = New-Object System.Windows.Forms.Form
# Build form title from canonical VERSION.psd1 values
# Iteration badge shown for non-production environments only
# UI-REWORK: Include session ID in title for easy reference
$shortSessionId = $script:SessionId.Substring(0, 8)
$formTitle = "$AppName v.$AppVersion - $shortSessionId"
if ($Iteration -ne "production") {
    $formTitle = "$AppName v.$AppVersion [$($Iteration.ToUpper())] - $shortSessionId"
}
$form.Text = $formTitle
$form.StartPosition = "CenterScreen"
$form.BackColor = $backgroundColor
$form.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
# DPI-SAFE MIN SIZE: AutoScaleMode::Dpi alone doesn't scale MinimumSize when set
# in code (design baseline = current DPI → ratio 1.0, no scaling). Fonts however
# render in points and grow with DPI naturally, so on high-DPI displays like
# Surface Pro 10 (2880x1920 @ 200%) the form ends up at 900 physical px wide
# with full-size fonts inside → severe clipping. Read system DPI directly and
# scale the design-time minimum (900x600 logical) to physical pixels.
$script:DesignMinWidth = 900
$script:DesignMinHeight = 600
$tmpGraphics = [System.Drawing.Graphics]::FromHwnd([System.IntPtr]::Zero)
$script:DpiScale = $tmpGraphics.DpiX / 96.0
$tmpGraphics.Dispose()
$scaledMinWidth = [int]([Math]::Round($script:DesignMinWidth * $script:DpiScale))
$scaledMinHeight = [int]([Math]::Round($script:DesignMinHeight * $script:DpiScale))
$form.MinimumSize = New-Object System.Drawing.Size($scaledMinWidth, $scaledMinHeight)
$form.Size = $form.MinimumSize  # Start at minimum, grow as needed

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
# UI-REWORK: Remove fixed ItemSize; tabs auto-size to content + DPI
$tabControl.SizeMode = [System.Windows.Forms.TabSizeMode]::Normal
$tabControl.Padding = New-Object System.Drawing.Point(12, 6)  # Tab padding for touch-friendly targets
$form.Controls.Add($tabControl)

# Function to create a tab page
function New-TabPage($name) {
    $tabPage = New-Object System.Windows.Forms.TabPage
    $tabPage.Text = $name
    $tabPage.BackColor = $backgroundColor
    $tabPage.UseVisualStyleBackColor = $false

    $flowLayoutPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowLayoutPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $flowLayoutPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
    $flowLayoutPanel.WrapContents = $false
    $flowLayoutPanel.AutoScroll = $true
    $flowLayoutPanel.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)  # Add padding here
    $tabPage.Controls.Add($flowLayoutPanel)

    return $tabPage
}


# Function to create a headline
function New-Headline($text) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $text
    $label.AutoSize = $true
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $label.ForeColor = $tabColor
    return $label
}

# Function to create a button
# UI-REWORK: AutoSize with padding instead of fixed dimensions; scales with DPI
function New-Button($text) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $text
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $button.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $button.ForeColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    # HIGH-DENSITY: Smaller, faster buttons - controls not CTAs
    $button.AutoSize = $true
    $button.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $button.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
    $button.MinimumSize = New-Object System.Drawing.Size(90, 28)
    $button.Margin = New-Object System.Windows.Forms.Padding(2, 2, 2, 2)
    $button.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

    return $button
}

function Get-WindowsUpdateHistory {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    $history = $searcher.QueryHistory(0, $historyCount)
    
    $updates = @()
    foreach ($update in $history) {
        if ($update.Operation -eq 1 -and $update.Title -match "Windows") {
            $updates += [PSCustomObject]@{
                Title = $update.Title
                Date = $update.Date
                KB = if ($update.Title -match "KB\d+") { $matches[0] } else { "N/A" }
            }
        }
    }
    
    return $updates | Sort-Object Date -Descending | Select-Object -First 20
}

# Function to copy KB number to clipboard
function Copy-KBToClipboard($kb) {
    [System.Windows.Forms.Clipboard]::SetText($kb)
}

# Function to search Windows Catalog
function Search-WindowsCatalog($kb) {
    $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$kb"
    Start-Process $url
}

# Add the Remove-IntelSSTAudioDriver function
$buttonClickHandler = {
    # Check if running as administrator
    if (-not (Assert-WinConfigIsAdmin)) { return }

    # SAFETY: Block mutations if audit trail is broken
    if (-not (Assert-AuditTrailHealthyForMutation)) { return }

    # Register session action (admin verified, interactive operation)
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Intel SST Removal" -Detail "Intel Smart Sound Technology driver removal initiated" -Category "AdminChange" -Result "PASS" -Tier 0 -Summary "Removal wizard launched"
    }
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

    # Create a new form for output
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "Remove Intel SST Audio Driver"
    $outputForm.Size = New-Object System.Drawing.Size(800, 800)
    $outputForm.StartPosition = "CenterScreen"

    $outputTextBox = New-Object System.Windows.Forms.RichTextBox
    Initialize-GuiDiagnosticBox -Box $outputTextBox
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $outputForm.Controls.Add($outputTextBox)

    # Show the form immediately
    $outputForm.Show()
    $outputForm.Refresh()

    # Redirect Write-Host to the RichTextBox
    function Write-Log {
        param (
            [string]$Message,
            [string]$Type = "INFO"
        )
        $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [$Type] $Message"
        $outputTextBox.AppendText("$logMessage`r`n")
        $outputTextBox.ScrollToCaret()
        $outputForm.Refresh()
    }

    # Function to find Intel Smart Sound Technology USB Audio drivers and Hardware IDs
    function Find-IntelAudioDrivers {
        Write-Log "Searching for Intel Smart Sound Technology USB Audio drivers..."

        $intelAudioDrivers = @()
        $hardwareIDs = @()

        # Search for Intel Smart Sound Technology USB Audio devices using WMI
        $devices = Get-WmiObject Win32_PnPEntity | Where-Object {
            $_.Name -like "*Intel*Smart Sound Technology*USB Audio*"
        }

        foreach ($device in $devices) {
            Write-Log "Found active Intel Smart Sound Technology USB Audio device: $($device.Name)"
            $driverInfo = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceID -eq $device.DeviceID }
            
            if ($driverInfo) {
                $intelAudioDrivers += [PSCustomObject]@{
                    DeviceName = $device.Name
                    Driver = $driverInfo.InfName
                    DriverVersion = $driverInfo.DriverVersion
                    OriginalFileName = $driverInfo.InfName
                    HardwareIds = $device.HardwareID
                }
                $hardwareIDs += $device.HardwareID
            }
        }

        # Search for installed drivers that might not have an active device
        $driverFiles = Get-WindowsDriver -Online -All | Where-Object {
            ($_.ClassName -eq "MEDIA" -or $_.ClassName -eq "AUDIO") -and 
            ($_.OriginalFileName -match "intcusb\.inf")
        }

        foreach ($driver in $driverFiles) {
            try {
                $content = Get-Content $driver.OriginalFileName -ErrorAction Stop
                if ($content -match "Intel.*Smart Sound Technology" -and $content -match "USB Audio") {
                    Write-Log "Found installed driver (possibly inactive): $($driver.Driver) - $($driver.OriginalFileName) - Version: $($driver.Version)"
                    
                    # Attempt to get hardware IDs from INF file
                    $infHardwareIDs = Select-String -Path $driver.OriginalFileName -Pattern 'HardwareID.*=(.*)' | 
                        ForEach-Object { $_.Matches.Groups[1].Value.Trim() -split ',' } | 
                        ForEach-Object { $_.Trim('"') } | 
                        Where-Object { $_ -ne '' }
                    
                    $intelAudioDrivers += [PSCustomObject]@{
                        DeviceName = "Intel Smart Sound Technology USB Audio (Inactive)"
                        Driver = $driver.Driver
                        DriverVersion = $driver.Version
                        OriginalFileName = $driver.OriginalFileName
                        HardwareIds = $infHardwareIDs
                    }
                    $hardwareIDs += $infHardwareIDs
                }
            } catch {
                Write-Log "Error processing driver file $($driver.OriginalFileName): $_" -Type "ERROR"
            }
        }

        return @{
            Drivers = $intelAudioDrivers
            HardwareIDs = $hardwareIDs | Select-Object -Unique
        }
    }

    # Function to uninstall and remove driver
    function Remove-Driver {
        param (
            [Parameter(Mandatory=$true)]
            [PSCustomObject[]]$Drivers
        )
        
        foreach ($driverInfo in $Drivers) {
            try {
                # Remove the driver
                Write-Log "Removing driver: $($driverInfo.Driver)"
                pnputil /delete-driver $driverInfo.Driver /uninstall /force

                # Delete driver files with STRICT path validation
                # SECURITY: Multi-layer validation to prevent directory traversal and reparse point attacks
                $driverPath = Split-Path $driverInfo.OriginalFileName -Parent

                # Step 1: Canonicalize path using GetFullPath (handles ../ sequences, doesn't require path to exist)
                $canonicalPath = $null
                try {
                    $canonicalPath = [System.IO.Path]::GetFullPath($driverPath)
                } catch {
                    Write-Log "SECURITY: Path canonicalization failed for: $driverPath" -Type "FAIL"
                    throw "Invalid driver path - canonicalization failed"
                }

                # Step 2: Normalize the allowed base path
                $driverStoreBase = [System.IO.Path]::GetFullPath((Join-Path $env:SystemRoot "System32\DriverStore\FileRepository"))

                # Step 3: Strict prefix check (case-insensitive, handles trailing slashes)
                $normalizedCanonical = $canonicalPath.TrimEnd('\', '/')
                $normalizedBase = $driverStoreBase.TrimEnd('\', '/')
                if (-not $normalizedCanonical.StartsWith($normalizedBase + '\', [StringComparison]::OrdinalIgnoreCase) -and
                    -not $normalizedCanonical.Equals($normalizedBase, [StringComparison]::OrdinalIgnoreCase)) {
                    Write-Log "SECURITY: Refusing to delete path outside DriverStore" -Type "FAIL"
                    Write-Log "  Raw path: $driverPath" -Type "FAIL"
                    Write-Log "  Canonical: $canonicalPath" -Type "FAIL"
                    Write-Log "  Expected prefix: $driverStoreBase" -Type "FAIL"
                    throw "Invalid driver path - outside allowed directory"
                }

                # Step 4: Check if path exists before attempting deletion
                if (-not (Test-Path $canonicalPath)) {
                    Write-Log "Driver files not found at $canonicalPath (already removed)" -Type "WARNING"
                }
                else {
                    # Step 5: REPARSE POINT PROTECTION - check if target or any parent is a junction/symlink
                    $pathToCheck = $canonicalPath
                    $reparsePointDetected = $false
                    while ($pathToCheck -and $pathToCheck.Length -gt $normalizedBase.Length) {
                        if (Test-Path $pathToCheck) {
                            $item = Get-Item $pathToCheck -Force -ErrorAction SilentlyContinue
                            if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                                Write-Log "SECURITY: Reparse point detected in path: $pathToCheck" -Type "FAIL"
                                $reparsePointDetected = $true
                                break
                            }
                        }
                        $pathToCheck = Split-Path $pathToCheck -Parent
                    }

                    if ($reparsePointDetected) {
                        throw "Invalid driver path - contains reparse point (junction/symlink)"
                    }

                    # Step 6: Safe to delete
                    Remove-Item -Path $canonicalPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed driver files from $canonicalPath"
                }
            }
            catch {
                Write-Log "Failed to remove driver $($driverInfo.Driver). Error: $_" -Type "ERROR"
            }
        }
    }

    # Function to prevent driver reinstallation
    function Set-DriverReinstallationPrevention {
        param (
            [Parameter(Mandatory=$true)]
            [string[]]$HardwareIds
        )

        $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        $denyListPath = "$gpoPath\DenyDeviceIDs"

        try {
            # Create the DenyDeviceIDs key if it doesn't exist
            if (!(Test-Path $denyListPath)) {
                New-Item -Path $denyListPath -Force | Out-Null
            }

            # Add each Hardware ID as a separate value
            for ($i = 0; $i -lt $HardwareIds.Count; $i++) {
                New-ItemProperty -Path $denyListPath -Name $i -Value $HardwareIds[$i] -PropertyType String -Force | Out-Null
            }

            # Set the DenyDeviceIDsRetroactive value
            New-ItemProperty -Path $gpoPath -Name "DenyDeviceIDsRetroactive" -Value 1 -PropertyType DWORD -Force | Out-Null

            Write-Log "Driver reinstallation prevention measures applied for the following Hardware IDs:"
            $HardwareIds | ForEach-Object { Write-Log "  $_" }
        }
        catch {
            Write-Log "Failed to set driver reinstallation prevention. Error: $_" -Type "ERROR"
        }
    }

    # Function to block the specific driver using Group Policy
    function Block-SpecificDriver {
        param (
            [Parameter(Mandatory=$true)]
            [string[]]$HardwareIds
        )

        try {
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
            if (!(Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }

            Set-ItemProperty -Path $policyPath -Name "DenyDeviceIDs" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $policyPath -Name "DenyDeviceIDsRetroactive" -Value 1 -Type DWord -Force

            $denyListPath = "$policyPath\DenyDeviceIDs"
            if (!(Test-Path $denyListPath)) {
                New-Item -Path $denyListPath -Force | Out-Null
            }

            for ($i = 0; $i -lt $HardwareIds.Count; $i++) {
                New-ItemProperty -Path $denyListPath -Name $i -Value $HardwareIds[$i] -PropertyType String -Force | Out-Null
            }

            Write-Log "Blocked specific driver installation using Group Policy for the following Hardware IDs:"
            $HardwareIds | ForEach-Object { Write-Log "  $_" }
        }
        catch {
            Write-Log "Failed to block specific driver with Group Policy. Error: $_" -Type "ERROR"
        }
    }

    # Function to exclude the specific driver from Windows Update
    function Block-DriverFromWindowsUpdate {
        param (
            [Parameter(Mandatory=$true)]
            [string[]]$HardwareIds
        )

        try {
            $updatePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            if (!(Test-Path $updatePolicyPath)) {
                New-Item -Path $updatePolicyPath -Force | Out-Null
            }

            # Convert hardware IDs to the format expected by Windows Update
            $excludedIds = $HardwareIds | ForEach-Object { $_.Replace("\", "#") }
            $excludedIdsString = $excludedIds -join ";"

            # Set the policy to exclude these specific drivers
            Set-ItemProperty -Path $updatePolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $updatePolicyPath -Name "PauseFeatureUpdates" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $updatePolicyPath -Name "PauseQualityUpdates" -Value 0 -Type DWord -Force
            New-ItemProperty -Path $updatePolicyPath -Name "ExcludeWUDriversInQualityUpdateForDevices" -Value $excludedIdsString -PropertyType String -Force

            Write-Log "Excluded specific driver from Windows Update for the following Hardware IDs:"
            $excludedIds | ForEach-Object { Write-Log "  $_" }
        }
        catch {
            Write-Log "Failed to exclude driver from Windows Update. Error: $_" -Type "ERROR"
        }
    }

    # Main script execution
    try {
        Write-Log "Script started."

        # Find the drivers and hardware IDs
        $result = Find-IntelAudioDrivers
        $intelAudioDrivers = $result.Drivers
        $allHardwareIds = $result.HardwareIDs

        # List found drivers and show hardware IDs
        if ($intelAudioDrivers.Count -eq 0) {
            Write-Log "No Intel Smart Sound Technology USB Audio drivers found to remove. Verify if it exists in Device Manager. If you still have issues removing the driver, close this window and try the manual steps in SUP-368" -Type "WARNING"
            return
        }
        else {
            Write-Log "Found the following Intel Smart Sound Technology USB Audio drivers:"
            foreach ($driverInfo in $intelAudioDrivers) {
                Write-Log "  $($driverInfo.DeviceName) - $($driverInfo.Driver) - Version: $($driverInfo.DriverVersion)"
            }
            
            if ($allHardwareIds) {
                Write-Log "`nThe following Hardware IDs will be used to block reinstallation:"
                $allHardwareIds | ForEach-Object { Write-Log "  $_" }
            } else {
                Write-Log "`nNo Hardware IDs found to prevent reinstallation." -Type "WARNING"
            }

            $confirmation = [System.Windows.Forms.MessageBox]::Show(
                "Do you want to proceed with uninstalling these drivers and blocking reinstallation?",
                "Confirm Driver Removal",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )

            if ($confirmation -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Operation cancelled by user." -Type "WARNING"
                return
            }
        }

        # SAFETY: Create backups BEFORE any driver mutations
        # Strategy: Restore point (primary) + Driver export (fallback)
        $hasRestorePoint = $false
        $hasDriverBackup = $false
        $driverBackupPath = $null

        # Step 1: Try to create system restore point
        Write-Log "Creating system restore point before driver removal..."
        $restoreResult = New-WinConfigSafetyRestorePoint -Description "Before Intel SST Audio Driver Removal"
        if ($restoreResult.Success) {
            if ($restoreResult.Throttled) {
                Write-Log "Restore point was throttled (recent restore point exists)" -Type "WARNING"
                $hasRestorePoint = $true  # A recent one exists
            } else {
                Write-Log "Restore point created successfully"
                $hasRestorePoint = $true
            }
        } else {
            Write-Log "Could not create restore point: $($restoreResult.Error)" -Type "WARNING"
        }

        # Step 2: Export drivers as additional backup (always try, even if restore point succeeded)
        $driverNames = $intelAudioDrivers | ForEach-Object { $_.Driver }
        if ($driverNames.Count -gt 0) {
            Write-Log "Exporting driver packages as backup..."
            $exportResult = Export-WinConfigDriverBackup -DriverNames $driverNames
            if ($exportResult.Success) {
                Write-Log "Drivers exported to: $($exportResult.BackupPath)"
                $hasDriverBackup = $true
                $driverBackupPath = $exportResult.BackupPath
            } else {
                Write-Log "Driver export failed: $($exportResult.Error)" -Type "WARNING"
            }
        }

        # Step 3: If neither backup method worked, require explicit acknowledgment
        if (-not $hasRestorePoint -and -not $hasDriverBackup) {
            Write-Log "NO ROLLBACK PATH AVAILABLE - both restore point and driver export failed" -Type "FAIL"
            $proceedWithoutRollback = [System.Windows.Forms.MessageBox]::Show(
                "WARNING: No rollback path available!`n`n" +
                "- Restore point: $($restoreResult.Error)`n" +
                "- Driver export: $($exportResult.Error)`n`n" +
                "If something goes wrong, you may need to reinstall Windows or manually restore drivers.`n`n" +
                "Proceed anyway? (NOT RECOMMENDED)",
                "No Rollback Path - Data Loss Risk",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Exclamation
            )
            if ($proceedWithoutRollback -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Operation cancelled - no rollback path available." -Type "WARNING"
                return
            }
            Write-Log "User acknowledged proceeding without rollback path" -Type "WARNING"
        } elseif ($hasDriverBackup -and -not $hasRestorePoint) {
            # Only driver backup - inform user
            [System.Windows.Forms.MessageBox]::Show(
                "System restore point could not be created, but drivers have been exported to:`n$driverBackupPath`n`nYou can reinstall from this backup if needed.",
                "Driver Backup Created",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        }

        # SAFETY: Final audit check before irreversible driver mutations
        if (-not (Assert-AuditTrailHealthyForMutation)) {
            Write-Log "Operation blocked - audit trail failure detected" -Type "FAIL"
            return
        }

        # Remove the drivers
        Remove-Driver -Drivers $intelAudioDrivers

        # Prevent driver reinstallation
        if ($allHardwareIds) {
            Block-SpecificDriver -HardwareIds $allHardwareIds
            Block-DriverFromWindowsUpdate -HardwareIds $allHardwareIds
        } else {
            Write-Log "No Hardware IDs available to prevent reinstallation." -Type "WARNING"
        }

        Write-Log "Script execution completed. A system restart is recommended for changes to take full effect."

        # SAFETY: Check for other logged-in users before reboot
        $safetyCheck = Test-WinConfigSafeToReboot
        if (-not $safetyCheck.Safe) {
            $multiUserWarning = [System.Windows.Forms.MessageBox]::Show(
                "WARNING: $($safetyCheck.Reason)`n`nRebooting now may cause data loss for other users.`n`nProceed anyway?",
                "Multi-User Warning",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Exclamation
            )
            if ($multiUserWarning -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Reboot cancelled due to other active sessions." -Type "WARNING"
                return
            }
        }

        $restart = [System.Windows.Forms.MessageBox]::Show(
            "Do you want to restart now?",
            "Restart Required",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($restart -eq [System.Windows.Forms.DialogResult]::Yes) {
            # SAFETY: Final audit check before reboot
            if (-not (Assert-AuditTrailHealthyForMutation)) {
                Write-Log "Reboot blocked - audit trail failure detected" -Type "FAIL"
                return
            }
            Restart-Computer
        }
    }
    catch {
        Write-Log "An unexpected error occurred: $_" -Type "ERROR"
    }
}

# =============================================================================
# BLUETOOTH GHOST-PORT TARGET PLAN
# =============================================================================
# Get-BluetoothGhostPortPlan lives in BluetoothDeviceProbe.psm1, which is an
# OPTIONAL module loaded lazily when the recorder panel opens. The repair
# buttons can be pressed without ever opening that panel, so resolve it here.
#
# This FAILS CLOSED. There is deliberately no local copy of the ghost predicate
# to fall back on: a fallback would be a second answerer for "what gets
# deleted", which is the exact divergence this function was extracted to end.

function Get-BtGhostPortPlanOrThrow {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not (Get-Command Get-BluetoothGhostPortPlan -ErrorAction SilentlyContinue)) {
        # $PSScriptRoot can be empty when this runs outside a script file. Guard
        # the path build: an unguarded Join-Path fails with a parameter-binding
        # error, which still fails closed but hides the reason from the tech.
        $bdpPath = if ($PSScriptRoot) { Join-Path $PSScriptRoot "Modules\BluetoothDeviceProbe.psm1" } else { $null }
        if ($bdpPath -and (Test-Path $bdpPath)) {
            try { Import-Module $bdpPath -Force -DisableNameChecking -ErrorAction Stop } catch { }
        }
    }
    if (-not (Get-Command Get-BluetoothGhostPortPlan -ErrorAction SilentlyContinue)) {
        throw "Cannot determine which Bluetooth ports would be removed: BluetoothDeviceProbe.psm1 did not provide Get-BluetoothGhostPortPlan. Refusing to remove anything on a guess."
    }

    $devices = @(Get-PnpDevice -Class Ports -ErrorAction Stop)
    return (Get-BluetoothGhostPortPlan -PortDevices $devices)
}

# =============================================================================
# SESSION LEDGER INSTRUMENTATION HELPER
# =============================================================================
# Wrapper function that ensures operations are recorded BEFORE execution.
# If recording fails, the operation is NOT executed (fail-closed).

function Invoke-InstrumentedAction {
    <#
    .SYNOPSIS
        Wraps an action with automatic session ledger recording.
    .DESCRIPTION
        Records the operation start BEFORE executing the scriptblock.
        If recording fails, the operation is NOT executed (fail-closed).
        After execution, completes the operation with the result.
    .PARAMETER Name
        Human-readable name of the operation
    .PARAMETER Source
        Source identifier (e.g., "Button:DISM")
    .PARAMETER Category
        Network | System | Audio | Bluetooth | Maintenance | Other
    .PARAMETER OperationType
        Test | Action | ExternalTool | UI
    .PARAMETER MutatesSystem
        Whether this action changes system state
    .PARAMETER Script
        The scriptblock to execute
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Network", "System", "Audio", "Bluetooth", "Maintenance", "Support", "Other")]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Test", "Action", "ExternalTool", "UI")]
        [string]$OperationType,

        [Parameter(Mandatory = $true)]
        [bool]$MutatesSystem,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Script
    )

    # Check if ledger is available
    $ledgerAvailable = Get-Command Start-WinConfigSessionOperation -ErrorAction SilentlyContinue

    $opId = $null
    if ($ledgerAvailable) {
        # CRITICAL: Record BEFORE execute - throws on failure, aborting operation
        $opId = Start-WinConfigSessionOperation `
            -Category $Category `
            -OperationType $OperationType `
            -Name $Name `
            -Source $Source `
            -MutatesSystem $MutatesSystem
        # If we reach here, operation was recorded successfully
    }

    $result = "Success"
    $summary = ""
    $evidence = @{}

    try {
        $output = & $Script

        # Attempt to extract result from output if it's a result object
        if ($output -is [hashtable]) {
            if ($output.Success -eq $false) { $result = "Failed" }
            elseif ($output.Warning -eq $true) { $result = "Warning" }
            if ($output.Message) { $summary = $output.Message }
            if ($output.Summary) { $summary = $output.Summary }
            if ($output.Evidence -and $output.Evidence -is [hashtable]) { $evidence = $output.Evidence }
        }
        elseif ($output -is [PSCustomObject]) {
            if ($output.PSObject.Properties['Success'] -and $output.Success -eq $false) { $result = "Failed" }
            elseif ($output.PSObject.Properties['Warning'] -and $output.Warning -eq $true) { $result = "Warning" }
            if ($output.PSObject.Properties['Message']) { $summary = $output.Message }
            if ($output.PSObject.Properties['Summary']) { $summary = $output.Summary }
        }
    }
    catch {
        $result = "Failed"
        $summary = $_.Exception.Message
    }

    # Complete operation in ledger
    if ($opId -and $ledgerAvailable) {
        Complete-WinConfigSessionOperation `
            -OperationId $opId `
            -Result $result `
            -Summary $summary `
            -Evidence $evidence
    }

    return $output
}

# =============================================================================
# ZAMP TRUST-REPAIR DIAGNOSTIC REPORT (ZAMP-TRUST-REPAIR-001 §6)
# =============================================================================
# One builder feeds both operator and analytics channels. Defined at script
# scope as scriptblocks so BOTH the dry-run PLAN generator (invoked across the
# DryRun module boundary) and the EXECUTE button handler resolve the same code.
# The builder is pure (no side effects); delivery to clipboard/file happens only
# on the EXECUTE path, so PLAN stays read-only per TOOL_AUTHORING_PROTOCOL.
$script:BuildZampRepairReport = {
    param([hashtable]$Ctx)

    # Cap an array and append an explicit truncation marker (never truncate silently).
    function _capArray { param($Items, [int]$Max, [string]$Noun)
        $a = @($Items)
        if ($a.Count -le $Max) { return $a }
        return @($a[0..($Max - 1)]) + @("...truncated ($($a.Count - $Max) more $Noun)")
    }

    $now = Get-Date
    $osBuild = $null
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.CurrentBuildNumber) { $osBuild = "$($cv.CurrentBuildNumber).$([int]$cv.UBR)" }
    } catch { }
    if (-not $osBuild) { $osBuild = [System.Environment]::OSVersion.Version.ToString() }

    # pnputil entries carry both decimal and hex exit codes (KI-001 triage need).
    $pnputil = @()
    foreach ($p in @($Ctx.Pnputil)) {
        if (-not $p) { continue }
        $exitVal = [int]$p.exit
        $pnputil += [ordered]@{
            inf        = $p.inf
            exit       = $exitVal
            exitHex    = ('0x{0:X8}' -f $exitVal)
            outputTail = @(_capArray $p.outputTail 15 "lines")
        }
    }

    $report = [ordered]@{
        report        = "ZAMP-REPAIR"
        v             = 1
        ts            = $now.ToString("yyyy-MM-ddTHH:mm:sszzz")
        computer      = $env:COMPUTERNAME
        osBuild       = $osBuild
        toolId        = "zamp-driver-trust-repair"
        mode          = $Ctx.Mode
        elevated      = [bool]$Ctx.Elevated
        outcome       = $Ctx.Outcome
        preconditions = [ordered]@{
            admin            = [bool]$Ctx.Admin
            loaderDirPresent = [bool]$Ctx.LoaderDirPresent
        }
        findings      = [ordered]@{
            deviceBefore           = @(_capArray $Ctx.DeviceBefore 8 "instances")
            catalogSignatures      = $Ctx.CatalogSignatures
            embeddedCerts          = @($Ctx.EmbeddedCerts)
            chainBuildsBefore      = [bool]$Ctx.ChainBuildsBefore
            chainStatus            = @($Ctx.ChainStatus)
            leafInTrustedPublisher = [bool]$Ctx.LeafInTrustedPublisher
            rootE46InRoot          = [bool]$Ctx.RootE46InRoot
            staged                 = $Ctx.Staged
            bundledRoot            = $Ctx.BundledRoot
        }
        actions       = [ordered]@{
            certsAdded       = @($Ctx.CertsAdded)
            chainBuildsAfter = $Ctx.ChainBuildsAfter
        }
        pnputil        = $pnputil
        setupapiTail   = @(if ($Ctx.SetupapiTail) { _capArray $Ctx.SetupapiTail 40 "lines" } else { @() })
        deviceAfter    = @(_capArray $Ctx.DeviceAfter 8 "instances")
        rebootRequired = [bool]$Ctx.RebootRequired
        operatorAction = $(if ($Ctx.OperatorAction) { $Ctx.OperatorAction } else { "none" })
        errors         = @($Ctx.Errors)
    }
    return [PSCustomObject]$report
}

# Wrap a report object in the fixed BEGIN/END markers around its JSON form.
$script:ConvertZampReportToBlock = {
    param($Report)
    $json = $Report | ConvertTo-Json -Depth 12
    return "----- BEGIN ZAMP-REPAIR REPORT v1 -----`r`n$json`r`n----- END ZAMP-REPAIR REPORT -----"
}

# Persist the report JSON to ProgramData (fallback: user temp). Returns path or $null.
$script:SaveZampRepairReportFile = {
    param([string]$Json, [string]$Stamp)
    $name = "zamp-repair-report-$Stamp.json"
    $targets = @(
        (Join-Path (Join-Path $env:ProgramData "Zengar\WinConfig") $name),
        (Join-Path $env:TEMP $name)
    )
    foreach ($target in $targets) {
        try {
            $dir = Split-Path $target -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [System.IO.File]::WriteAllText($target, $Json)
            return $target
        } catch { }
    }
    return $null
}

# Filtered tail of setupapi.dev.log for lines written after $Since (best-effort
# section-start scoping), matching sig:/VID_1167/zamp. Captured only on pnputil
# failure — the artifact that revealed the Authenticode-fallback mechanism.
$script:GetZampSetupapiTail = {
    param([datetime]$Since, [int]$Max = 40)
    $log = Join-Path $env:SystemRoot "INF\setupapi.dev.log"
    if (-not (Test-Path $log)) { return @("setupapi.dev.log not found") }
    try {
        $lines = @(Get-Content -LiteralPath $log -Tail 4000 -ErrorAction Stop)
    } catch {
        return @("setupapi.dev.log unreadable: $($_.Exception.Message)")
    }
    $startIdx = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})') {
            $t = [datetime]::MinValue
            if ([datetime]::TryParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$t)) {
                if ($t -ge $Since) { $startIdx = $i; break }
            }
        }
    }
    $scoped = @($lines[$startIdx..($lines.Count - 1)])
    $filtered = @($scoped | Where-Object { $_ -match '(?i)sig:|VID_1167|zamp' })
    if ($filtered.Count -eq 0) { return @("(no matching setupapi lines after run start)") }
    if ($filtered.Count -le $Max) { return $filtered }
    return @($filtered[0..($Max - 1)]) + @("...truncated ($($filtered.Count - $Max) more lines)")
}

# Button event handlers
# PERF-001: Use Get-WinConfigMachineInfo for cached CIM queries (no repeated WMI calls)
$buttonHandlers = @{
    "Copy System Info" = {
        $machineInfo = Get-WinConfigMachineInfo
        $clipboardText = "Device Name: $($machineInfo.DeviceName)`nSerial Number: $($machineInfo.SerialNumber)`nOS: $($machineInfo.FormattedVersion)"
        [System.Windows.Forms.Clipboard]::SetText($clipboardText)

        $infoMessage = "The following Device Information was copied to the clipboard:`n`nDevice Name: $($machineInfo.DeviceName)`nSerial Number: $($machineInfo.SerialNumber)`nOS: $($machineInfo.FormattedVersion)"
        [System.Windows.Forms.MessageBox]::Show($infoMessage, "Device Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Copy Device Name" = {
        $machineInfo = Get-WinConfigMachineInfo
        [System.Windows.Forms.Clipboard]::SetText($machineInfo.DeviceName)
        [System.Windows.Forms.MessageBox]::Show("Device Name copied to clipboard: $($machineInfo.DeviceName)", "Device Name", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Copy Serial Number" = {
        $machineInfo = Get-WinConfigMachineInfo
        [System.Windows.Forms.Clipboard]::SetText($machineInfo.SerialNumber)
        [System.Windows.Forms.MessageBox]::Show("Serial Number copied to clipboard: $($machineInfo.SerialNumber)", "Serial Number", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Copy Windows version" = {
        $machineInfo = Get-WinConfigMachineInfo
        [System.Windows.Forms.Clipboard]::SetText($machineInfo.FormattedVersion)
        [System.Windows.Forms.MessageBox]::Show("Windows version copied to clipboard: $($machineInfo.FormattedVersion)", "Windows Version", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Machine Identifiers" = {
        # Shows the same three values the Zengar licensing app fingerprints the
        # machine with - MAC Addresses, ProcessorID, DiskID - read from the same
        # WMI sources, plus the cause when one of them is missing or fragile.
        # All logic lives in MachineIdentifiers.psm1; this handler owns only UI.
        # Read-only: nothing here mutates, so there is no dry-run path.
        if (-not (Get-Command Get-WinConfigMachineIdentifiers -ErrorAction SilentlyContinue)) {
            $miModulePath = Join-Path $PSScriptRoot "Modules\MachineIdentifiers.psm1"
            if (Test-Path $miModulePath) {
                try {
                    Import-Module $miModulePath -Force -Global -ErrorAction Stop
                } catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to load the machine identifiers module:`n$($_.Exception.Message)",
                        "Module Load Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    ) | Out-Null
                    return
                }
            }
        }
        if (-not (Get-Command Get-WinConfigMachineIdentifiers -ErrorAction SilentlyContinue)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Machine identifiers module not found. This is unexpected for a bootstrap install - please re-run the bootstrap command to repair.",
                "Module Not Available",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        $miForm = New-Object System.Windows.Forms.Form
        $miForm.Text = "Machine Identifiers"
        $miForm.StartPosition = "CenterScreen"
        $miForm.Font = New-Object System.Drawing.Font('Segoe UI', 10)
        $miForm.Size = New-Object System.Drawing.Size(780, 660)
        $miForm.MinimumSize = New-Object System.Drawing.Size(620, 480)

        # --- Identifier panel: mirrors the licensing app's layout so the tech can
        # --- compare the two screens value-for-value without translating fields.
        $miGroup = New-Object System.Windows.Forms.GroupBox
        $miGroup.Text = "Machine Identifiers"
        $miGroup.Dock = [System.Windows.Forms.DockStyle]::Top
        $miGroup.Height = 300
        $miGroup.Padding = New-Object System.Windows.Forms.Padding(10)

        $miFields = New-Object System.Windows.Forms.FlowLayoutPanel
        $miFields.Dock = [System.Windows.Forms.DockStyle]::Fill
        $miFields.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $miFields.WrapContents = $false
        $miFields.AutoScroll = $true
        $miGroup.Controls.Add($miFields)

        $miMonoFont = New-Object System.Drawing.Font('Consolas', 10)

        $miMacLabel = New-Object System.Windows.Forms.Label
        $miMacLabel.Text = "MAC Addresses"
        $miMacLabel.AutoSize = $true
        $miMacLabel.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 2)
        $miFields.Controls.Add($miMacLabel)

        # Value display fields (not diagnostic output) - $txtValue naming per the
        # console-wrapper contract exemption for value fields.
        $txtValueMacAddresses = New-Object System.Windows.Forms.TextBox
        $txtValueMacAddresses.Multiline = $true
        $txtValueMacAddresses.ReadOnly = $true
        $txtValueMacAddresses.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        $txtValueMacAddresses.Width = 560
        $txtValueMacAddresses.Height = 96
        $txtValueMacAddresses.Font = $miMonoFont
        $txtValueMacAddresses.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
        $txtValueMacAddresses.Text = "Reading..."
        $miFields.Controls.Add($txtValueMacAddresses)

        $miProcLabel = New-Object System.Windows.Forms.Label
        $miProcLabel.Text = "ProcessorID"
        $miProcLabel.AutoSize = $true
        $miProcLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
        $miFields.Controls.Add($miProcLabel)

        $txtValueProcessorId = New-Object System.Windows.Forms.TextBox
        $txtValueProcessorId.ReadOnly = $true
        $txtValueProcessorId.Width = 560
        $txtValueProcessorId.Font = $miMonoFont
        $txtValueProcessorId.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
        $txtValueProcessorId.Text = "Reading..."
        $miFields.Controls.Add($txtValueProcessorId)

        $miDiskLabel = New-Object System.Windows.Forms.Label
        $miDiskLabel.Text = "DiskID"
        $miDiskLabel.AutoSize = $true
        $miDiskLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
        $miFields.Controls.Add($miDiskLabel)

        $txtValueDiskId = New-Object System.Windows.Forms.TextBox
        $txtValueDiskId.ReadOnly = $true
        $txtValueDiskId.Width = 560
        $txtValueDiskId.Font = $miMonoFont
        $txtValueDiskId.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)
        $txtValueDiskId.Text = "Reading..."
        $miFields.Controls.Add($txtValueDiskId)

        $miStatusLabel = New-Object System.Windows.Forms.Label
        $miStatusLabel.Dock = [System.Windows.Forms.DockStyle]::Top
        $miStatusLabel.Height = 30
        $miStatusLabel.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 0)
        $miStatusLabel.Text = "Reading machine identifiers..."

        $miLog = New-Object System.Windows.Forms.RichTextBox
        $miLog.Dock = [System.Windows.Forms.DockStyle]::Fill
        Initialize-WinConfigGuiDiagnosticBox -Box $miLog
        $miLog.Font = New-Object System.Drawing.Font('Consolas', 9)

        $miButtonRow = New-Object System.Windows.Forms.FlowLayoutPanel
        $miButtonRow.Dock = [System.Windows.Forms.DockStyle]::Bottom
        $miButtonRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $miButtonRow.AutoSize = $true
        $miButtonRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $miButtonRow.Padding = New-Object System.Windows.Forms.Padding(8)

        $miCloseBtn = New-Object System.Windows.Forms.Button
        $miCloseBtn.Text = "Close"
        $miCloseBtn.AutoSize = $true
        $miCloseBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
        # EXEMPT-CONTRACT-001: dialog-local window control, no diagnostic work to wrap
        $miCloseBtn.Add_Click({ $this.FindForm().Close() })
        $miButtonRow.Controls.Add($miCloseBtn)

        $miCopyBtn = New-Object System.Windows.Forms.Button
        $miCopyBtn.Text = "Copy Report"
        $miCopyBtn.AutoSize = $true
        $miCopyBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
        $miCopyBtn.Enabled = $false
        $miButtonRow.Controls.Add($miCopyBtn)

        # Fill first, then Top, then Bottom - WinForms resolves docking in reverse
        # add order, so this is the order that leaves the log filling the middle.
        $miForm.Controls.Add($miLog)
        $miForm.Controls.Add($miGroup)
        $miForm.Controls.Add($miStatusLabel)
        $miForm.Controls.Add($miButtonRow)
        $miForm.Show()
        [System.Windows.Forms.Application]::DoEvents()

        $miIds = $null
        try {
            $miIds = Get-WinConfigMachineIdentifiers
        } catch {
            Write-WinConfigGuiDiagnostic -Level FAIL -Message "Identifier collection failed: $($_.Exception.Message)" -Box $miLog
            $miStatusLabel.Text = "Collection failed - see the log below."
            return
        }

        $miMacValues = @($miIds.MacAddresses.Values)
        $txtValueMacAddresses.Lines = $(if ($miMacValues.Count -gt 0) { $miMacValues } else { @("(none - see findings below)") })
        $txtValueProcessorId.Text = $(if ($miIds.ProcessorId.Value) { $miIds.ProcessorId.Value } else { "(empty - see findings below)" })
        $txtValueDiskId.Text = $(if ($miIds.DiskId.Value) { $miIds.DiskId.Value } else { "(empty - see findings below)" })

        Write-WinConfigGuiDiagnostic -Level STEP -Message "Sources read by the licensing app" -Box $miLog
        Write-WinConfigGuiDiagnostic -Level DIM -Message "MAC Addresses : Win32_NetworkAdapter (physical adapters only)" -Box $miLog
        Write-WinConfigGuiDiagnostic -Level DIM -Message "ProcessorID   : Win32_Processor.ProcessorId" -Box $miLog
        Write-WinConfigGuiDiagnostic -Level DIM -Message "DiskID        : $(if ($miIds.DiskId.Source) { $miIds.DiskId.Source } else { 'Win32_DiskDrive.SerialNumber (Index 0)' })" -Box $miLog

        # Adapters Windows reports but licensing ignores. Without this list the
        # count mismatch against ipconfig looks like a bug in one of the tools.
        $miExcluded = @($miIds.MacAddresses.Adapters | Where-Object { -not $_.Included })
        if ($miExcluded.Count -gt 0) {
            Write-WinConfigGuiDiagnostic -Level STEP -Message "Adapters excluded from the licensing view ($($miExcluded.Count))" -Box $miLog
            foreach ($miAdapter in $miExcluded) {
                Write-WinConfigGuiDiagnostic -Level DIM -Message "$($miAdapter.Address)  $($miAdapter.Name) - $($miAdapter.ExcludedReason)" -Box $miLog
            }
        }

        $miFindings = @($miIds.Findings)
        $miFailures = @($miFindings | Where-Object { $_.Severity -eq 'Fail' })
        $miWarnings = @($miFindings | Where-Object { $_.Severity -eq 'Warn' })

        # Severity -> console level by lookup, not by branching: the branching ban
        # (DiagnosticResult.BranchingBan.Tests.ps1) covers .Severity, and a map
        # fails closed to INFO on an unknown severity instead of throwing inside
        # the handler on Write-WinConfigGuiDiagnostic's -Level ValidateSet.
        $miLevelMap = @{ 'Fail' = 'FAIL'; 'Warn' = 'WARN'; 'Info' = 'INFO' }
        if ($miFindings.Count -gt 0) {
            Write-WinConfigGuiDiagnostic -Level STEP -Message "Findings" -Box $miLog
            foreach ($miFinding in $miFindings) {
                $miLevel = $miLevelMap[[string]$miFinding.Severity]
                if (-not $miLevel) { $miLevel = 'INFO' }
                Write-WinConfigGuiDiagnostic -Level $miLevel -Message "$($miFinding.Identifier): $($miFinding.Title)" -Box $miLog
                Write-WinConfigGuiDiagnostic -Level DIM -Message "    Cause: $($miFinding.Cause)" -Box $miLog
                Write-WinConfigGuiDiagnostic -Level ACTION -Message "    Fix:   $($miFinding.Fix)" -Box $miLog
            }
        }

        if ($miFailures.Count -gt 0) {
            $miStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 50, 50)
            $miStatusLabel.Text = "$($miFailures.Count) identifier problem(s) found - licensing will not read this machine correctly."
        } elseif ($miWarnings.Count -gt 0) {
            $miStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 20)
            $miStatusLabel.Text = "All three identifiers were read, but $($miWarnings.Count) of them are unstable - see findings."
        } else {
            $miStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(40, 120, 40)
            $miStatusLabel.Text = "All three identifiers read successfully."
        }

        $miReport = Format-WinConfigMachineIdentifierReport -Identifiers $miIds
        $miCopyBtn.Tag = $miReport
        $miCopyBtn.Enabled = $true
        # EXEMPT-CONTRACT-001: clipboard copy of an already-rendered report, no diagnostic work to wrap
        $miCopyBtn.Add_Click({
            try {
                [System.Windows.Forms.Clipboard]::SetText([string]$this.Tag)
                $this.Text = "Copied"
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Clipboard copy failed: $($_.Exception.Message)",
                    "Copy Failed",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
        })

        if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
            $miResult = if ($miFailures.Count -gt 0) { "Warning" } else { "Success" }
            $miSummary = "MAC: $($miMacValues.Count) licensed adapter(s); ProcessorID: $($miIds.ProcessorId.Status); DiskID: $($miIds.DiskId.Status)"
            try {
                Write-WinConfigSessionOperation -Category "System" -OperationType "Test" `
                    -Name "Machine Identifiers" -Source "Button:MachineIdentifiers" -MutatesSystem $false `
                    -Result $miResult -Summary $miSummary
            } catch {
                # Bookkeeping must never take down a completed read.
                Write-WinConfigGuiDiagnostic -Level WARN -Message "Session ledger write failed: $($_.Exception.Message)" -Box $miLog
            }
        }
    }
    "Collect Support Bundle" = {
        # SUPPORT-PROBE-001: read-only escalation collector. All collection logic
        # lives in SupportBundle.psm1; this handler owns only UI + upload wiring.
        if (-not (Get-Command Initialize-WinConfigGuiDiagnosticBox -ErrorAction SilentlyContinue)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Collect Support Bundle cannot start: Console module failed to load.",
                "Module Load Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }
        if ($script:SupportBundleActive) {
            [System.Windows.Forms.MessageBox]::Show(
                "A support bundle collection is already running.",
                "Collection In Progress",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }

        # Locate bundle module: bundled copy (mirrors the Bluetooth probe pattern)
        if (-not (Get-Command New-WinConfigSupportBundle -ErrorAction SilentlyContinue)) {
            $sbModulePath = Join-Path $PSScriptRoot "Modules\SupportBundle.psm1"
            if (Test-Path $sbModulePath) {
                try {
                    Import-Module $sbModulePath -Force -Global -ErrorAction Stop
                } catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to load support bundle module:`n$($_.Exception.Message)",
                        "Module Load Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    ) | Out-Null
                    return
                }
            }
        }
        if (-not (Get-Command New-WinConfigSupportBundle -ErrorAction SilentlyContinue)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Support bundle module not found. This is unexpected for a bootstrap install - please re-run the bootstrap command to repair.",
                "Module Not Available",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        # --- Case ID prompt: pre-filled, never blocking (§12.5) ---
        # Pre-fill must identify the machine to support staff with zero typing:
        # hostname + model + BIOS serial + date (Get-WinConfigSupportCaseIdPrefill).
        # A stale module copy without the function degrades to hostname-date.
        $sbCasePrefill = ''
        if (Get-Command Get-WinConfigSupportCaseIdPrefill -ErrorAction SilentlyContinue) {
            try { $sbCasePrefill = Get-WinConfigSupportCaseIdPrefill } catch { $sbCasePrefill = '' }
        }
        if (-not $sbCasePrefill) {
            $sbCasePrefill = "$($env:COMPUTERNAME)-$([datetime]::Now.ToString('yyyyMMdd'))"
        }

        # AutoSize flow layout throughout — fixed pixel positions clip on
        # DPI-scaled displays (AutoScaleMode is a no-op for code-built forms)
        $caseForm = New-Object System.Windows.Forms.Form
        $caseForm.Text = "Collect Support Bundle"
        $caseForm.StartPosition = "CenterScreen"
        $caseForm.FormBorderStyle = "FixedDialog"
        $caseForm.MaximizeBox = $false
        $caseForm.MinimizeBox = $false
        $caseForm.Font = New-Object System.Drawing.Font('Segoe UI', 10)
        $caseForm.AutoSize = $true
        $caseForm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

        $casePanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $casePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $casePanel.WrapContents = $false
        $casePanel.AutoSize = $true
        $casePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $casePanel.Padding = New-Object System.Windows.Forms.Padding(12)
        $caseForm.Controls.Add($casePanel)

        $caseLabel = New-Object System.Windows.Forms.Label
        $caseLabel.Text = "Case / ticket number (pre-filled value works fine):"
        $caseLabel.AutoSize = $true
        $caseLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
        $casePanel.Controls.Add($caseLabel)

        # Value input field (not diagnostic output) — $txtValue naming per the
        # console-wrapper contract exemption for value fields
        $txtValueCaseId = New-Object System.Windows.Forms.TextBox
        $txtValueCaseId.Width = 440
        $txtValueCaseId.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
        $txtValueCaseId.Text = $sbCasePrefill
        $casePanel.Controls.Add($txtValueCaseId)

        $caseButtonRow = New-Object System.Windows.Forms.FlowLayoutPanel
        $caseButtonRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $caseButtonRow.AutoSize = $true
        $caseButtonRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $caseButtonRow.Margin = New-Object System.Windows.Forms.Padding(0)
        $casePanel.Controls.Add($caseButtonRow)

        $caseOk = New-Object System.Windows.Forms.Button
        $caseOk.Text = "Start Collection"
        $caseOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $caseOk.AutoSize = $true
        $caseOk.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
        $caseButtonRow.Controls.Add($caseOk)
        $caseForm.AcceptButton = $caseOk

        $caseCancel = New-Object System.Windows.Forms.Button
        $caseCancel.Text = "Cancel"
        $caseCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $caseCancel.AutoSize = $true
        $caseCancel.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
        $caseButtonRow.Controls.Add($caseCancel)
        $caseForm.CancelButton = $caseCancel

        if ($caseForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            $caseForm.Dispose()
            return
        }
        $sbCaseId = $txtValueCaseId.Text
        $caseForm.Dispose()

        $script:SupportBundleActive = $true
        try {
            # --- Progress window ---
            $sbForm = New-Object System.Windows.Forms.Form
            $sbForm.Text = "Collect Support Bundle"
            $sbForm.StartPosition = "CenterScreen"
            $sbForm.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $sbForm.Size = New-Object System.Drawing.Size(720, 540)
            $sbForm.MinimumSize = New-Object System.Drawing.Size(560, 400)
            $sbForm.ControlBox = $false   # no closing mid-collection; Close enables at the end

            $sbStatusLabel = New-Object System.Windows.Forms.Label
            $sbStatusLabel.Dock = [System.Windows.Forms.DockStyle]::Top
            $sbStatusLabel.Height = 34
            $sbStatusLabel.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 0)
            $sbStatusLabel.Text = "Starting collection..."

            $sbLog = New-Object System.Windows.Forms.RichTextBox
            $sbLog.Dock = [System.Windows.Forms.DockStyle]::Fill
            Initialize-WinConfigGuiDiagnosticBox -Box $sbLog
            $sbLog.Font = New-Object System.Drawing.Font('Consolas', 10)

            $sbButtonRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $sbButtonRow.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $sbButtonRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $sbButtonRow.AutoSize = $true
            $sbButtonRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $sbButtonRow.Padding = New-Object System.Windows.Forms.Padding(8)

            $sbCloseBtn = New-Object System.Windows.Forms.Button
            $sbCloseBtn.Text = "Close"
            $sbCloseBtn.AutoSize = $true
            $sbCloseBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $sbCloseBtn.Enabled = $false
            $sbCloseBtn.Add_Click({ $this.FindForm().Close() })
            $sbButtonRow.Controls.Add($sbCloseBtn)

            $sbOpenFolderBtn = New-Object System.Windows.Forms.Button
            $sbOpenFolderBtn.Text = "Open Folder"
            $sbOpenFolderBtn.AutoSize = $true
            $sbOpenFolderBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $sbOpenFolderBtn.Visible = $false
            $sbOpenFolderBtn.Add_Click({
                $folder = $this.Tag
                if ($folder -and (Test-Path $folder)) { Start-Process explorer.exe -ArgumentList "`"$folder`"" }
            })
            $sbButtonRow.Controls.Add($sbOpenFolderBtn)

            $sbForm.Controls.Add($sbLog)
            $sbForm.Controls.Add($sbStatusLabel)
            $sbForm.Controls.Add($sbButtonRow)
            $sbForm.Show()
            [System.Windows.Forms.Application]::DoEvents()

            $sbProgress = {
                param($CollectorId, $Status, $Index, $Total)
                if ($Status -eq 'Running') {
                    $sbStatusLabel.Text = "Collecting $CollectorId ($Index of $Total)..."
                } else {
                    $sbLevel = switch ($Status) {
                        'Ok'      { 'OK' }
                        'Skipped' { 'DIM' }
                        'Timeout' { 'WARN' }
                        default   { 'FAIL' }
                    }
                    Write-WinConfigGuiDiagnostic -Level $sbLevel -Message "$CollectorId ($Status)" -Box $sbLog
                }
                [System.Windows.Forms.Application]::DoEvents()
            }.GetNewClosure()

            $sbBundle = New-WinConfigSupportBundle -CaseId $sbCaseId -ProgressCallback $sbProgress

            # --- Upload (Support channel — bucket winconfig-support, never the BT bucket) ---
            $sbUpload = $null
            if ($sbBundle.ZipPath -and (Get-Command Get-WinConfigDiagnosticsUploadConfig -ErrorAction SilentlyContinue)) {
                $sbStatusLabel.Text = "Uploading bundle..."
                [System.Windows.Forms.Application]::DoEvents()
                $sbConfig = Get-WinConfigDiagnosticsUploadConfig -Channel Support
                $sbUpload = Send-WinConfigDiagnosticPackage `
                    -PackagePath $sbBundle.ZipPath `
                    -Config $sbConfig `
                    -Metadata @{ RunId = $sbBundle.RunId; CaseId = $sbBundle.CaseId } `
                    -FolderPrefix $sbBundle.CaseId
            }

            # --- Honest outcome banner: LocalOnly/Skipped must NOT read as success ---
            $sbSummary = if ($sbBundle.Counts) {
                "Collectors: $($sbBundle.Counts.ok) ok, $($sbBundle.Counts.skipped) skipped, $($sbBundle.Counts.error) error, $($sbBundle.Counts.timeout) timeout."
            } else { "Collection did not produce a manifest." }
            Write-WinConfigGuiDiagnostic -Level STEP -Message $sbSummary -Box $sbLog

            if (-not $sbBundle.ZipPath) {
                $sbStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 50, 50)
                $sbStatusLabel.Text = "FAILED: no bundle was produced. $($sbBundle.Error)"
            } elseif ($sbUpload -and $sbUpload.Status -eq 'Uploaded') {
                $sbStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(40, 120, 40)
                $sbStatusLabel.Text = "Bundle uploaded to support. Case ID: $($sbBundle.CaseId)"
                Write-WinConfigGuiDiagnostic -Level OK -Message "Uploaded to $($sbUpload.Destination) as $($sbUpload.RemotePath)" -Box $sbLog
            } elseif ($sbUpload -and $sbUpload.Status -eq 'LocalOnly') {
                $sbStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 20)
                $sbStatusLabel.Text = "Upload FAILED - bundle is on this PC only. Send it manually."
                Write-WinConfigGuiDiagnostic -Level FAIL -Message "Cloud upload failed: $($sbUpload.Error)" -Box $sbLog
                Write-WinConfigGuiDiagnostic -Level ACTION -Message "Saved to: $($sbUpload.RemotePath) - send this file to support manually." -Box $sbLog
                $sbOpenFolderBtn.Tag = $sbUpload.Destination
                $sbOpenFolderBtn.Visible = $true
            } else {
                # Skipped (no upload configured in this build) or upload module missing.
                # The ZIP lives in the ephemeral session folder and is DELETED when
                # WinConfig closes - the operator must copy it out first.
                $sbStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 20)
                $sbStatusLabel.Text = "Bundle NOT uploaded (uploads not configured). Copy it out before closing WinConfig."
                Write-WinConfigGuiDiagnostic -Level WARN -Message "Bundle saved to: $($sbBundle.ZipPath)" -Box $sbLog
                Write-WinConfigGuiDiagnostic -Level ACTION -Message "This folder is deleted when WinConfig closes - copy the file out first." -Box $sbLog
                $sbOpenFolderBtn.Tag = (Split-Path $sbBundle.ZipPath -Parent)
                $sbOpenFolderBtn.Visible = $true
            }

            if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
                $sbLedgerSummary = "$sbSummary Upload: $(if ($sbUpload) { $sbUpload.Status } else { 'NotAttempted' })"
                try {
                    Write-WinConfigSessionOperation -Category "Support" -OperationType "Test" `
                        -Name "Collect Support Bundle" -Source "Button:CollectSupportBundle" -MutatesSystem $false `
                        -Result "Success" -Summary $sbLedgerSummary
                } catch {
                    # Bookkeeping must never take down a completed collection — the
                    # bundle has already shipped by this point. Surface, don't throw.
                    Write-WinConfigGuiDiagnostic -Level WARN -Message "Session ledger write failed: $($_.Exception.Message)" -Box $sbLog
                }
            }
        } finally {
            $script:SupportBundleActive = $false
            # Whatever happened above, never leave the window wedged with Close disabled
            if ($sbForm -and -not $sbForm.IsDisposed) {
                $sbForm.ControlBox = $true
                $sbCloseBtn.Enabled = $true
            }
        }
    }
    "%programdata%" = { Start-Process "explorer.exe" "$env:ProgramData" }
    "%localappdata%" = { Start-Process "explorer.exe" "$env:LocalAppData" }
    "Documents\ScreenConnect" = { 
        $path = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("MyDocuments"), "ScreenConnect")
        if (Test-Path $path) {
            Start-Process "explorer.exe" $path
        } else {
            [System.Windows.Forms.MessageBox]::Show("ScreenConnect folder not found.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    "Device Manager" = {
        if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
            Write-WinConfigSessionOperation -Category "System" -OperationType "ExternalTool" `
                -Name "Open Device Manager" -Source "Button:DeviceManager" -MutatesSystem $false `
                -Result "Success" -Summary "Launched devmgmt.msc"
        }
        Start-Process "devmgmt.msc"
    }
    "Task Manager" = {
        if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
            Write-WinConfigSessionOperation -Category "System" -OperationType "ExternalTool" `
                -Name "Open Task Manager" -Source "Button:TaskManager" -MutatesSystem $false `
                -Result "Success" -Summary "Launched taskmgr.exe"
        }
        Start-Process "taskmgr.exe"
    }
    "Control Panel" = {
        if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
            Write-WinConfigSessionOperation -Category "System" -OperationType "ExternalTool" `
                -Name "Open Control Panel" -Source "Button:ControlPanel" -MutatesSystem $false `
                -Result "Success" -Summary "Launched control.exe"
        }
        Start-Process "control.exe"
    }
    "Sound Panel" = {
        if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
            Write-WinConfigSessionOperation -Category "Audio" -OperationType "ExternalTool" `
                -Name "Open Sound Panel" -Source "Button:SoundPanel" -MutatesSystem $false `
                -Result "Success" -Summary "Launched mmsys.cpl"
        }
        Start-Process "mmsys.cpl"
    }
    "Apply Win 11 Start Menu" = {
        # Register session action
        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "Start Menu Apply" -Detail "Custom Start Menu configuration applied" -Category "Configuration" -Result "PASS" -Tier 0 -Summary "Start Menu configured"
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

        $dropboxUrl = "https://www.dropbox.com/scl/fi/mgwtlv7hibypxmka5mdvg/start2.bin?rlkey=94h8zx279gwtg2uao4eblh07j&st=nqklcwdq&dl=1"
        $tempFile = Join-Path -Path $env:TEMP -ChildPath "start2.bin"
        Invoke-WebRequest -Uri $dropboxUrl -OutFile $tempFile

        $startMenuPackagePath = Join-Path -Path $env:LocalAppData -ChildPath "Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
        $existingStart2BinPath = Join-Path -Path $startMenuPackagePath -ChildPath "start2.bin"

        if (Test-Path $existingStart2BinPath) {
            Copy-Item -Path $existingStart2BinPath -Destination "$existingStart2BinPath.bak" -Force
            Copy-Item -Path $tempFile -Destination $existingStart2BinPath -Force
        } else {
            New-Item -ItemType Directory -Path $startMenuPackagePath -Force | Out-Null
            Copy-Item -Path $tempFile -Destination $existingStart2BinPath -Force
        }

        Remove-Item $tempFile

        [System.Windows.Forms.MessageBox]::Show("Start Menu configuration applied successfully. You may need to restart your computer for the changes to take effect.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Apply branding colors" = {
        # Register session action
        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "Branding Colors" -Detail "NeurOptimal branding colors applied to Windows" -Category "Configuration" -Result "PASS" -Tier 0 -Summary "Branding colors applied"
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"
        $AccentColorMenuKey = @{
            Key   = 'AccentColorMenu';
            Type  = "DWORD";
            Value = 0xff9b794c
        }
        if (!(Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -Type $AccentColorMenuKey.Type -Force

        $AccentPaletteKey = @{
            Key   = 'AccentPalette';
            Type  = "Binary";
            Value = 'bf,e7,ed,00,9d,c7,d5,00,5d,8f,b0,00,4c,79,9b,00,3b,60,81,00,26,40,60,00,0e,1c,3a,00,88,17,98,00'
        }
        $hexified = $AccentPaletteKey.Value -split ',' | ForEach-Object { [byte]('0x' + $_) }
        Set-ItemProperty -Path $RegPath -Name $AccentPaletteKey.Key -Value $hexified -Type $AccentPaletteKey.Type -Force

        $MotionAccentIdKey = @{
            Key   = 'MotionAccentId_v1.00';
            Type  = "DWORD";
            Value = 0x000000db
        }
        Set-ItemProperty -Path $RegPath -Name $MotionAccentIdKey.Key -Value $MotionAccentIdKey.Value -Type $MotionAccentIdKey.Type -Force

        $StartMenuKey = @{
            Key   = 'StartColorMenu';
            Type  = "DWORD";
            Value = 0xff81603b
        }
        Set-ItemProperty -Path $RegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -Type $StartMenuKey.Type -Force

        [System.Windows.Forms.MessageBox]::Show("NeurOptimal branding colors applied successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    "Pin Taskbar Icons" = {
        # Register session action
        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "Taskbar Pinning" -Detail "Taskbar icons configured and pinned" -Category "Configuration" -Result "PASS" -Tier 0 -Summary "Taskbar icons pinned"
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

        $shortcutPaths = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk",
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk",
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk",
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk"
        )

        foreach ($shortcutPath in $shortcutPaths) {
            if (Test-Path $shortcutPath) {
                $shell = New-Object -ComObject "Shell.Application"
                $folder = Split-Path $shortcutPath
                $itemName = Split-Path $shortcutPath -Leaf
                $item = $shell.Namespace($folder).ParseName($itemName)
                $item.InvokeVerb("taskbarpin")
            }
        }

        Stop-Process -ProcessName explorer -Force
        Start-Process explorer -Wait

        [System.Windows.Forms.MessageBox]::Show("Taskbar icons pinned successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

        Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Force -Recurse -ErrorAction SilentlyContinue

        Stop-Process -ProcessName explorer -Force
        Start-Process explorer

        $taskbar_layout = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%WINDIR%\explorer.exe" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%WINDIR%\SystemApps\Microsoft.Windows.Explorer_cw5n1h2txyewy\Explorer.exe" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2404.40.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="C:\zengar\NO.exe" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
 </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

        # EPHEMERAL: Use session temp runtime path (zero-footprint)
        # NOTE: This XML file is referenced by a registry policy. The policy will break
        # after session ends since the file is deleted. For persistent taskbar layout,
        # the policy mechanism should be refactored.
        $runtimePath = if (Get-Command Get-WinConfigRuntimePath -ErrorAction SilentlyContinue) {
            Get-WinConfigRuntimePath
        } else {
            Join-Path $env:TEMP "WinConfig-runtime"
        }
        [System.IO.FileInfo]$provisioning = Join-Path $runtimePath "taskbar_layout.xml"
        if (!$provisioning.Directory.Exists) {
            $provisioning.Directory.Create()
        }

        $taskbar_layout | Out-File $provisioning.FullName -Encoding utf8

        $settings = [PSCustomObject]@{
            Path  = "SOFTWARE\Policies\Microsoft\Windows\Explorer"
            Value = $provisioning.FullName
            Name  = "StartLayoutFile"
            Type  = [Microsoft.Win32.RegistryValueKind]::ExpandString
        },
        [PSCustomObject]@{
            Path  = "SOFTWARE\Policies\Microsoft\Windows\Explorer"
            Value = 1
            Name  = "LockedStartLayout"
        } | Group-Object Path

        foreach ($setting in $settings) {
            $registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($setting.Name, $true)
            if ($null -eq $registry) {
                $registry = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($setting.Name, $true)
            }
            $setting.Group | ForEach-Object {
                if (!$_.Type) {
                    $registry.SetValue($_.name, $_.value)
                }
                else {
                    $registry.SetValue($_.name, $_.value, $_.type)
                }
            }
            $registry.Dispose()
        }
    }
    "MS Store Updates" = { Start-Process "ms-windows-store://downloadsandupdates" }

    "Update Surface Drivers" = { Start-Process "https://support.microsoft.com/en-us/surface/download-drivers-and-firmware-for-surface-09bb2e09-2a4b-cb69-0951-078a7739e120" }
    "Microsoft Update Catalog" = {
        # Create the Windows Update History form
        $updateForm = New-Object System.Windows.Forms.Form
        $updateForm.Text = "Windows Update History"
        $updateForm.Size = New-Object System.Drawing.Size(900,450)
        $updateForm.StartPosition = "CenterScreen"
        $updateForm.MinimumSize = New-Object System.Drawing.Size(500,300)

        # Create a ListView to display update history
        $listView = New-Object System.Windows.Forms.ListView
        $listView.View = [System.Windows.Forms.View]::Details
        $listView.FullRowSelect = $true
        $listView.GridLines = $true
        $listView.Font = New-Object System.Drawing.Font($listView.Font.FontFamily, 14)
        $listView.Location = New-Object System.Drawing.Point(10,10)
        $listView.Size = New-Object System.Drawing.Size(860,300)
        $listView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

        # Add columns to the ListView
        $listView.Columns.Add("Title", 500)
        $listView.Columns.Add("Date", 150)
        $listView.Columns.Add("KB", 120)

        # Add the ListView to the form
        $updateForm.Controls.Add($listView)

        # Get update history and populate the ListView
        $updates = Get-WindowsUpdateHistory
        foreach ($update in $updates) {
            $item = New-Object System.Windows.Forms.ListViewItem($update.Title)
            $item.SubItems.Add($update.Date.ToString("yyyy-MM-dd HH:mm:ss"))
            $item.SubItems.Add($update.KB)
            $listView.Items.Add($item)
        }

        # Create a "Copy KB" button
        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Location = New-Object System.Drawing.Point(10,320)
        $copyButton.Size = New-Object System.Drawing.Size(100,30)
        $copyButton.Text = "Copy KB"
        $copyButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
        # EXEMPT-CONTRACT-001: Simple clipboard operation, no diagnostic functions
        $copyButton.Add_Click({
            $selectedItem = $listView.SelectedItems[0]
            if ($selectedItem) {
                $kb = $selectedItem.SubItems[2].Text
                if ($kb -ne "N/A") {
                    Copy-KBToClipboard $kb
                    [System.Windows.Forms.MessageBox]::Show("KB $kb copied to clipboard", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                } else {
                    [System.Windows.Forms.MessageBox]::Show("No KB number available for this update", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                }
            } else {
                [System.Windows.Forms.MessageBox]::Show("Please select an update from the list", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        })
        $updateForm.Controls.Add($copyButton)

        # Create a "Search Microsoft Catalog" button
        $searchButton = New-Object System.Windows.Forms.Button
        $searchButton.Location = New-Object System.Drawing.Point(120,320)
        $searchButton.Size = New-Object System.Drawing.Size(220,30)
        $searchButton.Text = "Search Microsoft Catalog"
        $searchButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
        # EXEMPT-CONTRACT-001: Simple navigation action, no diagnostic functions
        $searchButton.Add_Click({
            $selectedItem = $listView.SelectedItems[0]
            if ($selectedItem) {
                $kb = $selectedItem.SubItems[2].Text
                if ($kb -ne "N/A") {
                    Search-WindowsCatalog $kb
                } else {
                    [System.Windows.Forms.MessageBox]::Show("No KB number available for this update", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                }
            } else {
                [System.Windows.Forms.MessageBox]::Show("Please select an update from the list", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        })
        $updateForm.Controls.Add($searchButton)

        # Create "Looking Glass" font size adjuster
        $fontSizePanel = New-Object System.Windows.Forms.Panel
        $fontSizePanel.Location = New-Object System.Drawing.Point(350,320)
        $fontSizePanel.Size = New-Object System.Drawing.Size(100,30)
        $fontSizePanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
        $fontSizePanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

        $decreaseFont = New-Object System.Windows.Forms.Button
        $decreaseFont.Text = "-"
        $decreaseFont.Size = New-Object System.Drawing.Size(30,28)
        $decreaseFont.Location = New-Object System.Drawing.Point(0,0)
        $decreaseFont.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        # EXEMPT-CONTRACT-001: Font size adjustment, no diagnostic functions
        $decreaseFont.Add_Click({
            $currentFont = $listView.Font
            $newSize = [Math]::Max($currentFont.Size - 1, 6)  # Min size of 6
            $listView.Font = New-Object System.Drawing.Font($currentFont.FontFamily, $newSize, $currentFont.Style)
        })
        $fontSizePanel.Controls.Add($decreaseFont)

        $fontSizeLabel = New-Object System.Windows.Forms.Label
        $fontSizeLabel.Text = [char]::ConvertFromUtf32(0x1F50D)  # Magnifying glass emoji
        $fontSizeLabel.Size = New-Object System.Drawing.Size(38,28)
        $fontSizeLabel.Location = New-Object System.Drawing.Point(30,0)
        $fontSizeLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $fontSizePanel.Controls.Add($fontSizeLabel)

        $increaseFont = New-Object System.Windows.Forms.Button
        $increaseFont.Text = "+"
        $increaseFont.Size = New-Object System.Drawing.Size(30,28)
        $increaseFont.Location = New-Object System.Drawing.Point(68,0)
        $increaseFont.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        # EXEMPT-CONTRACT-001: Font size adjustment, no diagnostic functions
        $increaseFont.Add_Click({
            $currentFont = $listView.Font
            $newSize = [Math]::Min($currentFont.Size + 1, 20)  # Max size of 20
            $listView.Font = New-Object System.Drawing.Font($currentFont.FontFamily, $newSize, $currentFont.Style)
        })
        $fontSizePanel.Controls.Add($increaseFont)

        $updateForm.Controls.Add($fontSizePanel)

        $updateForm.Add_Resize({
            $listView.Width = $updateForm.ClientSize.Width - 20
            $listView.Height = $updateForm.ClientSize.Height - 80
            $copyButton.Top = $updateForm.ClientSize.Height - 70
            $searchButton.Top = $updateForm.ClientSize.Height - 70
            $fontSizePanel.Top = $updateForm.ClientSize.Height - 70
            $fontSizePanel.Left = $searchButton.Right + 10
        })
        

        # Show the form
        $updateForm.ShowDialog()
    }
"Windows Insider" = {
    if (-not $GitHubToken) {
        [System.Windows.Forms.MessageBox]::Show(
            "This feature requires a GitHub token.`n`nSet WINCONFIG_GITHUB_TOKEN environment variable and restart.",
            "Token Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $headers = @{
        Authorization = "Bearer $GitHubToken"
        Accept = "application/vnd.github.v3.raw"
    }
    $owner = "mariusneuroptimal"
    $repo = "WinConfig"
    $path = "WindowsInsider.ps1"
    $apiUrl = "https://api.github.com/repos/$owner/$repo/contents/$path"

    try {
        $ProgressPreference = 'SilentlyContinue'

        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Verbose
        
        # Fix the typo in the script content
        $fixedResponse = $response -replace 'Add_Measureltem', 'Add_MeasureItem'
        
        # Execute the fixed script content directly
        $scriptBlock = [ScriptBlock]::Create($fixedResponse)
        
        # Create a new PowerShell instance to run the script
        $ps = [PowerShell]::Create()
        $ps.AddScript($scriptBlock) | Out-Null
        
        # Execute the script and capture any errors
        $result = $ps.Invoke()
        
        if ($ps.HadErrors) {
            $errorMessage = $ps.Streams.Error | Out-String
            throw $errorMessage
        }

        # Show the form returned by the script
        if ($result -and $result[0] -is [System.Windows.Forms.Form]) {
            $form = $result[0]
            $form.Add_FormClosed({
                # Do nothing when the form is closed
            })
            $form.ShowDialog()
        } else {
            throw "The script did not return a valid form object."
        }
    } catch {
        if ($_ -notmatch "The script did not return a valid form object") {
            $errorMessage = "Failed to load or execute the Windows Insider script.`nError: $_"
            [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}
        "Remove Intel SST Audio Driver" = $buttonClickHandler
        "DISM Restore Health" = {
            # Record operation in session ledger (mutating system operation)
            if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
                Write-WinConfigSessionOperation -Category "System" -OperationType "ExternalTool" `
                    -Name "DISM Restore Health" -Source "Button:DISM" -MutatesSystem $true `
                    -Result "Success" -Summary "DISM launched in elevated window"
            }
            $wrapperPath = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\Invoke-DiagnosticConsole.ps1"
            $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\Run-DISMRestoreHealth.ps1"
            Start-Process "powershell" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $wrapperPath, "-Title", "DISM Restore Health", "-Mode", "System Repair (requires elevation)", "-ScriptPath", $scriptPath, "-KeepOpen" -Verb RunAs
        }
        "/sfc scannow" = {
            # Record operation in session ledger (mutating system operation)
            if (Get-Command Write-WinConfigSessionOperation -ErrorAction SilentlyContinue) {
                Write-WinConfigSessionOperation -Category "System" -OperationType "ExternalTool" `
                    -Name "SFC Scannow" -Source "Button:SFC" -MutatesSystem $true `
                    -Result "Success" -Summary "SFC launched in elevated window"
            }
            $wrapperPath = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\Invoke-DiagnosticConsole.ps1"
            $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\Run-SFCScannow.ps1"
            Start-Process "powershell" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $wrapperPath, "-Title", "SFC Scannow", "-Mode", "System Repair (requires elevation)", "-ScriptPath", $scriptPath, "-KeepOpen" -Verb RunAs
        }
        "Apply Win Update Icon" = {
            [System.Windows.Forms.MessageBox]::Show("This feature will be implemented in a future version.", "Not Implemented", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
"Run Network Test" = {
    # GUARD: Verify required Console module functions are available (DIAG-GUI-001)
    if (-not (Get-Command Initialize-WinConfigGuiDiagnosticBox -ErrorAction SilentlyContinue)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Network Test cannot start: Console module failed to load.`n`nThe Initialize-WinConfigGuiDiagnosticBox function is not available. This may indicate a corrupted installation or missing module file.`n`nPlease reinstall WinConfig or contact support.",
            "Module Load Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    # Create a new form for output
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "Network Test Results"
    $outputForm.Size = New-Object System.Drawing.Size(800, 650)
    $outputForm.StartPosition = "CenterScreen"

    # Use RichTextBox with canonical diagnostic colors (from Console.psm1)
    $outputTextBox = New-Object System.Windows.Forms.RichTextBox
    $outputTextBox.Multiline = $true
    $outputTextBox.ScrollBars = "Vertical"
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    Initialize-WinConfigGuiDiagnosticBox -Box $outputTextBox
    $outputForm.Controls.Add($outputTextBox)

    # Show the form immediately
    $outputForm.Show()
    $outputForm.Refresh()

    # Wrapper for semantic diagnostic output (delegates to Console.psm1)
    function Write-Log {
        param (
            [string]$Message,
            [string]$Level = "INFO"
        )
        Write-WinConfigGuiDiagnostic -Level $Level -Message $Message -Box $outputTextBox -NoPrefix
        $outputForm.Refresh()
    }

    # Initialize evidence collection
    $networkEvidence = @{
        LatencyMs = $null
        LatencyMin = $null
        LatencyMax = $null
        JitterMs = $null
        PacketLossDetected = $false
        LatencyQuality = $null
        LinkSpeedMbps = $null
        LinkStandard = $null
        SignalStrength = $null          # Percentage (0-100) as reported by Windows
        ConnectionType = $null
        PublicIP = $null
        CountryCode = $null
        CountryName = $null
        IpType = $null                  # Enum: residential | business | datacenter | unknown
        NatDetected = $null
        ActiveAdapterCount = 0
        RiskFlags = @()                 # Array of @{Id; Severity} objects
        TestResult = "PASS"
    }

    # Collect structured risk flags throughout
    $riskFlags = @()

    try {
        # ═══════════════════════════════════════════════════════════════════
        # NETWORK CONTEXT
        # ═══════════════════════════════════════════════════════════════════
        Write-Log "NETWORK CONTEXT" -Level STEP
        Write-Log ("=" * 60) -Level DIM

        # Get all adapters and identify active ones
        $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        $activeAdapters = $allAdapters | Where-Object { $_.Status -eq "Up" -and $_.MediaConnectionState -eq "Connected" }
        $networkEvidence.ActiveAdapterCount = @($activeAdapters).Count

        # Identify primary adapter (first connected)
        $primaryAdapter = $activeAdapters | Select-Object -First 1
        $wifiAdapter = $activeAdapters | Where-Object { $_.Name -match "Wi-Fi" -or $_.InterfaceDescription -match "Wireless" } | Select-Object -First 1
        $ethernetAdapter = $activeAdapters | Where-Object { $_.Name -match "Ethernet" -and $_.InterfaceDescription -notmatch "Wireless" } | Select-Object -First 1

        # Determine connection type
        $activeConnections = @()
        if ($wifiAdapter) { $activeConnections += "Wi-Fi" }
        if ($ethernetAdapter) { $activeConnections += "Ethernet" }
        $networkEvidence.ConnectionType = if ($activeConnections.Count -gt 0) { $activeConnections -join "+" } else { "None" }

        if ($primaryAdapter) {
            Write-Log "Active Interface: $($primaryAdapter.Name) ($($primaryAdapter.InterfaceDescription))"

            # Determine link standard and speed
            $linkSpeed = $primaryAdapter.LinkSpeed
            $speedValue = [double]($linkSpeed -replace '[^0-9.]')
            $speedUnit = if ($linkSpeed -match 'Gbps') { 'Gbps' } else { 'Mbps' }
            $speedMbps = if ($speedUnit -eq 'Gbps') { $speedValue * 1000 } else { $speedValue }
            $networkEvidence.LinkSpeedMbps = $speedMbps

            # Wi-Fi specific: get radio type and signal strength
            if ($wifiAdapter -and ($primaryAdapter.Name -eq $wifiAdapter.Name -or $primaryAdapter.InterfaceDescription -match "Wireless")) {
                $wlanInfo = netsh wlan show interfaces 2>$null | Out-String

                # Extract radio type (802.11ax, 802.11ac, etc.)
                $radioType = if ($wlanInfo -match "Radio type\s*:\s*(.+)") {
                    $matches[1].Trim()
                } else { "Unknown" }
                $networkEvidence.LinkStandard = $radioType
                Write-Log "Link Standard: $radioType"

                # Extract signal strength
                $signalPct = if ($wlanInfo -match "Signal\s*:\s*(\d+)%") {
                    [int]$matches[1]
                } else { $null }

                if ($signalPct) {
                    $networkEvidence.SignalStrength = $signalPct
                    $signalQuality = if ($signalPct -ge 80) { "Strong" } elseif ($signalPct -ge 50) { "Moderate" } else { "Weak" }
                    Write-Log "Signal Strength: $signalPct% ($signalQuality)"
                    if ($signalPct -lt 50) {
                        $riskFlags += "Wi-Fi signal weak ($signalPct%) - move closer to router"
                    }
                }
            } else {
                # Ethernet: show link speed as standard
                $linkStandard = if ($speedMbps -ge 2500) { "2.5G Ethernet" }
                                elseif ($speedMbps -ge 1000) { "1G Ethernet" }
                                elseif ($speedMbps -ge 100) { "100M Ethernet" }
                                else { "$speedMbps Mbps" }
                $networkEvidence.LinkStandard = $linkStandard
                Write-Log "Link Standard: $linkStandard"
            }
        } else {
            Write-Log "Active Interface: None detected"
            $riskFlags += "No active network connection"
            $networkEvidence.TestResult = "WARN"
        }

        Write-Log ""

        # ═══════════════════════════════════════════════════════════════════
        # CONNECTIVITY QUALITY
        # ═══════════════════════════════════════════════════════════════════
        Write-Log "CONNECTIVITY QUALITY" -Level STEP
        Write-Log ("=" * 60) -Level DIM

        # Ping burst (3 packets) to neuroptimal.com
        $pingResult = Test-Connection -ComputerName neuroptimal.com -Count 3 -ErrorAction SilentlyContinue
        $pingCount = @($pingResult).Count

        # Packet loss detection: if fewer than 3 responses, some packets were lost
        if ($pingCount -lt 3 -and $pingCount -gt 0) {
            $networkEvidence.PacketLossDetected = $true
        }

        if ($pingResult) {
            $pingTimes = $pingResult | ForEach-Object { $_.ResponseTime }
            $minPing = [math]::Round(($pingTimes | Measure-Object -Minimum).Minimum, 1)
            $maxPing = [math]::Round(($pingTimes | Measure-Object -Maximum).Maximum, 1)
            $avgPing = [math]::Round(($pingTimes | Measure-Object -Average).Average, 1)
            $jitter = [math]::Round($maxPing - $minPing, 1)

            $networkEvidence.LatencyMs = $avgPing
            $networkEvidence.LatencyMin = $minPing
            $networkEvidence.LatencyMax = $maxPing
            $networkEvidence.JitterMs = $jitter

            # Determine quality
            $latencyQuality = if ($avgPing -le 50) { "excellent" } elseif ($avgPing -le 100) { "good" } elseif ($avgPing -le 150) { "average" } else { "slow" }
            $jitterQuality = if ($jitter -le 10) { "excellent" } elseif ($jitter -le 30) { "acceptable" } else { "unstable" }
            $networkEvidence.LatencyQuality = $latencyQuality

            Write-Log "Latency to neuroptimal.com:"
            Write-Log "  min $minPing ms | avg $avgPing ms | max $maxPing ms"
            Write-Log "  jitter: $jitter ms ($jitterQuality)"

            if ($networkEvidence.PacketLossDetected) {
                Write-Log "  packet loss: detected ($pingCount/3 responses)"
                $riskFlags += @{ Id = "PACKET_LOSS"; Result = "WARN" }
            }

            if ($avgPing -gt 150) {
                $riskFlags += @{ Id = "HIGH_LATENCY"; Result = "WARN" }
            }
            if ($jitter -gt 30) {
                $riskFlags += @{ Id = "HIGH_JITTER"; Result = "WARN" }
            }
        } else {
            Write-Log "Latency: Unable to reach neuroptimal.com"
            $networkEvidence.LatencyMs = -1
            $networkEvidence.LatencyQuality = "unreachable"
            $networkEvidence.PacketLossDetected = $true
            $riskFlags += @{ Id = "UNREACHABLE"; Result = "FAIL" }
            $networkEvidence.TestResult = "WARN"
        }

        Write-Log ""

        # ═══════════════════════════════════════════════════════════════════
        # ROUTING / GEO
        # ═══════════════════════════════════════════════════════════════════
        Write-Log "ROUTING / NETWORK REGION" -Level STEP
        Write-Log ("=" * 60) -Level DIM

        # Get expected country from OS timezone (for geo mismatch detection)
        $expectedCountry = $null
        try {
            $tz = (Get-TimeZone).Id
            # Common timezone to country mappings
            $tzCountryMap = @{
                "Pacific Standard Time" = "US"; "Mountain Standard Time" = "US"; "Central Standard Time" = "US"; "Eastern Standard Time" = "US"
                "Eastern Standard Time (Mexico)" = "MX"; "Central Standard Time (Mexico)" = "MX"; "Pacific Standard Time (Mexico)" = "MX"
                "Canada Central Standard Time" = "CA"; "Atlantic Standard Time" = "CA"; "Newfoundland Standard Time" = "CA"
                "GMT Standard Time" = "GB"; "W. Europe Standard Time" = "DE"; "Romance Standard Time" = "FR"
                "AUS Eastern Standard Time" = "AU"; "AUS Central Standard Time" = "AU"; "W. Australia Standard Time" = "AU"
            }
            if ($tzCountryMap.ContainsKey($tz)) {
                $expectedCountry = $tzCountryMap[$tz]
            }
        } catch { }

        # Get IP info from external API (single call, already in use)
        try {
            $ipInfo = Invoke-RestMethod -Uri "https://ipapi.co/json/" -TimeoutSec 5
            $networkEvidence.PublicIP = $ipInfo.ip
            $networkEvidence.CountryCode = $ipInfo.country_code
            $networkEvidence.CountryName = $ipInfo.country_name

            Write-Log "Public IP: $($ipInfo.ip)"
            Write-Log "Estimated network region: $($ipInfo.country_name)"
            if ($expectedCountry) {
                Write-Log "System Region: $expectedCountry (based on timezone)"
            }

            # Classify IP type based on org/ASN (heuristic) - normalized enum values
            $orgLower = ($ipInfo.org + " " + $ipInfo.asn).ToLower()
            $ipType = if ($orgLower -match "amazon|google|microsoft|azure|aws|digitalocean|linode|vultr|ovh|hetzner|cloudflare|vpn|proxy|tunnel") {
                "datacenter"
            } elseif ($orgLower -match "business|enterprise|corporate|commercial") {
                "business"
            } else {
                "residential"
            }
            $networkEvidence.IpType = $ipType

            # Display friendly name but store enum
            $ipTypeDisplay = @{ "datacenter" = "Datacenter/VPN"; "business" = "Business ISP"; "residential" = "Residential ISP" }[$ipType]
            Write-Log "IP Type: $ipTypeDisplay"

            if ($ipType -eq "datacenter") {
                # Context flag only - per governance contract, does not create severity
                $riskFlags += @{ Id = "DATACENTER_IP"; Result = "PASS" }
            }

        } catch {
            Write-Log "Public IP: Unable to determine (API timeout)"
            $networkEvidence.PublicIP = "Unknown"
            $networkEvidence.IpType = "unknown"
        }

        # NAT detection: check for RFC1918 private addresses on local adapters
        $privateIpFound = $false
        $localIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne "WellKnown" }
        foreach ($ip in $localIPs) {
            if ($ip.IPAddress -match "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") {
                $privateIpFound = $true
                break
            }
        }
        $networkEvidence.NatDetected = $privateIpFound
        # Network type display - descriptive, not judgmental (per governance contract)
        $networkType = if ($privateIpFound) { "Private LAN (NAT)" } else { "Public (no NAT)" }
        Write-Log "Network Type: $networkType"

        Write-Log ""

        # ═══════════════════════════════════════════════════════════════════
        # INTERFACE HEALTH
        # ═══════════════════════════════════════════════════════════════════
        Write-Log "INTERFACE HEALTH"
        Write-Log ("=" * 60)

        # Check specific adapter types
        $btPan = $allAdapters | Where-Object { $_.InterfaceDescription -match "Bluetooth|PAN" -and $_.Status -eq "Up" }

        foreach ($adapter in $allAdapters | Where-Object { $_.Name -match "Wi-Fi|Ethernet|Bluetooth" -or $_.InterfaceDescription -match "Wireless|Bluetooth|PAN" }) {
            $status = if ($adapter.Status -eq "Up" -and $adapter.MediaConnectionState -eq "Connected") { "Connected" } else { "Disconnected" }
            $adapterType = if ($adapter.InterfaceDescription -match "Bluetooth|PAN") { "Bluetooth PAN" }
                          elseif ($adapter.InterfaceDescription -match "Wireless" -or $adapter.Name -match "Wi-Fi") { "Wi-Fi" }
                          else { "Ethernet" }
            Write-Log "$($adapterType): $status"
        }

        # Context flag: multiple active adapters (informational only)
        if ($networkEvidence.ActiveAdapterCount -gt 1) {
            $riskFlags += @{ Id = "MULTIPLE_ADAPTERS"; Result = "PASS" }
        }

        # Context flag: Bluetooth PAN (informational only)
        if ($btPan) {
            $riskFlags += @{ Id = "BLUETOOTH_PAN"; Result = "PASS" }
        }

        Write-Log ""

        # ═══════════════════════════════════════════════════════════════════
        # NETWORK ENVIRONMENT
        # ═══════════════════════════════════════════════════════════════════
        Write-Log "NETWORK ENVIRONMENT" -Level STEP
        Write-Log ("=" * 60) -Level DIM

        # Context flag: Wi-Fi in use (informational only)
        if ($wifiAdapter -and -not $ethernetAdapter) {
            $riskFlags += @{ Id = "WIFI_IN_USE"; Result = "PASS" }
        }

        # Context flag: weak signal (informational - only escalates if paired with metric failure)
        if ($networkEvidence.SignalStrength -and $networkEvidence.SignalStrength -lt 40) {
            $riskFlags += @{ Id = "WEAK_SIGNAL"; Result = "PASS" }
        }

        # Add positive confirmations (severity = "ok")
        if ($networkEvidence.LatencyMs -and $networkEvidence.LatencyMs -gt 0 -and $networkEvidence.LatencyMs -le 150) {
            $riskFlags += @{ Id = "LATENCY_OK"; Result = "PASS" }
        }
        if ($networkEvidence.LinkSpeedMbps -and $networkEvidence.LinkSpeedMbps -ge 50) {
            $riskFlags += @{ Id = "BANDWIDTH_OK"; Result = "PASS" }
        }
        if ($ethernetAdapter -and -not $wifiAdapter) {
            $riskFlags += @{ Id = "ETHERNET_CONNECTED"; Result = "PASS" }
        }
        if (-not $networkEvidence.PacketLossDetected -and $networkEvidence.LatencyMs -gt 0) {
            $riskFlags += @{ Id = "NO_PACKET_LOSS"; Result = "PASS" }
        }

        $networkEvidence.RiskFlags = $riskFlags

        # Flag display labels
        # Context flags are descriptive (no warnings/judgments)
        # Measurement flags can indicate severity
        $flagLabels = @{
            # Measurement-based flags (can indicate severity)
            "UNREACHABLE" = "Cannot reach neuroptimal.com"
            "HIGH_LATENCY" = "High latency detected (>150ms)"
            "HIGH_JITTER" = "Connection jitter detected (>30ms)"
            "PACKET_LOSS" = "Packet loss detected"
            # Context flags (informational only - no judgments)
            "DATACENTER_IP" = "IP type: Datacenter/VPN"
            "MULTIPLE_ADAPTERS" = "Multiple network adapters active"
            "BLUETOOTH_PAN" = "Bluetooth PAN connected"
            "WIFI_IN_USE" = "Connection type: Wi-Fi"
            "WEAK_SIGNAL" = "Wi-Fi signal strength: Low"
            # Positive flags
            "LATENCY_OK" = "Latency within optimal range"
            "BANDWIDTH_OK" = "Bandwidth sufficient"
            "ETHERNET_CONNECTED" = "Connection type: Ethernet"
            "NO_PACKET_LOSS" = "No packet loss detected"
        }

        # Action hints - lowest-cost next step for measurement-based failures ONLY
        # Per governance contract: context flags (INFO severity) do NOT get action hints
        # Structured with Id (for analytics) and Text (for display)
        $flagHints = @{
            "UNREACHABLE" = @{ Id = "DISCONNECT_VPN"; Text = "If using VPN, disconnect and retry" }
            "HIGH_LATENCY" = @{ Id = "PAUSE_STREAMING"; Text = "If other devices streaming, pause them and retry" }
            "HIGH_JITTER" = @{ Id = "MOVE_CLOSER_WIFI"; Text = "If on Wi-Fi, try moving closer to router" }
            "PACKET_LOSS" = @{ Id = "SWITCH_ETHERNET"; Text = "If on Wi-Fi, switch to Ethernet if available" }
            # Note: Context flags (DATACENTER_IP, GEO_CONTEXT, MULTIPLE_ADAPTERS, BLUETOOTH_PAN,
            # WIFI_IN_USE, WEAK_SIGNAL) intentionally excluded - no action hints for info-only flags
        }

        # Display flags by severity category
        # Per governance contract: info flags are context only (no warnings, no action hints)
        $failures = $riskFlags | Where-Object { $_.Result -eq $DiagnosticResult.FAIL -or $_.Result -eq $DiagnosticResult.WARN }
        $context = @()  # Info flags now mapped to PASS - shown with positives
        $positives = $riskFlags | Where-Object { $_.Result -eq $DiagnosticResult.PASS }

        # Show failures/warnings first (with action hints)
        foreach ($flag in $failures) {
            $label = $flagLabels[$flag.Id]
            if (-not $label) { $label = $flag.Id }
            Write-Log "[!] $label"
            $hint = $flagHints[$flag.Id]
            if ($hint) {
                Write-Log "    -> $($hint.Text)"
            }
        }

        # Show context flags (informational only - no warnings, no action hints)
        foreach ($flag in $context) {
            $label = $flagLabels[$flag.Id]
            if (-not $label) { $label = $flag.Id }
            Write-Log "    $label"
        }

        # Show positive confirmations
        foreach ($flag in $positives) {
            $label = $flagLabels[$flag.Id]
            if (-not $label) { $label = $flag.Id }
            Write-Log "[OK] $label"
        }

        # Summary line if no issues
        if ($failures.Count -eq 0 -and $positives.Count -gt 0) {
            Write-Log ""
            Write-Log "[OK] No issues detected"
        }

        # FAST CHECKS section - only for measurement-based failures (not context flags)
        if ($failures.Count -gt 0) {
            # Only measurement-based flags have action hints
            $fastCheckOrder = @("UNREACHABLE", "PACKET_LOSS", "HIGH_JITTER", "HIGH_LATENCY")
            $fastChecks = @()
            foreach ($checkId in $fastCheckOrder) {
                if ($failures | Where-Object { $_.Id -eq $checkId }) {
                    $hint = $flagHints[$checkId]
                    if ($hint) {
                        $fastChecks += $hint.Text
                        if ($fastChecks.Count -ge 2) { break }
                    }
                }
            }
            if ($fastChecks.Count -gt 0) {
                Write-Log ""
                Write-Log "FAST CHECKS (Lowest Cost First)"
                Write-Log "============================================================"
                $i = 1
                foreach ($check in $fastChecks) {
                    Write-Log "$i. $check"
                    $i++
                }
                Write-Log "$i. Re-run Network Test"
                Write-Log ""
            }
        }

        Write-Log ""
        Write-Log "You can now close this window."

        # Set test result based on critical flags
        $hasFailure = $riskFlags | Where-Object { $_.Result -eq $DiagnosticResult.FAIL }
        $hasWarning = $riskFlags | Where-Object { $_.Result -eq $DiagnosticResult.WARN }

        if ($hasFailure) {
            $networkEvidence.TestResult = "FAIL"
        } elseif ($hasWarning) {
            $networkEvidence.TestResult = "WARN"
        }

    } catch {
        Write-Log ""
        Write-Log "[ERROR] An error occurred: $_"
        $networkEvidence.TestResult = "FAIL"
    }

    # Register session action with enhanced evidence
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        # Get country info for flag emoji in summary
        $countryInfo = if (Get-Command Get-SessionCountryInfo -ErrorAction SilentlyContinue) {
            Get-SessionCountryInfo
        } else {
            @{ CountryCode = $networkEvidence.CountryCode; CountryName = $networkEvidence.CountryName; CountryFlag = "" }
        }

        $latencyStr = if ($networkEvidence.LatencyMs -and $networkEvidence.LatencyMs -gt 0) { "$($networkEvidence.LatencyMs)ms" } else { "N/A" }
        $summary = "$($countryInfo.CountryFlag) $($networkEvidence.CountryName) - Latency: $latencyStr ($($networkEvidence.LatencyQuality))"
        Register-WinConfigSessionAction -Action "Network Test" -Detail "Network connectivity test executed" -Category "Diagnostics" -Result $networkEvidence.TestResult -Tier 0 -Summary $summary -Evidence $networkEvidence
    }

    # Refresh Details tab to show new action
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) {
        Update-ResultsDiagnosticsView
    }
}
"Domain, IP && Ports Test" = {
    # Import in click handler runspace (WinForms delegates don't inherit modules)
    Import-Module (Join-Path $PSScriptRoot 'Modules\DiagnosticTypes.psm1') -Force

    # GUARD: Verify required Console module functions are available (DIAG-GUI-001)
    if (-not (Get-Command Initialize-WinConfigGuiDiagnosticBox -ErrorAction SilentlyContinue)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Domain Test cannot start: Console module failed to load.`n`nThe Initialize-WinConfigGuiDiagnosticBox function is not available. This may indicate a corrupted installation or missing module file.`n`nPlease reinstall WinConfig or contact support.",
            "Module Load Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    # Get country info from Windows locale (no external calls)
    $countryInfo = if (Get-Command Get-SessionCountryInfo -ErrorAction SilentlyContinue) {
        Get-SessionCountryInfo
    } else {
        @{ CountryCode = "XX"; CountryName = "Unknown"; CountryFlag = "" }
    }

    # Register session action (test initiated - actual result comes from Connectivity Test Complete)
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Domain/IP/Ports Test" -Detail "Domain connectivity and port testing executed" -Category "Diagnostics" -Result "PASS" -Tier 0 -Summary "Connectivity test initiated"
    }

    # Refresh Details tab to show new action
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) {
        Update-ResultsDiagnosticsView
    }

    # Create a new form for output
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "Domain, IP & Ports Test"
    $outputForm.Size = New-Object System.Drawing.Size(1000, 800)  # Increased initial size
    $outputForm.StartPosition = "CenterScreen"
    $outputForm.MinimumSize = New-Object System.Drawing.Size(800, 600)  # Set minimum size

    # Use RichTextBox with canonical diagnostic colors (from Console.psm1)
    $outputTextBox = New-Object System.Windows.Forms.RichTextBox
    $outputTextBox.Multiline = $true
    $outputTextBox.ScrollBars = "Vertical"
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    Initialize-WinConfigGuiDiagnosticBox -Box $outputTextBox
    $outputForm.Controls.Add($outputTextBox)

    # Show the form immediately
    $outputForm.Show()
    $outputForm.Refresh()

    # Get canonical GUI colors for semantic mapping
    $guiColors = Get-WinConfigGuiColors

    # Semantic color references (map old variable names to canonical palette)
    $successColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["OK"])
    $failureColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["FAIL"])
    $warningColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["WARN"])
    $infoColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["INFO"])
    $headerColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["STEP"])
    $explanationColor = [System.Drawing.ColorTranslator]::FromHtml($guiColors["ACTION"])

    # Severity classification for operational decision-making
    $Severity = @{
        PASS = "PASS"    # Required for operation - test succeeded
        WARN = "WARN"    # Non-blocking but noteworthy
        INFO = "INFO"    # Contextual diagnostics
        FAIL = "FAIL"    # Blocks licensing/operation
    }

    # Function to write colored text to the RichTextBox (compatibility wrapper)
    function Write-ColoredLog {
        param (
            [string]$Message,
            [System.Drawing.Color]$Color = [System.Drawing.Color]::White
        )
        $outputTextBox.SelectionStart = $outputTextBox.TextLength
        $outputTextBox.SelectionLength = 0
        $outputTextBox.SelectionColor = $Color
        $outputTextBox.AppendText("$Message`r`n")
        $outputTextBox.SelectionColor = $outputTextBox.ForeColor
        $outputTextBox.ScrollToCaret()
        $outputForm.Refresh()
    }

    # Unified TCP endpoint test function - used for all connectivity tests
    function Test-TcpEndpoint {
        param (
            [string]$HostName,
            [int]$Port,
            [int]$TimeoutMs = 3000,
            [int]$Retries = 3
        )

        for ($attempt = 1; $attempt -le $Retries; $attempt++) {
            try {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($HostName, $Port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

                if ($wait) {
                    $tcpClient.EndConnect($connect)
                    $stopwatch.Stop()
                    $tcpClient.Close()
                    return @{
                        Success = $true
                        ResponseTime = $stopwatch.ElapsedMilliseconds
                        Attempts = $attempt
                        Error = $null
                    }
                } else {
                    $tcpClient.Close()
                }
            } catch {
                # Continue to next attempt
            }
            if ($attempt -lt $Retries) {
                Start-Sleep -Milliseconds 500
            }
        }

        return @{
            Success = $false
            ResponseTime = $null
            Attempts = $Retries
            Error = "Connection timed out after $Retries attempts"
        }
    }

    # Function to test domain connectivity (DNS + HTTPS)
    function Test-DomainConnectivity {
        param (
            [string]$Domain,
            [int]$TimeoutMs = 5000
        )

        # First try DNS resolution
        try {
            $dnsResult = [System.Net.Dns]::GetHostAddresses($Domain)
            if ($dnsResult.Count -eq 0) {
                return @{
                    Success = $false
                    Method = "DNS"
                    Error = "DNS resolution returned no addresses"
                }
            }
        } catch {
            return @{
                Success = $false
                Method = "DNS"
                Error = "DNS resolution failed: $($_.Exception.Message)"
            }
        }

        # Then try TCP connection to port 443
        $tcpResult = Test-TcpEndpoint -HostName $Domain -Port 443 -TimeoutMs $TimeoutMs -Retries 2
        if ($tcpResult.Success) {
            return @{
                Success = $true
                Method = "HTTPS"
                ResponseTime = $tcpResult.ResponseTime
                Attempts = $tcpResult.Attempts
            }
        }

        # Fallback: try HTTP request
        try {
            $webRequest = Invoke-WebRequest -Uri "https://$Domain" -UseBasicParsing -TimeoutSec ([math]::Ceiling($TimeoutMs / 1000)) -ErrorAction Stop
            return @{
                Success = $true
                Method = "HTTP"
                StatusCode = $webRequest.StatusCode
            }
        } catch {
            return @{
                Success = $false
                Method = "TCP"
                Error = $tcpResult.Error
                Attempts = $tcpResult.Attempts
            }
        }
    }

    # Function to get explanation for domain failure
    function Get-DomainFailureExplanation {
        param (
            [string]$Domain,
            [string]$ErrorMessage
        )
        
        $explanation = "The test attempted to ping $Domain and then tried to connect via HTTP, but both methods failed.`r`n"
        $explanation += "Possible reasons for failure:`r`n"
        $explanation += "  * DNS resolution issue - The domain name cannot be resolved to an IP address`r`n"
        $explanation += "  * Network connectivity issue - Your network connection may be limited or restricted`r`n"
        $explanation += "  * Firewall blocking - A firewall might be blocking outbound connections to this domain`r`n"
        $explanation += "  * The server might be down or not responding to requests`r`n"
        
        if ($ErrorMessage -match "could not be resolved") {
            $explanation += "`r`nSpecific issue: DNS resolution failure - The domain name could not be resolved to an IP address.`r`n"
            $explanation += "Try checking your DNS settings or try using a different DNS server."
        }
        elseif ($ErrorMessage -match "timed out") {
            $explanation += "`r`nSpecific issue: Connection timeout - The server did not respond within the expected time.`r`n"
            $explanation += "This could indicate network congestion or that the server is overloaded."
        }
        
        return $explanation
    }

    # Function to get explanation for IP failure
    function Get-IPFailureExplanation {
        param (
            [string]$IPAddress,
            [int]$Port,
            [string]$ErrorMessage
        )

        $explanation = "The test attempted to connect to port $Port on IP address $IPAddress but could not establish a connection.`r`n"
        $explanation += "Possible reasons for failure:`r`n"
        $explanation += "  * Network routing issue - There might be a problem with the route to this IP address`r`n"
        $explanation += "  * Firewall blocking - A firewall might be blocking connections to this IP/port`r`n"
        $explanation += "  * The server at this IP address might not have port $Port open`r`n"
        $explanation += "  * The server might be down or offline`r`n"

        if ($ErrorMessage -match "timed out") {
            $explanation += "`r`nSpecific issue: Connection timeout - The server did not respond within the expected time."
        }

        return $explanation
    }

    # Function to get explanation for port failure
    function Get-PortFailureExplanation {
        param (
            [string]$Server,
            [int]$Port,
            [string]$Description
        )
        
        $explanation = "The test attempted to connect to port $Port on $Server but could not establish a connection.`r`n"
        $explanation += "Possible reasons for failure:`r`n"
        $explanation += "  * The service on this port might not be running`r`n"
        $explanation += "  * A firewall might be blocking connections to this port`r`n"
        $explanation += "  * The server might be configured to only accept connections from specific IP addresses`r`n"
        
        switch ($Port) {
            7000 { $explanation += "`r`nThis port (7000) is used for BLT Server communication. Without this connection, NeurOptimal may not be able to validate licenses properly." }
            7001 { $explanation += "`r`nThis port (7001) is used for BLT Server communication. Without this connection, NeurOptimal may not be able to validate licenses properly." }
            7002 { $explanation += "`r`nThis port (7002) is used for BLT Server communication. Without this connection, NeurOptimal may not be able to validate licenses properly." }
            443 { $explanation += "`r`nThis port (443) is used for secure HTTPS connections." }
        }
        
        return $explanation
    }

    # Create a runspace pool for parallel execution (capped at 8 to avoid timeout issues on slower machines)
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, 8)
    $runspacePool.Open()
    $runspaces = @()

    # List of domains for DNS resolution quality test
    $domains = @(
        "zengar.com",
        "neuroptimal.com",
        "connectwise.com",
        "screenconnect.com",
        "zengarinst.beyondtrustcloud.com"
    )

    # Endpoints for TLS handshake test (detect SSL inspection/MITM)
    $tlsEndpoints = @(
        @{Domain = "neuroptimal.com"; Description = "NeurOptimal Main"; Critical = $true},
        @{Domain = "connectwise.com"; Description = "ConnectWise/ScreenConnect"; Critical = $true},
        @{Domain = "zengarinst.beyondtrustcloud.com"; Description = "BeyondTrust Remote Support"; Critical = $false}
    )

    # List of ports to test (CRITICAL - required for licensing)
    # Note: Only BLT ports matter for licensing - these are the actual licensing servers
    $ports = @(
        @{Server = "blt-server.neuroptimal.com"; Port = 7000; Description = "BLT Server Port 7000"; Critical = $true},
        @{Server = "blt-server.neuroptimal.com"; Port = 7001; Description = "BLT Server Port 7001"; Critical = $true},
        @{Server = "blt-server.neuroptimal.com"; Port = 7002; Description = "BLT Server Port 7002"; Critical = $true}
    )

    # ============================================================================
    # UPDATE REACHABILITY TEST - CONTRACT (REGRESSION GUARD)
    # ============================================================================
    # 1. Update delivery uses HTTPS + CDN infrastructure, NOT static port probing
    # 2. Static port probing is INVALID for update verification (different infra)
    # 3. This test is INTENTIONALLY NON-BLOCKING - update failures don't break runtime
    # 4. Update functionality is primarily verified in-application, not by this diagnostic
    # 5. Any HTTPS response (200, 204, 302, 307, 401, 403) = REACHABLE
    # 6. Timeout/connection failure = NOT REACHABLE (informational only)
    # ============================================================================
    $updateEndpoint = @{
        # Primary: Use neuroptimal.com main site as sentinel - same CDN/infrastructure class
        # This tests HTTPS reachability using system HTTP stack (WinHTTP/.NET HttpClient)
        Url = "https://neuroptimal.com"
        Description = "Update server reachability"
        # NON-BLOCKING: Failure does NOT affect overall verdict or licensing
        Critical = $false
    }

    # SNI test endpoint (for educational comparison)
    $sniTestDomain = "connectwise.com"
    $sniTestIP = "145.40.105.128"

    Write-ColoredLog "Starting comprehensive connectivity diagnostics..." $headerColor
    Write-ColoredLog "System Region: $($countryInfo.CountryName)" $infoColor
    Write-ColoredLog "Testing DNS, TLS security, licensing ports, update reachability, and system time." $infoColor
    Write-ColoredLog "--------------------------------------------------------------" $headerColor

    # Progress tracking (DNS + TLS + Ports + Time + SNI + Update = domains + tlsEndpoints + ports + 1 + 1 + 1)
    $totalTests = $domains.Count + $tlsEndpoints.Count + $ports.Count + 3
    $completedTests = 0

    # Show initial progress with dots that will animate
    $outputTextBox.SelectionColor = $infoColor
    $outputTextBox.AppendText("Running tests ")
    $outputTextBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()

    # ============================================================================
    # PHASE 0: ENVIRONMENT STABILIZATION (MANDATORY - DCTC Contract)
    # ============================================================================
    # SUCCESS DEFINITION (BINARY - ALL THREE REQUIRED):
    #   Warmed = TRUE if and only if:
    #     1. DnsConfirmed = true (GetHostAddresses returned >= 1 address)
    #     2. TcpConfirmed = true (TCP connection established)
    #     3. HttpsConfirmed = true (TLS handshake completed)
    #   Warmed = FALSE if ANY of the above failed. No partial success.
    #
    # FAILURE STAGE TRACKING:
    #   FailureStage = NONE | DNS | TCP | TLS (where the warm-up died)
    # ============================================================================

    # FIXED CONSTANTS (do not derive from runtime conditions)
    $PHASE0_TIMEOUT_MS = 5000
    $PHASE0_MAX_ATTEMPTS = 2
    $PHASE0_RETRY_DELAY_MS = 500

    $phase0Result = @{
        Warmed = $false
        Timestamp = $null
        WarmupDomain = "neuroptimal.com"
        DnsConfirmed = $false
        TcpConfirmed = $false
        HttpsConfirmed = $false
        AttemptCount = 0
        FailureStage = "NONE"
        AttemptDetails = @()
        Error = $null
    }

    for ($warmupAttempt = 1; $warmupAttempt -le $PHASE0_MAX_ATTEMPTS; $warmupAttempt++) {
        $phase0Result.AttemptCount = $warmupAttempt

        # Per-attempt tracking
        $attemptDetail = @{
            AttemptIndex = $warmupAttempt
            DnsConfirmed = $false
            TcpConfirmed = $false
            HttpsConfirmed = $false
            FailureStage = "DNS"
            Error = $null
        }

        try {
            # Step 1: DNS resolution (REQUIRED)
            $dnsWarmup = [System.Net.Dns]::GetHostAddresses($phase0Result.WarmupDomain)
            if ($dnsWarmup.Count -gt 0) {
                $attemptDetail.DnsConfirmed = $true
                $attemptDetail.FailureStage = "TCP"

                # Step 2: TCP connection (REQUIRED)
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($phase0Result.WarmupDomain, 443, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne($PHASE0_TIMEOUT_MS, $false)

                if ($wait) {
                    $tcpClient.EndConnect($connect)
                    $attemptDetail.TcpConfirmed = $true
                    $attemptDetail.FailureStage = "TLS"

                    # Step 3: TLS handshake (REQUIRED) - using standard validation
                    # SECURITY: No cert bypass - warmup domain should have valid cert
                    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
                    $sslStream.AuthenticateAsClient($phase0Result.WarmupDomain)
                    $attemptDetail.HttpsConfirmed = $true
                    $attemptDetail.FailureStage = "NONE"
                    $sslStream.Close()
                }
                $tcpClient.Close()
            }
        } catch {
            $attemptDetail.Error = $_.Exception.Message
        }

        $phase0Result.AttemptDetails += $attemptDetail

        # SUCCESS: All three steps succeeded in THIS attempt
        if ($attemptDetail.DnsConfirmed -and $attemptDetail.TcpConfirmed -and $attemptDetail.HttpsConfirmed) {
            $phase0Result.DnsConfirmed = $true
            $phase0Result.TcpConfirmed = $true
            $phase0Result.HttpsConfirmed = $true
            $phase0Result.Warmed = $true
            $phase0Result.FailureStage = "NONE"
            $phase0Result.Timestamp = (Get-Date).ToString("o")
            break
        } else {
            # Record where it died
            $phase0Result.FailureStage = $attemptDetail.FailureStage
            $phase0Result.Error = $attemptDetail.Error
        }

        # Fixed delay before retry
        if ($warmupAttempt -lt $PHASE0_MAX_ATTEMPTS) {
            Start-Sleep -Milliseconds $PHASE0_RETRY_DELAY_MS
        }
    }

    # INVARIANT: Warmed IFF all step flags true
    if ($phase0Result.Warmed -ne ($phase0Result.DnsConfirmed -and $phase0Result.TcpConfirmed -and $phase0Result.HttpsConfirmed)) {
        $phase0Result.Warmed = $false
        $phase0Result.Error = "INVARIANT VIOLATION: Warmed state inconsistent"
    }

    # Progress indicator
    $outputTextBox.AppendText(".")
    $outputTextBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()

    # ============================================================================
    # PHASE 1: CAPABILITY DISCOVERY (READ-ONLY - DCTC Contract)
    # ============================================================================

    # DNS Resolution Quality Test - shows record count, timing, and resolution health
    foreach ($domain in $domains) {
        $powershell = [powershell]::Create().AddScript({
            param ($Domain)
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            try {
                $dnsResult = @([System.Net.Dns]::GetHostAddresses($Domain))
                $stopwatch.Stop()
                $resolveTime = $stopwatch.ElapsedMilliseconds

                if ($dnsResult.Count -eq 0) {
                    return @{
                        Domain = $Domain
                        Success = $false
                        RecordCount = 0
                        ResolveTime = $resolveTime
                        Error = "No DNS records returned"
                        Result = "FAIL"
                        Type = "DNS"
                    }
                }

                # Count IPv4 (A) and IPv6 (AAAA) records
                $ipv4Count = @($dnsResult | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).Count
                $ipv6Count = @($dnsResult | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' }).Count

                # Warn if resolution is slow (>500ms suggests DNS issues)
                $result = if ($resolveTime -gt 500) { "WARN" } else { "PASS" }

                return @{
                    Domain = $Domain
                    Success = $true
                    RecordCount = $dnsResult.Count
                    IPv4Count = $ipv4Count
                    IPv6Count = $ipv6Count
                    ResolveTime = $resolveTime
                    Result = $result
                    Type = "DNS"
                }
            } catch {
                $stopwatch.Stop()
                return @{
                    Domain = $Domain
                    Success = $false
                    RecordCount = 0
                    ResolveTime = $stopwatch.ElapsedMilliseconds
                    Error = $_.Exception.Message
                    Result = "FAIL"
                    Type = "DNS"
                }
            }
        }).AddArgument($domain)

        $powershell.RunspacePool = $runspacePool

        $runspaces += [PSCustomObject]@{
            Runspace = $powershell.BeginInvoke()
            PowerShell = $powershell
            Domain = $domain
            Type = "DNS"
        }
    }

    # TLS Handshake Test - detects SSL inspection, MITM proxies, outdated TLS
    foreach ($endpoint in $tlsEndpoints) {
        $powershell = [powershell]::Create().AddScript({
            param ($Endpoint, $DiagnosticResultEnum)
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'

            $domain = $Endpoint.Domain
            $description = $Endpoint.Description
            $critical = $Endpoint.Critical
            $timeoutMs = 10000

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($domain, 443, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne($timeoutMs, $false)

                if (-not $wait) {
                    $tcpClient.Close()
                    return @{
                        Domain = $domain
                        Description = $description
                        Success = $false
                        Error = "Connection timeout"
                        Result = if ($critical) { $DiagnosticResultEnum.FAIL } else { $DiagnosticResultEnum.WARN }
                        Type = "TLS"
                        Intercepted = $false
                    }
                }

                $tcpClient.EndConnect($connect)

                # SECURITY EXCEPTION: SSL Inspection Detection
                # This callback INTENTIONALLY accepts all certificates to:
                # 1. Retrieve the certificate for issuer inspection
                # 2. Detect corporate proxy/firewall TLS interception (MITM)
                # 3. Report when cert issuer doesn't match expected CAs
                # This is DIAGNOSTIC ONLY - no data is sent, only cert metadata is inspected.
                # DO NOT copy this pattern to other locations.
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {
                    param($sender, $cert, $chain, $errors)
                    return $true  # Accept all certs for inspection detection
                })

                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $sslStream.AuthenticateAsClient($domain)
                $stopwatch.Stop()

                $cert = $sslStream.RemoteCertificate
                $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

                # Check for SSL inspection (issuer doesn't match expected CAs)
                $issuer = $cert2.Issuer
                $subject = $cert2.Subject

                # Known legitimate issuers for these domains
                $intercepted = $false
                $interceptedBy = ""

                # Check if certificate appears to be intercepted
                # Legitimate certs usually have well-known CA issuers
                $knownCAs = @("DigiCert", "Let's Encrypt", "Sectigo", "GlobalSign", "Comodo", "GoDaddy", "Amazon", "Google Trust", "Microsoft", "Entrust")
                $isKnownCA = $false
                foreach ($ca in $knownCAs) {
                    if ($issuer -like "*$ca*") {
                        $isKnownCA = $true
                        break
                    }
                }

                if (-not $isKnownCA) {
                    $intercepted = $true
                    # Extract issuer CN for display
                    if ($issuer -match "CN=([^,]+)") {
                        $interceptedBy = $matches[1]
                    } else {
                        $interceptedBy = "Unknown proxy"
                    }
                }

                $tlsVersion = $sslStream.SslProtocol.ToString()

                $sslStream.Close()
                $tcpClient.Close()

                return @{
                    Domain = $domain
                    Description = $description
                    Success = $true
                    TlsVersion = $tlsVersion
                    HandshakeTime = $stopwatch.ElapsedMilliseconds
                    Intercepted = $intercepted
                    InterceptedBy = $interceptedBy
                    Issuer = $issuer
                    Result = if ($intercepted) { $DiagnosticResultEnum.WARN } else { $DiagnosticResultEnum.PASS }
                    Type = "TLS"
                }
            } catch {
                return @{
                    Domain = $domain
                    Description = $description
                    Success = $false
                    Error = $_.Exception.Message
                    Result = if ($critical) { $DiagnosticResultEnum.FAIL } else { $DiagnosticResultEnum.WARN }
                    Type = "TLS"
                    Intercepted = $false
                }
            }
        }).AddArgument($endpoint).AddArgument($DiagnosticResult)

        $powershell.RunspacePool = $runspacePool

        $runspaces += [PSCustomObject]@{
            Runspace = $powershell.BeginInvoke()
            PowerShell = $powershell
            Endpoint = $endpoint
            Type = "TLS"
        }
    }

    # Test ports (CRITICAL - these are required for licensing)
    foreach ($portTest in $ports) {
        $powershell = [powershell]::Create().AddScript({
            param ($PortTest)
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'

            $timeout = 5000  # 5 second timeout for ports

            # Try TCP connection up to 3 times
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcpClient.BeginConnect($PortTest.Server, $PortTest.Port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false)

                    if ($wait) {
                        $tcpClient.EndConnect($connect)
                        $stopwatch.Stop()
                        $tcpClient.Close()

                        return @{
                            Server = $PortTest.Server
                            Port = $PortTest.Port
                            Description = $PortTest.Description
                            Success = $true
                            ResponseTime = $stopwatch.ElapsedMilliseconds
                            Method = "TCP"
                            Result = "PASS"
                        }
                    } else {
                        $tcpClient.Close()
                    }
                } catch {
                    # Continue to next attempt
                }
                Start-Sleep -Milliseconds 500
            }

            # All attempts failed - FAIL result (ports are critical)
            return @{
                Server = $PortTest.Server
                Port = $PortTest.Port
                Description = $PortTest.Description
                Success = $false
                Error = "Connection timed out after 3 attempts"
                Method = "TCP"
                Result = "FAIL"
            }
        }).AddArgument($portTest)

        $powershell.RunspacePool = $runspacePool

        $runspaces += [PSCustomObject]@{
            Runspace = $powershell.BeginInvoke()
            PowerShell = $powershell
            PortTest = $portTest
            Type = "Port"
        }
    }

    # ============================================================================
    # UPDATE REACHABILITY TEST (HTTPS-based, NON-BLOCKING)
    # ============================================================================
    # This test uses the system HTTP stack (WinHTTP/.NET HttpClient) which:
    #   - Supports SNI (Server Name Indication)
    #   - Uses TLS 1.2+
    #   - Respects system proxy configuration
    #   - Follows redirects automatically
    #
    # RESULT CLASSIFICATION:
    #   REACHABLE: Any HTTP response (200, 204, 302, 307, 401, 403) = success
    #   NOT REACHABLE: Timeout, connection refused, DNS failure = informational warning
    #
    # This test is NON-BLOCKING - failure does NOT affect overall licensing verdict
    # ============================================================================
    $updatePowershell = [powershell]::Create().AddScript({
        param ($Endpoint)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $url = $Endpoint.Url
        $description = $Endpoint.Description

        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # Use Invoke-WebRequest with system HTTP stack
            # This ensures we use the same stack as real applications:
            # - SNI support
            # - TLS 1.2+ negotiation
            # - System proxy settings
            # - Redirect following
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -Method HEAD -ErrorAction Stop

            $stopwatch.Stop()

            # Any HTTP response means the endpoint is reachable
            # 200, 204, 302, 307, 401, 403 all indicate reachability
            return @{
                Url = $url
                Description = $description
                Success = $true
                StatusCode = $response.StatusCode
                ResponseTime = $stopwatch.ElapsedMilliseconds
                Method = "HTTPS"
                # NON-BLOCKING: Always INFO severity regardless of result
                Severity = "INFO"
                Type = "Update"
                Message = "Update server reachable"
            }
        } catch {
            $errorMsg = $_.Exception.Message

            # Check if this is an HTTP error response (which still means reachable)
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                # 401, 403, 404, etc. all mean the server IS reachable
                return @{
                    Url = $url
                    Description = $description
                    Success = $true
                    StatusCode = $statusCode
                    ResponseTime = -1
                    Method = "HTTPS"
                    Severity = "INFO"
                    Type = "Update"
                    Message = "Update server reachable (HTTP $statusCode)"
                }
            }

            # True connectivity failure - but NON-BLOCKING
            return @{
                Url = $url
                Description = $description
                Success = $false
                StatusCode = 0
                ResponseTime = -1
                Method = "HTTPS"
                Error = $errorMsg
                # NON-BLOCKING: Failure is informational only
                Severity = "INFO"
                Type = "Update"
                Message = "Update server not reachable from this network (non-blocking)"
            }
        }
    }).AddArgument($updateEndpoint)

    $updatePowershell.RunspacePool = $runspacePool
    $runspaces += [PSCustomObject]@{
        Runspace = $updatePowershell.BeginInvoke()
        PowerShell = $updatePowershell
        Type = "Update"
    }

    # Time Drift Check - detects clock issues that break TLS/licensing
    $timePowershell = [powershell]::Create().AddScript({
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        try {
            # Get time from HTTP header (doesn't require NTP)
            $response = Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 10 -Method HEAD
            $serverTime = [DateTime]::Parse($response.Headers.Date)
            $localTime = Get-Date
            $drift = [Math]::Abs(($localTime - $serverTime).TotalSeconds)

            # More than 60 seconds drift can cause TLS/licensing issues
            $result = if ($drift -gt 300) { "FAIL" } elseif ($drift -gt 60) { "WARN" } else { "PASS" }

            return @{
                Success = $true
                LocalTime = $localTime.ToString("yyyy-MM-dd HH:mm:ss")
                ServerTime = $serverTime.ToString("yyyy-MM-dd HH:mm:ss")
                DriftSeconds = [Math]::Round($drift, 1)
                Result = $result
                Type = "Time"
            }
        } catch {
            # Fallback - just report local time without server comparison
            return @{
                Success = $true
                LocalTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                ServerTime = "Unable to fetch"
                DriftSeconds = -1
                Result = "WARN"
                Error = "Could not verify time against server"
                Type = "Time"
            }
        }
    })

    $timePowershell.RunspacePool = $runspacePool
    $runspaces += [PSCustomObject]@{
        Runspace = $timePowershell.BeginInvoke()
        PowerShell = $timePowershell
        Type = "Time"
    }

    # SNI vs Direct-IP Explanation Test - educational comparison
    $sniPowershell = [powershell]::Create().AddScript({
        param ($Domain, $DirectIP)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        # RESULT SEMANTICS (clear distinction between failure modes):
        # - TcpOk: TCP socket connected successfully
        # - TlsOk: TLS handshake completed (regardless of cert validation)
        # - CertOk: Certificate validated successfully (CN/SAN match, chain trusted)
        # - Error: Human-readable error message for the failure point

        $timeoutMs = 5000

        # Test 1: HTTPS with domain name (SNI)
        $domainTcpOk = $false
        $domainTlsOk = $false
        $domainCertOk = $false
        $domainError = ""
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($Domain, 443, $null, $null)
            if ($connect.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
                $tcpClient.EndConnect($connect)
                $domainTcpOk = $true  # TCP connected

                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
                try {
                    $sslStream.AuthenticateAsClient($Domain)
                    $domainTlsOk = $true   # TLS handshake completed
                    $domainCertOk = $true  # Cert validated (no exception)
                }
                catch [System.Security.Authentication.AuthenticationException] {
                    # TLS started but cert failed
                    $domainTlsOk = $true  # TLS handshake initiated
                    $domainError = "Certificate error: $($_.Exception.Message)"
                }
                $sslStream.Close()
            } else {
                $domainError = "TCP connection timeout"
            }
            $tcpClient.Close()
        } catch {
            if (-not $domainTcpOk) {
                $domainError = "TCP error: $($_.Exception.Message)"
            } else {
                $domainError = "TLS error: $($_.Exception.Message)"
            }
        }

        # Test 2: HTTPS to direct IP (no SNI) - WITHOUT cert validation bypass
        # SECURITY: We test TCP+TLS handshake without bypassing certificate validation.
        # Certificate will fail (expected - IP won't match cert CN), but TLS handshake confirms connectivity.
        $directIPTcpOk = $false
        $directIPTlsOk = $false
        $directIPCertOk = $false  # Expected to be false (IP won't match CN)
        $directIPError = ""
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($DirectIP, 443, $null, $null)
            if ($connect.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
                $tcpClient.EndConnect($connect)
                $directIPTcpOk = $true  # TCP connected

                # Use standard SSL stream with default validation
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
                try {
                    $sslStream.AuthenticateAsClient($DirectIP)
                    $directIPTlsOk = $true   # TLS handshake completed
                    $directIPCertOk = $true  # Cert validated (unexpected for IP test)
                }
                catch [System.Security.Authentication.AuthenticationException] {
                    # Expected: certificate won't match IP address
                    # But TLS handshake succeeded (we got far enough to check cert)
                    $directIPTlsOk = $true
                    # Not an error for this test - cert mismatch is expected
                }
                $sslStream.Close()
            } else {
                $directIPError = "TCP connection timeout"
            }
            $tcpClient.Close()
        } catch {
            if (-not $directIPTcpOk) {
                $directIPError = "TCP error: $($_.Exception.Message)"
            } else {
                $directIPError = "TLS error: $($_.Exception.Message)"
            }
        }

        return @{
            Domain = $Domain
            DirectIP = $DirectIP
            # Domain test results (clear semantics)
            DomainTcpOk = $domainTcpOk
            DomainTlsOk = $domainTlsOk
            DomainCertOk = $domainCertOk
            DomainError = $domainError
            # Direct IP test results (clear semantics)
            DirectIPTcpOk = $directIPTcpOk
            DirectIPTlsOk = $directIPTlsOk
            DirectIPCertOk = $directIPCertOk  # Expected false (IP won't match CN)
            DirectIPError = $directIPError
            # Legacy compatibility (DomainSuccess = full success, DirectIPSuccess = TLS worked)
            DomainSuccess = ($domainTcpOk -and $domainTlsOk -and $domainCertOk)
            DirectIPSuccess = ($directIPTcpOk -and $directIPTlsOk)  # Cert mismatch expected, not failure
            DirectIPCertMismatch = ($directIPTcpOk -and $directIPTlsOk -and -not $directIPCertOk)
            Type = "SNI"
            # This is purely educational - not a pass/fail
            Severity = "INFO"
        }
    }).AddArgument($sniTestDomain).AddArgument($sniTestIP)

    $sniPowershell.RunspacePool = $runspacePool
    $runspaces += [PSCustomObject]@{
        Runspace = $sniPowershell.BeginInvoke()
        PowerShell = $sniPowershell
        Type = "SNI"
    }

    # Create collections to store results by type
    $dnsResults = @()
    $tlsResults = @()
    $portResults = @()
    $timeResult = $null
    $sniResult = $null
    $updateResult = $null
    
    # Process results as they complete
    $pendingRunspaces = $runspaces.Clone()
    
    while ($pendingRunspaces.Count -gt 0) {
        # Find completed runspaces
        $justCompleted = @($pendingRunspaces | Where-Object { $_.Runspace.IsCompleted })
        
        # Remove completed runspaces from pending collection
        $pendingRunspaces = @($pendingRunspaces | Where-Object { -not $_.Runspace.IsCompleted })
        
        # Process completed runspaces
        foreach ($runspace in $justCompleted) {
            $result = $runspace.PowerShell.EndInvoke($runspace.Runspace)
            $runspace.PowerShell.Dispose()

            # Store result in appropriate collection based on type
            switch ($runspace.Type) {
                "DNS" { $dnsResults += $result }
                "TLS" { $tlsResults += $result }
                "Port" { $portResults += $result }
                "Time" { $timeResult = $result }
                "SNI" { $sniResult = $result }
                "Update" { $updateResult = $result }
            }

            # Update progress - add a dot for each completed test
            $completedTests++
            $outputTextBox.SelectionColor = $infoColor
            $outputTextBox.AppendText(".")
            $outputTextBox.ScrollToCaret()
            [System.Windows.Forms.Application]::DoEvents()
        }

        # If there are still pending runspaces, wait a bit
        if ($pendingRunspaces.Count -gt 0) {
            Start-Sleep -Milliseconds 100
        }
    }
    
    # Clean up runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()

    # Add completion indicator
    $outputTextBox.SelectionColor = $successColor
    $outputTextBox.AppendText(" Done!`n")
    $outputTextBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()

    # ============================================================================
    # VERDICT FREEZE BARRIER (DCTC Contract)
    # ============================================================================
    # At this point:
    #   - All probes have reported (runspace pool is closed and disposed)
    #   - No late-arriving async results can mutate state
    #   - Evidence collections are now effectively immutable
    #
    # The verdict resolution below is a PURE FUNCTION:
    #   - No network calls
    #   - No mutation of evidence after this point
    #   - Same inputs -> same output (deterministic)
    # ============================================================================

    # ============================================================================
    # PHASE 3: VERDICT RESOLUTION (PURE FUNCTION - DCTC Contract)
    # ============================================================================
    # VERDICT STATES (internal names for precise reasoning):
    #   - PASS: all required probes PASS (positive evidence)
    #   - FAIL: >= 1 required probe FAIL with complete evidence (negative evidence)
    #   - INSUFFICIENT_SIGNAL: Phase 0 incomplete, probe not executed, or evidence incomplete
    #
    # UI MAPPING (external display):
    #   PASS -> "OK" / "FULLY OPERATIONAL"
    #   FAIL -> "BLOCKED" / "PORTS BLOCKED"
    #   INSUFFICIENT_SIGNAL -> "UNDETERMINED" (retest recommended)
    # ============================================================================

    # FREEZE EVIDENCE: Calculate all derived values once (immutable after this point)
    $dnsSuccessCount = ($dnsResults | Where-Object { $_.Success -eq $true }).Count
    $tlsSuccessCount = ($tlsResults | Where-Object { $_.Success -eq $true }).Count
    $portSuccessCount = ($portResults | Where-Object { $_.Success -eq $true }).Count
    $dnsOK = $dnsSuccessCount -eq $domains.Count
    $tlsOK = $tlsSuccessCount -eq $tlsEndpoints.Count
    $portsOK = $portSuccessCount -eq $ports.Count
    $timeOK = $timeResult -and $timeResult.Result -ne $DiagnosticResult.FAIL
    $tlsIntercepted = ($tlsResults | Where-Object { $_.Intercepted -eq $true }).Count -gt 0

    # DCTC: Track NOT_RUN port results (probes with incomplete evidence)
    $portInsufficientCount = ($portResults | Where-Object { $_.Result -eq $DiagnosticResult.NOT_RUN }).Count
    $portFailedCount = ($portResults | Where-Object { $_.Result -eq $DiagnosticResult.FAIL }).Count
    $portsInsufficientSignal = $portInsufficientCount -gt 0
    $portsConfirmedFailed = $portFailedCount -gt 0 -and $portInsufficientCount -eq 0

    # DCTC: Evidence contract - only emit FAIL if all preconditions met
    $phase0Complete = $phase0Result.Warmed
    $allProbesExecuted = $portResults.Count -eq $ports.Count
    $evidenceComplete = $phase0Complete -and $allProbesExecuted -and -not $portsInsufficientSignal

    # ============================================================================
    # COLD-START INVARIANT ASSERTION (DCTC Contract)
    # ============================================================================
    # First run after launch may only emit PASS or INSUFFICIENT_SIGNAL.
    # If Phase 0 did not complete, we MUST NOT emit FAIL regardless of probe results.
    # This prevents false negatives from cold-start timing issues.
    # ============================================================================
    $coldStartViolation = (-not $phase0Complete) -and ($portFailedCount -gt 0)
    if ($coldStartViolation) {
        # INVARIANT ENFORCEMENT: Reclassify failed probes as insufficient signal
        # This is a safety net - probe logic should already handle this, but we enforce here
        $portsConfirmedFailed = $false
        $portsInsufficientSignal = $true
    }

    # Backward compatibility alias for display logic
    $portsInconclusive = $portsInsufficientSignal

    # === TIME DRIFT CHECK ===
    Write-ColoredLog "`nSYSTEM TIME CHECK:" $headerColor
    Write-ColoredLog "Verifies system clock accuracy - incorrect time breaks TLS certificates and licensing." $infoColor
    if ($timeResult) {
        if ($timeResult.DriftSeconds -ge 0) {
            $timeIndicator = Switch-DiagnosticResult -Result $timeResult.Result -Cases @{
                'PASS'    = { "[OK]" }
                'WARN'    = { "[!!]" }
                'FAIL'    = { "[FAIL]" }
                'NOT_RUN' = { "[SKIP]" }
            }
            $timeColor = Switch-DiagnosticResult -Result $timeResult.Result -Cases @{
                'PASS'    = { $successColor }
                'WARN'    = { $warningColor }
                'FAIL'    = { $failureColor }
                'NOT_RUN' = { $infoColor }
            }
            Write-ColoredLog "$timeIndicator System time within acceptable range (drift: $($timeResult.DriftSeconds)s)" $timeColor
        } else {
            Write-ColoredLog "[!!] Could not verify time against server" $warningColor
        }
        # Additional guidance based on result
        Switch-DiagnosticResult -Result $timeResult.Result -Cases @{
            'PASS'    = { }  # No additional message needed
            'WARN'    = { Write-ColoredLog "    System clock may be slightly off - consider syncing" $warningColor }
            'FAIL'    = {
                Write-ColoredLog "    System clock is significantly off - this can break TLS and licensing!" $failureColor
                Write-ColoredLog "    Fix: Settings > Time & Language > Sync now" $explanationColor
            }
            'NOT_RUN' = { }  # No additional message needed
        }
    }

    # === DNS RESOLUTION QUALITY ===
    Write-ColoredLog "`nDNS RESOLUTION QUALITY:" $headerColor
    Write-ColoredLog "Tests if domain names resolve correctly - detects DNS issues, captive portals, and filtering." $infoColor
    foreach ($result in $dnsResults) {
        if ($result.Success) {
            $recordInfo = "$($result.RecordCount) records"
            $timeInfo = "$($result.ResolveTime) ms"
            $indicator = Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS'    = { "[OK]" }
                'WARN'    = { "[!!]" }
                'FAIL'    = { "[FAIL]" }
                'NOT_RUN' = { "[SKIP]" }
            }
            $color = Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS'    = { $successColor }
                'WARN'    = { $warningColor }
                'FAIL'    = { $failureColor }
                'NOT_RUN' = { $infoColor }
            }
            Write-ColoredLog "$indicator $($result.Domain) resolved ($recordInfo, $timeInfo)" $color
            Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS'    = { }
                'WARN'    = { Write-ColoredLog "    Slow DNS resolution detected" $warningColor }
                'FAIL'    = { }
                'NOT_RUN' = { }
            }
        } else {
            Write-ColoredLog "[FAIL] $($result.Domain) - $($result.Error)" $failureColor
        }
    }
    $dnsFailures = $dnsResults | Where-Object { -not $_.Success }
    if ($dnsFailures.Count -gt 0) {
        Write-ColoredLog "`nDNS failures may indicate:" $explanationColor
        Write-ColoredLog "  * DNS server issues or misconfiguration" $explanationColor
        Write-ColoredLog "  * Captive portal (hotel/airport WiFi)" $explanationColor
        Write-ColoredLog "  * Network filtering or DNS poisoning" $explanationColor
    }

    # === TLS SECURITY CHECK ===
    Write-ColoredLog "`nTLS SECURITY CHECK:" $headerColor
    Write-ColoredLog "Performs secure handshake - detects SSL inspection, MITM proxies, and outdated encryption." $infoColor
    foreach ($result in $tlsResults) {
        if ($result.Success) {
            if ($result.Intercepted) {
                Write-ColoredLog "[!!] $($result.Domain) - TLS INTERCEPTED" $warningColor
                Write-ColoredLog "    Certificate issued by: $($result.InterceptedBy)" $warningColor
                Write-ColoredLog "    This indicates SSL inspection (corporate proxy/antivirus)" $explanationColor
            } else {
                Write-ColoredLog "[OK] $($result.Domain) - $($result.TlsVersion) ($($result.HandshakeTime) ms)" $successColor
            }
        } else {
            $indicator = Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS'    = { "[OK]" }
                'WARN'    = { "[!!]" }
                'FAIL'    = { "[FAIL]" }
                'NOT_RUN' = { "[??]" }
            }
            $color = Switch-DiagnosticResult -Result $result.Result -Cases @{
                'PASS'    = { $successColor }
                'WARN'    = { $warningColor }
                'FAIL'    = { $failureColor }
                'NOT_RUN' = { $infoColor }
            }
            Write-ColoredLog "$indicator $($result.Domain) - $($result.Error)" $color
        }
    }
    if ($tlsIntercepted) {
        Write-ColoredLog "`nSSL inspection detected - connections are being decrypted by a proxy." $warningColor
        Write-ColoredLog "This may cause certificate errors in some applications." $explanationColor
    }

    # === PORT CONNECTIVITY ===
    Write-ColoredLog "`nLICENSING PORT CHECK:" $headerColor
    Write-ColoredLog "Checks required ports for NeurOptimal licensing - blocked ports prevent activation." $infoColor

    # DCTC: Show Phase 0 warm-up status if it failed
    if (-not $phase0Complete) {
        Write-ColoredLog "[!!] Environment warm-up incomplete - port verdicts may be unreliable" $warningColor
        Write-ColoredLog "    Warm-up attempted $($phase0Result.AttemptCount) time(s)" $explanationColor
    }

    foreach ($result in $portResults) {
        # Use Switch-DiagnosticResult for exhaustive handling
        Switch-DiagnosticResult -Result $result.Result -Cases @{
            'PASS'    = {
                # DCTC UI Mapping: PASS -> "OK"
                Write-ColoredLog "[OK] $($result.Server):$($result.Port) - OPEN ($($result.Description))" $successColor
            }
            'WARN'    = {
                Write-ColoredLog "[!!] $($result.Server):$($result.Port) - WARNING ($($result.Description))" $warningColor
            }
            'FAIL'    = {
                # DCTC UI Mapping: FAIL -> "BLOCKED" (only with evidence)
                Write-ColoredLog "[FAIL] $($result.Server):$($result.Port) - BLOCKED ($($result.Description))" $failureColor
                if ($result.Attempts -and $result.Attempts.Count -gt 0) {
                    Write-ColoredLog "    All $($result.Attempts.Count) attempts failed" $explanationColor
                }
            }
            'NOT_RUN' = {
                # DCTC UI Mapping: NOT_RUN -> "UNDETERMINED"
                Write-ColoredLog "[??] $($result.Server):$($result.Port) - UNDETERMINED ($($result.Description))" $warningColor
                if ($result.Attempts -and $result.Attempts.Count -gt 0) {
                    $attemptSummary = ($result.Attempts | ForEach-Object { "$($_.result)" }) -join ", "
                    Write-ColoredLog "    Attempts: $attemptSummary" $explanationColor
                }
            }
        }
    }

    # DCTC: Different messaging based on evidence quality
    $portFailures = $portResults | Where-Object { $_.Result -eq $DiagnosticResult.FAIL }
    $portInsufficient = $portResults | Where-Object { $_.Result -eq $DiagnosticResult.NOT_RUN }

    if ($portInsufficient.Count -gt 0) {
        Write-ColoredLog "`nSome port checks were inconclusive:" $warningColor
        Write-ColoredLog "  * Environment may not have stabilized (cold start)" $explanationColor
        Write-ColoredLog "  * Re-run the test to get a definitive result" $explanationColor
        Write-ColoredLog "  * DCTC: No remediation steps shown for inconclusive results" $infoColor
    } elseif ($portFailures.Count -gt 0) {
        Write-ColoredLog "`nBlocked ports will prevent NeurOptimal licensing:" $failureColor
        Write-ColoredLog "  * Firewall may be blocking specific ports" $explanationColor
        Write-ColoredLog "  * Required: ports 7000-7002 (BLT Server licensing)" $explanationColor
    }

    # === UPDATE REACHABILITY (HTTPS-based, NON-BLOCKING) ===
    # CONTRACT: This section is INFORMATIONAL ONLY and MUST NOT affect the licensing verdict.
    # Update reachability is separate from licensing - the app can function without updates.
    Write-ColoredLog "`nUPDATE SERVER REACHABILITY (Informational):" $headerColor
    Write-ColoredLog "Tests if update infrastructure is reachable - does not affect licensing or runtime." $infoColor

    if ($updateResult) {
        if ($updateResult.Success) {
            $responseInfo = if ($updateResult.ResponseTime -gt 0) { " ($($updateResult.ResponseTime) ms)" } else { "" }
            Write-ColoredLog "[OK] $($updateResult.Message)$responseInfo" $successColor
        } else {
            # NON-BLOCKING: Show as informational, not as failure
            Write-ColoredLog "[i] $($updateResult.Message)" $infoColor
            if ($updateResult.Error) {
                Write-ColoredLog "    Note: $($updateResult.Error)" $explanationColor
            }
            Write-ColoredLog "    This does not affect NeurOptimal licensing or operation." $successColor
        }
    } else {
        Write-ColoredLog "[i] Update reachability test did not complete" $infoColor
    }

    # === SNI vs DIRECT IP EXPLANATION (INFORMATIONAL ONLY - DCTC Contract) ===
    # DCTC: This section is purely observational and MUST NOT influence the licensing verdict.
    # Direct-IP blocking is expected behavior on many networks and does not affect operation.
    Write-ColoredLog "`nNETWORK BEHAVIOR ANALYSIS (Informational):" $headerColor
    Write-ColoredLog "Compares domain vs direct IP access - educational context only, not part of verdict." $infoColor
    if ($sniResult) {
        if ($sniResult.DomainSuccess) {
            Write-ColoredLog "[i] HTTPS with domain name ($($sniResult.Domain)) - succeeds" $infoColor
        } else {
            Write-ColoredLog "[i] HTTPS with domain name ($($sniResult.Domain)) - blocked" $infoColor
        }
        if ($sniResult.DirectIPSuccess) {
            Write-ColoredLog "[i] HTTPS to direct IP ($($sniResult.DirectIP)) - succeeds" $infoColor
        } else {
            Write-ColoredLog "[i] HTTPS to direct IP ($($sniResult.DirectIP)) - blocked" $infoColor
        }

        # Educational explanation - DCTC: This is context only, not a verdict signal
        if ($sniResult.DomainSuccess -and -not $sniResult.DirectIPSuccess) {
            Write-ColoredLog "`n[i] Network behavior: Domain-based HTTPS allowed, direct IP blocked." $infoColor
            Write-ColoredLog "    This is normal and does not affect NeurOptimal licensing." $successColor
        } elseif (-not $sniResult.DomainSuccess -and -not $sniResult.DirectIPSuccess) {
            Write-ColoredLog "`n[i] Network behavior: Both domain and direct IP blocked on test endpoint." $infoColor
            Write-ColoredLog "    Note: This observation is separate from licensing port results above." $infoColor
        }
    }

    # === DECISION-ORIENTED SUMMARY (Context-Aware Action Model) ===
    Write-ColoredLog "`n==============================================================" $headerColor

    # Build evidence for context-aware action resolution (FROZEN - do not mutate)
    $evidence = @{
        DNS               = $dnsOK
        Ports             = $portsOK
        Time              = $timeOK
        TLSIntercepted    = $tlsIntercepted
        Phase0Complete    = $phase0Complete
        EvidenceComplete  = $evidenceComplete
        PortsInsufficientSignal = $portsInsufficientSignal
    }

    # ============================================================================
    # DCTC Verdict Logic (Pure Function - Same inputs -> Same output)
    # ============================================================================
    # PASS: all required probes PASS
    # FAIL: >= 1 required probe FAIL (with complete evidence)
    # INSUFFICIENT_SIGNAL: Phase 0 incomplete, probe not executed, or evidence incomplete
    # ============================================================================

    # Determine overall result status per DCTC contract
    $overallStatus = if (-not $phase0Complete -or $portsInsufficientSignal) {
        # DCTC: Cannot emit FAIL if preconditions unmet
        "INSUFFICIENT_SIGNAL"
    } elseif ($dnsOK -and $portsOK -and $timeOK) {
        "PASS"
    } elseif ($evidenceComplete -and ($portsConfirmedFailed -or -not $timeOK)) {
        # DCTC: Only FAIL with complete evidence
        "FAIL"
    } elseif (-not $dnsOK) {
        "WARN"
    } else {
        "INSUFFICIENT_SIGNAL"
    }

    # Boundary translation: INSUFFICIENT_SIGNAL is DCTC-contract vocabulary only.
    # The resolver and ledger speak the DiagnosticResult set, where NOT_RUN replaces it
    # (their ValidateSet rejects the DCTC token - passing it raw crashes the click handler).
    $ledgerStatus = if ($overallStatus -eq "INSUFFICIENT_SIGNAL") { $DiagnosticResult.NOT_RUN } else { $overallStatus }

    # Use Context-Aware Action resolver if available, otherwise fallback to inline logic
    $actionResult = $null
    if (Get-Command Resolve-WinConfigContextAwareActions -ErrorAction SilentlyContinue) {
        $actionResult = Resolve-WinConfigContextAwareActions -Category "Diagnostics" -Result $ledgerStatus -Evidence $evidence
    }

    # Determine display values from action result or fallback
    $overallResult = ""
    $overallColor = $successColor
    $operationalStatus = ""

    if ($actionResult) {
        # Use values from Context-Aware Action resolver
        $overallResult = $actionResult.Classification.ToUpper()
        $operationalStatus = switch ($actionResult.OperationalImpact) {
            "Blocking"      { "Action required before NeurOptimal can function." }
            "NonBlocking"   { "Minor issue detected - operation should continue normally." }
            "Informational" { "All systems operational." }
            default         { "" }
        }
        $overallColor = switch ($actionResult.Status) {
            "PASS" { $successColor }
            "WARN" { $warningColor }
            "FAIL" { $failureColor }
            "NOT_RUN" { $warningColor }
            default { $infoColor }
        }
    } else {
        # Fallback: inline decision matrix (DCTC-compliant)
        if ($overallStatus -eq "INSUFFICIENT_SIGNAL") {
            # DCTC: INSUFFICIENT_SIGNAL -> "UNDETERMINED" in UI
            $overallResult = "UNDETERMINED"
            if (-not $phase0Complete) {
                $operationalStatus = "Environment warm-up failed - retest recommended."
            } elseif ($portsInsufficientSignal) {
                $operationalStatus = "Port check results inconclusive - retest recommended."
            } else {
                $operationalStatus = "Test did not complete - retest recommended."
            }
            $overallColor = $warningColor
        }
        elseif ($dnsOK -and $portsOK -and $timeOK) {
            if ($tlsIntercepted) {
                $overallResult = "OPERATIONAL (SSL INSPECTED)"
                $operationalStatus = "Services reachable but TLS is being intercepted."
                $overallColor = $warningColor
            } else {
                $overallResult = "FULLY OPERATIONAL"
                $operationalStatus = "All connectivity tests passed."
                $overallColor = $successColor
            }
        }
        elseif ($dnsOK -and $portsOK -and -not $timeOK) {
            $overallResult = "TIME SYNC REQUIRED"
            $operationalStatus = "System clock is off - fix before using NeurOptimal."
            $overallColor = $failureColor
        }
        elseif (-not $dnsOK -and $portsOK) {
            $overallResult = "DNS ISSUE DETECTED"
            $operationalStatus = "DNS resolution failing - check network connection."
            $overallColor = $warningColor
        }
        elseif ($portsConfirmedFailed) {
            # DCTC: Only show "PORTS BLOCKED" with confirmed evidence
            $overallResult = "PORTS BLOCKED"
            $operationalStatus = "Required licensing ports are blocked (confirmed)."
            $overallColor = $failureColor
        }
        else {
            $overallResult = "CONNECTIVITY ISSUES"
            $operationalStatus = "Multiple issues detected - review results above."
            $overallColor = $failureColor
        }
    }

    Write-ColoredLog "OVERALL RESULT: $overallResult" $overallColor
    Write-ColoredLog ""
    Write-ColoredLog $operationalStatus $overallColor

    # Status indicators summary - DCTC UI mapping
    Write-ColoredLog ""
    Write-ColoredLog "$(if ($dnsOK) { '[OK]' } else { '[FAIL]' }) DNS resolution" $(if ($dnsOK) { $successColor } else { $failureColor })
    Write-ColoredLog "$(if ($tlsOK) { '[OK]' } else { '[!!]' }) TLS security" $(if ($tlsOK -and -not $tlsIntercepted) { $successColor } elseif ($tlsIntercepted) { $warningColor } else { $failureColor })

    # DCTC: Port status indicator must distinguish OK/BLOCKED/UNDETERMINED
    $portIndicator = if ($portsOK) { '[OK]' } elseif ($portsInsufficientSignal) { '[??]' } else { '[FAIL]' }
    $portLabel = if ($portsOK) { 'Licensing ports' } elseif ($portsInsufficientSignal) { 'Licensing ports (undetermined)' } else { 'Licensing ports' }
    $portColor = if ($portsOK) { $successColor } elseif ($portsInsufficientSignal) { $warningColor } else { $failureColor }
    Write-ColoredLog "$portIndicator $portLabel" $portColor

    Write-ColoredLog "$(if ($timeOK) { '[OK]' } else { '[FAIL]' }) System time" $(if ($timeOK) { $successColor } else { $failureColor })

    # Update reachability - NON-BLOCKING, purely informational
    $updateIndicator = if ($updateResult -and $updateResult.Success) { '[OK]' } else { '[i]' }
    $updateLabel = if ($updateResult -and $updateResult.Success) { 'Updates (reachable)' } else { 'Updates (informational)' }
    $updateColor = if ($updateResult -and $updateResult.Success) { $successColor } else { $infoColor }
    Write-ColoredLog "$updateIndicator $updateLabel" $updateColor

    # Tiered recommendations (Context-Aware Action Contract)
    # Principle: Always recommend the lowest-cost, lowest-authority action first
    # Tier 0: No Action | Tier 1: Local User Action | Tier 2: Alternate Context
    # Tier 3: Guided Technical Step | Tier 4: Local IT/Admin | Tier 5: External (ISP/Vendor)
    Write-ColoredLog "`nRECOMMENDED NEXT STEPS:" $headerColor

    if ($actionResult -and $actionResult.Recommendations.Count -gt 0) {
        # Display tier-aware recommendations from the resolver
        $tierLabel = if (Get-Command Get-WinConfigActionTierLabel -ErrorAction SilentlyContinue) {
            Get-WinConfigActionTierLabel -Tier $actionResult.MinimumTier
        } else { "" }

        if ($tierLabel -and $actionResult.MinimumTier -gt 0) {
            Write-ColoredLog "Action Level: $tierLabel" $infoColor
        }

        foreach ($rec in $actionResult.Recommendations) {
            # Determine color based on recommendation content
            $recColor = if ($rec -match "^No action required") { $successColor }
                        elseif ($rec -match "Escalate|IT|ISP") { $infoColor }
                        elseif ($rec -match "CRITICAL|blocked|fail") { $failureColor }
                        else { $explanationColor }
            Write-ColoredLog "* $rec" $recColor
        }
    } else {
        # Fallback: inline recommendations (tiered, lowest-cost first)
        # DCTC: Never show remediation steps on INSUFFICIENT_SIGNAL
        if ($overallStatus -eq "INSUFFICIENT_SIGNAL") {
            Write-ColoredLog "* Re-run this test to get a definitive result" $warningColor
            Write-ColoredLog "* Wait a few seconds for network to stabilize before retesting" $explanationColor
            Write-ColoredLog "* DCTC: No remediation steps shown until result is confirmed" $infoColor
        }
        elseif ($dnsOK -and $portsOK -and $timeOK) {
            # Tier 0: No Action Required
            Write-ColoredLog "* No action required - NeurOptimal should function normally" $successColor
            if ($tlsIntercepted) {
                Write-ColoredLog "* SSL inspection detected but does not block operation" $warningColor
                Write-ColoredLog "* If connection issues occur, try a mobile hotspot to bypass proxy" $explanationColor
            }
            Write-ColoredLog "* Escalate only if NeurOptimal reports connectivity errors despite this result" $infoColor
        }
        elseif (-not $timeOK -and $evidenceComplete) {
            # Tier 1: Local User Action (only with confirmed evidence)
            Write-ColoredLog "* Sync system clock: Settings > Time & Language > Date & time > Sync now" $explanationColor
            Write-ColoredLog "* If sync fails, check internet connection and retry" $explanationColor
            Write-ColoredLog "* Incorrect system time breaks TLS certificates and licensing" $explanationColor
            Write-ColoredLog "* No escalation needed - this is a local fix" $infoColor
        }
        elseif (-not $dnsOK) {
            # Tier 1-2: Local Action then Alternate Context
            Write-ColoredLog "* Restart modem/router if you have access to it" $explanationColor
            Write-ColoredLog "* Check for captive portal: open a browser and see if a login page appears" $explanationColor
            Write-ColoredLog "* Try a different network (mobile hotspot) to test if DNS works elsewhere" $explanationColor
            Write-ColoredLog "* Run: ipconfig /flushdns in Command Prompt (Start > type 'cmd' > Enter)" $explanationColor
        }
        elseif ($portsConfirmedFailed) {
            # Tier 2: Alternate Context first, escalation only with CONFIRMED evidence
            Write-ColoredLog "* Try a different network (mobile hotspot) to verify if ports are blocked locally" $explanationColor
            Write-ColoredLog "* Restart modem/router if you have access - some routers block unusual ports by default" $explanationColor
            Write-ColoredLog "* If mobile hotspot works: the local network is blocking ports 7000-7002" $infoColor
            Write-ColoredLog "* Required ports: 7000, 7001, 7002 (BLT Server licensing)" $infoColor
        }
    }

    Write-ColoredLog "`n==============================================================" $headerColor
    Write-ColoredLog "Test completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $infoColor
    Write-ColoredLog "`nYou can now close this window." $infoColor

    # Update session action with classification, tier, and result
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        $result = if ($actionResult) { $actionResult.Status } else { $ledgerStatus }
        $tier = if ($actionResult) { $actionResult.MinimumTier } else { 0 }
        $summary = if ($actionResult) { $actionResult.Classification } else { $overallResult }
        $detail = "$overallResult - DNS: $dnsSuccessCount/$($domains.Count), TLS: $tlsSuccessCount/$($tlsEndpoints.Count), Ports: $portSuccessCount/$($ports.Count)"

        # Build evidence for logging (DCTC audit trail - append-only)
        $logEvidence = @{
            Source = "ActionTiers"
            Country = $countryInfo
            DNS = $dnsOK
            Ports = $portsOK
            Time = $timeOK
            TLSIntercepted = $tlsIntercepted
            DnsResults = "$dnsSuccessCount/$($domains.Count)"
            TlsResults = "$tlsSuccessCount/$($tlsEndpoints.Count)"
            PortResults = "$portSuccessCount/$($ports.Count)"
            # DCTC Audit Fields (immutable after freeze barrier)
            Phase0Warmed = $phase0Complete
            Phase0Timestamp = $phase0Result.Timestamp
            EvidenceComplete = $evidenceComplete
            PortsInsufficientSignal = $portsInsufficientSignal
            PortsConfirmedFailed = $portsConfirmedFailed
            VerdictType = $overallStatus
            ColdStartViolation = $coldStartViolation
            # Update reachability (NON-BLOCKING, informational only - does NOT affect verdict)
            UpdateReachable = if ($updateResult) { $updateResult.Success } else { $null }
        }

        # Include country context in summary for operator visibility
        $countrySummary = "$($countryInfo.CountryFlag) $($countryInfo.CountryName) - $summary"
        Register-WinConfigSessionAction -Action "Connectivity Test Complete" -Detail $detail -Category "Diagnostics" -Result $result -Tier $tier -Summary $countrySummary -Evidence $logEvidence
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
    }

    # Adjust window size based on content
    $textHeight = $outputTextBox.GetPositionFromCharIndex($outputTextBox.TextLength).Y + 50
    $desiredHeight = [Math]::Min([Math]::Max($textHeight, 600), 900)
    $outputForm.Height = $desiredHeight
}
        "Open Speedtest.net" = {
            if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                Register-WinConfigSessionAction -Action "Speedtest Launch" -Detail "Speedtest.net opened in browser" -Category "Diagnostics" -Result "PASS" -Tier 0 -Summary "Browser launched"
            }
            if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
            Start-Process "https://www.speedtest.net/"
        }

        # =========================================================================
        # NETWORK TOOLS (Mutating - Dry Run supported)
        # =========================================================================
        "Network Reset" = {
            # This is a mutating tool - actual execution happens here
            # Dry Run is handled separately by the Dry Run button
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Network Reset requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "This will reset TCP/IP stack, Winsock catalog, and DNS cache.`n`nA system restart is recommended after this operation.`n`nContinue?",
                "Confirm Network Reset",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            try {
                netsh int ip reset | Out-Null
                netsh winsock reset | Out-Null
                ipconfig /flushdns | Out-Null

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "Network Reset" -Detail "TCP/IP, Winsock, DNS reset" -Category "AdminChange" -Result "PASS" -Tier 3 -Summary "Network stack reset complete"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show("Network reset complete.`n`nPlease restart your computer for changes to take full effect.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "Network Reset" -Detail "Reset failed: $($_.Exception.Message)" -Category "AdminChange" -Result "FAIL" -Tier 4 -Summary "Network reset failed"
                }
                [System.Windows.Forms.MessageBox]::Show("Network reset failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        "Flush DNS Cache" = {
            try {
                ipconfig /flushdns | Out-Null
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "DNS Flush" -Detail "DNS resolver cache cleared" -Category "AdminChange" -Result "PASS" -Tier 1 -Summary "DNS cache flushed"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show("DNS resolver cache has been flushed.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "DNS Flush" -Detail "Flush failed: $($_.Exception.Message)" -Category "AdminChange" -Result "FAIL" -Tier 2 -Summary "DNS flush failed"
                }
                [System.Windows.Forms.MessageBox]::Show("DNS flush failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        # =========================================================================
        # SERVICE RESTART TOOLS (Mutating - Dry Run supported)
        # =========================================================================
        "Restart Audio Service" = {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Restarting services requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            try {
                Restart-Service -Name "Audiosrv" -Force -ErrorAction Stop
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "Audio Service Restart" -Detail "Audiosrv restarted" -Category "AdminChange" -ToolCategory "Audio" -Result "PASS" -Tier 1 -Summary "Service restarted"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show("Windows Audio Service has been restarted.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "Audio Service Restart" -Detail "Restart failed: $($_.Exception.Message)" -Category "AdminChange" -ToolCategory "Audio" -Result "FAIL" -Tier 2 -Summary "Service restart failed"
                }
                [System.Windows.Forms.MessageBox]::Show("Failed to restart Audio service: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        # =========================================================================
        # BLUETOOTH DIAGNOSTICS TOOL (Read-only - no dry run needed)
        # =========================================================================
        "Run Bluetooth Diagnostics" = {
            # GUARD: Verify Console module is available for diagnostic output
            if (-not (Get-Command Initialize-WinConfigGuiDiagnosticBox -ErrorAction SilentlyContinue)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Bluetooth Diagnostics cannot start: Console module failed to load.",
                    "Module Load Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
                return
            }

            # Locate probe module: env var override -> bundled copy -> sibling-repo (dev only)
            if (-not (Get-Command Invoke-BluetoothDiagnosticsAndRecord -ErrorAction SilentlyContinue)) {
                $btModulePath = $env:WINCONFIG_BT_MODULE_PATH
                if (-not $btModulePath) {
                    $btModulePath = Join-Path $PSScriptRoot "Modules\BluetoothProbe.psm1"
                }
                if (-not (Test-Path $btModulePath)) {
                    $winConfigRoot = Split-Path -Parent $PSScriptRoot
                    $reposRoot     = Split-Path -Parent $winConfigRoot
                    $btModulePath  = Join-Path $reposRoot "winconfig-bluetooth\src\Modules\Bluetooth.psm1"
                }
                if (Test-Path $btModulePath) {
                    try {
                        Import-Module $btModulePath -Force -Global -ErrorAction Stop
                    } catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Failed to load Bluetooth probe module:`n$($_.Exception.Message)",
                            "Module Load Error",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        ) | Out-Null
                        return
                    }
                }
            }

            if (-not (Get-Command Invoke-BluetoothDiagnosticsAndRecord -ErrorAction SilentlyContinue)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Bluetooth probe module not found. This is unexpected for a bootstrap install - please re-run the bootstrap command to repair.",
                    "Probe Not Available",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return
            }

            # FI-012 state-aware preflight. It is safe whether NO is closed or
            # already running: registry + QueryDosDevice + process enumeration
            # only, never a COM open. A CONFIRMED namespace fault stops a new
            # recording after preserving a small evidence package. An UNVERIFIED
            # collector warns but continues in passive troubleshooting mode --
            # inability to prove health is not proof of corruption.
            $btSerialPreflight = $null
            $btSerialPreflightError = $null
            $btPreflightIntegrity = $null
            $btNoProcesses = @(Get-Process -Name 'NO' -ErrorAction SilentlyContinue)
            $btNoProcessState = @($btNoProcesses | ForEach-Object {
                [ordered]@{
                    Id              = $_.Id
                    ProcessName     = $_.ProcessName
                    StartTime       = $(try { $_.StartTime } catch { $null })
                    MainWindowTitle = $(try { $_.MainWindowTitle } catch { $null })
                }
            })
            try {
                if (-not (Get-Command Get-BluetoothSerialPortIntegrity -ErrorAction SilentlyContinue) -or
                    -not (Get-Command Test-BluetoothRecorderSerialPreflight -ErrorAction SilentlyContinue)) {
                    throw 'The installed Bluetooth probe does not include the serial-readiness preflight.'
                }
                $btPreflightIntegrity = Get-BluetoothSerialPortIntegrity
                $btSerialPreflight = Test-BluetoothRecorderSerialPreflight -Integrity $btPreflightIntegrity
            } catch {
                $btSerialPreflightError = $_.Exception.Message
            }

            if (-not $btSerialPreflight) {
                $btSerialPreflight = [ordered]@{
                    CanStart = $true; Status = 'Unverified'; Reason = 'PreflightUnavailable'
                    PassiveCaptureAllowed = $true; ApplicationSessionReady = $false
                    Summary = "Bluetooth serial readiness could not be verified: $btSerialPreflightError"
                    CheckedAt = Get-Date; CollisionCount = $null; MissingSymlinkCount = $null
                    DanglingSymlinkCount = $null; ResumeCountSinceBoot = $null
                    VerifiedAfterLastResume = $null
                }
            }

            $btPfResponse = if (Get-Command Get-BluetoothSerialTroubleshootingResponse -ErrorAction SilentlyContinue) {
                Get-BluetoothSerialTroubleshootingResponse -Readiness $btSerialPreflight `
                    -NoExeRunning ($btNoProcesses.Count -gt 0) -RecorderActive ([bool]$script:BtRecordingActive)
            } else {
                [ordered]@{
                    Status = 'Unverified'; NotifyUser = $true; StopRecorderStart = $false
                    ApplicationState = if ($btNoProcesses.Count -gt 0) { 'NoExeRunning' } else { 'NoExeClosed' }
                    FaultStage = $null; Title = 'Bluetooth Serial Readiness Not Verified'
                    Summary = "Bluetooth serial readiness could not be verified: $btSerialPreflightError"
                    LikelyCause = 'The installed passive collector could not verify SERIALCOMM and COM symlink agreement. This is not proof that FI-012 is present.'
                    Impact = 'The probe can continue collecting passive evidence, but this result is not an all-clear for a new NO session.'
                    Steps = @('Continue the diagnostic capture if troubleshooting is needed.', 'Repair or update WinConfig and repeat the passive serial-readiness check.')
                }
            }

            if ($btPfResponse.NotifyUser) {
                $btPfEvidencePath = $null

                # A known fault must survive beyond the modal that reports it.
                # Preserve the complete registration/symlink table, power
                # correlation, and whether NO was already running. Do not upload
                # automatically; the operator owns that external action.
                if ($btPfResponse.StopRecorderStart -and
                    (Get-Command New-WinConfigDiagnosticRun -ErrorAction SilentlyContinue) -and
                    (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue) -and
                    (Get-Command Compress-WinConfigDiagnosticRun -ErrorAction SilentlyContinue)) {
                    try {
                        $btPfRun = New-WinConfigDiagnosticRun -ToolId 'bluetooth-serial-readiness'
                        Add-WinConfigDiagnosticArtifact -RunFolder $btPfRun.RunFolder -Name 'serialcomm-integrity.json' -Depth 8 -Data ([ordered]@{
                            Fault             = 'FI-012'
                            Reference         = 'docs/FIELD-ISSUES.md'
                            AtPreflight       = $btSerialPreflight
                            Integrity         = $btPreflightIntegrity
                            Troubleshooting   = $btPfResponse
                            ApplicationState  = [ordered]@{
                                ObservedAt     = Get-Date
                                NoExeRunning   = ($btNoProcesses.Count -gt 0)
                                NoProcesses    = $btNoProcessState
                                RecorderActive = [bool]$script:BtRecordingActive
                            }
                            Safety            = [ordered]@{
                                SerialPortOpened = $false
                                ProcessStopped   = $false
                                PairingChanged   = $false
                            }
                        })
                        Add-WinConfigDiagnosticArtifact -RunFolder $btPfRun.RunFolder -Name 'manifest.json' -Depth 6 -Data ([ordered]@{
                            RunId                              = $btPfRun.RunId
                            ToolId                             = $btPfRun.ToolId
                            StartedAtUtc                       = $btPfRun.StartedAtUtc
                            MachineName                        = $env:COMPUTERNAME
                            SerialPortPreflightStatus          = $btPfResponse.Status
                            SerialPortPreflightFaultStage      = $btPfResponse.FaultStage
                            SerialPortCollisionCount           = $btSerialPreflight.CollisionCount
                            SerialPortMissingSymlinkCount      = $btSerialPreflight.MissingSymlinkCount
                            SerialPortDanglingSymlinkCount     = $btSerialPreflight.DanglingSymlinkCount
                            SerialResumeCountSinceBoot         = $btSerialPreflight.ResumeCountSinceBoot
                            NoExeRunning                       = ($btNoProcesses.Count -gt 0)
                            RecorderStartPrevented             = $true
                            PassiveCheckOpenedSerialPort       = $false
                        })
                        $btPfHost = ($env:COMPUTERNAME -replace '[^A-Za-z0-9]', '').ToUpper()
                        $btPfPkg = Compress-WinConfigDiagnosticRun -RunFolder $btPfRun.RunFolder `
                            -ExportsRoot $btPfRun.ExportsRoot -Label "serial-fault_${btPfHost}" -Prefix 'bt-preflight'
                        $btPfEvidencePath = $btPfPkg.ZipPath
                    } catch {
                        $btPfEvidencePath = $null
                    }
                }

                $btPfSteps = @($btPfResponse.Steps)
                $btPfStepText = if ($btPfSteps.Count -gt 0) {
                    ((0..($btPfSteps.Count - 1) | ForEach-Object { "$($_ + 1). $($btPfSteps[$_])" }) -join "`n")
                } else { '' }
                $btPfAppText = if ($btNoProcesses.Count -gt 0) { 'NO.exe is currently running.' } else { 'NO.exe is currently closed.' }
                $btPfEvidenceText = if ($btPfEvidencePath) { "`n`nEvidence saved locally:`n$btPfEvidencePath" } else { '' }
                [System.Windows.Forms.MessageBox]::Show(
                    "$($btPfResponse.Summary)`n`nLikely cause:`n$($btPfResponse.LikelyCause)`n`nImpact:`n$($btPfResponse.Impact)`n`nCurrent application state:`n$btPfAppText`n`nWhat to do:`n$btPfStepText`n`nThis passive check opened no serial port and changed no pairing or process state.$btPfEvidenceText",
                    $btPfResponse.Title,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null

                if ($btPfResponse.StopRecorderStart) { return }
            }

            # One recorder at a time. This guard follows the passive preflight
            # deliberately: clicking the tool while a recorder is active is still
            # an opportunity to surface a newly visible known namespace fault.
            # If readiness is clean, retain the original one-recorder behavior.
            if ($script:BtRecordingActive) {
                [System.Windows.Forms.MessageBox]::Show(
                    "A Bluetooth Flight Recorder session is already running.`n`nUse the existing recorder window - click 'Stop and Upload' (or Abort) there before starting a new recording.",
                    "Recording Already Running",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
                return
            }
            # While this flag is set, the mutating-tool click gate blocks
            # 'bt-stack-reset' (pairing wipe + reboot would destroy the recording
            # before upload) and records every other repair tool the operator runs
            # into $script:BtRecOperatorActions so the session log + ZIP can
            # attribute the resulting Bluetooth changes to the operator instead of
            # counting them as spontaneous field evidence.
            $script:BtRecordingActive    = $true
            $script:BtRecOperatorActions = [System.Collections.ArrayList]::new()
            try {

            # Resolve path string for Start-Job (loaded module not accessible across runspace boundary)
            $btModPath = $env:WINCONFIG_BT_MODULE_PATH
            if (-not $btModPath) { $btModPath = Join-Path $PSScriptRoot "Modules\BluetoothProbe.psm1" }
            if (-not (Test-Path $btModPath)) {
                $btModPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "winconfig-bluetooth\src\Modules\Bluetooth.psm1"
            }

            # ── Build form ────────────────────────────────────────────────────────
            $btForm = New-Object System.Windows.Forms.Form
            $btForm.Text = "Bluetooth Flight Recorder"
            $btForm.StartPosition = "CenterScreen"
            $btForm.FormBorderStyle = "Sizable"
            $btForm.MaximizeBox = $true
            # Mirror the main form's DPI mode for consistency. NOTE: WinForms
            # auto-scaling does not reliably fire for a code-built form (the layout
            # stays at its birth-DPI), so the actual fix for buttons clipping on
            # scaled displays is the AutoSize bottom action bar below -- the panel
            # and buttons grow with the font/DPI instead of relying on auto-scale.
            $btForm.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

            # Size to fit the screen — remote desktop and small displays may have
            # less usable area than expected, so cap to 90% of the working area.
            #
            # ── DISPLAY SCALE ────────────────────────────────────────────────
            #
            # 🔴 FONTS SCALE WITH DPI, HAND-WRITTEN PIXELS DO NOT. Every font
            # below is specified in POINTS, so on a 200 % display Windows renders
            # it at twice the pixel height. Every geometry constant in this panel
            # was a raw pixel count. The two drifted apart by a factor of two,
            # and on an SP9 at 2880x1920 / 200 % the result was: headings drawn
            # on top of the panels they label, every caption ellipsised
            # ("Bluetooth rea...", "Hold (COM5"), panel labels sliced off at the
            # tile boundary, and the verdict cut in half.
            #
            # WinForms auto-scaling does NOT rescue this. AutoScaleMode::Dpi does
            # not reliably fire for a CODE-BUILT form -- the layout stays at its
            # birth DPI -- which this file already knew about the action bar and
            # then repeated here.
            #
            # So: ONE factor, read from the real device context, applied to every
            # constant. At 96 DPI it is exactly 1.0 and the layout is unchanged
            # from what was tested; at 200 % everything moves together.
            #
            # $script:BtViewScaleOverride is the seam a test uses to lay the
            # window out at a scale the test machine does not have. Production
            # never sets it.
            $script:BtViewScale = 1.0
            if ($script:BtViewScaleOverride) {
                $script:BtViewScale = [double]$script:BtViewScaleOverride
            } else {
                try {
                    $btDpiG = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
                    if ($btDpiG.DpiX -gt 0) { $script:BtViewScale = [double]$btDpiG.DpiX / 96.0 }
                    $btDpiG.Dispose()
                } catch { $script:BtViewScale = 1.0 }
            }
            if ($script:BtViewScale -lt 1.0) { $script:BtViewScale = 1.0 }

            # Every tuned constant, in one table, already scaled. The painters and
            # the layout function read from HERE and never from a literal -- a
            # literal that survives in one of the three is exactly how the
            # headings ended up overlapping the panels.
            $btS = $script:BtViewScale
            $script:BtViewM = @{
                Pad        = [int](24  * $btS)
                TopY       = [int](16  * $btS)
                TileWMin   = [int](92  * $btS)
                TileWMax   = [int](190 * $btS)
                TileWSlack = [int](96  * $btS)
                GapMin     = [int](22  * $btS)
                GapMax     = [int](150 * $btS)
                # MEASURED against what a tile now has to carry, not picked to
                # look right on the healthy screen. Both rows grew when the
                # header strip's identifiers moved into the panels:
                #   connection tile: badge 42 + label 19 + caption 15 +
                #                    1 identifier 15 + note/caveat 15 + 4 = 110
                #   signal tile:     the same, with TWO identifier lines
                #                    (Data: / Command:) and a note = 133
                # The signal row is the taller one for the first time, and that
                # is correct: the COM panel is the one that gained a mapping.
                # Anything shorter clips a line, and the line that clips first
                # is the last one -- "nobody is using it", the half that says an
                # idle port is not a fault.
                ConnH      = [int](120 * $btS)
                SigH       = [int](136 * $btS)
                BadgeR     = [int](16  * $btS)
                BadgeTop   = [int](10  * $btS)
                HeadH      = [int](16  * $btS)
                # The three gaps the vertical budget is allowed to spend, in the
                # order it spends them. Named by ROLE, not by the pair they sit
                # between, so the squeeze code cannot silently shrink one it was
                # never meant to touch.
                GapSmall   = [int](6   * $btS)
                GapMed     = [int](22  * $btS)
                GapBig     = [int](22  * $btS)
                LabelH     = [int](19  * $btS)
                LineH      = [int](15  * $btS)
                VerdictH   = [int](28  * $btS)
                ContextH   = [int](18  * $btS)
                FootH      = [int](16  * $btS)
                EventsH    = [int](96  * $btS)
                BadgeW     = [int](15  * $btS)
                BadgeH     = [int](13  * $btS)
                Pen        = [float][Math]::Max(2.0, (2.0 * $btS))
            }

            # Sized to hold the whole diagram plus the session-events block
            # without a scrollbar at the default size, AT THIS DISPLAY'S SCALE.
            # The 860x880 figure is measured at 96 DPI: the view panel lays out
            # to roughly 530 px of content and the header, phase strip and status
            # bar take about 210 px. Unscaled, it produced a small window full of
            # double-size text.
            $btScreen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $btFormW = [Math]::Min([int](860 * $btS), [int]($btScreen.Width * 0.9))
            $btFormH = [Math]::Min([int](880 * $btS), [int]($btScreen.Height * 0.9))
            $btForm.Size = New-Object System.Drawing.Size($btFormW, $btFormH)
            $btForm.MinimumSize = New-Object System.Drawing.Size([int](560 * $btS), [int](420 * $btS))

            # ── Colours, fonts and glyph geometry for the visual panel ────────
            #
            # script:-scoped on purpose. A Paint handler does NOT run in the
            # scope it was written in, so a local $btViewColors would resolve to
            # nothing at paint time and the panel would draw blank on a field
            # machine -- the same failure class as a dead Add_Click button.
            #
            # Colour is never the only status signal. Every panel also carries a
            # distinct GLYPH SHAPE (tick / cross / bar / question mark) and a
            # short state WORD, because roughly one man in twelve cannot
            # separate this palette's green from its red and these windows get
            # read over the phone from a screenshot.
            $script:BtViewColors = @{
                Healthy       = [System.Drawing.Color]::FromArgb(105, 200, 130)
                Failed        = [System.Drawing.Color]::FromArgb(235,  95,  95)
                Degraded      = [System.Drawing.Color]::FromArgb(228, 178,  60)
                Idle          = [System.Drawing.Color]::FromArgb(140, 140, 150)
                # Blue-grey for "nobody looked", NOT the neutral grey the
                # measured-but-idle states use. Grey is what an operator reads as
                # "fine, nothing happening"; an unread sensor must not look the
                # same as a reading.
                Unknown       = [System.Drawing.Color]::FromArgb(120, 155, 205)
                NotMeasurable = [System.Drawing.Color]::FromArgb(125, 125, 125)
            }
            $script:BtViewInk       = [System.Drawing.Color]::FromArgb(226, 226, 232)
            $script:BtViewInkDim    = [System.Drawing.Color]::FromArgb(140, 140, 150)
            # IDENTIFIERS sit between the caption and the note: brighter than a
            # note, because a MAC or a COM number is read and transcribed off
            # this screen, and dimmer than the caption, because it is not the
            # state. Its own tone rather than a shared one so a reader can tell
            # a fact about the device from a comment on the reading.
            $script:BtViewInkDetail = [System.Drawing.Color]::FromArgb(176, 176, 188)
            $script:BtViewInkCaveat = [System.Drawing.Color]::FromArgb(228, 178,  60)
            $script:BtViewBack      = [System.Drawing.Color]::FromArgb(20, 20, 25)
            $script:BtViewFontLabel   = New-Object System.Drawing.Font("Segoe UI", 9.75, [System.Drawing.FontStyle]::Bold)
            $script:BtViewFontCaption = New-Object System.Drawing.Font("Segoe UI", 9)
            $script:BtViewFontNote    = New-Object System.Drawing.Font("Segoe UI", 7.5)
            # Half a point above the note font. These lines carry COM numbers,
            # a driver version and a MAC -- strings that get read back over the
            # phone -- so they are not allowed to be the smallest text on screen.
            $script:BtViewFontDetail  = New-Object System.Drawing.Font("Segoe UI", 8)
            $script:BtViewFontGlyph   = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
            $script:BtViewFontBadge   = New-Object System.Drawing.Font("Segoe UI", 6.75, [System.Drawing.FontStyle]::Bold)
            # Badge geometry lives in $script:BtViewM (above), in ONE place: the
            # edge painter draws its connector through the badge centres, so a
            # radius that lived in two functions would put the line through empty
            # space the moment one moved -- or the moment the display scaled.

            # ── Painters ──────────────────────────────────────────────────────
            #
            # Everything a panel needs is on its own Tag. A Paint handler does
            # NOT run in the scope it was written in -- a captured local would
            # resolve to nothing at paint time -- so the handler reads $sender
            # and script:-scoped state and nothing else.
            #
            # ONE scriptblock serves all six panels. Six near-identical handlers
            # is six places for the historical marker to be forgotten in five.
            $script:BtViewTilePaint = {
                param($sender, $e)
                $t = $sender.Tag
                if (-not $t) { return }
                $g = $e.Graphics
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
                $w = $sender.ClientSize.Width
                $h = $sender.ClientSize.Height
                if ($w -lt 20 -or $h -lt 20) { return }

                $col = $script:BtViewColors[$t.Level]
                if (-not $col) { $col = $script:BtViewColors['Unknown'] }
                $ink = $script:BtViewInk
                # A CONSEQUENCE RECEDES. It keeps its own marker and its own
                # reading -- both were honestly obtained -- but it is dimmed so it
                # does not read as a second, separate problem to chase.
                if ($t.Blocked) {
                    $col = [System.Drawing.Color]::FromArgb([int]($col.R * 0.45), [int]($col.G * 0.45), [int]($col.B * 0.45))
                    $ink = [System.Drawing.Color]::FromArgb(112, 112, 120)
                }

                $m = $script:BtViewM
                if ($t.Focus) {
                    $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(31, 31, 39))
                    $g.FillRectangle($fill, 0, 0, $w, $h)
                    $fill.Dispose()
                    $ring = New-Object System.Drawing.Pen($col, $m.Pen)
                    $g.DrawRectangle($ring, 1, 1, ($w - 3), ($h - 3))
                    $ring.Dispose()
                } elseif ($t.Attention) {
                    # A SECOND independent root, marked but not headlined. Two
                    # branches down at once is materially different from one, and
                    # the verdict line can only carry one of them.
                    $rule = New-Object System.Drawing.Pen($col, $m.Pen)
                    $g.DrawLine($rule, 12, ($h - 3), ($w - 12), ($h - 3))
                    $rule.Dispose()
                }

                $r  = $m.BadgeR
                $cx = [int]($w / 2)
                $cy = $m.BadgeTop + $r
                $pen = New-Object System.Drawing.Pen($col, $m.Pen)
                $g.DrawEllipse($pen, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r))
                # THE GLYPH IS THE SECOND SIGNAL. Tick, cross, bar and question
                # mark are different SHAPES, so the state survives a reader who
                # cannot separate the palette and a screenshot that has been
                # through two rounds of phone compression.
                #
                # Every offset is a FRACTION OF THE RADIUS, not a pixel count, so
                # the glyph keeps its proportions at any display scale.
                $gx = [int](0.44 * $r); $gy = [int](0.31 * $r); $gd = [int](0.38 * $r)
                switch ($t.Glyph) {
                    'Check' {
                        $g.DrawLine($pen, ($cx - $gx), $cy, ($cx - [int](0.12 * $r)), ($cy + $gy))
                        $g.DrawLine($pen, ($cx - [int](0.12 * $r)), ($cy + $gy), ($cx + $gx), ($cy - $gy))
                    }
                    'Cross' {
                        $g.DrawLine($pen, ($cx - $gd), ($cy - $gd), ($cx + $gd), ($cy + $gd))
                        $g.DrawLine($pen, ($cx + $gd), ($cy - $gd), ($cx - $gd), ($cy + $gd))
                    }
                    'Dash' {
                        $g.DrawLine($pen, ($cx - $gx), $cy, ($cx + $gx), $cy)
                    }
                    default {
                        $sym = '?'
                        if ($t.Glyph -eq 'Warn')          { $sym = '!' }
                        if ($t.Glyph -eq 'NotApplicable') { $sym = 'n/a' }
                        $gf = $(if ($sym -eq 'n/a') { $script:BtViewFontNote } else { $script:BtViewFontGlyph })
                        $gb = New-Object System.Drawing.SolidBrush($col)
                        $gs = New-Object System.Drawing.StringFormat
                        $gs.Alignment = [System.Drawing.StringAlignment]::Center
                        $gs.LineAlignment = [System.Drawing.StringAlignment]::Center
                        $g.DrawString($sym, $gf, $gb, (New-Object System.Drawing.RectangleF(($cx - $r), ($cy - $r), (2 * $r), (2 * $r))), $gs)
                        $gb.Dispose(); $gs.Dispose()
                    }
                }
                $pen.Dispose()

                # HISTORICAL MARKER. A fact that was true earlier and was not
                # re-checked on this tick must not draw like a live healthy
                # reading -- "COM ok" during a dropped link is exactly how a
                # reader concludes the link is fine.
                #
                # Drawn against the status circle rather than in the panel
                # corner: with no panel border to anchor it, a corner badge
                # floats in the whitespace between two panels and reads as
                # belonging to neither.
                if ($t.Historical) {
                    $hc = [System.Drawing.Color]::FromArgb(176, 156, 104)
                    $bw = $m.BadgeW; $bh = $m.BadgeH
                    $bx = $cx + $r + [int](5 * $script:BtViewScale); $by = $cy - [int]($bh / 2)
                    $hp = New-Object System.Drawing.Pen($hc, 1)
                    $g.DrawRectangle($hp, $bx, $by, $bw, $bh)
                    $hp.Dispose()
                    $hb = New-Object System.Drawing.SolidBrush($hc)
                    $hs = New-Object System.Drawing.StringFormat
                    $hs.Alignment = [System.Drawing.StringAlignment]::Center
                    $hs.LineAlignment = [System.Drawing.StringAlignment]::Center
                    $g.DrawString('H', $script:BtViewFontBadge, $hb, (New-Object System.Drawing.RectangleF($bx, $by, $bw, $bh)), $hs)
                    $hb.Dispose(); $hs.Dispose()
                }

                $sf = New-Object System.Drawing.StringFormat
                $sf.Alignment = [System.Drawing.StringAlignment]::Center
                $sf.LineAlignment = [System.Drawing.StringAlignment]::Near
                $sf.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
                $y = $cy + $r + [int](8 * $script:BtViewScale)

                $lb = New-Object System.Drawing.SolidBrush($ink)
                $g.DrawString([string]$t.Label, $script:BtViewFontLabel, $lb, (New-Object System.Drawing.RectangleF(2, $y, ($w - 4), $m.LabelH)), $sf)
                $lb.Dispose()
                $y += $m.LabelH

                # THE NOTE AND THE CAVEAT ARE ANCHORED TO THE BOTTOM, and the
                # caption takes what is left between them. Flowing all three from
                # the top made the last line's visibility depend on how tall the
                # caption happened to measure -- a two-word caption fitted and a
                # wrapped one silently pushed "not a fault" off the bottom edge.
                # Losing that half of the line turns an idle reading into what
                # looks like a failure, which is the exact misreading this
                # redesign exists to stop, produced by a layout accident.
                # The bottom 4px are reserved for the second-root rule, whether or
                # not this tile draws one. Letting the text claim them when there
                # is no rule would make the layout depend on the diagnostic state,
                # and the one tile that ever collides is the one being pointed at.
                $bottom = $h - [int](4 * $script:BtViewScale)
                $lineH = $m.LineH
                if ($t.Caveat) {
                    $vb = New-Object System.Drawing.SolidBrush($script:BtViewInkCaveat)
                    $g.DrawString([string]$t.Caveat, $script:BtViewFontNote, $vb, (New-Object System.Drawing.RectangleF(2, ($bottom - $lineH), ($w - 4), $lineH)), $sf)
                    $vb.Dispose()
                    $bottom -= $lineH
                }
                if ($t.Note) {
                    $nb = New-Object System.Drawing.SolidBrush($script:BtViewInkDim)
                    $g.DrawString([string]$t.Note, $script:BtViewFontNote, $nb, (New-Object System.Drawing.RectangleF(2, ($bottom - $lineH), ($w - 4), $lineH)), $sf)
                    $nb.Dispose()
                    $bottom -= $lineH
                }

                # THE IDENTIFIER LINES, anchored bottom-up like the note and the
                # caveat, and drawn LAST-FIRST so they read in the order the view
                # supplied them. They sit between the caption and the note for
                # the same reason those two are anchored at all: flowed from the
                # top, a caption that happened to wrap would push "Command: COM5"
                # off the bottom edge silently, and a mapping that is half
                # present is worse than one that is absent -- a reader takes the
                # single visible port for the only port.
                #
                # Two lines is the budget the tile height is measured for, so a
                # third is dropped rather than drawn over the caption. The view
                # builds at most two; this clamp is the guard, not the policy.
                $detailLines = @($t.Details | Where-Object { $_ })
                if ($detailLines.Count -gt 2) { $detailLines = @($detailLines[0], $detailLines[1]) }
                if ($detailLines.Count -gt 0) {
                    # A consequence recedes here too. The identifiers are still
                    # true on a blocked panel -- the COM ports really are those
                    # ports -- so they are dimmed with the rest of it rather than
                    # left at full weight, which would make an explained panel
                    # shout louder than the cause.
                    $detailInk = $(if ($t.Blocked) { [System.Drawing.Color]::FromArgb(96, 96, 104) } else { $script:BtViewInkDetail })
                    $db = New-Object System.Drawing.SolidBrush($detailInk)
                    for ($di = $detailLines.Count - 1; $di -ge 0; $di--) {
                        $g.DrawString([string]$detailLines[$di], $script:BtViewFontDetail, $db, (New-Object System.Drawing.RectangleF(2, ($bottom - $lineH), ($w - 4), $lineH)), $sf)
                        $bottom -= $lineH
                    }
                    $db.Dispose()
                }

                # The caption is the state IN WORDS. Colour is decoration on top
                # of it, never the carrier -- which is why it is the one element
                # that gets the slack and is trimmed with an ellipsis rather than
                # dropped.
                $capCol = $ink
                if (-not $t.Blocked -and $t.Level -in @('Failed', 'Degraded')) { $capCol = $col }
                $capH = $bottom - $y - 2
                if ($capH -lt $lineH) { $capH = $lineH }
                $cb = New-Object System.Drawing.SolidBrush($capCol)
                $g.DrawString([string]$t.Caption, $script:BtViewFontCaption, $cb, (New-Object System.Drawing.RectangleF(4, $y, ($w - 8), $capH)), $sf)
                $cb.Dispose()
                $sf.Dispose()
            }

            # The two connectors. Both carry the WIRELESS state, because the
            # wireless panel IS the link -- giving them independent states would
            # invent a distinction nothing measures. A broken edge is drawn with a
            # gap and a cross; an idle or unread edge is dotted, so "no traffic
            # right now" and "broken" are not the same picture.
            $script:BtViewEdgePaint = {
                param($sender, $e)
                $tiles = @($sender.Controls | Sort-Object -Property Left)
                if ($tiles.Count -lt 2) { return }
                $state = [string]$sender.Tag
                $col = switch ($state) {
                    'Live'      { $script:BtViewColors['Healthy'] }
                    'Broken'    { $script:BtViewColors['Failed'] }
                    'Degrading' { $script:BtViewColors['Degraded'] }
                    'Idle'      { $script:BtViewColors['Idle'] }
                    default     { $script:BtViewColors['Unknown'] }
                }
                $col = [System.Drawing.Color]::FromArgb([int]($col.R * 0.8), [int]($col.G * 0.8), [int]($col.B * 0.8))
                $g = $e.Graphics
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
                $m = $script:BtViewM
                # Through the badge CENTRES, read from the shared metrics -- the
                # one number the tile painter and this one both depend on.
                $y = $tiles[0].Top + $m.BadgeTop + $m.BadgeR
                $s = $script:BtViewScale
                $gapHalf = [int](9 * $s); $xArm = [int](5 * $s); $inset = [int](3 * $s)
                $pen = New-Object System.Drawing.Pen($col, $m.Pen)
                if ($state -ne 'Live') { $pen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dot }
                for ($i = 0; $i -lt ($tiles.Count - 1); $i++) {
                    $x1 = $tiles[$i].Right + $inset
                    $x2 = $tiles[$i + 1].Left - $inset
                    if (($x2 - $x1) -lt (16 * $s)) { continue }
                    if ($state -eq 'Broken') {
                        $mid = [int](($x1 + $x2) / 2)
                        $g.DrawLine($pen, $x1, $y, ($mid - $gapHalf), $y)
                        $g.DrawLine($pen, ($mid + $gapHalf), $y, $x2, $y)
                        $xp = New-Object System.Drawing.Pen($col, $m.Pen)
                        $g.DrawLine($xp, ($mid - $xArm), ($y - $xArm), ($mid + $xArm), ($y + $xArm))
                        $g.DrawLine($xp, ($mid + $xArm), ($y - $xArm), ($mid - $xArm), ($y + $xArm))
                        $xp.Dispose()
                    } else {
                        $g.DrawLine($pen, $x1, $y, $x2, $y)
                    }
                }
                $pen.Dispose()
            }

            # ── Layout ────────────────────────────────────────────────────────
            #
            # Laid out by hand from the panel's own client size rather than by a
            # nest of AutoSize containers, because the whitespace IS the design
            # here and an AutoSize stack gives it away first. AutoScroll on the
            # panel is the safety net for a display too short to hold it all --
            # this window's history is of controls clipping rather than reflowing
            # (#64), and content that runs off the bottom is the same defect.
            function script:Set-BtRecorderViewLayout {
                if (-not $script:BtView) { return }
                $p = $script:BtView.Panel
                if (-not $p) { return }
                $m = $script:BtViewM
                $w = $p.ClientSize.Width
                if ($w -lt (240 * $script:BtViewScale)) { return }
                $pad = $m.Pad
                $rowW = $w - (2 * $pad)

                $tileW = [Math]::Max($m.TileWMin, [Math]::Min($m.TileWMax, [int](($rowW - $m.TileWSlack) / 3)))
                $gap   = [Math]::Max($m.GapMin, [Math]::Min($m.GapMax, [int](($rowW - (3 * $tileW)) / 2)))
                $x0    = [int](($rowW - ((3 * $tileW) + (2 * $gap))) / 2)
                if ($x0 -lt 0) { $x0 = 0 }

                # ── Vertical budget ──────────────────────────────────────────
                #
                # The blocks below have a natural height. On a scaled display
                # that height doubles while the SCREEN does not, so on a 150 %
                # 1080p box the verdict -- the one line the whole redesign exists
                # to deliver -- falls below the fold and the operator has to
                # scroll to find out whether anything is wrong.
                #
                # So the layout SPENDS a budget rather than asserting a size.
                # What gets cut, in order, is what costs least: the session-event
                # rows first (down to three, they are a tail), then the gaps
                # between blocks (down to a floor). The text-bearing tile heights
                # are never squeezed -- shrinking those clips the captions, which
                # is the defect this whole pass is fixing.
                $connH = $m.ConnH
                $sigH  = $m.SigH
                $gapSmall = $m.GapSmall; $gapMed = $m.GapMed; $gapBig = $m.GapBig
                $eventsH  = $m.EventsH
                $availH   = $p.ClientSize.Height
                $fixedH   = $m.TopY + (2 * $m.HeadH) + $connH + $sigH + $m.VerdictH +
                            $m.ContextH + 2 + $m.FootH + $m.LineH + 3 + [int](8 * $script:BtViewScale)
                $need = $fixedH + (2 * $gapSmall) + (2 * $gapMed) + $gapBig + $eventsH
                if ($availH -gt 0 -and $need -gt $availH) {
                    # 1. Event rows. Three is the floor: fewer stops being a
                    #    timeline, and the raw log still holds every line.
                    $minEventsH = 3 * $m.LineH
                    $take = [Math]::Min(($need - $availH), ($eventsH - $minEventsH))
                    if ($take -gt 0) { $eventsH -= $take; $need -= $take }
                }
                if ($availH -gt 0 -and $need -gt $availH) {
                    # 2. Gaps, proportionally, to a floor of 4 scaled px.
                    $floor = [int](4 * $script:BtViewScale)
                    $gapTotal = (2 * $gapSmall) + (2 * $gapMed) + $gapBig
                    $gapFloor = 5 * $floor
                    $want = $gapTotal - ($need - $availH)
                    if ($want -lt $gapFloor) { $want = $gapFloor }
                    $q = if ($gapTotal -gt 0) { [double]$want / $gapTotal } else { 1.0 }
                    $gapSmall = [Math]::Max($floor, [int]($gapSmall * $q))
                    $gapMed   = [Math]::Max($floor, [int]($gapMed   * $q))
                    $gapBig   = [Math]::Max($floor, [int]($gapBig   * $q))
                }
                # Anything still over spills to AutoScroll, which is reachable --
                # unlike the clipping this window has a history of.

                $y = $m.TopY
                $script:BtView.ConnHeading.SetBounds($pad, $y, $rowW, $m.HeadH)
                $y += $m.HeadH + $gapSmall

                # Tile heights are MEASURED against what a tile can carry, not
                # picked to look right on the healthy screen. A connection tile
                # must fit badge + label + caption + note + caveat, because the
                # Arc tile carries a target caveat; a supporting tile has no
                # caveat and stops one line earlier. Too short and the note is
                # silently clipped -- which is how "Registered, idle / nobody is
                # using it" loses the half that says it is not a fault.
                #
                # Both come from the scaled metrics table. Left as raw pixels
                # they held their 96-DPI size while the text inside them doubled.
                $script:BtView.ConnRow.SetBounds($pad, $y, $rowW, $connH)
                $y += $connH + $gapMed

                $script:BtView.SigHeading.SetBounds($pad, $y, $rowW, $m.HeadH)
                $y += $m.HeadH + $gapSmall

                $script:BtView.SigRow.SetBounds($pad, $y, $rowW, $sigH)
                $y += $sigH + $gapMed

                foreach ($row in @(@{ R = $script:BtView.ConnRow; H = $connH }, @{ R = $script:BtView.SigRow; H = $sigH })) {
                    $i = 0
                    foreach ($tile in @($row.R.Controls)) {
                        $tile.SetBounds(($x0 + ($i * ($tileW + $gap))), 0, $tileW, $row.H)
                        $i++
                    }
                }

                $script:BtView.Verdict.SetBounds($pad, $y, $rowW, $m.VerdictH)
                $y += $m.VerdictH
                $script:BtView.Context.SetBounds($pad, $y, $rowW, $m.ContextH)
                $y += $m.ContextH + [int](2 * $script:BtViewScale)
                $script:BtView.Footnote.SetBounds($pad, $y, $rowW, $m.FootH)
                $y += $m.FootH + $gapBig

                $script:BtView.EventsHeading.SetBounds($pad, $y, [int]($rowW * 0.6), $m.LineH)
                $script:BtView.TechToggle.Left = $pad + $rowW - $script:BtView.TechToggle.Width
                $script:BtView.TechToggle.Top  = $y - [int](4 * $script:BtViewScale)
                $y += $m.LineH + [int](3 * $script:BtViewScale)
                $script:BtView.EventsPanel.SetBounds($pad, $y, $rowW, $eventsH)
            }

            # ── Renderer ──────────────────────────────────────────────────────
            #
            # A RENDERER ONLY. Every judgement -- which panel is the boundary,
            # which readings are consequences, what the verdict says -- is made by
            # Get-BtDiagnosticChain and mapped by Get-BtRecorderView, and read off
            # the object here. A second place that works out what is wrong is a
            # second place that can disagree with the first, and the one a human
            # happens to be looking at wins.
            function script:Update-BtRecorderPanel {
                param($View, $Chain)
                if (-not $View -or -not $script:BtView -or -not $script:BtView.Panel) { return }

                # Repaint on CHANGE ONLY. This runs on the UI thread inside the
                # probe tick, and the tick is already this window's bottleneck --
                # an unconditional Invalidate of six panels plus two label
                # assignments every three seconds buys nothing at a display whose
                # finest unit is one state transition.
                $key = (@(@($View.Connection) + @($View.Signals)) | ForEach-Object {
                    "$($_.Slot)=$($_.Level)/$($_.Caption)/$(@($_.Details) -join '|')/$($_.Note)/$($_.Caveat)/$($_.Historical)/$($_.Blocked)"
                }) -join ';'
                $key = "$key|$($View.EdgeState)|$($View.FocusSlot)|$(@($View.AttentionSlots) -join ',')|$($View.Verdict)|$($View.VerdictContext)|$($View.TargetState)|$($View.TargetLabel)"
                if ($key -eq $script:BtView_LastKey) { return }
                $script:BtView_LastKey = $key

                $nodeById = @{}
                if ($Chain) { foreach ($n in @($Chain.Nodes)) { if ($n -and $n.Id) { $nodeById[$n.Id] = $n } } }

                foreach ($tv in @(@($View.Connection) + @($View.Signals))) {
                    $tile = $script:BtView_Tiles[$tv.Slot]
                    if (-not $tile) { continue }
                    $tile.Tag = @{
                        Slot       = $tv.Slot
                        Label      = $tv.Label
                        Caption    = $tv.Caption
                        # The adapter/driver, the headset MAC and the
                        # DATA/COMMAND mapping. Read off the view like
                        # everything else here -- this renderer resolves no
                        # ports and names no devices of its own.
                        Details    = @($tv.Details)
                        Marker     = $tv.Marker
                        Glyph      = $tv.Glyph
                        Level      = $tv.Level
                        Note       = $tv.Note
                        Caveat     = $tv.Caveat
                        Historical = [bool]$tv.Historical
                        Blocked    = [bool]$tv.Blocked
                        BlockedBy  = $tv.BlockedBy
                        Focus      = ($tv.Slot -eq $View.FocusSlot)
                        Attention  = ($tv.Slot -ne $View.FocusSlot -and $tv.Slot -in @($View.AttentionSlots))
                        # Every node behind the panel, so the evidence dialog can
                        # show BOTH facts the COM panel merges rather than the one
                        # that happened to win the precedence.
                        Nodes      = @(@($tv.NodeIds) | ForEach-Object { $nodeById[$_] } | Where-Object { $_ })
                    }
                    # The marker text lives here as well as in the glyph: a
                    # tooltip is the one place a reader can get the state as WORDS
                    # without opening a dialog.
                    $tip = "$($tv.Marker)  $($tv.Label): $($tv.Caption)"
                    # The identifiers go in the tooltip UNTRIMMED. On the panel a
                    # long adapter name is ellipsised to keep the layout stable,
                    # and the full string has to stay reachable without opening a
                    # dialog -- these are exactly the values that get read back
                    # over the phone.
                    foreach ($d in @($tv.Details)) { if ($d) { $tip = "$tip`r`n$d" } }
                    if ($tv.Historical) { $tip = "$tip`r`nH = historical. This was true earlier and was NOT re-checked just now." }
                    if ($tv.Blocked)    { $tip = "$tip`r`nExplained by '$($tv.BlockedBy)'. A consequence, not a separate problem to chase." }
                    if ($tv.Caveat)     { $tip = "$tip`r`n$($tv.Caveat)" }
                    $script:BtView.Tooltip.SetToolTip($tile, "$tip`r`nClick for the evidence behind this.")
                    $tile.Invalidate()
                }

                $script:BtView.ConnRow.Tag = $View.EdgeState
                $script:BtView.ConnRow.Invalidate()

                $vCol = switch ($View.VerdictLevel) {
                    'Failure'   { $script:BtViewColors['Failed'] }
                    'Degrading' { $script:BtViewColors['Degraded'] }
                    'Idle'      { $script:BtViewInkDim }
                    'Unscoped'  { $script:BtViewInkCaveat }
                    'Unknown'   { $script:BtViewColors['Unknown'] }
                    # Healthy is deliberately NOT green. A calm state should read
                    # as calm, and a wall of green is what trains a reader to stop
                    # looking at the line that will one day be red.
                    default     { $script:BtViewInk }
                }
                if ($script:BtView.Verdict.Text -ne $View.Verdict) { $script:BtView.Verdict.Text = $View.Verdict }
                if ($script:BtView.Verdict.ForeColor -ne $vCol)    { $script:BtView.Verdict.ForeColor = $vCol }
                if ($script:BtView.Context.Text -ne $View.VerdictContext) { $script:BtView.Context.Text = $View.VerdictContext }

                # Target uncertainty is NOT re-rendered here any more. It used to
                # get its own header line as well as the Arc panel's caveat, and
                # the two were built from different fields of the same view --
                # one more place for the screen to say two things about one fact.
                # Every state it carried is on the Arc panel now: Suspended
                # replaces the identity with "Not confirmed" and names the
                # candidate, Provisional keeps the identity and marks it, and
                # Unstated -- the wiring-break state -- carries "Target not
                # stated" rather than passing as a confirmed device.
            }

            # Per-panel evidence, on click. Delegates to the SAME dialog the chain
            # chips use, so the operator and the engineer read one account of the
            # evidence. The COM panel opens both of the nodes it merges, in
            # dependency order, rather than the one that won the precedence.
            function script:Show-BtViewTileDetail {
                param($Owner, $Tile)
                if (-not $Tile -or -not $Tile.Tag) { return }
                foreach ($n in @($Tile.Tag.Nodes)) {
                    if ($n) { script:Show-BtChainNodeDetail -Owner $Owner -Node $n }
                }
            }

            function script:Switch-BtTechnicalDetails {
                if (-not $script:BtView -or -not $script:BtView.TechPanel) { return }
                $tp = $script:BtView.TechPanel
                $tp.Visible = -not $tp.Visible
                if ($script:BtView.TechToggle) {
                    $script:BtView.TechToggle.Text = $(if ($tp.Visible) { 'Hide technical details' } else { 'Technical details' })
                }
                # The scope and boundary lines are AutoSize labels that only wrap
                # once they are given a maximum width, and that width is computed
                # at render time from the panel they sit in. While the panel was
                # hidden it had never been laid out, so the width they locked was
                # the collapsed one -- and the boundary sentence, the highest-value
                # line in the technical view, opened as a column four words wide.
                # Recomputed here from the container that actually has a width.
                if ($tp.Visible) {
                    $maxW = $tp.ClientSize.Width - [int](32 * $script:BtViewScale)
                    if ($maxW -gt 100) {
                        foreach ($lbl in @($script:BtView.ScopeLabel, $script:BtView.BoundaryLabel)) {
                            if ($lbl) { $lbl.MaximumSize = New-Object System.Drawing.Size($maxW, 0) }
                        }
                    }
                }
                script:Set-BtRecorderViewLayout
            }

            # Session events: transitions only, newest last, at most six.
            function script:Add-BtRecorderEvent {
                param([string]$Text, [string]$Level = 'INFO', $At)
                if (-not $Text) { return }
                if ($null -eq $script:BtRec_ViewEvents) { return }
                $when = $(if ($At) { $At } else { Get-Date })
                [void]$script:BtRec_ViewEvents.Add([pscustomobject]@{
                    Time = $when.ToString('HH:mm:ss'); Text = $Text; Level = $Level
                })
                while ($script:BtRec_ViewEvents.Count -gt 6) { $script:BtRec_ViewEvents.RemoveAt(0) }
                script:Update-BtRecorderEventList
            }

            function script:Update-BtRecorderEventList {
                if (-not $script:BtView_EventLabels) { return }
                $items = @($script:BtRec_ViewEvents)
                for ($i = 0; $i -lt @($script:BtView_EventLabels).Count; $i++) {
                    $lbl = $script:BtView_EventLabels[$i]
                    if ($i -lt $items.Count) {
                        $txt = "$($items[$i].Time)   $($items[$i].Text)"
                        if ($lbl.Text -ne $txt) { $lbl.Text = $txt }
                        $c = switch ($items[$i].Level) {
                            'FAIL'   { $script:BtViewColors['Failed'] }
                            'WARN'   { $script:BtViewColors['Degraded'] }
                            'ACTION' { $script:BtViewInkCaveat }
                            'OK'     { $script:BtViewInk }
                            default  { $script:BtViewInkDim }
                        }
                        if ($lbl.ForeColor -ne $c) { $lbl.ForeColor = $c }
                    } elseif ($lbl.Text -ne '') {
                        $lbl.Text = ''
                    }
                }
            }

            # Bottom status bar. AutoSize + TopDown flow: the panel reserves
            # exactly the height its content needs, so on scaled/high-DPI displays
            # the labels and action buttons grow with the font instead of
            # overflowing a fixed-height panel and clipping them. Do NOT set a
            # fixed Height here. It is added to the form in the assembly block
            # further down, not here -- dock order is add order and assembling in
            # one place is what makes it reviewable.
            $btStatusPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $btStatusPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $btStatusPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $btStatusPanel.WrapContents = $false
            $btStatusPanel.AutoSize = $true
            $btStatusPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btStatusPanel.BackColor = [System.Drawing.Color]::FromArgb(28, 28, 34)
            $btStatusPanel.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 10)

            # Kept, but DEMOTED. The recording clock now lives in the header where
            # the operator looks; this line carries the packaging/abort wording the
            # steps below assign to it.
            $btElapsedLabel = New-Object System.Windows.Forms.Label
            $btElapsedLabel.Text = "Initializing..."
            $btElapsedLabel.AutoSize = $true
            $btElapsedLabel.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 1)
            $btElapsedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.25)
            $btElapsedLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 158)
            $btStatusPanel.Controls.Add($btElapsedLabel)

            $btUploadLabel = New-Object System.Windows.Forms.Label
            # Empty while recording. "Upload: -" looked like a missing or failed
            # reading even though upload does not begin until Stop and Upload is
            # pressed. Real upload outcomes populate this line below.
            $btUploadLabel.Text = ""
            $btUploadLabel.AutoSize = $true
            $btUploadLabel.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 1)
            $btUploadLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btUploadLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 158)
            $btStatusPanel.Controls.Add($btUploadLabel)

            # Shows where the package was saved on this PC (filled in when kept locally,
            # e.g. when the cloud upload fails). Lets the operator find and send the file.
            $btLocalPathLabel = New-Object System.Windows.Forms.Label
            $btLocalPathLabel.Text = ""
            $btLocalPathLabel.AutoSize = $true
            $btLocalPathLabel.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 2)
            $btLocalPathLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btLocalPathLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 158)
            $btStatusPanel.Controls.Add($btLocalPathLabel)

            # SECONDARY action row. The primary action -- Stop and Upload -- is NOT
            # here any more: it lives in the header where it cannot be confused
            # with the utilities beside it. What stays here is everything that
            # must remain reachable without competing for the eye.
            #
            # The NO-code marker box and its button stay VISIBLE rather than
            # moving into the overflow menu, and that is a deliberate exception
            # to "group the secondary actions". The operator marker is currently
            # the ONLY labelling channel this investigation has -- NO_messages.xml
            # was measured empty and written seven minutes before the event it
            # was supposed to describe -- so a redesign that costs the recorder
            # its labels would be a regression in data collection dressed up as a
            # simplification.
            #
            # Left-to-right flow of AutoSize buttons: AutoSize never clips text on
            # a scaled display, and hidden buttons take no space in the flow.
            $btButtonRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $btButtonRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $btButtonRow.WrapContents = $false
            $btButtonRow.AutoSize = $true
            $btButtonRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btButtonRow.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
            $btStatusPanel.Controls.Add($btButtonRow)

            # "Open Folder" — appears after packaging so the operator can grab the ZIP,
            # which matters most when the cloud upload fails and the file is saved locally.
            $btOpenFolderBtn = New-Object System.Windows.Forms.Button
            $btOpenFolderBtn.Text = "Open Folder"
            $btOpenFolderBtn.AutoSize = $true
            $btOpenFolderBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btOpenFolderBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $btOpenFolderBtn.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
            $btOpenFolderBtn.Visible = $false
            $btOpenFolderBtn.Add_Click({
                $folder = $this.Tag
                if ($folder -and (Test-Path $folder)) {
                    Start-Process explorer.exe -ArgumentList "`"$folder`""
                }
            })
            $btButtonRow.Controls.Add($btOpenFolderBtn)

            # Phase strip. SLIMMED from a 56px banner to a single quiet line: it
            # says which of the three phases the run is in, which is worth one
            # line and not a block. The control and every later assignment to it
            # are unchanged, so the abort/packaging wording still lands here.
            $btBanner = New-Object System.Windows.Forms.Panel
            $btBanner.Dock = [System.Windows.Forms.DockStyle]::Top
            $btBanner.Height = [int](30 * $script:BtViewScale)
            $btBanner.BackColor = [System.Drawing.Color]::FromArgb(30, 50, 80)

            $btBannerLabel = New-Object System.Windows.Forms.Label
            $btBannerLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 210, 255)
            $btBannerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
            $btBannerLabel.TextAlign = "MiddleLeft"
            $btBannerLabel.Padding = New-Object System.Windows.Forms.Padding(18, 0, 0, 0)
            $btBannerLabel.Text = "Step 1 of 3 - Taking Bluetooth baseline snapshot, please wait..."
            $btBanner.Controls.Add($btBannerLabel)

            # Anomaly confirmation bar (initially hidden, shown when anomaly detected)
            $btAnomalyBar = New-Object System.Windows.Forms.Panel
            $btAnomalyBar.Dock = [System.Windows.Forms.DockStyle]::Top
            $btAnomalyBar.Height = [int](40 * $script:BtViewScale)
            $btAnomalyBar.BackColor = [System.Drawing.Color]::FromArgb(180, 130, 20)
            $btAnomalyBar.Visible = $false

            $btAnomalyLabel = New-Object System.Windows.Forms.Label
            $btAnomalyLabel.Text = "Stream stopped unexpectedly -- was this a manual stop?"
            $btAnomalyLabel.AutoSize = $false
            $btAnomalyLabel.Height = 28
            $btAnomalyLabel.Location = New-Object System.Drawing.Point(12, 7)
            $btAnomalyLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
            $btAnomalyLabel.Width = $btAnomalyBar.ClientSize.Width - 210
            $btAnomalyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $btAnomalyLabel.ForeColor = [System.Drawing.Color]::White
            $btAnomalyBar.Controls.Add($btAnomalyLabel)

            $script:BtAnomaly_Resolved = $false
            $script:BtAnomaly_IsExpected = $false

            $btAnomalyExpectedBtn = New-Object System.Windows.Forms.Button
            $btAnomalyExpectedBtn.Text = "Expected"
            $btAnomalyExpectedBtn.Size = New-Object System.Drawing.Size(90, 26)
            $btAnomalyExpectedBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
            $btAnomalyExpectedBtn.Location = New-Object System.Drawing.Point(($btAnomalyBar.ClientSize.Width - 190), 7)
            $btAnomalyExpectedBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btAnomalyExpectedBtn.BackColor = [System.Drawing.Color]::FromArgb(60, 140, 60)
            $btAnomalyExpectedBtn.ForeColor = [System.Drawing.Color]::White
            $btAnomalyExpectedBtn.Add_Click({ $script:BtAnomaly_Resolved = $true; $script:BtAnomaly_IsExpected = $true })
            $btAnomalyBar.Controls.Add($btAnomalyExpectedBtn)

            $btAnomalyInvestBtn = New-Object System.Windows.Forms.Button
            $btAnomalyInvestBtn.Text = "Investigate"
            $btAnomalyInvestBtn.Size = New-Object System.Drawing.Size(90, 26)
            $btAnomalyInvestBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
            $btAnomalyInvestBtn.Location = New-Object System.Drawing.Point(($btAnomalyBar.ClientSize.Width - 95), 7)
            $btAnomalyInvestBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btAnomalyInvestBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 60, 60)
            $btAnomalyInvestBtn.ForeColor = [System.Drawing.Color]::White
            $btAnomalyInvestBtn.Add_Click({ $script:BtAnomaly_Resolved = $true; $script:BtAnomaly_IsExpected = $false })
            $btAnomalyBar.Controls.Add($btAnomalyInvestBtn)

            # ── TECHNICAL DETAILS, collapsed by default ───────────────────────
            #
            # Everything the old window put on the main screen at once lives in
            # here: the eight-node chain with its per-node evidence, the target
            # scope sentence, the engineer-facing boundary statement and the
            # full raw log.
            #
            # HIDDEN, NOT DELETED, and nothing here is removed from the capture.
            # The window is still the only live view of a probe -- events.jsonl
            # and chain.jsonl reach disk as they happen, but tick state does not
            # -- so a fact that cannot be recovered from this panel is a fact a
            # remote assistant reading a screenshot cannot obtain. Progressive
            # disclosure is a change to what is DEFAULT, not to what exists.
            $btTechPanel = New-Object System.Windows.Forms.Panel
            $btTechPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $btTechPanel.Height = [int]($btFormH * 0.45)
            $btTechPanel.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
            $btTechPanel.Visible = $false

            # ── Diagnostic chain strip ────────────────────────────────────────
            #
            # REPLACED the five independent state indicators that used to live at
            # the top of the window (Device / COM / Radio / Port / NO.exe). They
            # were rendered as five equals, and they are not equals: when the
            # radio link is down, the port reading and everything under it are
            # CONSEQUENCES. An operator reading five indicators counted four
            # problems where there was one cause and three effects, and picked a
            # remedy from the wrong layer.
            #
            # The strip is not kept alongside the chain. Two on-screen renderers
            # of one question is the channel-mismatch class this repo has filed
            # nine instances of -- the moment they disagree, the one a human
            # happens to read wins. Get-BtDiagnosticChain is the single answerer,
            # this panel is a renderer of it, and so is the visual panel above:
            # BOTH are fed from one chain object through one mapping
            # (Get-BtRecorderView), not from two reads of session state.
            #
            # It now sits inside the technical details rather than at the top of
            # the window. Eight chips and a two-line boundary sentence is the
            # engineer's view of the same state the diagram shows an operator.
            #
            # WrapContents is TRUE on the node row, deliberately. Eight chips do
            # not fit one line on a scaled display, and this form's history is of
            # controls clipping rather than reflowing (#64).
            $btChainPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $btChainPanel.Dock = [System.Windows.Forms.DockStyle]::Top
            $btChainPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $btChainPanel.WrapContents = $false
            $btChainPanel.AutoSize = $true
            $btChainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btChainPanel.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
            $btChainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
            $btChainPanel.Visible = $false

            # SCOPE, ABOVE THE EVIDENCE. Which headset this chain describes is a
            # prerequisite for reading any chip under it, not a detail beside
            # them -- so it sits on its own line at the top rather than
            # competing with the node row.
            #
            # This is a renderer of Get-BtDiagnosticChain's binding fields, NOT
            # a second reader of the session target. The identity strip further
            # down answers "what is this recording watching"; this answers "is
            # the conclusion below entitled to name a device", and both are fed
            # from the one selection.
            $btScopeLabel = New-Object System.Windows.Forms.Label
            $btScopeLabel.Text = "Target: (resolving...)"
            $btScopeLabel.AutoSize = $true
            $btScopeLabel.Margin = New-Object System.Windows.Forms.Padding(2, 0, 0, 3)
            $btScopeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btScopeLabel.ForeColor = [System.Drawing.Color]::FromArgb(170, 170, 170)
            $btChainPanel.Controls.Add($btScopeLabel)

            $btChainRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $btChainRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $btChainRow.WrapContents = $true
            $btChainRow.AutoSize = $true
            $btChainRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btChainRow.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)
            $btChainPanel.Controls.Add($btChainRow)

            # The failure boundary, in a sentence. This is the highest-value line
            # in the window: "verified through X, first failing step Y" is what a
            # clinic tech can act on and what a remote assistant can triage from a
            # screenshot. Bold and full width, because it is the conclusion and
            # everything above it is the working.
            $btBoundaryLabel = New-Object System.Windows.Forms.Label
            $btBoundaryLabel.Text = "Diagnostic chain: (starting...)"
            $btBoundaryLabel.AutoSize = $true
            $btBoundaryLabel.Margin = New-Object System.Windows.Forms.Padding(2, 0, 0, 2)
            $btBoundaryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $btBoundaryLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
            $btChainPanel.Controls.Add($btBoundaryLabel)

            # Keep the one interpretation warning that is unsafe to lose when
            # the long glossary is removed. It belongs beside the chain state it
            # qualifies, not behind another button or in the event timeline.
            $btObservationKeyLabel = New-Object System.Windows.Forms.Label
            $btObservationKeyLabel.Text = "NOT OBSERVED means NOTHING CHECKED THIS. Do not read it as 'fine'."
            $btObservationKeyLabel.AutoSize = $true
            $btObservationKeyLabel.Margin = New-Object System.Windows.Forms.Padding(2, 1, 0, 1)
            $btObservationKeyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btObservationKeyLabel.ForeColor = [System.Drawing.Color]::FromArgb(155, 155, 165)
            $btChainPanel.Controls.Add($btObservationKeyLabel)

            # Node chips are created ONCE, on the first render, keyed by the node
            # ids the module hands back -- so the module owns the node set and
            # this file never carries a second copy of it. Rebuilding controls
            # every tick would also churn the UI thread, which is already this
            # window's bottleneck.
            $script:BtChain_NodeLabels = @{}
            $script:BtChain_LastBoundaryKey = $null

            # ── HEADER: "what am I watching, and am I seeing it?" ─────────────
            #
            # Added last among the Top-docked controls, so it docks closest to the
            # top edge and is the first thing read.
            #
            # This is also where the PRIMARY action lives. Stop and Upload used to
            # sit in the bottom row beside Abort, the NO-code box, Mark and Open
            # Folder -- five controls of equal visual weight, one of which ends
            # the recording and sends it to support. It is now the only emphasised
            # control on the screen.
            #
            # Capture 8E39860E4AF2 (2026-08-07) measured Arc 019 -- switched off, in
            # a drawer -- while the operator ran a 37-minute session on Arc 013. The
            # selected target WAS printed, once, at startup, and had scrolled out of
            # view long before the session began; observation coverage was computed
            # only for the closing report. Both facts existed the whole time. Neither
            # was in front of the person who could have stopped the recording and
            # fixed it. Keeping them pinned is the reader-side half of the fix that
            # PR #57 made on the selector side.
            # A two-column TableLayoutPanel rather than the old TopDown flow: the
            # identity text grows down the left while the recording clock and the
            # primary action sit right. AutoSize on both the panel and its columns
            # so the header still reserves exactly the height its content needs on
            # a scaled display -- the property #64 and #68 both turned on.
            $btIdentityPanel = New-Object System.Windows.Forms.TableLayoutPanel
            $btIdentityPanel.Dock = [System.Windows.Forms.DockStyle]::Top
            $btIdentityPanel.ColumnCount = 2
            $btIdentityPanel.RowCount = 1
            [void]$btIdentityPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
            [void]$btIdentityPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $btIdentityPanel.AutoSize = $true
            $btIdentityPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btIdentityPanel.BackColor = [System.Drawing.Color]::FromArgb(16, 16, 20)
            $btIdentityPanel.Padding = New-Object System.Windows.Forms.Padding(18, 10, 14, 10)
            $btIdentityPanel.Visible = $false

            $btHeaderText = New-Object System.Windows.Forms.FlowLayoutPanel
            $btHeaderText.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $btHeaderText.WrapContents = $false
            $btHeaderText.AutoSize = $true
            $btHeaderText.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btHeaderText.Margin = New-Object System.Windows.Forms.Padding(0)
            $btIdentityPanel.Controls.Add($btHeaderText, 0, 0)

            $btHeaderActions = New-Object System.Windows.Forms.FlowLayoutPanel
            $btHeaderActions.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $btHeaderActions.WrapContents = $false
            $btHeaderActions.AutoSize = $true
            $btHeaderActions.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btHeaderActions.Anchor = [System.Windows.Forms.AnchorStyles]::Right
            $btHeaderActions.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
            $btIdentityPanel.Controls.Add($btHeaderActions, 1, 0)

            # The recording clock, promoted out of the bottom status line. It is
            # the one number an operator checks repeatedly while reproducing a
            # fault, and it used to be an 9pt line at the bottom of the window
            # next to five buttons.
            $btTimerLabel = New-Object System.Windows.Forms.Label
            $btTimerLabel.Text = ""
            $btTimerLabel.AutoSize = $true
            $btTimerLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 2, 4)
            $btTimerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
            $btTimerLabel.ForeColor = [System.Drawing.Color]::FromArgb(210, 210, 218)
            $btTimerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
            $btHeaderActions.Controls.Add($btTimerLabel)

            # Findings raised BEFORE the recording loop starts, kept for the life
            # of the window (#68 item 3). The SERIALCOMM collision that carried a
            # REBOOT remedy was only recovered because the operator pasted the log
            # text out by hand before it scrolled; a startup finding that can only
            # be read in the first ten seconds of a 30-minute run is a finding the
            # recorder did not deliver.
            $script:BtRec_StartupPhase    = $true
            $script:BtRec_StartupFindings = New-Object System.Collections.ArrayList
            # Placeholder wording says which state this is (#68 item 4). The run
            # folder is created further down; until then there is no Run ID to
            # show, and that is different from failing to read one.
            $script:BtRec_RunIdText = '(not assigned yet)'

            # THE HEADER CARRIES ONLY WHAT IS NOT IN THE PICTURE. It used to open
            # with "Watching: NeurOptimal Arc - 000013  8C1F6471000D" and a line
            # of DATA/COMMAND port roles. Both facts are now inside the panels
            # they describe -- the Arc panel names the headset, the COM Ports
            # panel carries the mapping -- and printing them twice was not merely
            # redundant: the header answered "which headset" from
            # $btProbeTargetMac while the picture answered it from the chain's
            # target binding, which is two answerers for one field and the defect
            # class this window keeps producing. What is left here is the run
            # identity and the clock, which the diagram does not carry.
            #
            # Issue #68 item 2 is preserved, not reverted: the Run ID and the
            # port roles both stay pinned and visible for the whole run, because
            # no tick data reaches disk until the run ends and a fact that is not
            # on screen is a fact no screenshot can recover. They are simply
            # pinned in the panels rather than in a strip above them.
            #
            # Consolas because a Run ID gets read back over the phone and
            # transcribed into a case.
            $btIdentityDetailLabel = New-Object System.Windows.Forms.Label
            $btIdentityDetailLabel.Text = "Run ID: (starting...)"
            $btIdentityDetailLabel.AutoSize = $true
            $btIdentityDetailLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
            $btIdentityDetailLabel.Font = New-Object System.Drawing.Font("Consolas", 8)
            $btIdentityDetailLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 150)
            $btHeaderText.Controls.Add($btIdentityDetailLabel)

            # Coverage line. Carries a text marker ([ok]/[~]/[!]) as well as colour,
            # so "not observed" is legible without relying on yellow-versus-red.
            #
            # It stays on the main screen and is NOT folded into the verdict, even
            # though both are one-liners under a diagram. They answer different
            # questions: the verdict says what the recorder believes about the
            # HEADSET, and this says whether the recorder is seeing the session at
            # all. Capture 8E39860E4AF2 is the case where the first was confident
            # and the second was the actual defect.
            $btCoverageLabel = New-Object System.Windows.Forms.Label
            $btCoverageLabel.Text = "Waiting for a session -- nothing measured yet"
            $btCoverageLabel.AutoSize = $true
            $btCoverageLabel.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)
            $btCoverageLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.25)
            $btCoverageLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 150)
            $btHeaderText.Controls.Add($btCoverageLabel)

            # Re-opens the startup findings for the life of the window (#68 item
            # 3). Hidden while there are none, so a clean start costs no space and
            # the button appearing is itself the signal.
            $btStartupFindingsBtn = New-Object System.Windows.Forms.Button
            $btStartupFindingsBtn.Text = "Startup findings"
            $btStartupFindingsBtn.AutoSize = $true
            $btStartupFindingsBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btStartupFindingsBtn.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
            $btStartupFindingsBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btStartupFindingsBtn.BackColor = [System.Drawing.Color]::FromArgb(90, 60, 20)
            $btStartupFindingsBtn.ForeColor = [System.Drawing.Color]::FromArgb(255, 225, 170)
            $btStartupFindingsBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btStartupFindingsBtn.Visible = $false
            # script: scope and FindForm() rather than a closure. An Add_Click
            # scriptblock does NOT run inside the local scope it was written in,
            # so a locally-defined function or a captured $btForm would resolve to
            # nothing at click time -- and the failure would be a dead button on a
            # field machine, invisible to every test here.
            $btStartupFindingsBtn.Add_Click({ script:Show-BtStartupFindings -Owner $this.FindForm() })
            $btHeaderText.Controls.Add($btStartupFindingsBtn)

            # Console output fills the space the technical panel's docked children
            # leave. It is the RAW log now -- every line that used to scroll past
            # the operator still arrives here, unfiltered, and is still what the
            # package's log artifact is written from.
            #
            # The Fill control must sit at CHILD INDEX 0 of its container, and
            # "add last" does NOT achieve that. WinForms lays a container's
            # children out from the HIGHEST index down, shrinking the remaining
            # rectangle as it goes, so the control at index 0 is positioned LAST
            # and is the one that receives what is left. Added last, this box got
            # the highest index, was laid out FIRST against the full client
            # rectangle, and the docked panels were then painted ON TOP of it.
            #
            # That is issue #64, measured: with a 900x600 client the log sat at
            # Top=0 Height=600 behind 136px of pinned panels and a 40px status
            # bar. The hidden band at the top is exactly where the Run ID, the
            # baseline verdict and the startup [!] findings are written -- a
            # SERIALCOMM collision with a REBOOT remedy was nearly missed because
            # of it, and no amount of scrolling could bring it back: the text was
            # not scrolled away, it was underneath another control.
            #
            # SetChildIndex(0) is used rather than reordering the Add calls
            # because it states the invariant at the point it matters. Note
            # SendToBack() does the OPPOSITE of what is wanted here -- it moves
            # the control to the HIGHEST index, which is the broken state.
            $btOutputBox = New-Object System.Windows.Forms.RichTextBox
            $btOutputBox.Multiline = $true
            $btOutputBox.ScrollBars = "Vertical"
            $btOutputBox.Dock = [System.Windows.Forms.DockStyle]::Fill
            Initialize-WinConfigGuiDiagnosticBox -Box $btOutputBox
            $btTechPanel.Controls.Add($btChainPanel)
            $btTechPanel.Controls.Add($btOutputBox)
            $btTechPanel.Controls.SetChildIndex($btOutputBox, 0)

            # =================================================================
            # THE VISUAL PANEL
            # =================================================================
            #
            # Six panels and two connectors, drawn rather than written. The
            # arrangement carries a claim about causality, so it is worth being
            # explicit about which claims it does and does not make:
            #
            #   CONNECTION        Host / System --- Wireless --- Arc
            #   SUPPORTING        NeurOptimal      COM        Data
            #
            # The supporting three are drawn side by side with NO connectors,
            # because they are observations rather than a chain:
            #
            #   * NeurOptimal has no Bluetooth dependency. Drawing it downstream
            #     of the radio would report a closed application as a consequence
            #     of a dead link, and send the operator to the wrong layer.
            #   * COM registration is HISTORICAL -- what an earlier successful
            #     pairing left behind. It survives a flat battery and a headset in
            #     a drawer, so it cannot sit under the live link without making
            #     every idle box show a broken COM layer.
            #   * Data activity is a read-operation count, not proof of EEG.
            #
            # Nothing here decides anything. Get-BtRecorderView maps the chain
            # onto these six slots and this code draws what it is handed.
            $btViewPanel = New-Object System.Windows.Forms.Panel
            $btViewPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
            $btViewPanel.BackColor = $script:BtViewBack
            $script:BtView_Tiles = @{}
            $script:BtView_LastKey = $null

            $btConnHeading = New-Object System.Windows.Forms.Label
            $btConnHeading.Text = "CONNECTION"
            $btConnHeading.AutoSize = $false
            $btConnHeading.Font = New-Object System.Drawing.Font("Segoe UI", 7.5, [System.Drawing.FontStyle]::Bold)
            $btConnHeading.ForeColor = [System.Drawing.Color]::FromArgb(110, 110, 122)
            $btConnHeading.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $btViewPanel.Controls.Add($btConnHeading)

            $btConnRow = New-Object System.Windows.Forms.Panel
            $btConnRow.BackColor = [System.Drawing.Color]::Transparent
            $btConnRow.Tag = 'Unknown'
            $btConnRow.Add_Paint($script:BtViewEdgePaint)
            $btViewPanel.Controls.Add($btConnRow)

            $btSigHeading = New-Object System.Windows.Forms.Label
            $btSigHeading.Text = "SUPPORTING SIGNALS"
            $btSigHeading.AutoSize = $false
            $btSigHeading.Font = New-Object System.Drawing.Font("Segoe UI", 7.5, [System.Drawing.FontStyle]::Bold)
            $btSigHeading.ForeColor = [System.Drawing.Color]::FromArgb(110, 110, 122)
            $btSigHeading.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $btViewPanel.Controls.Add($btSigHeading)

            $btSigRow = New-Object System.Windows.Forms.Panel
            $btSigRow.BackColor = [System.Drawing.Color]::Transparent
            $btViewPanel.Controls.Add($btSigRow)

            # Six panels, created once, keyed by slot. Rebuilding controls every
            # tick would churn the UI thread, which is already this window's
            # bottleneck.
            $btViewTooltip = New-Object System.Windows.Forms.ToolTip
            $btViewTooltip.AutoPopDelay = 20000
            $btViewTooltip.InitialDelay = 350
            foreach ($spec in @(
                @{ Slot = 'Host';     Row = $btConnRow },
                @{ Slot = 'Wireless'; Row = $btConnRow },
                @{ Slot = 'Arc';      Row = $btConnRow },
                @{ Slot = 'App';      Row = $btSigRow  },
                @{ Slot = 'Com';      Row = $btSigRow  },
                @{ Slot = 'Data';     Row = $btSigRow  }
            )) {
                $tile = New-Object System.Windows.Forms.Panel
                $tile.BackColor = [System.Drawing.Color]::Transparent
                $tile.Cursor = [System.Windows.Forms.Cursors]::Hand
                # The whole panel is the click target, and the text is PAINTED
                # rather than placed in child labels: a child label would swallow
                # the click and the evidence dialog would be unreachable from
                # half the tile.
                $tile.Add_Paint($script:BtViewTilePaint)
                $tile.Add_Click({ script:Show-BtViewTileDetail -Owner $this.FindForm() -Tile $this })
                $spec.Row.Controls.Add($tile)
                $script:BtView_Tiles[$spec.Slot] = $tile
            }

            # The verdict. ONE sentence, in the operator's words. The engineer's
            # sentence -- "FIRST FAILING STEP: <edge>. (6 of 8 steps verified.)" --
            # is not deleted: it is Chain.Summary and it renders unchanged on the
            # boundary line inside the technical details, and it is what
            # chain.jsonl records.
            $btVerdictLabel = New-Object System.Windows.Forms.Label
            $btVerdictLabel.Text = ""
            $btVerdictLabel.AutoSize = $false
            $btVerdictLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
            $btVerdictLabel.ForeColor = $script:BtViewInk
            $btVerdictLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $btViewPanel.Controls.Add($btVerdictLabel)

            $btVerdictContextLabel = New-Object System.Windows.Forms.Label
            $btVerdictContextLabel.Text = ""
            $btVerdictContextLabel.AutoSize = $false
            $btVerdictContextLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $btVerdictContextLabel.ForeColor = $script:BtViewInkDim
            $btVerdictContextLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $btViewPanel.Controls.Add($btVerdictContextLabel)

            # PERMANENT, and deliberately not a panel. Every measurable step going
            # green is routinely read as "the session is fine". It is not: nothing
            # in this tool validates EEG content. As a node in the chain it was
            # NotMeasurable on every tick of every recording and readers learned to
            # skip it; as a footnote under the verdict it is read at the moment the
            # conclusion it limits is being drawn.
            $btFootnoteLabel = New-Object System.Windows.Forms.Label
            $btFootnoteLabel.Text = "EEG signal quality cannot be measured by this tool."
            $btFootnoteLabel.AutoSize = $false
            $btFootnoteLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btFootnoteLabel.ForeColor = [System.Drawing.Color]::FromArgb(110, 110, 122)
            $btFootnoteLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $btViewPanel.Controls.Add($btFootnoteLabel)

            # ── Session events ────────────────────────────────────────────────
            # TRANSITIONS ONLY, newest last, at most six. The heartbeat lines
            # ("... watching [108s] Device: Paired | Port open") and every other
            # repeated line stay in the raw log where they belong.
            #
            # This is a FILTER AT RENDER TIME, not at collection time: everything
            # dropped here is still written to events.jsonl and still printed in
            # the raw log. A filter in the collector would remove evidence from the
            # capture, which is the one thing this redesign must not do.
            $script:BtRec_ViewEvents = New-Object System.Collections.ArrayList
            $btEventsHeading = New-Object System.Windows.Forms.Label
            $btEventsHeading.Text = "SESSION EVENTS"
            $btEventsHeading.AutoSize = $false
            $btEventsHeading.Font = New-Object System.Drawing.Font("Segoe UI", 7.5, [System.Drawing.FontStyle]::Bold)
            $btEventsHeading.ForeColor = [System.Drawing.Color]::FromArgb(110, 110, 122)
            $btEventsHeading.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            $btViewPanel.Controls.Add($btEventsHeading)

            $btEventsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $btEventsPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $btEventsPanel.WrapContents = $false
            $btEventsPanel.AutoSize = $false
            $btEventsPanel.BackColor = [System.Drawing.Color]::Transparent
            $btViewPanel.Controls.Add($btEventsPanel)
            $script:BtView_EventLabels = @()
            for ($i = 0; $i -lt 6; $i++) {
                $el = New-Object System.Windows.Forms.Label
                $el.AutoSize = $true
                $el.Text = ""
                $el.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                $el.Font = New-Object System.Drawing.Font("Consolas", 8.5)
                $el.ForeColor = $script:BtViewInkDim
                $btEventsPanel.Controls.Add($el)
                $script:BtView_EventLabels += $el
            }

            # The disclosure control. Unobtrusive, bottom-right, and the window
            # opens with the details CLOSED.
            $btTechToggleBtn = New-Object System.Windows.Forms.Button
            $btTechToggleBtn.Text = "Technical details"
            $btTechToggleBtn.AutoSize = $true
            $btTechToggleBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btTechToggleBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btTechToggleBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 60, 70)
            $btTechToggleBtn.BackColor = $script:BtViewBack
            $btTechToggleBtn.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 162)
            $btTechToggleBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btTechToggleBtn.Add_Click({ script:Switch-BtTechnicalDetails })
            $btViewPanel.Controls.Add($btTechToggleBtn)

            # Laid out by hand, from the panel's own client size, so the diagram
            # keeps its whitespace at every window size instead of a nested stack
            # of AutoSize containers deciding it. Re-run on every resize.
            #
            # AutoScroll is the guard against the failure this window has a
            # history of: on a display too short for the content, controls used to
            # be CLIPPED rather than reachable (#64). Here they scroll.
            $btViewPanel.AutoScroll = $true
            $btViewPanel.Add_Resize({ script:Set-BtRecorderViewLayout })

            # The control registry the layout, the renderer and the disclosure
            # toggle read. script:-scoped because none of those run in the scope
            # this file was written in.
            $script:BtView = @{
                Panel         = $btViewPanel
                ConnHeading   = $btConnHeading
                ConnRow       = $btConnRow
                SigHeading    = $btSigHeading
                SigRow        = $btSigRow
                Verdict       = $btVerdictLabel
                Context       = $btVerdictContextLabel
                Footnote      = $btFootnoteLabel
                EventsHeading = $btEventsHeading
                EventsPanel   = $btEventsPanel
                TechToggle    = $btTechToggleBtn
                TechPanel     = $btTechPanel
                Tooltip       = $btViewTooltip
                # Registered so the disclosure toggle can re-measure them; they
                # are still rendered only by Update-BtChainPanel.
                ScopeLabel    = $btScopeLabel
                BoundaryLabel = $btBoundaryLabel
            }

            # =================================================================
            # ASSEMBLY
            # =================================================================
            # Dock order IS add order, and getting it wrong is issue #64. Read it
            # as: last added wins the outer edge. Bottom edge first (status bar
            # outermost, technical panel above it), then the Top group from the
            # inside out, and finally the Fill panel forced to child index 0 so it
            # is laid out LAST and receives whatever rectangle is left.
            $btForm.Controls.Add($btTechPanel)      # Bottom, inner
            $btForm.Controls.Add($btStatusPanel)    # Bottom, outermost
            $btForm.Controls.Add($btBanner)         # Top, innermost
            $btForm.Controls.Add($btAnomalyBar)     # Top
            $btForm.Controls.Add($btIdentityPanel)  # Top, outermost (header)
            $btForm.Controls.Add($btViewPanel)      # Fill
            $btForm.Controls.SetChildIndex($btViewPanel, 0)

            $btForm.Show()
            $btForm.Refresh()
            script:Set-BtRecorderViewLayout

            function Write-BtLog {
                param([string]$Message, [string]$Level = "INFO")

                # #68 item 3. Captured HERE, at the one place every startup line
                # passes through, rather than at each of the seven sites that
                # raise one. A per-site hook is a detector that a new call site
                # silently opts out of -- the failure mode is no field data and
                # no test that can see it. The choke point cannot be un-called.
                #
                # Marker OR level, because both channels exist in this code and
                # neither is a superset: the arrival cross-check carries [!]/[~]
                # markers, while the USB-suspend risk factor is a bare WARN line.
                if ($script:BtRec_StartupPhase -and $null -ne $script:BtRec_StartupFindings) {
                    if ($Level -in @('FAIL', 'WARN') -or $Message -match '^\s*\[[!~]\]') {
                        # Level travels WITH the message. Re-deriving severity in
                        # the viewer would be a second answerer to a question this
                        # call already answered, and it would silently downgrade
                        # every finding that carries no [!]/[~] marker.
                        if ($Message.Trim()) {
                            [void]$script:BtRec_StartupFindings.Add([pscustomobject]@{
                                Level = $Level; Message = $Message.TrimEnd()
                            })
                        }
                        if ($btStartupFindingsBtn -and $script:BtRec_StartupFindings.Count -gt 0) {
                            $btStartupFindingsBtn.Text = "Startup findings ($($script:BtRec_StartupFindings.Count))"
                            if (-not $btStartupFindingsBtn.Visible) { $btStartupFindingsBtn.Visible = $true }
                        }
                    }
                }

                Write-WinConfigGuiDiagnostic -Level $Level -Message $Message -Box $btOutputBox -NoPrefix
                # Repaint the log box only, NOT the whole form. $btForm.Refresh()
                # invalidates and synchronously redraws every control in the tree
                # (banner, status strip, five state labels, button row) on every
                # single log line. A paint is still forced here on purpose: large
                # stretches of this routine block the UI thread with no message
                # pump running, and without an explicit paint the operator would
                # watch a blank window during the baseline.
                $btOutputBox.Update()
            }

            # Re-surfaces the startup findings on demand (#68 item 3).
            #
            # A RichTextBox rather than a MessageBox on purpose: the reason this
            # issue exists is that the operator had to select and copy the
            # findings out of the log to preserve them, and a MessageBox can be
            # neither scrolled nor partially selected. It is also the diagnostic
            # output contract -- semantic colouring has to survive, so a [!] here
            # reads the same as it did in the log. Modal is safe: the recorder
            # host is STA and this runs on its UI thread.
            function script:Show-BtStartupFindings {
                param($Owner)
                $items = @($script:BtRec_StartupFindings)
                $dlg = New-Object System.Windows.Forms.Form
                $dlg.Text = "Findings from the start of this recording"
                $dlg.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
                $dlg.ClientSize = New-Object System.Drawing.Size(820, 420)

                $hdr = New-Object System.Windows.Forms.Label
                $hdr.Dock = [System.Windows.Forms.DockStyle]::Top
                $hdr.Height = 34
                $hdr.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)
                $hdr.Text = "These were raised before recording began and stay available for the whole run."
                $dlg.Controls.Add($hdr)

                $tb = New-Object System.Windows.Forms.RichTextBox
                $tb.ReadOnly = $true
                $tb.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
                $tb.WordWrap = $false
                $tb.Dock = [System.Windows.Forms.DockStyle]::Fill
                Initialize-WinConfigGuiDiagnosticBox -Box $tb
                if ($items.Count -gt 0) {
                    foreach ($it in $items) {
                        Write-WinConfigGuiDiagnostic -Level $it.Level -Message $it.Message -Box $tb -NoPrefix
                    }
                } else {
                    # Absence rendered as absence (#68 item 4): the button is
                    # hidden while there are none, so an empty list HERE means the
                    # collection was lost, not that the start was clean.
                    Write-WinConfigGuiDiagnostic -Level 'WARN' -Box $tb -NoPrefix `
                        -Message "No startup findings were retained. This is NOT a statement that the start was clean -- scroll to the top of the log to read it directly."
                }
                $dlg.Controls.Add($tb)
                $dlg.Controls.SetChildIndex($tb, 0)

                $close = New-Object System.Windows.Forms.Button
                $close.Text = "Close"
                $close.Dock = [System.Windows.Forms.DockStyle]::Bottom
                $close.Height = 32
                $close.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $dlg.Controls.Add($close)
                $dlg.AcceptButton = $close

                if ($Owner) { [void]$dlg.ShowDialog($Owner) } else { [void]$dlg.ShowDialog() }
                $dlg.Dispose()
            }

            # Per-node evidence, on click. FACT AND INTERPRETATION ARE SEPARATED
            # HERE, under their own headings, because the recorder's findings
            # already mix them -- "the most likely reason by far is that the
            # headset is switched off" is a useful sentence and it is not an
            # observation. A reader who cannot tell which is which cannot judge
            # how far to trust the conclusion, and this window is read by people
            # deciding whether to re-pair a headset or send a machine away.
            #
            # script: scope and $this.Tag rather than a closure: an Add_Click
            # scriptblock does not run in the scope it was written in, so a
            # captured variable resolves to nothing at click time and the failure
            # is a dead button on a field machine.
            function script:Show-BtChainNodeDetail {
                param($Owner, $Node)
                if (-not $Node) { return }

                $statusWord = switch ($Node.Health) {
                    'Healthy'  { 'OK' }
                    'Failed'   { 'FAILING' }
                    'Degraded' { 'GETTING WORSE' }
                    'Idle'     { 'IDLE (not a fault)' }
                    default    {
                        if ($Node.Observation -eq 'NotMeasurable') { 'NOT MEASURABLE BY THIS TOOL' }
                        elseif ($Node.Observation -eq 'NotObserved') { 'NOT OBSERVED -- no reading was taken' }
                        else { 'UNKNOWN' }
                    }
                }

                $lines = New-Object System.Collections.ArrayList
                [void]$lines.Add($Node.Title)
                [void]$lines.Add(('-' * $Node.Title.Length))
                [void]$lines.Add("State      : $($Node.Detail)")
                [void]$lines.Add("Status     : $statusWord")
                [void]$lines.Add("Reading    : $($Node.Observation)")
                if ($Node.EdgeLabel) { [void]$lines.Add("This step  : $($Node.EdgeLabel)") }
                if ($Node.BlockedBy) {
                    [void]$lines.Add("")
                    [void]$lines.Add("EXPLAINED BY: $($Node.BlockedBy)")
                    [void]$lines.Add("This step depends on that one, so its state here is a consequence.")
                    [void]$lines.Add("Fix the step above first; this is not a separate problem to chase.")
                }

                # Grouped by evidence kind rather than listed flat. The grouping
                # IS the message.
                $groups = @(
                    @{ Kind = 'Observed';      Head = 'OBSERVED  (directly measured)' }
                    @{ Kind = 'Inferred';      Head = 'INFERRED  (concluded from the above, not measured)' }
                    @{ Kind = 'Historical';    Head = 'HISTORICAL  (true earlier; not re-checked just now)' }
                    @{ Kind = 'NotObserved';   Head = 'NOT OBSERVED  (no reading exists)' }
                    @{ Kind = 'NotMeasurable'; Head = 'BEYOND THIS TOOL' }
                )
                foreach ($grp in $groups) {
                    $items = @($Node.Evidence | Where-Object { $_.Kind -eq $grp.Kind })
                    if ($items.Count -eq 0) { continue }
                    [void]$lines.Add("")
                    [void]$lines.Add($grp.Head)
                    foreach ($it in $items) { [void]$lines.Add("  - $($it.Text)") }
                }

                [void][System.Windows.Forms.MessageBox]::Show(
                    ($lines -join "`r`n"), "Evidence: $($Node.Title)",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
            }

            # Refreshes the pinned identity/coverage strip from live session state.
            #
            # Reads the SAME Get-ProbeObservationCoverage the closing report is
            # built from -- deliberately not a second, simpler live estimate. Two
            # pieces of code independently answering "is this recording seeing the
            # session?" is exactly the split that produced the false-green closing
            # verdict and the wrong-headset capture; the live strip and the final
            # report must be the same answerer or they will eventually disagree.
            #
            # Assigns only on change: these labels are AutoSize inside an AutoSize
            # docked panel, so every assignment costs a layout pass.
            # How long NeurOptimal may be running with nothing observed on the
            # target before the coverage line escalates. Long enough that normal
            # session start-up does not trip it, short enough to be actionable
            # inside a session rather than in the closing report.
            $btCoverageEscalateSec = 120
            $script:BtRec_NoRunningSince = $null

            # Renders the diagnostic chain. A RENDERER ONLY -- every judgement
            # here (which node is the root cause, which are consequences, how far
            # the chain is verified) is made by Get-BtDiagnosticChain and read off
            # the object. Nothing in this function decides anything, deliberately:
            # a second place that works out what is wrong is a second place that
            # can disagree with the first, and the one a human happens to be
            # looking at wins.
            #
            # It drives BOTH views: the visual panel an operator reads, through
            # Get-BtRecorderView, and the eight chips an engineer reads inside the
            # technical details. That is one chain object through one mapping, NOT
            # two readers of session state -- which is the whole point.
            function Update-BtChainPanel {
                param($Chain)
                if (-not $Chain -or -not $btChainPanel) { return }
                if (-not $btChainPanel.Visible) { $btChainPanel.Visible = $true }

                # The operator's view first. It is the default screen, so a
                # failure to render the chips below must not cost it.
                if (Get-Command Get-BtRecorderView -ErrorAction SilentlyContinue) {
                    $view = try { Get-BtRecorderView -Chain $Chain } catch { $null }
                    if ($view) { script:Update-BtRecorderPanel -View $view -Chain $Chain }
                }

                # ── Scope line ───────────────────────────────────────────────
                # Marker word AND colour. A confirmed target is stated plainly
                # and quietly; an unconfirmed one leads with the words, because
                # this is the line that stops a reader acting on a boundary
                # attributed to a headset nobody identified.
                if ($btScopeLabel) {
                    $sText = switch ($Chain.LocalizationScope) {
                        'Confirmed'   { "TARGET: $(if ($Chain.TargetLabel) { $Chain.TargetLabel } else { 'confirmed' })  --  $($Chain.TargetEvidence)" }
                        'Provisional' { "[?] TARGET NOT CONFIRMED  --  candidate: $(if ($Chain.TargetLabel) { $Chain.TargetLabel } else { 'not named' }).  $($Chain.TargetEvidence)  Everything below is provisional." }
                        'Suspended'   { "[!] TARGET NOT CONFIRMED  --  $($Chain.TargetEvidence)  No failing step can be attributed to a device until the headset is identified." }
                        default       { "[?] TARGET NOT STATED  --  this recording did not record which headset the chain below describes." }
                    }
                    $sCol = switch ($Chain.LocalizationScope) {
                        'Confirmed'   { [System.Drawing.Color]::FromArgb(150, 170, 150) }
                        'Provisional' { [System.Drawing.Color]::FromArgb(225, 190, 110) }
                        'Suspended'   { [System.Drawing.Color]::FromArgb(240, 150, 110) }
                        default       { [System.Drawing.Color]::FromArgb(150, 185, 235) }
                    }
                    if ($btScopeLabel.Text -ne $sText) { $btScopeLabel.Text = $sText }
                    if ($btScopeLabel.ForeColor -ne $sCol) { $btScopeLabel.ForeColor = $sCol }
                }

                foreach ($node in $Chain.Nodes) {
                    # Marker text AND colour, never colour alone. Roughly one man
                    # in twelve cannot separate this palette's green from its red,
                    # and these windows get read over a phone from a screenshot.
                    $marker = switch ($node.Health) {
                        'Healthy'  { '[ok]' }
                        'Failed'   { '[!]' }
                        'Degraded' { '[~]' }
                        'Idle'     { '[idle]' }
                        default    {
                            if ($node.Observation -eq 'NotMeasurable') { '[n/a]' }
                            elseif ($node.Observation -eq 'NotObserved') { '[not observed]' }
                            else { '[?]' }
                        }
                    }
                    $colour = switch ($node.Health) {
                        'Healthy'  { [System.Drawing.Color]::FromArgb(70, 190, 90) }
                        'Failed'   { [System.Drawing.Color]::FromArgb(235, 95, 95) }
                        'Degraded' { [System.Drawing.Color]::FromArgb(225, 175, 55) }
                        'Idle'     { [System.Drawing.Color]::FromArgb(150, 150, 150) }
                        default    {
                            # Blue-grey for "nobody looked", NOT the neutral grey
                            # the measured-but-idle states use. Grey is what an
                            # operator reads as "fine, nothing happening"; an
                            # unread sensor must not look the same as a reading.
                            if ($node.Observation -eq 'NotObserved') { [System.Drawing.Color]::FromArgb(120, 155, 205) }
                            else { [System.Drawing.Color]::FromArgb(125, 125, 125) }
                        }
                    }

                    $text = "$marker $($node.Title): $($node.Detail)"
                    if ($node.BlockedBy) {
                        # A consequence recedes. The leading dot carries it for
                        # readers who cannot use the dimming.
                        $text = ". $text"
                        $colour = [System.Drawing.Color]::FromArgb(
                            [int]($colour.R * 0.55), [int]($colour.G * 0.55), [int]($colour.B * 0.55))
                    }

                    $lbl = $script:BtChain_NodeLabels[$node.Id]
                    if (-not $lbl) {
                        $lbl = New-Object System.Windows.Forms.Label
                        $lbl.AutoSize = $true
                        $lbl.Margin = New-Object System.Windows.Forms.Padding(0, 2, 14, 2)
                        $lbl.Font = New-Object System.Drawing.Font("Consolas", 8)
                        $lbl.Cursor = [System.Windows.Forms.Cursors]::Hand
                        $lbl.Add_Click({ script:Show-BtChainNodeDetail -Owner $this.FindForm() -Node $this.Tag })
                        $btChainRow.Controls.Add($lbl)
                        $script:BtChain_NodeLabels[$node.Id] = $lbl
                    }
                    # Tag carries the node for the click handler, which cannot see
                    # this scope. Refreshed every render so a dialog opened at
                    # 14:32 shows 14:32's evidence and not the first tick's.
                    $lbl.Tag = $node
                    if ($lbl.Text -ne $text) { $lbl.Text = $text }
                    if ($lbl.ForeColor -ne $colour) { $lbl.ForeColor = $colour }
                }

                $bColour = switch ($Chain.Localization) {
                    'Failure'     { [System.Drawing.Color]::FromArgb(255, 130, 130) }
                    'Degrading'   { [System.Drawing.Color]::FromArgb(240, 195, 90) }
                    'Idle'        { [System.Drawing.Color]::FromArgb(180, 180, 180) }
                    'LimitOfTool' { [System.Drawing.Color]::FromArgb(150, 210, 165) }
                    default       { [System.Drawing.Color]::FromArgb(150, 185, 235) }
                }
                if ($btBoundaryLabel.Text -ne $Chain.Summary) { $btBoundaryLabel.Text = $Chain.Summary }
                if ($btBoundaryLabel.ForeColor -ne $bColour) { $btBoundaryLabel.ForeColor = $bColour }
                # An AutoSize label in a FlowLayoutPanel does not wrap unless it is
                # given a maximum width, and an unwrapped sentence this long forces
                # the panel wider than the form -- the clipping failure mode #64
                # was about. Recomputed each render so it survives a resize.
                $maxW = $btChainPanel.ClientSize.Width - [int](24 * $script:BtViewScale)
                if ($maxW -gt 100 -and $btBoundaryLabel.MaximumSize.Width -ne $maxW) {
                    $btBoundaryLabel.MaximumSize = New-Object System.Drawing.Size($maxW, 0)
                }
                # The scope line needs the same treatment for the same reason:
                # it is a sentence, not a chip, and an unwrapped one pushes the
                # panel wider than the form (#64).
                if ($btScopeLabel -and $maxW -gt 100 -and $btScopeLabel.MaximumSize.Width -ne $maxW) {
                    $btScopeLabel.MaximumSize = New-Object System.Drawing.Size($maxW, 0)
                }
            }

            # Computes the chain from live session state, renders it, and
            # persists it when it CHANGES. One function, called from the arrival
            # snapshot and from the tick, so the inputs are assembled in exactly
            # one place: two call sites each mapping session fields onto the
            # module's parameters is two mappings that can drift, and a drift here
            # would show the operator one chain and write another to the capture.
            #
            # PERSIST FIRST, RENDER SECOND, for the reason #87 established: a
            # window closed without uploading used to leave nothing behind. The
            # boundary is the single most useful thing to score a capture by --
            # "what did this recorder believe was broken, and when did that
            # change" -- and until now it did not exist in any file.
            function Update-BtChain {
                if (-not (Get-Command Get-BtDiagnosticChain -ErrorAction SilentlyContinue)) { return }
                if (-not $btProbeWatch -or -not $btProbeSession) { return }

                $portNames = @()
                if ($btProbeWatch.ComPortMatches)          { $portNames += @($btProbeWatch.ComPortMatches          | ForEach-Object { $_.PortName }) }
                if ($btProbeWatch.AmbiguousComPortMatches) { $portNames += @($btProbeWatch.AmbiguousComPortMatches | ForEach-Object { $_.PortName }) }
                $portNames = @($portNames | Where-Object { $_ } | Select-Object -Unique | Sort-Object)

                # $null, not $false, when the process channel produced no state.
                # $false here is the claim "NeurOptimal is not running", and an
                # unobserved claim is exactly what the chain's NotObserved rung
                # exists to keep out.
                $appRunning = switch ($btProbeWatch.AppProcessState) {
                    'Running'    { $true }
                    'NotRunning' { $false }
                    default      { $null }
                }

                $chainArgs = @{
                    DeviceState         = $btProbeWatch.DeviceState
                    ComPortState        = $btProbeWatch.ComPortState
                    ComPortNames        = $portNames
                    BtLinkState         = $btProbeSession.BtLinkState
                    StreamState         = $btProbeSession.StreamingState
                    HeldPorts           = @($btProbeSession.HeldPorts | Where-Object { $_ })
                    UnavailablePorts    = @($btProbeSession.UnavailablePorts | Where-Object { $_ })
                    AppRunning          = $appRunning
                    BtLinkEverConnected = [bool]$btProbeSession.BtLinkEverConnected
                    # The locked setting, NOT a re-read of the environment. The
                    # toggle is resolved once per run on purpose (#94); asking the
                    # environment again here could disagree with the run's own
                    # recorded arm.
                    PortHoldObserved    = [bool]$btProbeSession.ActivePortOpenProbeEnabled
                    IoObserved          = [bool]$btProbeSession.IoApiAvailable
                    IoVerdict           = $btProbeSession.IoVerdict
                    IoSamplesTotal      = [int]$btProbeSession.IoSamplesTotal
                    AdapterInfo         = $btProbeSession.AdapterInfo
                }

                # DATA/COMMAND roles for the COM Ports panel, from the SAME
                # ComPortMatches the closing report reads -- not a second, simpler
                # live estimate, for the same reason the coverage line reuses
                # Get-ProbeObservationCoverage. Resolve-ComPortRole decides the
                # role; this only carries it. Left absent when the function is
                # missing from the build: the chain renders that as 'NotStated'
                # and the panel falls back to the bare port list, which is a
                # different thing from a mapping that came back empty.
                if (Get-Command Get-ComPortRoleMap -ErrorAction SilentlyContinue) {
                    $btRoleMap = try { Get-ComPortRoleMap -WatchState $btProbeWatch } catch { $null }
                    if ($btRoleMap) { $chainArgs.ComPortRoleMap = $btRoleMap }
                }

                # ── Target binding: the PREREQUISITE for any device-scoped
                # claim below. Computed here, at the one place the chain's
                # inputs are assembled, for the same reason everything else in
                # this hashtable is: a second mapping is a second thing that can
                # drift, and a drift here would show the operator one scope and
                # write another to the capture.
                #
                # The chain used to be able to print "FIRST FAILING STEP:
                # adapter present -> Windows pairing record" while the identity
                # strip two lines above printed "NO HEADSET SELECTED". Those
                # cannot both be safe: without knowing which headset, the
                # honest claim is that the fallback CANDIDATE has no device
                # record, not that the session's headset failed to pair.
                $btBinding = $null
                if (Get-Command Get-BtTargetBinding -ErrorAction SilentlyContinue) {
                    # The record MAC is only ever a FALLBACK identity, and it is
                    # read from the session's own resolved value rather than
                    # re-resolved here. It is populated exactly when PnP had no
                    # node -- which is the state that produced this defect.
                    $btRecMac  = if ($btProbeSession.PairingTargetSource -eq 'PairingRecord') { [string]$btProbeSession.PairingTargetMac } else { '' }
                    $btRecName = ''
                    if ($btRecMac -and $btProbeSession.PairingRecord) {
                        $btRecName = [string](@($btProbeSession.PairingRecord.Records |
                            Where-Object { $_ -and $_.Mac -and (([string]$_.Mac -replace '[^0-9A-Fa-f]','').ToUpperInvariant() -eq ($btRecMac -replace '[^0-9A-Fa-f]','').ToUpperInvariant()) } |
                            ForEach-Object { $_.Name } | Select-Object -First 1))
                    }
                    $btBinding = try {
                        Get-BtTargetBinding -SessionTarget $btProbeSession.SessionTarget `
                            -RecordCandidateMac $btRecMac -RecordCandidateName $btRecName
                    } catch { $null }
                }
                if ($btBinding) {
                    $chainArgs.TargetBinding         = $btBinding.Binding
                    $chainArgs.TargetLabelName       = [string]$btBinding.Name
                    $chainArgs.TargetLabelMac        = [string]$btBinding.Mac
                    $chainArgs.TargetBindingEvidence = [string]$btBinding.Evidence
                }
                # TargetState, and ONLY when the check was scoped. Records[] is
                # every BTHPORT record on the box, so counting it would report
                # "this headset has a pairing record" because a mouse does --
                # a fabricated observation, and the same trap OrphanCount sets
                # by reading 0 on an unscoped run.
                #
                # $null when nothing looked, never $false. $false is the claim
                # "Windows holds no pairing record for this headset", and the
                # chain's Pairing node says exactly that in words -- so an
                # unchecked record must not arrive wearing it.
                # The presence test handles BOTH shapes on purpose: this record is
                # a hashtable today, and a PSObject.Properties test alone would
                # read $false against it and silently never wire the field --
                # which is the failure mode where a detector nobody feeds
                # produces no field data.
                $btPr = $btProbeSession.PairingRecord
                $btPrHasState = $false
                if ($btPr -is [hashtable]) { $btPrHasState = $btPr.ContainsKey('TargetState') }
                elseif ($btPr)             { $btPrHasState = ($btPr.PSObject.Properties.Name -contains 'TargetState') }
                if ($btPr -and $btPr.Scoped -and $btPrHasState -and $btPr.TargetState) {
                    $chainArgs.PairingRecordPresent = ([string]$btPr.TargetState -ne 'NoRecord')
                }
                if ($null -ne $btProbeSession.IoFractionOfBaseline)   { $chainArgs.IoFractionOfBaseline   = [double]$btProbeSession.IoFractionOfBaseline }
                if ($null -ne $btProbeSession.IoRecentOpsPerSecond)   { $chainArgs.IoRecentOpsPerSecond   = [double]$btProbeSession.IoRecentOpsPerSecond }
                if ($null -ne $btProbeSession.IoBaselineOpsPerSecond) { $chainArgs.IoBaselineOpsPerSecond = [double]$btProbeSession.IoBaselineOpsPerSecond }

                $chain = $null
                try { $chain = Get-BtDiagnosticChain @chainArgs } catch { return }
                if (-not $chain) { return }

                # Keyed on the FULL node vector, not just the boundary. A node
                # degrading below the boundary is a real change in what this
                # recorder believes, and a file that only recorded boundary moves
                # would render those ticks as "nothing happened".
                # The BINDING is part of the key. A recording that starts
                # unscoped and later resolves its target (the late-MAC path
                # below) has changed what this recorder believes it is
                # describing, which is at least as material as a node moving --
                # and with the boundary gated on scope, the summary changes with
                # it. Keyed on nodes alone, that transition wrote no line.
                $key = ($chain.Nodes | ForEach-Object {
                    "$($_.Id)=$($_.Health)/$($_.Observation)/$(if ($_.BlockedBy) { $_.BlockedBy } else { '-' })"
                }) -join ';'
                $key = "$($chain.TargetBinding)/$($chain.LocalizationScope)|$key"

                if ($btDiagRun -and $key -ne $script:BtChain_LastBoundaryKey) {
                    $wrote = Add-WinConfigDiagnosticJsonLine -RunFolder $btDiagRun.RunFolder -Name 'chain.jsonl' -Depth 6 -Data ([ordered]@{
                        AtUtc          = (Get-Date).ToUniversalTime().ToString('o')
                        BoundaryNodeId = $chain.BoundaryNodeId
                        BoundaryEdge   = $chain.BoundaryEdge
                        Localization   = $chain.Localization
                        Confidence     = $chain.Confidence
                        # Scope travels with every line, not just the ones where
                        # it is bad. A reader scoring an archived capture has to
                        # be able to ask "was this boundary even attributable?"
                        # of any line, and an absent field would be answered
                        # optimistically.
                        TargetBinding     = $chain.TargetBinding
                        TargetConfirmed   = $chain.TargetConfirmed
                        TargetLabel       = $chain.TargetLabel
                        TargetEvidence    = $chain.TargetEvidence
                        LocalizationScope = $chain.LocalizationScope
                        Verified       = @($chain.VerifiedNodeIds)
                        Roots          = @($chain.RootNodeIds)
                        Blocked        = @($chain.BlockedNodeIds)
                        Consequences   = @($chain.ConsequenceNodeIds)
                        Summary        = $chain.Summary
                        Nodes          = @($chain.Nodes | ForEach-Object {
                            [ordered]@{ Id = $_.Id; Health = $_.Health; Observation = $_.Observation; BlockedBy = $_.BlockedBy; Detail = $_.Detail }
                        })
                        EpisodeId      = $btProbeSession.IoEpisodeId
                        TickIndex      = [int]$btProbeSession.TickCount
                    })
                    if ($wrote) {
                        $script:BtChain_LastBoundaryKey = $key
                        $script:BtChain_LinesWritten = [int]$script:BtChain_LinesWritten + 1
                    } else {
                        # Counted, never silent -- a timeline with holes that reads
                        # as complete is the same class of lie as an unmeasured
                        # zero rendered as 0. The key is NOT advanced on a failed
                        # write, so the next tick retries this state rather than
                        # treating it as recorded.
                        $script:BtChain_LinesDropped = [int]$script:BtChain_LinesDropped + 1
                    }
                }

                Update-BtChainPanel -Chain $chain
            }

            function Update-BtLiveCoverage {
                if (-not $btIdentityPanel) { return }
                if (-not $btIdentityPanel.Visible) { $btIdentityPanel.Visible = $true }

                # The header is the RUN's identity now, and nothing else. Which
                # headset this recording is watching, and which of its COM ports
                # is DATA and which is COMMAND, are rendered once each -- in the
                # Arc panel and the COM Ports panel -- from the chain, which is
                # the one answerer for both. This function used to answer "which
                # headset" a second time from $btProbeTargetMac and could
                # disagree with the picture below it.
                $dText = "Run ID: $script:BtRec_RunIdText"
                if ($btIdentityDetailLabel.Text -ne $dText) { $btIdentityDetailLabel.Text = $dText }

                # How long NeurOptimal has been up. Not-yet-observed is the NORMAL
                # state before a session starts, so it is only worth escalating
                # once a session could reasonably have been expected. This is
                # presentation context applied to the one coverage answer, not a
                # second opinion about it -- the level below still comes entirely
                # from Get-ProbeObservationCoverage.
                $noUp = ($btProbeWatch -and $btProbeWatch.AppProcessState -eq 'Running')
                if ($noUp) {
                    if (-not $script:BtRec_NoRunningSince) { $script:BtRec_NoRunningSince = Get-Date }
                } else {
                    $script:BtRec_NoRunningSince = $null
                }
                $noUpSec = if ($script:BtRec_NoRunningSince) {
                    ((Get-Date) - $script:BtRec_NoRunningSince).TotalSeconds
                } else { 0 }

                # The duration is evidence supplied to the pure coverage rule;
                # this renderer does not decide whether silence is a scope
                # conflict. The returned structured finding is also persisted in
                # probe-session.json, so the warning survives the screenshot.
                $cov = $null
                if (Get-Command Get-ProbeObservationCoverage -ErrorAction SilentlyContinue) {
                    $cov = try {
                        Get-ProbeObservationCoverage -Session $btProbeSession -WatchState $btProbeWatch `
                            -Target $btProbeSession.SessionTarget -AppRunningSeconds ([int]$noUpSec) `
                            -ScopeWarningThresholdSeconds $btCoverageEscalateSec
                    } catch { $null }
                }
                if ($cov) {
                    # Latch context findings on the session so a contradiction
                    # observed live remains in the closing Coverage object even
                    # if NeurOptimal exits before Stop is pressed.
                    $btProbeSession.ScopeFindings = @($cov.Findings)
                }

                $cText = 'Measurement status unavailable'
                $cCol  = [System.Drawing.Color]::FromArgb(190, 190, 190)
                $neutral = [System.Drawing.Color]::FromArgb(190, 190, 190)
                if ($cov) {
                    switch ($cov.Level) {
                        'Observed' {
                            # SHORTENED, not weakened. The three things it used to
                            # enumerate -- headset linked, COM port held, data flow
                            # measured -- are now three panels on the screen above
                            # it, and restating them in a sentence is the duplicate
                            # state this redesign removes. The LEVEL is unchanged
                            # and still comes from Get-ProbeObservationCoverage.
                            $cText = '[ok] Observing this session'
                            $cCol  = [System.Drawing.Color]::FromArgb(120, 190, 130)
                        }
                        'Partial' {
                            $missing = @()
                            if (-not $cov.TargetEverLinked)   { $missing += 'never linked to the radio' }
                            # NOT OBSERVED and NEVER HELD are different strip
                            # texts, because they are different facts. With the
                            # active port-open probe disabled nothing looked, and
                            # "COM port never held" would be the recorder
                            # reporting a finding it did not make.
                            if ($null -eq $cov.TargetPortEverHeld) {
                                $missing += 'COM port hold NOT OBSERVED (active port-open probe disabled)'
                            } elseif (-not $cov.TargetPortEverHeld) {
                                $missing += 'COM port never held'
                            }
                            if ($cov.IoSampleCount -eq 0)     { $missing += 'data flow not measured yet' }
                            $cText = "[~] Partly observing -- $($missing -join '; ')"
                            $cCol  = [System.Drawing.Color]::FromArgb(240, 210, 110)
                        }
                        default {
                            # NotObserved. Waiting is not a fault: a red alarm from
                            # the moment the window opens is noise the operator
                            # learns to ignore, which is precisely the state they
                            # would need to notice later.
                            if (-not $noUp) {
                                $cText = 'Waiting for the headset session -- start NeurOptimal and begin a session'
                                $cCol  = $neutral
                            } else {
                                $cText = 'Waiting for session activity on this headset -- NeurOptimal is running'
                                $cCol  = $neutral
                            }
                        }
                    }
                    # Context findings outrank component/coverage status, but
                    # they do not turn a graph node red. The module classifies
                    # this as EvidenceConflict: the likely defect is scope, not
                    # necessarily Bluetooth or NeurOptimal.
                    $scopeFinding = @($cov.Findings | Where-Object { $_.Code -eq 'ScopeMismatchSuspected' } | Select-Object -First 1)
                    if ($scopeFinding.Count -gt 0) {
                        $finding = $scopeFinding[0]
                        $evidenceText = @($finding.Evidence | Where-Object { $_ }) -join ' '
                        $cText = "[!] $($finding.Title) -- $evidenceText $($finding.Summary)"
                        $cCol  = if ($finding.Severity -eq 'High') {
                            [System.Drawing.Color]::FromArgb(255, 120, 120)
                        } else {
                            [System.Drawing.Color]::FromArgb(255, 140, 140)
                        }
                    }
                }
                if ($btCoverageLabel.Text -ne $cText) { $btCoverageLabel.Text = $cText }
                if ($btCoverageLabel.ForeColor -ne $cCol) { $btCoverageLabel.ForeColor = $cCol }
            }

            # Blocking wait that keeps the message pump alive.
            #
            # The recorder is a manual DoEvents loop, so between pumps the window
            # is frozen: a flat Start-Sleep -Milliseconds 200 meant input was
            # serviced 5 times a second and dragging the window was visibly
            # jerky even when no probe work was running. Slicing the same wait
            # and pumping each slice costs nothing measurable (DoEvents on an
            # empty queue is cheap) and drops the acknowledgement latency for
            # Stop, Abort and Mark from up to 200 ms to roughly one slice.
            # -BreakOnOperatorAction returns the moment Stop/Abort/Mark is pressed,
            # so the recording loop acts on the click instead of finishing its wait
            # first. It is OPT-IN, and deliberately not the default: the job-wait
            # loops below run with $script:BtRec_StopClicked already $true (that
            # flag is what ended the recording), so defaulting it on would turn the
            # final-snapshot wait into a busy spin.
            function Wait-BtPump {
                param(
                    [int]$Milliseconds = 200,
                    [int]$SliceMs = 15,
                    [switch]$BreakOnOperatorAction
                )
                $deadline = (Get-Date).AddMilliseconds($Milliseconds)
                do {
                    [System.Windows.Forms.Application]::DoEvents()
                    if ($BreakOnOperatorAction -and
                        ($script:BtRec_StopClicked -or $script:BtRec_AbortClicked -or $script:BtRec_MarkRequested)) {
                        return
                    }
                    $left = ($deadline - (Get-Date)).TotalMilliseconds
                    if ($left -le 0) { return }
                    Start-Sleep -Milliseconds ([Math]::Min($SliceMs, [int][Math]::Ceiling($left)))
                } while ((Get-Date) -lt $deadline)
            }

            # Modal chooser shown ONLY when Select-BluetoothSessionTarget refuses
            # to guess between several paired headsets. Returns the chosen MAC, or
            # $null if the operator closed it -- and $null must block the
            # recording, never fall back to a guess. Modal is safe here: the
            # recorder host is STA and this runs on its UI thread.
            function Show-BtTargetChooser {
                param([array]$Candidates = @(), $Owner)
                $cands = @($Candidates | Where-Object { $_ -and $_.Mac })
                if ($cands.Count -eq 0) { return $null }

                $dlg = New-Object System.Windows.Forms.Form
                $dlg.Text = "Which headset is this session using?"
                $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                $dlg.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
                $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
                $dlg.ClientSize = New-Object System.Drawing.Size(560, 210)

                $msg = New-Object System.Windows.Forms.Label
                $msg.Text = "More than one NeurOptimal headset is paired on this computer, and none of them is clearly the one in use. Choose the headset you are about to run the session with. Recording against the wrong one produces a capture that describes a headset that was never in the session."
                $msg.SetBounds(14, 12, 532, 72)
                $dlg.Controls.Add($msg)

                $list = New-Object System.Windows.Forms.ComboBox
                $list.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
                $list.SetBounds(14, 92, 532, 24)
                foreach ($c in $cands) {
                    $act = if (@($c.HeldPorts).Count -gt 0) { "  [in use: $(@($c.HeldPorts) -join ', ')]" }
                           elseif (@($c.ComPorts).Count -gt 0) { "  [ports: $(@($c.ComPorts) -join ', ')]" }
                           else { '  [no COM ports]' }
                    [void]$list.Items.Add("$($c.Name)  --  $($c.Mac)$act")
                }
                $list.SelectedIndex = 0
                $dlg.Controls.Add($list)

                $hint = New-Object System.Windows.Forms.Label
                $hint.Text = "If you are not sure, power on the headset you are about to use, wait for it to connect, then close this and start the recording again."
                $hint.SetBounds(14, 122, 532, 34)
                $dlg.Controls.Add($hint)

                $ok = New-Object System.Windows.Forms.Button
                $ok.Text = "Use this headset"; $ok.SetBounds(300, 166, 130, 30)
                $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $dlg.Controls.Add($ok); $dlg.AcceptButton = $ok

                $cancel = New-Object System.Windows.Forms.Button
                $cancel.Text = "Cancel recording"; $cancel.SetBounds(436, 166, 110, 30)
                $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $dlg.Controls.Add($cancel); $dlg.CancelButton = $cancel

                $res = if ($Owner) { $dlg.ShowDialog($Owner) } else { $dlg.ShowDialog() }
                $picked = $null
                if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $list.SelectedIndex -ge 0) {
                    $picked = $cands[$list.SelectedIndex].Mac
                }
                $dlg.Dispose()
                return $picked
            }

            # ── Diagnostic run folder ─────────────────────────────────────────────
            $btDiagRun = $null
            if (Get-Command New-WinConfigDiagnosticRun -ErrorAction SilentlyContinue) {
                try { $btDiagRun = New-WinConfigDiagnosticRun -ToolId 'bluetooth-diagnostics' } catch { }
            }
            $btRunId = if ($btDiagRun) { $btDiagRun.RunId } else { [guid]::NewGuid().ToString("N").Substring(0,12).ToUpper() }

            # Pinned as well as logged (#68 item 2): the log line is written into
            # the top band and is the first thing pushed out of reach.
            $script:BtRec_RunIdText = $btRunId
            # events.jsonl accounting (#87). Reset per run, so a second recording
            # in one app session does not inherit the first one's totals.
            $script:BtRec_EventLinesWritten = 0
            $script:BtRec_EventLinesDropped = 0
            # chain.jsonl accounting, reset for the same reason. The change key
            # is reset with them: carried over from a previous recording it would
            # suppress the new run's opening chain line as "unchanged", and the
            # capture would open with no boundary at all.
            $script:BtChain_LinesWritten    = 0
            $script:BtChain_LinesDropped    = 0
            $script:BtChain_LastBoundaryKey = $null
            $btIdentityDetailLabel.Text = "Run ID: $btRunId"
            if (-not $btIdentityPanel.Visible) { $btIdentityPanel.Visible = $true }

            Write-BtLog "Run ID: $btRunId" -Level "DIM"
            Write-BtLog "Step 1 of 3: Taking Bluetooth baseline snapshot (5-10 seconds)..." -Level "STEP"

            # ── PHASE 1: Baseline — background job, DoEvents loop keeps UI live ───
            $btBaselineJob = Start-Job -ScriptBlock {
                param($mp)
                Import-Module $mp -Force -ErrorAction Stop
                Invoke-BluetoothDiagnosticsAndRecord -RecordAction {} -TimeoutSeconds 60
            } -ArgumentList $btModPath

            # Pumped wait: the baseline can run for up to 60 s and the window was
            # servicing input 5 times a second throughout it, so the "please wait"
            # phase could not even be dragged out of the way.
            while ($btBaselineJob.State -in @('Running','NotStarted')) {
                Wait-BtPump -Milliseconds 200
            }

            $baselineResult = $null
            try {
                $baselineResult = Receive-Job $btBaselineJob -ErrorAction SilentlyContinue
                Remove-Job $btBaselineJob -Force -ErrorAction SilentlyContinue
            } catch {
                Remove-Job $btBaselineJob -Force -ErrorAction SilentlyContinue
            }

            if ($baselineResult) {
                $vStr  = if ($baselineResult.VerdictStatus) { $baselineResult.VerdictStatus } else { "N/A" }
                $blvl  = switch ($baselineResult.Status) {
                    "Success"        { if ($baselineResult.VerdictStatus -eq "READY") { "OK" } else { "WARN" } }
                    "PartialSuccess" { "WARN" }
                    default          { "WARN" }
                }
                # SCOPED, because this verdict is the AUDIO-domain check and says
                # nothing at all about EEG data flow. Rendered bare it reads as
                # the verdict on the session: on SP9 the operator reported
                # "Verdict=DEGRADED" for a run whose data flow was perfectly
                # Stable, the single finding behind it being "[~] USB selective
                # suspend: ENABLED". A domain-scoped name must say its scope
                # wherever it is rendered or a reader will generalise it
                # (issue #68).
                Write-BtLog "Baseline: $($baselineResult.Status)  Audio verdict=$vStr (audio checks only -- says nothing about EEG data flow)  Findings=$($baselineResult.FindingCount)" -Level $blvl
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try { Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name "baseline.json" -Data $baselineResult } catch { }
                }
            } else {
                Write-BtLog "Baseline complete (Bluetooth adapter may be unavailable)" -Level "WARN"
            }

            # ── PHASE 2: Recording — Deep probe with DoEvents loop ────────────────
            $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(20, 65, 25)
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(160, 240, 160)
            $btBannerLabel.Text      = "Step 2 of 3 - Recording. Reproduce the issue, then click Stop and Upload."

            Write-BtLog ""
            Write-BtLog "Step 2 of 3: Recording in progress" -Level "STEP"
            # An empty events list on a fresh window is ambiguous -- it could mean
            # nothing has happened yet or that the list is not wired. One seeded
            # line removes the ambiguity, and it is a real transition.
            script:Add-BtRecorderEvent -Text 'Recording started' -Level 'OK'

            # Check if deep probe modules are available
            $btDeepProbeAvailable = (Get-Command New-TargetDeviceConfiguration -ErrorAction SilentlyContinue) -and
                                    (Get-Command Initialize-BtWin32Api -ErrorAction SilentlyContinue) -and
                                    (Get-Command New-DeviceProbeSession -ErrorAction SilentlyContinue)

            # Load probe modules if not already loaded
            $btProbeLoadError = $null
            if (-not $btDeepProbeAvailable) {
                $tdwPath = Join-Path $PSScriptRoot "Modules\TargetDeviceWatch.psm1"
                $bdpPath = Join-Path $PSScriptRoot "Modules\BluetoothDeviceProbe.psm1"
                try {
                    if (Test-Path $tdwPath) { Import-Module $tdwPath -Force -DisableNameChecking -ErrorAction Stop }
                    if (Test-Path $bdpPath) { Import-Module $bdpPath -Force -DisableNameChecking -ErrorAction Stop }
                    $btDeepProbeAvailable = (Get-Command New-TargetDeviceConfiguration -ErrorAction SilentlyContinue) -and
                                            (Get-Command Initialize-BtWin32Api -ErrorAction SilentlyContinue)
                } catch {
                    $btProbeLoadError = $_.Exception.Message
                }
            }

            # THE PRIMARY ACTION, and now the only emphasised control on the
            # screen. It sits in the header beside the recording clock rather than
            # in the bottom row, where it used to be one of five same-weight
            # buttons -- the one that ends the recording and sends it to support,
            # rendered at the same size as "Open Folder".
            #
            # AutoSize so the text is never clipped on a scaled display, with
            # padding rather than a fixed size to make it big.
            $script:BtRec_StopClicked = $false
            $btStopBtn = New-Object System.Windows.Forms.Button
            $btStopBtn.Text = "Stop and Upload"
            $btStopBtn.AutoSize = $true
            $btStopBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btStopBtn.Padding = New-Object System.Windows.Forms.Padding(20, 9, 20, 9)
            $btStopBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 2, 0)
            $btStopBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Bold)
            $btStopBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btStopBtn.FlatAppearance.BorderSize = 0
            $btStopBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
            $btStopBtn.ForeColor = [System.Drawing.Color]::White
            $btStopBtn.Add_Click({ $script:BtRec_StopClicked = $true })
            $btHeaderActions.Controls.Add($btStopBtn)

            # Operator marker. The recorder can see the machine but not what
            # NeurOptimal is telling the person in front of it, and NO's error
            # codes are still being mapped -- several dialogs that look identical
            # are different failures underneath. Typing the code here binds it to
            # the full machine state at that instant, which is what turns a
            # recording into a labelled sample instead of an anonymous one.
            $script:BtRec_MarkRequested = $false
            $btMarkBox = New-Object System.Windows.Forms.TextBox
            $btMarkBox.Width = [int](110 * $script:BtViewScale)
            $btMarkBox.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
            # Lighter than the (now dark) status bar behind it. At 35,35,35 on a
            # 28,28,34 panel the field was invisible until it was clicked, and an
            # invisible input is an input nobody uses -- which for this one costs
            # the recording its only label.
            $btMarkBox.BackColor = [System.Drawing.Color]::FromArgb(48, 48, 56)
            $btMarkBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
            $btMarkBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $btMarkBox.Text = "NO code"
            $btMarkBox.Tag = 'placeholder'
            $btMarkBox.Add_Enter({
                if ($this.Tag -eq 'placeholder') { $this.Text = ''; $this.Tag = $null; $this.ForeColor = [System.Drawing.Color]::White }
            })
            $btMarkBox.Add_Leave({
                if ([string]::IsNullOrWhiteSpace($this.Text)) { $this.Text = 'NO code'; $this.Tag = 'placeholder'; $this.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220) }
            })
            $btButtonRow.Controls.Add($btMarkBox)

            $btMarkBtn = New-Object System.Windows.Forms.Button
            $btMarkBtn.Text = "Mark what NO is showing"
            $btMarkBtn.AutoSize = $true
            $btMarkBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btMarkBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $btMarkBtn.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
            $btMarkBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btMarkBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
            $btMarkBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
            $btMarkBtn.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
            $btMarkBtn.Add_Click({ $script:BtRec_MarkRequested = $true })
            $btButtonRow.Controls.Add($btMarkBtn)
            $btButtonRow.Controls.SetChildIndex($btMarkBtn, 0)
            $btButtonRow.Controls.SetChildIndex($btMarkBox, 0)

            # Abort remains visible. It is intentionally quieter than the red
            # primary action, but it must not be hidden behind a disclosure: it
            # is the only way to stop without packaging and sending the capture.
            # Moving it from a two-click menu to a direct button adds an explicit
            # confirmation so an accidental click cannot discard the upload.
            $script:BtRec_AbortClicked = $false
            $btAbortBtn = New-Object System.Windows.Forms.Button
            $btAbortBtn.Text = "Abort without uploading"
            $btAbortBtn.AutoSize = $true
            $btAbortBtn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btAbortBtn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $btAbortBtn.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
            $btAbortBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btAbortBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(130, 92, 72)
            $btAbortBtn.BackColor = [System.Drawing.Color]::FromArgb(38, 38, 46)
            $btAbortBtn.ForeColor = [System.Drawing.Color]::FromArgb(205, 172, 155)
            $btAbortBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
            $btAbortBtn.Add_Click({
                $answer = [System.Windows.Forms.MessageBox]::Show(
                    $this.FindForm(),
                    "Stop this recording without uploading?`n`nThe diagnostic package will not be created or sent to support.",
                    "Abort Bluetooth recording",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                )
                if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) {
                    $script:BtRec_AbortClicked = $true
                    $script:BtRec_StopClicked = $true
                }
            })
            $btButtonRow.Controls.Add($btAbortBtn)

            $btRecordStart = Get-Date
            $btPollJob     = $null
            # A bounded pre-roll is persisted on every run. Authentication and
            # BTHUSB failures often precede the operator clicking Record; starting
            # at the click made the most useful causal evidence disappear.
            $btPollSince   = $btRecordStart.AddMinutes(-10)
            $btNextPoll    = $btRecordStart.AddSeconds(6)
            $btSvcStates   = $null
            $btFirstPoll   = $true
            $btEventReport = $null
            $btDeviceProbeModPath = Join-Path $PSScriptRoot "Modules\BluetoothDeviceProbe.psm1"
            $btEventEvidence = if (Get-Command New-BluetoothEventEvidenceRecord -ErrorAction SilentlyContinue) {
                New-BluetoothEventEvidenceRecord -WindowStart $btPollSince
            } else { $null }

            # One collector and one consumer for live polls and the final drain.
            # The topology snapshot is conditional work in this background job,
            # never on the three-second tick/UI thread.
            $btPollJobScript = {
                param($probeModulePath, $deviceProbeModulePath, $since, [bool]$collectTopology)
                Import-Module $probeModulePath -Force -DisableNameChecking -ErrorAction SilentlyContinue
                Import-Module $deviceProbeModulePath -Force -DisableNameChecking -ErrorAction SilentlyContinue
                $eventError = $null
                $events = try { Get-BluetoothRecentEvents -Since $since -MaxEventsPerLog 100 } catch {
                    $eventError = $_.Exception.Message
                    $null
                }
                $services = try { Get-BluetoothServiceStates } catch { @{} }
                $topology = $null
                $topologyError = $null
                if ($collectTopology) {
                    $topology = try { Get-BluetoothSerialPortIntegrity } catch {
                        $topologyError = $_.Exception.Message
                        $null
                    }
                }
                [pscustomobject]@{
                    Events              = $events
                    EventCollectorError = $eventError
                    Services            = $services
                    TopologyRequested   = $collectTopology
                    Topology            = $topology
                    TopologyError       = $topologyError
                }
            }

            $mergeBtPollData = {
                param($pollData, [bool]$renderLive)
                if ($pollData -is [array]) { $pollData = @($pollData)[-1] }
                if ($null -eq $pollData) {
                    if ($btEventEvidence -and (Get-Command Add-BluetoothEventEvidenceBatch -ErrorAction SilentlyContinue)) {
                        Add-BluetoothEventEvidenceBatch -Record $btEventEvidence -Batch $null -CollectorError 'Background collector returned no result.' | Out-Null
                    }
                } else {
                    $mergeResult = $null
                    if ($btEventEvidence -and (Get-Command Add-BluetoothEventEvidenceBatch -ErrorAction SilentlyContinue)) {
                        $mergeResult = Add-BluetoothEventEvidenceBatch -Record $btEventEvidence -Batch $pollData.Events -CollectorError $pollData.EventCollectorError
                        if ($mergeResult.NextSince) { $btPollSince = $mergeResult.NextSince }
                    }

                    if ($pollData.Services) {
                        if (-not $btSvcStates) {
                            $btSvcStates = $pollData.Services
                        } else {
                            foreach ($k in @($pollData.Services.Keys)) {
                                $prev = $btSvcStates[$k]; $curr = $pollData.Services[$k]
                                if ($prev -and $curr -and $prev.Status -ne $curr.Status -and $renderLive) {
                                    $lvl = if ($curr.Running) { 'OK' } else { 'WARN' }
                                    Write-BtLog "  Service: $($curr.DisplayName)  $($prev.Status) -> $($curr.Status)" -Level $lvl
                                }
                            }
                            $btSvcStates = $pollData.Services
                        }
                    }

                    if ($renderLive -and $mergeResult) {
                        $newEvts = @($mergeResult.AcceptedEvents | Where-Object { $_ -and $_.TimeCreated -ge $btRecordStart })
                        $connEvts  = @($newEvts | Where-Object { $_.StableClass -eq 'Connected' })
                        $discEvts  = @($newEvts | Where-Object { $_.StableClass -eq 'Disconnected' })
                        $otherEvts = @($newEvts | Where-Object { $_.StableClass -eq 'Unknown' })
                        foreach ($ev in $connEvts) { Write-BtLog "  $($ev.TimeCreated.ToString('HH:mm:ss'))  Connected  ($($ev.ProviderName))" -Level 'OK' }
                        foreach ($ev in $discEvts) { Write-BtLog "  $($ev.TimeCreated.ToString('HH:mm:ss'))  Disconnected  ($($ev.ProviderName))" -Level 'WARN' }
                        if ($otherEvts.Count -gt 0) { Write-BtLog "  $($otherEvts.Count) Bluetooth event(s) captured" -Level 'DIM' }
                        if ($newEvts.Count -eq 0 -and $btFirstPoll) { Write-BtLog '  (no Bluetooth activity yet)' -Level 'DIM' }
                    }

                    if ($pollData.TopologyRequested -and $btProbeSession -and
                        (Get-Command Complete-SerialOpenTopologyRequest -ErrorAction SilentlyContinue)) {
                        Complete-SerialOpenTopologyRequest -Record $btProbeSession.SerialOpenAttempts -Snapshot $pollData.Topology -FailureReason $pollData.TopologyError | Out-Null
                    }
                    $btFirstPoll = $false
                }
            }

            # Deep probe session state (used across recording + summary)
            $btProbeSession  = $null
            $btProbeWatch    = $null
            $btProbeConfig   = $null
            $btProbeTargetMac = ''
            $btProbeAppName  = 'NO'

            if ($btDeepProbeAvailable) {
                # ── Initialize deep probe ────────────────────────────────────
                $btWin32Ok = Initialize-BtWin32Api
                $btProbeSession = New-DeviceProbeSession
                $btProbeSession.BtWin32Available = $btWin32Ok
                # Proof that the passive FI-012 gate ran before this recorder was
                # constructed. The full start/end tables below remain separate.
                $btProbeSession.SerialPortPreflight = $btSerialPreflight
                if ($btSerialPreflight.Status -eq 'Unverified') {
                    Write-BtLog "  [~] $($btSerialPreflight.Summary) Passive troubleshooting will continue, but this is not a serial-readiness all-clear." -Level "WARN"
                }
                $btProbeSession.NoExeVersion = try { Get-NoExeVersion } catch { $null }
                # The recording window opens HERE, on the same $btRecordStart the
                # operator markers and the on-screen "Recording mm:ss" label
                # already count from -- not at the first probe tick, which is at
                # least one interval later and on a starved run far more than
                # that (issue #78). This is the only place it is stamped; the
                # duration is derived from it by Get-ProbeRecordingWindow.
                $btProbeSession.RecordingStartedAt = $btRecordStart

                # ── The active port-open probe treatment, announced ───────────
                # New-DeviceProbeSession resolved and LOCKED it a few lines
                # above, which is before target selection and before the arrival
                # snapshot -- i.e. before the first instant any code here could
                # open a target port. Announced immediately for two reasons: the
                # operator has to verify it at BOTH ends of an experimental arm
                # (pre-registration section 3.4(2)), and a disabled probe removes
                # a whole evidence channel from everything printed below it.
                #
                # A malformed/unreadable value is announced as loudly as a
                # disabled probe. An absent value is the ordinary clinic default
                # and remains visible as DefaultedMissing without turning every
                # non-experimental recording into a warning. Either defaulted
                # status invalidates an experimental arm; the capture records the
                # distinction so the protocol can enforce it.
                if ($btProbeSession.ContainsKey('ActivePortOpenProbeEnabled')) {
                    $apopLevel = if (-not $btProbeSession.ActivePortOpenProbeEnabled) { 'WARN' }
                                 elseif ($btProbeSession.ActivePortOpenProbeReadStatus -ne 'Explicit' -and
                                         $btProbeSession.ActivePortOpenProbeReadStatus -ne 'DefaultedMissing') { 'WARN' }
                                 else { 'DIM' }
                    Write-BtLog "  Active port-open probe: $(if ($btProbeSession.ActivePortOpenProbeEnabled) { 'ENABLED' } else { 'DISABLED' })  (read: $($btProbeSession.ActivePortOpenProbeReadStatus))" -Level $apopLevel
                    if (-not $btProbeSession.ActivePortOpenProbeEnabled) {
                        Write-BtLog "      This recording will NOT open the headset's COM ports. Port-hold, streaming state and the port-release cycle are NOT OBSERVED -- not 'idle', not 'stopped'. Read-rate sampling continues unchanged." -Level "WARN"
                    }
                    if ($btProbeSession.ActivePortOpenProbeReadStatus -eq 'DefaultedError') {
                        Write-BtLog "      $($btProbeSession.ActivePortOpenProbeReason)" -Level "WARN"
                    }

                    # ── PROVENANCE, line 1 of events.jsonl ────────────────────
                    # Written to the timeline as well as the manifest, and
                    # FIRST. The manifest is produced at teardown, so a run whose
                    # window is closed without uploading has no manifest at all
                    # -- and that has already happened once, on 2026-08-10. The
                    # treatment an arm ran under is the one fact that cannot be
                    # reconstructed afterwards from anything else in the package,
                    # because the whole point of the toggle is that it removes
                    # the evidence that would betray it.
                    if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticJsonLine -ErrorAction SilentlyContinue)) {
                        $provWrote = Add-WinConfigDiagnosticJsonLine -RunFolder $btDiagRun.RunFolder -Name 'events.jsonl' -Data ([ordered]@{
                            AtUtc      = $btRecordStart.ToUniversalTime().ToString('o')
                            Kind       = 'PROVENANCE'
                            State      = 'ActivePortOpenProbe'
                            Level      = $(if ($btProbeSession.ActivePortOpenProbeEnabled) { 'INFO' } else { 'WARN' })
                            Reason     = [string]$btProbeSession.ActivePortOpenProbeReason
                            ActivePortOpenProbeEnabled    = [bool]$btProbeSession.ActivePortOpenProbeEnabled
                            ActivePortOpenProbeReadStatus = [string]$btProbeSession.ActivePortOpenProbeReadStatus
                            ActivePortOpenProbeSource     = [string]$btProbeSession.ActivePortOpenProbeSource
                            ActivePortOpenProbeRawValue   = $btProbeSession.ActivePortOpenProbeRawValue
                            PortObservationSources        = @($btProbeSession.PortObservationSources)
                            ActiveSensorState             = [string]$btProbeSession.ActiveSensorState
                            RunId      = $btRunId
                        })
                        if (-not $provWrote) { $script:BtRec_EventLinesDropped = [int]$script:BtRec_EventLinesDropped + 1 }
                        else { $script:BtRec_EventLinesWritten = [int]$script:BtRec_EventLinesWritten + 1 }
                    }
                }

                # FI-012 baseline. Read-only registry + QueryDosDevice; cheap
                # enough to run inline. Guarded because the probe module may be
                # an older copy without it (env-var override / sibling repo).
                if (Get-Command Get-BluetoothSerialPortIntegrity -ErrorAction SilentlyContinue) {
                    $btProbeSession.SerialPortIntegrity = try { Get-BluetoothSerialPortIntegrity } catch { $null }
                    if ($btProbeSession.SerialPortIntegrity -and -not $btProbeSession.SerialPortIntegrity.Healthy) {
                        Write-BtLog "  [!] $($btProbeSession.SerialPortIntegrity.Summary)" -Level "FAIL"
                        foreach ($f in $btProbeSession.SerialPortIntegrity.Findings) { Write-BtLog "      $f" -Level "DIM" }
                        if ($btProbeSession.SerialPortIntegrity.Recommendation) {
                            Write-BtLog "      $($btProbeSession.SerialPortIntegrity.Recommendation)" -Level "FAIL"
                        }
                    }
                }

                # ── Target selection ──────────────────────────────────────────
                # This used to be `... -match 'NeurOptimal' | Select-Object -First 1`.
                # With two Arcs paired, first-match won over an unordered
                # enumeration and nobody was told a choice had been made: capture
                # 8E39860E4AF2 watched Arc 000019 (switched off, in a drawer) for
                # the whole of a clean 37-minute session run on Arc 000013, then
                # reported two problems and a session that "did NOT end clean".
                #
                # Selection is now evidence-based and refuses to guess. The MAC it
                # produces is FROZEN for the recording and is the single identity
                # every consumer below is scoped to.
                $btTargetName    = 'NeurOptimal Headset'
                $btSessionTarget = $null
                # Read off the SESSION, which locked it at construction a few
                # lines above -- never re-read from the environment here. This is
                # the first point in a recording at which any code could open a
                # target port, and it must be governed by the same frozen answer
                # the arrival snapshot and every tick will use.
                $btSelectActiveProbe = if (Get-Command Test-ActivePortOpenProbeEnabled -ErrorAction SilentlyContinue) {
                    Test-ActivePortOpenProbeEnabled -Session $btProbeSession
                } else { $true }
                # Start every recording from a cold property cache. The module can
                # outlive a recording (a second capture in the same app session),
                # and target selection must never be decided from values cached
                # during an earlier run against different hardware.
                if (Get-Command Clear-BluetoothComPortPropertyCache -ErrorAction SilentlyContinue) {
                    try { Clear-BluetoothComPortPropertyCache } catch { }
                }
                try {
                    $initPnp = Get-BluetoothPnpSnapshot
                    # -NoCache: this snapshot picks the headset the whole capture is
                    # about. It is read once, it is not on the hot path, and it is
                    # the last place that should be answered from a cache.
                    $btComForSelect = try { Get-BluetoothComPortSnapshot -NoCache } catch { $null }
                    $btCandidates = @()
                    foreach ($cd in @($initPnp.Devices | Where-Object { $_.FriendlyName -match 'NeurOptimal' })) {
                        $cdMac = try { Get-MacFromPnpInstanceId -InstanceId $cd.InstanceId } catch { $null }
                        $cdHex = ([string]$cdMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                        $cdPorts = @()
                        if ($cdHex -and $btComForSelect) {
                            $cdPorts = @($btComForSelect.Ports | Where-Object {
                                $_.PortName -and $_.AssociatedBluetoothMac -and
                                (([string]$_.AssociatedBluetoothMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $cdHex)
                            } | ForEach-Object { $_.PortName } | Select-Object -Unique)
                        }
                        # A HELD port is the positive-activity signal. Reading it
                        # steals nothing: on a port NO.exe owns the open fails with
                        # a sharing violation and no handle is ever acquired. This
                        # is the same call the probe already makes every tick.
                        #
                        # TIMED, and folded into the same accumulator the probe
                        # loop feeds. The recording window opened at
                        # $btRecordStart above, so these opens are INSIDE it --
                        # and being the first of the session they are the cold,
                        # slowest ones. Leaving them out while the denominator
                        # counted their wall clock biased the observer-effect
                        # figure downward, in the direction that exonerates the
                        # recorder. Note this loop probes EVERY candidate Arc,
                        # not just the one finally selected; the report is
                        # per-port so those stay separable.
                        #
                        # GATED. This is one of three direct call sites and one of
                        # four invocation paths -- arrival and tick share
                        # Get-StreamingState, while the anomaly snapshot uses the
                        # Test-ComPortInUse wrapper. $null, not @(): an empty held set
                        # here is read by Select-BluetoothSessionTarget as
                        # positive evidence that this candidate is idle, so
                        # emptying it would not merely lose the tie-breaker, it
                        # would feed the selector a fabricated observation.
                        $cdHeld = $(if ($btSelectActiveProbe) { ,@() } else { $null })
                        if ($btSelectActiveProbe -and (Get-Command Get-ComPortOpenObservation -ErrorAction SilentlyContinue)) {
                            foreach ($cdP in $cdPorts) {
                                # ONE attempt, which times itself and returns the raw
                                # win32 code. Selection opens are the COLD ones and the
                                # first chance in a session to see 433, so they must
                                # carry the code too -- a tick-only raw channel would
                                # miss the most diagnostic opens of the run.
                                $cdObs = try { Get-ComPortOpenObservation -PortName $cdP -Phase 'Selection' } catch { $null }
                                $cdState = if ($cdObs) { $cdObs.CoarseState } else { $null }
                                if ($cdObs -and (Get-Command Add-PortOpenTimingSamples -ErrorAction SilentlyContinue)) {
                                    try {
                                        $null = Add-PortOpenTimingSamples -Timing $btProbeSession.PortOpenTiming -Phase 'Selection' -Durations @(
                                            @{ Port = $cdP; State = ([string]$cdState); DurationMs = $cdObs.ElapsedMs; Contract = $cdObs.Contract }
                                        )
                                    } catch { }
                                }
                                if ($cdObs -and $btProbeSession -and $btProbeSession.SerialOpenAttempts -and (Get-Command Add-SerialOpenAttempt -ErrorAction SilentlyContinue)) {
                                    try { $null = Add-SerialOpenAttempt -Record $btProbeSession.SerialOpenAttempts -Observation $cdObs } catch { }
                                }
                                if ($cdState -eq 'Held') { $cdHeld += $cdP }
                            }
                        }
                        $btCandidates += [pscustomobject]@{
                            Mac = $cdHex; Name = $cd.FriendlyName; Present = $cd.Present
                            ComPorts = $cdPorts; HeldPorts = $cdHeld; HasPairingRecord = $false
                        }
                    }

                    if (Get-Command Select-BluetoothSessionTarget -ErrorAction SilentlyContinue) {
                        $btSessionTarget = Select-BluetoothSessionTarget -Candidates $btCandidates `
                            -HeldPortEvidenceAvailable $btSelectActiveProbe
                    }

                    if ($btSessionTarget -and $btSessionTarget.RequiresOperatorChoice) {
                        # Refuse to guess. Recording against the wrong headset
                        # produces a confident capture about a device that was not
                        # in the session, which is worse than no capture at all.
                        Write-BtLog "" -Level "DIM"
                        Write-BtLog "  [!] $($btSessionTarget.Summary)" -Level "FAIL"
                        $btPick = $null
                        try {
                            $btPick = Show-BtTargetChooser -Candidates @($btSessionTarget.Candidates) -Owner $btForm
                        } catch { $btPick = $null }
                        if ($btPick) {
                            $btSessionTarget = Select-BluetoothSessionTarget -Candidates $btCandidates -ExplicitMac $btPick `
                                -HeldPortEvidenceAvailable $btSelectActiveProbe
                            Write-BtLog "  Target chosen: $($btSessionTarget.Summary)" -Level "OK"
                        } else {
                            Write-BtLog "  Recording cancelled: no headset was chosen, so this capture would have described the wrong device." -Level "FAIL"
                            $script:BtRec_AbortClicked = $true
                            $script:BtRec_StopClicked  = $true
                        }
                    }

                    if ($btSessionTarget -and $btSessionTarget.IsResolved) {
                        $btProbeTargetMac = $btSessionTarget.Mac
                        if ($btSessionTarget.Name) { $btTargetName = $btSessionTarget.Name }
                        Write-BtLog "  Target: $btTargetName  MAC: $btProbeTargetMac" -Level "OK"
                        Write-BtLog "    $($btSessionTarget.Summary)" -Level "DIM"
                    } elseif (-not $script:BtRec_AbortClicked) {
                        $btWhy = if ($btSessionTarget) { $btSessionTarget.Summary } else { 'No NeurOptimal device found in PnP' }
                        Write-BtLog "  $btWhy -- watching for any changes" -Level "DIM"
                    }
                    # Frozen from here on. Every consumer below is scoped to this
                    # one MAC so a capture can never describe two devices at once.
                    $btProbeSession.SessionTarget    = $btSessionTarget
                    $btProbeSession.TargetMacFrozen  = $btProbeTargetMac
                } catch {
                    $initPnp = [pscustomobject]@{ Devices = @(); Failures = @() }
                }

                # ── FI-014 baseline: BTHPORT pairing record vs PnP node ──────
                # Read-only (registry + PnP enumeration), so unlike the serial
                # OPEN probes this is safe on the automatic path during a live
                # client session.
                #
                # Scoped on purpose. An unscoped scan is Healthy by
                # construction -- a nodeless record is ordinary removal residue
                # -- so it would put an inventory in every ZIP and a verdict in
                # none. The MAC comes from the PnP node when there is one and
                # from the pairing record when there is not, which is the case
                # that matters: FI-014 IS "record present, node absent", so the
                # PnP lookup above returns nothing exactly when this check has
                # something to say.
                if (Get-Command Get-BluetoothOrphanPairingRecord -ErrorAction SilentlyContinue) {
                    try {
                        $btPairInv = Get-BluetoothOrphanPairingRecord
                        # The frozen MAC wins when there is one. Resolve-Bluetooth-
                        # TargetMac is the right tool ONLY once the session device
                        # is known: its fallback deliberately ranks the NODELESS
                        # record first, which is the FI-014 device of interest and
                        # precisely NOT the headset in a live clinical session.
                        # With a selection made, that ranking must not get a vote.
                        $btPairTarget = if ($btProbeSession.TargetMacFrozen) {
                            [pscustomobject]@{
                                Mac    = $btProbeSession.TargetMacFrozen
                                Source = 'SessionTarget'
                                Summary = "Scoped to the headset selected for this recording ($($btProbeSession.TargetMacFrozen))"
                            }
                        } else {
                            Resolve-BluetoothTargetMac -PnpMac $btProbeTargetMac -Records @($btPairInv.Records)
                        }
                        $btProbeSession.PairingTargetMac    = $btPairTarget.Mac
                        $btProbeSession.PairingTargetSource = $btPairTarget.Source
                        $btProbeSession.PairingTargetSummary = $btPairTarget.Summary

                        $btProbeSession.PairingRecord = if ($btPairTarget.Mac) {
                            Get-BluetoothOrphanPairingRecord -TargetMac $btPairTarget.Mac
                        } else { $btPairInv }

                        # A MAC recovered from a record when PnP had none is the
                        # headline, not a detail: it means the headset is known
                        # to this box and has no device node right now.
                        if ($btPairTarget.Source -eq 'PairingRecord') {
                            Write-BtLog "  [!] $($btPairTarget.Summary)" -Level "WARN"
                        }
                        if ($btProbeSession.PairingRecord -and -not $btProbeSession.PairingRecord.Healthy) {
                            Write-BtLog "  [!] $($btProbeSession.PairingRecord.Summary)" -Level "FAIL"
                            foreach ($f in @($btProbeSession.PairingRecord.Findings)) { Write-BtLog "      $f" -Level "DIM" }
                            if ($btProbeSession.PairingRecord.Recommendation) {
                                Write-BtLog "      $($btProbeSession.PairingRecord.Recommendation)" -Level "FAIL"
                            }
                        }
                    } catch { }
                }

                Write-BtLog "  Gathering system state (adapters, COM ports, power settings)..." -Level "DIM"
                [System.Windows.Forms.Application]::DoEvents()

                $btProbeConfig = New-TargetDeviceConfiguration -TargetName $btTargetName -TargetMac $btProbeTargetMac -AppProcessName $btProbeAppName
                $btProbeWatch  = New-TargetWatchState -Configuration $btProbeConfig

                # Initial state snapshot. -NoCache: this is the baseline the whole
                # recording is diffed against and it is persisted as evidence, so
                # it is read from the device, not from the cache. Only the repeating
                # tick reuses cached node properties.
                $initCom  = try { Get-BluetoothComPortSnapshot -NoCache } catch { [pscustomobject]@{ Ports = @() } }
                $initProc = try { Get-TargetDeviceProcessSnapshot } catch { @() }
                $null = Update-TargetWatchState -WatchState $btProbeWatch -PnpSnapshot $initPnp -ProcessNames $initProc -ComPortSnapshot $initCom

                # Seed timing
                $btProbeSession.StateEnteredAt['device']  = Get-Date
                $btProbeSession.StateEnteredAt['comport'] = Get-Date
                $btProbeSession.StateEnteredAt['process'] = Get-Date

                # Seed known COM ports
                if ($btProbeWatch.ComPortState -eq 'ComPortAmbiguous') {
                    $btProbeSession.LastComPortNames = @($btProbeWatch.AmbiguousComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ } | Sort-Object)
                } elseif ($btProbeWatch.ComPortState -eq 'ComPortFound') {
                    $btProbeSession.LastComPortNames = @($btProbeWatch.ComPortMatches | ForEach-Object { $_.PortName } | Where-Object { $_ } | Sort-Object)
                }

                # SPP server channel count
                $sppPorts = @($initCom.Ports | Where-Object { $_.InstanceId -match 'LOCALMFG' -and $_.InstanceId -match '000000000000' })
                $btProbeSession.StartupSppChannelCount = $sppPorts.Count

                # Read-rate monitoring. Optional: if the P/Invoke will not load or
                # NO.exe's handle cannot be queried, the session still records
                # everything else and the summary says data flow was not assessed
                # rather than implying it was assessed and found healthy.
                if (Get-Command Initialize-ProcessIoApi -ErrorAction SilentlyContinue) {
                    $btProbeSession.IoApiAvailable = try { Initialize-ProcessIoApi } catch { $false }
                    if (-not $btProbeSession.IoApiAvailable) {
                        Write-BtLog "  Read-rate monitoring unavailable -- data flow will not be assessed this session" -Level "WARN"
                    }
                }

                # Adapter info + power plan (captured once)
                try { $btProbeSession.AdapterInfo = Get-BluetoothAdapterInfo } catch { }
                try { $btProbeSession.PowerPlan   = Get-PowerPlanInfo } catch { }

                # BT link initial state
                $initLink = Get-BtConnectionState -Mac $btProbeTargetMac -BtWin32Available $btWin32Ok
                $btProbeSession.BtLinkState    = $initLink
                $btProbeSession.BtLinkEnteredAt = Get-Date
                # A link that is ALREADY up when recording starts is a real
                # observation and must be recorded as one. Only the probe ticks
                # set BtLinkEverConnected, and the first is 3s away, so a capture
                # stopped or aborted before then threw away a valid sighting --
                # and everything keyed on it (observation coverage, the serial
                # fault fingerprint, the never-linked findings) then read as
                # though the headset had never linked at all.
                if ($initLink -eq 'Connected') { $btProbeSession.BtLinkEverConnected = $true }

                # Port-hold initial state. NOT a data-flow reading -- see
                # Get-ComPortHoldState. The distinction matters here more than
                # anywhere else, because this snapshot is what the operator reads
                # before deciding whether anything is wrong.
                # -Session is what gates it: Get-StreamingState reads the locked
                # ActivePortOpenProbeEnabled and returns 'DisabledBySetting'
                # without touching a port. This is the SECOND of the three active
                # -open paths; passing the session here is not optional plumbing.
                $initStream = Get-StreamingState -WatchState $btProbeWatch -Session $btProbeSession -Phase 'Startup'
                # This call opens the same ports the tick loop does, and it too
                # sits inside the recording window ($btRecordStart, above). It
                # already emits PortOpenDurations -- the first cut of #83 threw
                # them away, so the arrival opens were spent but never counted.
                if (Get-Command Add-PortOpenTimingSamples -ErrorAction SilentlyContinue) {
                    try {
                        $null = Add-PortOpenTimingSamples -Timing $btProbeSession.PortOpenTiming `
                            -Durations $initStream.PortOpenDurations -Phase 'Startup'
                    } catch { }
                }
                # Raw codes for those same arrival opens. Startup is where a box
                # that ARRIVED broken shows 433 on the very first attempt, which
                # is what separates it from one that degraded mid-session.
                if ($btProbeSession.SerialOpenAttempts -and (Get-Command Add-SerialOpenAttempt -ErrorAction SilentlyContinue)) {
                    try {
                        foreach ($obs in @($initStream.PortOpenObservations)) {
                            $null = Add-SerialOpenAttempt -Record $btProbeSession.SerialOpenAttempts -Observation $obs
                        }
                    } catch { }
                }
                $btProbeSession.StreamingState = $initStream.State
                $btProbeSession.ActiveStreamPort = $initStream.ActivePort
                # Assigned ONLY when a sensor produced them. On the disabled path
                # these keys are absent from the result, and @($null) would turn
                # that absence into a one-element array containing $null -- an
                # observation of nothing, which then seeds every consumer below.
                # Leave the session's own $null seeding in place instead.
                if ($initStream.ContainsKey('HeldPorts')) {
                    $btProbeSession.HeldPorts = @($initStream.HeldPorts)
                }
                if ($initStream.ContainsKey('UnavailablePorts')) {
                    $arrivalDead = @($initStream.UnavailablePorts | Where-Object { $_ })
                    $btProbeSession.UnavailablePorts        = @($arrivalDead)
                    $btProbeSession.UnavailablePortsCurrent = @($arrivalDead)
                    $btProbeSession.UnavailablePortsEver    = @($arrivalDead)
                    # Arrival has no earlier tick.  Even if another port is held
                    # in the same snapshot, simultaneity cannot support the
                    # sentence "worked, then stopped opening" (#81).
                    $btProbeSession.UnavailableAfterHeldPortsCurrent = @()
                }
                # A port ALREADY held when recording starts is a real observation,
                # for the same reason as the link seeding above -- and here it is
                # also the state that seeds StreamingState to 'Active', which means
                # the tick loop will never see a transition. Issue #67: the old
                # ever-held flag latched only on that transition, so the commonest
                # healthy shape (recorder started during a live session) reported
                # "COM port never held" for the whole run, live in the window and
                # again in the bundle, and downgraded a clean capture to Partial.
                #
                # Only ever latches to $true, and only from an observation. On
                # the disabled path there is no HeldPorts key, the condition is
                # false, and PortEverHeld stays at the $null the session seeded
                # -- NOT $false. Writing $false here would be this recorder
                # asserting "no process ever held the port" on a run where it
                # never looked.
                if ($initStream.ContainsKey('HeldPorts') -and
                    @($initStream.HeldPorts | Where-Object { $_ }).Count -gt 0) {
                    $arrivalHeld = @($initStream.HeldPorts | Where-Object { $_ })
                    $btProbeSession.PortEverHeld = $true
                    $btProbeSession.HeldPortsEver = @($arrivalHeld)
                }
                if ($initStream.State -eq 'Active') { $btProbeSession.StateEnteredAt['streaming_Active_at'] = Get-Date }

                # Show the diagnostic chain and the initial state. Rendered from
                # the ARRIVAL snapshot, before the first tick: a box that is
                # already in a bad combination when Record is pressed produces no
                # transitions at all, so a chain that only appeared on tick one
                # would miss precisely the state the arrival cross-check exists
                # for.
                Update-BtChain
                # Pin the target/coverage strip before the first tick, so the
                # operator can check the headset identity BEFORE starting a
                # session rather than discovering it in the closing report.
                Update-BtLiveCoverage

                Write-BtLog "CURRENT STATE" -Level "STEP"
                Write-BtLog "  Device        : $(Get-ProbeStateUserText -Kind device -State $btProbeWatch.DeviceState)" -Level (Get-ProbeStateGuiLevel $btProbeWatch.DeviceState)
                Write-BtLog "  COM port      : $(Get-ProbeStateUserText -Kind comport -State $btProbeWatch.ComPortState)" -Level (Get-ProbeStateGuiLevel $btProbeWatch.ComPortState)
                Write-BtLog "  Radio link    : $(Get-ProbeStateUserText -Kind btlink -State $initLink)" -Level (Get-ProbeStateGuiLevel $initLink)
                if ($initStream.State -eq 'Active') {
                    $streamPort = if ($initStream.ActivePort) { " ($($initStream.ActivePort))" } else { '' }
                    Write-BtLog "  COM port open : Yes$streamPort -- a process is holding the port (this does NOT confirm data is flowing)" -Level "OK"
                } elseif ($initStream.State -eq 'DisabledBySetting') {
                    # WARN, not DIM. The dim line is where a reading that came
                    # back negative belongs; a channel that was switched off has
                    # to be visible enough that an operator notices it is missing
                    # from every conclusion the rest of the run reaches.
                    Write-BtLog "  COM port open : $(Get-ProbeStateUserText -Kind stream -State $initStream.State)" -Level "WARN"
                } else {
                    Write-BtLog "  COM port open : $(Get-ProbeStateUserText -Kind stream -State $initStream.State)" -Level "DIM"
                }
                $noRunning = Test-ProcessRunningInSnapshot -ProcessNames $initProc -Name $btProbeAppName
                Write-BtLog "  NO.exe        : $(if ($noRunning) { 'Running' } else { 'Not running' })" -Level $(if ($noRunning) { 'OK' } else { 'DIM' })

                # Arrival-state cross-check. Every other alarm in the probe fires on
                # a state CHANGE, so a box that is already broken when Record is
                # pressed produces no transitions and used to slide through the
                # snapshot with each line individually unremarkable (field case
                # 2026-07-30: port held, radio link down, nothing flagged, NO.exe
                # showing 'Arc Not Detected' on the next monitor).
                if (Get-Command Get-ProbeStateConsistency -ErrorAction SilentlyContinue) {
                    try {
                        $btArrival = @(Get-ProbeStateConsistency `
                            -DeviceState  $btProbeWatch.DeviceState `
                            -ComPortState $btProbeWatch.ComPortState `
                            -BtLinkState  $initLink `
                            -StreamState  $initStream.State `
                            -HeldPorts    @($initStream.HeldPorts | Where-Object { $_ }) `
                            -UnavailablePorts @($initStream.UnavailablePorts | Where-Object { $_ }) `
                            -PortHoldObserved ([bool]$btProbeSession.ActivePortOpenProbeEnabled) `
                            -AppRunning   $noRunning `
                            -SerialIntegrityFault ([bool]($btProbeSession.SerialPortIntegrity -and -not $btProbeSession.SerialPortIntegrity.Healthy)))
                        $btProbeSession.StartupConsistency = $btArrival
                        if ($btArrival.Count -gt 0) {
                            Write-BtLog "" -Level "DIM"
                            Write-BtLog "  State on arrival needs attention:" -Level "WARN"
                            foreach ($c in $btArrival) {
                                Write-BtLog "  $($c.Text)" -Level $c.Level
                            }
                        }
                    } catch {
                        # DIM made a check that did not run look like a check that
                        # found nothing -- the exact silence #68 item 4 is about.
                        # WARN also enrols it in the startup findings, so the
                        # operator can still see it 30 minutes later.
                        Write-BtLog "  [~] Arrival cross-check DID NOT RUN ($_) -- the state on arrival was not assessed. Absence of arrival findings below means nothing." -Level "WARN"
                    }
                }
                if ($btProbeSession.NoExeVersion) {
                    if (Test-NoUsesMacResolve -Version $btProbeSession.NoExeVersion) {
                        Write-BtLog "  NO.exe version: $($btProbeSession.NoExeVersion) -- resolves COM port from MAC each connect (port-number changes are benign)" -Level "DIM"
                    } else {
                        Write-BtLog "  NO.exe version: $($btProbeSession.NoExeVersion) -- caches COM port (a port-number change can break reconnect)" -Level "DIM"
                    }
                }
                if ($btProbeSession.AdapterInfo -and $btProbeSession.AdapterInfo.Present) {
                    # "driver vunknown" reads as a version string that was read
                    # and came back odd. The driver version is the field this
                    # investigation rolls back and compares across hosts, so an
                    # unread one has to say it was not read (#68 item 4).
                    $driverVer = if ($btProbeSession.AdapterInfo.DriverInfo -and $btProbeSession.AdapterInfo.DriverInfo.Version) {
                        "driver v$($btProbeSession.AdapterInfo.DriverInfo.Version)"
                    } else {
                        'driver version NOT READ from Windows'
                    }
                    Write-BtLog "  BT adapter    : $($btProbeSession.AdapterInfo.FriendlyName)  $driverVer" -Level "DIM"
                    $pm = $btProbeSession.AdapterInfo.PowerManagementEnabled
                    if ($pm -eq $true) {
                        Write-BtLog "  USB suspend   : ENABLED (risk factor -- can cause random disconnects)" -Level "WARN"
                        Write-BtLog "                  To disable: Device Manager > Bluetooth adapter > Properties > Power Management" -Level "WARN"
                        Write-BtLog "                  Uncheck 'Allow the computer to turn off this device to save power'" -Level "WARN"
                    }
                }
                if ($btProbeSession.PowerPlan -and $btProbeSession.PowerPlan.IsPowerSaver) {
                    Write-BtLog "  Power plan    : $($btProbeSession.PowerPlan.ActivePlan) -- throttles USB/Bluetooth performance" -Level "WARN"
                }
                # Reference prose does not belong in the live timeline: it pushes
                # the transitions the operator needs below the fold. Panel clicks
                # and Technical details carry the evidence on demand.
                Write-BtLog "" -Level "DIM"
                if ($noRunning) {
                    Write-BtLog "  NeurOptimal is already running. Run tests or reproduce the issue you have been seeing." -Level "INFO"
                } else {
                    Write-BtLog "  Launch NeurOptimal, start a session and reproduce the Bluetooth issue" -Level "INFO"
                }
                Write-BtLog "  Click  Stop and Upload  when done (~10 sec to finish)" -Level "INFO"
                Write-BtLog "  IF NEUROPTIMAL SHOWS AN ERROR: type its NO Code in the box at the bottom" -Level "ACTION"
                Write-BtLog "  and click  Mark what NO is showing.  This stamps the exact machine state" -Level "ACTION"
                Write-BtLog "  behind that message -- the same code can mean different things, and this" -Level "ACTION"
                Write-BtLog "  is the only way the recording can tell them apart." -Level "ACTION"
                Write-BtLog "  You can run the Bluetooth repair tools from the main window while recording" -Level "DIM"
                Write-BtLog "  (except Full Bluetooth Stack Reset) -- they will be marked in this log" -Level "DIM"
                Write-BtLog "" -Level "DIM"
                Write-BtLog "  Watching for Bluetooth changes (every 3s) -- events appear below as they happen" -Level "DIM"
            } else {
                # In this mode neither Update-BtLiveCoverage nor Update-BtChain
                # ever runs, so the six panels stay blank for the whole run and
                # this line is the ONLY thing on screen that can say why. It
                # therefore has to carry the scope fact as well as the coverage
                # one: without it, a recording that is not scoped to any headset
                # would look like a recording whose panels are merely still
                # filling in. #68 item 1: never assert a state the run
                # contradicts, and never leave one unstated either.
                $btCoverageLabel.Text = "Limited monitoring -- NO HEADSET IS BEING TRACKED, so this recording is not scoped to a device, and coverage is NOT being measured. Only Bluetooth connect/disconnect events are captured."
                $btCoverageLabel.ForeColor = [System.Drawing.Color]::FromArgb(240, 210, 110)

                Write-BtLog "  Limited monitoring mode -- device tracking not available" -Level "WARN"
                if ($btProbeLoadError) {
                    Write-BtLog "  Reason: $btProbeLoadError" -Level "DIM"
                }
                Write-BtLog "  Only Bluetooth connect/disconnect events will be captured" -Level "DIM"
                $noRunningBasic = try { !!(Get-Process -Name $btProbeAppName -ErrorAction SilentlyContinue) } catch { $false }
                if ($noRunningBasic) {
                    Write-BtLog "  NeurOptimal is already running. Run tests or reproduce the issue you have been seeing." -Level "INFO"
                } else {
                    Write-BtLog "  Launch NeurOptimal, start a session and reproduce the Bluetooth issue" -Level "INFO"
                }
                Write-BtLog "  Click  Stop and Upload  when done (~10 sec to finish)" -Level "INFO"
                Write-BtLog "  IF NEUROPTIMAL SHOWS AN ERROR: type its NO Code in the box at the bottom" -Level "ACTION"
                Write-BtLog "  and click  Mark what NO is showing.  This stamps the exact machine state" -Level "ACTION"
                Write-BtLog "  behind that message -- the same code can mean different things, and this" -Level "ACTION"
                Write-BtLog "  is the only way the recording can tell them apart." -Level "ACTION"
                Write-BtLog "" -Level "DIM"
                Write-BtLog "  Monitoring Bluetooth activity -- connect/disconnect events will appear here" -Level "DIM"
            }

            $btNextProbeTick = $btRecordStart.AddSeconds(3)
            $btHeartbeatTick = 0
            $btAnomalyBarTime = $null
            $btOpActionsLogged = 0
            $btLastElapsedSec = -1
            # Per-collector tick cost, recorded as evidence. Before this, nothing
            # in a capture said how long a tick took, so "watching every 3s" was
            # an assertion no artifact could contradict -- and on the dev box the
            # real figure was ~5.5s, i.e. the recorder was blocking its own UI
            # thread continuously and the stated cadence was fiction.
            $btTickIntervalSec = 3
            $btLastTickStart = $null
            $btTickStats = [ordered]@{
                TickCount = 0; SlowTickCount = 0; SlowTickThresholdMs = 2000
                TotalMs = [double]0; MaxMs = [double]0
                # Scheduling health, kept separate from execution cost: a tick can
                # be fast and still be running at the wrong rate.
                IntervalCount = 0; IntervalTotalMs = [double]0; IntervalMaxMs = [double]0
                MissedDeadlines = 0; MinPumpRecoveryMs = 250
                PumpFloorDeviations = 0
                TargetIntervalMs = 3000
                # The cold-cache tick, isolated. This is the measurement that
                # decides whether seeding the property cache from the pre-recording
                # -NoCache snapshot is worth doing -- deferred until field timing
                # says so, which needs this number to exist in field bundles.
                FirstTickMs = [double]0
                CollectorMaxMs = [ordered]@{ Inventory = [double]0; Pnp = [double]0; ComPort = [double]0; Process = [double]0; Update = [double]0; Render = [double]0 }
                CollectorTotalMs = [ordered]@{ Inventory = [double]0; Pnp = [double]0; ComPort = [double]0; Process = [double]0; Update = [double]0; Render = [double]0 }
            }
            $btSlowTickWarned = $false
            $btCadenceWarned = $false
            $btSlowTicksAfterFirst = 0
            $btInvFailWarned = $false
            $btTickSw = [System.Diagnostics.Stopwatch]::new()
            $btPartSw = [System.Diagnostics.Stopwatch]::new()

            # Everything above this line was raised before any recording happened,
            # so it is what the "Startup findings" button reopens. From here on,
            # findings belong to the session timeline and are events, not arrival
            # state -- mixing them would turn the button into a second copy of the
            # log and destroy the reason it exists.
            $script:BtRec_StartupPhase = $false

            while (-not $script:BtRec_StopClicked) {
                [System.Windows.Forms.Application]::DoEvents()
                $now = Get-Date
                $elapsed = $now - $btRecordStart

                # Repair tools clicked in the main window execute nested inside the
                # DoEvents call above; when the loop resumes, surface them here so
                # the recording attributes the resulting Bluetooth changes to the
                # operator instead of presenting them as spontaneous events.
                while ($btOpActionsLogged -lt $script:BtRecOperatorActions.Count) {
                    $opa = $script:BtRecOperatorActions[$btOpActionsLogged]
                    $btOpActionsLogged++
                    $opaDur = if ($opa.CompletedAt) { " (took $([int]($opa.CompletedAt - $opa.StartedAt).TotalSeconds)s)" } else { '' }
                    Write-BtLog "[~] Operator ran '$($opa.Tool)'$opaDur -- Bluetooth changes right after this are likely caused by it, not by NeurOptimal" -Level "WARN"
                    # A repair tool the operator ran is a state transition with a
                    # known cause, which is exactly what this list is for -- the
                    # events just after it are attributable to the tool.
                    script:Add-BtRecorderEvent -Text "Operator ran '$($opa.Tool)'" -Level 'WARN'
                }

                # Update elapsed label with current state summary.
                #
                # Recomputed at 1 Hz, not on every 200 ms pass, and assigned only
                # when the string actually differs. The label is AutoSize inside
                # an AutoSize docked FlowLayoutPanel, so each assignment re-runs
                # the panel's layout and can reflow the form -- five times a
                # second for a display whose finest unit is one second.
                $elSecNow = [int]$elapsed.TotalSeconds
                if ($elSecNow -ne $btLastElapsedSec) {
                    $btLastElapsedSec = $elSecNow
                    # Scrolling up stops the log following new lines (see the
                    # sticky-bottom writer in Console.psm1). Say so, otherwise a
                    # log that has quietly stopped moving reads as a hang.
                    # Only worth saying while the raw log is on screen. With the
                    # technical details collapsed there is no log to have scrolled
                    # away from, and the hint would be a claim about a control the
                    # operator cannot see.
                    $btScrollHint = ''
                    try {
                        if ($btTechPanel.Visible -and -not (Test-WinConfigGuiBoxAtBottom -Box $btOutputBox)) {
                            $btScrollHint = '  |  scrolled up -- new events below'
                        }
                    } catch { }
                    # The clock alone in the header. The device/stream shorthand
                    # that used to ride along here is now the diagram, and
                    # repeating it in words beside it was the duplicate-state
                    # problem this redesign is about.
                    #
                    # NAMED, because this label is also where "Packaging" and
                    # "Complete" appear when the run ends. A bare "02:14" that
                    # turns into a word is a control whose meaning the reader has
                    # to infer; "Recording 02:14" makes the phase explicit and
                    # the transition legible.
                    $newTimerText = "Recording {0:mm\:ss}" -f $elapsed
                    if ($btTimerLabel.Text -ne $newTimerText) { $btTimerLabel.Text = $newTimerText }
                    # The bottom line carries ONLY what the header does not. With
                    # the clock and the primary action moved up there, repeating
                    # "Recording 12:47 -- click Stop and Upload when done" is the
                    # duplicated state this redesign removes. The later phases
                    # still write "Packaging..." and "Aborted." here.
                    $newElapsedText = $btScrollHint.TrimStart(' ', '|')
                    if ($btElapsedLabel.Text -ne $newElapsedText) { $btElapsedLabel.Text = $newElapsedText }
                }

                # ── Operator marker ──────────────────────────────────────────
                # Handled on every loop pass, not on the 3s probe tick, so the
                # marker lands on the moment the operator saw the dialog rather
                # than up to three seconds later.
                if ($script:BtRec_MarkRequested) {
                    $script:BtRec_MarkRequested = $false
                    try {
                        $mkLabel = if ($btMarkBox.Tag -eq 'placeholder') { '' } else { $btMarkBox.Text }
                        if ($btDeepProbeAvailable -and $btProbeWatch -and (Get-Command New-ProbeStateMarker -ErrorAction SilentlyContinue)) {
                            $mk = New-ProbeStateMarker -Label $mkLabel -At $now `
                                -ElapsedSeconds ([int]$elapsed.TotalSeconds) `
                                -DeviceState  $btProbeWatch.DeviceState `
                                -ComPortState $btProbeWatch.ComPortState `
                                -BtLinkState  $btProbeSession.BtLinkState `
                                -StreamState  $btProbeSession.StreamingState `
                                -HeldPorts    @($btProbeSession.HeldPorts | Where-Object { $_ }) `
                                -UnavailablePorts @($btProbeSession.UnavailablePortsCurrent | Where-Object { $_ }) `
                                -UnavailableAfterHeldPorts @($btProbeSession.UnavailableAfterHeldPortsCurrent | Where-Object { $_ }) `
                                -PortHoldObserved ([bool]$btProbeSession.ActivePortOpenProbeEnabled) `
                                -AppRunning   ($btProbeWatch.AppProcessState -eq 'Running') `
                                -NoExeVersion $btProbeSession.NoExeVersion `
                                -IoVerdict    $btProbeSession.IoVerdict `
                                -IoBaselineOpsPerSecond ([double]$btProbeSession.IoBaselineOpsPerSecond) `
                                -IoRecentOpsPerSecond   ([double]$btProbeSession.IoRecentOpsPerSecond) `
                                -EpisodeId    ([string]$btProbeSession.IoEpisodeId) `
                                -SerialIntegrityFault ([bool]($btProbeSession.SerialPortIntegrity -and -not $btProbeSession.SerialPortIntegrity.Healthy)) `
                                -TargetEverActive     ([bool]$btProbeSession.PortEverHeld)
                            [void]$btProbeSession.OperatorMarkers.Add($mk)
                            Write-BtLog "  $($now.ToString('HH:mm:ss'))  [MARK    ]  $(Format-ProbeStateMarker -Marker $mk)" -Level "ACTION"
                            # The operator marker is the only labelling channel
                            # this investigation has, so its acknowledgement has
                            # to be visible on the default screen rather than in
                            # a log the operator has to open.
                            script:Add-BtRecorderEvent -Text $(if ($mkLabel) { "Marked: $mkLabel" } else { 'Operator marked this moment' }) -Level 'ACTION' -At $now
                            foreach ($cx in @($mk.Contradictions)) {
                                Write-BtLog "             $cx" -Level "WARN"
                            }
                            # Only claimable when every channel was actually
                            # read. With the active port-open probe disabled the
                            # held-port checks cannot fire, so "looks consistent"
                            # would be an all-clear derived from an unread
                            # channel -- and this line is the one an operator
                            # takes away from the moment a dialog appeared.
                            # Get-ProbeStateConsistency now emits an explicit
                            # not-observed row in that case, so Contradictions is
                            # non-empty and this branch is skipped; the guard is
                            # belt-and-braces against that row being dropped.
                            if (@($mk.Contradictions).Count -eq 0 -and $btProbeSession.ActivePortOpenProbeEnabled) {
                                Write-BtLog "             [~] Bluetooth layer looks consistent at this moment -- whatever NeurOptimal is showing comes from above it. Marked for follow-up." -Level "WARN"
                            }
                        } else {
                            Write-BtLog "  $($now.ToString('HH:mm:ss'))  [MARK    ]  Operator marked '$mkLabel' (limited monitoring -- no machine state captured with it)" -Level "ACTION"
                            script:Add-BtRecorderEvent -Text "Marked: $mkLabel (no machine state)" -Level 'ACTION' -At $now
                        }
                        $btMarkBox.Text = 'NO code'
                        $btMarkBox.Tag  = 'placeholder'
                        $btMarkBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
                    } catch {
                        Write-BtLog "  Could not record the marker: $_" -Level "WARN"
                    }
                }

                # ── Deep probe tick (every 3s, main thread) ──────────────────
                if ($btDeepProbeAvailable -and $btProbeWatch -and $now -ge $btNextProbeTick) {
                    # Start-to-start interval is what the "checked every 3s" claim
                    # actually means. Execution duration alone cannot contradict
                    # that claim -- it was the missing measurement that let a ~5 s
                    # cadence be reported as 3 s.
                    $btTickStart = Get-Date
                    if ($btLastTickStart) {
                        $btIntervalMs = ($btTickStart - $btLastTickStart).TotalMilliseconds
                        $btTickStats.IntervalCount++
                        $btTickStats.IntervalTotalMs += $btIntervalMs
                        if ($btIntervalMs -gt $btTickStats.IntervalMaxMs) { $btTickStats.IntervalMaxMs = $btIntervalMs }
                    }
                    $btLastTickStart = $btTickStart
                    $btTickSw.Restart()
                    try {
                        # One enumeration for both snapshots. Measured on the dev
                        # box: four scoped queries ~1,230 ms, one inventory plus
                        # projection ~400 ms, with the projections byte-identical
                        # to the queries they replace. It also removes a real
                        # inconsistency -- the two snapshots used to describe
                        # enumeration instants about half a second apart, so a
                        # device arriving or leaving between them produced a
                        # capture whose halves disagreed about the machine.
                        #
                        # TICK ONLY. Baseline and final still run their own
                        # queries; the evidence paths do not move until this has
                        # field parity. On inventory failure $btInv is unusable,
                        # both collectors fall back to their own queries, and the
                        # two channels fail independently as before.
                        $btPartSw.Restart()
                        $btInv = try { Get-BluetoothPnpInventory } catch { $null }
                        if ($btInv -and -not $btInv.Ok -and -not $btInvFailWarned) {
                            $btInvFailWarned = $true
                            Write-BtLog "  [~] Shared device enumeration unavailable ($($btInv.Failure)) -- each check is querying separately, which is slower but complete." -Level "DIM"
                        }
                        $btTickStats.CollectorTotalMs['Inventory'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['Inventory']) { $btTickStats.CollectorMaxMs['Inventory'] = $btPartSw.Elapsed.TotalMilliseconds }

                        $btPartSw.Restart()
                        $pnpNow  = Get-BluetoothPnpSnapshot -Inventory $btInv
                        $btTickStats.CollectorTotalMs['Pnp'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['Pnp']) { $btTickStats.CollectorMaxMs['Pnp'] = $btPartSw.Elapsed.TotalMilliseconds }

                        $btPartSw.Restart()
                        $comNow  = try { Get-BluetoothComPortSnapshot -Inventory $btInv } catch { [pscustomobject]@{ Ports = @() } }
                        $btTickStats.CollectorTotalMs['ComPort'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['ComPort']) { $btTickStats.CollectorMaxMs['ComPort'] = $btPartSw.Elapsed.TotalMilliseconds }

                        $btPartSw.Restart()
                        $procNow = try { Get-TargetDeviceProcessSnapshot } catch { @() }
                        $btTickStats.CollectorTotalMs['Process'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['Process']) { $btTickStats.CollectorMaxMs['Process'] = $btPartSw.Elapsed.TotalMilliseconds }

                        # ── Self-heal target acquisition ─────────────────────
                        # If we never locked onto the headset's MAC (operator
                        # started the recorder before Windows finished bringing
                        # the paired device up, so the seed detect fell back to
                        # the base name with no MAC), keep re-detecting. Without
                        # the MAC the COM ports -- whose friendly name is the
                        # generic "Standard Serial over Bluetooth link" -- can't
                        # be tied to this headset, so it would read COM: none
                        # for the whole session even after it reconnects.
                        #
                        # Only ever runs when NO MAC was frozen at startup, so it
                        # cannot retarget a recording mid-flight. And it will not
                        # guess between several headsets for the same reason the
                        # startup selector will not: `-First 1` over an unordered
                        # PnP enumeration is what produced capture 8E39860E4AF2.
                        if (-not $btProbeTargetMac -and $pnpNow -and $pnpNow.Devices) {
                            $lateAll = @($pnpNow.Devices | Where-Object { $_.FriendlyName -match 'NeurOptimal' })
                            if ($lateAll.Count -gt 1) {
                                if (-not $script:BtRec_LateAmbiguityReported) {
                                    $script:BtRec_LateAmbiguityReported = $true
                                    Write-BtLog "  [!] $($lateAll.Count) NeurOptimal headsets appeared and none was selected at startup -- not guessing which one this session is about. This recording will not be scoped to a headset. Stop, power on only the headset you are using, and record again." -Level "FAIL"
                                }
                            } elseif ($lateAll.Count -eq 1) {
                                $lateDev = $lateAll[0]
                                $lateMac = Get-MacFromPnpInstanceId -InstanceId $lateDev.InstanceId
                                $btProbeConfig = New-TargetDeviceConfiguration -TargetName $lateDev.FriendlyName -TargetMac $lateMac -AppProcessName $btProbeAppName
                                $btProbeWatch.Configuration = $btProbeConfig
                                if ($lateMac) {
                                    $btProbeTargetMac = $lateMac
                                    # Freeze it now, so every consumer downstream
                                    # scopes to the same device the watch does.
                                    $btProbeSession.TargetMacFrozen = $lateMac
                                    Write-BtLog "  Target acquired: $($lateDev.FriendlyName)  MAC: $lateMac" -Level "OK"
                                    script:Add-BtRecorderEvent -Text "Target acquired: $($lateDev.FriendlyName)" -Level 'OK'
                                }
                            }
                        }

                        $btPartSw.Restart()
                        $newObs = Update-TargetWatchState -WatchState $btProbeWatch -PnpSnapshot $pnpNow -ProcessNames $procNow -ComPortSnapshot $comNow

                        $probeEvents = Invoke-DeviceProbeTick -Session $btProbeSession -WatchState $btProbeWatch `
                            -NewObservations $newObs -TargetMac $btProbeTargetMac -AppProcessName $btProbeAppName
                        $btTickStats.CollectorTotalMs['Update'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['Update']) { $btTickStats.CollectorMaxMs['Update'] = $btPartSw.Elapsed.TotalMilliseconds }

                        $btPartSw.Restart()
                        foreach ($evt in $probeEvents) {
                            # PERSIST FIRST, render second (#87). Until now these
                            # events went to the GUI log and NOWHERE else: the
                            # package has eight files and none of them held the
                            # session's timeline, so the port release/reacquire
                            # cycle -- the crispest signal this failure mode
                            # emits, and the candidate primary outcome for the
                            # A/B/A control -- could not be scored from a capture
                            # at all. WatchReport.Observations is not a
                            # substitute: on DB98B6EE3324 it held 3 entries, all
                            # stamped at the arrival snapshot, across a 324 s run
                            # with two port-release cycles.
                            #
                            # Written on the SAME loop that renders, so the file
                            # and the operator's window cannot describe different
                            # runs, and appended per event so a window closed
                            # without upload still leaves evidence on disk.
                            if ($btDiagRun) {
                                $wrote = Add-WinConfigDiagnosticJsonLine -RunFolder $btDiagRun.RunFolder -Name 'events.jsonl' -Data ([ordered]@{
                                    AtUtc      = $evt.Timestamp.ToUniversalTime().ToString('o')
                                    Kind       = $evt.Kind
                                    State      = $evt.State
                                    Level      = $evt.Level
                                    Reason     = $evt.Reason
                                    Annotation = $evt.Annotation
                                    # The state the event happened IN, not just
                                    # the event: a STREAM transition is only
                                    # scoreable beside the set it moved from.
                                    # $null when the active probe is disabled:
                                    # a file of "HeldPorts": [] lines reads as
                                    # continuous port-free operation.
                                    HeldPorts  = $(if ($btProbeSession.ActivePortOpenProbeEnabled) {
                                        ,@($btProbeSession.HeldPorts | Where-Object { $_ })
                                    } else { $null })
                                    EpisodeId  = $btProbeSession.IoEpisodeId
                                    IoVerdict  = $btProbeSession.IoVerdict
                                    TickIndex  = [int]$btProbeSession.TickCount
                                })
                                # Counted, never silent. A timeline with holes
                                # that reads as complete is the same class of lie
                                # as an unmeasured zero rendered as 0.
                                if (-not $wrote) { $script:BtRec_EventLinesDropped = [int]$script:BtRec_EventLinesDropped + 1 }
                                else { $script:BtRec_EventLinesWritten = [int]$script:BtRec_EventLinesWritten + 1 }
                            }
                            $ts = $evt.Timestamp.ToString('HH:mm:ss')
                            $kindTag = switch ($evt.Kind) {
                                'device'  { 'DEVICE' }
                                'comport' { 'COM' }
                                'STREAM'  { 'STREAM' }
                                'BTLINK'  { 'RADIO' }
                                'ANOMALY' { 'ALERT' }
                                'process' { 'PROCESS' }
                                default   { $evt.Kind.ToUpper() }
                            }
                            $kindTag = $kindTag.PadRight(8)
                            $evtKind = switch ($evt.Kind) { 'device' { 'device' } 'comport' { 'comport' } 'BTLINK' { 'btlink' } 'STREAM' { 'stream' } default { '' } }
                            $evtStateText = if ($evtKind) { Get-ProbeStateUserText -Kind $evtKind -State $evt.State -Short } else { $evt.State }
                            Write-BtLog "  $ts  [$kindTag]  $evtStateText  --  $($evt.Reason)" -Level $evt.Level

                            # ── Session events, the operator's short list ────
                            # A RENDER-TIME filter over the SAME events that were
                            # just persisted and logged in full. Anything dropped
                            # here is still in events.jsonl and still in the raw
                            # log above; what is removed is only the promotion to
                            # the summary list. Filtering in the collector would
                            # remove evidence from the capture, which is the one
                            # thing this redesign must not do.
                            if (Get-Command Get-BtRecorderEventText -ErrorAction SilentlyContinue) {
                                $viewEvt = try { Get-BtRecorderEventText -Kind $evt.Kind -State $evt.State -Level $evt.Level } catch { $null }
                                if ($viewEvt) { script:Add-BtRecorderEvent -Text $viewEvt.Text -Level $viewEvt.Level -At $evt.Timestamp }
                            }
                            if ($evt.Annotation) {
                                $annoLevel = if ($evt.Annotation.StartsWith('[!]')) { 'FAIL' } elseif ($evt.Annotation.StartsWith('[~]')) { 'WARN' } else { 'OK' }
                                Write-BtLog "             $($evt.Annotation)" -Level $annoLevel
                            }
                        }

                        # Diagnostic chain: compute, persist on change, render.
                        # This replaced five independent indicators that showed a
                        # single root cause as four separate problems.
                        Update-BtChain

                        # Always-visible answer to "which headset is this watching,
                        # and is it actually seeing my session?" -- the two questions
                        # capture 8E39860E4AF2 could not answer while it was running.
                        # Both were derivable at the time; neither reached the
                        # operator until the closing report, 37 minutes too late.
                        Update-BtLiveCoverage

                        $btTickStats.CollectorTotalMs['Render'] += $btPartSw.Elapsed.TotalMilliseconds
                        if ($btPartSw.Elapsed.TotalMilliseconds -gt $btTickStats.CollectorMaxMs['Render']) { $btTickStats.CollectorMaxMs['Render'] = $btPartSw.Elapsed.TotalMilliseconds }
                    } catch {
                        Write-BtLog "  [probe tick error]: $_" -Level "DIM"
                    }

                    $btTickSw.Stop()
                    $btTickMs = $btTickSw.Elapsed.TotalMilliseconds
                    $btTickStats.TickCount++
                    $btTickStats.TotalMs += $btTickMs
                    if ($btTickMs -gt $btTickStats.MaxMs) { $btTickStats.MaxMs = $btTickMs }
                    # The first tick pays for a cold property cache -- by design,
                    # and once. Kept in MaxMs and reported on its own, because it
                    # is the number that decides whether seeding the cache from
                    # the pre-recording snapshot is worth doing; excluded only
                    # from the judgement about whether this PC is PERSISTENTLY
                    # slow, which is a different question about a later state.
                    if ($btTickStats.TickCount -eq 1) { $btTickStats.FirstTickMs = $btTickMs }

                    # ── Execution cost, NOT cadence ──────────────────────────
                    # A slow tick means the window is unresponsive WHILE a check
                    # runs. It does not by itself mean checks are further apart:
                    # a 2.5 s tick still finishes 500 ms inside a 3 s deadline,
                    # clear of the pump floor, so the cadence is untouched. Those
                    # were one warning making a claim only one of them supported;
                    # the cadence half is now emitted from the scheduler, which is
                    # the only place that actually measures it.
                    if ($btTickMs -gt $btTickStats.SlowTickThresholdMs) {
                        $btTickStats.SlowTickCount++
                        if ($btTickStats.TickCount -gt 1) {
                            $btSlowTicksAfterFirst++
                            # Two, so a single blip is not reported as a property
                            # of the machine.
                            if (-not $btSlowTickWarned -and $btSlowTicksAfterFirst -ge 2) {
                                $btSlowTickWarned = $true
                                Write-BtLog "  [~] Checks on this PC are taking about $([int]$btTickMs) ms each -- the window may feel sluggish while one runs. Checks are still happening on schedule and the recording is unaffected." -Level "WARN"
                            }
                        }
                    }

                    # Anomaly confirmation bar handling
                    if ($btProbeSession.PendingConfirmation -and -not $btAnomalyBar.Visible) {
                        $btAnomalyBar.Visible = $true
                        $btAnomalyBarTime = Get-Date
                        $script:BtAnomaly_Resolved = $false
                    }
                    if ($btAnomalyBar.Visible) {
                        if ($script:BtAnomaly_Resolved) {
                            if ($script:BtAnomaly_IsExpected) {
                                Write-BtLog "  Confirmed: stream stop was expected (user-initiated)" -Level "OK"
                            } else {
                                Write-BtLog "  Confirmed: stream stop was unexpected -- capturing diagnostic snapshot..." -Level "WARN"
                                try {
                                    $diagSnap = Invoke-AnomalyDiagnosticSnapshot -Context $btProbeSession.PendingConfirmation -Session $btProbeSession
                                    if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                                        try { Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name "anomaly-diagnostic.json" -Data $diagSnap } catch { }
                                    }
                                    if ($diagSnap.EventLogs -and $diagSnap.EventLogs.Events) {
                                        Write-BtLog "  Captured $(@($diagSnap.EventLogs.Events).Count) event log entries" -Level "DIM"
                                    }
                                    Write-BtLog "  Diagnostic snapshot saved to package" -Level "INFO"
                                } catch {
                                    Write-BtLog "  Diagnostic snapshot failed: $_" -Level "WARN"
                                }
                            }
                            $btAnomalyBar.Visible = $false
                            $btProbeSession.PendingConfirmation = $null
                            $btAnomalyBarTime = $null
                        } elseif ($btAnomalyBarTime -and ($now - $btAnomalyBarTime).TotalSeconds -gt 60) {
                            $btAnomalyBar.Visible = $false
                            $btProbeSession.PendingConfirmation = $null
                            $btAnomalyBarTime = $null
                            Write-BtLog "  (anomaly confirmation timed out -- not confirmed)" -Level "DIM"
                        }
                    }

                    # Heartbeat every ~90s
                    $btHeartbeatTick++
                    if ($btHeartbeatTick -ge 30) {
                        $btHeartbeatTick = 0
                        $elSec = [int]$elapsed.TotalSeconds
                        $hbDevice = Get-ProbeStateUserText -Kind device -State $btProbeWatch.DeviceState -Short
                        $hbStream = Get-ProbeStateUserText -Kind stream -State $btProbeSession.StreamingState -Short
                        Write-BtLog "  ... watching  [${elSec}s]  Device: $hbDevice  |  $hbStream" -Level "DIM"
                    }

                    # ── Fixed-rate scheduling ────────────────────────────────
                    # The next deadline is the PREVIOUS DEADLINE plus the
                    # interval, not "now plus the interval". Scheduling from the
                    # end of the tick makes the real period interval + execution
                    # time -- a 1 s tick would start every 4 s, not every 3 --
                    # and every tick-count-based detection window would silently
                    # stretch by a third.
                    #
                    # Overrun is handled by SKIPPING missed deadlines rather than
                    # running catch-up ticks back to back, and by guaranteeing a
                    # floor of message-pump time afterwards. Without that floor a
                    # box slower than its own interval never pumps at all, which
                    # is the failure this replaced.
                    # Arithmetic lives in Get-NextProbeTickDeadline so it is a pure
                    # function with its own tests rather than a branch buried in a
                    # GUI loop that no test can reach.
                    $btSched = Get-NextProbeTickDeadline -PreviousDeadline $btNextProbeTick `
                        -TickEnd (Get-Date) -IntervalSeconds $btTickIntervalSec `
                        -MinPumpRecoveryMs $btTickStats.MinPumpRecoveryMs
                    $btNextProbeTick = $btSched.NextDeadline
                    $btTickStats.MissedDeadlines += $btSched.MissedDeadlines
                    # The floor overriding the fixed rate means the box could not
                    # sustain the advertised cadence AND stay responsive. Counted,
                    # not absorbed: it is the difference between "checked every 3s"
                    # and "checked as often as this PC allowed".
                    if ($btSched.PumpFloorApplied) { $btTickStats.PumpFloorDeviations++ }

                    # ── Cadence, NOT execution cost ──────────────────────────
                    # Emitted only on evidence that the schedule actually slipped:
                    # a deadline was missed, or the pump floor had to override the
                    # fixed rate. This is the ONLY claim that "checks are further
                    # apart than 3s" is entitled to make, and it is made from the
                    # scheduler's own outputs rather than inferred from how long a
                    # tick happened to take.
                    if (-not $btCadenceWarned -and
                        ($btSched.MissedDeadlines -gt 0 -or $btSched.PumpFloorApplied)) {
                        $btCadenceWarned = $true
                        Write-BtLog "  [~] This PC cannot sustain a check every 3s, so checks are being spaced further apart to keep the window usable. Recording is unaffected -- the capture records the cadence it actually achieved, not the one it aimed for." -Level "WARN"
                    }
                }

                # ── Event log poll (background job, every 8s -- unchanged) ───
                if ($btPollJob -and $btPollJob.State -notin @('Running', 'NotStarted')) {
                    $pollData = $null
                    try { $pollData = Receive-Job $btPollJob -ErrorAction SilentlyContinue } catch { }
                    Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue
                    $btPollJob = $null

                    . $mergeBtPollData $pollData $true

                    $btNextPoll = (Get-Date).AddSeconds(8)
                }

                if (-not $btPollJob -and $now -ge $btNextPoll) {
                    $collectTopology = [bool]($btProbeSession -and $btProbeSession.SerialOpenAttempts.TopologyRequest -and
                        $btProbeSession.SerialOpenAttempts.TopologyRequest.Status -eq 'Pending')
                    $btPollJob = Start-Job -ScriptBlock $btPollJobScript -ArgumentList $btModPath, $btDeviceProbeModPath, $btPollSince, $collectTopology
                }

                Wait-BtPump -Milliseconds 200 -BreakOnOperatorAction
            }

            # The recording window closes the instant the loop exits, before any
            # packaging work is charged to it (issue #78). Paired with
            # RecordingStartedAt above; together they are the ONLY source of the
            # recorded duration.
            if ($btProbeSession) { $btProbeSession.RecordingStoppedAt = Get-Date }

            # Both operator paths out of the recording are closed the instant the
            # loop exits. A live-looking Abort during packaging would promise an
            # action that can no longer happen.
            $btStopBtn.Enabled = $false
            $btAbortBtn.Enabled = $false
            $btAnomalyBar.Visible = $false

            if ($script:BtRec_AbortClicked) {
                if ($btPollJob) {
                    Stop-Job $btPollJob -ErrorAction SilentlyContinue
                    Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue
                    $btPollJob = $null
                }
                Write-BtLog ""
                Write-BtLog "ABORTED -- recording stopped without uploading." -Level "WARN"
                $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(60, 50, 10)
                $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 180, 80)
                $btBannerLabel.Text      = "Aborted -- no data was uploaded. You may close this window."
                $btElapsedLabel.Text     = "Aborted."
                # The header clock must stop claiming a running recording. A timer
                # left ticking on an aborted run is the window asserting a state
                # the run contradicts.
                $btTimerLabel.Text       = "Aborted"
                $btTimerLabel.ForeColor  = [System.Drawing.Color]::FromArgb(220, 180, 80)
                $btStopBtn.Visible       = $false
                $btMarkBtn.Visible       = $false
                $btMarkBox.Visible       = $false
                $btAbortBtn.Visible      = $false
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                return
            }

            $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(60, 40, 10)
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 100)
            $btBannerLabel.Text      = "Step 3 of 3 - Taking final snapshot, packaging and uploading..."
            # THE IN-PROGRESS WORDING, and it must stay in progress until the
            # outcome is known. The completion switch at the end of this function
            # is the ONLY place allowed to retire it -- previously nothing did,
            # so a finished run showed the header still saying "Packaging" beside
            # a banner saying the results had been sent. Both were written by
            # this file, three hundred lines apart, and neither was wrong on its
            # own; together they said the upload was simultaneously running and
            # done.
            $btElapsedLabel.Text     = "Packaging results..."
            $btTimerLabel.Text       = "Packaging..."
            $btTimerLabel.Font       = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
            $btTimerLabel.ForeColor  = [System.Drawing.Color]::FromArgb(255, 200, 100)

            # Recording is over -- free the bottom row for the saved-file path +
            # Open Folder. Abort goes with the marker controls because it can no
            # longer do anything.
            $btStopBtn.Visible  = $false
            $btMarkBtn.Visible  = $false
            $btMarkBox.Visible  = $false
            $btAbortBtn.Visible = $false

            # Consume the in-flight poll instead of discarding its result, then
            # perform one bounded final drain. This closes both prior gaps: the
            # last BTHUSB rows survive Stop, and a 2/433 raised on the final tick
            # still receives its one background topology snapshot.
            if ($btPollJob) {
                $pollDeadline = (Get-Date).AddSeconds(30)
                while ($btPollJob.State -in @('Running', 'NotStarted') -and (Get-Date) -lt $pollDeadline) {
                    Wait-BtPump -Milliseconds 200
                }
                if ($btPollJob.State -notin @('Running', 'NotStarted')) {
                    $pollData = $null
                    try { $pollData = Receive-Job $btPollJob -ErrorAction SilentlyContinue } catch { }
                    . $mergeBtPollData $pollData $false
                } elseif ($btEventEvidence) {
                    Add-BluetoothEventEvidenceBatch -Record $btEventEvidence -Batch $null -CollectorError 'In-flight event poll timed out during stop.' | Out-Null
                }
                Stop-Job $btPollJob -ErrorAction SilentlyContinue
                Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue
                $btPollJob = $null
            }

            $finalDrainCollected = $false
            $finalDrainReason = $null
            try {
                $collectTopology = [bool]($btProbeSession -and $btProbeSession.SerialOpenAttempts.TopologyRequest -and
                    $btProbeSession.SerialOpenAttempts.TopologyRequest.Status -eq 'Pending')
                $btPollJob = Start-Job -ScriptBlock $btPollJobScript -ArgumentList $btModPath, $btDeviceProbeModPath, $btPollSince, $collectTopology
                $drainDeadline = (Get-Date).AddSeconds(30)
                while ($btPollJob.State -in @('Running', 'NotStarted') -and (Get-Date) -lt $drainDeadline) {
                    Wait-BtPump -Milliseconds 200
                }
                if ($btPollJob.State -notin @('Running', 'NotStarted')) {
                    $pollData = $null
                    try { $pollData = Receive-Job $btPollJob -ErrorAction Stop } catch { $finalDrainReason = $_.Exception.Message }
                    . $mergeBtPollData $pollData $false
                    $finalDrainCollected = ($null -ne $pollData)
                } else {
                    $finalDrainReason = 'Final Bluetooth event drain timed out after 30 seconds.'
                }
            } catch {
                $finalDrainReason = $_.Exception.Message
            } finally {
                if ($btPollJob) {
                    Stop-Job $btPollJob -ErrorAction SilentlyContinue
                    Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue
                    $btPollJob = $null
                }
            }
            if ($btEventEvidence -and (Get-Command Set-BluetoothEventEvidenceFinalDrain -ErrorAction SilentlyContinue)) {
                if ($finalDrainCollected) {
                    Set-BluetoothEventEvidenceFinalDrain -Record $btEventEvidence -Status Collected | Out-Null
                } else {
                    if ([string]::IsNullOrWhiteSpace($finalDrainReason)) { $finalDrainReason = 'Final Bluetooth event drain returned no result.' }
                    Add-BluetoothEventEvidenceBatch -Record $btEventEvidence -Batch $null -CollectorError $finalDrainReason | Out-Null
                    Set-BluetoothEventEvidenceFinalDrain -Record $btEventEvidence -Status Failed -Reason $finalDrainReason | Out-Null
                    if ($btProbeSession -and (Get-Command Complete-SerialOpenTopologyRequest -ErrorAction SilentlyContinue)) {
                        Complete-SerialOpenTopologyRequest -Record $btProbeSession.SerialOpenAttempts -Snapshot $null -FailureReason $finalDrainReason | Out-Null
                    }
                }
            }

            # Persist immediately after the drain, before any later summary or
            # packaging work can fail. An empty result and a collection failure
            # are both evidence and therefore both produce this artifact.
            if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                try {
                    $btEventReport = if ($btEventEvidence -and (Get-Command Get-BluetoothEventEvidenceReport -ErrorAction SilentlyContinue)) {
                        Get-BluetoothEventEvidenceReport -Record $btEventEvidence -TargetMac $btProbeTargetMac
                    } else {
                        [pscustomobject]@{
                            Contract = 'WinConfig.BluetoothEventEvidence/v1'
                            EventCount = 0
                            Events = @()
                            FailureCount = 1
                            Failures = @([pscustomobject]@{ Reason = 'Bluetooth event evidence accumulator was unavailable.' })
                            FinalDrainStatus = 'Failed'
                        }
                    }
                    Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'bluetooth-events.json' -Depth 12 -Data $btEventReport
                } catch { }
            }

            Write-BtLog ""
            Write-BtLog "Step 3 of 3: Stopping - taking final snapshot..." -Level "STEP"

            # ── Probe session summary (before final snapshot) ─────────────────────
            $btProbeSummary = $null
            if ($btDeepProbeAvailable -and $btProbeSession -and $btProbeWatch) {
                # ── Active port-open probe: END verification ──────────────────
                # Re-READ, never re-APPLIED. Behaviour for this run was fixed at
                # New-DeviceProbeSession and nothing here may change it: a run
                # whose treatment moved halfway through is not a run with a late
                # treatment, it is an invalid run, and the only useful thing to
                # do with that fact is record it.
                #
                # This is the operator's second verification point
                # (pre-registration section 3.4(2)) made automatic. Verifying by
                # hand at both ends is exactly the kind of step that gets skipped
                # on the third arm at the end of a long afternoon.
                if (Get-Command Get-ActivePortOpenProbeSetting -ErrorAction SilentlyContinue) {
                    try {
                        $apopEnd = Get-ActivePortOpenProbeSetting
                        $btProbeSession.ActivePortOpenProbeEndEnabled    = [bool]$apopEnd.Enabled
                        $btProbeSession.ActivePortOpenProbeEndReadStatus = [string]$apopEnd.SettingReadStatus
                        # Drift is EITHER field moving. A run that started
                        # Explicit-enabled and ended DefaultedMissing-enabled has
                        # the same behaviour and a different provenance, and the
                        # provenance is what an arm is scored on.
                        $btProbeSession.ActivePortOpenProbeDrift = (
                            ([bool]$apopEnd.Enabled -ne [bool]$btProbeSession.ActivePortOpenProbeEnabled) -or
                            ([string]$apopEnd.SettingReadStatus -ne [string]$btProbeSession.ActivePortOpenProbeReadStatus)
                        )
                        if ($btProbeSession.ActivePortOpenProbeDrift) {
                            Write-BtLog "  [!] The active port-open probe setting CHANGED during this recording: started $($btProbeSession.ActivePortOpenProbeReadStatus)/$(if ($btProbeSession.ActivePortOpenProbeEnabled) { 'ENABLED' } else { 'DISABLED' }), ended $($apopEnd.SettingReadStatus)/$(if ($apopEnd.Enabled) { 'ENABLED' } else { 'DISABLED' }). The recorder's BEHAVIOUR did not change -- it was locked at the start -- but this capture must NOT be scored as an experimental arm." -Level "FAIL"
                        }
                    } catch {
                        # An end read that fails is itself a result, and reads as
                        # drift rather than as agreement: the alternative is a
                        # silent $null that a reader fills in with "unchanged".
                        $btProbeSession.ActivePortOpenProbeEndReadStatus = 'DefaultedError'
                        $btProbeSession.ActivePortOpenProbeDrift         = $true
                    }
                }

                # FI-012 second sample. Taken before the summary so a box that
                # degraded mid-recording is reported as such rather than as
                # "arrived broken".
                if (Get-Command Get-BluetoothSerialPortIntegrity -ErrorAction SilentlyContinue) {
                    $btProbeSession.SerialPortIntegrityEnd = try { Get-BluetoothSerialPortIntegrity } catch { $null }
                }

                # FI-014 second sample, same reasoning as the FI-012 pair above:
                # it separates "arrived with no node" from "lost its node while
                # we watched", and only the second pins the trigger to this
                # recording. Re-resolves the MAC because a device removed DURING
                # the session loses the PnP node the start sample resolved from.
                if (Get-Command Get-BluetoothOrphanPairingRecord -ErrorAction SilentlyContinue) {
                    try {
                        $btPairInvEnd = Get-BluetoothOrphanPairingRecord
                        # Frozen MAC first: the end sample must describe the SAME
                        # headset as the start sample, or the pair of them cannot
                        # show that anything changed during the recording.
                        $btPairMacEnd = $btProbeSession.TargetMacFrozen
                        if (-not $btPairMacEnd) { $btPairMacEnd = $btProbeSession.PairingTargetMac }
                        if (-not $btPairMacEnd) {
                            $btPairMacEnd = (Resolve-BluetoothTargetMac -PnpMac '' -Records @($btPairInvEnd.Records)).Mac
                        }
                        $btProbeSession.PairingRecordEnd = if ($btPairMacEnd) {
                            Get-BluetoothOrphanPairingRecord -TargetMac $btPairMacEnd
                        } else { $btPairInvEnd }
                    } catch { }
                }

                # ── "Can this box see the headset at all?" ───────────────────
                # CONDITIONAL, and deliberately not part of every capture. A real
                # BR/EDR inquiry drives the radio for tens of seconds, so running
                # it on every recording would perturb the very link being
                # measured. It is only run when it is both SAFE and the only
                # thing that can answer:
                #   - the target has no device node (nothing else can tell a
                #     headset this box cannot discover from one merely unpaired),
                #   - and NO.exe is closed, so there is no live client session to
                #     disturb.
                # Runs in a background job because Start-Job is MTA: the scan
                # refuses on STA by design, and this form is what keeps the GUI
                # message pump alive rather than freezing it for the whole scan.
                $btInquiry = @{
                    Collected = $false
                    Reason    = $null
                    Result    = $null
                }
                try {
                    $btPairEndVerdict = $btProbeSession.PairingRecordEnd
                    $btTargetNodeless = [bool]($btPairEndVerdict -and
                        $btPairEndVerdict.TargetState -in @('Orphan', 'Sighting', 'NoRecord'))
                    $btNoRunning = [bool](Get-Process -Name 'NO' -ErrorAction SilentlyContinue)

                    if (-not $btTargetNodeless) {
                        $btInquiry.Reason = 'Skipped: the target has a device node, so discovery is not in question. An inquiry would only perturb the radio.'
                    } elseif ($btNoRunning) {
                        $btInquiry.Reason = 'Skipped: NO.exe is running. A radio inquiry during a live client session can disturb the link being measured.'
                    } else {
                        Write-BtLog "  Target has no device node -- running a discovery scan to see whether this box can hear it at all..." -Level "STEP"
                        [System.Windows.Forms.Application]::DoEvents()
                        $btScanJob = Start-Job -ScriptBlock {
                            param($mp)
                            Import-Module $mp -Force -ErrorAction Stop
                            Get-BluetoothInquiryScan -TimeoutMs 45000
                        } -ArgumentList $btModPath
                        $btScanDeadline = (Get-Date).AddSeconds(75)
                        while ($btScanJob.State -in @('Running','NotStarted') -and (Get-Date) -lt $btScanDeadline) {
                            Wait-BtPump -Milliseconds 200
                        }
                        if ($btScanJob.State -in @('Running','NotStarted')) {
                            Stop-Job $btScanJob -ErrorAction SilentlyContinue
                            $btInquiry.Reason = 'Scan exceeded its deadline and was stopped.'
                        } else {
                            $btInquiry.Result    = Receive-Job $btScanJob -ErrorAction SilentlyContinue
                            $btInquiry.Collected = [bool]$btInquiry.Result
                            if ($btInquiry.Result -and $btInquiry.Result.Summary) {
                                Write-BtLog "  $($btInquiry.Result.Summary)" -Level $(if ($btInquiry.Result.Count -gt 0) { 'OK' } else { 'WARN' })
                            }
                        }
                        Remove-Job $btScanJob -Force -ErrorAction SilentlyContinue
                    }
                } catch {
                    $btInquiry.Reason = "Scan failed: $($_.Exception.Message)"
                }
                $btProbeSession.InquiryScan = $btInquiry

                # FI-012 fault 2 fingerprint. Read-only: radio State (never
                # SetStateAsync) plus the paired-device link state WinRT already
                # exposes. Deliberately NOT an open attempt -- see
                # Test-BluetoothSerialPortOpen for why that cannot run here.
                if (Get-Command Get-SerialFaultFingerprint -ErrorAction SilentlyContinue) {
                    try {
                        $btRadio = try { Get-BluetoothRadioState } catch { $null }
                        $btPaired = try { @(Get-BluetoothDevicesWinRT) } catch { @() }
                        $btIntegForFp = if ($btProbeSession.SerialPortIntegrityEnd) {
                            $btProbeSession.SerialPortIntegrityEnd
                        } else { $btProbeSession.SerialPortIntegrity }
                        # LastConnectedTime for the target: the passive signal
                        # that actually discriminated during the field case.
                        #
                        # Scoped to the FROZEN MAC, not to a name regex. This
                        # block used to run its own `-match 'NeurOptimal|Arc'`
                        # over every paired device and take [0] -- a second,
                        # independent selector. On capture 8E39860E4AF2 it landed
                        # on Arc 000013 while the recording watched Arc 000019, so
                        # one artifact described two headsets and said neither.
                        $btFrozenMac = $btProbeSession.TargetMacFrozen
                        $btFrozenHex = ([string]$btFrozenMac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                        $btTarget = if ($btFrozenHex) {
                            @($btPaired | Where-Object {
                                $_ -and (([string]$_.Address -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $btFrozenHex)
                            })
                        } else {
                            @($btPaired | Where-Object { $_.Name -and $_.Name -match 'NeurOptimal|Arc' })
                        }
                        $btLinkHist = $null
                        if ($btTarget.Count -gt 0 -and $btTarget[0].Address) {
                            $btLinkHist = try { Get-BluetoothLinkHistory -Address $btTarget[0].Address } catch { $null }
                        } elseif ($btFrozenHex) {
                            $btLinkHist = try { Get-BluetoothLinkHistory -Address $btFrozenHex } catch { $null }
                        }
                        # SessionObservedLink: this recording's own first-hand
                        # evidence. Without it the fingerprint decides from a
                        # post-stop IsConnected sample and a registry timestamp
                        # FI-012 already records as untrustworthy -- and stopping
                        # a session releases the link, so a clean capture reads
                        # Disconnected and drew an FI-012 fault-2 finding
                        # (capture B9F9F0EE5E21).
                        $btProbeSession.SerialFaultFingerprint = Get-SerialFaultFingerprint `
                            -Integrity $btIntegForFp -PairedDevices $btPaired `
                            -RadioOn $(if ($btRadio) { $btRadio.BluetoothOn } else { $null }) `
                            -LinkHistory $btLinkHist -TargetMac $btFrozenHex `
                            -SessionObservedLink ([bool]$btProbeSession.BtLinkEverConnected)
                        if ($btRadio) { $btProbeSession.SerialFaultFingerprint.RadioState = $btRadio }
                    } catch { }
                }

                $btProbeSummary = Get-DeviceProbeSessionSummary -Session $btProbeSession -WatchState $btProbeWatch
                $btWatchReport  = New-TargetWatchReport -WatchState $btProbeWatch

                # Attribution caveat: repair tools run mid-recording change the very
                # state the probe observes (COM ports, BTHENUM entries), so flag it
                # for triage -- readers must not count those changes as field
                # evidence of spontaneous/NO.exe-driven behavior.
                if ($script:BtRecOperatorActions.Count -gt 0) {
                    $opaTools = @($script:BtRecOperatorActions | ForEach-Object { "'$($_.Tool)'" }) -join ', '
                    $btProbeSummary.Findings = @($btProbeSummary.Findings) + "[info] Operator ran $($script:BtRecOperatorActions.Count) repair action(s) during this recording ($opaTools) -- some changes above may be operator-induced, not spontaneous"
                }

                Write-BtLog ""
                Write-BtLog "SESSION SUMMARY" -Level "STEP"
                Write-BtLog "  Final device state  : $(Get-ProbeStateUserText -Kind device -State $btWatchReport.DeviceState -Short)" -Level (Get-ProbeStateGuiLevel $btWatchReport.DeviceState)
                Write-BtLog "  Final COM port      : $(Get-ProbeStateUserText -Kind comport -State $btWatchReport.ComPortState -Short)" -Level (Get-ProbeStateGuiLevel $btWatchReport.ComPortState)
                Write-BtLog "  Total state changes : $($btProbeSummary.ObservationCount)" -Level "INFO"

                if ($btProbeSummary.ReconnectStats) {
                    $rs = $btProbeSummary.ReconnectStats
                    Write-BtLog "  Reconnect times     : min=$($rs.Min)s  avg=$($rs.Avg)s  max=$($rs.Max)s  ($($rs.Count) reconnect(s))" -Level "INFO"
                }

                if ($btProbeSummary.ComPortHistory.Count -gt 0) {
                    Write-BtLog "" -Level "DIM"
                    Write-BtLog "COM PORT HISTORY" -Level "STEP"
                    foreach ($h in $btProbeSummary.ComPortHistory) {
                        $portStr = ($h.Ports | Sort-Object) -join ', '
                        $timeStr = $h.Time.ToString('HH:mm:ss')
                        if ($h.IsFirst) {
                            Write-BtLog "  Re-pair $($h.RepairNum.ToString().PadLeft(2))  $timeStr  $portStr  (initial)" -Level "DIM"
                        } elseif ($h.Changed) {
                            $parts = @()
                            if ($h.Removed.Count -gt 0) { $parts += "lost $($h.Removed -join ', ')" }
                            if ($h.Added.Count -gt 0)   { $parts += "gained $($h.Added -join ', ')" }
                            Write-BtLog "  Re-pair $($h.RepairNum.ToString().PadLeft(2))  $timeStr  $portStr  [~] $($parts -join ', ')" -Level "WARN"
                        } else {
                            Write-BtLog "  Re-pair $($h.RepairNum.ToString().PadLeft(2))  $timeStr  $portStr  [ok] same ports" -Level "DIM"
                        }
                    }
                }

                # The recording window, and the join guard over it (issue #78).
                # Computed BEFORE the findings are printed so a divergence
                # between the marker clock, the episode ledger and the duration
                # lands in the FINDINGS section an operator actually reads --
                # a guard whose result only the manifest carries is a guard
                # nobody is warned by. Same object feeds the manifest duration
                # below, so the number and the check cannot come apart.
                $btWindow = $null
                if ($btProbeSession -and (Get-Command Get-ProbeRecordingWindow -ErrorAction SilentlyContinue)) {
                    $btWindow = try { Get-ProbeRecordingWindow -Session $btProbeSession } catch { $null }
                }
                if ($btWindow -and @($btWindow.Findings).Count -gt 0) {
                    $btProbeSummary.Findings = @($btProbeSummary.Findings) + @($btWindow.Findings)
                }

                Write-BtLog "" -Level "DIM"
                Write-BtLog "FINDINGS" -Level "STEP"
                foreach ($f in $btProbeSummary.Findings) {
                    $fLevel = if ($f.StartsWith('[!]')) { 'FAIL' } elseif ($f.StartsWith('[~]')) { 'WARN' } elseif ($f.StartsWith('[ok]')) { 'OK' } else { 'DIM' }
                    Write-BtLog "  $f" -Level $fLevel
                }

                # The closing verdict must see BOTH issue channels. It used to read
                # $btWatchReport.Unresolved alone, which is COM-port matching only and
                # therefore empty by construction whenever the ports are present -- that
                # is how capture B499E903C68C ended on a green "No unresolved issues."
                # with a collapsed read rate and two operator-marked 12006s in Findings.
                #
                # Coverage goes in as well, so a recording that never observed the
                # session reads INCONCLUSIVE instead of failing it. Capture
                # 8E39860E4AF2 counted an idle headset's two findings as "2
                # problems" and told an operator their clean 37-minute session
                # "did NOT end clean".
                # Session-long read-rate record, computed from the SAME function
                # the findings are built from so the bundle and the printed
                # summary cannot disagree about whether reads ever collapsed.
                $btIoRecord = $null
                if ($btProbeSession -and (Get-Command Get-IoSessionReadRateRecord -ErrorAction SilentlyContinue)) {
                    $btIoRecord = try { Get-IoSessionReadRateRecord -Session $btProbeSession } catch { $null }
                }

                $btCoverage = $null
                if (Get-Command Get-ProbeObservationCoverage -ErrorAction SilentlyContinue) {
                    $btCoverage = try {
                        Get-ProbeObservationCoverage -Session $btProbeSession -WatchState $btProbeWatch `
                            -Target $btProbeSession.SessionTarget
                    } catch { $null }
                }
                $btVerdict = Get-ProbeSessionVerdict -Findings @($btProbeSummary.Findings) `
                    -Unresolved @($btWatchReport.Unresolved) -Coverage $btCoverage
                Write-BtLog "" -Level "DIM"
                # GuiLevel, never Level: INCONCLUSIVE is not in the Console
                # -Level ValidateSet and throws at runtime.
                if ($btVerdict.Header) { Write-BtLog $btVerdict.Header -Level $btVerdict.GuiLevel }
                foreach ($vl in $btVerdict.Lines) { Write-BtLog "  $($vl.Text)" -Level $vl.Level }
                Write-BtLog "" -Level "DIM"

                # Save probe session artifact
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try {
                        Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'probe-session.json' -Data @{
                            SessionSummary  = $btProbeSummary
                            WatchReport     = $btWatchReport
                            SessionVerdict  = $btVerdict
                            # Which headset this capture is about, why it was
                            # chosen, and what else it could have been. Without
                            # the rejected candidates a reader cannot tell a
                            # correct choice from a lucky one -- and capture
                            # 8E39860E4AF2 read as authoritative precisely
                            # because the alternative was invisible.
                            SessionTarget   = $btProbeSession.SessionTarget
                            TargetMacFrozen = $btProbeSession.TargetMacFrozen
                            Coverage        = $btCoverage
                            # Per-episode read-rate history. The live fields
                            # describe only the last port-open episode, so this
                            # is the only place a collapse that preceded a
                            # re-open is recoverable from the bundle.
                            ReadRateRecord  = $btIoRecord
                            Observations    = @($btProbeWatch.Observations)
                            # How long each tick actually took, per collector.
                            # A capture used to assert "watching every 3s" with
                            # nothing able to contradict it; measured on the dev
                            # box a tick ran ~5.5s, so ticks were both further
                            # apart than advertised and blocking the UI thread
                            # almost continuously. Recorded so cadence changes
                            # are argued from field data rather than guessed --
                            # and so a box where this is still bad is visible
                            # without anyone having to reproduce it.
                            TickTiming      = if ($btTickStats -and $btTickStats.TickCount -gt 0) { @{
                                TickCount           = [int]$btTickStats.TickCount
                                MeanMs              = [int]($btTickStats.TotalMs / $btTickStats.TickCount)
                                MaxMs               = [int]$btTickStats.MaxMs
                                # Reported separately from MeanMs/MaxMs: the first
                                # tick runs against a cold property cache, so
                                # folding it into an average makes a one-off
                                # start-up cost look like the steady state.
                                FirstTickMs         = [int]$btTickStats.FirstTickMs
                                SlowTickCount       = [int]$btTickStats.SlowTickCount
                                SlowTickThresholdMs = [int]$btTickStats.SlowTickThresholdMs
                                # What the capture's cadence ACTUALLY was, so the
                                # "checked every 3s" claim is falsifiable from the
                                # bundle instead of taken on trust.
                                TargetIntervalMs    = [int]$btTickStats.TargetIntervalMs
                                MeanIntervalMs      = if ($btTickStats.IntervalCount -gt 0) { [int]($btTickStats.IntervalTotalMs / $btTickStats.IntervalCount) } else { $null }
                                MaxIntervalMs       = [int]$btTickStats.IntervalMaxMs
                                MissedDeadlines     = [int]$btTickStats.MissedDeadlines
                                PumpFloorDeviations = [int]$btTickStats.PumpFloorDeviations
                                CollectorMeanMs     = @{
                                    Inventory = [int]($btTickStats.CollectorTotalMs['Inventory'] / $btTickStats.TickCount)
                                    Pnp     = [int]($btTickStats.CollectorTotalMs['Pnp']     / $btTickStats.TickCount)
                                    ComPort = [int]($btTickStats.CollectorTotalMs['ComPort'] / $btTickStats.TickCount)
                                    Process = [int]($btTickStats.CollectorTotalMs['Process'] / $btTickStats.TickCount)
                                    Update  = [int]($btTickStats.CollectorTotalMs['Update']  / $btTickStats.TickCount)
                                    Render  = [int]($btTickStats.CollectorTotalMs['Render']  / $btTickStats.TickCount)
                                }
                                CollectorMaxMs      = @{
                                    Inventory = [int]$btTickStats.CollectorMaxMs['Inventory']
                                    Pnp     = [int]$btTickStats.CollectorMaxMs['Pnp']
                                    ComPort = [int]$btTickStats.CollectorMaxMs['ComPort']
                                    Process = [int]$btTickStats.CollectorMaxMs['Process']
                                    Update  = [int]$btTickStats.CollectorMaxMs['Update']
                                    Render  = [int]$btTickStats.CollectorMaxMs['Render']
                                }
                            } } else { $null }
                            OperatorActions = @($script:BtRecOperatorActions | ForEach-Object { @{
                                Tool        = $_.Tool
                                ToolId      = $_.ToolId
                                StartedAt   = $_.StartedAt.ToString('o')
                                CompletedAt = if ($_.CompletedAt) { $_.CompletedAt.ToString('o') } else { $null }
                            } })
                        }
                    } catch { }
                }

                # Operator-labelled state vectors, as their own artifact rather
                # than only inside the summary prose. These are the only records
                # that pair NeurOptimal's own message with the machine state that
                # produced it, so they need to be machine-readable: mapping a code
                # that means two different things means clustering these across
                # many boxes, not reading them one at a time.
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try {
                        $mkAll = @($btProbeSession.OperatorMarkers)
                        Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'operator-markers.json' -Data @{
                            MarkerCount = $mkAll.Count
                            NoExeVersion = if ($btProbeSession.NoExeVersion) { [string]$btProbeSession.NoExeVersion } else { $null }
                            Markers     = @($mkAll | ForEach-Object { @{
                                At               = $_.AtIso
                                ElapsedSeconds   = $_.ElapsedSeconds
                                Label            = $_.Label
                                NoCode           = $_.NoCode
                                DeviceState      = $_.DeviceState
                                ComPortState     = $_.ComPortState
                                BtLinkState      = $_.BtLinkState
                                StreamState      = $_.StreamState
                                HeldPorts        = @($_.HeldPorts)
                                UnavailablePorts = @($_.UnavailablePorts)
                                UnavailableAfterHeldPorts = @($_.UnavailableAfterHeldPorts)
                                AppRunning       = $_.AppRunning
                                IoVerdict            = $_.IoVerdict
                                IoBaselineOpsPerSecond = $_.IoBaselineOpsPerSecond
                                IoRecentOpsPerSecond   = $_.IoRecentOpsPerSecond
                                # The read-rate episode live when the operator
                                # pressed Mark (#87). This is the join key: the
                                # episode ledger records the same id, so "did the
                                # 12006 land inside the episode that collapsed?"
                                # is answerable from the record instead of being
                                # reconstructed from timestamps.
                                EpisodeId            = $_.EpisodeId
                                Contradictions   = @($_.Contradictions)
                            } })
                        }
                    } catch { }
                }

                # FI-012 structured evidence. The session summary carries the
                # verdict as a sentence; this carries the table it was derived
                # from -- every SERIALCOMM registration, which device objects
                # collided on which COM name, and what each symlink resolved to.
                # That is what makes a ZIP triageable remotely without the box in
                # front of you, which is exactly what this escalation lacked.
                # Two samples so "arrived broken" and "degraded while recording"
                # stay distinguishable after the fact.
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try {
                        $siStart = $btProbeSession.SerialPortIntegrity
                        $siEnd   = $btProbeSession.SerialPortIntegrityEnd
                        if ($siStart -or $siEnd) {
                            # Depth 8 as headroom. The nesting runs Data >
                            # AtSessionStart > Entries > entry > DeviceObjects >
                            # string; the default 5 does happen to serialize
                            # that intact today (verified), but the colliding
                            # device-object names are the entire evidentiary
                            # value of this artifact and ConvertTo-Json flattens
                            # silently -- a file that looks complete and proves
                            # nothing is the worst failure mode here. Cheap
                            # insurance against a future field being added.
                            Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'serialcomm-integrity.json' -Depth 8 -Data @{
                                Fault          = 'FI-012'
                                Reference      = 'docs/FIELD-ISSUES.md'
                                AtPreflight    = $btProbeSession.SerialPortPreflight
                                AtSessionStart = $siStart
                                AtSessionEnd   = $siEnd
                                DegradedInRun  = [bool]($siStart -and $siEnd -and $siStart.Healthy -and -not $siEnd.Healthy)
                                # Fault 2 cannot be confirmed without opening a
                                # port, which is barred here. This is the
                                # unconfirmed fingerprint plus the radio state
                                # that makes it interpretable.
                                Fingerprint    = $btProbeSession.SerialFaultFingerprint
                            }
                        }
                    } catch { }
                }

                # FI-014 structured evidence, kept as its own artifact rather
                # than folded into the Bluetooth blob -- same reasoning as
                # serialcomm-integrity.json above. A reader triaging "the
                # headset is not there" needs the registry-vs-node table and
                # what the target actually resolved to, not a verdict sentence.
                #
                # Every not-collected case carries its REASON. A missing field
                # reads as "nothing found" and that is the failure this artifact
                # exists to prevent: the check was corrected twice and until now
                # it never ran in a field capture at all.
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try {
                        $prStart = $btProbeSession.PairingRecord
                        $prEnd   = $btProbeSession.PairingRecordEnd
                        if ($prStart -or $prEnd) {
                            Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'pairing-target-evidence.json' -Depth 8 -Data @{
                                Fault        = 'FI-014'
                                Reference    = 'docs/FIELD-ISSUES.md'
                                Target       = @{
                                    Mac     = $btProbeSession.PairingTargetMac
                                    # PnpNode | PairingRecord | None. 'None'
                                    # means the verdict below is unscoped and
                                    # therefore Healthy by construction -- read
                                    # it as an inventory, not a clean bill.
                                    Source  = $btProbeSession.PairingTargetSource
                                    Summary = $btProbeSession.PairingTargetSummary
                                }
                                AtSessionStart = $prStart
                                AtSessionEnd   = $prEnd
                                # The transition that pins a teardown to THIS
                                # recording rather than to some earlier removal.
                                LostNodeInRun  = [bool]($prStart -and $prEnd -and
                                    $prStart.TargetState -eq 'Paired' -and $prEnd.TargetState -eq 'Orphan')
                                Discovery      = $btProbeSession.InquiryScan
                                # Not collected, and this says why rather than
                                # leaving a hole. Get-BluetoothDeviceReachability
                                # OPENS a COM port; its own contract bars it from
                                # the recorder path because an automatic open can
                                # steal the port from a live NO.exe session and
                                # manufacture the error being diagnosed. It is
                                # also useless in the case that would be safe: a
                                # target with no node has no port to open.
                                Reachability   = @{
                                    Collected = $false
                                    Reason    = 'Not run automatically: this probe opens a COM port, which can steal it from a live session. Operator-initiated only -- run Get-BluetoothDeviceReachability with NO.exe closed.'
                                }
                            }
                        }
                    } catch { }
                }
            }

            # ── PHASE 3: Final snapshot, package, upload ──────────────────────────
            $btFinalJob = Start-Job -ScriptBlock {
                param($mp)
                Import-Module $mp -Force -ErrorAction SilentlyContinue
                Invoke-BluetoothDiagnosticsAndRecord -RecordAction {
                    param([hashtable]$e)
                    try { if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) { Register-WinConfigSessionAction @e } } catch {}
                } -TimeoutSeconds 60
            } -ArgumentList $btModPath

            # NOT -BreakOnOperatorAction: Stop has already been clicked by the time
            # this runs, so an early return here would spin instead of waiting.
            while ($btFinalJob.State -in @('Running','NotStarted')) {
                Wait-BtPump -Milliseconds 200
            }

            $finalResult = $null
            try {
                $finalResult = Receive-Job $btFinalJob -ErrorAction SilentlyContinue
                Remove-Job $btFinalJob -Force -ErrorAction SilentlyContinue
            } catch {
                Remove-Job $btFinalJob -Force -ErrorAction SilentlyContinue
            }

            if ($finalResult) {
                $vStr  = if ($finalResult.VerdictStatus) { $finalResult.VerdictStatus } else { "N/A" }
                $flvl  = switch ($finalResult.Status) {
                    "Success"        { if ($finalResult.VerdictStatus -eq "READY") { "OK" } else { "WARN" } }
                    "PartialSuccess" { "WARN" }
                    default          { "WARN" }
                }
                # Scoped for the same reason as the baseline line above. The data
                # flow answer is the read-rate outcome, printed separately.
                Write-BtLog "Final: $($finalResult.Status)  Audio verdict=$vStr (audio checks only -- says nothing about EEG data flow)  Findings=$($finalResult.FindingCount)" -Level $flvl
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try { Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name "final.json" -Data $finalResult } catch { }
                }
            } else {
                # No final result means the final diagnostics pass crashed or timed out.
                # Don't swallow it — the package will still be saved with what we captured.
                Write-BtLog "Final check did not finish (it stopped early or timed out). Your results will still be saved with the data collected so far." -Level "WARN"
            }

            # System identity — computed once for manifest + zip naming
            $systemModel = try { (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Model } catch { 'Unknown' }
            $safeModel   = ($systemModel -replace '[^A-Za-z0-9 -]', '' -replace '\s+', '-').Trim('-')
            if ($safeModel.Length -gt 20) { $safeModel = $safeModel.Substring(0, 20).TrimEnd('-') }
            $safeHost    = ($env:COMPUTERNAME -replace '[^A-Za-z0-9]', '').ToUpper()
            if ($safeHost.Length -gt 12) { $safeHost = $safeHost.Substring(0, 12) }

            # Manifest artifact — machine identity + run summary for triage
            if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                try {
                    # OS identity: CIM Caption reports Windows 11 correctly. The registry
                    # ProductName value is stale on Win11 (always "Windows 10 Pro"), so it is
                    # only a fallback and is build-corrected (>= 22000 == Windows 11).
                    $osCaption = $null; $osBuild = $null; $osDisplayVersion = $null
                    try {
                        $cimOs     = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                        $osCaption = "$($cimOs.Caption)"
                        $osBuild   = "$($cimOs.BuildNumber)"
                    } catch {
                        try {
                            $cv      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                            $osBuild = "$($cv.CurrentBuild)"
                            $pn      = $cv.ProductName
                            if ([int]$osBuild -ge 22000) { $pn = $pn -replace 'Windows 10', 'Windows 11' }
                            $osCaption = $pn
                        } catch { }
                    }
                    try { $osDisplayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion } catch { }
                    $manifest = [ordered]@{
                        RunId                = $btDiagRun.RunId
                        StartedAtUtc         = $btDiagRun.StartedAtUtc
                        PackagedAtUtc        = [datetime]::UtcNow.ToString('o')
                        MachineName          = $env:COMPUTERNAME
                        UserName             = $env:USERNAME
                        UserDomain           = $env:USERDOMAIN
                        SystemModel          = $systemModel
                        PSVersion            = $PSVersionTable.PSVersion.ToString()
                        OSCaption            = $osCaption
                        OSBuild              = $osBuild
                        OSDisplayVersion     = $osDisplayVersion
                        BaselineVerdict      = if ($baselineResult) { $baselineResult.VerdictStatus } else { $null }
                        BaselineFindingCount = if ($baselineResult) { $baselineResult.FindingCount  } else { $null }
                        BaselineStatus       = if ($baselineResult) { $baselineResult.Status        } else { $null }
                        FinalVerdict         = if ($finalResult)    { $finalResult.VerdictStatus    } else { $null }
                        FinalFindingCount    = if ($finalResult)    { $finalResult.FindingCount     } else { $null }
                        FinalStatus          = if ($finalResult)    { $finalResult.Status           } else { $null }
                        BluetoothEventEvidence = if ($btEventReport) {
                            [ordered]@{
                                Artifact         = 'bluetooth-events.json'
                                Contract         = $btEventReport.Contract
                                EventCount       = $btEventReport.EventCount
                                FailureCount     = $btEventReport.FailureCount
                                FinalDrainStatus = $btEventReport.FinalDrainStatus
                            }
                        } else { $null }
                        ProbeObservationCount  = if ($btProbeSummary) { $btProbeSummary.ObservationCount } else { $null }
                        ProbeFindingCount      = if ($btProbeSummary) { $btProbeSummary.Findings.Count   } else { $null }
                        ProbeReconnectCount    = if ($btProbeSession) { $btProbeSession.ReconnectTimes.Count } else { $null }
                        ProbeBtLinkFlapCount   = if ($btProbeSession) { $btProbeSession.BtLinkFlapCount } else { $null }
                        # How long the recording ran and how many samples it took.
                        # ProbeObservationCount counts TRANSITIONS, so a box that
                        # arrived already in its final state reports 3 whether the
                        # run lasted 55 seconds or 6 hours -- and that difference
                        # decides whether a tail of link flaps is a fault or an
                        # unattended overnight run.
                        ProbeTickCount           = if ($btProbeSession) { [int]$btProbeSession.TickCount } else { $null }
                        # From Get-ProbeRecordingWindow, which is now the ONLY
                        # answerer for this question. It used to be computed
                        # here as the TICK span (FirstTickAt..LastTickAt) --
                        # a different clock from the one operator markers and
                        # the on-screen elapsed label count from, and shorter
                        # by however long the loop took to reach its first tick
                        # plus however long it ran past its last. On capture
                        # 236061907514 that gap was ~65 s of a ~134 s run, so
                        # the manifest reported 69 s for a recording carrying
                        # markers at 86 s and 107 s (issue #78).
                        #
                        # Null when the window was never stamped, deliberately.
                        # Falling back to the tick span would restore the second
                        # answerer, and a wrong duration is worse than an absent
                        # one here: durationSeconds / tickCount is how cadence is
                        # read, and 69/22 = 3.14 s passes for a healthy 3 s loop
                        # when the truth was 6.1 s and 18 of 22 deadlines missed.
                        RecordingDurationSeconds = if ($btWindow) { $btWindow.DurationSeconds } else { $null }
                        # The tick span survives under a name that says what it
                        # is, so the gap between "how long the recorder ran" and
                        # "how long the sampling loop was alive" is visible in
                        # the bundle instead of being inferred from timestamps.
                        RecordingTickSpanSeconds = if ($btWindow) { $btWindow.TickSpanSeconds } else { $null }
                        # False means a marker or an episode is stamped outside
                        # the recording window -- the timeline of this capture
                        # cannot be trusted. Null on builds before #78.
                        RecordingWindowConsistent = if ($btWindow) { [bool]$btWindow.Consistent } else { $null }
                        # ── Identity of what was recorded ────────────────────
                        # All three were already captured in the session and went
                        # only to the console log, so reading a bundle meant
                        # opening another artifact (NoExeVersion lives in
                        # operator-markers.json) or regexing English prose out of
                        # the findings list. The adapter vendor is the fact that
                        # made the SP6-vs-MMEVOLD_06 comparison meaningful, and it
                        # existed only as a sentence.
                        NoExeVersion           = if ($btProbeSession -and $btProbeSession.NoExeVersion) { [string]$btProbeSession.NoExeVersion } else { $null }
                        BtAdapterName          = if ($btProbeSession -and $btProbeSession.AdapterInfo) { $btProbeSession.AdapterInfo.FriendlyName } else { $null }
                        BtAdapterDriverVersion = if ($btProbeSession -and $btProbeSession.AdapterInfo -and $btProbeSession.AdapterInfo.DriverInfo) {
                            $btProbeSession.AdapterInfo.DriverInfo.Version
                        } else { $null }
                        PowerPlanName          = if ($btProbeSession -and $btProbeSession.PowerPlan) { $btProbeSession.PowerPlan.ActivePlan } else { $null }
                        PowerPlanIsPowerSaver  = if ($btProbeSession -and $btProbeSession.PowerPlan) { [bool]$btProbeSession.PowerPlan.IsPowerSaver } else { $null }
                        # ── Structured forms of prose-only findings ──────────
                        # The dashboard derived these by regex over the findings
                        # text, so rewording a finding silently zeroed a fleet
                        # count -- which reads as "no machines affected" rather
                        # than "the signal broke". Same reasoning as the FI-012
                        # counts above, which were deliberately keyed on manifest
                        # fields rather than text for exactly this reason.
                        UsbSelectiveSuspendEnabled = if ($btProbeSession -and $btProbeSession.AdapterInfo) {
                            [bool]($btProbeSession.AdapterInfo.PowerManagementEnabled -eq $true)
                        } else { $null }
                        AppHangDetected        = if ($btProbeSession) { [bool]$btProbeSession.AppHangReported } else { $null }
                        BtLinkEverConnected    = if ($btProbeSession) { [bool]$btProbeSession.BtLinkEverConnected } else { $null }
                        BtLinkPreSessionFlapCount = if ($btProbeSession) { [int]$btProbeSession.BtLinkPreSessionFlapCount } else { $null }
                        BtLinkActiveSessionDropCount = if ($btProbeSession) { [int]$btProbeSession.BtLinkActiveSessionDropCount } else { $null }
                        StartupSppChannelCount = if ($btProbeSession) { [int]$btProbeSession.StartupSppChannelCount } else { $null }
                        # Raw count, NOT the [!]-vs-[ok] judgement. Whether a
                        # reassignment matters depends on the NO build (>= 4.0
                        # re-resolves from the MAC, so it invalidates nothing),
                        # and duplicating that decision here would give it two
                        # homes that could disagree. The consumer gets both facts.
                        ComPortChangeCount     = if ($btProbeSession) {
                            @($btProbeSession.ComPortHistory | Where-Object { $_.Changed -and -not $_.IsFirst }).Count
                        } else { $null }
                        SlowReconnectCount     = if ($btProbeSession) {
                            @($btProbeSession.ReconnectTimes | Where-Object { $_ -ge 90 }).Count
                        } else { $null }
                        # The other half of the reassignment judgement, so a
                        # consumer can reach the same [!]-vs-[ok] conclusion the
                        # summary text does without parsing the prefix.
                        NoResolvesPortFromMac  = if ($btProbeSession -and $btProbeSession.NoExeVersion) {
                            try { [bool](Test-NoUsesMacResolve -Version $btProbeSession.NoExeVersion) } catch { $null }
                        } else { $null }
                        # ── Which SPP channel each port is ───────────────────
                        # Two ports for one MAC is the Arc's NORMAL shape, so the
                        # recorder used to report it as an unresolved ambiguity on
                        # every healthy capture. Roles come from two sources that
                        # must agree (see Resolve-ComPortRole); RoleConflict means
                        # the FI-012 channel-to-role invariant failed on this box,
                        # which is a finding about the invariant itself.
                        ComPortRoles = @(if ($btProbeWatch) {
                            @(@($btProbeWatch.ComPortMatches) | Where-Object { $_.PortName } | ForEach-Object {
                                @{
                                    PortName = $_.PortName
                                    Role     = $_.ChannelRole
                                    Source   = $_.ChannelRoleSource
                                }
                            })
                        } else { @() })
                        ComPortRoleConflict = if ($btProbeWatch) { [bool]$btProbeWatch.ComPortRoleConflict } else { $null }
                        # ── How invasive the recorder itself was ─────────────
                        # Hold detection works by opening the port. On a port
                        # NO.exe holds the attempt is DENIED and no handle is
                        # taken; on a free port we really do open and close it,
                        # every ~3s. Recorded so this is answered from a capture
                        # rather than argued -- and so a decision to back the
                        # interval off rests on a measured number.
                        # ── Provenance: which build wrote this capture ───────
                        # Every capture before this one was unattributable --
                        # nothing in the manifest carried a build id, so a
                        # package could not be tied to the code that produced
                        # it. Derived, never asserted: the open contract comes
                        # from what was actually observed, so a fallback capture
                        # reports SerialPortLegacy/v1 honestly and a run that
                        # never reached a port reports NotObserved.
                        # A failed read renders as null with a status; it never
                        # costs the recording.
                        BtEvidenceProvenance = if ($btProbeSession -and (Get-Command Get-BtEvidenceProvenance -ErrorAction SilentlyContinue)) {
                            try { Get-BtEvidenceProvenance -SerialOpenRecord $btProbeSession.SerialOpenAttempts } catch { $null }
                        } else { $null }
                        # ── The treatment this capture ran under ─────────────
                        # ABSENT on a pre-toggle build, and that is NOT the same
                        # as $true -- a reader who finds no key here is looking
                        # at a package from a build that had no toggle, which is
                        # a different fact from a build that had one and left it
                        # on. The key's PRESENCE remains the discriminator for
                        # packages written BEFORE BtEvidenceProvenance existed
                        # (same reasoning as the #86 ops-per-second rename).
                        ActivePortOpenProbeEnabled = if ($btProbeSession -and $btProbeSession.ContainsKey('ActivePortOpenProbeEnabled')) {
                            [bool]$btProbeSession.ActivePortOpenProbeEnabled
                        } else { $null }
                        # 'Explicit' / 'DefaultedMissing' / 'DefaultedError'. A
                        # defaulted read is SAFE for a clinic and INVALIDATES an
                        # experimental arm; both consumers read this one field.
                        ActivePortOpenProbeReadStatus = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeReadStatus } else { $null }
                        ActivePortOpenProbeSource     = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeSource } else { $null }
                        ActivePortOpenProbeRawValue   = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeRawValue } else { $null }
                        # Verified at BOTH ends, automatically. Drift means the
                        # capture is not scoreable as an arm even though the
                        # recorder's own behaviour never changed.
                        ActivePortOpenProbeEndEnabled    = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeEndEnabled } else { $null }
                        ActivePortOpenProbeEndReadStatus = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeEndReadStatus } else { $null }
                        ActivePortOpenProbeDrift         = if ($btProbeSession) { $btProbeSession.ActivePortOpenProbeDrift } else { $null }
                        # Which sensors were live for the port-hold question, so
                        # an empty or absent HeldPorts anywhere in this package
                        # can be read correctly without inferring it.
                        PortObservationSources = if ($btProbeSession) { @($btProbeSession.PortObservationSources) } else { $null }
                        ActiveSensorState      = if ($btProbeSession) { $btProbeSession.ActiveSensorState } else { $null }
                        # STILL REPORTED when the probe is disabled, and the
                        # value is a truthful 0 -- unlike an empty HeldPorts.
                        # This counts an ACTION the recorder took; zero opens
                        # attempted is a fact about behaviour, not a claim about
                        # the hardware. The distinction is the whole rule:
                        # measure-an-action fields may report 0, observe-a-state
                        # fields must report absence.
                        PortOpenAttempts = if ($btProbeSession) { [int]$btProbeSession.PortOpenAttempts } else { $null }
                        PortOpenAcquired = if ($btProbeSession) { [int]$btProbeSession.PortOpenAcquired } else { $null }
                        PortOpenDenied   = if ($btProbeSession) { [int]$btProbeSession.PortOpenDenied } else { $null }
                        # ...and for HOW LONG (#83). The counts above cannot say
                        # what share of the recording the probe spent inside a
                        # successful open of a port NO.exe was trying to take,
                        # and they cannot settle whether these opens are the tick
                        # cost -- `Update` spans several calls, so blaming them
                        # was an inference. SuccessfulOpenCallMs is an UPPER
                        # BOUND on the lock-out interval, not a measurement of
                        # it: the stopwatch spans the whole call, ownership is a
                        # subset. The report carries that in its Basis field.
                        # Null, not zero, on a run that measured none: an
                        # unmeasured observer effect must not read as an absent
                        # one. Roles are passed so DATA and COMMAND stay
                        # separable -- 12005 names the COMMAND port, and pooling
                        # the two would bury it.
                        PortOpenTiming = if ($btProbeSession -and (Get-Command Get-PortOpenTimingReport -ErrorAction SilentlyContinue)) {
                            Get-PortOpenTimingReport -Timing $btProbeSession.PortOpenTiming `
                                -RecordingSeconds $(if ($btWindow) { $btWindow.DurationSeconds } else { $null }) `
                                -PortRoles @(if ($btProbeWatch) {
                                    @(@($btProbeWatch.ComPortMatches) | Where-Object { $_.PortName } | ForEach-Object {
                                        @{ PortName = $_.PortName; Role = $_.ChannelRole }
                                    })
                                } else { @() })
                        } else { $null }
                        # Raw win32 evidence for the same opens, under its own
                        # versioned contract. SEPARATE KEY, never merged into
                        # PortOpenTiming: that one measured a System.IO.Ports
                        # call which configures DCB/baud, this measures a bare
                        # CreateFile. Same units, different work. A capture
                        # normally carries one or the other, not both.
                        PortOpenAttemptTiming = if ($btProbeSession -and $btProbeSession.SerialOpenAttempts -and (Get-Command Get-SerialOpenAttemptReport -ErrorAction SilentlyContinue)) {
                            Get-SerialOpenAttemptReport -Record $btProbeSession.SerialOpenAttempts `
                                -RecordingSeconds $(if ($btWindow) { $btWindow.DurationSeconds } else { 0 })
                        } else { $null }
                        # Read rate on BOTH scopes (#84). The read-rate channel
                        # used to be gated on the invasive port-hold test, so a
                        # 12005 -- which BY DEFINITION means NO holds no port --
                        # took no sample at all and was unscoreable by
                        # construction, not for want of evidence. PortHeld* is
                        # the window the collapse detector judges; Unscoped* is
                        # the only channel that can say anything at all about a
                        # 12005. Neither attributes a read to a port: the counter
                        # is process-wide, and Basis says so inside the capture.
                        IoReadRateScopes = if ($btProbeSession -and (Get-Command Get-IoReadRateScopes -ErrorAction SilentlyContinue)) {
                            Get-IoReadRateScopes -Samples $btProbeSession.IoSamples `
                                -DroppedCount ([int]$btProbeSession.IoSamplesDropped)
                        } else { $null }
                        # FI-012 at the top level so a ZIP can be triaged from
                        # the manifest alone -- these ZIPs are not auto-analyzed,
                        # so whoever opens one should not have to know which
                        # artifact to read to find out the box could not open a
                        # single serial port. Null on older/partial runs.
                        SerialPortIntegrityHealthy = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            [bool]($(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).Healthy)
                        } else { $null }
                        SerialPortCollisionCount = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            $(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).CollisionCount
                        } else { $null }
                        SerialPortMissingSymlinkCount = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            $(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).MissingSymlinkCount
                        } else { $null }
                        SerialPortDegradedInRun = [bool]($btProbeSession -and $btProbeSession.SerialPortIntegrity -and $btProbeSession.SerialPortIntegrityEnd -and
                                                          $btProbeSession.SerialPortIntegrity.Healthy -and -not $btProbeSession.SerialPortIntegrityEnd.Healthy)
                        SerialPortDanglingSymlinkCount = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            $(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).DanglingSymlinkCount
                        } else { $null }
                        # Passive gate evaluated before the recorder window was
                        # constructed. These fields prove that a package started
                        # from a verified namespace and, when power events were
                        # readable, that the verification followed the last wake.
                        SerialPortPreflightStatus = if ($btProbeSession -and $btProbeSession.SerialPortPreflight) {
                            $btProbeSession.SerialPortPreflight.Status
                        } else { $null }
                        SerialPortPreflightCheckedAt = if ($btProbeSession -and $btProbeSession.SerialPortPreflight) {
                            $btProbeSession.SerialPortPreflight.CheckedAt
                        } else { $null }
                        SerialPortPreflightWakeObserved = if ($btProbeSession -and $btProbeSession.SerialPortPreflight) {
                            $btProbeSession.SerialPortPreflight.WakeObservedSinceBoot
                        } else { $null }
                        SerialPortPreflightVerifiedAfterLastResume = if ($btProbeSession -and $btProbeSession.SerialPortPreflight) {
                            $btProbeSession.SerialPortPreflight.VerifiedAfterLastResume
                        } else { $null }
                        # Which FI-012 fault, and how strongly. 'DeviceNotLinked'
                        # is Suspected by construction -- confirming it needs an
                        # open attempt, which never runs during a recording.
                        SerialFault           = if ($btProbeSession -and $btProbeSession.SerialFaultFingerprint) { $btProbeSession.SerialFaultFingerprint.Fault } else { $null }
                        SerialFaultConfidence = if ($btProbeSession -and $btProbeSession.SerialFaultFingerprint) { $btProbeSession.SerialFaultFingerprint.Confidence } else { $null }
                        # Tests the FI-012 sleep/resume hypothesis on this box.
                        # 'Unexplained' means resumes do not account for the
                        # extra registrations and the story is incomplete.
                        SerialRegistrationCorrelation = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            $c = $(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).Correlation
                            if ($c) { $c.Assessment } else { $null }
                        } else { $null }
                        SerialResumeCountSinceBoot = if ($btProbeSession -and $btProbeSession.SerialPortIntegrity) {
                            $p = $(if ($btProbeSession.SerialPortIntegrityEnd) { $btProbeSession.SerialPortIntegrityEnd } else { $btProbeSession.SerialPortIntegrity }).PowerContext
                            if ($p) { $p.ResumeCount } else { $null }
                        } else { $null }
                        # Port held with no data moving through it. The recorder
                        # could not express this before: any held handle read as
                        # "EEG streaming: Active", so a stalled Arc uploaded as a
                        # clean session (field case 2026-07-30).
                        PortHeldWithoutDataFlow = [bool]($btProbeSession -and $btProbeSession.StreamCpuStalled)
                        # Read-rate collapse: the signal for a fault where the
                        # transport is clean end to end and only NO.exe's serial
                        # path dies (field capture 2026-07-30, NO code 12006).
                        # ReadRateVerdict must be read alongside it -- 'NoBaseline'
                        # means data flow was NOT assessed, not that it was fine.
                        ReadRateCollapsed = [bool]($btProbeSession -and $btProbeSession.IoStalled)
                        ReadRateVerdict = if ($btProbeSession) { $btProbeSession.IoVerdict } else { $null }
                        ReadRateBaselineOpsPerSecond = if ($btProbeSession) { $btProbeSession.IoBaselineOpsPerSecond } else { $null }
                        ReadRateRecentOpsPerSecond = if ($btProbeSession) { $btProbeSession.IoRecentOpsPerSecond } else { $null }
                        # Percent of the session's own baseline, so triage can
                        # rank severity from the manifest alone.
                        ReadRateFractionOfBaseline = if ($btProbeSession) { $btProbeSession.IoFractionOfBaseline } else { $null }
                        # Dips that recovered. A collapse that never completes is
                        # invisible in ReadRateCollapsed but is exactly what an
                        # intermittent Arc produces, so it gets its own counter.
                        # SECONDS, and the key says so (#86). Leaving the old
                        # ...DegradedTicks name on a seconds value would be worse
                        # than either unit on its own: the field name is the ONLY
                        # thing telling a reader which unit a capture is in, since
                        # the manifest carries no build id.
                        ReadRateDegradedSeconds = if ($btProbeSession) { [math]::Round([double]$btProbeSession.IoDegradedSeconds, 1) } else { $null }
                        # Read from the RECORD, not the session. This field and
                        # ReadRateWorstRecentOpsPerSecond below are two halves of one
                        # observation; sourcing them from two objects is how capture
                        # E0C8B0588CC7 shipped a worst fraction of 0% beside a worst
                        # rate of null (issue #65). The record chooses both together.
                        ReadRateWorstFractionOfBaseline = if ($btIoRecord) { $btIoRecord.WorstFractionOfBaseline } else { $null }
                        # ── Session-long read-rate record ────────────────────
                        # Every field above describes the LAST port-open episode
                        # only, because NO.exe re-opening the port resets the live
                        # measurement. Capture C0AE9604CDAC (Arc 000013) measured
                        # a 776 ops/tick baseline collapse to 1%, was marked by
                        # the operator against 12006 -- and reported
                        # ReadRateVerdict 'NoBaseline' with baseline 0, so the
                        # dashboard counted it as data flow UNMEASURED.
                        #
                        # These answer "did it ever collapse", which is the
                        # question a bundle is read to answer.
                        ReadRateEverCollapsed = if ($btIoRecord) { [bool]$btIoRecord.EverCollapsed } else { $null }
                        ReadRateCollapseEpisodes = if ($btIoRecord) { [int]$btIoRecord.CollapseEpisodes } else { $null }
                        # The marker channel, counted separately from the episode
                        # ledger. An operator marker samples the INSTANT the fault
                        # was on screen; the ledger evaluates a trailing window and
                        # can legitimately miss what the marker caught. Both counts
                        # are published so a reader can see which one saw it.
                        ReadRateMarkerCollapseCount = if ($btIoRecord) { [int]$btIoRecord.MarkerCollapseCount } else { $null }
                        ReadRateCollapseObservedBy = if ($btIoRecord) { $btIoRecord.CollapseObservedBy } else { $null }
                        # A baseline WAS announced and the ledger no longer holds
                        # one -- so the collapse fields describe a question that
                        # was not assessed, not an answer of "no". An unbounded
                        # recording window is what destroys it: idle ticks drag
                        # the trailing median under the floor (capture
                        # 31D0729CA5B8, 15.4 h of idle after a 33-min session).
                        ReadRateBaselineLostAfterAnnouncement = if ($btIoRecord) { [bool]$btIoRecord.BaselineLostAfterAnnouncement } else { $null }
                        ReadRateIdleTailSeconds = if ($btIoRecord) { $btIoRecord.IdleTailSeconds } else { $null }
                        # >0 means 'NoBaseline' at the end can mean "thrown away",
                        # not "never found". Without it the two are identical in
                        # the record and only one of them is benign.
                        ReadRateBaselineResetCount = if ($btIoRecord) { [int]$btIoRecord.BaselineResetCount } else { $null }
                        ReadRatePeakBaselineOpsPerSecond = if ($btIoRecord) { [double]$btIoRecord.PeakBaselineOpsPerSecond } else { $null }
                        ReadRateWorstRecentOpsPerSecond = if ($btIoRecord) { $btIoRecord.WorstRecentOpsPerSecond } else { $null }
                        ReadRateEpisodeCount = if ($btIoRecord) { [int]$btIoRecord.EpisodeCount } else { $null }
                        # #85: an episode is a Stopped -> Active EPOCH, not one
                        # port-handle lifetime. >0 means at least one episode's
                        # baseline spans more than one handle, so any per-handle
                        # reading of the episode ledger is over-precise. Absent
                        # on pre-#85 captures, which is NOT the same as 0 -- those
                        # runs could not tell either way.
                        ReadRateHandleChangeCount = if ($btIoRecord) { [int]$btIoRecord.HandleChangeCount } else { $null }
                        # #87: markers that fall INSIDE an episode which
                        # collapsed, joined on the EpisodeId the marker recorded
                        # at the time. Deliberately a different claim from
                        # ReadRateMarkerCollapseCount, which counts markers whose
                        # OWN verdict was Collapsed -- DB98B6EE3324 had six
                        # markers stamped 'NoBaseline' sitting inside an episode
                        # that ended Collapsed at 7%, and reporting only the
                        # first made the corpus pattern look broken when it was
                        # the marker channel that was blind.
                        ReadRateMarkerInCollapsedEpisodeCount = if ($btIoRecord) { [int]$btIoRecord.MarkerInCollapsedEpisodeCount } else { $null }
                        # events.jsonl accounting (#87). A timeline with holes
                        # that reads as complete is the same class of lie as an
                        # unmeasured zero rendered as 0, so the drops are
                        # reported rather than left to be inferred from a line
                        # count nobody can check against anything.
                        EventTimelineLinesWritten = [int]$script:BtRec_EventLinesWritten
                        EventTimelineLinesDropped = [int]$script:BtRec_EventLinesDropped
                        # chain.jsonl accounting, for the same reason. Zero
                        # DiagnosticChainLinesWritten on a completed run means the
                        # boundary was never recorded -- a capture that cannot be
                        # scored for what the recorder believed was broken.
                        DiagnosticChainLinesWritten = [int]$script:BtChain_LinesWritten
                        DiagnosticChainLinesDropped = [int]$script:BtChain_LinesDropped
                        # ── The session-level answer ─────────────────────────
                        # Collapsed | Degraded | Stable | Unassessed, derived once
                        # in Get-IoSessionReadRateRecord and shared with the
                        # findings so the bundle and the printed summary cannot
                        # disagree.
                        #
                        # ReadRateVerdict above is the LAST TICK's instantaneous
                        # state and is kept for operator markers, where it is the
                        # right thing. It is NOT a session verdict: on capture
                        # 91C5F8EB3E3F a clean 33-minute run ended 'Degrading'
                        # purely because the trailing window straddled port
                        # teardown, and the dashboard badged it as degraded next
                        # to a genuine collapse.
                        ReadRateSessionOutcome = if ($btIoRecord) { [string]$btIoRecord.Outcome } else { $null }
                        ReadRateMeaningfullyDegraded = if ($btIoRecord) { [bool]$btIoRecord.MeaningfullyDegraded } else { $null }
                        ReadRateBaselineEstablished = if ($btIoRecord) { [bool]$btIoRecord.BaselineEstablished } else { $null }
                        # ── Observation coverage: category AND duration ──────
                        # Two separate claims, kept separate. Level says whether
                        # every channel was seen; Quality says for how long.
                        # Captures B9F9F0EE5E21 (~17s of measurement) and
                        # 91C5F8EB3E3F (~32 min) both score Observed and are not
                        # the same evidence. The raw seconds are exported too, so
                        # a consumer can apply its own bar instead of inheriting
                        # this one.
                        ObservationCoverageLevel = if ($btCoverage) { [string]$btCoverage.Level } else { $null }
                        ObservationQuality = if ($btCoverage) { [string]$btCoverage.Quality } else { $null }
                        # Whether there was a measured window at all, as a fact
                        # rather than a clause inside ObservationSummary. The
                        # summary sentence used to claim "data flow was
                        # measured" off IoSampleCount > 0, which says samples
                        # were COLLECTED, not that they were usable -- capture
                        # 236061907514 shipped that sentence beside
                        # ObservationQuality 'None' and findings saying data
                        # flow was NOT assessed (issue #77). Null before #77.
                        ObservationDataFlowMeasured = if ($btCoverage) { [bool]$btCoverage.DataFlowMeasured } else { $null }
                        ObservationSeconds = if ($btCoverage) { $btCoverage.ObservationSeconds } else { $null }
                        ObservationTickCount = if ($btCoverage) { [int]$btCoverage.TickCount } else { $null }
                        # SESSION TOTAL since #88. It used to be the current
                        # episode's delta buffer, which is cleared on every port
                        # re-open: DB98B6EE3324 shipped 7 beside a baseline of
                        # 176, a peak of 297 and two resets, when a verdict needs
                        # 9 deltas to exist -- arithmetically impossible as a
                        # total. Worse, Coverage.Level keys off it, so a run
                        # whose port re-opened on its last tick could report a
                        # measured session as 'NotObserved'.
                        ObservationIoSampleCount = if ($btCoverage) { [int]$btCoverage.IoSampleCount } else { $null }
                        # The current-episode buffer, named for what it is: the
                        # answer to "could a verdict be reached right now".
                        ObservationIoSampleCountCurrentEpisode = if ($btCoverage) { [int]$btCoverage.IoSampleCountCurrentEpisode } else { $null }
                        # CURRENT vs EVER as separate fields (#88). HeldPorts was
                        # last-tick-only while UnavailablePorts was a session
                        # union, and joining those two without noticing the
                        # asymmetry is exactly what produced #81's false
                        # "port will not open".
                        HeldPortsCurrent      = if ($btProbeSession) { @($btProbeSession.HeldPorts | Where-Object { $_ }) } else { @() }
                        HeldPortsEver         = if ($btProbeSession) { @($btProbeSession.HeldPortsEver | Where-Object { $_ }) } else { @() }
                        UnavailablePortsCurrent = if ($btProbeSession) { @($btProbeSession.UnavailablePortsCurrent | Where-Object { $_ }) } else { @() }
                        UnavailablePortsEver    = if ($btProbeSession) { @($btProbeSession.UnavailablePortsEver | Where-Object { $_ }) } else { @() }
                        UnavailableAfterHeldPortsCurrent = if ($btProbeSession) { @($btProbeSession.UnavailableAfterHeldPortsCurrent | Where-Object { $_ }) } else { @() }
                        UnavailableAfterHeldPorts = if ($btProbeSession) { @($btProbeSession.UnavailableAfterHeldPorts | Where-Object { $_ }) } else { @() }
                        SecondsToReadBaseline = if ($btCoverage) { $btCoverage.SecondsToReadBaseline } else { $null }
                        PostBaselineObservationSeconds = if ($btCoverage) { $btCoverage.PostBaselineSeconds } else { $null }
                        # When the recorder told the operator a read baseline
                        # existed, and at what rate. The live STREAM/ReadBaseline
                        # event scrolls past and is not written to
                        # probe-session.json, so before this a bundle could not
                        # say whether data flow was ever measurable -- capture
                        # D8EE48E60DF2 (2026-08-01) had to be confirmed by asking
                        # the operator what they remembered seeing.
                        #
                        # Two independent readings, both useful:
                        #   FIELD ABSENT  -> pre-1.5.0 recorder build. Another
                        #                    manifest sentinel, like ReadRateVerdict.
                        #   FIELD null    -> this build, but no baseline was EVER
                        #                    established. Data flow was never
                        #                    assessed; do not read it as healthy.
                        # The announced rate is kept separately from
                        # ReadRateBaselineOpsPerSecond because the baseline is a
                        # running median -- what the operator saw is not
                        # necessarily what the run ended on.
                        ReadBaselineAnnouncedAtUtc = if ($btProbeSession -and $btProbeSession.IoBaselineAnnouncedAt) {
                            ([datetime]$btProbeSession.IoBaselineAnnouncedAt).ToUniversalTime().ToString('o')
                        } else { $null }
                        ReadBaselineAnnouncedOpsPerSecond = if ($btProbeSession) { $btProbeSession.IoBaselineAnnouncedOpsPerSecond } else { $null }
                        # Ports registered in SERIALCOMM that would not open. The
                        # old bool port test folded these in with "free".
                        UnopenablePortCount = if ($btProbeSession) { @($btProbeSession.UnavailablePorts | Where-Object { $_ }).Count } else { $null }
                        # The ordered subset that can actually support "worked,
                        # then stopped opening" (#81).  UnopenablePortCount is
                        # retained as the lossless ever-observed count.
                        UnavailableAfterHeldPortCount = if ($btProbeSession) { @($btProbeSession.UnavailableAfterHeldPorts | Where-Object { $_ }).Count } else { $null }
                        # Contradictions present before recording started -- the
                        # transition-driven alarms are blind to these by design.
                        ArrivalContradictionCount = if ($btProbeSession) { @($btProbeSession.StartupConsistency).Count } else { $null }
                        # Operator-labelled moments. The NO codes let triage group
                        # recordings by what the application actually said, which
                        # is the axis the code mapping needs and the one the
                        # recorder could not report before.
                        OperatorMarkerCount = if ($btProbeSession) { @($btProbeSession.OperatorMarkers).Count } else { $null }
                        # The @( ) around the WHOLE if-expression is load-bearing.
                        # Without it a single-element result unrolls to a bare
                        # string on assignment and ConvertTo-Json emits
                        # "OperatorMarkedNoCodes": "12006" instead of ["12006"] --
                        # which is what shipped, and what every consumer that
                        # iterates the field then reads one character at a time.
                        # Casting to [string[]] does NOT help; only the wrap does.
                        OperatorMarkedNoCodes = @(if ($btProbeSession) {
                            @(@($btProbeSession.OperatorMarkers) | ForEach-Object { $_.NoCode } | Where-Object { $_ } | Select-Object -Unique)
                        } else { @() })
                        # The read-rate state AT each marked instant. This is the
                        # axis the code mapping actually needs: it separates a
                        # 12006 raised over a dead read path from a 12006 raised
                        # while data was still flowing, which are different faults
                        # wearing the same dialog.
                        OperatorMarkerIoVerdicts = @(if ($btProbeSession) {
                            @(@($btProbeSession.OperatorMarkers) | ForEach-Object { $_.IoVerdict } | Where-Object { $_ })
                        } else { @() })
                        # Markers whose moment had corroborating read-path evidence.
                        OperatorMarkersWithIoFault = if ($btProbeSession) {
                            @(@($btProbeSession.OperatorMarkers) | Where-Object { $_.IoVerdict -eq 'Collapsed' -or $_.IoVerdict -eq 'Degrading' }).Count
                        } else { $null }
                        # Markers whose cross-check produced at least one
                        # contradiction -- a labelled moment the probe could
                        # independently corroborate, the highest-value sample there is.
                        OperatorMarkersWithContradiction = if ($btProbeSession) {
                            @(@($btProbeSession.OperatorMarkers) | Where-Object { @($_.Contradictions).Count -gt 0 }).Count
                        } else { $null }
                    }
                    Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'manifest.json' -Depth 10 -Data $manifest
                } catch { }
            }

            # Package
            $btZipPath   = $null
            $btZipFolder = $safeModel
            if ($btDiagRun -and (Get-Command Compress-WinConfigDiagnosticRun -ErrorAction SilentlyContinue)) {
                try {
                    $btZipLabel = "${safeModel}_${safeHost}_$([datetime]::UtcNow.ToString('yyyyMMdd'))"
                    Write-BtLog "Packaging diagnostic artifacts..."
                    $pkg       = Compress-WinConfigDiagnosticRun -RunFolder $btDiagRun.RunFolder -ExportsRoot $btDiagRun.ExportsRoot -Label $btZipLabel
                    $btZipPath = $pkg.ZipPath
                    $sizeKb    = [Math]::Round($pkg.SizeBytes / 1024, 1)
                    Write-BtLog "Package ready: $btZipPath ($sizeKb KB)"

                    # Let the operator open the folder holding the package.
                    $btOpenFolderBtn.Tag     = Split-Path $btZipPath -Parent
                    $btOpenFolderBtn.Visible = $true
                } catch {
                    Write-BtLog "Packaging failed: $($_.Exception.Message)" -Level "WARN"
                }
            }

            # Upload — the banner at the end reflects the ACTUAL outcome, in plain language.
            # Default to a FAILURE state; only a genuine success/handled path upgrades it,
            # so a packaging failure can never fall through to a false "all good" banner.
            $btOutcomeLevel = 'fail'
            $btOutcomeMsg   = "Results were captured, but the package could not be created on this PC. Please run the diagnostics again."

            if (-not $btZipPath) {
                # Packaging failed or was unavailable — there is nothing to send.
                Write-BtLog "Could not create the diagnostic package - there is nothing to send." -Level "FAIL"
                $btUploadLabel.Text = "FAILED - package not created"
            }
            elseif (Get-Command Get-WinConfigDiagnosticsUploadConfig -ErrorAction SilentlyContinue) {
                $uploadConfig = Get-WinConfigDiagnosticsUploadConfig
                Write-BtLog "Sending results to support..."
                $btUploadLabel.Text = "Upload: Sending..."
                $btForm.Refresh()
                $runIdForMeta = if ($btDiagRun) { $btDiagRun.RunId } else { "" }
                $uploadResult = Send-WinConfigDiagnosticPackage -PackagePath $btZipPath -Config $uploadConfig -Metadata @{ RunId = $runIdForMeta } -FolderPrefix $btZipFolder

                switch ($uploadResult.Status) {
                    'Uploaded' {
                        if ($uploadResult.Provider -eq 'R2') {
                            Write-BtLog "Sent to support successfully." -Level "OK"
                            $btUploadLabel.Text = "Upload: Sent to support OK"
                            $btOutcomeLevel = 'success'
                            $btOutcomeMsg   = "Done - your Bluetooth results were captured and sent to support. You can close this window."
                        } else {
                            Write-BtLog "Saved on this PC: $($uploadResult.RemotePath)" -Level "OK"
                            $btUploadLabel.Text    = "Saved on this PC"
                            $btLocalPathLabel.Text = "File: $($uploadResult.RemotePath)"
                            $btOutcomeLevel = 'success'
                            $btOutcomeMsg   = "Done - your Bluetooth results were saved on this PC. You can close this window."
                        }
                    }
                    'LocalOnly' {
                        # Cloud upload failed; the file is on this PC only. Make this loud and clear.
                        $localFolder = Split-Path $uploadResult.RemotePath -Parent
                        $btOpenFolderBtn.Tag     = $localFolder
                        $btOpenFolderBtn.Visible = $true
                        $btLocalPathLabel.Text   = "File on this PC: $($uploadResult.RemotePath)"
                        Write-BtLog "Could NOT send the results to support (no connection or upload error)." -Level "WARN"
                        Write-BtLog "The file was saved on this PC instead: $($uploadResult.RemotePath)" -Level "WARN"
                        Write-BtLog "Please click 'Open Folder' and send that file to support, or run the diagnostics again later." -Level "WARN"
                        $btUploadLabel.Text = "NOT sent - saved on this PC only (click 'Open Folder')"
                        $btOutcomeLevel = 'warn'
                        $btOutcomeMsg   = "Results captured OK, but they could NOT be sent to support. The file is saved on this PC - click 'Open Folder' and send it to support."
                    }
                    'Skipped' {
                        # Uploads disabled — the packaged file is on this PC; point the operator at it.
                        $btLocalPathLabel.Text = "File on this PC: $btZipPath"
                        Write-BtLog "Sending is turned off on this PC - the file was kept on this PC: $btZipPath" -Level "WARN"
                        $btUploadLabel.Text = "Sending disabled - kept on this PC (click 'Open Folder')"
                        $btOutcomeLevel = 'warn'
                        $btOutcomeMsg   = "Results captured OK. Sending is turned off on this PC, so the file was kept here - click 'Open Folder' to find it."
                    }
                    default {
                        # Failed - the package did not survive anywhere.
                        Write-BtLog "Could not save the results: $($uploadResult.Error)" -Level "FAIL"
                        $btUploadLabel.Text = "FAILED - $($uploadResult.Error)"
                        $btOutcomeLevel = 'fail'
                        $btOutcomeMsg   = "Something went wrong saving the results: $($uploadResult.Error). Please run the diagnostics again."
                    }
                }
            }
            else {
                # Packaged, but the upload component isn't loaded — the ZIP is on disk only.
                Write-BtLog "Results packaged but the upload component is unavailable - the file is on this PC: $btZipPath" -Level "WARN"
                $btUploadLabel.Text    = "Saved on this PC - not sent (click 'Open Folder')"
                $btLocalPathLabel.Text = "File: $btZipPath"
                $btOutcomeLevel = 'warn'
                $btOutcomeMsg   = "Results captured and saved on this PC, but they could not be sent automatically. Click 'Open Folder' and send the file to support."
            }

            # ── ONE OUTCOME, WRITTEN TO EVERY PLACE THAT SHOWS IT ─────────────
            # Banner colour, banner text, the header phase and the status line
            # are set together from the SAME $btOutcomeLevel, in one switch. They
            # used to be set in three places: the header was left on "Packaging"
            # from before the upload started, and the status line said "Complete."
            # whatever happened -- so a failed upload could read as finished and a
            # successful one could read as still running. A phase word and an
            # outcome sentence that disagree is the same defect class as two
            # panels disagreeing about a reading; the fix is the same, which is
            # to have one answerer.
            #
            # Nothing about packaging or uploading itself changed here. This is
            # the representation of an outcome that was already decided above.
            switch ($btOutcomeLevel) {
                'warn' {
                    $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(70, 55, 10)
                    $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(250, 225, 150)
                    # Complete, and NOT sent. The package exists, so the run did
                    # finish -- but a header that said only "Complete" beside a
                    # banner explaining the file is stranded on this PC would let
                    # the reader take the good half.
                    $btTimerLabel.Text       = "Not sent"
                    $btTimerLabel.ForeColor  = [System.Drawing.Color]::FromArgb(250, 225, 150)
                    $btElapsedLabel.Text     = "Finished - results were NOT sent to support."
                }
                'fail' {
                    $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(70, 20, 20)
                    $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(250, 170, 170)
                    $btTimerLabel.Text       = "Failed"
                    $btTimerLabel.ForeColor  = [System.Drawing.Color]::FromArgb(250, 170, 170)
                    $btElapsedLabel.Text     = "Finished - the results could not be saved."
                }
                default {
                    $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(20, 65, 25)
                    $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(160, 240, 160)
                    $btTimerLabel.Text       = "Complete"
                    $btTimerLabel.ForeColor  = [System.Drawing.Color]::FromArgb(160, 240, 160)
                    $btElapsedLabel.Text     = "Complete."
                }
            }
            $btBannerLabel.Text  = $btOutcomeMsg

            if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

            } finally {
                # Always release the recorder lock -- every exit path (Stop, Abort,
                # early returns, exceptions) must re-enable 'Run Bluetooth
                # Diagnostics' and stop routing repair-tool clicks to this session.
                $script:BtRecordingActive = $false
            }
        }

        # =========================================================================
        # BLUETOOTH RESET TOOLS (Mutating - Dry Run supported)
        # =========================================================================
        "Reset COM Port Numbers" = {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Reset COM Port Numbers requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            $arbiterPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
            $regExportPath = 'HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'

            $comDb = $null
            try { $comDb = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB } catch {}

            if (-not $comDb) {
                [System.Windows.Forms.MessageBox]::Show("COM Name Arbiter ComDB is already clean -- no action needed.", "No Action Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                return
            }

            $backupDir = Join-Path $env:ProgramData "WinConfig\BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $backupPath = Join-Path $backupDir "ComArbiter-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

            try {
                # SAFETY: verify the backup actually wrote BEFORE deleting anything.
                & reg export $regExportPath $backupPath /y 2>&1 | Out-Null
                $bk = Get-Item $backupPath -ErrorAction SilentlyContinue
                if ($LASTEXITCODE -ne 0 -or -not $bk -or $bk.Length -le 0) {
                    throw "Backup failed (reg export did not produce a non-empty $backupPath) - aborting before any change was made."
                }

                Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop

                # VERIFY: re-read to confirm the change actually took effect.
                $comDbAfter = $null
                try { $comDbAfter = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB } catch {}
                if ($comDbAfter) {
                    throw "ComDB is still present after the reset - the change did not take effect."
                }

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT COM Port Reset" -Detail "ComDB cleared and verified absent; backup at $backupPath" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "PASS" -Tier 2 -Summary "COM arbiter reset"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                # NO CAUSAL PROMISE HERE. This previously predicted the specific
                # low COM numbers the next pairing would be assigned -- never
                # measured, and not guaranteed by the change: ComDB is an
                # allocation BITMAP of reserved names, and clearing it does not
                # decide what the next pairing receives. Say what was changed,
                # not what is predicted to follow. The retracted sentence is
                # quoted only in tests/BluetoothGhostPortPlan.Tests.ps1, so the
                # regression guard there can stay a plain literal scan.
                [System.Windows.Forms.MessageBox]::Show("COM Name Arbiter has been reset.`n`nThe global COM-name reservation bitmap was cleared. This frees the reserved names; it does NOT choose which COM number the next pairing receives, and it does not repair COM symlinks, existing port assignments, or pairing state.`n`nBackup saved to:`n$backupPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT COM Port Reset" -Detail "Reset failed: $($_.Exception.Message)" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "FAIL" -Tier 3 -Summary "COM arbiter reset failed"
                }
                [System.Windows.Forms.MessageBox]::Show("COM port reset failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        "Clean Bluetooth Ports" = {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Clean Bluetooth Ports requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            # ONE answerer for the removal set, shared with the Dry Run planner.
            $ghostPorts = @()
            try {
                $ghostPorts = @((Get-BtGhostPortPlanOrThrow).Targets)
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to enumerate Bluetooth ports: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }

            $arbiterPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
            $regExportPath = 'HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
            $hasComDb = $false
            try { $hasComDb = $null -ne (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB } catch {}

            if ($ghostPorts.Count -eq 0 -and -not $hasComDb) {
                [System.Windows.Forms.MessageBox]::Show("No ghost Bluetooth ports or COM allocations found -- no action needed.", "No Action Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                return
            }

            # The confirm dialog IS the operator's preview on the live path, so it
            # states the same scope the Dry Run plan does -- including WHY each
            # node is a target. A bare count let an operator approve "1 port" and
            # get three removed.
            $ghostBreakdown = @($ghostPorts | ForEach-Object { "  - $($_.InstanceId) [$($_.Reason)]" }) -join "`n"
            $comDbLine = if ($hasComDb) {
                "`n`nIt will ALSO clear the global COM-name reservation bitmap (ComDB). That bitmap is not Bluetooth-specific: it covers every serial device on this PC, including non-Bluetooth hardware."
            } else { '' }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "This will remove $($ghostPorts.Count) Bluetooth port device node(s):`n`n$ghostBreakdown$comDbLine`n`nRemoving a port node is not the same as unpairing, and Windows may need a reboot to finish. This does NOT repair a headset whose port nodes are still present and healthy.`n`nContinue?",
                "Confirm Bluetooth Port Cleanup",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            $backupDir = Join-Path $env:ProgramData "WinConfig\BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $backupPath = Join-Path $backupDir "ComArbiter-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

            try {
                # SAFETY: verify the COM-arbiter backup wrote BEFORE removing anything.
                & reg export $regExportPath $backupPath /y 2>&1 | Out-Null
                $bk = Get-Item $backupPath -ErrorAction SilentlyContinue
                if ($LASTEXITCODE -ne 0 -or -not $bk -or $bk.Length -le 0) {
                    throw "Backup failed (reg export did not produce a non-empty $backupPath) - aborting before any change was made."
                }

                $removed = 0
                $failed = 0
                foreach ($ghost in $ghostPorts) {
                    $result = & pnputil /remove-device $ghost.InstanceId 2>&1
                    if ($LASTEXITCODE -eq 0) { $removed++ } else { $failed++ }
                }

                if ($hasComDb) {
                    Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop
                }

                # VERIFY: re-read state to confirm the cleanup actually took effect.
                $verifyNotes = @()
                if ($hasComDb) {
                    $comDbAfter = $null
                    try { $comDbAfter = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB } catch {}
                    if ($comDbAfter) { $verifyNotes += "ComDB still present" }
                }
                # Post-check reads the SAME plan the removal did: a narrower
                # re-query here would report success for nodes still present.
                #
                # A FAILED re-enumeration is not zero remaining ghosts. Swallowing
                # it left $ghostsAfter empty, which added no verify note, which
                # made the result PASS -- reporting a verified cleanup when the
                # verification never ran. An absent measurement renders as absent.
                $ghostsAfter = @()
                $ghostVerifyError = $null
                try {
                    $ghostsAfter = @((Get-BtGhostPortPlanOrThrow).Targets)
                } catch {
                    $ghostVerifyError = $_.Exception.Message
                }
                if ($ghostVerifyError) {
                    $verifyNotes += "remaining ghost ports NOT checked (re-enumeration failed: $ghostVerifyError)"
                } elseif ($ghostsAfter.Count -gt 0) {
                    $verifyNotes += "$($ghostsAfter.Count) ghost port(s) still present (a reboot may be required)"
                }

                $summary = "$removed ghost port(s) removed"
                if ($failed -gt 0) { $summary += ", $failed failed" }
                if ($hasComDb) { $summary += ", COM arbiter reset" }
                if ($verifyNotes.Count -gt 0) { $summary += " -- NOT fully verified: " + ($verifyNotes -join '; ') }

                $cleanResult = if ($failed -gt 0 -or $verifyNotes.Count -gt 0) { "WARN" } else { "PASS" }
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Port Cleanup" -Detail "$summary; backup at $backupPath" -Category "AdminChange" -ToolCategory "Bluetooth" -Result $cleanResult -Tier 2 -Summary $summary
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show("Bluetooth port cleanup complete.`n`n$summary`n`nBackup saved to:`n$backupPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Port Cleanup" -Detail "Cleanup failed: $($_.Exception.Message)" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "FAIL" -Tier 3 -Summary "Bluetooth port cleanup failed"
                }
                [System.Windows.Forms.MessageBox]::Show("Bluetooth port cleanup failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        "Full Bluetooth Stack Reset" = {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Full Bluetooth Stack Reset requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "WARNING: This will wipe ALL Bluetooth pairing data.`n`n" +
                "- All paired Bluetooth devices will be removed`n" +
                "- All local Bluetooth services will be cleared`n" +
                "- Ghost port entries will be removed`n" +
                "- COM port assignments will be reset`n`n" +
                "A system REBOOT is required after this operation.`n" +
                "ALL Bluetooth devices will need to be re-paired.`n`n" +
                "Continue?",
                "Confirm Full Bluetooth Stack Reset",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            $devicesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
            $localSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\LocalServices'
            $arbiterPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'

            $backupDir = Join-Path $env:ProgramData "WinConfig\BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

            try {
                # SAFETY: this is a Tier-4 wipe of ALL pairing data. Verify BOTH backups
                # actually wrote before deleting anything; abort if either failed.
                $bthportBackup = Join-Path $backupDir "BTHPORT-$timestamp.reg"
                $arbiterBackup = Join-Path $backupDir "ComArbiter-$timestamp.reg"
                & reg export 'HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters' $bthportBackup /y 2>&1 | Out-Null
                $bthItem = Get-Item $bthportBackup -ErrorAction SilentlyContinue
                $bthOk = ($LASTEXITCODE -eq 0 -and $bthItem -and $bthItem.Length -gt 0)
                & reg export 'HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter' $arbiterBackup /y 2>&1 | Out-Null
                $arbItem = Get-Item $arbiterBackup -ErrorAction SilentlyContinue
                $arbOk = ($LASTEXITCODE -eq 0 -and $arbItem -and $arbItem.Length -gt 0)
                if (-not $bthOk -or -not $arbOk) {
                    throw "Backup verification failed (BTHPORT ok=$bthOk, ComArbiter ok=$arbOk) - aborting the stack reset BEFORE deleting anything, so no pairing data is lost."
                }

                $devicesRemoved = 0
                $servicesRemoved = 0
                $ghostsRemoved = 0
                $stackNotes = @()

                if (Test-Path $devicesPath) {
                    $devSubkeys = Get-ChildItem $devicesPath -ErrorAction SilentlyContinue
                    foreach ($dev in $devSubkeys) {
                        Remove-Item $dev.PSPath -Recurse -Force -ErrorAction Stop
                        $devicesRemoved++
                    }
                }

                if (Test-Path $localSvcPath) {
                    $svcSubkeys = Get-ChildItem $localSvcPath -ErrorAction SilentlyContinue
                    foreach ($svc in $svcSubkeys) {
                        Remove-Item $svc.PSPath -Recurse -Force -ErrorAction Stop
                        $servicesRemoved++
                    }
                }

                # Ghost-port and ComDB removal: capture errors rather than swallowing them,
                # so a silent no-op can't be reported as a clean reset.
                try {
                    $ghostPorts = @((Get-BtGhostPortPlanOrThrow).Targets)
                    foreach ($ghost in $ghostPorts) {
                        & pnputil /remove-device $ghost.InstanceId 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) { $ghostsRemoved++ } else { $stackNotes += "ghost removal returned exit $LASTEXITCODE" }
                    }
                } catch { $stackNotes += "ghost enumeration/removal error: $($_.Exception.Message)" }

                try { Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop } catch { $stackNotes += "ComDB clear error: $($_.Exception.Message)" }

                # VERIFY: confirm the pairing database and COM arbiter are actually empty.
                $devLeft = if (Test-Path $devicesPath) { @(Get-ChildItem $devicesPath -ErrorAction SilentlyContinue).Count } else { 0 }
                $svcLeft = if (Test-Path $localSvcPath) { @(Get-ChildItem $localSvcPath -ErrorAction SilentlyContinue).Count } else { 0 }
                $comDbAfter = $null
                try { $comDbAfter = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB } catch {}
                if ($devLeft -gt 0)  { $stackNotes += "$devLeft device key(s) still present" }
                if ($svcLeft -gt 0)  { $stackNotes += "$svcLeft local-service key(s) still present" }
                if ($comDbAfter)     { $stackNotes += "ComDB still present" }

                $summary = "$devicesRemoved paired device(s), $servicesRemoved service(s), $ghostsRemoved ghost port(s) removed, COM arbiter reset"
                if ($stackNotes.Count -gt 0) { $summary += " -- WARNINGS: " + ($stackNotes -join '; ') }

                # The reset isn't complete until the user reboots, so this is recorded as
                # WARN ("reboot required"), never a plain PASS that reads as "already fixed".
                $detail = "$summary; REBOOT REQUIRED to finish; backups at $backupDir"
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Stack Reset" -Detail $detail -Category "AdminChange" -ToolCategory "Bluetooth" -Result "WARN" -Tier 4 -Summary "BT stack reset - REBOOT REQUIRED"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show(
                    "Bluetooth stack reset applied.`n`n$summary`n`nBackups saved to:`n$backupDir`n`nThe reset is NOT finished until you REBOOT. Please reboot your computer now.",
                    "Reboot Required",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Stack Reset" -Detail "Reset failed: $($_.Exception.Message)" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "FAIL" -Tier 4 -Summary "BT stack reset failed"
                }
                [System.Windows.Forms.MessageBox]::Show("Bluetooth stack reset failed: $($_.Exception.Message)`n`nPartial changes may have been made. Backups are at:`n$backupDir", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

        "Disable USB Suspend" = {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                [System.Windows.Forms.MessageBox]::Show("Disable USB Suspend requires Administrator privileges.`n`nPlease restart WinConfig as Administrator.", "Elevation Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            try {
                $usbSubGuid  = '2a737441-1930-4402-8d77-b2bebba308a3'
                $usbSuspGuid = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'

                # ── Layer A: global power-plan USB selective suspend, ALL schemes ──
                # (Was SCHEME_CURRENT only, so switching power plans re-enabled it.)
                $schemeGuids = @()
                try {
                    foreach ($l in (powercfg /list)) {
                        if ($l -match 'Power Scheme GUID:\s*([0-9a-fA-F-]{36})') { $schemeGuids += $Matches[1] }
                    }
                } catch {}
                if ($schemeGuids.Count -eq 0) { $schemeGuids = @('SCHEME_CURRENT') }
                # Set AND verify EACH scheme — an unverified write to a non-active scheme
                # must not let the tool over-claim that all plans are disabled.
                $schemesVerified = 0
                $schemeNotes = @()
                foreach ($g in $schemeGuids) {
                    powercfg /setacvalueindex $g $usbSubGuid $usbSuspGuid 0 2>&1 | Out-Null
                    powercfg /setdcvalueindex $g $usbSubGuid $usbSuspGuid 0 2>&1 | Out-Null
                    $sac = -1; $sdc = -1
                    foreach ($line in (powercfg /query $g $usbSubGuid $usbSuspGuid)) {
                        if ($line -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') { $sac = [Convert]::ToInt32($Matches[1], 16) }
                        if ($line -match 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')  { $sdc = [Convert]::ToInt32($Matches[1], 16) }
                    }
                    if ($sac -eq 0 -and $sdc -eq 0) { $schemesVerified++ } else { $schemeNotes += "scheme $g not disabled (AC=$sac DC=$sdc)" }
                }
                powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
                $globalOk = ($schemeGuids.Count -gt 0 -and $schemesVerified -eq $schemeGuids.Count)

                # ── Layer B: per-device "Allow the computer to turn off this device" ──
                # This per-device flag (not the power plan) is what the probe flags and what
                # actually stops the adapter suspending. It cannot be set or verified reliably
                # in code (the WMI approach never worked across the field adapters), so open the
                # adapter's Properties window and walk the operator through the one manual step.
                $adapterOpened = 0
                $adapterNotes  = @()
                $btRadios      = @()
                try {
                    # Prefer the physical USB radio (it carries the Power Management tab).
                    $btRadios = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
                        Where-Object { $_.Present -and $_.InstanceId -like 'USB\*' })
                    if ($btRadios.Count -eq 0) {
                        $btRadios = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Present })
                    }
                    foreach ($radio in $btRadios) {
                        try {
                            # Opens the same Properties dialog as Device Manager for this device.
                            # (There is no supported way to pre-select the Power Management tab.)
                            $rdArgs = "devmgr.dll,DeviceProperties_RunDLL /MachineName `"`" /DeviceID `"$($radio.InstanceId)`""
                            Start-Process -FilePath 'rundll32.exe' -ArgumentList $rdArgs -ErrorAction Stop
                            $adapterOpened++
                        } catch { $adapterNotes += "could not open properties for '$($radio.FriendlyName)': $($_.Exception.Message)" }
                    }
                } catch { $adapterNotes += "adapter enumeration failed: $($_.Exception.Message)" }

                $detail = "Global USB selective suspend disabled and verified on $schemesVerified/$($schemeGuids.Count) power scheme(s); per-device step is MANUAL (opened $adapterOpened adapter properties window(s))"
                if ($schemeNotes.Count -gt 0)  { $detail += "; " + ($schemeNotes -join '; ') }
                if ($adapterNotes.Count -gt 0) { $detail += "; " + ($adapterNotes -join '; ') }

                $manualSteps = "In the Bluetooth adapter Properties window:`n  1. Click the 'Power Management' tab.`n  2. Uncheck 'Allow the computer to turn off this device to save power'.`n  3. Click OK."

                if (-not $globalOk) {
                    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                        Register-WinConfigSessionAction -Action "Disable USB Suspend" -Detail "powercfg verification failed ($schemesVerified/$($schemeGuids.Count) schemes confirmed); $detail" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "FAIL" -Tier 3 -Summary "USB suspend disable not verified"
                    }
                    [System.Windows.Forms.MessageBox]::Show("powercfg commands ran but verification failed ($schemesVerified of $($schemeGuids.Count) power plan(s) confirmed).`n`nTry manually: Power Options > Change plan settings > Change advanced power settings > USB settings > USB selective suspend setting.", "Verification Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                } else {
                    # Global layer verified; the per-device flag is a manual operator step -> WARN, never PASS.
                    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                        Register-WinConfigSessionAction -Action "Disable USB Suspend" -Detail $detail -Category "AdminChange" -ToolCategory "Bluetooth" -Result "WARN" -Tier 3 -Summary "USB plan suspend disabled; per-device is a manual step"
                    }
                    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                    if ($adapterOpened -gt 0) {
                        [System.Windows.Forms.MessageBox]::Show("USB selective suspend was disabled on all $($schemeGuids.Count) power plan(s).`n`nOne manual step is needed to finish. The Bluetooth adapter Properties window has been opened for you.`n`n$manualSteps`n`nThen re-run 'Run Bluetooth Diagnostics' to confirm USB suspend no longer shows as ENABLED.", "Almost Done - One Manual Step", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    } elseif ($btRadios.Count -eq 0) {
                        [System.Windows.Forms.MessageBox]::Show("USB selective suspend was disabled on all $($schemeGuids.Count) power plan(s).`n`nNo Bluetooth adapter was detected, so its Properties window could not be opened. If an adapter is present, set it via Device Manager > Bluetooth > [adapter] > Properties > Power Management.", "Plan Setting Disabled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("USB selective suspend was disabled on all $($schemeGuids.Count) power plan(s), but the adapter Properties window could not be opened automatically.`n`nOpen it via Device Manager > Bluetooth > [adapter] > Properties, then:`n$manualSteps", "Almost Done - One Manual Step", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    }
                }
            } catch {
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "Disable USB Suspend" -Detail "Failed: $($_.Exception.Message)" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "FAIL" -Tier 3 -Summary "USB suspend disable failed"
                }
                [System.Windows.Forms.MessageBox]::Show("Failed to disable USB selective suspend: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }

"Delete old backups" = {
    # Confirm the cleanup process
    $confirmation = [System.Windows.Forms.MessageBox]::Show(
        "This utility will permanently delete all but the 3 most recent NeurOptimal session backups. Do you want to continue?",
        "Confirm Backup Deletion",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirmation -ne [System.Windows.Forms.DialogResult]::Yes) {
        [System.Windows.Forms.MessageBox]::Show("Operation cancelled by the user.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    # Define the directory containing the backup files
    $backupDirectory = "C:\zengar\backups"

    # Check if the directory exists
    if (-not (Test-Path $backupDirectory)) {
        # Register failure
        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "Backup Cleanup" -Detail "Backup directory not found" -Category "Maintenance" -Result "FAIL" -Tier 2 -Summary "Directory not found: $backupDirectory"
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
        [System.Windows.Forms.MessageBox]::Show("Backup directory not found: $backupDirectory", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    # Get all backup files with .vaultzip extension, sorted by creation time
    $allBackups = Get-ChildItem -Path $backupDirectory -Filter "*.vaultzip" | Sort-Object CreationTime -Descending

    # Initialize counter for deleted files
    $deletedFilesCount = 0

    # Check if there are more than three backups
    if ($allBackups.Count -gt 3) {
        # Delete all but the three most recent files
        $filesToDelete = $allBackups | Select-Object -Skip 3
        $deletedFilesCount = $filesToDelete.Count
        $filesToDelete | ForEach-Object {
            Remove-Item $_.FullName -Force
        }
    }

    # Wait a moment to ensure file operations complete
    Start-Sleep -Seconds 1

    # Check free space after cleanup
    $driveLetter = (Get-Item $backupDirectory).PSDrive.Name
    $postFreeSpace = (Get-PSDrive $driveLetter).Free

    # Convert free space to GB for better readability
    $freeSpaceGB = [math]::Round($postFreeSpace / 1GB, 2)

    # Register session action with results
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Backup Cleanup" -Detail "Old NeurOptimal session backups deleted" -Category "Maintenance" -Result "PASS" -Tier 0 -Summary "$deletedFilesCount files deleted, $freeSpaceGB GB free"
    }
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

    # Display the result
    $resultMessage = "Your NeurOptimal session backups have been successfully cleaned.`n`n"
    $resultMessage += "$deletedFilesCount files were deleted.`n"
    $resultMessage += "$freeSpaceGB GB of disk space is available on drive $driveLetter."

    [System.Windows.Forms.MessageBox]::Show($resultMessage, "Backup Cleanup Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
"Disk Cleanup" = {
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Disk Cleanup" -Detail "Windows Disk Cleanup utility launched" -Category "Maintenance" -Result "PASS" -Tier 0 -Summary "Disk Cleanup launched"
    }
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
    Start-Process $cleanmgrPath
}
"Defrag && Optimize" = {
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Defrag/Optimize" -Detail "Windows Defragment and Optimize utility launched" -Category "Maintenance" -Result "PASS" -Tier 0 -Summary "Optimize utility launched"
    }
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
    Start-Process "$env:SystemRoot\System32\dfrgui.exe"
}
"C:\zengar" = { Start-Process "explorer.exe" "C:\zengar" }
"Empty Recycle Bin" = {
    $shell = New-Object -ComObject Shell.Application
    $recycleBin = $shell.Namespace(0xA)
    $recycleBinSize = ($recycleBin.Items() | Measure-Object Size -Sum).Sum
    $sizeInMB = [math]::Round($recycleBinSize / 1MB, 2)

    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    # Register session action with result
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Empty Recycle Bin" -Detail "Recycle Bin emptied ($sizeInMB MB freed)" -Category "Maintenance" -Result "PASS" -Tier 0 -Summary "$sizeInMB MB freed"
    }
    if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }

    [System.Windows.Forms.MessageBox]::Show("Recycle Bin has been emptied.`nSpace freed: $sizeInMB MB", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
# ===== ZAMP DRIVER UNINSTALL =====
# Canonical Zengar Driver Uninstall Algorithm (Windows)
# Follows deterministic multi-phase removal with full telemetry
"Uninstall zAmp Drivers" = {
    # SAFETY: Block mutations if audit trail is broken
    if (-not (Assert-AuditTrailHealthyForMutation)) { return }

    # Check elevation
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isElevated) {
        [System.Windows.Forms.MessageBox]::Show(
            "This operation requires Administrator privileges.`n`nPlease restart the Support Tool as Administrator.",
            "Elevation Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null

        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "zAmp Uninstall" -Detail "Elevation required" -Category "AdminChange" -Result "FAIL" -Tier 2 -Summary "PERMISSION_DENIED: Not elevated"
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
        return
    }

    # Create output window
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "zAmp Driver Uninstall"
    $outputForm.Size = New-Object System.Drawing.Size(900, 700)
    $outputForm.StartPosition = "CenterScreen"
    $outputForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $outputTextBox = New-Object System.Windows.Forms.RichTextBox
    Initialize-GuiDiagnosticBox -Box $outputTextBox
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $outputForm.Controls.Add($outputTextBox)

    # Initialize execution ledger
    $ledger = @{
        Timestamp = (Get-Date).ToUniversalTime().ToString("o")
        RunId = [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
        ToolVersion = $AppVersion
        OSVersion = [System.Environment]::OSVersion.VersionString
        Elevated = $isElevated
        Phase = "INIT"
        TargetsDiscovered = @()
        Actions = [System.Collections.Generic.List[object]]::new()
        FinalResult = "PENDING"
        FailureClass = $null
        ForceJustification = $null
    }

    function Write-LedgerLog {
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = Get-Date -Format "HH:mm:ss"
        $line = "[$timestamp] [$Level] $Message"
        $outputTextBox.AppendText("$line`r`n")
        $outputTextBox.SelectionStart = $outputTextBox.TextLength
        $outputTextBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }

    function Add-LedgerAction {
        param(
            [string]$Action,
            [string]$Target,
            [string]$Mode,
            [string]$Result,
            [int]$ExitCode = 0,
            [string]$Stdout = "",
            [string]$Stderr = ""
        )
        $ledger.Actions.Add(@{
            Action = $Action
            Target = $Target
            Mode = $Mode
            Result = $Result
            ExitCode = $ExitCode
            Stdout = $Stdout
            Stderr = $Stderr
            Timestamp = (Get-Date).ToUniversalTime().ToString("o")
        })
    }

    $outputForm.Add_Shown({
        Write-LedgerLog "=== zAmp Driver Uninstall - Run ID: $($ledger.RunId) ===" "INFO"
        Write-LedgerLog "Tool Version: $($ledger.ToolVersion)" "INFO"
        Write-LedgerLog "OS: $($ledger.OSVersion)" "INFO"
        Write-LedgerLog "Elevated: $($ledger.Elevated)" "INFO"
        Write-LedgerLog ""

        # ===== PHASE 1: DISCOVERY =====
        $ledger.Phase = "DISCOVERY"
        Write-LedgerLog "--- PHASE 1: DISCOVERY ---" "INFO"

        try {
            $targets = Get-WindowsDriver -Online -ErrorAction Stop |
                Where-Object {
                    $_.ProviderName -match "Zengar" -or
                    $_.OriginalFileName -match "zamp"
                } |
                Select-Object Driver, OriginalFileName, ProviderName, ClassName

            if (-not $targets -or @($targets).Count -eq 0) {
                Write-LedgerLog "No Zengar/zAmp drivers found in driver store." "INFO"
                Write-LedgerLog "System is already clean - no action required." "INFO"
                $ledger.FinalResult = "PASS"
                $ledger.FailureClass = "ALREADY_CLEAN"
                Add-LedgerAction -Action "Get-WindowsDriver" -Target "Zengar|zamp" -Mode "discovery" -Result "empty"
            } else {
                $targetList = @($targets)
                $ledger.TargetsDiscovered = $targetList | ForEach-Object {
                    @{
                        Driver = $_.Driver
                        OriginalFileName = $_.OriginalFileName
                        ProviderName = $_.ProviderName
                        ClassName = $_.ClassName
                    }
                }

                Write-LedgerLog "Found $($targetList.Count) driver package(s):" "INFO"
                foreach ($t in $targetList) {
                    Write-LedgerLog "  - $($t.Driver): $($t.OriginalFileName) [$($t.ProviderName)]" "INFO"
                }
                Write-LedgerLog ""

                # ===== PHASE 2: GHOST DEVICE REMOVAL =====
                $ledger.Phase = "GHOST_CLEANUP"
                Write-LedgerLog "--- PHASE 2: GHOST DEVICE REMOVAL ---" "INFO"

                $ghostsRemoved = 0
                $ghostsFailed = 0

                foreach ($t in $targetList) {
                    Write-LedgerLog "Checking for ghost devices bound to $($t.Driver)..." "INFO"

                    $enumOutput = & pnputil /enum-devices /disconnected /drivers 2>&1 | Out-String
                    $deviceMatches = $enumOutput -split "Instance ID:" |
                        Where-Object { $_ -match $t.Driver }

                    foreach ($match in $deviceMatches) {
                        if ($match -match "^\s*(\S+)") {
                            $instanceId = $Matches[1].Trim()
                            if ($instanceId -and $instanceId -ne "") {
                                Write-LedgerLog "  Removing ghost device: $instanceId" "INFO"
                                $removeResult = & pnputil /remove-device "$instanceId" 2>&1 | Out-String

                                if ($LASTEXITCODE -eq 0) {
                                    $ghostsRemoved++
                                    Add-LedgerAction -Action "pnputil /remove-device" -Target $instanceId -Mode "ghost" -Result "success" -Stdout $removeResult
                                    Write-LedgerLog "    Removed successfully" "INFO"
                                } else {
                                    $ghostsFailed++
                                    Add-LedgerAction -Action "pnputil /remove-device" -Target $instanceId -Mode "ghost" -Result "failed" -ExitCode $LASTEXITCODE -Stderr $removeResult
                                    Write-LedgerLog "    Failed to remove (exit code: $LASTEXITCODE)" "WARN"
                                }
                            }
                        }
                    }
                }

                if ($ghostsRemoved -gt 0) {
                    Write-LedgerLog "Removed $ghostsRemoved ghost device(s)" "INFO"
                }
                if ($ghostsFailed -gt 0) {
                    Write-LedgerLog "Failed to remove $ghostsFailed ghost device(s)" "WARN"
                }
                if ($ghostsRemoved -eq 0 -and $ghostsFailed -eq 0) {
                    Write-LedgerLog "No ghost devices found" "INFO"
                }
                Write-LedgerLog ""

                # ===== PHASE 3: CLEAN STAGED REMOVAL =====
                $ledger.Phase = "CLEAN_REMOVAL"
                Write-LedgerLog "--- PHASE 3: CLEAN STAGED REMOVAL ---" "INFO"

                $cleanRemoved = 0
                $cleanFailed = @()

                foreach ($t in $targetList) {
                    Write-LedgerLog "Attempting clean removal of $($t.Driver)..." "INFO"
                    $deleteResult = & pnputil /delete-driver $t.Driver 2>&1 | Out-String

                    if ($LASTEXITCODE -eq 0) {
                        $cleanRemoved++
                        Add-LedgerAction -Action "pnputil /delete-driver" -Target $t.Driver -Mode "clean" -Result "success" -Stdout $deleteResult
                        Write-LedgerLog "  Removed successfully" "INFO"
                    } else {
                        $cleanFailed += $t
                        Add-LedgerAction -Action "pnputil /delete-driver" -Target $t.Driver -Mode "clean" -Result "failed" -ExitCode $LASTEXITCODE -Stderr $deleteResult
                        Write-LedgerLog "  Clean removal failed (exit code: $LASTEXITCODE)" "WARN"
                    }
                }
                Write-LedgerLog ""

                # ===== PHASE 4: FORCE REMOVAL (if needed and safe) =====
                if ($cleanFailed.Count -gt 0) {
                    $ledger.Phase = "FORCE_REMOVAL"
                    Write-LedgerLog "--- PHASE 4: FORCE REMOVAL ---" "INFO"
                    Write-LedgerLog "$($cleanFailed.Count) driver(s) require force removal" "WARN"

                    # Build force justification
                    $justification = @{
                        CheckedAt = (Get-Date).ToUniversalTime().ToString("o")
                        BoundDevices = @()
                        Services = @()
                        EnumeratorsChecked = @("USB", "SoftwareDevice", "ROOT")
                        SafeToForce = $true
                        Reason = ""
                    }

                    # Check for bound devices
                    Write-LedgerLog "Checking for bound devices..." "INFO"
                    $boundDevices = & pnputil /enum-devices /connected /drivers 2>&1 | Out-String
                    foreach ($t in $cleanFailed) {
                        if ($boundDevices -match $t.Driver) {
                            $justification.BoundDevices += $t.Driver
                            $justification.SafeToForce = $false
                        }
                    }

                    # Check for services
                    Write-LedgerLog "Checking for related services..." "INFO"
                    $services = Get-Service | Where-Object { $_.DisplayName -match "Zengar|zAmp" }
                    if ($services) {
                        $justification.Services = @($services | ForEach-Object { $_.Name })
                        $justification.SafeToForce = $false
                    }

                    $ledger.ForceJustification = $justification

                    if ($justification.SafeToForce) {
                        Write-LedgerLog "Force removal is SAFE:" "INFO"
                        Write-LedgerLog "  - No bound devices remain" "INFO"
                        Write-LedgerLog "  - No related services found" "INFO"
                        Write-LedgerLog ""

                        foreach ($t in $cleanFailed) {
                            Write-LedgerLog "Force removing $($t.Driver)..." "INFO"
                            $forceResult = & pnputil /delete-driver $t.Driver /force 2>&1 | Out-String

                            if ($LASTEXITCODE -eq 0) {
                                Add-LedgerAction -Action "pnputil /delete-driver" -Target $t.Driver -Mode "force" -Result "success" -Stdout $forceResult
                                Write-LedgerLog "  Force removed successfully" "INFO"
                            } else {
                                Add-LedgerAction -Action "pnputil /delete-driver" -Target $t.Driver -Mode "force" -Result "failed" -ExitCode $LASTEXITCODE -Stderr $forceResult
                                Write-LedgerLog "  Force removal FAILED (exit code: $LASTEXITCODE)" "ERROR"
                                $ledger.FailureClass = "FORCE_FAILED"
                            }
                        }
                    } else {
                        Write-LedgerLog "Force removal is NOT SAFE:" "ERROR"
                        if ($justification.BoundDevices.Count -gt 0) {
                            Write-LedgerLog "  - Bound devices still present: $($justification.BoundDevices -join ', ')" "ERROR"
                        }
                        if ($justification.Services.Count -gt 0) {
                            Write-LedgerLog "  - Related services exist: $($justification.Services -join ', ')" "ERROR"
                        }
                        $ledger.FailureClass = "DRIVER_DELETE_BLOCKED"
                    }
                }
                Write-LedgerLog ""

                # ===== PHASE 5: VERIFICATION =====
                $ledger.Phase = "VERIFICATION"
                Write-LedgerLog "--- PHASE 5: VERIFICATION ---" "INFO"

                $remaining = Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.ProviderName -match "Zengar" -or
                        $_.OriginalFileName -match "zamp"
                    }

                if (-not $remaining -or @($remaining).Count -eq 0) {
                    Write-LedgerLog "VERIFICATION PASSED: No Zengar/zAmp drivers remain." "INFO"
                    $ledger.FinalResult = "PASS"
                } else {
                    Write-LedgerLog "VERIFICATION FAILED: Drivers still present:" "ERROR"
                    foreach ($r in @($remaining)) {
                        Write-LedgerLog "  - $($r.Driver): $($r.OriginalFileName)" "ERROR"
                    }
                    $ledger.FinalResult = "FAIL"
                    if (-not $ledger.FailureClass) {
                        $ledger.FailureClass = "VERIFICATION_FAILED"
                    }
                }
            }
        } catch {
            Write-LedgerLog "ERROR: $($_.Exception.Message)" "ERROR"
            $ledger.FinalResult = "FAIL"
            $ledger.FailureClass = "UNEXPECTED_ERROR"
            Add-LedgerAction -Action "Exception" -Target "N/A" -Mode "error" -Result "failed" -Stderr $_.Exception.Message
        }

        Write-LedgerLog ""
        Write-LedgerLog "=== UNINSTALL COMPLETE ===" "INFO"
        Write-LedgerLog "Final Result: $($ledger.FinalResult)" "INFO"
        if ($ledger.FailureClass) {
            Write-LedgerLog "Failure Class: $($ledger.FailureClass)" "INFO"
        }
        Write-LedgerLog "Run ID: $($ledger.RunId)" "INFO"

        # Register session action with full evidence
        $summaryText = switch ($ledger.FinalResult) {
            "PASS" {
                if ($ledger.FailureClass -eq "ALREADY_CLEAN") {
                    "Already clean: no drivers found"
                } else {
                    "$($ledger.TargetsDiscovered.Count) driver(s) removed"
                }
            }
            "FAIL" { "$($ledger.FailureClass): removal incomplete" }
            default { "Unknown result" }
        }

        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "zAmp Uninstall" `
                -Detail "Canonical driver uninstall executed" `
                -Category "AdminChange" `
                -Result $ledger.FinalResult `
                -Tier $(if ($ledger.FinalResult -eq "PASS") { 0 } else { 2 }) `
                -Summary $summaryText `
                -Evidence $ledger
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
    })

    $outputForm.ShowDialog() | Out-Null
}

# ===== ZAMP DRIVER TRUST REPAIR (ZAMP-TRUST-REPAIR-001) =====
# Fix 0x800B010A CERT_E_CHAINING driver-install failure: import the Sectigo ->
# Zengar catalog trust chain, re-stage both zAmp packages, verify device state.
# Every run terminates by emitting exactly one §6 diagnostic report (output
# pane + clipboard + ProgramData file), including aborts and precondition fails.
"Repair zAmp Driver Trust" = {
    if (-not (Assert-AuditTrailHealthyForMutation)) { return }

    # --- Constants (ZAMP-TRUST-REPAIR-001 §8) ---
    $ZampLoaderDriverDir  = 'C:\zengar\zAmpLoader\driver'
    $ZampBootloaderInf    = 'zAmpBootloader_WinUSB.inf'   # PID_1104
    $ZampRuntimeInf       = 'zAmpVISA_W8x64.inf'          # PID_1124
    $ZampCatalogForChain  = 'zAmpBootloader_WinUSB.cat'
    $ZengarLeafThumbprint = 'E2DF802CEF9C3C3EE6DCF4842812DB03E0E5C00F'
    $SectigoE46Thumbprint = 'BBEF5C4C11489770F586FB307D143291307F119A'
    $SectigoE46FileSha256 = '8F6371D8CC5AA7CA149667A98B5496398951E4319F7AFBCC6A660D673E438D0B'
    $ZampVidMatch         = '*VID_1167*'
    $PnputilSuccessCodes  = @(0, 3010)

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"

    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        # No output pane yet; still emit the report (clipboard + file) before returning.
        $report = & $script:BuildZampRepairReport @{
            Mode = "Execute"; Outcome = "PLAN_FAILED_NOT_ADMIN"; Elevated = $false
            Admin = $false; LoaderDirPresent = $false
            Errors = @(@{ step = "Preconditions"; message = "Administrator privileges are required to import certificates and install drivers."; hresult = "" })
        }
        $json = $report | ConvertTo-Json -Depth 12
        $block = & $script:ConvertZampReportToBlock $report
        $clipOk = $false
        try { Set-Clipboard -Value $block -ErrorAction Stop; $clipOk = $true } catch { }
        $reportFile = & $script:SaveZampRepairReportFile $json $stamp
        $extra = if ($clipOk) { "`n`nA diagnostic report was copied to your clipboard" + $(if ($reportFile) { " and saved to:`n$reportFile" } else { "." }) } else { "" }
        [System.Windows.Forms.MessageBox]::Show(
            "This operation requires Administrator privileges.`n`nPlease restart the Support Tool as Administrator.$extra",
            "Elevation Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
            Register-WinConfigSessionAction -Action "zAmp Trust Repair" -Detail "Elevation required" -Category "AdminChange" -Result "FAIL" -Tier 2 -Summary "PLAN_FAILED_NOT_ADMIN" -Evidence @{ Report = $report; ReportFile = $reportFile }
        }
        if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
        return
    }

    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "zAmp Driver Trust Repair"
    $outputForm.Size = New-Object System.Drawing.Size(920, 720)
    $outputForm.StartPosition = "CenterScreen"
    $outputForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $outputTextBox = New-Object System.Windows.Forms.RichTextBox
    Initialize-GuiDiagnosticBox -Box $outputTextBox
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $outputForm.Controls.Add($outputTextBox)

    $runStart = Get-Date

    # Report accumulator — every §6 field. Pessimistic default outcome so an
    # unexpected crash still reports a failure, never a false pass.
    $ctx = @{
        Mode = "Execute"; Outcome = "EXEC_FAILED_UNEXPECTED"; Elevated = $true
        Admin = $true; LoaderDirPresent = $false
        DeviceBefore = @(); CatalogSignatures = @{}; EmbeddedCerts = @()
        ChainBuildsBefore = $false; ChainStatus = @(); LeafInTrustedPublisher = $false
        RootE46InRoot = $false; Staged = @{ bootloader = $false; visa = $false }
        BundledRoot = "not-checked"; CertsAdded = @(); ChainBuildsAfter = $null
        Pnputil = @(); SetupapiTail = @(); DeviceAfter = @()
        RebootRequired = $false; OperatorAction = $null; Errors = @()
    }

    function Write-LedgerLog {
        param([string]$Message, [string]$Level = "INFO")
        $ts = Get-Date -Format "HH:mm:ss"
        $outputTextBox.AppendText("[$ts] [$Level] $Message`r`n")
        $outputTextBox.SelectionStart = $outputTextBox.TextLength
        $outputTextBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }

    function Add-CtxError {
        param([string]$Step, [string]$Message, $Hresult = "")
        $hr = if ($Hresult -is [int]) { ('0x{0:X8}' -f $Hresult) } else { "$Hresult" }
        $ctx.Errors += @{ step = $Step; message = $Message; hresult = $hr }
    }

    function Import-ZampCert {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$StoreName)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Cert.Thumbprint, $false)
            if ($found.Count -gt 0) { return "present" }
            $store.Add($Cert)
            return "added"
        } finally { $store.Close() }
    }

    $outputForm.Add_Shown({
        Write-LedgerLog "=== zAmp Driver Trust Repair ===" "INFO"
        Write-LedgerLog "OS: $([System.Environment]::OSVersion.VersionString)" "INFO"
        Write-LedgerLog "Elevated: $isElevated" "INFO"
        Write-LedgerLog ""

        try {
            # ---- Precondition: loader package present ----
            $catPath = Join-Path $ZampLoaderDriverDir $ZampCatalogForChain
            $bootInf = Join-Path $ZampLoaderDriverDir $ZampBootloaderInf
            $runInf  = Join-Path $ZampLoaderDriverDir $ZampRuntimeInf
            $ctx.LoaderDirPresent = (Test-Path $catPath) -and (Test-Path $bootInf) -and (Test-Path $runInf)
            if (-not $ctx.LoaderDirPresent) {
                Write-LedgerLog "zAmp loader package not found at $ZampLoaderDriverDir." "ERROR"
                Write-LedgerLog "NO 3.5.0.32+ update has not been applied on this system." "ERROR"
                $ctx.Outcome = "PLAN_FAILED_NO_LOADER"
                Add-CtxError -Step "Preconditions" -Message "zAmp loader package not found at $ZampLoaderDriverDir"
                return
            }

            # ---- Discovery (before state) ----
            Write-LedgerLog "--- DISCOVERY ---" "INFO"
            $devsBefore = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like $ZampVidMatch })
            $ctx.DeviceBefore = @($devsBefore | ForEach-Object { @{ id = $_.InstanceId; status = "$($_.Status)"; problem = "$($_.Problem)" } })
            Write-LedgerLog "VID_1167 devices present: $($devsBefore.Count)" "INFO"

            $catSigs = [ordered]@{}
            $catSigs["bootloader"] = $(try { "$((Get-AuthenticodeSignature -FilePath $catPath -ErrorAction Stop).Status)" } catch { "Error" })
            $visaCat = Join-Path $ZampLoaderDriverDir 'zAmpVISA_W8x64.cat'
            $catSigs["visa"] = $(if (Test-Path $visaCat) { try { "$((Get-AuthenticodeSignature -FilePath $visaCat -ErrorAction Stop).Status)" } catch { "Error" } } else { "Missing" })
            $ctx.CatalogSignatures = $catSigs

            # embedded certs (pure parse, no trust needed)
            $embedded = @()
            $leafCert = $null
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode([System.IO.File]::ReadAllBytes($catPath))
            foreach ($c in $cms.Certificates) {
                $role = if ($c.Subject -eq $c.Issuer) { "Root" } elseif ($c.Subject -like "*Zengar*") { "Leaf" } else { "Intermediate" }
                $embedded += [PSCustomObject]@{ Cert = $c; role = $role; subject = $c.Subject; thumb = $c.Thumbprint }
                if ($c.Thumbprint -eq $ZengarLeafThumbprint) { $leafCert = $c }
            }
            if (-not $leafCert -and $cms.SignerInfos.Count -gt 0) { $leafCert = $cms.SignerInfos[0].Certificate }
            $ctx.EmbeddedCerts = @($embedded | ForEach-Object { @{ role = $_.role; subject = $_.subject; thumb = $_.thumb } })
            Write-LedgerLog "Catalog embeds $($embedded.Count) certificate(s)." "INFO"

            $chainBefore = $false
            if ($leafCert) {
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $chainBefore = $chain.Build($leafCert)
                $ctx.ChainStatus = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" })
            }
            $ctx.ChainBuildsBefore = $chainBefore

            $ctx.LeafInTrustedPublisher = [bool](Get-ChildItem "Cert:\LocalMachine\TrustedPublisher" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $ZengarLeafThumbprint })
            $ctx.RootE46InRoot = [bool](Get-ChildItem "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $SectigoE46Thumbprint })

            $enum = & pnputil /enum-drivers 2>&1 | Out-String
            $bootStaged = [bool]($enum -match 'zampbootloader_winusb\.inf')
            $runStaged  = [bool]($enum -match 'zampvisa_w8x64\.inf')
            $ctx.Staged = @{ bootloader = $bootStaged; visa = $runStaged }

            $embeddedRootPresent = @($embedded | Where-Object { $_.role -eq "Root" }).Count -gt 0
            $e46Path = $null
            foreach ($cand in @((Join-Path $PSScriptRoot "..\assets\E46.cer"), (Join-Path $PSScriptRoot "assets\E46.cer"), (Join-Path (Split-Path $PSScriptRoot -Parent) "assets\E46.cer"))) {
                if (Test-Path $cand) { $e46Path = $cand; break }
            }
            $bundledRootValid = $false
            if (-not $e46Path) {
                $ctx.BundledRoot = "missing"
            } else {
                $h = $null
                try { $h = (Get-FileHash -Path $e46Path -Algorithm SHA256).Hash } catch { }
                if ($h -eq $SectigoE46FileSha256) { $bundledRootValid = $true; $ctx.BundledRoot = "valid" } else { $ctx.BundledRoot = "hash-mismatch" }
            }
            if ($embeddedRootPresent) { $ctx.BundledRoot = "embedded" }

            # ---- Healthy no-op ----
            if ($bootStaged -and $runStaged -and $chainBefore) {
                Write-LedgerLog "zAmp driver trust is healthy - no action required." "INFO"
                $ctx.Outcome = "HEALTHY_NOOP"
                $ctx.ChainBuildsAfter = $true
                return
            }

            # ---- Unrepairable: chain cannot be completed from any source ----
            $rootObtainable = $chainBefore -or $embeddedRootPresent -or $ctx.RootE46InRoot -or $bundledRootValid
            if (-not $rootObtainable) {
                Write-LedgerLog "Certificate chain cannot be completed from available sources." "ERROR"
                Write-LedgerLog "Obtain E46.cer per SUPPORT-BULLETIN-KI-001 and place it in the WinConfig assets folder." "ERROR"
                $ctx.Outcome = "PLAN_FAILED_UNREPAIRABLE_CHAIN"
                Add-CtxError -Step "ChainSourceCheck" -Message "No embedded root, Sectigo E46 not in Root store, and no valid bundled E46.cer ($($ctx.BundledRoot))."
                return
            }

            # ---- Step 1: import certificates (idempotent; records reversibility) ----
            Write-LedgerLog "--- TRUST CHAIN IMPORT ---" "INFO"
            foreach ($e in $embedded) {
                $stores = switch ($e.role) {
                    "Root"         { @("Root") }
                    "Intermediate" { @("CA") }
                    "Leaf"         { @("TrustedPublisher", "CA") }
                    default        { @() }
                }
                foreach ($sn in $stores) {
                    $o = Import-ZampCert -Cert $e.Cert -StoreName $sn
                    if ($o -eq "added") {
                        $ctx.CertsAdded += @{ store = $sn; thumb = $e.thumb }
                        Write-LedgerLog "  Imported [$($e.role)] -> LocalMachine\$sn" "INFO"
                    } else {
                        Write-LedgerLog "  Present [$($e.role)] in LocalMachine\$sn - skipped" "INFO"
                    }
                }
            }
            if (-not $embeddedRootPresent -and -not $ctx.RootE46InRoot) {
                if ($bundledRootValid) {
                    $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($e46Path)
                    $o = Import-ZampCert -Cert $rootCert -StoreName "Root"
                    if ($o -eq "added") {
                        $ctx.CertsAdded += @{ store = "Root"; thumb = $rootCert.Thumbprint }
                        Write-LedgerLog "  Imported bundled Sectigo Root E46 -> LocalMachine\Root (SHA-256 verified)" "INFO"
                    }
                } else {
                    Write-LedgerLog "Bundled E46.cer $($ctx.BundledRoot) - not imported (Root store integrity preserved)." "WARN"
                }
            }

            # ---- Step 2: re-verify chain BEFORE pnputil ----
            Write-LedgerLog "--- CHAIN VERIFICATION ---" "INFO"
            $chainAfter = $false
            if ($leafCert) {
                $chain2 = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain2.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $chainAfter = $chain2.Build($leafCert)
                $ctx.ChainStatus = @($chain2.ChainStatus | ForEach-Object { "$($_.Status)" })
            }
            $ctx.ChainBuildsAfter = $chainAfter
            if (-not $chainAfter) {
                Write-LedgerLog "Chain still does not build after import - ABORTING before pnputil." "ERROR"
                Write-LedgerLog "Running pnputil now would fail with the same 0x800B010A." "ERROR"
                $ctx.Outcome = "EXEC_FAILED_CHAIN_AFTER_IMPORT"
                Add-CtxError -Step "ChainVerify" -Message "X509Chain.Build() returned false after import" -Hresult "0x800B010A"
                return
            }
            Write-LedgerLog "Certificate chain builds successfully." "INFO"

            # ---- Steps 3-4: stage driver packages ----
            Write-LedgerLog "--- DRIVER PACKAGE STAGING ---" "INFO"
            $installTargets = @(
                @{ Inf = $bootInf; Name = $ZampBootloaderInf; Staged = $bootStaged; FailOutcome = "EXEC_FAILED_PNPUTIL_BOOTLOADER"; Step = "PnputilBootloader" },
                @{ Inf = $runInf;  Name = $ZampRuntimeInf;    Staged = $runStaged;  FailOutcome = "EXEC_FAILED_PNPUTIL_RUNTIME";    Step = "PnputilRuntime" }
            )
            $installFailed = $false
            foreach ($t in $installTargets) {
                if ($t.Staged) { Write-LedgerLog "$($t.Name) already staged - skipping." "INFO"; continue }
                Write-LedgerLog "Installing $($t.Name)..." "INFO"
                $out = & pnputil /add-driver $t.Inf /install 2>&1 | Out-String
                $exit = $LASTEXITCODE
                $ok = $PnputilSuccessCodes -contains $exit
                $tail = @($out -split "`r?`n" | Where-Object { $_.Trim() })
                $ctx.Pnputil += @{ inf = $t.Name; exit = $exit; outputTail = $tail }
                if ($exit -eq 3010) { $ctx.RebootRequired = $true }
                $hex = ('0x{0:X8}' -f $exit)
                if ($ok) {
                    Write-LedgerLog "  $($t.Name): exit $exit ($hex) - success" "INFO"
                } else {
                    Write-LedgerLog "  $($t.Name): exit $exit ($hex) - FAILED" "ERROR"
                    $ctx.Outcome = $t.FailOutcome
                    Add-CtxError -Step $t.Step -Message "pnputil /add-driver /install failed" -Hresult $exit
                    $ctx.SetupapiTail = & $script:GetZampSetupapiTail $runStart 40
                    $installFailed = $true
                    break
                }
            }
            if ($installFailed) { return }

            # ---- Step 5: device verification (staged => success even if unplugged) ----
            Write-LedgerLog "--- DEVICE VERIFICATION ---" "INFO"
            $deviceReady = $false
            $devs = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like $ZampVidMatch })
            if ($devs.Count -eq 0) {
                $ctx.OperatorAction = "Plug in (or unplug/replug) the zAmp, wait ~1 minute, then verify PID_1124 appears in Device Manager."
                Write-LedgerLog "No VID_1167 device enumerated. $($ctx.OperatorAction)" "INFO"
            } elseif ($devs | Where-Object { $_.InstanceId -like "*PID_1124*" -and $_.Status -eq "OK" }) {
                $deviceReady = $true
                Write-LedgerLog "Runtime device PID_1124 present and OK - zAmp ready." "INFO"
            } elseif ($devs | Where-Object { $_.InstanceId -like "*PID_1104*" -and $_.Status -eq "OK" }) {
                Write-LedgerLog "Bootloader PID_1104 present - waiting up to 90s for renumeration to PID_1124..." "INFO"
                $limit = (Get-Date).AddSeconds(90)
                while ((Get-Date) -lt $limit) {
                    Start-Sleep -Milliseconds 2000
                    [System.Windows.Forms.Application]::DoEvents()
                    if (Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "*PID_1124*" -and $_.Status -eq "OK" }) { $deviceReady = $true; break }
                }
                if ($deviceReady) {
                    Write-LedgerLog "Renumerated to PID_1124 - zAmp ready." "INFO"
                } else {
                    $ctx.OperatorAction = "Unplug and replug the zAmp, wait ~1 minute, then verify PID_1124 in Device Manager."
                    Write-LedgerLog "Did not renumerate within 90s. $($ctx.OperatorAction)" "WARN"
                }
            } else {
                $ctx.OperatorAction = "Unplug and replug the zAmp, wait ~1 minute, then verify PID_1124 in Device Manager."
                Write-LedgerLog "VID_1167 present but not OK. $($ctx.OperatorAction)" "WARN"
            }
            $devsAfter = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like $ZampVidMatch })
            $ctx.DeviceAfter = @($devsAfter | ForEach-Object { @{ id = $_.InstanceId; status = "$($_.Status)"; problem = "$($_.Problem)" } })

            $ctx.Outcome = if ($deviceReady) { "REPAIRED_VERIFIED" } else { "REPAIRED_AWAITING_REPLUG" }
        } catch {
            Write-LedgerLog "UNEXPECTED ERROR: $($_.Exception.Message)" "ERROR"
            $ctx.Outcome = "EXEC_FAILED_UNEXPECTED"
            Add-CtxError -Step "Unexpected" -Message $_.Exception.Message -Hresult $_.Exception.HResult
        } finally {
            # ===== ALWAYS emit exactly one §6 diagnostic report =====
            $report = & $script:BuildZampRepairReport $ctx
            $json = $report | ConvertTo-Json -Depth 12
            $block = & $script:ConvertZampReportToBlock $report

            Write-LedgerLog "" "INFO"
            Write-LedgerLog "Outcome: $($ctx.Outcome)" "INFO"
            if ($ctx.RebootRequired) { Write-LedgerLog "REBOOT REQUIRED to finish driver install (pnputil returned 3010)." "WARN" }

            $clipOk = $false
            try { Set-Clipboard -Value $block -ErrorAction Stop; $clipOk = $true } catch { }
            $reportFile = & $script:SaveZampRepairReportFile $json $stamp

            $outputTextBox.AppendText("`r`n$block`r`n`r`n")
            if ($clipOk) { Write-LedgerLog "Report copied to clipboard - paste it into the support ticket." "INFO" }
            else { Write-LedgerLog "Clipboard copy failed - use the saved report file below." "WARN" }
            if ($reportFile) { Write-LedgerLog "Report saved: $reportFile" "INFO" }
            $outputTextBox.SelectionStart = $outputTextBox.TextLength
            $outputTextBox.ScrollToCaret()

            $result = if ($ctx.Outcome -like "REPAIRED_*" -or $ctx.Outcome -eq "HEALTHY_NOOP") { "PASS" } else { "FAIL" }
            if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                Register-WinConfigSessionAction -Action "zAmp Trust Repair" `
                    -Detail "Cert chain import + driver re-stage (0x800B010A remediation)" `
                    -Category "AdminChange" `
                    -Result $result `
                    -Tier $(if ($result -eq "PASS") { 0 } else { 2 }) `
                    -Summary $ctx.Outcome `
                    -Evidence @{ Report = $report; ReportFile = $reportFile }
            }
            if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
        }
    })

    $outputForm.ShowDialog() | Out-Null
}
}

# FINAL: 2-tab structure (Tools → Details)
# Tools = high-density execution surface (where techs spend 80% of time)
# Details = observation + handoff (Diagnostics + Export combined)
$tabPages = @(
    "Tools",
    "Details"
)

foreach ($tabName in $tabPages) {
    $tabPage = New-TabPage $tabName
    $tabControl.TabPages.Add($tabPage) | Out-Null
}

# PERF-001: Lazy loading flags for expensive tabs
# The UI must render before expensive work (module loads, CIM queries) begins
$script:DiagnosticsTabInitialized = $false
$script:ToolsTabInitialized = $false  # UI-REWORK: Tools tab lazy load

# Populate tab pages
$tabContents = @{
    "System" = @(
        @{headline="System"; buttons=@("Copy System Info", "Copy Device Name", "Copy Serial Number", "Copy Windows version")}
        @{headline="NO Shortcuts"; buttons=@("%programdata%", "%localappdata%", "C:\zengar", "Documents\ScreenConnect")}
        @{headline="Windows Panels"; buttons=@("Device Manager", "Task Manager", "Control Panel", "Sound Panel")}
    )
    "Updates" = @(
        @{headline="Microsoft Store Updates"; buttons=@("MS Store Updates")}
        @{headline="Firmware"; buttons=@("Update Surface Drivers")}
        @{headline="Microsoft Update Catalog"; buttons=@("Microsoft Update Catalog")}
        @{headline="Windows Insider"; buttons=@("Windows Insider")}
    )
    "Sound" = @(
        @{headline="Drivers"; buttons=@("Remove Intel SST Audio Driver")}
        @{headline="Sound Settings"; buttons=@("Sound Panel")}
    )
    "Disk Health" = @(
        @{headline="Deployment Image Servicing and Management"; buttons=@("DISM Restore Health")}
        @{headline="System File Checker"; buttons=@("/sfc scannow")}
        @{headline="Disk Optimization"; buttons=@("Defrag && Optimize")}
    )
    "Custom UI" = @(
        @{headline="Start Menu"; buttons=@("Apply Win 11 Start Menu")}
        @{headline="Branding"; buttons=@("Apply branding colors")}
        @{headline="Taskbar"; buttons=@("Pin Taskbar Icons")}
        @{headline="Windows Update Icon"; buttons=@("Apply Win Update Icon")}
    )
    "Network Test" = @(
        @{headline="PowerShell"; buttons=@("Run Network Test", "Domain, IP && Ports Test")}
        @{headline="Browser"; buttons=@("Open Speedtest.net")}
    )
"Disk Space" = @(
    @{headline="Zengar backups"; buttons=@("Delete old backups")}
    @{headline="Disk Cleanup"; buttons=@("Disk Cleanup", "Empty Recycle Bin")}
)
}

# FINAL: Build 2-tab structure (Tools → Details)
# Tools = high-density execution surface
# Details = observation + handoff (Diagnostics + Export combined)

foreach ($tabPage in $tabControl.TabPages) {
    $flowLayoutPanel = $tabPage.Controls[0]

    # ==================== TOOLS TAB ====================
    # Phase 8.0: Category List Layout Hardening
    # - Single source of truth for categories
    # - One panel per category (created once, not on selection)
    # - Keyboard navigation (Up/Down/Enter/Escape)
    # - Regression guards: category switch never cancels/restarts/mutates tools
    if ($tabPage.Text -eq "Tools") {
        $tabPage.Controls.Clear()

        # === STEP 1: SINGLE SOURCE OF TRUTH ===
        # This ordered array is THE ONLY place categories are defined
        # Used for: list population, panel creation, selection, badges
        $script:Categories = @(
            "Network",
            "Updates",
            "NO Shortcuts",
            "Disk",
            "System",
            "Audio",
            "Bluetooth",
            "zAmp",
            "Zengar UI",
            "Support"
        )

        # === DRY RUN INFRASTRUCTURE ===
        # Script-scoped function to invoke dry run for a tool
        # Uses DryRun.psm1 infrastructure: creates PLAN, writes to ledger, exports normally
        $script:InvokeDryRunForToolFn = {
            param(
                [string]$ToolId,
                [string]$ToolName
            )

            # Import DryRun module globally (required for scriptblock closures to access New-DryRunPlan)
            $dryRunPath = Join-Path $PSScriptRoot "Modules\DryRun.psm1"
            if (Test-Path $dryRunPath) {
                Import-Module $dryRunPath -Force -Global
            }

            # === MODE BANNER: Resolve dry-run intent for operator visibility ===
            $modeResolution = Resolve-DryRunIntent -DryRun
            $modeBanner = if ($modeResolution.IsDryRun) {
                "DRY RUN (Source: $($modeResolution.Source))"
            } else {
                "LIVE (Source: $($modeResolution.Source))"
            }

            # Tool-specific plan generators
            $planGenerators = @{
                "intel-sst-removal" = {
                    # === PLAN PHASE: Pure, read-only system inspection ===
                    # PLAN failures return structured data, not exceptions.

                    # Precondition 1: Admin check
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    # Precondition 2: Restore point capability
                    $restoreCapable = $false
                    try {
                        $sr = Get-WmiObject -Class SystemRestore -Namespace "root\default" -ErrorAction Stop
                        $restoreCapable = ($null -ne $sr)
                    } catch {
                        $restoreCapable = $false
                    }

                    # === PRECONDITION FAILURE: Return structured failure plan ===
                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "intel-sst-removal" `
                            -ToolName "Remove Intel SST Audio Driver" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED", "RestorePoint: Not checked") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Administrator privileges are required to enumerate and remove drivers."
                                Preconditions = @{
                                    IsAdmin = $false
                                    RestorePointCapable = "Not checked"
                                }
                                Findings = @{
                                    DriversFound = @()
                                    DriverCount = 0
                                }
                            }
                    }

                    # === READ-ONLY DISCOVERY: Find Intel SST drivers ===
                    # Use Get-WindowsDriver for consistency with zAmp pattern
                    $driversFound = @()
                    try {
                        $targets = Get-WindowsDriver -Online -ErrorAction Stop |
                            Where-Object {
                                $_.OriginalFileName -match "intcusb" -or
                                $_.OriginalFileName -match "IntcSST" -or
                                $_.ProviderName -match "Intel.*Smart Sound"
                            }

                        foreach ($d in $targets) {
                            $driversFound += @{
                                Driver           = $d.Driver
                                OriginalFileName = $d.OriginalFileName
                                ProviderName     = $d.ProviderName
                                ClassName        = $d.ClassName
                            }
                        }
                    } catch {
                        # Get-WindowsDriver failed
                    }

                    # === BUILD CONCRETE ACTIONS (WOULD_* verbs) ===
                    $actions = @()
                    if ($driversFound.Count -gt 0) {
                        $actions += (New-DryRunStep -Verb WOULD_CREATE -Target "system restore point").Summary
                        foreach ($drv in $driversFound) {
                            $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "driver package: $($drv.Driver)" -Detail "$($drv.OriginalFileName) [$($drv.ProviderName)]").Summary
                        }
                        $actions += (New-DryRunStep -Verb WOULD_EXEC -Target "removal verification").Summary
                    }

                    # === BUILD AFFECTED RESOURCES ===
                    $resources = @()
                    foreach ($drv in $driversFound) {
                        $resources += "DriverStore:$($drv.Driver)"
                        $resources += "File:$($drv.OriginalFileName)"
                    }

                    New-DryRunPlan `
                        -ToolId "intel-sst-removal" `
                        -ToolName "Remove Intel SST Audio Driver" `
                        -Steps $(if ($actions.Count -gt 0) { $actions } else { @("No Intel SST drivers found - no action required") }) `
                        -AffectedResources $(if ($resources.Count -gt 0) { $resources } else { @("None") }) `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact $(if ($driversFound.Count -gt 0) { "Medium" } else { "None" }) `
                        -Preconditions @("Admin: $isAdmin", "RestorePoint: $restoreCapable") `
                        -Evidence @{
                            Preconditions = @{
                                IsAdmin = $isAdmin
                                RestorePointCapable = $restoreCapable
                            }
                            Findings = @{
                                DriversFound = $driversFound
                                DriverCount = $driversFound.Count
                            }
                        }
                }
                "zamp-driver-uninstall" = {
                    # === PLAN PHASE: Pure, read-only system inspection ===
                    # This is NOT a simulation. This queries real system state.
                    # PLAN failures return structured data, not exceptions.

                    # Precondition 1: Admin check
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    # Precondition 2: Restore point capability check
                    $restoreCapable = $false
                    try {
                        $sr = Get-WmiObject -Class SystemRestore -Namespace "root\default" -ErrorAction Stop
                        $restoreCapable = ($null -ne $sr)
                    } catch {
                        $restoreCapable = $false
                    }

                    # === PRECONDITION FAILURE: Return structured failure plan ===
                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "zamp-driver-uninstall" `
                            -ToolName "Uninstall zAmp Drivers" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED", "RestorePoint: Not checked") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Administrator privileges are required to enumerate and remove drivers."
                                Preconditions = @{
                                    IsAdmin = $false
                                    RestorePointCapable = "Not checked"
                                }
                                Findings = @{
                                    DriversFound = @()
                                    DriverCount = 0
                                }
                            }
                    }

                    # === READ-ONLY DISCOVERY: Find zAmp/Zengar drivers ===
                    # Use same detection as actual uninstall: Get-WindowsDriver with ProviderName/OriginalFileName
                    $driversFound = @()
                    try {
                        $targets = Get-WindowsDriver -Online -ErrorAction Stop |
                            Where-Object {
                                $_.ProviderName -match "Zengar" -or
                                $_.OriginalFileName -match "zamp"
                            }

                        foreach ($d in $targets) {
                            $driversFound += @{
                                Driver           = $d.Driver
                                OriginalFileName = $d.OriginalFileName
                                ProviderName     = $d.ProviderName
                                ClassName        = $d.ClassName
                            }
                        }
                    } catch {
                        # Get-WindowsDriver failed - still report empty findings
                    }

                    # === BUILD CONCRETE ACTIONS (WOULD_* verbs) ===
                    $actions = @()
                    if ($driversFound.Count -gt 0) {
                        $actions += (New-DryRunStep -Verb WOULD_CREATE -Target "system restore point").Summary
                        foreach ($drv in $driversFound) {
                            $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "driver package: $($drv.Driver)" -Detail "$($drv.OriginalFileName) [$($drv.ProviderName)]").Summary
                        }
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost devices").Summary
                        $actions += (New-DryRunStep -Verb WOULD_EXEC -Target "removal verification").Summary
                    }
                    # If no drivers found, Actions = @() - valid no-op plan

                    # === BUILD AFFECTED RESOURCES (concrete, not wildcards) ===
                    $resources = @()
                    foreach ($drv in $driversFound) {
                        $resources += "DriverStore:$($drv.Driver)"
                        $resources += "File:$($drv.OriginalFileName)"
                    }
                    if ($driversFound.Count -gt 0) {
                        $resources += "Service:AudioSrv"
                    }

                    # === RETURN PLAN with Evidence ===
                    New-DryRunPlan `
                        -ToolId "zamp-driver-uninstall" `
                        -ToolName "Uninstall zAmp Drivers" `
                        -Steps $(if ($actions.Count -gt 0) { $actions } else { @("No zAmp drivers found - no action required") }) `
                        -AffectedResources $(if ($resources.Count -gt 0) { $resources } else { @("None") }) `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact $(if ($driversFound.Count -gt 0) { "Medium" } else { "None" }) `
                        -Preconditions @("Admin: $isAdmin", "RestorePoint: $restoreCapable") `
                        -Evidence @{
                            Preconditions = @{
                                IsAdmin = $isAdmin
                                RestorePointCapable = $restoreCapable
                            }
                            Findings = @{
                                DriversFound = $driversFound
                                DriverCount = $driversFound.Count
                            }
                        }
                }

                "zamp-driver-trust-repair" = {
                    # === PLAN PHASE: Pure, read-only system inspection (ZAMP-TRUST-REPAIR-001 §4) ===
                    # Queries real state; never throws. A §6 diagnostic report is attached to
                    # Evidence.Report (the analytics channel). Operator-facing clipboard/file
                    # delivery happens on EXECUTE only, so PLAN stays side-effect-free.

                    $ZampLoaderDriverDir  = 'C:\zengar\zAmpLoader\driver'
                    $ZampBootloaderInf    = 'zAmpBootloader_WinUSB.inf'
                    $ZampRuntimeInf       = 'zAmpVISA_W8x64.inf'
                    $ZampCatalogForChain  = 'zAmpBootloader_WinUSB.cat'
                    $ZengarLeafThumbprint = 'E2DF802CEF9C3C3EE6DCF4842812DB03E0E5C00F'
                    $SectigoE46Thumbprint = 'BBEF5C4C11489770F586FB307D143291307F119A'
                    $SectigoE46FileSha256 = '8F6371D8CC5AA7CA149667A98B5496398951E4319F7AFBCC6A660D673E438D0B'
                    $ZampVidMatch         = '*VID_1167*'

                    # --- P1: Admin ---
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    if (-not $isAdmin) {
                        $rep = & $script:BuildZampRepairReport @{
                            Mode = "Plan"; Outcome = "PLAN_FAILED_NOT_ADMIN"; Elevated = $false
                            Admin = $false; LoaderDirPresent = $false
                            Errors = @(@{ step = "Preconditions"; message = "Administrator privileges are required to import certificates and install drivers."; hresult = "" })
                        }
                        return New-DryRunPlan `
                            -ToolId "zamp-driver-trust-repair" -ToolName "Repair zAmp Driver Trust" `
                            -Steps @("PLAN FAILED: Cannot proceed") -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true -Reversible $true -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Administrator privileges are required to import certificates and install drivers."
                                Preconditions = @{ IsAdmin = $false }
                                Report = $rep
                            }
                    }

                    # --- P2: loader package present ---
                    $catPath = Join-Path $ZampLoaderDriverDir $ZampCatalogForChain
                    $bootInf = Join-Path $ZampLoaderDriverDir $ZampBootloaderInf
                    $runInf  = Join-Path $ZampLoaderDriverDir $ZampRuntimeInf
                    $pkgPresent = (Test-Path $catPath) -and (Test-Path $bootInf) -and (Test-Path $runInf)
                    if (-not $pkgPresent) {
                        $rep = & $script:BuildZampRepairReport @{
                            Mode = "Plan"; Outcome = "PLAN_FAILED_NO_LOADER"; Elevated = $true
                            Admin = $true; LoaderDirPresent = $false
                            Errors = @(@{ step = "Preconditions"; message = "zAmp loader package not found at $ZampLoaderDriverDir"; hresult = "" })
                        }
                        return New-DryRunPlan `
                            -ToolId "zamp-driver-trust-repair" -ToolName "Repair zAmp Driver Trust" `
                            -Steps @("PLAN FAILED: Cannot proceed") -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true -Reversible $true -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: $isAdmin", "LoaderPackage: MISSING") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "zAmp loader package not found at C:\zengar\zAmpLoader\driver - NO 3.5.0.32+ update has not been applied on this system."
                                Preconditions = @{ IsAdmin = $isAdmin; LoaderPackagePresent = $false }
                                Report = $rep
                            }
                    }

                    # --- Read-only discovery ---
                    $deviceState = @()
                    try {
                        foreach ($d in @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -like $ZampVidMatch })) {
                            $deviceState += @{ id = $d.InstanceId; status = "$($d.Status)"; problem = "$($d.Problem)" }
                        }
                    } catch { }

                    $catSigs = [ordered]@{}
                    $catSigs["bootloader"] = $(try { "$((Get-AuthenticodeSignature -FilePath $catPath -ErrorAction Stop).Status)" } catch { "Error" })
                    $visaCat = Join-Path $ZampLoaderDriverDir 'zAmpVISA_W8x64.cat'
                    $catSigs["visa"] = $(if (Test-Path $visaCat) { try { "$((Get-AuthenticodeSignature -FilePath $visaCat -ErrorAction Stop).Status)" } catch { "Error" } } else { "Missing" })

                    $embedded = @()
                    $leafCert = $null
                    $catalogParseError = $null
                    try {
                        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                        $cms.Decode([System.IO.File]::ReadAllBytes($catPath))
                        foreach ($c in $cms.Certificates) {
                            $role = if ($c.Subject -eq $c.Issuer) { "Root" } elseif ($c.Subject -like "*Zengar*") { "Leaf" } else { "Intermediate" }
                            $embedded += @{ role = $role; subject = $c.Subject; thumb = $c.Thumbprint }
                            if ($c.Thumbprint -eq $ZengarLeafThumbprint) { $leafCert = $c }
                        }
                        if (-not $leafCert -and $cms.SignerInfos.Count -gt 0) { $leafCert = $cms.SignerInfos[0].Certificate }
                    } catch { $catalogParseError = $_.Exception.Message }

                    $chainBuilds = $false
                    $chainStatus = @()
                    if ($leafCert) {
                        try {
                            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                            $chainBuilds = $chain.Build($leafCert)
                            $chainStatus = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" })
                        } catch { }
                    }

                    $leafInTP = [bool](Get-ChildItem "Cert:\LocalMachine\TrustedPublisher" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $ZengarLeafThumbprint })
                    $rootInStore = [bool](Get-ChildItem "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $SectigoE46Thumbprint })

                    $bootStaged = $false; $runStaged = $false
                    try {
                        $enum = & pnputil /enum-drivers 2>&1 | Out-String
                        $bootStaged = [bool]($enum -match 'zampbootloader_winusb\.inf')
                        $runStaged  = [bool]($enum -match 'zampvisa_w8x64\.inf')
                    } catch { }

                    $embeddedRootPresent = @($embedded | Where-Object { $_.role -eq "Root" }).Count -gt 0
                    $bundledRootValid = $false
                    $bundledRootState = "missing"
                    $e46Path = $null
                    foreach ($cand in @((Join-Path $PSScriptRoot "..\assets\E46.cer"), (Join-Path $PSScriptRoot "assets\E46.cer"), (Join-Path (Split-Path $PSScriptRoot -Parent) "assets\E46.cer"))) {
                        if (Test-Path $cand) { $e46Path = $cand; break }
                    }
                    if ($e46Path) {
                        $h = $null
                        try { $h = (Get-FileHash -Path $e46Path -Algorithm SHA256).Hash } catch { }
                        if ($h -eq $SectigoE46FileSha256) { $bundledRootValid = $true; $bundledRootState = "valid" } else { $bundledRootState = "hash-mismatch" }
                    }
                    if ($embeddedRootPresent) { $bundledRootState = "embedded" }

                    $baseCtx = @{
                        Mode = "Plan"; Elevated = $true; Admin = $true; LoaderDirPresent = $true
                        DeviceBefore = $deviceState; CatalogSignatures = $catSigs; EmbeddedCerts = $embedded
                        ChainBuildsBefore = $chainBuilds; ChainStatus = $chainStatus
                        LeafInTrustedPublisher = $leafInTP; RootE46InRoot = $rootInStore
                        Staged = @{ bootloader = $bootStaged; visa = $runStaged }; BundledRoot = $bundledRootState
                        CertsAdded = @(); ChainBuildsAfter = $null; Pnputil = @(); SetupapiTail = @()
                        DeviceAfter = @(); RebootRequired = $false; OperatorAction = $null
                        Errors = $(if ($catalogParseError) { @(@{ step = "CatalogParse"; message = $catalogParseError; hresult = "" }) } else { @() })
                    }

                    $findings = @{
                        DeviceState = $(if ($deviceState.Count -gt 0) { $deviceState } else { "none-enumerated" })
                        CatalogSignatureValid = $catSigs; EmbeddedCerts = $embedded; ChainBuilds = $chainBuilds
                        ChainStatus = $chainStatus; LeafInTrustedPublisher = $leafInTP; RootE46InStore = $rootInStore
                        PackagesStaged = @{ Bootloader = $bootStaged; Runtime = $runStaged }
                        BundledRootAvailable = $bundledRootValid; BundledRoot = $bundledRootState
                        CatalogParseError = $catalogParseError
                    }

                    # --- Healthy no-op ---
                    if ($bootStaged -and $runStaged -and $chainBuilds) {
                        # Hashtable + throws on duplicate keys, so overwrite via Clone (baseCtx
                        # already carries ChainBuildsAfter/Errors defaults).
                        $repCtx = $baseCtx.Clone()
                        $repCtx.Outcome = "HEALTHY_NOOP"
                        $repCtx.ChainBuildsAfter = $true
                        $rep = & $script:BuildZampRepairReport $repCtx
                        return New-DryRunPlan `
                            -ToolId "zamp-driver-trust-repair" -ToolName "Repair zAmp Driver Trust" `
                            -Steps @("zAmp driver trust is healthy - no action required") -AffectedResources @("None") `
                            -RequiresAdmin $true -Reversible $true -EstimatedImpact "None" `
                            -Preconditions @("Admin: $isAdmin", "LoaderPackage: $pkgPresent", "ChainBuilds: $chainBuilds") `
                            -Evidence @{ Preconditions = @{ IsAdmin = $isAdmin; LoaderPackagePresent = $pkgPresent }; Findings = $findings; Healthy = $true; Report = $rep }
                    }

                    # --- Unrepairable: no source can complete the chain ---
                    $rootObtainable = $chainBuilds -or $embeddedRootPresent -or $rootInStore -or $bundledRootValid
                    if (-not $rootObtainable) {
                        $repCtx = $baseCtx.Clone()
                        $repCtx.Outcome = "PLAN_FAILED_UNREPAIRABLE_CHAIN"
                        $repCtx.Errors = @($repCtx.Errors) + @(@{ step = "ChainSourceCheck"; message = "No embedded root, Sectigo E46 not in Root store, no valid bundled E46.cer ($bundledRootState)."; hresult = "" })
                        $rep = & $script:BuildZampRepairReport $repCtx
                        return New-DryRunPlan `
                            -ToolId "zamp-driver-trust-repair" -ToolName "Repair zAmp Driver Trust" `
                            -Steps @("PLAN FAILED: Cannot proceed") -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true -Reversible $true -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: $isAdmin", "LoaderPackage: $pkgPresent", "ChainBuilds: false") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Certificate chain cannot be completed from available sources. Obtain E46.cer per SUPPORT-BULLETIN-KI-001 and place it in the WinConfig assets folder."
                                Preconditions = @{ IsAdmin = $isAdmin; LoaderPackagePresent = $pkgPresent }
                                Findings = $findings; Report = $rep
                            }
                    }

                    # --- Repair plan: emit WOULD_* only for what is missing ---
                    $steps = @()
                    $resources = @()
                    $storeThumbs = @{}
                    foreach ($sn in @("Root", "CA", "TrustedPublisher")) {
                        $set = @{}
                        try { Get-ChildItem "Cert:\LocalMachine\$sn" -ErrorAction Stop | ForEach-Object { $set[$_.Thumbprint] = $true } } catch { }
                        $storeThumbs[$sn] = $set
                    }
                    foreach ($e in $embedded) {
                        $targets = switch ($e.role) {
                            "Root"         { @("Root") }
                            "Intermediate" { @("CA") }
                            "Leaf"         { @("TrustedPublisher", "CA") }
                            default        { @() }
                        }
                        foreach ($sn in $targets) {
                            if (-not $storeThumbs[$sn][$e.thumb]) {
                                $steps += (New-DryRunStep -Verb WOULD_CREATE -Target "certificate: $($e.subject) -> LocalMachine\$sn").Summary
                                $resources += "CertStore:LocalMachine\${sn}:$($e.thumb)"
                            }
                        }
                    }
                    if (-not $embeddedRootPresent -and -not $rootInStore -and $bundledRootValid) {
                        $steps += (New-DryRunStep -Verb WOULD_CREATE -Target "certificate: Sectigo Root E46 (bundled) -> LocalMachine\Root").Summary
                        $resources += "CertStore:LocalMachine\Root:$SectigoE46Thumbprint"
                    }
                    if (-not $bootStaged) {
                        $steps += (New-DryRunStep -Verb WOULD_EXEC -Target "pnputil /add-driver $ZampBootloaderInf /install").Summary
                        $resources += "DriverStore:zampbootloader_winusb.inf"
                    }
                    if (-not $runStaged) {
                        $steps += (New-DryRunStep -Verb WOULD_EXEC -Target "pnputil /add-driver $ZampRuntimeInf /install").Summary
                        $resources += "DriverStore:zampvisa_w8x64.inf"
                    }
                    $steps += (New-DryRunStep -Verb WOULD_EXEC -Target "device state verification (VID_1167)").Summary

                    $repCtx = $baseCtx.Clone()
                    $repCtx.Outcome = "PLAN_REPAIR_AVAILABLE"
                    $rep = & $script:BuildZampRepairReport $repCtx
                    New-DryRunPlan `
                        -ToolId "zamp-driver-trust-repair" -ToolName "Repair zAmp Driver Trust" `
                        -Steps $steps -AffectedResources $(if ($resources.Count -gt 0) { $resources } else { @("None") }) `
                        -RequiresAdmin $true -Reversible $true -EstimatedImpact "Medium" `
                        -Preconditions @("Admin: $isAdmin", "LoaderPackage: $pkgPresent", "ChainBuilds: $chainBuilds") `
                        -Evidence @{ Preconditions = @{ IsAdmin = $isAdmin; LoaderPackagePresent = $pkgPresent }; Findings = $findings; Report = $rep }
                }

                # =========================================================================
                # SERVICE RESTART TOOLS
                # =========================================================================
                "audio-service-restart" = {
                    # === PLAN PHASE: Check audio service state ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "audio-service-restart" `
                            -ToolName "Restart Audio Service" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Administrator privileges are required to restart services."
                                Preconditions = @{ IsAdmin = $false }
                                Findings = @{}
                            }
                    }

                    # === READ-ONLY DISCOVERY: Check Audio service state ===
                    $serviceInfo = @{}
                    try {
                        $svc = Get-Service -Name "Audiosrv" -ErrorAction Stop
                        $serviceInfo = @{
                            Name = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status = $svc.Status.ToString()
                            StartType = $svc.StartType.ToString()
                        }
                    } catch {
                        $serviceInfo = @{ Name = "Audiosrv"; Status = "NotFound"; Error = $_.Exception.Message }
                    }

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_RESTART -Target "service: Audiosrv" -Detail "Windows Audio").Summary,
                        (New-DryRunStep -Verb WOULD_RESTART -Target "service: AudioEndpointBuilder" -Detail "dependent service").Summary,
                        (New-DryRunStep -Verb WOULD_EXEC -Target "service state verification").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "audio-service-restart" `
                        -ToolName "Restart Audio Service" `
                        -Steps $actions `
                        -AffectedResources @("Service:Audiosrv", "Service:AudioEndpointBuilder") `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact "Low" `
                        -Preconditions @("Admin: $isAdmin", "Service: $($serviceInfo.Status)") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings = @{ Service = $serviceInfo }
                        }
                }

                # =========================================================================
                # NETWORK TOOLS
                # =========================================================================
                "network-reset" = {
                    # === PLAN PHASE: Network reset is admin-only ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "network-reset" `
                            -ToolName "Network Reset" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed = $true
                                FailureReason = "Administrator privileges are required to reset network stack."
                                Preconditions = @{ IsAdmin = $false }
                                Findings = @{}
                            }
                    }

                    # === READ-ONLY DISCOVERY: Check network adapters ===
                    $adapters = @()
                    try {
                        $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
                        foreach ($a in $netAdapters) {
                            $adapters += @{
                                Name = $a.Name
                                InterfaceDescription = $a.InterfaceDescription
                                Status = $a.Status
                                MacAddress = $a.MacAddress
                            }
                        }
                    } catch {
                        # Get-NetAdapter failed
                    }

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_EXEC -Target "TCP/IP stack reset" -Detail "netsh int ip reset").Summary,
                        (New-DryRunStep -Verb WOULD_EXEC -Target "Winsock catalog reset" -Detail "netsh winsock reset").Summary,
                        (New-DryRunStep -Verb WOULD_EXEC -Target "DNS resolver cache flush" -Detail "ipconfig /flushdns").Summary,
                        (New-DryRunStep -Verb WOULD_EXEC -Target "DHCP lease renewal").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "network-reset" `
                        -ToolName "Network Reset" `
                        -Steps $actions `
                        -AffectedResources @("TCP/IP Stack", "Winsock Catalog", "DNS Cache", "DHCP Leases") `
                        -RequiresAdmin $true `
                        -Reversible $false `
                        -EstimatedImpact "High" `
                        -Preconditions @("Admin: $isAdmin", "Active Adapters: $($adapters.Count)") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings = @{
                                ActiveAdapters = $adapters
                                AdapterCount = $adapters.Count
                            }
                        }
                }

                # =========================================================================
                # MAINTENANCE TOOLS
                # =========================================================================
                "empty-recycle-bin" = {
                    # === PLAN PHASE: Enumerate recycle bin contents (read-only) ===
                    $binItems = @()
                    $totalSize = 0
                    $itemCount = 0
                    $discoveryErrors = @()
                    $sampleLimit = 10

                    # --- Stage 1: COM instantiation ---
                    $shell = $null
                    $recycleBin = $null
                    try {
                        $shell = New-Object -ComObject Shell.Application
                        $recycleBin = $shell.Namespace(0xA)
                        if ($null -eq $recycleBin) {
                            throw "Shell.Application.Namespace(0xA) returned null"
                        }
                    } catch {
                        # COM failed to instantiate — cannot discover recycle bin at all
                        return New-DryRunPlan `
                            -ToolId "empty-recycle-bin" `
                            -ToolName "Empty Recycle Bin" `
                            -Steps @("PLAN FAILED: Cannot enumerate recycle bin") `
                            -AffectedResources @("RecycleBin (unknown)") `
                            -RequiresAdmin $false `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Evidence @{
                                PlanFailed      = $true
                                FailureReason   = "COM discovery failed: $($_.Exception.Message)"
                                FailureCode     = "RECYCLEBIN_DISCOVERY_FAILED"
                                DiscoveryMethod = "Shell.Application"
                                DiscoveryErrors = @($_.Exception.Message)
                            }
                    }

                    # --- Stage 2: Item enumeration ---
                    try {
                        $items = $recycleBin.Items()
                        if ($null -eq $items) {
                            throw "RecycleBin.Items() returned null"
                        }
                        $itemCount = @($items).Count
                        $totalSize = ($items | Measure-Object Size -Sum -ErrorAction SilentlyContinue).Sum
                        if (-not $totalSize) { $totalSize = 0 }

                        # Sample first N items for evidence
                        $sampleItems = @($items) | Select-Object -First $sampleLimit
                        foreach ($item in $sampleItems) {
                            $binItems += @{
                                Name = $item.Name
                                Size = $item.Size
                                Type = $item.Type
                            }
                        }
                    } catch {
                        # Enumeration failed — COM works but items inaccessible
                        $discoveryErrors += $_.Exception.Message
                        return New-DryRunPlan `
                            -ToolId "empty-recycle-bin" `
                            -ToolName "Empty Recycle Bin" `
                            -Steps @("PLAN FAILED: Cannot enumerate recycle bin items") `
                            -AffectedResources @("RecycleBin (unknown)") `
                            -RequiresAdmin $false `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Evidence @{
                                PlanFailed      = $true
                                FailureReason   = "Enumeration failed: $($_.Exception.Message)"
                                FailureCode     = "RECYCLEBIN_ENUM_FAILED"
                                DiscoveryMethod = "Shell.Application"
                                DiscoveryErrors = $discoveryErrors
                            }
                    }

                    $sizeInMB = [math]::Round($totalSize / 1MB, 2)

                    # --- Stage 3: Build concrete actions ---
                    # 0 items → Skipped (not Success), Impact=None
                    if ($itemCount -eq 0) {
                        return New-DryRunPlan `
                            -ToolId "empty-recycle-bin" `
                            -ToolName "Empty Recycle Bin" `
                            -Steps @("No items in recycle bin - no action required") `
                            -AffectedResources @("RecycleBin (empty)") `
                            -RequiresAdmin $false `
                            -Reversible $false `
                            -EstimatedImpact "None" `
                            -Preconditions @("No admin required") `
                            -Evidence @{
                                Preconditions   = @{ IsAdmin = "Not required" }
                                DiscoveryMethod = "Shell.Application"
                                SampleLimit     = $sampleLimit
                                DiscoveryErrors = @()
                                Findings = @{
                                    ItemCount   = 0
                                    TotalSizeMB = 0
                                    SampleItems = @()
                                }
                            }
                    }

                    # Items found → build WOULD_DELETE plan
                    $actions = @(
                        (New-DryRunStep -Verb WOULD_DELETE -Target "recycle bin contents" -Detail "$itemCount items, $sizeInMB MB").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "empty-recycle-bin" `
                        -ToolName "Empty Recycle Bin" `
                        -Steps $actions `
                        -AffectedResources @("RecycleBin ($itemCount items, $sizeInMB MB)") `
                        -RequiresAdmin $false `
                        -Reversible $false `
                        -EstimatedImpact $(if ($sizeInMB -gt 100) { "Medium" } elseif ($itemCount -gt 0) { "Low" } else { "None" }) `
                        -Preconditions @("No admin required") `
                        -Evidence @{
                            Preconditions   = @{ IsAdmin = "Not required" }
                            DiscoveryMethod = "Shell.Application"
                            SampleLimit     = $sampleLimit
                            DiscoveryErrors = @()
                            Findings = @{
                                ItemCount   = $itemCount
                                TotalSizeMB = $sizeInMB
                                SampleItems = $binItems
                            }
                        }
                }

                "dism-restore-health" = {
                    # === PLAN PHASE: DISM RestoreHealth (low branching) ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "dism-restore-health" `
                            -ToolName "DISM RestoreHealth" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to run DISM."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    $dismPath = "$env:SystemRoot\System32\DISM.exe"
                    $dismExists = Test-Path $dismPath

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_EXEC -Target "DISM /Online /Cleanup-Image /RestoreHealth" -Detail "Repairs Windows component store from Windows Update").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "dism-restore-health" `
                        -ToolName "DISM RestoreHealth" `
                        -Steps $actions `
                        -AffectedResources @("Windows Component Store (WinSxS)") `
                        -RequiresAdmin $true `
                        -Reversible $false `
                        -EstimatedImpact "High" `
                        -Preconditions @("Admin: $isAdmin", "DISM.exe: $(if ($dismExists) { 'Found' } else { 'NOT FOUND' })") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin; DISMExists = $dismExists }
                            Findings      = @{ DISMPath = $dismPath }
                        }
                }

                "sfc-scannow" = {
                    # === PLAN PHASE: SFC Scan (low branching) ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "sfc-scannow" `
                            -ToolName "SFC Scan" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to run SFC."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    $sfcPath = "$env:SystemRoot\System32\sfc.exe"
                    $sfcExists = Test-Path $sfcPath

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_EXEC -Target "sfc /scannow" -Detail "Scans and repairs protected Windows system files").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "sfc-scannow" `
                        -ToolName "SFC Scan" `
                        -Steps $actions `
                        -AffectedResources @("Protected system files (System32)") `
                        -RequiresAdmin $true `
                        -Reversible $false `
                        -EstimatedImpact "High" `
                        -Preconditions @("Admin: $isAdmin", "sfc.exe: $(if ($sfcExists) { 'Found' } else { 'NOT FOUND' })") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin; SFCExists = $sfcExists }
                            Findings      = @{ SFCPath = $sfcPath }
                        }
                }

                "gpo-enable" = {
                    # === PLAN PHASE: Check current GPO state before enabling ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "gpo-enable" `
                            -ToolName "Enable Group Policy" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to modify Group Policy."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    # === READ-ONLY DISCOVERY: Check current registry state ===
                    $regPaths = @(
                        'HKCU:\Software\Policies\Microsoft\Control Panel\International',
                        'HKLM:\Software\Policies\Microsoft\Control Panel\International'
                    )
                    $valueNames = @('PreventGeoIdChange', 'PreventUserOverrides', 'HideLocaleSelectAndCustomize', 'RestrictUserLocales')
                    $currentState = @{}

                    foreach ($path in $regPaths) {
                        $hive = if ($path -match '^HKCU') { 'HKCU' } else { 'HKLM' }
                        $pathExists = Test-Path $path
                        $values = @{}
                        if ($pathExists) {
                            foreach ($name in $valueNames) {
                                try {
                                    $val = Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop
                                    $values[$name] = $val
                                } catch {
                                    $values[$name] = '(not set)'
                                }
                            }
                        }
                        $currentState[$hive] = @{ PathExists = $pathExists; Values = $values }
                    }

                    $actions = @()
                    foreach ($path in $regPaths) {
                        $hive = if ($path -match '^HKCU') { 'HKCU' } else { 'HKLM' }
                        if (-not (Test-Path $path)) {
                            $actions += (New-DryRunStep -Verb WOULD_CREATE -Target "registry key: $path").Summary
                        }
                        $actions += (New-DryRunStep -Verb WOULD_SET -Target "$($hive):PreventGeoIdChange" -Detail "DWORD = 1").Summary
                        $actions += (New-DryRunStep -Verb WOULD_SET -Target "$($hive):PreventUserOverrides" -Detail "DWORD = 1").Summary
                        $actions += (New-DryRunStep -Verb WOULD_SET -Target "$($hive):HideLocaleSelectAndCustomize" -Detail "DWORD = 1").Summary
                        $actions += (New-DryRunStep -Verb WOULD_SET -Target "$($hive):RestrictUserLocales" -Detail "String = (empty)").Summary
                    }

                    New-DryRunPlan `
                        -ToolId "gpo-enable" `
                        -ToolName "Enable Group Policy" `
                        -Steps $actions `
                        -AffectedResources @($regPaths) `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact "Medium" `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{ CurrentState = $currentState }
                        }
                }

                "gpo-disable" = {
                    # === PLAN PHASE: Check current GPO state before disabling ===
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "gpo-disable" `
                            -ToolName "Disable Group Policy" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to modify Group Policy."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    # === READ-ONLY DISCOVERY: Check which values currently exist ===
                    $regPaths = @(
                        'HKCU:\Software\Policies\Microsoft\Control Panel\International',
                        'HKLM:\Software\Policies\Microsoft\Control Panel\International'
                    )
                    $valueNames = @('PreventGeoIdChange', 'PreventUserOverrides', 'HideLocaleSelectAndCustomize', 'RestrictUserLocales')
                    $currentState = @{}
                    $existingValueCount = 0

                    foreach ($path in $regPaths) {
                        $hive = if ($path -match '^HKCU') { 'HKCU' } else { 'HKLM' }
                        $pathExists = Test-Path $path
                        $values = @{}
                        if ($pathExists) {
                            foreach ($name in $valueNames) {
                                try {
                                    $val = Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop
                                    $values[$name] = $val
                                    $existingValueCount++
                                } catch {
                                    $values[$name] = '(not set)'
                                }
                            }
                        }
                        $currentState[$hive] = @{ PathExists = $pathExists; Values = $values }
                    }

                    # If no policy values exist, nothing to do
                    if ($existingValueCount -eq 0) {
                        return New-DryRunPlan `
                            -ToolId "gpo-disable" `
                            -ToolName "Disable Group Policy" `
                            -Steps @("No policy restrictions found - no action required") `
                            -AffectedResources @("Registry (no matching values)") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "None" `
                            -Preconditions @("Admin: $isAdmin") `
                            -Evidence @{
                                Preconditions = @{ IsAdmin = $isAdmin }
                                Findings      = @{ CurrentState = $currentState; ExistingValueCount = 0 }
                            }
                    }

                    $actions = @()
                    foreach ($path in $regPaths) {
                        $hive = if ($path -match '^HKCU') { 'HKCU' } else { 'HKLM' }
                        if (Test-Path $path) {
                            foreach ($name in $valueNames) {
                                try {
                                    Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop | Out-Null
                                    $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "$($hive):$name" -Detail "Remove policy restriction").Summary
                                } catch {
                                    # Value doesn't exist, skip
                                }
                            }
                        }
                    }

                    New-DryRunPlan `
                        -ToolId "gpo-disable" `
                        -ToolName "Disable Group Policy" `
                        -Steps $actions `
                        -AffectedResources @($regPaths | Where-Object { Test-Path $_ }) `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact "Medium" `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{ CurrentState = $currentState; ExistingValueCount = $existingValueCount }
                        }
                }

                "dns-cache-flush" = {
                    # === PLAN PHASE: DNS flush doesn't require admin ===
                    $dnsCache = @()
                    try {
                        # Get sample of DNS cache entries (read-only)
                        $entries = Get-DnsClientCache -ErrorAction Stop | Select-Object -First 10
                        foreach ($e in $entries) {
                            $dnsCache += @{
                                Entry = $e.Entry
                                RecordType = $e.Type
                                TTL = $e.TimeToLive
                            }
                        }
                    } catch {
                        # Get-DnsClientCache may not be available
                    }

                    $totalEntries = 0
                    try {
                        $totalEntries = (Get-DnsClientCache -ErrorAction Stop | Measure-Object).Count
                    } catch {}

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_EXEC -Target "DNS resolver cache flush" -Detail "ipconfig /flushdns").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "dns-cache-flush" `
                        -ToolName "Flush DNS Cache" `
                        -Steps $actions `
                        -AffectedResources @("DNS Resolver Cache ($totalEntries entries)") `
                        -RequiresAdmin $false `
                        -Reversible $false `
                        -EstimatedImpact "Low" `
                        -Preconditions @("No admin required") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = "Not required" }
                            Findings = @{
                                CacheEntriesSample = $dnsCache
                                TotalEntries = $totalEntries
                            }
                        }
                }

                "bt-reset-com-ports" = {
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "bt-reset-com-ports" `
                            -ToolName "Reset COM Port Numbers" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to read and modify the COM Name Arbiter registry."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    $arbiterPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
                    $allocatedPorts = @()
                    $comDbSize = 0
                    try {
                        $comDb = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB
                        if ($comDb) {
                            $comDbSize = $comDb.Length
                            for ($i = 0; $i -lt ($comDb.Length * 8); $i++) {
                                $byteIndex = [Math]::Floor($i / 8)
                                $bitIndex = $i % 8
                                if ($comDb[$byteIndex] -band (1 -shl $bitIndex)) {
                                    $allocatedPorts += "COM$($i + 1)"
                                }
                            }
                        }
                    } catch {
                        # ComDB not present -- already clean
                    }

                    if ($allocatedPorts.Count -eq 0) {
                        return New-DryRunPlan `
                            -ToolId "bt-reset-com-ports" `
                            -ToolName "Reset COM Port Numbers" `
                            -Steps @("No action required -- COM Name Arbiter is already clean") `
                            -AffectedResources @("COM Name Arbiter (0 ports allocated)") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "None" `
                            -Preconditions @("Admin: $isAdmin") `
                            -Evidence @{
                                Preconditions = @{ IsAdmin = $isAdmin }
                                Findings      = @{ AllocatedPorts = @(); PortCount = 0; ComDbSize = $comDbSize }
                            }
                    }

                    $actions = @(
                        (New-DryRunStep -Verb WOULD_CREATE -Target "registry backup" -Detail "COM Name Arbiter .reg export").Summary,
                        (New-DryRunStep -Verb WOULD_DELETE -Target "COM Name Arbiter ComDB value" -Detail "$($allocatedPorts.Count) port slots ($($allocatedPorts -join ', '))").Summary
                    )

                    New-DryRunPlan `
                        -ToolId "bt-reset-com-ports" `
                        -ToolName "Reset COM Port Numbers" `
                        -Steps $actions `
                        -AffectedResources @("HKLM:\...\COM Name Arbiter\ComDB") `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact $(if ($allocatedPorts.Count -gt 10) { "Medium" } else { "Low" }) `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{
                                AllocatedPorts = $allocatedPorts
                                PortCount      = $allocatedPorts.Count
                                ComDbSize      = $comDbSize
                            }
                        }
                }

                "bt-clean-ports" = {
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "bt-clean-ports" `
                            -ToolName "Clean Bluetooth Ports" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to enumerate PnP devices and modify the COM Name Arbiter."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    # Same plan the live handler removes from. This previously
                    # matched only the all-zero set while the live path also
                    # removed non-present nodes, so the preview under-reported
                    # a destructive scope.
                    #
                    # A planning failure must NOT fall through as an empty target
                    # list: "0 ghost ports found" and "could not determine the
                    # ghost ports" are different facts that rendered identically,
                    # and the empty one reads to an operator as nothing to clean.
                    $ghostPorts = @()
                    try {
                        $ghostPorts = @((Get-BtGhostPortPlanOrThrow).Targets)
                    } catch {
                        return New-DryRunPlan `
                            -ToolId "bt-clean-ports" `
                            -ToolName "Clean Bluetooth Ports" `
                            -Steps @("PLAN FAILED: cannot determine which ports would be removed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: $isAdmin") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Ghost-port enumeration failed: $($_.Exception.Message)"
                                Preconditions = @{ IsAdmin = $isAdmin }
                                Findings      = @{}
                            }
                    }

                    $arbiterPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
                    $allocatedPorts = @()
                    try {
                        $comDb = (Get-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop).ComDB
                        if ($comDb) {
                            for ($i = 0; $i -lt ($comDb.Length * 8); $i++) {
                                $byteIndex = [Math]::Floor($i / 8)
                                $bitIndex = $i % 8
                                if ($comDb[$byteIndex] -band (1 -shl $bitIndex)) {
                                    $allocatedPorts += "COM$($i + 1)"
                                }
                            }
                        }
                    } catch {}

                    if ($ghostPorts.Count -eq 0 -and $allocatedPorts.Count -eq 0) {
                        return New-DryRunPlan `
                            -ToolId "bt-clean-ports" `
                            -ToolName "Clean Bluetooth Ports" `
                            -Steps @("No action required -- no ghost ports or COM allocations found") `
                            -AffectedResources @("BTHENUM (0 ghosts)", "COM Name Arbiter (0 ports)") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "None" `
                            -Preconditions @("Admin: $isAdmin") `
                            -Evidence @{
                                Preconditions = @{ IsAdmin = $isAdmin }
                                Findings      = @{ GhostPorts = @(); AllocatedPorts = @() }
                            }
                    }

                    $actions = @()
                    $affected = @()
                    $actions += (New-DryRunStep -Verb WOULD_CREATE -Target "registry backup" -Detail "COM Name Arbiter .reg export").Summary
                    foreach ($ghost in $ghostPorts) {
                        # Reason is shown, not just the count: "3 ghost ports" hides
                        # that two of them are being removed for being absent.
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost PnP device" -Detail "$($ghost.InstanceId) [$($ghost.Reason)]").Summary
                        $affected += $ghost.InstanceId
                    }
                    if ($allocatedPorts.Count -gt 0) {
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "COM Name Arbiter ComDB value" -Detail "$($allocatedPorts.Count) port slots").Summary
                        $affected += "HKLM:\...\COM Name Arbiter\ComDB"
                    }

                    $ghostInfo = @()
                    foreach ($g in $ghostPorts) {
                        $ghostInfo += @{ InstanceId = $g.InstanceId; Status = "$($g.Status)"; FriendlyName = $g.FriendlyName; Reason = $g.Reason }
                    }

                    New-DryRunPlan `
                        -ToolId "bt-clean-ports" `
                        -ToolName "Clean Bluetooth Ports" `
                        -Steps $actions `
                        -AffectedResources $affected `
                        -RequiresAdmin $true `
                        -Reversible $false `
                        -EstimatedImpact $(if ($ghostPorts.Count -gt 5) { "Medium" } else { "Low" }) `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{
                                GhostPorts     = $ghostInfo
                                GhostCount     = $ghostPorts.Count
                                AllocatedPorts = $allocatedPorts
                                PortCount      = $allocatedPorts.Count
                            }
                        }
                }

                "bt-stack-reset" = {
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "bt-stack-reset" `
                            -ToolName "Full Bluetooth Stack Reset" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to access BTHPORT registry and remove PnP devices."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    $devicesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
                    $localSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\LocalServices'

                    $pairedDevices = @()
                    if (Test-Path $devicesPath) {
                        $devSubkeys = Get-ChildItem $devicesPath -ErrorAction SilentlyContinue
                        foreach ($dev in $devSubkeys) {
                            $props = Get-ItemProperty $dev.PSPath -ErrorAction SilentlyContinue
                            $devName = '(unknown)'
                            if ($props.PSObject.Properties.Name -contains 'Name') {
                                try { $devName = [System.Text.Encoding]::UTF8.GetString($props.Name).TrimEnd("`0") } catch {}
                            }
                            $pairedDevices += @{ MAC = $dev.PSChildName; Name = $devName }
                        }
                    }

                    $localServices = @()
                    if (Test-Path $localSvcPath) {
                        $svcSubkeys = Get-ChildItem $localSvcPath -ErrorAction SilentlyContinue
                        foreach ($svc in $svcSubkeys) {
                            $localServices += $svc.PSChildName
                        }
                    }

                    # Shared plan: the stack reset removes the same ghost set as
                    # Clean Ports, so its preview must not compute a smaller one.
                    # As above, a planning failure is reported as a failure rather
                    # than silently becoming an empty removal list.
                    $ghostPorts = @()
                    try {
                        $ghostPorts = @((Get-BtGhostPortPlanOrThrow).Targets)
                    } catch {
                        return New-DryRunPlan `
                            -ToolId "bt-stack-reset" `
                            -ToolName "Full Bluetooth Stack Reset" `
                            -Steps @("PLAN FAILED: cannot determine which ports would be removed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $false `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: $isAdmin") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Ghost-port enumeration failed: $($_.Exception.Message)"
                                Preconditions = @{ IsAdmin = $isAdmin }
                                Findings      = @{}
                            }
                    }

                    $allocatedPorts = @()
                    try {
                        $comDb = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter' -Name 'ComDB' -ErrorAction Stop).ComDB
                        if ($comDb) {
                            for ($i = 0; $i -lt ($comDb.Length * 8); $i++) {
                                $byteIndex = [Math]::Floor($i / 8)
                                $bitIndex = $i % 8
                                if ($comDb[$byteIndex] -band (1 -shl $bitIndex)) {
                                    $allocatedPorts += "COM$($i + 1)"
                                }
                            }
                        }
                    } catch {}

                    $actions = @()
                    $affected = @()

                    $actions += (New-DryRunStep -Verb WOULD_CREATE -Target "registry backup" -Detail "BTHPORT + COM Name Arbiter .reg exports").Summary

                    foreach ($dev in $pairedDevices) {
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "paired device: $($dev.Name)" -Detail "MAC $($dev.MAC)").Summary
                        $affected += "BTHPORT\Devices\$($dev.MAC)"
                    }

                    foreach ($svc in $localServices) {
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "local BT service: $svc").Summary
                        $affected += "BTHPORT\LocalServices\$svc"
                    }

                    foreach ($ghost in $ghostPorts) {
                        # Reason is shown, not just the count: "3 ghost ports" hides
                        # that two of them are being removed for being absent.
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost PnP device" -Detail "$($ghost.InstanceId) [$($ghost.Reason)]").Summary
                        $affected += $ghost.InstanceId
                    }

                    if ($allocatedPorts.Count -gt 0) {
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "COM Name Arbiter ComDB value" -Detail "$($allocatedPorts.Count) port slots").Summary
                        $affected += "HKLM:\...\COM Name Arbiter\ComDB"
                    }

                    $actions += (New-DryRunStep -Verb WOULD_EXEC -Target "reboot prompt" -Detail "system restart required to complete stack reset").Summary

                    if ($actions.Count -le 1) {
                        $actions = @("No Bluetooth state found -- stack may already be clean")
                    }

                    $ghostInfo = @()
                    foreach ($g in $ghostPorts) {
                        $ghostInfo += @{ InstanceId = $g.InstanceId; Status = "$($g.Status)" }
                    }

                    New-DryRunPlan `
                        -ToolId "bt-stack-reset" `
                        -ToolName "Full Bluetooth Stack Reset" `
                        -Steps $actions `
                        -AffectedResources $affected `
                        -RequiresAdmin $true `
                        -Reversible $false `
                        -EstimatedImpact "High" `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{
                                PairedDevices  = $pairedDevices
                                DeviceCount    = $pairedDevices.Count
                                LocalServices  = $localServices
                                ServiceCount   = $localServices.Count
                                GhostPorts     = $ghostInfo
                                GhostCount     = $ghostPorts.Count
                                AllocatedPorts = $allocatedPorts
                                PortCount      = $allocatedPorts.Count
                            }
                        }
                }

                "bt-disable-usb-suspend" = {
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                    if (-not $isAdmin) {
                        return New-DryRunPlan `
                            -ToolId "bt-disable-usb-suspend" `
                            -ToolName "Disable USB Suspend" `
                            -Steps @("PLAN FAILED: Cannot proceed") `
                            -AffectedResources @("Unknown - planning aborted") `
                            -RequiresAdmin $true `
                            -Reversible $true `
                            -EstimatedImpact "Unknown" `
                            -Preconditions @("Admin: FAILED") `
                            -Evidence @{
                                PlanFailed    = $true
                                FailureReason = "Administrator privileges are required to modify power plan settings."
                                Preconditions = @{ IsAdmin = $false }
                                Findings      = @{}
                            }
                    }

                    $usbSubGuid  = '2a737441-1930-4402-8d77-b2bebba308a3'
                    $usbSuspGuid = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'

                    $acVal = 1; $dcVal = 1
                    try {
                        $pcfgOut = powercfg /query SCHEME_CURRENT $usbSubGuid $usbSuspGuid
                        foreach ($line in $pcfgOut) {
                            if ($line -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') { $acVal = [Convert]::ToInt32($Matches[1], 16) }
                            if ($line -match 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')  { $dcVal = [Convert]::ToInt32($Matches[1], 16) }
                        }
                    } catch {}

                    $actions = @()
                    $affected = @()

                    if ($acVal -eq 0 -and $dcVal -eq 0) {
                        $actions = @("USB selective suspend is already DISABLED in the active power plan -- no change needed")
                    } else {
                        if ($acVal -ne 0) {
                            $actions += (New-DryRunStep -Verb WOULD_SET -Target "USB Selective Suspend (AC)" -Detail "powercfg: set AC index to 0 (disabled, currently $acVal)").Summary
                            $affected += "Power Plan: USB selective suspend setting (AC)"
                        }
                        if ($dcVal -ne 0) {
                            $actions += (New-DryRunStep -Verb WOULD_SET -Target "USB Selective Suspend (DC)" -Detail "powercfg: set DC index to 0 (disabled, currently $dcVal)").Summary
                            $affected += "Power Plan: USB selective suspend setting (DC)"
                        }
                        $actions += (New-DryRunStep -Verb WOULD_EXEC -Target "powercfg /setactive SCHEME_CURRENT" -Detail "Apply updated power plan immediately -- no reboot required").Summary
                    }

                    $impact = if ($acVal -eq 0 -and $dcVal -eq 0) { "None" } else { "Low" }
                    New-DryRunPlan `
                        -ToolId "bt-disable-usb-suspend" `
                        -ToolName "Disable USB Suspend" `
                        -Steps $actions `
                        -AffectedResources $affected `
                        -RequiresAdmin $true `
                        -Reversible $true `
                        -EstimatedImpact $impact `
                        -Preconditions @("Admin: $isAdmin") `
                        -Evidence @{
                            Preconditions = @{ IsAdmin = $isAdmin }
                            Findings      = @{
                                PowerPlan_AC_Current = $acVal
                                PowerPlan_DC_Current = $dcVal
                                UsbSubgroupGuid      = $usbSubGuid
                                UsbSuspendGuid       = $usbSuspGuid
                            }
                        }
                }
            }

            # Check if we have a plan generator for this tool
            if (-not $planGenerators.ContainsKey($ToolId)) {
                $refusal = New-DryRunRefusal -ToolId $ToolId -ToolName $ToolName
                $message = @"
MODE: $modeBanner

DRY RUN REFUSED

Tool: $ToolName

REASON:
$($refusal.FailureReason)

Code: $($refusal.FailureCode)

No system changes were made.
"@
                [System.Windows.Forms.MessageBox]::Show(
                    $message,
                    "Dry Run Refused - $ToolName",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                return
            }

            # Check for DryRun module
            if (-not (Get-Command Invoke-DryRunGuarded -ErrorAction SilentlyContinue)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "DryRun.psm1 module not loaded.`n`nCannot execute dry run.",
                    "Dry Run Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }

            # Execute dry run
            try {
                $result = Invoke-DryRunGuarded `
                    -ToolId $ToolId `
                    -DryRun `
                    -PlanScript $planGenerators[$ToolId] `
                    -ExecuteScript { param($Plan) } `
                    -Category "AdminChange" `
                    -ToolCategory "Audio" `
                    -Source "UI"

                # === BRANCH ON OUTCOME, not on "is dry run" ===
                # Outcome = "Failed" → Plan phase failed (show failure dialog)
                # Outcome = "Skipped" → Plan succeeded, execution skipped (show complete dialog)
                if ($result.Outcome -eq "Failed") {
                    # === PLAN FAILURE: Show structured failure message ===
                    $reasonText = "Planning phase failed."
                    if ($result.Plan -and $result.Plan.Evidence -and $result.Plan.Evidence.FailureReason) {
                        $reasonText = $result.Plan.Evidence.FailureReason
                    }

                    $preconditionText = ""
                    if ($result.Plan -and $result.Plan.Evidence -and $result.Plan.Evidence.Preconditions) {
                        $preconds = $result.Plan.Evidence.Preconditions
                        $adminVal = if ($null -ne $preconds.IsAdmin) { $preconds.IsAdmin } else { "Unknown" }
                        $restoreVal = if ($null -ne $preconds.RestorePointCapable) { $preconds.RestorePointCapable } else { "Unknown" }
                        $preconditionText = @"

PRECONDITIONS:
  Admin: $adminVal
  Restore Point: $restoreVal
"@
                    }

                    $modeLine = if ($result.DryRunSource) { "MODE: DRY RUN (Source: $($result.DryRunSource))" } else { "MODE: $modeBanner" }
                    $message = @"
$modeLine

DRY RUN FAILED DURING PLANNING

Tool: $ToolName

REASON:
$reasonText
$preconditionText

No actions were planned.
No system changes were made.

This failure has been recorded in the session ledger.
"@

                    [System.Windows.Forms.MessageBox]::Show(
                        $message,
                        "Dry Run Failed - $ToolName",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                } else {
                    # === PLAN SUCCESS (Outcome = Skipped): Show findings and planned actions ===
                    $planSteps = $result.Plan.Steps -join "`n  - "
                    $resources = $result.Plan.AffectedResources -join "`n  - "

                    $preconditions = ""
                    $findings = ""
                    $evidence = $result.Plan.Evidence

                    if ($evidence) {
                        if ($evidence.Preconditions) {
                            $preconds = $evidence.Preconditions
                            $adminVal = if ($null -ne $preconds.IsAdmin) { $preconds.IsAdmin } else { "Unknown" }
                            $restoreVal = if ($null -ne $preconds.RestorePointCapable) { $preconds.RestorePointCapable } else { "Unknown" }
                            $preconditions = "PRECONDITIONS:`n"
                            $preconditions += "  Admin: $adminVal`n"
                            $preconditions += "  Restore Point: $restoreVal`n"
                        }
                        if ($evidence.Findings) {
                            $findingsData = $evidence.Findings
                            $driverCount = if ($null -ne $findingsData.DriverCount) { $findingsData.DriverCount } else { 0 }
                            $findings = "SYSTEM INSPECTION:`n"
                            $findings += "  Driver packages found: $driverCount`n"
                            if ($findingsData.DriversFound -and $findingsData.DriversFound.Count -gt 0) {
                                foreach ($drv in $findingsData.DriversFound) {
                                    $findings += "    - $($drv.Driver): $($drv.OriginalFileName)`n"
                                    $findings += "      Provider: $($drv.ProviderName), Class: $($drv.ClassName)`n"
                                }
                            }
                        }
                    }

                    $modeLine = if ($result.DryRunSource) { "MODE: DRY RUN (Source: $($result.DryRunSource))" } else { "MODE: $modeBanner" }
                    $message = @"
$modeLine

DRY RUN COMPLETE (NO EXECUTION)

Tool: $ToolName

$preconditions
$findings
PLANNED ACTIONS:
  - $planSteps

AFFECTED RESOURCES:
  - $resources

This dry run has been recorded in the session ledger.
No system changes were made.
"@

                    [System.Windows.Forms.MessageBox]::Show(
                        $message,
                        "Dry Run Result - $ToolName",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }

                # Update results view if available
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) {
                    Update-ResultsDiagnosticsView
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Dry Run failed: $($_.Exception.Message)",
                    "Dry Run Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        }

        # Tool definitions with metadata (descriptions, groups)
        # Key = tool name (matches button handler), Value = @{ Description, Group }
        $script:ToolDefinitions = @{
            # Network tools
            "Run Network Test"         = @{ Description = "Full network diagnostics"; Group = "Diagnostics" }
            "Domain, IP && Ports Test" = @{ Description = "Domain resolution and port checks"; Group = "Diagnostics" }
            "Open Speedtest.net"       = @{ Description = "Launch browser speed test"; Group = "External" }
            "Network Reset" = @{
                Description = "Reset TCP/IP, Winsock, DNS"
                Group = "Actions"
                ToolId = "network-reset"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Flush DNS Cache" = @{
                Description = "Clear DNS resolver cache"
                Group = "Actions"
                ToolId = "dns-cache-flush"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            # Audio tools
            "Remove Intel SST Audio Driver" = @{
                Description = "Uninstall problematic SST driver"
                Group = "Actions"
                ToolId = "intel-sst-removal"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Restart Audio Service" = @{
                Description = "Restart Windows Audio service"
                Group = "Actions"
                ToolId = "audio-service-restart"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Sound Panel"              = @{ Description = "Open sound control panel"; Group = "Settings" }
            "Run Bluetooth Diagnostics" = @{
                Description = "Run Bluetooth probe and record findings"
                Group = "Diagnostics"
                ToolId = "bluetooth-diagnostics"
                SupportsDryRun = $false
                MutatesSystem = $false
            }
            "Reset COM Port Numbers" = @{
                Description = "Clear COM Name Arbiter bitmap"
                Group = "Actions"
                ToolId = "bt-reset-com-ports"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Clean Bluetooth Ports" = @{
                Description = "Remove ghost BTHENUM entries + reset COM arbiter"
                Group = "Actions"
                ToolId = "bt-clean-ports"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Full Bluetooth Stack Reset" = @{
                Description = "Wipe all BT pairing data -- requires reboot"
                Group = "Actions"
                ToolId = "bt-stack-reset"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Disable USB Suspend" = @{
                Description = "Disable USB selective suspend on BT adapter"
                Group = "Actions"
                ToolId = "bt-disable-usb-suspend"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            # Maintenance tools
            "DISM Restore Health"      = @{ Description = "Repair Windows component store"; Group = "Repair" }
            "/sfc scannow"             = @{ Description = "Scan and repair system files"; Group = "Repair" }
            "Defrag && Optimize"       = @{ Description = "Optimize drive performance"; Group = "Cleanup" }
            "Delete old backups"       = @{ Description = "Remove Zengar backup files"; Group = "Cleanup" }
            "Disk Cleanup"             = @{ Description = "Windows disk cleanup utility"; Group = "Cleanup" }
            "Empty Recycle Bin"        = @{
                Description = "Clear recycle bin contents"
                Group = "Cleanup"
                ToolId = "empty-recycle-bin"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            # System tools
            "Copy System Info"         = @{ Description = "Copy system details to clipboard"; Group = "Info" }
            "Copy Device Name"         = @{ Description = "Copy computer name"; Group = "Info" }
            "Copy Serial Number"       = @{ Description = "Copy BIOS serial number"; Group = "Info" }
            "Machine Identifiers"      = @{
                Description = "Show the MAC/ProcessorID/DiskID licensing reads, and why one is missing"
                Group = "Diagnostics"
                ToolId = "machine-identifiers"
                SupportsDryRun = $false
                MutatesSystem = $false
            }
            "Device Manager"           = @{ Description = "Open device manager"; Group = "Settings" }
            "Task Manager"             = @{ Description = "Open task manager"; Group = "Settings" }
            "Control Panel"            = @{ Description = "Open control panel"; Group = "Settings" }
            # zAmp tools
            "Uninstall zAmp Drivers"   = @{
                Description = "Canonical Zengar driver removal"
                Group = "Actions"
                ToolId = "zamp-driver-uninstall"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            "Repair zAmp Driver Trust" = @{
                Description = "Fix driver install failure 0x800B010A (cert chain + reinstall)"
                Group = "Actions"
                ToolId = "zamp-driver-trust-repair"
                SupportsDryRun = $true
                MutatesSystem = $true
            }
            # Zengar UI tools
            "Apply Win 11 Start Menu"  = @{ Description = "Apply custom Start Menu layout"; Group = "UI" }
            "Apply branding colors"    = @{ Description = "Apply Zengar brand colors"; Group = "UI" }
            "Pin Taskbar Icons"        = @{ Description = "Pin standard icons to taskbar"; Group = "UI" }
            "Apply Win Update Icon"    = @{ Description = "Apply Windows Update icon"; Group = "UI" }
            # Updates tools
            "MS Store Updates"         = @{ Description = "Check Microsoft Store updates"; Group = "Updates" }
            "Update Surface Drivers"   = @{ Description = "Update Surface firmware"; Group = "Updates" }
            "Microsoft Update Catalog" = @{ Description = "Open MS Update Catalog"; Group = "Updates" }
            "Windows Insider"          = @{ Description = "Open Windows Insider settings"; Group = "Updates" }
            # Support tools
            "Collect Support Bundle" = @{
                Description = "Collect a full diagnostic bundle for engineering escalation (read-only)"
                Group = "Diagnostics"
                ToolId = "support-bundle-collect"
                SupportsDryRun = $false
                MutatesSystem = $false
            }
            # NO Shortcuts tools
            "%programdata%"            = @{ Description = "Open ProgramData folder"; Group = "Shortcuts" }
            "%localappdata%"           = @{ Description = "Open LocalAppData folder"; Group = "Shortcuts" }
            "C:\zengar"                = @{ Description = "Open Zengar folder"; Group = "Shortcuts" }
            "Documents\ScreenConnect"  = @{ Description = "Open ScreenConnect folder"; Group = "Shortcuts" }
        }

        # Category → Tool mappings (uses $script:Categories as keys)
        $script:CategoryTools = [ordered]@{
            "Network"      = @("Run Network Test", "Domain, IP && Ports Test", "Network Reset", "Flush DNS Cache", "Open Speedtest.net")
            "Audio"        = @("Remove Intel SST Audio Driver", "Restart Audio Service", "Sound Panel", "Run Bluetooth Diagnostics")
            "Bluetooth"    = @("Run Bluetooth Diagnostics", "Reset COM Port Numbers", "Clean Bluetooth Ports", "Full Bluetooth Stack Reset", "Disable USB Suspend")
            "System"       = @("Copy System Info", "Copy Device Name", "Copy Serial Number", "Machine Identifiers", "Device Manager", "Task Manager", "Control Panel")
            "zAmp"         = @("Uninstall zAmp Drivers", "Repair zAmp Driver Trust")
            "Zengar UI"    = @("Apply Win 11 Start Menu", "Apply branding colors", "Pin Taskbar Icons", "Apply Win Update Icon")
            "Updates"      = @("MS Store Updates", "Update Surface Drivers", "Microsoft Update Catalog", "Windows Insider")
            "Disk"         = @("DISM Restore Health", "/sfc scannow", "Defrag && Optimize", "Delete old backups", "Disk Cleanup", "Empty Recycle Bin")
            "NO Shortcuts" = @("%programdata%", "%localappdata%", "C:\zengar", "Documents\ScreenConnect")
            "Support"      = @("Collect Support Bundle")
        }

        # Phase 7.2: Store category badge references for pattern-aware surfacing
        if (-not $script:CategoryBadges) { $script:CategoryBadges = @{} }

        # Phase 7.3: Store tool button references for re-run functionality
        # REGRESSION GUARD: This hashtable persists - never cleared on category switch
        if (-not $script:ToolButtonRegistry) { $script:ToolButtonRegistry = @{} }

        # Flight Recorder coordination: BtRecordingActive is set for the duration of
        # a Bluetooth Flight Recorder session; the mutating-tool click gate consults
        # it to block bt-stack-reset and to record other repair tools the operator
        # runs mid-recording into BtRecOperatorActions (attribution in the evidence).
        $script:BtRecordingActive    = $false
        $script:BtRecOperatorActions = [System.Collections.ArrayList]::new()

        # Store category panels for selection switching (created once, never recreated)
        $script:CategoryPanels = @{}
        $script:CategoryListButtons = @{}
        $script:CategoryListBadges = @{}

        # === SPLIT CONTAINER: Left (categories) | Right (tools) ===
        $splitContainer = New-Object System.Windows.Forms.SplitContainer
        $splitContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
        $splitContainer.Orientation = [System.Windows.Forms.Orientation]::Vertical
        # Initial SplitterDistance is a baseline; recomputed from button widths after
        # category buttons are created so it adapts to current font/DPI scaling.
        $splitContainer.SplitterDistance = 140
        $splitContainer.SplitterWidth = 4
        $splitContainer.FixedPanel = [System.Windows.Forms.FixedPanel]::Panel1
        # Allow manual drag as fallback when text scaling exceeds what AutoScaleMode::Dpi handles.
        $splitContainer.IsSplitterFixed = $false
        $splitContainer.Panel1MinSize = 100
        $splitContainer.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
        $tabPage.Controls.Add($splitContainer)

        # === LEFT PANE: Category List ===
        $categoryListPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $categoryListPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $categoryListPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $categoryListPanel.WrapContents = $false
        $categoryListPanel.AutoScroll = $true
        $categoryListPanel.Padding = New-Object System.Windows.Forms.Padding(8, 12, 8, 8)
        $categoryListPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
        $splitContainer.Panel1.Controls.Add($categoryListPanel)

        # Category list header
        $categoryHeader = New-Object System.Windows.Forms.Label
        $categoryHeader.Text = "Categories"
        $categoryHeader.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $categoryHeader.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
        $categoryHeader.AutoSize = $true
        $categoryHeader.Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 8)
        $categoryListPanel.Controls.Add($categoryHeader)

        # === RIGHT PANE: Tool Detail Container ===
        $detailContainer = New-Object System.Windows.Forms.Panel
        $detailContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
        $detailContainer.AutoScroll = $true
        $detailContainer.Padding = New-Object System.Windows.Forms.Padding(15, 10, 15, 10)
        $detailContainer.BackColor = [System.Drawing.Color]::White
        $splitContainer.Panel2.Controls.Add($detailContainer)

        # Helper: Create category panel with title and stacked buttons + inline status
        # (Unchanged from before - preserves all tool semantics)
        function New-CategoryPanel {
            param([string]$Title, [string[]]$Buttons)
            $panel = New-Object System.Windows.Forms.FlowLayoutPanel
            $panel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $panel.WrapContents = $false
            $panel.AutoSize = $true
            $panel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $panel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 15)
            $panel.Dock = [System.Windows.Forms.DockStyle]::Top

            # Title row: [CategoryName] [Badge]
            $titleRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $titleRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $titleRow.WrapContents = $false
            $titleRow.AutoSize = $true
            $titleRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $titleRow.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)

            # Category title (bold label)
            $titleLabel = New-Object System.Windows.Forms.Label
            $titleLabel.Text = $Title
            $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
            $titleLabel.ForeColor = $tabColor
            $titleLabel.AutoSize = $true
            $titleLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
            $titleRow.Controls.Add($titleLabel)

            # Phase 7.2: Attention badge (hidden by default, shown when DominantFailure)
            $badge = New-Object System.Windows.Forms.Label
            $badge.Text = [char]0x25CF + " Attention"  # Bullet + text
            $badge.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $badge.ForeColor = [System.Drawing.Color]::FromArgb(200, 80, 60)
            $badge.AutoSize = $true
            $badge.Margin = New-Object System.Windows.Forms.Padding(10, 3, 0, 0)
            $badge.Visible = $false
            $badge.Tag = "attention-badge"
            $titleRow.Controls.Add($badge)

            # Store badge reference for later updates
            $script:CategoryBadges[$Title] = $badge

            $panel.Controls.Add($titleRow)

            # === STEP 7: Group tools by their Group property (Preset first, then others) ===
            # Get unique groups in order: Preset first, then alphabetically
            $toolGroups = @{}
            foreach ($btnText in $Buttons) {
                $def = $script:ToolDefinitions[$btnText]
                $group = if ($def -and $def.Group) { $def.Group } else { "Actions" }
                if (-not $toolGroups.ContainsKey($group)) {
                    $toolGroups[$group] = @()
                }
                $toolGroups[$group] += $btnText
            }

            # Sort groups: Preset first, Actions last (dry-run tools sink to bottom), rest alphabetically
            $sortedGroups = $toolGroups.Keys | Sort-Object {
                if ($_ -eq "Preset") { "0" }
                elseif ($_ -eq "Actions") { "2" }
                else { "1$_" }
            }

            foreach ($group in $sortedGroups) {
                # Add group separator if more than one group
                if ($sortedGroups.Count -gt 1) {
                    $groupLabel = New-Object System.Windows.Forms.Label
                    $groupLabel.Text = $group
                    $groupLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                    $groupLabel.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
                    $groupLabel.AutoSize = $true
                    $groupLabel.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 4)
                    $panel.Controls.Add($groupLabel)
                }

                # Stacked action rows: [Button] [Description] [StatusLabel] [CancelButton]
                foreach ($btnText in $toolGroups[$group]) {
                    # Row container for button + description + inline status
                    $actionRow = New-Object System.Windows.Forms.FlowLayoutPanel
                    $actionRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
                    $actionRow.WrapContents = $false
                    $actionRow.AutoSize = $true
                    $actionRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $actionRow.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)

                    # Action button
                    $btn = New-Button $btnText
                    $btn.Tag = "action"  # Tag for preset discovery
                    if ($buttonHandlers.ContainsKey($btnText)) {
                        # === MUTATION BYPASS GATE ===
                        # Wrap mutating tool handlers with Assert-MutationGuarded
                        $toolDefForGate = $script:ToolDefinitions[$btnText]
                        if ($toolDefForGate -and $toolDefForGate.MutatesSystem -eq $true -and $toolDefForGate.ToolId) {
                            $gateToolId = $toolDefForGate.ToolId
                            $gateToolName = $btnText
                            $innerHandler = $buttonHandlers[$btnText]
                            # Capture path before closure — $PSScriptRoot may not resolve inside WinForms event
                            $gateDryRunPath = Join-Path $PSScriptRoot "Modules\DryRun.psm1"
                            $btn.Add_Click({
                                param($sender, $e)
                                # DryRun.psm1 may have been force-reimported without prefix by the Dry Run
                                # button handler, invalidating the startup WinConfig-prefixed names. Load
                                # it inline (no prefix) to guarantee function availability on every click.
                                if (Test-Path $gateDryRunPath) { Import-Module $gateDryRunPath -Force -Global }
                                $recOpAction = $null
                                $prevIntent = Get-ExecutionIntent
                                try {
                                    Set-ExecutionIntent -Intent ADMIN_ACTION
                                    $resolution = Resolve-DryRunIntent
                                    $ctx = New-ExecutionContext `
                                        -ToolId $gateToolId `
                                        -IsDryRun $resolution.IsDryRun `
                                        -DryRunSource $resolution.Source
                                    try {
                                        Assert-MutationGuarded -ToolId $gateToolId -ToolName $gateToolName -ExecutionContext $ctx
                                    } catch {
                                        [System.Windows.Forms.MessageBox]::Show(
                                            $_.Exception.Message,
                                            "Mutation Blocked",
                                            [System.Windows.Forms.MessageBoxButtons]::OK,
                                            [System.Windows.Forms.MessageBoxIcon]::Error
                                        )
                                        return
                                    }
                                    if ($ctx.IsDryRun) {
                                        [System.Windows.Forms.MessageBox]::Show(
                                            "MODE: DRY RUN (Source: $($ctx.DryRunSource))`n`nLive execution blocked in dry-run mode.`nUse the Dry Run button to preview this tool's plan.",
                                            "Live Execution Blocked - $gateToolName",
                                            [System.Windows.Forms.MessageBoxButtons]::OK,
                                            [System.Windows.Forms.MessageBoxIcon]::Information
                                        )
                                        return
                                    }
                                    # === FLIGHT RECORDER COORDINATION ===
                                    # While a Bluetooth recording is running, mutating tools are
                                    # allowed but recorded as operator actions so the captured
                                    # evidence attributes the changes correctly. The one exception
                                    # is the full stack reset: it wipes pairing data and requires
                                    # a reboot, which would destroy the recording before upload.
                                    if ($script:BtRecordingActive) {
                                        if ($gateToolId -eq 'bt-stack-reset') {
                                            [System.Windows.Forms.MessageBox]::Show(
                                                "A Bluetooth recording is in progress.`n`nThe Full Bluetooth Stack Reset removes all pairing data and needs a reboot, which would destroy the recording before it is sent to support.`n`nClick 'Stop and Upload' in the Flight Recorder window first, then run the stack reset.",
                                                "Finish the Recording First",
                                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                                [System.Windows.Forms.MessageBoxIcon]::Warning
                                            )
                                            return
                                        }
                                        if (-not $script:BtRecOperatorActions) { $script:BtRecOperatorActions = [System.Collections.ArrayList]::new() }
                                        $recOpAction = @{ Tool = $gateToolName; ToolId = $gateToolId; StartedAt = Get-Date; CompletedAt = $null }
                                        [void]$script:BtRecOperatorActions.Add($recOpAction)
                                    }
                                    & $innerHandler
                                } finally {
                                    if ($recOpAction) { $recOpAction.CompletedAt = Get-Date }
                                    Set-ExecutionIntent -Intent $prevIntent
                                }
                            }.GetNewClosure())
                        } else {
                            # Non-mutating tools: wire directly
                            $btn.Add_Click($buttonHandlers[$btnText])
                        }
                        # Phase 7.3: Register tool button for re-run functionality
                        $script:ToolButtonRegistry[$btnText] = $btn
                    }
                    $actionRow.Controls.Add($btn)

                    # === DRY RUN BUTTON (only for tools that support it) ===
                    $toolDef = $script:ToolDefinitions[$btnText]
                    if ($toolDef -and $toolDef.SupportsDryRun -eq $true) {
                        $dryRunBtn = New-Object System.Windows.Forms.Button
                        $dryRunBtn.Text = "Dry Run"
                        $dryRunBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                        $dryRunBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
                        $dryRunBtn.FlatAppearance.BorderSize = 1
                        $dryRunBtn.BackColor = [System.Drawing.Color]::White
                        $dryRunBtn.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
                        $dryRunBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                        $dryRunBtn.AutoSize = $true
                        $dryRunBtn.Padding = New-Object System.Windows.Forms.Padding(6, 2, 6, 2)
                        $dryRunBtn.Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)
                        $dryRunBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
                        $dryRunBtn.Tag = @{ ToolId = $toolDef.ToolId; ToolName = $btnText; IsDryRun = $true }

                        # Dry Run click handler - uses DryRun.psm1 infrastructure
                        # Capture scriptblock in local variable for closure
                        $invokeDryRunFn = $script:InvokeDryRunForToolFn
                        $dryRunBtn.Add_Click({
                            param($sender, $e)
                            $tag = $sender.Tag
                            & $invokeDryRunFn -ToolId $tag.ToolId -ToolName $tag.ToolName
                        }.GetNewClosure())

                        $actionRow.Controls.Add($dryRunBtn)
                    }

                    # === STEP 7: Tool description (muted, 1 line) ===
                    $def = $script:ToolDefinitions[$btnText]
                    if ($def -and $def.Description) {
                        $descLabel = New-Object System.Windows.Forms.Label
                        $descLabel.Text = "- $($def.Description)"
                        $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                        $descLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
                        $descLabel.AutoSize = $true
                        $descLabel.Margin = New-Object System.Windows.Forms.Padding(8, 6, 0, 0)
                        $descLabel.Tag = "description"
                        $actionRow.Controls.Add($descLabel)
                    }

                    # Status label (hidden by default, shows "Running..." when active)
                    $statusLabel = New-Object System.Windows.Forms.Label
                    $statusLabel.Text = "Running..."
                    $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
                    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
                    $statusLabel.AutoSize = $true
                    $statusLabel.Margin = New-Object System.Windows.Forms.Padding(10, 6, 0, 0)
                    $statusLabel.Visible = $false
                    $statusLabel.Tag = "status"
                    $actionRow.Controls.Add($statusLabel)

                    # Cancel button (hidden by default, appears when action is running)
                    $cancelBtn = New-Object System.Windows.Forms.Button
                    $cancelBtn.Text = "Cancel"
                    $cancelBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $cancelBtn.FlatAppearance.BorderSize = 0
                    $cancelBtn.BackColor = [System.Drawing.Color]::Transparent
                    $cancelBtn.ForeColor = [System.Drawing.Color]::FromArgb(180, 50, 50)
                    $cancelBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                    $cancelBtn.AutoSize = $true
                    $cancelBtn.Padding = New-Object System.Windows.Forms.Padding(4, 2, 4, 2)
                    $cancelBtn.Margin = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
                    $cancelBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
                    $cancelBtn.Visible = $false
                    $cancelBtn.Tag = "cancel"
                    $actionRow.Controls.Add($cancelBtn)

                    $panel.Controls.Add($actionRow)
                }
            }
            return $panel
        }

        # Helper: Create category list button
        function New-CategoryListButton {
            param([string]$CategoryName)

            $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $btnPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $btnPanel.WrapContents = $false
            $btnPanel.AutoSize = $true
            $btnPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btnPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
            $btnPanel.Cursor = [System.Windows.Forms.Cursors]::Hand
            $btnPanel.Tag = $CategoryName

            $btn = New-Object System.Windows.Forms.Button
            $btn.Text = $CategoryName
            $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btn.FlatAppearance.BorderSize = 0
            $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
            $btn.BackColor = [System.Drawing.Color]::Transparent
            $btn.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
            $btn.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            # AutoSize so text never wraps inside the button when Windows text-size
            # accessibility scaling enlarges fonts beyond what fixed width can hold.
            $btn.AutoSize = $true
            $btn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $btn.MinimumSize = New-Object System.Drawing.Size(110, 32)
            $btn.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
            $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
            $btn.Tag = $CategoryName
            $btnPanel.Controls.Add($btn)

            # Badge indicator (mirrors the detail badge, shown in list)
            $listBadge = New-Object System.Windows.Forms.Label
            $listBadge.Text = [char]0x25CF  # Bullet only
            $listBadge.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $listBadge.ForeColor = [System.Drawing.Color]::FromArgb(200, 80, 60)
            $listBadge.AutoSize = $true
            $listBadge.Margin = New-Object System.Windows.Forms.Padding(2, 10, 0, 0)
            $listBadge.Visible = $false
            $listBadge.Tag = "list-badge-$CategoryName"
            $btnPanel.Controls.Add($listBadge)

            # Store list badge for updates
            $script:CategoryListBadges[$CategoryName] = $listBadge

            return @{ Panel = $btnPanel; Button = $btn }
        }

        # === STEP 2: CATEGORY SELECTION (with regression guards) ===
        $script:SelectedCategory = $null
        $script:SelectedCategoryIndex = 0  # For keyboard navigation

        # Store tabColor for use in scriptblock (closure capture)
        $script:ToolsTabColor = $tabColor

        # Script-scoped function for category selection (accessible from event handlers)
        $script:SelectToolCategoryFn = {
            param(
                [string]$CategoryName,
                [switch]$FocusFirstTool  # Step 6: Only focus if explicitly requested
            )

            # REGRESSION GUARD: Category switch must never affect running tools
            # - No cancellation of active operations
            # - No restart of tools
            # - No ledger mutation
            # Only visual state changes are allowed

            # GUARDRAIL E-A2: Tool identity stability assertion
            if ($script:InitialToolCount -and $script:ToolButtonRegistry.Count -ne $script:InitialToolCount) {
                throw "GUARDRAIL A2: Tool registry mutated after initialization (expected $($script:InitialToolCount), got $($script:ToolButtonRegistry.Count))"
            }

            if ($script:SelectedCategory -eq $CategoryName) { return }
            $script:SelectedCategory = $CategoryName
            $script:SelectedCategoryIndex = [Array]::IndexOf($script:Categories, $CategoryName)

            # Update category list button styles (visual only)
            foreach ($catName in $script:CategoryListButtons.Keys) {
                $btn = $script:CategoryListButtons[$catName]
                if ($catName -eq $CategoryName) {
                    $btn.BackColor = [System.Drawing.Color]::FromArgb(220, 230, 245)
                    $btn.ForeColor = $script:ToolsTabColor
                    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                } else {
                    $btn.BackColor = [System.Drawing.Color]::Transparent
                    $btn.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
                }
            }

            # Show/hide category panels (panels persist, just visibility changes)
            # REGRESSION GUARD: Tool state survives - buttons/status/cancel all preserved
            foreach ($catName in $script:CategoryPanels.Keys) {
                $panel = $script:CategoryPanels[$catName]
                $panel.Visible = ($catName -eq $CategoryName)
                if ($panel.Visible) {
                    $panel.BringToFront()
                }
            }

            # Step 6: Focus first tool only if requested and no tool is running
            if ($FocusFirstTool) {
                $hasRunningTool = $false
                if (Get-Command Get-ActiveToolActions -ErrorAction SilentlyContinue) {
                    $runningTools = @(Get-ActiveToolActions)
                    $hasRunningTool = $runningTools.Count -gt 0
                }
                if (-not $hasRunningTool) {
                    $panel = $script:CategoryPanels[$CategoryName]
                    $firstBtn = $panel.Controls | ForEach-Object {
                        $_.Controls | Where-Object { $_.Tag -eq "action" }
                    } | Select-Object -First 1
                    if ($firstBtn) { $firstBtn.Focus() }
                }
            }
        }

        # === STEP 5: KEYBOARD NAVIGATION ===
        # Script-scoped function for keyboard navigation (accessible from event handlers)
        $script:MoveCategorySelectionFn = {
            param([int]$Delta)  # +1 = down, -1 = up
            $newIndex = $script:SelectedCategoryIndex + $Delta
            if ($newIndex -lt 0) { $newIndex = $script:Categories.Count - 1 }
            if ($newIndex -ge $script:Categories.Count) { $newIndex = 0 }
            & $script:SelectToolCategoryFn -CategoryName $script:Categories[$newIndex]
            # Keep focus on category list button
            $script:CategoryListButtons[$script:Categories[$newIndex]].Focus()
        }

        # === STEP 2: CREATE PANELS ONCE ===
        # Iterate over $script:Categories (single source of truth)
        # Use $script:CategoryTools for tool lists
        foreach ($catName in $script:Categories) {
            # Create tool panel for this category (created once, never recreated)
            $toolPanel = New-CategoryPanel -Title $catName -Buttons $script:CategoryTools[$catName]
            $toolPanel.Visible = $false
            $script:CategoryPanels[$catName] = $toolPanel
            $detailContainer.Controls.Add($toolPanel)

            # Create list button for this category
            $listItem = New-CategoryListButton -CategoryName $catName
            $script:CategoryListButtons[$catName] = $listItem.Button
            $categoryListPanel.Controls.Add($listItem.Panel)

            # Wire click handler
            $listItem.Button.Add_Click({
                param($sender, $e)
                & $script:SelectToolCategoryFn -CategoryName $sender.Tag
            }.GetNewClosure())

            # === STEP 5: Wire keyboard handlers to category buttons ===
            $listItem.Button.Add_KeyDown({
                param($sender, $e)
                switch ($e.KeyCode) {
                    "Up" {
                        & $script:MoveCategorySelectionFn -Delta -1
                        $e.Handled = $true
                        $e.SuppressKeyPress = $true
                    }
                    "Down" {
                        & $script:MoveCategorySelectionFn -Delta 1
                        $e.Handled = $true
                        $e.SuppressKeyPress = $true
                    }
                    "Enter" {
                        # Focus first tool in selected category
                        $panel = $script:CategoryPanels[$sender.Tag]
                        $firstBtn = $panel.Controls | ForEach-Object {
                            $_.Controls | Where-Object { $_.Tag -eq "action" }
                        } | Select-Object -First 1
                        if ($firstBtn) { $firstBtn.Focus() }
                        $e.Handled = $true
                        $e.SuppressKeyPress = $true
                    }
                }
            }.GetNewClosure())
        }

        # === DISPLAY-SAFE: Size category pane to fit widest button at current font/DPI ===
        # AutoScaleMode::Dpi does not respond to Windows text-size accessibility scaling,
        # so we measure actual rendered text width and size the pane accordingly. Without
        # this, the fixed SplitterDistance can clip category names like "Bluetooth" when
        # text scaling exceeds 100%.
        $maxBtnTextWidth = 0
        foreach ($catName in $script:Categories) {
            $btn = $script:CategoryListButtons[$catName]
            $textSize = [System.Windows.Forms.TextRenderer]::MeasureText($btn.Text, $btn.Font)
            if ($textSize.Width -gt $maxBtnTextWidth) { $maxBtnTextWidth = $textSize.Width }
        }
        # Reserve: button padding (20) + badge (~18) + panel padding (16) + scrollbar (20)
        # Floor scales with DPI so the pane never collapses below ~140 logical px.
        $splitFloor = [int]([Math]::Round(140 * $script:DpiScale))
        $splitContainer.SplitterDistance = [Math]::Max($splitFloor, $maxBtnTextWidth + 74)

        # === STEP 5: Wire Escape key on tool buttons to return to category list ===
        foreach ($catName in $script:Categories) {
            $panel = $script:CategoryPanels[$catName]
            foreach ($control in $panel.Controls) {
                foreach ($subControl in $control.Controls) {
                    if ($subControl.Tag -eq "action") {
                        $subControl.Add_KeyDown({
                            param($sender, $e)
                            if ($e.KeyCode -eq "Escape") {
                                # Return focus to selected category button
                                $catBtn = $script:CategoryListButtons[$script:SelectedCategory]
                                if ($catBtn) { $catBtn.Focus() }
                                $e.Handled = $true
                                $e.SuppressKeyPress = $true
                            }
                        }.GetNewClosure())
                    }
                }
            }
        }

        # GUARDRAIL E-A2: Lock tool count after initialization
        # Tool identity must be stable for cancellation, re-runs, correlation
        $script:InitialToolCount = $script:ToolButtonRegistry.Count

        # === STEP 6: Default selection on launch ===
        # Select first category from $script:Categories (single source of truth)
        & $script:SelectToolCategoryFn -CategoryName $script:Categories[0]

        continue  # Done with Tools tab
    }

    # ==================== DETAILS TAB ====================
    # Form-style diagnostics view matching reference design
    # Read-only diagnostic information for support escalation
    if ($tabPage.Text -eq "Details") {
        $tabPage.Controls.Clear()

        # Main container with scroll
        $resultsPanel = New-Object System.Windows.Forms.Panel
        $resultsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $resultsPanel.Padding = New-Object System.Windows.Forms.Padding(20, 15, 20, 15)
        $resultsPanel.AutoScroll = $true
        $tabPage.Controls.Add($resultsPanel)

        $resultsFlow = New-Object System.Windows.Forms.FlowLayoutPanel
        $resultsFlow.Dock = [System.Windows.Forms.DockStyle]::Top
        $resultsFlow.AutoSize = $true
        $resultsFlow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $resultsFlow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $resultsFlow.WrapContents = $false
        $resultsPanel.Controls.Add($resultsFlow)

        # === HEADER ===
        $headerTitle = New-Object System.Windows.Forms.Label
        $headerTitle.Text = "NO Support Tool Diagnostics"
        $headerTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
        $headerTitle.ForeColor = $tabColor
        $headerTitle.AutoSize = $true
        $headerTitle.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)
        $resultsFlow.Controls.Add($headerTitle)

        $headerSubtitle = New-Object System.Windows.Forms.Label
        $headerSubtitle.Text = "Read-only diagnostic information for support escalation. (Run ID is unique to this Support Tool run)"
        $headerSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $headerSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
        $headerSubtitle.AutoSize = $true
        $headerSubtitle.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 20)
        $resultsFlow.Controls.Add($headerSubtitle)

        # === METADATA FORM (TableLayoutPanel for label:value pairs) ===
        $metadataTable = New-Object System.Windows.Forms.TableLayoutPanel
        $metadataTable.AutoSize = $true
        $metadataTable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $metadataTable.ColumnCount = 2
        $metadataTable.RowCount = 6
        [void]$metadataTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$metadataTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $metadataTable.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 20)

        # Helper to create form row
        function Add-MetadataRow {
            param([string]$Label, [string]$Value, [int]$Row, [ref]$TextBoxRef)

            $lbl = New-Object System.Windows.Forms.Label
            $lbl.Text = "${Label}:"
            $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $lbl.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $lbl.AutoSize = $true
            $lbl.Margin = New-Object System.Windows.Forms.Padding(0, 6, 15, 6)
            $metadataTable.Controls.Add($lbl, 0, $Row)

            $txt = New-Object System.Windows.Forms.RichTextBox
            $txt.Text = $Value
            $txt.Font = New-Object System.Drawing.Font("Consolas", 9)
            $txt.ReadOnly = $true
            $txt.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $txt.BackColor = [System.Drawing.Color]::White
            $txt.Width = 500
            $txt.Height = 25
            $txt.Multiline = $false
            $txt.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
            $metadataTable.Controls.Add($txt, 1, $Row)

            if ($TextBoxRef) { $TextBoxRef.Value = $txt }
        }

        # Get metadata values
        $runId = $script:SessionId.Substring(0, 8).ToUpper()
        $version = "$AppVersion [$Iteration]"
        $started = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $deviceName = $env:COMPUTERNAME
        $serialNumber = try { (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber } catch { "Unknown" }
        $logFile = if (Get-Command Get-WinConfigLogFile -ErrorAction SilentlyContinue) { Get-WinConfigLogFile } else { "N/A" }

        # Create form rows
        $script:MetadataRunId = $null
        $script:MetadataVersion = $null
        $script:MetadataStarted = $null
        $script:MetadataDeviceName = $null
        $script:MetadataSerialNumber = $null
        $script:MetadataLogFile = $null

        Add-MetadataRow -Label "Support Tool Run ID" -Value $runId -Row 0 -TextBoxRef ([ref]$script:MetadataRunId)
        Add-MetadataRow -Label "NO Support Tool Version" -Value $version -Row 1 -TextBoxRef ([ref]$script:MetadataVersion)
        Add-MetadataRow -Label "Started" -Value $started -Row 2 -TextBoxRef ([ref]$script:MetadataStarted)
        Add-MetadataRow -Label "Device Name" -Value $deviceName -Row 3 -TextBoxRef ([ref]$script:MetadataDeviceName)
        Add-MetadataRow -Label "Serial Number" -Value $serialNumber -Row 4 -TextBoxRef ([ref]$script:MetadataSerialNumber)
        Add-MetadataRow -Label "Log File" -Value $logFile -Row 5 -TextBoxRef ([ref]$script:MetadataLogFile)

        $resultsFlow.Controls.Add($metadataTable)

        # === ACTIONS SECTION ===
        $actionsHeader = New-Object System.Windows.Forms.Label
        $actionsHeader.Text = "Actions Executed This Run:"
        $actionsHeader.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $actionsHeader.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $actionsHeader.AutoSize = $true
        $actionsHeader.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
        $resultsFlow.Controls.Add($actionsHeader)

        # Actions container (will be populated by Update-ResultsDiagnosticsView)
        $script:DiagSectionsContainer = New-Object System.Windows.Forms.FlowLayoutPanel
        $script:DiagSectionsContainer.AutoSize = $true
        $script:DiagSectionsContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $script:DiagSectionsContainer.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $script:DiagSectionsContainer.WrapContents = $false
        $script:DiagSectionsContainer.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 20)
        $resultsFlow.Controls.Add($script:DiagSectionsContainer)

        # === COPY TO CLIPBOARD BUTTON ===
        $copyBtn = New-Object System.Windows.Forms.Button
        $copyBtn.Text = "Copy to Clipboard"
        $copyBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
        $copyBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 122, 183)
        $copyBtn.ForeColor = [System.Drawing.Color]::White
        $copyBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $copyBtn.AutoSize = $true
        $copyBtn.Padding = New-Object System.Windows.Forms.Padding(12, 6, 12, 6)
        $copyBtn.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 15)
        $copyBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $copyBtn.Add_Click({
            $clipSessionActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
                Get-WinConfigSessionActions
            } else { @() }

            $clipText = "NO Support Tool Diagnostics`n"
            $clipText += "========================`n`n"
            $clipText += "Support Tool Run ID: $($script:SessionId.Substring(0, 8).ToUpper())`n"
            $clipText += "NO Support Tool Version: $AppVersion [$Iteration]`n"
            $clipText += "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
            $clipText += "Device Name: $env:COMPUTERNAME`n"
            $clipText += "Serial Number: $($script:MetadataSerialNumber.Text)`n"
            $clipText += "Log File: $($script:MetadataLogFile.Text)`n`n"
            $clipText += "Actions Executed This Run:`n"

            if ($clipSessionActions.Count -eq 0) {
                $clipText += "(No actions executed yet)`n"
            } else {
                foreach ($action in $clipSessionActions) {
                    $clipText += "[$($action.Result)] $($action.Action): $($action.Summary)`n"
                }
            }

            [System.Windows.Forms.Clipboard]::SetText($clipText)
            $this.Text = "Copied!"
            $this.BackColor = [System.Drawing.Color]::FromArgb(92, 184, 92)
            $resetTimer = New-Object System.Windows.Forms.Timer
            $resetTimer.Interval = 2000
            $resetTimer.Add_Tick({
                if ($copyBtn) {
                    $copyBtn.Text = "Copy to Clipboard"
                    $copyBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 122, 183)
                }
                $resetTimer.Stop()
                $resetTimer.Dispose()
            })
            $resetTimer.Start()
        })
        $resultsFlow.Controls.Add($copyBtn)

        # === SHARE CHECKBOX ===
        $script:chkExportDiagnostics = New-Object System.Windows.Forms.CheckBox
        $script:chkExportDiagnostics.Text = "Share anonymized network diagnostics for internal analysis"
        $script:chkExportDiagnostics.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $script:chkExportDiagnostics.ForeColor = $tabColor
        $script:chkExportDiagnostics.AutoSize = $true
        $script:chkExportDiagnostics.Checked = $true
        $script:chkExportDiagnostics.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
        $resultsFlow.Controls.Add($script:chkExportDiagnostics)

        # Hidden elements needed for compatibility with existing code
        $script:ResultsSummaryPass = New-Object System.Windows.Forms.Label
        $script:ResultsSummaryPass.Visible = $false
        $script:ResultsSummaryWarn = New-Object System.Windows.Forms.Label
        $script:ResultsSummaryWarn.Visible = $false
        $script:ResultsSummaryFail = New-Object System.Windows.Forms.Label
        $script:ResultsSummaryFail.Visible = $false
        $script:PatternInsightsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $script:PatternInsightsPanel.Visible = $false
        $script:RerunFailedPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $script:RerunFailedPanel.Visible = $false
        $script:RerunFailedBtn = New-Object System.Windows.Forms.Button
        $script:RerunFailedCountLabel = New-Object System.Windows.Forms.Label
        $script:DiagActionsContainer = New-Object System.Windows.Forms.Panel
        $script:DiagActionsContainer.Visible = $false

        # Initial population
        Update-ResultsDiagnosticsView

        continue  # Done with Details tab
    }

}  # End foreach tabPage

# Legacy tab code removed - migrated to 2-tab structure (Tools + Details)
# Create bottom banner
$bannerPanel = New-Object System.Windows.Forms.Panel
$bannerPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$bannerPanel.Height = 40
$form.Controls.Add($bannerPanel)

# Load and display the banner image
$bannerImageUrl = "https://neuroptimal.com/wp-content/themes/porto-child/header/DF_NO_Logo_2024_website_full.png"
try {
    $webClient = New-Object System.Net.WebClient
    $bannerImageStream = $webClient.OpenRead($bannerImageUrl)
    $bannerImage = [System.Drawing.Image]::FromStream($bannerImageStream)
    
    $bannerPictureBox = New-Object System.Windows.Forms.PictureBox
    $bannerPictureBox.Image = $bannerImage
    $bannerPictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    $bannerPictureBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $bannerPanel.Controls.Add($bannerPictureBox)
} catch {
    Write-Host "Failed to load banner image: $_"
}

# Custom drawing for tab control
$tabControl.Add_DrawItem({
    param($tabControl, $e)
    $tabRect = $tabControl.GetTabRect($e.Index)
    $g = $e.Graphics
    $textColor = if ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) { $textColor } else { [System.Drawing.SystemColors]::ControlText }
    $tabColor = if ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) { $tabColor } else { $backgroundColor }
    
    $brush = New-Object System.Drawing.SolidBrush($tabColor)
    $g.FillRectangle($brush, $tabRect)
    $brush.Dispose()

    $stringFormat = New-Object System.Drawing.StringFormat
    $stringFormat.Alignment = [System.Drawing.StringAlignment]::Center
    $stringFormat.LineAlignment = [System.Drawing.StringAlignment]::Center

    $brush = New-Object System.Drawing.SolidBrush($textColor)
    $textRect = New-Object System.Drawing.RectangleF($tabRect.X, $tabRect.Y, $tabRect.Width, $tabRect.Height)
    $g.DrawString($tabControl.TabPages[$e.Index].Text, $e.Font, $brush, $textRect, $stringFormat)
    $brush.Dispose()
    $stringFormat.Dispose()
})

# Refresh diagnostics view when switching to Results tab
# EXEMPT-CONTRACT-001: Simple UI refresh, no diagnostic functions
$tabControl.Add_SelectedIndexChanged({
    $selectedTab = $tabControl.SelectedTab
    if ($selectedTab -and $selectedTab.Text -eq "Results") {
        Update-ResultsDiagnosticsView
    }
})

# --- Cloudflare Diagnostics Transport (Phase 2: spool-first, single-POST) ---

function Ensure-DiagnosticsDir([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

function Compress-GzipBytes([byte[]]$bytes) {
    $ms = [System.IO.MemoryStream]::new()
    try {
        $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
        try { $gz.Write($bytes, 0, $bytes.Length) } finally { $gz.Dispose() }
        return $ms.ToArray()
    } finally { $ms.Dispose() }
}

function Send-DiagnosticsPayloadCloudflare {
    param(
        [Parameter(Mandatory)] [string] $JsonPayload,
        [Parameter(Mandatory)] [string] $SessionId,
        [Parameter(Mandatory)] [string] $IngestUrl
    )

    # EPHEMERAL: Use session temp cache path (zero-footprint)
    # NOTE: Spooled diagnostics are deleted on session exit. If upload fails,
    # the data is lost. This is acceptable for a zero-footprint support tool.
    $pendingRoot = if (Get-Command Get-WinConfigCachePath -ErrorAction SilentlyContinue) {
        Join-Path (Get-WinConfigCachePath) "PendingDiagnostics"
    } else {
        Join-Path $env:TEMP "WinConfig-cache\PendingDiagnostics"
    }
    Ensure-DiagnosticsDir $pendingRoot

    $spoolPath = Join-Path $pendingRoot "$SessionId.json"

    # 1) Spool FIRST (durability)
    if (-not (Test-Path -LiteralPath $spoolPath)) {
        $JsonPayload | Out-File -LiteralPath $spoolPath -Encoding utf8 -Force
    }

    # 2) Token acquisition (zero-config via /ingest-token)
    # SSOT: docs/SSOT_INGEST_AUTH.md - hard-fail if broker unavailable
    $token = Get-NoSupportIngestToken
    if (-not $token) {
        return @{ Status="auth_broker_unavailable"; SessionId=$SessionId; AuthMethod="JWT (runtime)"; TokenSource="/ingest-token"; Error="Token broker unreachable" }
    }

    # 3) Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonPayload)
    $compressed = Compress-GzipBytes $bytes

    $headers = @{
        Authorization      = "Bearer $token"
        "Content-Encoding" = "gzip"
        "Content-Type"     = "application/json"
    }

    # 4) Upload with bounded retries (using WebClient for reliable HTTP handling)
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $wc = [System.Net.WebClient]::new()
            $wc.Headers['Authorization'] = "Bearer $token"
            $wc.Headers['Content-Encoding'] = 'gzip'
            $wc.Headers['Content-Type'] = 'application/json'

            $responseBytes = $wc.UploadData($IngestUrl, 'POST', $compressed)
            $responseText = [System.Text.Encoding]::UTF8.GetString($responseBytes)

            # Success (2xx) - parse response to check status
            Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue
            return @{ Status="uploaded"; SessionId=$SessionId; Http=201; Response=$responseText; AuthMethod="JWT (runtime)"; TokenSource="/ingest-token" }
        }
        catch [System.Net.WebException] {
            $webEx = $_.Exception
            $httpResp = $webEx.Response -as [System.Net.HttpWebResponse]

            if ($httpResp) {
                $statusCode = [int]$httpResp.StatusCode

                # 409 Conflict = duplicate, treat as success (no retry, clean exit)
                if ($statusCode -eq 409) {
                    Write-Host "[Upload] Already uploaded: Session $SessionId (HTTP 409 - duplicate detected)" -ForegroundColor Cyan
                    Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue
                    return @{ Status="duplicate"; SessionId=$SessionId; Http=409; AuthMethod="JWT (runtime)"; TokenSource="/ingest-token" }
                }

                # 400/401/403 = fatal, don't retry
                if ($statusCode -in 400,401,403) {
                    return @{ Status="fatal"; SessionId=$SessionId; Http=$statusCode; Path=$spoolPath; AuthMethod="JWT (runtime)"; TokenSource="/ingest-token" }
                }
            }

            # Transient error - retry if attempts remain
            if ($attempt -lt $maxAttempts) {
                $base = [Math]::Pow(2, $attempt) # 2,4
                $jitter = Get-Random -Minimum 0 -Maximum 250
                Start-Sleep -Milliseconds ([int]($base*500 + $jitter))
                continue
            }
            return @{ Status="spooled_upload_failed"; SessionId=$SessionId; Error=$webEx.Message; Path=$spoolPath }
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                $base = [Math]::Pow(2, $attempt)
                $jitter = Get-Random -Minimum 0 -Maximum 250
                Start-Sleep -Milliseconds ([int]($base*500 + $jitter))
                continue
            }
            return @{ Status="spooled_upload_failed"; SessionId=$SessionId; Error=$_.Exception.Message; Path=$spoolPath }
        }
    }
}

# Log shutdown when form closes
# EXEMPT-CONTRACT-001: Shutdown logging, no Switch-DiagnosticResult usage
$form.Add_FormClosing({
    # Close session ledger (makes session immutable, generates markdown)
    if (Get-Command Close-WinConfigSession -ErrorAction SilentlyContinue) {
        Close-WinConfigSession | Out-Null
    }

    if (Get-Command Write-WinConfigLog -ErrorAction SilentlyContinue) {
        Write-WinConfigLog -Action "Shutdown" -Message "WinConfig application closed"
    }

    # EPHEMERAL CLEANUP: Remove session temp root (zero-footprint)
    # This ensures no persistent artifacts remain after application exit
    if (Get-Command Remove-WinConfigTempRoot -ErrorAction SilentlyContinue) {
        Remove-WinConfigTempRoot
    }

    # Ephemeral diagnostics export (checkbox-gated, Cloudflare R2)
    if ($script:chkExportDiagnostics -and $script:chkExportDiagnostics.Checked) {

        # Helper: Register export warning in session timeline
        function Register-ExportWarning {
            param([string]$Summary)
            if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                Register-WinConfigSessionAction -Action "Analytics Export" -Detail "Export failed or blocked" -Category "Diagnostics" -Result "WARN" -Tier 1 -Summary $Summary
            }
        }

        # Helper: Detect forbidden fields in payload (returns first violation or $null)
        function Test-ForbiddenFields {
            param($Data, [string]$Path = "")

            # Patterns for forbidden content
            $ipv4Pattern = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
            $ipv6Pattern = '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
            $macPattern = '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
            $hostnamePattern = '\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'

            # Forbidden key names (case-insensitive)
            # NOTE: deviceName, serialNumber, windowsVersion are ALLOWED (intentionally in payload)
            # See: tests/ExportPayloadContract.Tests.ps1 for guardrail ensuring no conflicts
            $forbiddenKeys = @('IPAddress', 'IP', 'IPv4', 'IPv6', 'Hostname', 'ComputerName', 'MachineName',
                               'MACAddress', 'MAC', 'Username', 'User', 'ISP', 'ASN', 'Organization', 'Org')

            if ($null -eq $Data) { return $null }

            if ($Data -is [hashtable] -or $Data -is [System.Collections.IDictionary]) {
                foreach ($key in $Data.Keys) {
                    # Check key name
                    if ($forbiddenKeys -contains $key) {
                        return "forbidden key '$key' at $Path"
                    }
                    # Recurse into value
                    $result = Test-ForbiddenFields -Data $Data[$key] -Path "$Path.$key"
                    if ($result) { return $result }
                }
            }
            elseif ($Data -is [array]) {
                for ($i = 0; $i -lt $Data.Count; $i++) {
                    $result = Test-ForbiddenFields -Data $Data[$i] -Path "$Path[$i]"
                    if ($result) { return $result }
                }
            }
            elseif ($Data -is [string]) {
                # Check string content for forbidden patterns
                if ($Data -match $ipv4Pattern) { return "IP address detected at $Path" }
                if ($Data -match $ipv6Pattern) { return "IPv6 address detected at $Path" }
                if ($Data -match $macPattern) { return "MAC address detected at $Path" }
                # Only check hostname pattern for longer strings (avoid false positives on country codes)
                if ($Data.Length -gt 10 -and $Data -match $hostnamePattern -and $Data -notmatch '^\w+\.(com|net|org|io)$') {
                    # Allow known safe domains
                    $safeDomains = @('neuroptimal.com', 'connectwise.com', 'screenconnect.com', 'zengar.com')
                    $isSafe = $false
                    foreach ($safe in $safeDomains) {
                        if ($Data -like "*$safe*") { $isSafe = $true; break }
                    }
                    if (-not $isSafe) { return "hostname/FQDN detected at $Path" }
                }
            }

            return $null
        }

        try {
            # Build diagnostics payload
            $exportSessionActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
                Get-WinConfigSessionActions | ForEach-Object {
                    # Extract ONLY safe evidence fields (no IPs, hostnames, usernames)
                    $safeEvidence = @{}
                    if ($_.Evidence) {
                        $ev = $_.Evidence
                        # Country info (safe - geographic only)
                        if ($ev.CountryCode) { $safeEvidence.CountryCode = $ev.CountryCode }
                        if ($ev.Country -is [string] -and $ev.Country.Length -eq 2) {
                            $safeEvidence.CountryCode = $ev.Country
                        }
                        if ($ev.Country -is [hashtable] -and $ev.Country.CountryCode) {
                            $safeEvidence.CountryCode = $ev.Country.CountryCode
                            if ($ev.Country.Name) { $safeEvidence.CountryName = $ev.Country.Name }
                        }
                        # Latency (safe - numeric only)
                        if ($ev.LatencyMs) { $safeEvidence.LatencyMs = $ev.LatencyMs }
                        if ($ev.Latency) { $safeEvidence.LatencyMs = $ev.Latency }
                        # DNS resolver type (safe - known public resolvers only)
                        if ($ev.ResolverType) { $safeEvidence.ResolverType = $ev.ResolverType }
                        # TLS info (safe - protocol info only)
                        if ($ev.TlsVersion) { $safeEvidence.TlsVersion = $ev.TlsVersion }
                        if ($ev.CipherSuite) { $safeEvidence.CipherSuite = $ev.CipherSuite }
                        # Port test results (safe - port numbers only)
                        if ($ev.PortsTested) { $safeEvidence.PortsTested = $ev.PortsTested }
                        if ($ev.PortsBlocked) { $safeEvidence.PortsBlocked = $ev.PortsBlocked }
                        if ($ev.PortsOpen) { $safeEvidence.PortsOpen = $ev.PortsOpen }
                        # Error codes (safe - structured error info)
                        if ($ev.ErrorCode) { $safeEvidence.ErrorCode = $ev.ErrorCode }
                        if ($ev.ErrorPhase) { $safeEvidence.ErrorPhase = $ev.ErrorPhase }
                        # Bluetooth diagnostics (safe - enum/boolean/count values, no device names or identifiers)
                        if ($ev.VerdictStatus)                   { $safeEvidence.VerdictStatus     = $ev.VerdictStatus }
                        if ($ev.VerdictConfidence)               { $safeEvidence.VerdictConfidence = $ev.VerdictConfidence }
                        if ($null -ne $ev.FindingCount)          { $safeEvidence.FindingCount      = $ev.FindingCount }
                        if ($ev.FindingIds)                      { $safeEvidence.FindingIds        = @($ev.FindingIds) }
                        if ($null -ne $ev.AdapterPresent)        { $safeEvidence.AdapterPresent    = $ev.AdapterPresent }
                        if ($null -ne $ev.ServicesHealthy)       { $safeEvidence.ServicesHealthy   = $ev.ServicesHealthy }
                        if ($null -ne $ev.DisconnectCount)       { $safeEvidence.DisconnectCount   = $ev.DisconnectCount }
                        if ($ev.FindingId)                       { $safeEvidence.FindingId         = $ev.FindingId }
                        if ($ev.AppliesTo)                       { $safeEvidence.AppliesTo         = $ev.AppliesTo }
                    }
                    @{
                        Timestamp = $_.Timestamp.ToString("o")
                        Action = $_.Action
                        Detail = $_.Detail
                        Category = $_.Category
                        Result = $_.Result
                        Tier = $_.Tier
                        Summary = $_.Summary
                        Evidence = if ($safeEvidence.Count -gt 0) { $safeEvidence } else { $null }
                    }
                }
            } else { @() }

            # === Generate PPF for export ===
            $exportPpf = $null
            try {
                $ppfFunction = Get-Command New-WinConfigProblemPatternFingerprint -ErrorAction SilentlyContinue
                if (-not $ppfFunction) {
                    $ppfFunction = Get-Command New-ProblemPatternFingerprint -ErrorAction SilentlyContinue
                }

                if ($ppfFunction) {
                    $ledgerOps = if (Get-Command Get-WinConfigLedgerOperations -ErrorAction SilentlyContinue) {
                        @(Get-WinConfigLedgerOperations)
                    } else { @() }

                    $ppfResult = & $ppfFunction -Operations $ledgerOps
                    if ($ppfResult) {
                        $exportPpf = @{
                            id           = $ppfResult.Id
                            schema       = $ppfResult.Schema
                            failureCount = $ppfResult.FailureCount
                            failures     = @($ppfResult.Failures)
                            osBucket     = $ppfResult.OsBucket
                            networkClass = $ppfResult.NetworkClass
                        }
                    }
                }
            }
            catch {
                # PPF generation failed - non-fatal, export without it
            }

            # Get device identity for payload (same source as UI display)
            $machineInfo = Get-WinConfigMachineInfo

            $payload = @{
                SchemaVersion = "1.0"
                ExportedAt = (Get-Date).ToString("o")
                SessionId = $script:SessionId
                AppVersion = $AppVersion
                Iteration = $Iteration
                SessionStartTime = $script:SessionStartTime
                Actions = @($exportSessionActions)
                ppf = $exportPpf
                # Device identity - verbatim from Get-WinConfigMachineInfo
                deviceName = $machineInfo.DeviceName
                serialNumber = $machineInfo.SerialNumber
                windowsVersion = $machineInfo.FormattedVersion
            }

            # === SCHEMA VALIDATION (fail-closed) ===
            $schemaErrors = @()
            if (-not $payload.SchemaVersion) { $schemaErrors += "missing SchemaVersion" }
            if (-not $payload.SessionId) { $schemaErrors += "missing SessionId" }
            if (-not $payload.ExportedAt) { $schemaErrors += "missing ExportedAt" }
            if ($null -eq $payload.Actions) { $schemaErrors += "missing Actions array" }

            if ($schemaErrors.Count -gt 0) {
                $reason = $schemaErrors -join ", "
                Register-ExportWarning -Summary "Analytics export skipped: schema validation failed ($reason)"
                return  # Fail-closed: do not write
            }

            # === FORBIDDEN FIELD BLOCKING (hard stop) ===
            $forbiddenViolation = Test-ForbiddenFields -Data $payload -Path "payload"
            if ($forbiddenViolation) {
                Register-ExportWarning -Summary "Analytics export blocked: $forbiddenViolation"
                return  # Hard stop: do not write
            }

            # === WRITE ATTEMPT (Cloudflare R2 only) ===
            $json = $payload | ConvertTo-Json -Depth 10

            # CONTRACT: Result MUST be captured and checked - DO NOT pipe to Out-Null
            # Regression guard: .github/workflows/lint-export-result.yml
            # History: Silent failure bug caused uploads to fail without user notification
            $uploadResult = Send-DiagnosticsPayloadCloudflare `
                -JsonPayload $json `
                -SessionId   $script:SessionId `
                -IngestUrl   $script:DiagnosticsIngestUrl

            # Check actual result status
            $resultStatus = if ($uploadResult) { $uploadResult.Status } else { "unknown" }
            $isSuccess = $resultStatus -in @("uploaded", "duplicate")

            if ($isSuccess) {
                # Silent success - log internally only (no console output)
                if (Get-Command Write-WinConfigLog -ErrorAction SilentlyContinue) {
                    Write-WinConfigLog -Action "AnalyticsExport" -Message "Export succeeded: $resultStatus"
                }

                # Register success in session timeline
                $script:DiagnosticActions += [PSCustomObject]@{
                    ActionId  = [guid]::NewGuid().ToString().Substring(0,8).ToUpper()
                    Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
                    Action    = "Analytics Export"
                    Detail    = "Uploaded ($resultStatus)"
                    Category  = "Diagnostics"
                    Result    = "PASS"
                }
            } else {
                # Silent failure - log internally only (no console output)
                $errorDetail = if ($uploadResult.Error) { $uploadResult.Error } else { $resultStatus }
                if (Get-Command Write-WinConfigLog -ErrorAction SilentlyContinue) {
                    Write-WinConfigLog -Action "AnalyticsExport" -Message "Export failed: $resultStatus - $errorDetail"
                }
                Register-ExportWarning -Summary "Analytics export failed: $errorDetail"

                # Register failure in session timeline
                $script:DiagnosticActions += [PSCustomObject]@{
                    ActionId  = [guid]::NewGuid().ToString().Substring(0,8).ToUpper()
                    Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
                    Action    = "Analytics Export"
                    Detail    = "Failed: $resultStatus"
                    Category  = "Diagnostics"
                    Result    = "FAIL"
                }
            }

        } catch {
            # Silent exception - log internally only (no console output)
            $errorMsg = $_.Exception.Message
            if (Get-Command Write-WinConfigLog -ErrorAction SilentlyContinue) {
                Write-WinConfigLog -Action "AnalyticsExport" -Message "Export exception: $errorMsg"
            }
            Register-ExportWarning -Summary "Analytics export exception: $errorMsg"
        }
    }
})

# PERF-001: Legacy lazy tab initialization removed (UI-REWORK)
# Bluetooth/Diagnostics tabs now integrated into Details subpages

# ============================================================================
# STARTUP INVARIANT GUARDRAILS (PERF-001)
# Prevents regression: deferred modules must NOT be loaded before ShowDialog()
# HARD ASSERTION: Fails startup if violated - symbol references cause parse-time load
# ============================================================================
$deferredModules = @('Network.Diagnostics')
foreach ($moduleName in $deferredModules) {
    if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
        throw "PERF-001 VIOLATION: $moduleName loaded during startup - symbol reference caused parse-time module load"
    }
}

# Set initial tab and focus when form loads
$form.Add_Shown({
    # Normal startup: Tools tab (index 0), focus on first category's first button
    $tabControl.SelectedIndex = 0
})

# ============================================================================
# PHASE 11: STAGING ASSERTIONS - Tripwires before launch
# ============================================================================
# These fail HARD if debug artifacts are present. No logs. No warnings.
Invoke-StagingAssertions -Form $form -Categories $script:Categories -CategoryTools $script:CategoryTools

# Show the form with proper message loop (Phase 4 requirement)
# Application.Run ensures proper WinForms message pump for async operations
[System.Windows.Forms.Application]::Run($form)

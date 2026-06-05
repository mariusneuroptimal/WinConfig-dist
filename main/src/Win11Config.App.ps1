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
        [ValidateSet("Network", "System", "Audio", "Bluetooth", "Maintenance", "Other")]
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

    # Use Context-Aware Action resolver if available, otherwise fallback to inline logic
    $actionResult = $null
    if (Get-Command Resolve-WinConfigContextAwareActions -ErrorAction SilentlyContinue) {
        $actionResult = Resolve-WinConfigContextAwareActions -Category "Diagnostics" -Result $overallStatus -Evidence $evidence
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
            "INSUFFICIENT_SIGNAL" { $warningColor }
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
        $result = if ($actionResult) { $actionResult.Status } else { $overallStatus }
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

            # Resolve path string for Start-Job (loaded module not accessible across runspace boundary)
            $btModPath = $env:WINCONFIG_BT_MODULE_PATH
            if (-not $btModPath) { $btModPath = Join-Path $PSScriptRoot "Modules\BluetoothProbe.psm1" }
            if (-not (Test-Path $btModPath)) {
                $btModPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "winconfig-bluetooth\src\Modules\Bluetooth.psm1"
            }

            # ── Build form ────────────────────────────────────────────────────────
            $btForm = New-Object System.Windows.Forms.Form
            $btForm.Text = "Bluetooth Flight Recorder"
            $btForm.Size = New-Object System.Drawing.Size(700, 650)
            $btForm.StartPosition = "CenterScreen"
            $btForm.FormBorderStyle = "FixedDialog"
            $btForm.MaximizeBox = $false

            # Bottom status bar (add first — docking is processed in reverse add order)
            $btStatusPanel = New-Object System.Windows.Forms.Panel
            $btStatusPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $btStatusPanel.Height = 80
            $btStatusPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
            $btStatusPanel.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)
            $btForm.Controls.Add($btStatusPanel)

            $btElapsedLabel = New-Object System.Windows.Forms.Label
            $btElapsedLabel.Text = "Initializing..."
            $btElapsedLabel.AutoSize = $false
            $btElapsedLabel.Width = 500
            $btElapsedLabel.Height = 18
            $btElapsedLabel.Location = New-Object System.Drawing.Point(8, 6)
            $btElapsedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $btElapsedLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $btStatusPanel.Controls.Add($btElapsedLabel)

            $btUploadLabel = New-Object System.Windows.Forms.Label
            $btUploadLabel.Text = "Upload: -"
            $btUploadLabel.AutoSize = $false
            $btUploadLabel.Width = 660
            $btUploadLabel.Height = 18
            $btUploadLabel.Location = New-Object System.Drawing.Point(8, 28)
            $btUploadLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $btUploadLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
            $btStatusPanel.Controls.Add($btUploadLabel)

            # Top instruction banner (add second)
            $btBanner = New-Object System.Windows.Forms.Panel
            $btBanner.Dock = [System.Windows.Forms.DockStyle]::Top
            $btBanner.Height = 56
            $btBanner.BackColor = [System.Drawing.Color]::FromArgb(30, 50, 80)
            $btForm.Controls.Add($btBanner)

            $btBannerLabel = New-Object System.Windows.Forms.Label
            $btBannerLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 210, 255)
            $btBannerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $btBannerLabel.TextAlign = "MiddleLeft"
            $btBannerLabel.Padding = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
            $btBannerLabel.Text = "Step 1 of 3 - Taking Bluetooth baseline snapshot, please wait..."
            $btBanner.Controls.Add($btBannerLabel)

            # Anomaly confirmation bar (initially hidden, shown when anomaly detected)
            $btAnomalyBar = New-Object System.Windows.Forms.Panel
            $btAnomalyBar.Dock = [System.Windows.Forms.DockStyle]::Top
            $btAnomalyBar.Height = 40
            $btAnomalyBar.BackColor = [System.Drawing.Color]::FromArgb(180, 130, 20)
            $btAnomalyBar.Visible = $false
            $btForm.Controls.Add($btAnomalyBar)

            $btAnomalyLabel = New-Object System.Windows.Forms.Label
            $btAnomalyLabel.Text = "Stream stopped unexpectedly -- was this a manual stop?"
            $btAnomalyLabel.AutoSize = $false
            $btAnomalyLabel.Width = 390
            $btAnomalyLabel.Height = 28
            $btAnomalyLabel.Location = New-Object System.Drawing.Point(12, 7)
            $btAnomalyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $btAnomalyLabel.ForeColor = [System.Drawing.Color]::White
            $btAnomalyBar.Controls.Add($btAnomalyLabel)

            $script:BtAnomaly_Resolved = $false
            $script:BtAnomaly_IsExpected = $false

            $btAnomalyExpectedBtn = New-Object System.Windows.Forms.Button
            $btAnomalyExpectedBtn.Text = "Expected"
            $btAnomalyExpectedBtn.Size = New-Object System.Drawing.Size(90, 26)
            $btAnomalyExpectedBtn.Location = New-Object System.Drawing.Point(420, 7)
            $btAnomalyExpectedBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btAnomalyExpectedBtn.BackColor = [System.Drawing.Color]::FromArgb(60, 140, 60)
            $btAnomalyExpectedBtn.ForeColor = [System.Drawing.Color]::White
            $btAnomalyExpectedBtn.Add_Click({ $script:BtAnomaly_Resolved = $true; $script:BtAnomaly_IsExpected = $true })
            $btAnomalyBar.Controls.Add($btAnomalyExpectedBtn)

            $btAnomalyInvestBtn = New-Object System.Windows.Forms.Button
            $btAnomalyInvestBtn.Text = "Investigate"
            $btAnomalyInvestBtn.Size = New-Object System.Drawing.Size(90, 26)
            $btAnomalyInvestBtn.Location = New-Object System.Drawing.Point(520, 7)
            $btAnomalyInvestBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btAnomalyInvestBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 60, 60)
            $btAnomalyInvestBtn.ForeColor = [System.Drawing.Color]::White
            $btAnomalyInvestBtn.Add_Click({ $script:BtAnomaly_Resolved = $true; $script:BtAnomaly_IsExpected = $false })
            $btAnomalyBar.Controls.Add($btAnomalyInvestBtn)

            # Device status strip (5 compact state indicators)
            $btStateStrip = New-Object System.Windows.Forms.Panel
            $btStateStrip.Dock = [System.Windows.Forms.DockStyle]::Top
            $btStateStrip.Height = 32
            $btStateStrip.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 30)
            $btStateStrip.Visible = $false
            $btForm.Controls.Add($btStateStrip)

            $btStateLabels = @{}
            $stateIndicators = @(
                @{ Key = 'Device';  X = 8;   W = 140; Text = 'Device: --' }
                @{ Key = 'COM';     X = 148; W = 120; Text = 'COM: --' }
                @{ Key = 'Link';    X = 268; W = 130; Text = 'Radio: --' }
                @{ Key = 'Stream';  X = 398; W = 120; Text = 'Stream: --' }
                @{ Key = 'App';     X = 518; W = 120; Text = 'NO.exe: --' }
            )
            foreach ($ind in $stateIndicators) {
                $lbl = New-Object System.Windows.Forms.Label
                $lbl.Text = $ind.Text
                $lbl.AutoSize = $false
                $lbl.Width = if ($ind.W) { $ind.W } else { 130 }
                $lbl.Height = 22
                $lbl.Location = New-Object System.Drawing.Point($ind.X, 5)
                $lbl.Font = New-Object System.Drawing.Font("Consolas", 8)
                $lbl.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
                $lbl.TextAlign = "MiddleLeft"
                $btStateStrip.Controls.Add($lbl)
                $btStateLabels[$ind.Key] = $lbl
            }

            # Console output fills remaining space (add last)
            $btOutputBox = New-Object System.Windows.Forms.RichTextBox
            $btOutputBox.Multiline = $true
            $btOutputBox.ScrollBars = "Vertical"
            $btOutputBox.Dock = [System.Windows.Forms.DockStyle]::Fill
            Initialize-WinConfigGuiDiagnosticBox -Box $btOutputBox
            $btForm.Controls.Add($btOutputBox)

            $btForm.Show()
            $btForm.Refresh()

            function Write-BtLog {
                param([string]$Message, [string]$Level = "INFO")
                Write-WinConfigGuiDiagnostic -Level $Level -Message $Message -Box $btOutputBox -NoPrefix
                $btForm.Refresh()
            }

            # ── Diagnostic run folder ─────────────────────────────────────────────
            $btDiagRun = $null
            if (Get-Command New-WinConfigDiagnosticRun -ErrorAction SilentlyContinue) {
                try { $btDiagRun = New-WinConfigDiagnosticRun -ToolId 'bluetooth-diagnostics' } catch { }
            }
            $btRunId = if ($btDiagRun) { $btDiagRun.RunId } else { [guid]::NewGuid().ToString("N").Substring(0,12).ToUpper() }

            Write-BtLog "Run ID: $btRunId" -Level "DIM"
            Write-BtLog "Step 1 of 3: Taking Bluetooth baseline snapshot (5-10 seconds)..." -Level "STEP"

            # ── PHASE 1: Baseline — background job, DoEvents loop keeps UI live ───
            $btBaselineJob = Start-Job -ScriptBlock {
                param($mp)
                Import-Module $mp -Force -ErrorAction Stop
                Invoke-BluetoothDiagnosticsAndRecord -RecordAction {} -TimeoutSeconds 60
            } -ArgumentList $btModPath

            while ($btBaselineJob.State -in @('Running','NotStarted')) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 200
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
                Write-BtLog "Baseline: $($baselineResult.Status)  Verdict=$vStr  Findings=$($baselineResult.FindingCount)" -Level $blvl
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try { Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name "baseline.json" -Data $baselineResult } catch { }
                }
            } else {
                Write-BtLog "Baseline complete (Bluetooth adapter may be unavailable)" -Level "WARN"
            }

            # ── PHASE 2: Recording — Deep probe with DoEvents loop ────────────────
            $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(20, 65, 25)
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(160, 240, 160)
            $btBannerLabel.Text      = "Step 2 of 3 - Recording.  Launch NeurOptimal, reproduce the issue, then click Stop and Upload."

            Write-BtLog ""
            Write-BtLog "Step 2 of 3: Recording in progress" -Level "STEP"

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

            $script:BtRec_StopClicked = $false
            $btStopBtn = New-Object System.Windows.Forms.Button
            $btStopBtn.Text = "Stop and Upload"
            $btStopBtn.Size = New-Object System.Drawing.Size(130, 28)
            $btStopBtn.Location = New-Object System.Drawing.Point(8, 48)
            $btStopBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btStopBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
            $btStopBtn.ForeColor = [System.Drawing.Color]::White
            $btStopBtn.Add_Click({ $script:BtRec_StopClicked = $true })
            $btStatusPanel.Controls.Add($btStopBtn)

            $btRecordStart = Get-Date
            $btPollJob     = $null
            $btPollSince   = $btRecordStart
            $btNextPoll    = $btRecordStart.AddSeconds(6)
            $btSvcStates   = $null
            $btFirstPoll   = $true

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

                # Auto-detect NeurOptimal device from PnP
                $btTargetName = 'NeurOptimal Headset'
                try {
                    $initPnp = Get-BluetoothPnpSnapshot
                    $noDevice = $initPnp.Devices | Where-Object { $_.FriendlyName -match 'NeurOptimal' } | Select-Object -First 1
                    if ($noDevice) {
                        $btTargetName = $noDevice.FriendlyName
                        $detectedMac = Get-MacFromPnpInstanceId -InstanceId $noDevice.InstanceId
                        if ($detectedMac) { $btProbeTargetMac = $detectedMac }
                        Write-BtLog "  Target detected: $btTargetName  MAC: $(if ($btProbeTargetMac) { $btProbeTargetMac } else { '(name match only)' })" -Level "OK"
                    } else {
                        Write-BtLog "  No NeurOptimal device found in PnP -- watching for any changes" -Level "DIM"
                    }
                } catch {
                    $initPnp = [pscustomobject]@{ Devices = @(); Failures = @() }
                }

                $btProbeConfig = New-TargetDeviceConfiguration -TargetName $btTargetName -TargetMac $btProbeTargetMac -AppProcessName $btProbeAppName
                $btProbeWatch  = New-TargetWatchState -Configuration $btProbeConfig

                # Initial state snapshot
                $initCom  = try { Get-BluetoothComPortSnapshot } catch { [pscustomobject]@{ Ports = @() } }
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

                # Adapter info + power plan (captured once)
                try { $btProbeSession.AdapterInfo = Get-BluetoothAdapterInfo } catch { }
                try { $btProbeSession.PowerPlan   = Get-PowerPlanInfo } catch { }

                # BT link initial state
                $initLink = Get-BtConnectionState -Mac $btProbeTargetMac -BtWin32Available $btWin32Ok
                $btProbeSession.BtLinkState    = $initLink
                $btProbeSession.BtLinkEnteredAt = Get-Date

                # Streaming initial state
                $initStream = Get-StreamingState -WatchState $btProbeWatch
                $btProbeSession.StreamingState = $initStream.State
                $btProbeSession.ActiveStreamPort = $initStream.ActivePort
                if ($initStream.State -eq 'Active') { $btProbeSession.StateEnteredAt['streaming_Active_at'] = Get-Date }

                # Show status strip and initial state
                $btStateStrip.Visible = $true

                Write-BtLog "  Device        : $(Get-ProbeStateUserText -Kind device -State $btProbeWatch.DeviceState)" -Level (Get-ProbeStateGuiLevel $btProbeWatch.DeviceState)
                Write-BtLog "  COM port      : $(Get-ProbeStateUserText -Kind comport -State $btProbeWatch.ComPortState)" -Level (Get-ProbeStateGuiLevel $btProbeWatch.ComPortState)
                Write-BtLog "  Radio link    : $(Get-ProbeStateUserText -Kind btlink -State $initLink)" -Level (Get-ProbeStateGuiLevel $initLink)
                if ($initStream.State -eq 'Active') {
                    $streamPort = if ($initStream.ActivePort) { " ($($initStream.ActivePort))" } else { '' }
                    Write-BtLog "  EEG streaming : Active$streamPort" -Level "OK"
                }
                $noRunning = Test-ProcessRunningInSnapshot -ProcessNames $initProc -Name $btProbeAppName
                Write-BtLog "  NO.exe        : $(if ($noRunning) { 'Running' } else { 'Not running' })" -Level $(if ($noRunning) { 'OK' } else { 'DIM' })
                if ($btProbeSession.AdapterInfo -and $btProbeSession.AdapterInfo.Present) {
                    $driverVer = if ($btProbeSession.AdapterInfo.DriverInfo -and $btProbeSession.AdapterInfo.DriverInfo.Version) { $btProbeSession.AdapterInfo.DriverInfo.Version } else { 'unknown' }
                    Write-BtLog "  Adapter       : $($btProbeSession.AdapterInfo.FriendlyName)  driver v$driverVer" -Level "DIM"
                    $pm = $btProbeSession.AdapterInfo.PowerManagementEnabled
                    if ($pm -eq $true) { Write-BtLog "  USB suspend   : ENABLED (risk factor)" -Level "WARN" }
                }
                if ($btProbeSession.PowerPlan -and $btProbeSession.PowerPlan.IsPowerSaver) {
                    Write-BtLog "  Power plan    : $($btProbeSession.PowerPlan.ActivePlan) -- throttles USB/BT" -Level "WARN"
                }
                Write-BtLog "" -Level "DIM"
                if ($noRunning) {
                    Write-BtLog "  NeurOptimal is already running -- reproduce the Bluetooth issue" -Level "INFO"
                } else {
                    Write-BtLog "  Launch NeurOptimal, start a session and reproduce the Bluetooth issue" -Level "INFO"
                }
                Write-BtLog "  Click  Stop and Upload  when done (~10 sec to finish)" -Level "INFO"
                Write-BtLog "" -Level "DIM"
                Write-BtLog "  Watching for Bluetooth changes (every 3s) -- events appear below as they happen" -Level "DIM"
            } else {
                Write-BtLog "  Limited monitoring mode -- device tracking not available" -Level "WARN"
                if ($btProbeLoadError) {
                    Write-BtLog "  Reason: $btProbeLoadError" -Level "DIM"
                }
                Write-BtLog "  Only Bluetooth connect/disconnect events will be captured" -Level "DIM"
                $noRunningBasic = try { !!(Get-Process -Name $btProbeAppName -ErrorAction SilentlyContinue) } catch { $false }
                if ($noRunningBasic) {
                    Write-BtLog "  NeurOptimal is already running -- reproduce the Bluetooth issue" -Level "INFO"
                } else {
                    Write-BtLog "  Launch NeurOptimal, start a session and reproduce the Bluetooth issue" -Level "INFO"
                }
                Write-BtLog "  Click  Stop and Upload  when done (~10 sec to finish)" -Level "INFO"
                Write-BtLog "" -Level "DIM"
                Write-BtLog "  Monitoring Bluetooth activity -- connect/disconnect events will appear here" -Level "DIM"
            }

            $btNextProbeTick = $btRecordStart.AddSeconds(3)
            $btHeartbeatTick = 0
            $btAnomalyBarTime = $null

            while (-not $script:BtRec_StopClicked) {
                [System.Windows.Forms.Application]::DoEvents()
                $now = Get-Date
                $elapsed = $now - $btRecordStart

                # Update elapsed label with current state summary
                if ($btDeepProbeAvailable -and $btProbeWatch) {
                    $devShort = Get-ProbeStateUserText -Kind device -State $btProbeWatch.DeviceState -Short
                    $streamShort = Get-ProbeStateUserText -Kind stream -State $btProbeSession.StreamingState -Short
                    $btElapsedLabel.Text = "Recording  {0:mm\:ss}  |  {1}  |  Stream: {2}" -f $elapsed, $devShort, $streamShort
                } else {
                    $btElapsedLabel.Text = "Recording  {0:mm\:ss}  -- click Stop and Upload when done" -f $elapsed
                }

                # ── Deep probe tick (every 3s, main thread) ──────────────────
                if ($btDeepProbeAvailable -and $btProbeWatch -and $now -ge $btNextProbeTick) {
                    try {
                        $pnpNow  = Get-BluetoothPnpSnapshot
                        $comNow  = try { Get-BluetoothComPortSnapshot } catch { [pscustomobject]@{ Ports = @() } }
                        $procNow = try { Get-TargetDeviceProcessSnapshot } catch { @() }

                        $newObs = Update-TargetWatchState -WatchState $btProbeWatch -PnpSnapshot $pnpNow -ProcessNames $procNow -ComPortSnapshot $comNow

                        $probeEvents = Invoke-DeviceProbeTick -Session $btProbeSession -WatchState $btProbeWatch `
                            -NewObservations $newObs -TargetMac $btProbeTargetMac -AppProcessName $btProbeAppName

                        foreach ($evt in $probeEvents) {
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
                            if ($evt.Annotation) {
                                $annoLevel = if ($evt.Annotation.StartsWith('[!]')) { 'FAIL' } elseif ($evt.Annotation.StartsWith('[~]')) { 'WARN' } else { 'OK' }
                                Write-BtLog "             $($evt.Annotation)" -Level $annoLevel
                            }
                        }

                        # Update status strip
                        $btStateLabels['Device'].Text = "Device: $(Get-ProbeStateUserText -Kind device -State $btProbeWatch.DeviceState -Short)"
                        $btStateLabels['Device'].ForeColor = Get-ProbeStateColor $btProbeWatch.DeviceState
                        $comText = Get-ProbeStateUserText -Kind comport -State $btProbeWatch.ComPortState -Short
                        if ($btProbeWatch.ComPortState -in @('ComPortFound','ComPortAmbiguous')) {
                            $portNames = @()
                            if ($btProbeWatch.ComPortMatches.Count -gt 0) { $portNames += $btProbeWatch.ComPortMatches | ForEach-Object { $_.PortName } }
                            if ($btProbeWatch.AmbiguousComPortMatches.Count -gt 0) { $portNames += $btProbeWatch.AmbiguousComPortMatches | ForEach-Object { $_.PortName } }
                            $portNames = @($portNames | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
                            if ($portNames.Count -gt 0) { $comText = $portNames -join ',' }
                        }
                        $btStateLabels['COM'].Text = "COM: $comText"
                        $btStateLabels['COM'].ForeColor = Get-ProbeStateColor $btProbeWatch.ComPortState
                        $btStateLabels['Link'].Text = "Radio: $(Get-ProbeStateUserText -Kind btlink -State $btProbeSession.BtLinkState -Short)"
                        $btStateLabels['Link'].ForeColor = Get-ProbeStateColor $btProbeSession.BtLinkState
                        $btStateLabels['Stream'].Text = "Stream: $(Get-ProbeStateUserText -Kind stream -State $btProbeSession.StreamingState -Short)"
                        $btStateLabels['Stream'].ForeColor = Get-ProbeStateColor $btProbeSession.StreamingState
                        $appState = $btProbeWatch.AppProcessState
                        $btStateLabels['App'].Text = "NO.exe: $(if ($appState -eq 'Running') { 'Running' } else { 'Off' })"
                        $btStateLabels['App'].ForeColor = Get-ProbeStateColor $appState
                    } catch {
                        Write-BtLog "  [probe tick error]: $_" -Level "DIM"
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
                                    $diagSnap = Invoke-AnomalyDiagnosticSnapshot -Context $btProbeSession.PendingConfirmation
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
                        Write-BtLog "  ... watching  [${elSec}s]  Device: $hbDevice  |  Stream: $hbStream" -Level "DIM"
                    }

                    $btNextProbeTick = $now.AddSeconds(3)
                }

                # ── Event log poll (background job, every 8s -- unchanged) ───
                if ($btPollJob -and $btPollJob.State -notin @('Running', 'NotStarted')) {
                    $pollData = $null
                    try { $pollData = Receive-Job $btPollJob -ErrorAction SilentlyContinue } catch { }
                    Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue
                    $btPollJob = $null

                    if ($pollData) {
                        if (-not $btSvcStates) {
                            $btSvcStates = $pollData.Services
                        } else {
                            foreach ($k in @($pollData.Services.Keys)) {
                                $prev = $btSvcStates[$k]; $curr = $pollData.Services[$k]
                                if ($prev -and $curr -and $prev.Status -ne $curr.Status) {
                                    $lvl = if ($curr.Running) { 'OK' } else { 'WARN' }
                                    Write-BtLog "  Service: $($curr.DisplayName)  $($prev.Status) -> $($curr.Status)" -Level $lvl
                                }
                            }
                            $btSvcStates = $pollData.Services
                        }

                        if (-not $btDeepProbeAvailable) {
                            $newEvts = @($pollData.Events.Events | Where-Object { $_ -and $_.TimeCreated -gt $btPollSince })
                            if ($newEvts.Count -gt 0) {
                                $btPollSince = ($newEvts | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
                                $connEvts  = @($newEvts | Where-Object { $_.StableClass -eq 'Connected' })
                                $discEvts  = @($newEvts | Where-Object { $_.StableClass -eq 'Disconnected' })
                                $otherEvts = @($newEvts | Where-Object { $_.StableClass -eq 'Unknown' })
                                foreach ($ev in $connEvts) {
                                    Write-BtLog "  $($ev.TimeCreated.ToString('HH:mm:ss'))  Connected  ($($ev.ProviderName))" -Level "OK"
                                }
                                foreach ($ev in $discEvts) {
                                    Write-BtLog "  $($ev.TimeCreated.ToString('HH:mm:ss'))  Disconnected  ($($ev.ProviderName))" -Level "WARN"
                                }
                                if ($otherEvts.Count -gt 0) {
                                    Write-BtLog "  $($otherEvts.Count) Bluetooth event(s) captured" -Level "DIM"
                                }
                            } elseif ($btFirstPoll) {
                                Write-BtLog "  (no Bluetooth activity yet)" -Level "DIM"
                            }
                        }
                        $btFirstPoll = $false
                    }

                    $btNextPoll = (Get-Date).AddSeconds(8)
                }

                if (-not $btPollJob -and $now -ge $btNextPoll) {
                    $pollSince = $btPollSince; $pollMod = $btModPath
                    $btPollJob = Start-Job -ScriptBlock {
                        param($mp, $since)
                        Import-Module $mp -Force -ErrorAction SilentlyContinue
                        $evts = try { Get-BluetoothRecentEvents -Since $since -MaxEventsPerLog 100 } catch { $null }
                        $svcs = try { Get-BluetoothServiceStates } catch { @{} }
                        return @{ Events = $evts; Services = $svcs }
                    } -ArgumentList $pollMod, $pollSince
                }

                Start-Sleep -Milliseconds 200
            }

            if ($btPollJob) { Remove-Job $btPollJob -Force -ErrorAction SilentlyContinue }

            $btStopBtn.Enabled = $false
            $btAnomalyBar.Visible = $false
            $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(60, 40, 10)
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 100)
            $btBannerLabel.Text      = "Step 3 of 3 - Taking final snapshot, packaging and uploading..."
            $btElapsedLabel.Text     = "Packaging..."

            Write-BtLog ""
            Write-BtLog "Step 3 of 3: Stopping - taking final snapshot..." -Level "STEP"

            # ── Probe session summary (before final snapshot) ─────────────────────
            $btProbeSummary = $null
            if ($btDeepProbeAvailable -and $btProbeSession -and $btProbeWatch) {
                $btProbeSummary = Get-DeviceProbeSessionSummary -Session $btProbeSession -WatchState $btProbeWatch
                $btWatchReport  = New-TargetWatchReport -WatchState $btProbeWatch

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

                Write-BtLog "" -Level "DIM"
                Write-BtLog "FINDINGS" -Level "STEP"
                foreach ($f in $btProbeSummary.Findings) {
                    $fLevel = if ($f.StartsWith('[!]')) { 'FAIL' } elseif ($f.StartsWith('[~]')) { 'WARN' } elseif ($f.StartsWith('[ok]')) { 'OK' } else { 'DIM' }
                    Write-BtLog "  $f" -Level $fLevel
                }

                $realIssues = @($btWatchReport.Unresolved | Where-Object {
                    $_ -notmatch 'Ambiguous COM-port matches' -and $_ -notmatch 'Multiple COM-port entries share MAC'
                })
                if ($realIssues.Count -gt 0) {
                    Write-BtLog "" -Level "DIM"
                    Write-BtLog "UNRESOLVED ISSUES" -Level "FAIL"
                    foreach ($u in $realIssues) { Write-BtLog "  - $u" -Level "WARN" }
                } else {
                    Write-BtLog "" -Level "DIM"
                    Write-BtLog "  No unresolved issues." -Level "OK"
                }
                Write-BtLog "" -Level "DIM"

                # Save probe session artifact
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try {
                        Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'probe-session.json' -Data @{
                            SessionSummary = $btProbeSummary
                            WatchReport    = $btWatchReport
                            Observations   = @($btProbeWatch.Observations)
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

            while ($btFinalJob.State -in @('Running','NotStarted')) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 200
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
                Write-BtLog "Final: $($finalResult.Status)  Verdict=$vStr  Findings=$($finalResult.FindingCount)" -Level $flvl
                if ($btDiagRun -and (Get-Command Add-WinConfigDiagnosticArtifact -ErrorAction SilentlyContinue)) {
                    try { Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name "final.json" -Data $finalResult } catch { }
                }
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
                    $osCaption = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName } catch { $null }
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
                        BaselineVerdict      = if ($baselineResult) { $baselineResult.VerdictStatus } else { $null }
                        BaselineFindingCount = if ($baselineResult) { $baselineResult.FindingCount  } else { $null }
                        BaselineStatus       = if ($baselineResult) { $baselineResult.Status        } else { $null }
                        FinalVerdict         = if ($finalResult)    { $finalResult.VerdictStatus    } else { $null }
                        FinalFindingCount    = if ($finalResult)    { $finalResult.FindingCount     } else { $null }
                        FinalStatus          = if ($finalResult)    { $finalResult.Status           } else { $null }
                        ProbeObservationCount  = if ($btProbeSummary) { $btProbeSummary.ObservationCount } else { $null }
                        ProbeFindingCount      = if ($btProbeSummary) { $btProbeSummary.Findings.Count   } else { $null }
                        ProbeReconnectCount    = if ($btProbeSession) { $btProbeSession.ReconnectTimes.Count } else { $null }
                        ProbeBtLinkFlapCount   = if ($btProbeSession) { $btProbeSession.BtLinkFlapCount } else { $null }
                    }
                    Add-WinConfigDiagnosticArtifact -RunFolder $btDiagRun.RunFolder -Name 'manifest.json' -Data $manifest
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

                } catch {
                    Write-BtLog "Packaging failed: $($_.Exception.Message)" -Level "WARN"
                }
            }

            # Upload
            if ($btZipPath -and (Get-Command Get-WinConfigDiagnosticsUploadConfig -ErrorAction SilentlyContinue)) {
                $uploadConfig = Get-WinConfigDiagnosticsUploadConfig
                Write-BtLog "Uploading to $($uploadConfig.Provider)..."
                $btUploadLabel.Text = "Upload: Sending..."
                $btForm.Refresh()
                $runIdForMeta = if ($btDiagRun) { $btDiagRun.RunId } else { "" }
                $uploadResult = Send-WinConfigDiagnosticPackage -PackagePath $btZipPath -Config $uploadConfig -Metadata @{ RunId = $runIdForMeta } -FolderPrefix $btZipFolder
                if ($uploadResult.Status -eq 'Uploaded') {
                    Write-BtLog "Uploaded ($($uploadResult.Provider)): $($uploadResult.RemotePath)" -Level "OK"
                    $dest = if ($uploadResult.Provider -eq 'R2') { "R2: $($uploadResult.RemotePath)" } else { $uploadResult.RemotePath }
                    $btUploadLabel.Text = "Upload: Completed - $dest"
                } else {
                    Write-BtLog "Upload failed: $($uploadResult.Error)" -Level "WARN"
                    $btUploadLabel.Text = "Upload: Failed - $($uploadResult.Error)"
                }
            }

            $btBanner.BackColor      = [System.Drawing.Color]::FromArgb(20, 65, 25)
            $btBannerLabel.ForeColor = [System.Drawing.Color]::FromArgb(160, 240, 160)
            $btBannerLabel.Text      = "Done - diagnostic package uploaded. You may close this window."
            $btElapsedLabel.Text     = "Complete."

            if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
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

            $backupDir = Join-Path $env:TEMP "WinConfig-BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $backupPath = Join-Path $backupDir "ComArbiter-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

            try {
                & reg export $regExportPath $backupPath /y 2>&1 | Out-Null
                Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT COM Port Reset" -Detail "ComDB cleared, backup at $backupPath" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "PASS" -Tier 2 -Summary "COM arbiter reset"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show("COM Name Arbiter has been reset.`n`nNext Bluetooth pairing will use low COM port numbers (COM3, COM4).`n`nBackup saved to:`n$backupPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
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

            $ghostPorts = @()
            try {
                $allBtPorts = Get-PnpDevice -Class Ports -ErrorAction Stop |
                    Where-Object { $_.InstanceId -match 'BTHENUM' }
                $ghostPorts = @($allBtPorts | Where-Object {
                    $_.InstanceId -match 'LOCALMFG' -and $_.InstanceId -match '000000000000'
                })
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

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "This will remove $($ghostPorts.Count) ghost Bluetooth port(s) and reset COM port assignments.`n`nDevices may need to be re-paired after this operation.`n`nContinue?",
                "Confirm Bluetooth Port Cleanup",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            $backupDir = Join-Path $env:TEMP "WinConfig-BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $backupPath = Join-Path $backupDir "ComArbiter-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

            try {
                & reg export $regExportPath $backupPath /y 2>&1 | Out-Null

                $removed = 0
                $failed = 0
                foreach ($ghost in $ghostPorts) {
                    $result = & pnputil /remove-device $ghost.InstanceId 2>&1
                    if ($LASTEXITCODE -eq 0) { $removed++ } else { $failed++ }
                }

                if ($hasComDb) {
                    Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop
                }

                $summary = "$removed ghost port(s) removed"
                if ($failed -gt 0) { $summary += ", $failed failed" }
                if ($hasComDb) { $summary += ", COM arbiter reset" }

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Port Cleanup" -Detail "$summary; backup at $backupPath" -Category "AdminChange" -ToolCategory "Bluetooth" -Result $(if ($failed -gt 0) { "WARN" } else { "PASS" }) -Tier 2 -Summary $summary
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

            $backupDir = Join-Path $env:TEMP "WinConfig-BT-Backups"
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

            try {
                & reg export 'HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters' (Join-Path $backupDir "BTHPORT-$timestamp.reg") /y 2>&1 | Out-Null
                & reg export 'HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter' (Join-Path $backupDir "ComArbiter-$timestamp.reg") /y 2>&1 | Out-Null

                $devicesRemoved = 0
                $servicesRemoved = 0
                $ghostsRemoved = 0

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

                try {
                    $ghostPorts = @(Get-PnpDevice -Class Ports -ErrorAction Stop |
                        Where-Object { $_.InstanceId -match 'BTHENUM' -and $_.InstanceId -match 'LOCALMFG' -and $_.InstanceId -match '000000000000' })
                    foreach ($ghost in $ghostPorts) {
                        & pnputil /remove-device $ghost.InstanceId 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) { $ghostsRemoved++ }
                    }
                } catch {}

                try { Remove-ItemProperty -Path $arbiterPath -Name 'ComDB' -ErrorAction Stop } catch {}

                $summary = "$devicesRemoved paired device(s), $servicesRemoved service(s), $ghostsRemoved ghost port(s) removed, COM arbiter reset"
                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    Register-WinConfigSessionAction -Action "BT Stack Reset" -Detail "$summary; backups at $backupDir" -Category "AdminChange" -ToolCategory "Bluetooth" -Result "PASS" -Tier 4 -Summary "Full BT stack reset"
                }
                if (Get-Command Update-ResultsDiagnosticsView -ErrorAction SilentlyContinue) { Update-ResultsDiagnosticsView }
                [System.Windows.Forms.MessageBox]::Show(
                    "Bluetooth stack reset complete.`n`n$summary`n`nBackups saved to:`n$backupDir`n`nPlease REBOOT your computer now to complete the reset.",
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
            "Zengar UI"
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

                    $ghostPorts = @()
                    try {
                        $allBtPorts = Get-PnpDevice -Class Ports -ErrorAction Stop |
                            Where-Object { $_.InstanceId -match 'BTHENUM' }
                        $ghostPorts = @($allBtPorts | Where-Object {
                            $_.InstanceId -match 'LOCALMFG' -and $_.InstanceId -match '000000000000'
                        })
                    } catch {
                        # Get-PnpDevice may fail on older systems
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
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost PnP device" -Detail "$($ghost.InstanceId)").Summary
                        $affected += $ghost.InstanceId
                    }
                    if ($allocatedPorts.Count -gt 0) {
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "COM Name Arbiter ComDB value" -Detail "$($allocatedPorts.Count) port slots").Summary
                        $affected += "HKLM:\...\COM Name Arbiter\ComDB"
                    }

                    $ghostInfo = @()
                    foreach ($g in $ghostPorts) {
                        $ghostInfo += @{ InstanceId = $g.InstanceId; Status = "$($g.Status)"; FriendlyName = $g.FriendlyName }
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

                    $ghostPorts = @()
                    try {
                        $allBtPorts = Get-PnpDevice -Class Ports -ErrorAction Stop |
                            Where-Object { $_.InstanceId -match 'BTHENUM' }
                        $ghostPorts = @($allBtPorts | Where-Object {
                            $_.InstanceId -match 'LOCALMFG' -and $_.InstanceId -match '000000000000'
                        })
                    } catch {}

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
                        $actions += (New-DryRunStep -Verb WOULD_DELETE -Target "ghost PnP device" -Detail "$($ghost.InstanceId)").Summary
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
            "Bluetooth"    = @("Run Bluetooth Diagnostics", "Reset COM Port Numbers", "Clean Bluetooth Ports", "Full Bluetooth Stack Reset")
            "System"       = @("Copy System Info", "Copy Device Name", "Copy Serial Number", "Device Manager", "Task Manager", "Control Panel")
            "zAmp"         = @("Uninstall zAmp Drivers")
            "Zengar UI"    = @("Apply Win 11 Start Menu", "Apply branding colors", "Pin Taskbar Icons", "Apply Win Update Icon")
            "Updates"      = @("MS Store Updates", "Update Surface Drivers", "Microsoft Update Catalog", "Windows Insider")
            "Disk"         = @("DISM Restore Health", "/sfc scannow", "Defrag && Optimize", "Delete old backups", "Disk Cleanup", "Empty Recycle Bin")
            "NO Shortcuts" = @("%programdata%", "%localappdata%", "C:\zengar", "Documents\ScreenConnect")
        }

        # Phase 7.2: Store category badge references for pattern-aware surfacing
        if (-not $script:CategoryBadges) { $script:CategoryBadges = @{} }

        # Phase 7.3: Store tool button references for re-run functionality
        # REGRESSION GUARD: This hashtable persists - never cleared on category switch
        if (-not $script:ToolButtonRegistry) { $script:ToolButtonRegistry = @{} }

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
                            $btn.Add_Click({
                                param($sender, $e)
                                # Create execution context via guarded entrypoint
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
                                # If dry-run resolved, block live execution and redirect to dry-run path
                                if ($ctx.IsDryRun) {
                                    [System.Windows.Forms.MessageBox]::Show(
                                        "MODE: DRY RUN (Source: $($ctx.DryRunSource))`n`nLive execution blocked in dry-run mode.`nUse the Dry Run button to preview this tool's plan.",
                                        "Live Execution Blocked - $gateToolName",
                                        [System.Windows.Forms.MessageBoxButtons]::OK,
                                        [System.Windows.Forms.MessageBoxIcon]::Information
                                    )
                                    return
                                }
                                & $innerHandler
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

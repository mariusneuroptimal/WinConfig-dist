# Re-entry guard (prevents double-execution when dot-sourced)
# Note: Uses Get-Variable to avoid StrictMode error on unset variable
if (Get-Variable -Name '__WINCONFIG_LOADED' -Scope Script -ValueOnly -ErrorAction SilentlyContinue) { return }
$script:__WINCONFIG_LOADED = $true

# Load Windows Forms early (needed for MessageBox in error handling)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================================
# MODULE LOADING - Using ModuleLoader helpers
# ============================================================================
# Bootstrap preloads ModuleLoader.psm1 - verify functions are available
# Raw Import-Module is banned in this file - use helpers instead
if (-not (Get-Command 'Import-RequiredModule' -ErrorAction SilentlyContinue)) {
    throw "FATAL: ModuleLoader not loaded. Import-RequiredModule function missing. Run via Bootstrap.ps1."
}
if (-not (Get-Command 'Import-OptionalModule' -ErrorAction SilentlyContinue)) {
    throw "FATAL: ModuleLoader not loaded. Import-OptionalModule function missing. Run via Bootstrap.ps1."
}

# REQUIRED MODULES - Application fails without these
# Order matters: dependencies must load before dependents

# Paths MUST load first - provides ephemeral temp root for zero-footprint operation
Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\Paths.psm1")
Initialize-WinConfigPaths | Out-Null

# ExecutionIntent provides non-mutating diagnostic contract
Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\ExecutionIntent.psm1")

# DiagnosticTypes - typed result constants and Switch-DiagnosticResult helper
Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\DiagnosticTypes.psm1")
# Ensure DiagnosticTypes functions available in UI runspace (WinForms event handlers)
# CRITICAL: Use -Global to avoid removing the already-imported global module
Import-Module (Join-Path $PSScriptRoot 'Modules\DiagnosticTypes.psm1') -Force -Global

# Console module for diagnostic output formatting
Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\Console.psm1") -Prefix WinConfig

# OPTIONAL MODULES - Graceful degradation if missing

# Logger for JSONL session logging (prefixed to avoid collision with local Write-Log functions)
if (Import-OptionalModule -Path (Join-Path $PSScriptRoot "Logging\Logger.psm1") -Prefix WinConfig) {
    Initialize-WinConfigLogger -Version $AppVersion -Iteration $Iteration
    Write-WinConfigLog -Action "Startup" -Message "WinConfig application initialized"

    # Log ephemeral temp root ONCE at startup (for support verification)
    $tempRoot = Get-WinConfigTempRoot
    Write-WinConfigLog -Action "Startup" -Message "Session temp root: $tempRoot"
}

# SessionOperationLedger for session-scoped operation recording (prefixed)
if (Import-OptionalModule -Path (Join-Path $PSScriptRoot "Modules\SessionOperationLedger.psm1") -Prefix WinConfig) {
    Initialize-WinConfigSessionLedger -Version $AppVersion -Iteration $Iteration
}

# PpfFingerprint for problem pattern fingerprinting (prefixed)
$null = Import-OptionalModule -Path (Join-Path $PSScriptRoot "Modules\PpfFingerprint.psm1") -Prefix WinConfig

# ActionTiers for context-aware recommendations
$null = Import-OptionalModule -Path (Join-Path $PSScriptRoot "Modules\ActionTiers.psm1") -Prefix WinConfig

# ============================================================================
# DEFERRED MODULE LOADING - Performance optimization (PERF-001)
# These modules are NOT loaded at startup. They load on first use.
# Rule: No code from these modules executes before their tab/button is activated.
# ============================================================================

# Bluetooth module - deferred until Bluetooth tab is selected
$script:BluetoothModulePath = Join-Path $PSScriptRoot "Modules\Bluetooth.psm1"
$script:BluetoothModuleLoaded = $false

function Ensure-BluetoothModule {
    <#
    .SYNOPSIS
        Lazy-loads the Bluetooth module on first use.
    .DESCRIPTION
        PERF-001: Bluetooth.psm1 (2400+ lines) is only needed when user
        accesses the Bluetooth tab (~10% of sessions). Deferring saves ~100ms startup.
    #>
    if (-not $script:BluetoothModuleLoaded) {
        if (Test-Path $script:BluetoothModulePath) {
            $null = Import-OptionalModule -Path $script:BluetoothModulePath -Prefix WinConfig
            $script:BluetoothModuleLoaded = $true
        }
    }
}

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

# Function to refresh the actions display (called on tab switch to Diagnostics)
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

# Import shared modules (Phase 2C) - REQUIRED, fail-closed
# Using ModuleLoader helpers (loaded at top of file)
try {
    Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\Env.psm1")
    Import-RequiredModule -Path (Join-Path $PSScriptRoot "Modules\Paths.psm1")
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "WinConfig failed to load a required module.`n`n$($_.Exception.Message)",
        "Startup Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
}

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
$formTitle = "$AppName v.$AppVersion"
if ($Iteration -ne "production") {
    $formTitle = "$AppName v.$AppVersion [$($Iteration.ToUpper())]"
}
$form.Text = $formTitle
$form.Size = New-Object System.Drawing.Size(1300, 850)
$form.StartPosition = "CenterScreen"
$form.BackColor = $backgroundColor
$form.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.MinimumSize = New-Object System.Drawing.Size(1100, 750)

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
$tabControl.Multiline = $true
$tabControl.ItemSize = New-Object System.Drawing.Size(200, 40)
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
function New-Button($text) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $text
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.BackColor = $tabColor
    $button.ForeColor = $textColor
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $button.Width = 220
    $button.Height = 50
    $button.Margin = New-Object System.Windows.Forms.Padding(5)
    $button.AutoEllipsis = $true
    $button.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

    $graphics = $button.CreateGraphics()
    $textSize = $graphics.MeasureString($text, $button.Font)
    $button.Width = [Math]::Max(220, [Math]::Min(300, $textSize.Width + 20))
    $graphics.Dispose()

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

    # Create a new form for output
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = "Remove Intel SST Audio Driver"
    $outputForm.Size = New-Object System.Drawing.Size(800, 800)
    $outputForm.StartPosition = "CenterScreen"

    $outputTextBox = New-Object System.Windows.Forms.TextBox
    $outputTextBox.Multiline = $true
    $outputTextBox.ScrollBars = "Vertical"
    $outputTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $outputTextBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $outputForm.Controls.Add($outputTextBox)

    # Show the form immediately
    $outputForm.Show()
    $outputForm.Refresh()

    # Redirect Write-Host to the TextBox
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
        Write-Log "ROUTING / GEO" -Level STEP
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
            Write-Log "Public IP Country: $($ipInfo.country_name)"
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
            Start-Process "https://www.speedtest.net/"
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
    Start-Process $cleanmgrPath
}
"Defrag && Optimize" = {
    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
        Register-WinConfigSessionAction -Action "Defrag/Optimize" -Detail "Windows Defragment and Optimize utility launched" -Category "Maintenance" -Result "PASS" -Tier 0 -Summary "Optimize utility launched"
    }
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

    [System.Windows.Forms.MessageBox]::Show("Recycle Bin has been emptied.`nSpace freed: $sizeInMB MB", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}





    }


# Create tab pages
$tabPages = @(
    "System",
    "Updates",
    "Sound",
    "Custom UI",
    "Network Test",
    "Disk Health",
    "Disk Space",
    "Bluetooth",
    "Diagnostics"
)

foreach ($tabName in $tabPages) {
    $tabPage = New-TabPage $tabName
    $tabControl.TabPages.Add($tabPage) | Out-Null
}

# PERF-001: Lazy loading flags for expensive tabs
# The UI must render before expensive work (module loads, CIM queries) begins
$script:DiagnosticsTabInitialized = $false
$script:BluetoothTabInitialized = $false

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

foreach ($tabPage in $tabControl.TabPages) {
    $flowLayoutPanel = $tabPage.Controls[0]
    $content = $tabContents[$tabPage.Text]

    if ($tabPage.Text -eq "System") {
        # Create two columns for the System tab
        $tableLayoutPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $tableLayoutPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $tableLayoutPanel.ColumnCount = 2
        $tableLayoutPanel.RowCount = 1
        $tableLayoutPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 40))) | Out-Null
        $tableLayoutPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 60))) | Out-Null
        $tabPage.Controls.Clear()
        $tabPage.Controls.Add($tableLayoutPanel)

        $leftColumn = New-Object System.Windows.Forms.FlowLayoutPanel
        $leftColumn.Dock = [System.Windows.Forms.DockStyle]::Fill
        $leftColumn.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $leftColumn.WrapContents = $false
        $leftColumn.AutoScroll = $true

        $rightColumn = New-Object System.Windows.Forms.FlowLayoutPanel
        $rightColumn.Dock = [System.Windows.Forms.DockStyle]::Fill
        $rightColumn.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $rightColumn.WrapContents = $false
        $rightColumn.AutoScroll = $true

        $tableLayoutPanel.Controls.Add($leftColumn, 0, 0)
        $tableLayoutPanel.Controls.Add($rightColumn, 1, 0)

        # Populate left and right columns
        $leftColumn.Controls.Add((New-Headline $content[0].headline))
        foreach ($buttonText in $content[0].buttons) {
            $button = New-Button $buttonText
            $button.Add_Click($buttonHandlers[$buttonText])
            $leftColumn.Controls.Add($button)
        }

        $leftColumn.Controls.Add((New-Headline $content[1].headline))
        foreach ($buttonText in $content[1].buttons) {
            $button = New-Button $buttonText
            $button.Add_Click($buttonHandlers[$buttonText])
            $leftColumn.Controls.Add($button)
        }

        $rightColumn.Controls.Add((New-Headline $content[2].headline))
        foreach ($buttonText in $content[2].buttons) {
            $button = New-Button $buttonText
            $button.Add_Click($buttonHandlers[$buttonText])
            $rightColumn.Controls.Add($button)
        }
    }
    else {
        foreach ($section in $content) {
            $flowLayoutPanel.Controls.Add((New-Headline $section.headline))
            foreach ($buttonText in $section.buttons) {
                $button = New-Button $buttonText
                $button.Add_Click($buttonHandlers[$buttonText])
                $flowLayoutPanel.Controls.Add($button)
            }
        }
    }

    # Add GPO subheadline and buttons to Custom UI tab (only once, not as a duplicate headline)
    if ($tabPage.Text -eq "Custom UI") {
        $gpoHeadline = New-Headline "GPO"
        $flowLayoutPanel.Controls.Add($gpoHeadline)

        $gpoSubheadline = New-Object System.Windows.Forms.Label
        $gpoSubheadline.Text = "Country or region"
        $gpoSubheadline.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
        $gpoSubheadline.ForeColor = $tabColor
        $gpoSubheadline.AutoSize = $true
        $flowLayoutPanel.Controls.Add($gpoSubheadline)

        $gpoEnableButton = New-Button "Enable"
        $gpoDisableButton = New-Button "Disable"
        # EXEMPT-CONTRACT-001: Registry operations only, no diagnostic functions
        $gpoEnableButton.Add_Click({
            # Ensure running as administrator
            if (-not (Assert-WinConfigIsAdmin)) { return }

            # SAFETY: Block mutations if audit trail is broken
            if (-not (Assert-AuditTrailHealthyForMutation)) { return }

            $regPaths = @(
                'HKCU:\Software\Policies\Microsoft\Control Panel\International',
                'HKLM:\Software\Policies\Microsoft\Control Panel\International'
            )

            foreach ($path in $regPaths) {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force | Out-Null
                }
                New-ItemProperty -Path $path -Name PreventGeoIdChange           -PropertyType DWord -Value 1 -Force | Out-Null
                New-ItemProperty -Path $path -Name PreventUserOverrides         -PropertyType DWord -Value 1 -Force | Out-Null
                New-ItemProperty -Path $path -Name HideLocaleSelectAndCustomize -PropertyType DWord -Value 1 -Force | Out-Null
                New-ItemProperty -Path $path -Name RestrictUserLocales          -PropertyType String -Value '' -Force | Out-Null
            }

            # Register session action (admin verified, operation complete)
            if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                Register-WinConfigSessionAction -Action "GPO Enable" -Detail "Country/Region restriction policy enabled" -Category "AdminChange" -Result "PASS" -Tier 0 -Summary "Restriction policy enabled"
            }

            [System.Windows.Forms.MessageBox]::Show(
                "Policies ENABLED: Users are now restricted from changing Country/Region and Regional format.",
                "Restriction Enabled",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

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
                    return
                }
            }

            $result = [System.Windows.Forms.MessageBox]::Show(
                "A reboot is recommended for changes to take effect. Reboot now?",
                "Reboot Required",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                # SAFETY: Final audit check before reboot
                if (-not (Assert-AuditTrailHealthyForMutation)) { return }
                Restart-Computer
            }
        })
        # EXEMPT-CONTRACT-001: Registry operations only, no diagnostic functions
        $gpoDisableButton.Add_Click({
            # Ensure running as administrator
            if (-not (Assert-WinConfigIsAdmin)) { return }

            # SAFETY: Block mutations if audit trail is broken
            if (-not (Assert-AuditTrailHealthyForMutation)) { return }

            $regPaths = @(
                'HKCU:\Software\Policies\Microsoft\Control Panel\International',
                'HKLM:\Software\Policies\Microsoft\Control Panel\International'
            )

            foreach ($path in $regPaths) {
                if (Test-Path $path) {
                    foreach ($name in 'PreventGeoIdChange','PreventUserOverrides','HideLocaleSelectAndCustomize','RestrictUserLocales') {
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }

            # Register session action (admin verified, operation complete)
            if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                Register-WinConfigSessionAction -Action "GPO Disable" -Detail "Country/Region restriction policy disabled" -Category "AdminChange" -Result "PASS" -Tier 0 -Summary "Restriction policy disabled"
            }

            [System.Windows.Forms.MessageBox]::Show(
                "Policies DISABLED: Users can now manually change Country/Region and Regional format.",
                "Restriction Disabled",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

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
                    return
                }
            }

            $result = [System.Windows.Forms.MessageBox]::Show(
                "A reboot is recommended for changes to take effect. Reboot now?",
                "Reboot Required",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                # SAFETY: Final audit check before reboot
                if (-not (Assert-AuditTrailHealthyForMutation)) { return }
                Restart-Computer
            }
        })
        $flowLayoutPanel.Controls.Add($gpoEnableButton)
        $flowLayoutPanel.Controls.Add($gpoDisableButton)
    }

    # Bluetooth tab - Bluetooth audio diagnostics for Kodi
    # UI-LAYOUT-001: Uses TableLayoutPanel for enforced 2-column layout
    if ($tabPage.Text -eq "Bluetooth") {
        $tabPage.Controls.Clear()

        # PERF-001: Store reference for lazy initialization handler
        $script:BluetoothTabPage = $tabPage

        # PERF-001: Show placeholder during initial population
        # Actual content loads on first tab selection (via SelectedIndexChanged handler)
        if (-not $script:BluetoothTabInitialized) {
            $placeholderLabel = New-Object System.Windows.Forms.Label
            $placeholderLabel.Text = "Bluetooth diagnostics will load when this tab is selected..."
            $placeholderLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11)
            $placeholderLabel.ForeColor = [System.Drawing.Color]::Gray
            $placeholderLabel.AutoSize = $true
            $placeholderLabel.Padding = New-Object System.Windows.Forms.Padding(20)
            $tabPage.Controls.Add($placeholderLabel)
            $tabPage.Tag = "NeedsInit"
            continue  # Skip the rest of this tab's initialization
        }

        # PERF-001: Lazy-load Bluetooth module on first tab access
        Ensure-BluetoothModule

        # === ROOT LAYOUT: TableLayoutPanel with 2 columns (60%/40%) ===
        $btLayout = New-Object System.Windows.Forms.TableLayoutPanel
        $btLayout.Dock = [System.Windows.Forms.DockStyle]::Fill
        $btLayout.ColumnCount = 2
        $btLayout.RowCount = 1
        $btLayout.Padding = New-Object System.Windows.Forms.Padding(15)
        [void]$btLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 60)))
        [void]$btLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 40)))
        [void]$btLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $tabPage.Controls.Add($btLayout)

        # === LEFT COLUMN: Decision & Action ===
        $leftPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $leftPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $leftPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $leftPanel.WrapContents = $false
        $leftPanel.AutoScroll = $true
        $leftPanel.Padding = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
        $btLayout.Controls.Add($leftPanel, 0, 0)

        # === RIGHT COLUMN: Evidence & Reference ===
        $rightPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $rightPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $rightPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $rightPanel.WrapContents = $false
        $rightPanel.AutoScroll = $true
        $rightPanel.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
        $rightPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
        $btLayout.Controls.Add($rightPanel, 1, 0)

        # Check if Bluetooth module is available
        $btModuleAvailable = Get-Command Get-WinConfigBluetoothDiagnostics -ErrorAction SilentlyContinue

        if (-not $btModuleAvailable) {
            # Module not available - show message
            $noModuleLabel = New-Object System.Windows.Forms.Label
            $noModuleLabel.Text = "Bluetooth diagnostics module not loaded."
            $noModuleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
            $noModuleLabel.ForeColor = [System.Drawing.Color]::Gray
            $noModuleLabel.AutoSize = $true
            $noModuleLabel.Margin = New-Object System.Windows.Forms.Padding(0, 20, 0, 0)
            $leftPanel.Controls.Add($noModuleLabel)
        }
        else {
            # Collect diagnostics
            $btDiagnostics = Get-WinConfigBluetoothDiagnostics

            # Per VERDICT_DISPLAY_CONTRACT: No global verdict banners. Absence of warnings is the signal.

            # =====================================================================
            # LEFT COLUMN CONTENT: Kodi Audio Path, Findings, Safe Resets, Probe
            # =====================================================================

            # === LEFT: Kodi Audio Path (primary content) ===
            if ($btDiagnostics.KodiSettings.Found -and -not $btDiagnostics.KodiSettings.Error) {
                $kodiHeadline = New-Headline "Kodi Audio Path"
                $leftPanel.Controls.Add($kodiHeadline)

                # Kodi panel (Phase 3: FlowLayoutPanel, no absolute positioning)
                $kodiPanel = New-Object System.Windows.Forms.FlowLayoutPanel
                $kodiPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
                $kodiPanel.WrapContents = $false
                $kodiPanel.AutoSize = $true
                $kodiPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                $kodiPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
                $kodiPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)
                $kodiPanel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 10)

                # Audio device
                $kodiDeviceLabel = New-Object System.Windows.Forms.Label
                $kodiDeviceLabel.Text = "Output: $($btDiagnostics.KodiSettings.AudioDevice)"
                $kodiDeviceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $kodiDeviceLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                $kodiDeviceLabel.MaximumSize = New-Object System.Drawing.Size(360, 0)
                $kodiDeviceLabel.AutoSize = $true
                $kodiDeviceLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                $kodiPanel.Controls.Add($kodiDeviceLabel)

                # Mode
                $modeText = if ($btDiagnostics.KodiSettings.IsWASAPI) { "WASAPI" } elseif ($btDiagnostics.KodiSettings.IsDirectSound) { "DirectSound" } else { "Default" }
                $kodiModeLabel = New-Object System.Windows.Forms.Label
                $kodiModeLabel.Text = "Mode: $modeText"
                $kodiModeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $kodiModeLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                $kodiModeLabel.AutoSize = $true
                $kodiModeLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                $kodiPanel.Controls.Add($kodiModeLabel)

                # Passthrough status
                $ptText = if ($btDiagnostics.KodiSettings.PassthroughEnabled) { "Enabled" } else { "Disabled" }
                $ptColor = if ($btDiagnostics.KodiSettings.PassthroughEnabled -and $btDiagnostics.KodiSettings.IsBluetooth) { [System.Drawing.Color]::Crimson } else { [System.Drawing.Color]::FromArgb(60, 60, 60) }
                $kodiPTLabel = New-Object System.Windows.Forms.Label
                $kodiPTLabel.Text = "Passthrough: $ptText"
                $kodiPTLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $kodiPTLabel.ForeColor = $ptColor
                $kodiPTLabel.AutoSize = $true
                $kodiPTLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                $kodiPanel.Controls.Add($kodiPTLabel)

                # Channels
                if ($btDiagnostics.KodiSettings.Channels) {
                    $kodiChannelsLabel = New-Object System.Windows.Forms.Label
                    $kodiChannelsLabel.Text = "Channels: $($btDiagnostics.KodiSettings.Channels)"
                    $kodiChannelsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                    $kodiChannelsLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                    $kodiChannelsLabel.AutoSize = $true
                    $kodiChannelsLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
                    $kodiPanel.Controls.Add($kodiChannelsLabel)
                }

                $leftPanel.Controls.Add($kodiPanel)
            }
            elseif (-not $btDiagnostics.KodiSettings.Found) {
                # Kodi not installed - show subtle note
                $noKodiLabel = New-Object System.Windows.Forms.Label
                $noKodiLabel.Text = "Kodi configuration not found."
                $noKodiLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
                $noKodiLabel.ForeColor = [System.Drawing.Color]::DimGray
                $noKodiLabel.AutoSize = $true
                $noKodiLabel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 10)
                $leftPanel.Controls.Add($noKodiLabel)
            }

            # === LEFT: Findings (only if present - exceptions surface here) ===
            if ($btDiagnostics.Findings.Count -gt 0) {
                $findingsHeadline = New-Headline "Findings"
                $leftPanel.Controls.Add($findingsHeadline)

                foreach ($finding in $btDiagnostics.Findings) {
                    # Finding panel (Phase 3: FlowLayoutPanel, no absolute positioning)
                    $findingPanel = New-Object System.Windows.Forms.FlowLayoutPanel
                    $findingPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
                    $findingPanel.WrapContents = $false
                    $findingPanel.AutoSize = $true
                    $findingPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $findingPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
                    $findingPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 5)
                    $findingPanel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)

                    # Title with result color
                    $titleLabel = New-Object System.Windows.Forms.Label
                    $titleLabel.Text = "[$($finding.Result)] $($finding.Title)"
                    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                    $titleLabel.ForeColor = Switch-DiagnosticResult -Result $finding.Result -Cases @{
                        'PASS'    = { [System.Drawing.Color]::ForestGreen }
                        'WARN'    = { [System.Drawing.Color]::DarkOrange }
                        'FAIL'    = { [System.Drawing.Color]::Crimson }
                        'NOT_RUN' = { [System.Drawing.Color]::FromArgb(60, 60, 60) }
                    }
                    $titleLabel.AutoSize = $true
                    $titleLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 3)
                    $findingPanel.Controls.Add($titleLabel)

                    # Applies to
                    $appliesToLabel = New-Object System.Windows.Forms.Label
                    $appliesToLabel.Text = "Applies to: $($finding.AppliesTo)"
                    $appliesToLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                    $appliesToLabel.ForeColor = [System.Drawing.Color]::DimGray
                    $appliesToLabel.AutoSize = $true
                    $appliesToLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                    $findingPanel.Controls.Add($appliesToLabel)

                    # Evidence
                    $evidenceText = if ($finding.Evidence -is [array]) { $finding.Evidence -join " | " } else { $finding.Evidence }
                    $evidenceLabel = New-Object System.Windows.Forms.Label
                    $evidenceLabel.Text = $evidenceText
                    $evidenceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                    $evidenceLabel.ForeColor = [System.Drawing.Color]::DimGray
                    $evidenceLabel.MaximumSize = New-Object System.Drawing.Size(360, 0)
                    $evidenceLabel.AutoSize = $true
                    $evidenceLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                    $findingPanel.Controls.Add($evidenceLabel)

                    # Action hint
                    if ($finding.ActionHint) {
                        $hintLabel = New-Object System.Windows.Forms.Label
                        $hintLabel.Text = "-> $($finding.ActionHint)"
                        $hintLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
                        $hintLabel.ForeColor = $tabColor
                        $hintLabel.AutoSize = $true
                        $hintLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
                        $findingPanel.Controls.Add($hintLabel)
                    }

                    $leftPanel.Controls.Add($findingPanel)
                }

                # Spacer after findings
                $spacerFindings = New-Object System.Windows.Forms.Panel
                $spacerFindings.Height = 10
                $spacerFindings.AutoSize = $false
                $spacerFindings.Dock = [System.Windows.Forms.DockStyle]::Top
                $leftPanel.Controls.Add($spacerFindings)
            }

            # === LEFT: Safe Resets ===
            $actionsHeadline = New-Headline "Safe Resets"
            $leftPanel.Controls.Add($actionsHeadline)

            # Tier 1 label
            $tier1Label = New-Object System.Windows.Forms.Label
            $tier1Label.Text = "Tier 1 - Service Restart (No data loss)"
            $tier1Label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $tier1Label.ForeColor = [System.Drawing.Color]::DimGray
            $tier1Label.AutoSize = $true
            $tier1Label.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
            $leftPanel.Controls.Add($tier1Label)

            # Restart Services button
            $btnRestartServices = New-Button "Restart BT + Audio Services"
            # EXEMPT-CONTRACT-001: Service operations, uses string result not DiagnosticResult
            $btnRestartServices.Add_Click({
                if (-not (Assert-WinConfigIsAdmin)) { return }

                $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                    "This will restart Bluetooth and Windows Audio services. Audio playback will be briefly interrupted.`n`nProceed?",
                    "Confirm Service Restart",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )

                if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                $result = Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
                    Invoke-WinConfigBluetoothServiceReset
                }

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    $status = if ($result.Success) { "PASS" } else { "FAIL" }
                    Register-WinConfigSessionAction -Action "BT Service Restart" -Detail ($result.Details -join "; ") -Category "AdminChange" -Result $status -Tier 1 -Summary $result.Message
                }

                [System.Windows.Forms.MessageBox]::Show(
                    $result.Message + "`n`n" + ($result.Details -join "`n"),
                    "Service Restart Result",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    $(if ($result.Success) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning })
                )
            })
            $leftPanel.Controls.Add($btnRestartServices)

            # Tier 2 label
            $tier2Label = New-Object System.Windows.Forms.Label
            $tier2Label.Text = "Tier 2 - Cleanup (May require re-pairing)"
            $tier2Label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $tier2Label.ForeColor = [System.Drawing.Color]::DimGray
            $tier2Label.AutoSize = $true
            $tier2Label.Margin = New-Object System.Windows.Forms.Padding(0, 15, 0, 5)
            $leftPanel.Controls.Add($tier2Label)

            # Cleanup Endpoints button
            $btnCleanupEndpoints = New-Button "Remove Stale BT Endpoints"
            # EXEMPT-CONTRACT-001: Endpoint cleanup, uses string result not DiagnosticResult
            $btnCleanupEndpoints.Add_Click({
                if (-not (Assert-WinConfigIsAdmin)) { return }

                $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                    "This will remove disconnected/stale Bluetooth audio endpoints.`n`nThis may require re-pairing some devices.`n`nProceed?",
                    "Confirm Endpoint Cleanup",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )

                if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                $result = Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
                    Invoke-WinConfigBluetoothEndpointCleanup
                }

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    $status = if ($result.Success) { "PASS" } else { "WARN" }
                    Register-WinConfigSessionAction -Action "BT Endpoint Cleanup" -Detail ($result.Details -join "; ") -Category "AdminChange" -Result $status -Tier 2 -Summary $result.Message
                }

                [System.Windows.Forms.MessageBox]::Show(
                    $result.Message + "`n`n" + ($result.Details -join "`n"),
                    "Endpoint Cleanup Result",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    $(if ($result.Success) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning })
                )
            })
            $leftPanel.Controls.Add($btnCleanupEndpoints)

            # Tier 3 label
            $tier3Label = New-Object System.Windows.Forms.Label
            $tier3Label.Text = "Tier 3 - Reset Adapter (Reboot required)"
            $tier3Label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $tier3Label.ForeColor = [System.Drawing.Color]::DarkOrange
            $tier3Label.AutoSize = $true
            $tier3Label.Margin = New-Object System.Windows.Forms.Padding(0, 15, 0, 5)
            $leftPanel.Controls.Add($tier3Label)

            # Reset Adapter button
            $btnResetAdapter = New-Button "Reset Bluetooth Adapter"
            $btnResetAdapter.BackColor = [System.Drawing.Color]::FromArgb(180, 80, 80)
            # EXEMPT-CONTRACT-001: Adapter reset, uses string result not DiagnosticResult
            $btnResetAdapter.Add_Click({
                if (-not (Assert-WinConfigIsAdmin)) { return }

                $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                    "WARNING: This will disable and re-enable your Bluetooth adapter.`n`nAll paired devices will be disconnected.`nA REBOOT may be required.`n`nUse only as a last resort.`n`nProceed?",
                    "Confirm Adapter Reset",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Exclamation
                )

                if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                $result = Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
                    Invoke-WinConfigBluetoothAdapterReset
                }

                if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                    $status = if ($result.Success) { "PASS" } else { "FAIL" }
                    Register-WinConfigSessionAction -Action "BT Adapter Reset" -Detail ($result.Details -join "; ") -Category "AdminChange" -Result $status -Tier 3 -Summary $result.Message
                }

                $msgIcon = if ($result.Success) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning }
                $msgText = $result.Message + "`n`n" + ($result.Details -join "`n")
                if ($result.RebootRequired) {
                    $msgText += "`n`nA reboot is recommended."
                }

                [System.Windows.Forms.MessageBox]::Show(
                    $msgText,
                    "Adapter Reset Result",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    $msgIcon
                )
            })
            $leftPanel.Controls.Add($btnResetAdapter)

            # === LEFT: Active Probe Section ===
            $spacerProbe = New-Object System.Windows.Forms.Panel
            $spacerProbe.Height = 15
            $spacerProbe.AutoSize = $false
            $spacerProbe.Dock = [System.Windows.Forms.DockStyle]::Top
            $leftPanel.Controls.Add($spacerProbe)

            $probeHeadline = New-Headline "Active Probe"
            $leftPanel.Controls.Add($probeHeadline)

            $probeDesc = New-Object System.Windows.Forms.Label
            $probeDesc.Text = "Plays silent audio for 30s while monitoring for disconnects."
            $probeDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $probeDesc.ForeColor = [System.Drawing.Color]::DimGray
            $probeDesc.AutoSize = $true
            $probeDesc.MaximumSize = New-Object System.Drawing.Size(360, 0)
            $probeDesc.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 5)
            $leftPanel.Controls.Add($probeDesc)

            $btnProbe = New-Button "Run 30-Second Probe"
            $btnProbe.Add_Click({
                # Import in click handler runspace (WinForms delegates don't inherit modules)
                Import-Module (Join-Path $PSScriptRoot 'Modules\DiagnosticTypes.psm1') -Force

                $btnProbe.Enabled = $false
                $btnProbe.Text = "Probe Running..."

                try {
                    $probeResult = Invoke-WinConfigBluetoothProbe -DurationSeconds 30

                    if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                        $probeEvidence = @{
                            Disconnects = $probeResult.Disconnects
                            DeviceChanges = $probeResult.DeviceChanges
                            Duration = 30
                        }
                        Register-WinConfigSessionAction -Action "BT Active Probe" -Detail "30s probe completed" -Category "Diagnostics" -Result $probeResult.Result -Tier 0 -Summary "$($probeResult.Result) (Confidence: $($probeResult.Confidence))" -Evidence $probeEvidence
                    }

                    $resultIcon = Switch-DiagnosticResult -Result $probeResult.Result -Cases @{
                        'PASS'    = { [System.Windows.Forms.MessageBoxIcon]::Information }
                        'WARN'    = { [System.Windows.Forms.MessageBoxIcon]::Warning }
                        'FAIL'    = { [System.Windows.Forms.MessageBoxIcon]::Error }
                        'NOT_RUN' = { [System.Windows.Forms.MessageBoxIcon]::Question }
                    }
                    $eventsText = if ($probeResult.Events.Count -gt 0) {
                        "`n`nEvents detected:`n" + (($probeResult.Events | ForEach-Object { "- $($_.Type): $($_.Detail)" }) -join "`n")
                    } else { "" }

                    [System.Windows.Forms.MessageBox]::Show(
                        "Probe Result: $($probeResult.Result)`nConfidence: $($probeResult.Confidence)`n`nDisconnects: $($probeResult.Disconnects)`nDevice Changes: $($probeResult.DeviceChanges)$eventsText",
                        "Active Probe Result",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        $resultIcon
                    )
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Probe failed: $($_.Exception.Message)",
                        "Probe Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
                finally {
                    $btnProbe.Enabled = $true
                    $btnProbe.Text = "Run 30-Second Probe"
                }
            })
            $leftPanel.Controls.Add($btnProbe)

            # =====================================================================
            # RIGHT COLUMN CONTENT: Adapter, Services, Advanced Details
            # =====================================================================

            # === RIGHT: Adapter Info ===
            $adapterInfo = $btDiagnostics.Adapter
            if ($adapterInfo.Present) {
                $adapterHeadline = New-Headline "Adapter"
                $rightPanel.Controls.Add($adapterHeadline)

                $adapterLabel = New-Object System.Windows.Forms.Label
                $adapterLabel.Text = $adapterInfo.FriendlyName
                $adapterLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $adapterLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                $adapterLabel.AutoSize = $true
                $adapterLabel.MaximumSize = New-Object System.Drawing.Size(280, 0)
                $adapterLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
                $rightPanel.Controls.Add($adapterLabel)

                $statusLabel = New-Object System.Windows.Forms.Label
                $statusLabel.Text = "Status: $($adapterInfo.Status)"
                $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $statusColor = if ($adapterInfo.Enabled) { [System.Drawing.Color]::ForestGreen } else { [System.Drawing.Color]::DarkOrange }
                $statusLabel.ForeColor = $statusColor
                $statusLabel.AutoSize = $true
                $statusLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                $rightPanel.Controls.Add($statusLabel)

                if ($adapterInfo.DriverInfo -and $adapterInfo.DriverInfo.Version) {
                    $driverLabel = New-Object System.Windows.Forms.Label
                    $driverLabel.Text = "Driver: v$($adapterInfo.DriverInfo.Version)"
                    $driverLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                    $driverLabel.ForeColor = [System.Drawing.Color]::DimGray
                    $driverLabel.AutoSize = $true
                    $driverLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
                    $rightPanel.Controls.Add($driverLabel)
                }
            }

            # === RIGHT: Services Status ===
            $svcHeadline = New-Headline "Services"
            $rightPanel.Controls.Add($svcHeadline)

            foreach ($svcName in $btDiagnostics.Services.Keys) {
                $svc = $btDiagnostics.Services[$svcName]
                $svcStatus = if ($svc.Running) { "[OK]" } elseif ($svc.Status -eq "NotFound") { "[N/A]" } else { "[!]" }
                $svcColor = if ($svc.Running) { [System.Drawing.Color]::ForestGreen } elseif ($svc.Status -eq "NotFound") { [System.Drawing.Color]::DimGray } else { [System.Drawing.Color]::DarkOrange }

                $svcItemLabel = New-Object System.Windows.Forms.Label
                $svcItemLabel.Text = "$svcStatus $($svc.DisplayName)"
                $svcItemLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                $svcItemLabel.ForeColor = $svcColor
                $svcItemLabel.AutoSize = $true
                $svcItemLabel.MaximumSize = New-Object System.Drawing.Size(280, 0)
                $svcItemLabel.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 1)
                $rightPanel.Controls.Add($svcItemLabel)
            }

            # Spacer
            $spacerSvc = New-Object System.Windows.Forms.Panel
            $spacerSvc.Height = 10
            $spacerSvc.AutoSize = $false
            $spacerSvc.Dock = [System.Windows.Forms.DockStyle]::Top
            $rightPanel.Controls.Add($spacerSvc)

            # === RIGHT: Bluetooth Audio Devices (Phase 1 & 2) ===
            if ($btDiagnostics.BluetoothAudioDevices -and $btDiagnostics.BluetoothAudioDevices.Count -gt 0) {
                $audioDevicesHeadline = New-Headline "Bluetooth Audio Devices"
                $rightPanel.Controls.Add($audioDevicesHeadline)

                foreach ($audioDevice in $btDiagnostics.BluetoothAudioDevices) {
                    # Device panel (Phase 3: FlowLayoutPanel, no absolute positioning)
                    $devicePanel = New-Object System.Windows.Forms.FlowLayoutPanel
                    $devicePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
                    $devicePanel.WrapContents = $false
                    $devicePanel.AutoSize = $true
                    $devicePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $devicePanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
                    $devicePanel.Padding = New-Object System.Windows.Forms.Padding(8, 5, 8, 5)
                    $devicePanel.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 3)

                    # Device name (bold)
                    $deviceNameLabel = New-Object System.Windows.Forms.Label
                    $deviceNameLabel.Text = $audioDevice.Name
                    $deviceNameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                    $deviceNameLabel.ForeColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
                    $deviceNameLabel.MaximumSize = New-Object System.Drawing.Size(260, 0)
                    $deviceNameLabel.AutoSize = $true
                    $deviceNameLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                    $devicePanel.Controls.Add($deviceNameLabel)

                    # Connection state
                    $stateColor = switch ($audioDevice.ConnectionState) {
                        "Connected" { [System.Drawing.Color]::ForestGreen }
                        "Paired" { [System.Drawing.Color]::DimGray }
                        default { [System.Drawing.Color]::DarkOrange }
                    }
                    $stateLabel = New-Object System.Windows.Forms.Label
                    $stateLabel.Text = "State: $($audioDevice.ConnectionState)"
                    $stateLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                    $stateLabel.ForeColor = $stateColor
                    $stateLabel.AutoSize = $true
                    $stateLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                    $devicePanel.Controls.Add($stateLabel)

                    # Profile info (only show if known)
                    $profiles = @()
                    if ($audioDevice.SupportsA2DP -eq $true) { $profiles += "Stereo (A2DP)" }
                    if ($audioDevice.SupportsHFP -eq $true) { $profiles += "Hands-Free (HFP)" }
                    if ($profiles.Count -gt 0) {
                        $profileLabel = New-Object System.Windows.Forms.Label
                        $profileLabel.Text = "Profiles: $($profiles -join ', ')"
                        $profileLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                        $profileLabel.ForeColor = [System.Drawing.Color]::DimGray
                        $profileLabel.AutoSize = $true
                        $profileLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                        $devicePanel.Controls.Add($profileLabel)
                    }

                    # Default playback indicator (only if known)
                    if ($null -ne $audioDevice.IsDefaultPlayback) {
                        $defaultText = if ($audioDevice.IsDefaultPlayback) { "Default output: Yes" } else { "Default output: No" }
                        $defaultColor = if ($audioDevice.IsDefaultPlayback) { [System.Drawing.Color]::ForestGreen } else { [System.Drawing.Color]::DimGray }
                        $defaultLabel = New-Object System.Windows.Forms.Label
                        $defaultLabel.Text = $defaultText
                        $defaultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                        $defaultLabel.ForeColor = $defaultColor
                        $defaultLabel.AutoSize = $true
                        $defaultLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
                        $devicePanel.Controls.Add($defaultLabel)
                    }

                    # Action buttons panel
                    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel
                    $btnPanel.AutoSize = $true
                    $btnPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $btnPanel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 0)
                    $btnPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight

                    # Disable button
                    $btnDisable = New-Object System.Windows.Forms.Button
                    $btnDisable.Text = "Disable"
                    $btnDisable.Font = New-Object System.Drawing.Font("Segoe UI", 7)
                    $btnDisable.AutoSize = $true
                    $btnDisable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $btnDisable.Padding = New-Object System.Windows.Forms.Padding(8, 2, 8, 2)
                    $btnDisable.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $btnDisable.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)

                    # Disable button gating - block for default playback AND connected devices
                    $disableBlocked = $false
                    $disableTooltip = New-Object System.Windows.Forms.ToolTip

                    if ($audioDevice.IsDefaultPlayback -eq $true) {
                        $btnDisable.Enabled = $false
                        $disableBlocked = $true
                        $disableTooltip.SetToolTip($btnDisable, "Disable is blocked for the current default playback device")
                    }
                    elseif ($audioDevice.ConnectionState -eq "Connected") {
                        # Block connected devices to prevent accidental audio interruption
                        $btnDisable.Enabled = $false
                        $disableBlocked = $true
                        $disableTooltip.SetToolTip($btnDisable, "Disable is blocked while device is connected. Disconnect first.")
                    }

                    # Store device info for button click handlers (closure)
                    $deviceInstanceId = $audioDevice.InstanceId
                    $deviceName = $audioDevice.Name
                    $deviceIsDefault = $audioDevice.IsDefaultPlayback
                    $deviceConnectionState = $audioDevice.ConnectionState

                    # EXEMPT-CONTRACT-001: Device management, uses string result not DiagnosticResult
                    $btnDisable.Add_Click({
                        # Check probe guard
                        if (Test-WinConfigBluetoothProbeInProgress) {
                            [System.Windows.Forms.MessageBox]::Show(
                                "Action blocked: Bluetooth probe is currently running.`n`nStop the probe before changing device state.",
                                "Action Blocked",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            )
                            return
                        }

                        if (-not (Assert-WinConfigIsAdmin)) { return }

                        # Build warning message based on device state
                        $warningMsg = "WARNING: This will disable the Bluetooth device in Windows.`n`n"
                        $warningMsg += "Device: $deviceName`n"

                        if ($deviceConnectionState -eq "Connected") {
                            $warningMsg += "Status: CONNECTED (audio may be interrupted!)`n`n"
                            $warningMsg += "This device appears to be actively connected. Disabling it will:`n"
                            $warningMsg += "- Immediately disconnect the device`n"
                            $warningMsg += "- Stop any audio currently playing through it`n"
                            $warningMsg += "- Require re-enabling in Device Manager to use again`n"
                        } else {
                            $warningMsg += "Status: $deviceConnectionState`n`n"
                            $warningMsg += "Disabling will prevent this device from connecting until re-enabled in Device Manager.`n"
                        }

                        $warningMsg += "`nAre you sure you want to disable this device?"

                        # Confirmation dialog with explicit warning
                        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                            $warningMsg,
                            "Confirm Disable Device",
                            [System.Windows.Forms.MessageBoxButtons]::YesNo,
                            [System.Windows.Forms.MessageBoxIcon]::Warning
                        )

                        if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                        $result = Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
                            Invoke-WinConfigBluetoothAudioDeviceDisable -InstanceId $deviceInstanceId -Name $deviceName -IsDefaultPlayback $deviceIsDefault
                        }

                        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                            $status = if ($result.Success) { "PASS" } else { "WARN" }
                            Register-WinConfigSessionAction -Action "BT Device Disable" -Detail "$deviceName" -Category "AdminChange" -Result $status -Tier 2 -Summary $result.Message
                        }

                        [System.Windows.Forms.MessageBox]::Show(
                            $result.Message + "`n`n" + ($result.Details -join "`n"),
                            "Disable Device Result",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            $(if ($result.Success) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning })
                        )
                    }.GetNewClosure())

                    $btnPanel.Controls.Add($btnDisable)

                    # Remove (Unpair) button
                    $btnRemove = New-Object System.Windows.Forms.Button
                    $btnRemove.Text = "Remove (Unpair)"
                    $btnRemove.Font = New-Object System.Drawing.Font("Segoe UI", 7)
                    $btnRemove.AutoSize = $true
                    $btnRemove.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $btnRemove.Padding = New-Object System.Windows.Forms.Padding(8, 2, 8, 2)
                    $btnRemove.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $btnRemove.BackColor = [System.Drawing.Color]::FromArgb(230, 180, 180)
                    $btnRemove.Margin = New-Object System.Windows.Forms.Padding(5, 0, 0, 0)

                    # EXEMPT-CONTRACT-001: Device management, uses string result not DiagnosticResult
                    $btnRemove.Add_Click({
                        # Check probe guard
                        if (Test-WinConfigBluetoothProbeInProgress) {
                            [System.Windows.Forms.MessageBox]::Show(
                                "Action blocked: Bluetooth probe is currently running.`n`nStop the probe before changing device state.",
                                "Action Blocked",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            )
                            return
                        }

                        if (-not (Assert-WinConfigIsAdmin)) { return }

                        # Confirmation dialog with explicit warning
                        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                            "This will remove the Bluetooth device pairing. You may need to re-pair the device.`n`nDevice: $deviceName`n`nProceed?",
                            "Confirm Remove (Unpair)",
                            [System.Windows.Forms.MessageBoxButtons]::YesNo,
                            [System.Windows.Forms.MessageBoxIcon]::Warning
                        )

                        if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                        $result = Invoke-WithExecutionIntent -Intent 'ADMIN_ACTION' {
                            Invoke-WinConfigBluetoothAudioDeviceRemove -InstanceId $deviceInstanceId -Name $deviceName
                        }

                        if (Get-Command Register-WinConfigSessionAction -ErrorAction SilentlyContinue) {
                            $status = if ($result.Success) { "PASS" } else { "WARN" }
                            Register-WinConfigSessionAction -Action "BT Device Remove" -Detail "$deviceName (InstanceId: $deviceInstanceId)" -Category "AdminChange" -Result $status -Tier 2 -Summary $result.Message
                        }

                        [System.Windows.Forms.MessageBox]::Show(
                            $result.Message + "`n`n" + ($result.Details -join "`n"),
                            "Remove Device Result",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            $(if ($result.Success) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning })
                        )
                    }.GetNewClosure())

                    $btnPanel.Controls.Add($btnRemove)

                    $devicePanel.Controls.Add($btnPanel)
                    $rightPanel.Controls.Add($devicePanel)
                }

                # Spacer after audio devices
                $spacerAudioDev = New-Object System.Windows.Forms.Panel
                $spacerAudioDev.Height = 10
                $spacerAudioDev.AutoSize = $false
                $spacerAudioDev.Dock = [System.Windows.Forms.DockStyle]::Top
                $rightPanel.Controls.Add($spacerAudioDev)
            }

            # === RIGHT: Advanced Details (Collapsible) - Phase 3: FlowLayoutPanel ===
            $advancedContainer = New-Object System.Windows.Forms.FlowLayoutPanel
            $advancedContainer.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $advancedContainer.WrapContents = $false
            $advancedContainer.AutoSize = $true
            $advancedContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

            $toggleAdvanced = New-Object System.Windows.Forms.Button
            $toggleAdvanced.Text = "+ Details"
            $toggleAdvanced.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $toggleAdvanced.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
            $toggleAdvanced.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
            $toggleAdvanced.Font = New-Object System.Drawing.Font("Segoe UI", 8)
            $toggleAdvanced.AutoSize = $true
            $toggleAdvanced.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 5)
            $advancedContainer.Controls.Add($toggleAdvanced)

            $advancedContent = New-Object System.Windows.Forms.FlowLayoutPanel
            $advancedContent.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $advancedContent.WrapContents = $false
            $advancedContent.AutoSize = $true
            $advancedContent.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $advancedContent.Visible = $false
            $advancedContainer.Controls.Add($advancedContent)

            # Event log hints
            if ($btDiagnostics.EventLogHints.Count -gt 0) {
                $evtLabel = New-Object System.Windows.Forms.Label
                $evtLabel.Text = "Recent Events ($($btDiagnostics.EventLogHints.Count)):"
                $evtLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
                $evtLabel.AutoSize = $true
                $evtLabel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 2)
                $advancedContent.Controls.Add($evtLabel)

                foreach ($hint in ($btDiagnostics.EventLogHints.Hints | Select-Object -First 3)) {
                    $hintText = "[$($hint.Level)] $($hint.Time.ToString('HH:mm'))"
                    $hintLabel = New-Object System.Windows.Forms.Label
                    $hintLabel.Text = $hintText
                    $hintLabel.Font = New-Object System.Drawing.Font("Consolas", 7)
                    $hintLabel.ForeColor = if ($hint.Level -eq "Error") { [System.Drawing.Color]::Crimson } else { [System.Drawing.Color]::DarkOrange }
                    $hintLabel.AutoSize = $true
                    $advancedContent.Controls.Add($hintLabel)
                }
            }

            # Kodi raw settings (compact)
            if ($btDiagnostics.KodiSettings.Found -and $btDiagnostics.KodiSettings.RawSettings) {
                $kodiRawLabel = New-Object System.Windows.Forms.Label
                $kodiRawLabel.Text = "Kodi Audio (raw):"
                $kodiRawLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
                $kodiRawLabel.AutoSize = $true
                $kodiRawLabel.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 2)
                $advancedContent.Controls.Add($kodiRawLabel)

                foreach ($setting in ($btDiagnostics.KodiSettings.RawSettings | Select-Object -First 8)) {
                    $shortId = $setting.Id -replace "^audiooutput\.", ""
                    $settingLabel = New-Object System.Windows.Forms.Label
                    $settingLabel.Text = "$shortId`: $($setting.Value)"
                    $settingLabel.Font = New-Object System.Drawing.Font("Consolas", 7)
                    $settingLabel.ForeColor = [System.Drawing.Color]::DimGray
                    $settingLabel.AutoSize = $true
                    $settingLabel.MaximumSize = New-Object System.Drawing.Size(260, 0)
                    $advancedContent.Controls.Add($settingLabel)
                }
            }

            # EXEMPT-CONTRACT-001: Simple visibility toggle, no diagnostic functions
            $toggleAdvanced.Add_Click({
                $advancedContent.Visible = -not $advancedContent.Visible
                if ($advancedContent.Visible) {
                    $toggleAdvanced.Text = "- Details"
                } else {
                    $toggleAdvanced.Text = "+ Details"
                }
            }.GetNewClosure())

            $rightPanel.Controls.Add($advancedContainer)
        }
    }

    # Diagnostics tab - read-only operator support panel
    if ($tabPage.Text -eq "Diagnostics") {
        $tabPage.Controls.Clear()

        # Create a panel for diagnostics info
        $diagPanel = New-Object System.Windows.Forms.Panel
        $diagPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $diagPanel.Padding = New-Object System.Windows.Forms.Padding(20)
        $tabPage.Controls.Add($diagPanel)

        # Create a flow layout for the content
        $diagFlow = New-Object System.Windows.Forms.FlowLayoutPanel
        $diagFlow.Dock = [System.Windows.Forms.DockStyle]::Fill
        $diagFlow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $diagFlow.WrapContents = $false
        $diagFlow.AutoScroll = $true
        $diagPanel.Controls.Add($diagFlow)

        # Create TableLayoutPanel for diagnostic rows (Phase 1: DPI-safe layout)
        $diagTable = New-Object System.Windows.Forms.TableLayoutPanel
        $diagTable.Dock = [System.Windows.Forms.DockStyle]::Top
        $diagTable.AutoSize = $true
        $diagTable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $diagTable.ColumnCount = 2
        $diagTable.RowCount = 0
        $diagTable.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
        $diagTable.MinimumSize = New-Object System.Drawing.Size(700, 0)
        # Column 0: Labels (AutoSize)
        [void]$diagTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        # Column 1: Values (Fill remaining space)
        [void]$diagTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

        # Helper to add a diagnostic row to the TableLayoutPanel
        function Add-DiagnosticRow {
            param(
                [System.Windows.Forms.TableLayoutPanel]$Table,
                [string]$Label,
                [string]$Value
            )
            $rowIndex = $Table.RowCount
            $Table.RowCount++
            [void]$Table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

            $lblLabel = New-Object System.Windows.Forms.Label
            $lblLabel.Text = "${Label}:"
            $lblLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $lblLabel.ForeColor = $tabColor
            $lblLabel.AutoSize = $true
            $lblLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left
            $lblLabel.Margin = New-Object System.Windows.Forms.Padding(0, 8, 15, 8)
            $Table.Controls.Add($lblLabel, 0, $rowIndex)

            $txtValue = New-Object System.Windows.Forms.TextBox
            $txtValue.Text = $Value
            $txtValue.Font = New-Object System.Drawing.Font("Consolas", 10)
            $txtValue.ReadOnly = $true
            $txtValue.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $txtValue.BackColor = [System.Drawing.Color]::White
            $txtValue.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txtValue.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
            $Table.Controls.Add($txtValue, 1, $rowIndex)
        }

        # Add headline
        $diagHeadline = New-Headline "NO Support Tool Diagnostics"
        $diagFlow.Controls.Add($diagHeadline)

        # Add description with run ID clarification
        $descLabel = New-Object System.Windows.Forms.Label
        $descLabel.Text = "Read-only diagnostic information for support escalation. (Run ID is unique to this Support Tool run)"
        $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $descLabel.ForeColor = [System.Drawing.Color]::Gray
        $descLabel.AutoSize = $true
        $descLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 15)
        $diagFlow.Controls.Add($descLabel)

        # Get machine info for display
        $machineInfo = Get-WinConfigMachineInfo

        # Determine log file display text based on status
        $logFileDisplay = switch ($script:LogPathInfo.Status) {
            "Active"      { $script:LogPathInfo.Path }
            "Initialized" { "Initialized (no actions logged yet)" }
            "Disabled"    { "Logging disabled for this run" }
            default       { "Logging disabled for this run" }
        }

        # Get source commit for traceability display
        $sourceCommitDisplay = if ($env:WINCONFIG_SOURCE_COMMIT) {
            $env:WINCONFIG_SOURCE_COMMIT.Substring(0, 7)
        } else { "unknown" }

        # Add diagnostic rows to TableLayoutPanel (Phase 1: no absolute positioning)
        Add-DiagnosticRow -Table $diagTable -Label "Support Tool Run ID" -Value $script:SessionId
        Add-DiagnosticRow -Table $diagTable -Label "NO Support Tool Version" -Value "$AppVersion [$sourceCommitDisplay]"
        Add-DiagnosticRow -Table $diagTable -Label "Started" -Value $script:SessionStartTime
        Add-DiagnosticRow -Table $diagTable -Label "Device Name" -Value $machineInfo.DeviceName
        Add-DiagnosticRow -Table $diagTable -Label "Serial Number" -Value $machineInfo.SerialNumber
        Add-DiagnosticRow -Table $diagTable -Label "Log File" -Value $logFileDisplay
        $diagFlow.Controls.Add($diagTable)

        # Add spacer before Network Insights
        $spacer1 = New-Object System.Windows.Forms.Panel
        $spacer1.Height = 15
        $spacer1.AutoSize = $false
        $spacer1.Dock = [System.Windows.Forms.DockStyle]::Top
        $diagFlow.Controls.Add($spacer1)

        # === NETWORK INSIGHTS PANEL ===
        # Extract network test evidence from session actions
        $networkActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
            Get-WinConfigSessionActions | Where-Object {
                $_.Action -in @("Network Test", "Connectivity Test Complete") -and $_.Evidence
            }
        } else {
            @()
        }

        # Build Network Insights section if any network tests were run
        if ($networkActions.Count -gt 0) {
            $networkInsightsLabel = New-Object System.Windows.Forms.Label
            $networkInsightsLabel.Text = "Network Insights (This Run):"
            $networkInsightsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $networkInsightsLabel.ForeColor = $tabColor
            $networkInsightsLabel.AutoSize = $true
            $networkInsightsLabel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
            $diagFlow.Controls.Add($networkInsightsLabel)

            # Create network insights container (Phase 2: FlowLayoutPanel + TableLayoutPanel)
            $networkInsightsContainer = New-Object System.Windows.Forms.Panel
            $networkInsightsContainer.Dock = [System.Windows.Forms.DockStyle]::Top
            $networkInsightsContainer.AutoSize = $true
            $networkInsightsContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $networkInsightsContainer.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
            $networkInsightsContainer.Padding = New-Object System.Windows.Forms.Padding(10)
            $networkInsightsContainer.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 10)

            # Inner TableLayoutPanel for structured layout
            $insightsTable = New-Object System.Windows.Forms.TableLayoutPanel
            $insightsTable.Dock = [System.Windows.Forms.DockStyle]::Fill
            $insightsTable.AutoSize = $true
            $insightsTable.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $insightsTable.ColumnCount = 2
            $insightsTable.RowCount = 0
            # Column 0: Primary info (50%), Column 1: Secondary info (50%)
            [void]$insightsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
            [void]$insightsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
            $networkInsightsContainer.Controls.Add($insightsTable)

            # Extract country info from the most recent network action
            $latestNetworkAction = $networkActions | Sort-Object Timestamp -Descending | Select-Object -First 1
            $countryInfo = if ($latestNetworkAction.Evidence.Country) {
                $latestNetworkAction.Evidence.Country
            } else {
                @{ CountryCode = "XX"; CountryName = "Unknown"; CountryFlag = "" }
            }

            # Row 0: Country (spans both columns as header)
            $insightsTable.RowCount++
            [void]$insightsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $countryLabel = New-Object System.Windows.Forms.Label
            $countryLabel.Text = $countryInfo.CountryName
            $countryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
            $countryLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $countryLabel.AutoSize = $true
            $countryLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 5)
            $insightsTable.Controls.Add($countryLabel, 0, 0)
            $insightsTable.SetColumnSpan($countryLabel, 2)

            # Collect latency data from Network Test actions
            $latencyValues = @()
            foreach ($action in $networkActions) {
                if ($action.Evidence.LatencyMs -and $action.Evidence.LatencyMs -gt 0) {
                    $latencyValues += $action.Evidence.LatencyMs
                }
            }

            # Calculate average latency
            $avgLatency = if ($latencyValues.Count -gt 0) {
                [math]::Round(($latencyValues | Measure-Object -Average).Average, 1)
            } else { $null }

            # Row 1: Latency | Connection
            $insightsTable.RowCount++
            [void]$insightsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

            $latencyText = if ($null -ne $avgLatency) {
                $latencyQuality = if ($avgLatency -le 50) { "good" } elseif ($avgLatency -le 150) { "average" } else { "slow" }
                "Avg Latency: ${avgLatency}ms ($latencyQuality)"
            } else {
                "Avg Latency: N/A"
            }
            $latencyLabel = New-Object System.Windows.Forms.Label
            $latencyLabel.Text = $latencyText
            $latencyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $latencyLabel.ForeColor = [System.Drawing.Color]::DimGray
            $latencyLabel.AutoSize = $true
            $latencyLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
            $insightsTable.Controls.Add($latencyLabel, 0, 1)

            # Connection type (right column of row 1)
            $connectionTypes = @()
            foreach ($action in $networkActions) {
                if ($action.Evidence.ConnectionType -and $action.Evidence.ConnectionType -ne "None") {
                    $connectionTypes += $action.Evidence.ConnectionType
                }
            }
            $connectionText = if ($connectionTypes.Count -gt 0) {
                "Connection: $($connectionTypes | Select-Object -Unique | Select-Object -First 1)"
            } else {
                "Connection: Unknown"
            }
            $connectionLabel = New-Object System.Windows.Forms.Label
            $connectionLabel.Text = $connectionText
            $connectionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $connectionLabel.ForeColor = [System.Drawing.Color]::DimGray
            $connectionLabel.AutoSize = $true
            $connectionLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
            $insightsTable.Controls.Add($connectionLabel, 1, 1)

            # Collect link speed data
            $linkSpeeds = @()
            foreach ($action in $networkActions) {
                if ($action.Evidence.LinkSpeedMbps -and $action.Evidence.LinkSpeedMbps -gt 0) {
                    $linkSpeeds += $action.Evidence.LinkSpeedMbps
                }
            }
            $avgLinkSpeed = if ($linkSpeeds.Count -gt 0) {
                [math]::Round(($linkSpeeds | Measure-Object -Average).Average, 0)
            } else { $null }

            # Row 2: Link Speed
            $insightsTable.RowCount++
            [void]$insightsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

            $linkSpeedText = if ($null -ne $avgLinkSpeed) {
                if ($avgLinkSpeed -ge 1000) {
                    "Link Speed: $([math]::Round($avgLinkSpeed / 1000, 1)) Gbps"
                } else {
                    "Link Speed: ${avgLinkSpeed} Mbps"
                }
            } else {
                "Link Speed: N/A"
            }
            $linkSpeedLabel = New-Object System.Windows.Forms.Label
            $linkSpeedLabel.Text = $linkSpeedText
            $linkSpeedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $linkSpeedLabel.ForeColor = [System.Drawing.Color]::DimGray
            $linkSpeedLabel.AutoSize = $true
            $linkSpeedLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
            $insightsTable.Controls.Add($linkSpeedLabel, 0, 2)
            $insightsTable.SetColumnSpan($linkSpeedLabel, 2)

            # Failure counts by type
            $dnsFailures = 0
            $portFailures = 0
            $tlsInterceptions = 0
            foreach ($action in $networkActions) {
                if ($action.Evidence) {
                    if ($action.Evidence.DNS -eq $false) { $dnsFailures++ }
                    if ($action.Evidence.Ports -eq $false) { $portFailures++ }
                    if ($action.Evidence.TLSIntercepted -eq $true) { $tlsInterceptions++ }
                }
            }

            $failureSummary = @()
            if ($dnsFailures -gt 0) { $failureSummary += "DNS: $dnsFailures" }
            if ($portFailures -gt 0) { $failureSummary += "Ports: $portFailures" }
            if ($tlsInterceptions -gt 0) { $failureSummary += "TLS Intercept: $tlsInterceptions" }

            $failureText = if ($failureSummary.Count -gt 0) {
                "Issues: $($failureSummary -join ' | ')"
            } else {
                "Issues: None detected"
            }
            $failureColor = if ($failureSummary.Count -gt 0) { [System.Drawing.Color]::DarkOrange } else { [System.Drawing.Color]::ForestGreen }

            # Row 3: Issues
            $insightsTable.RowCount++
            [void]$insightsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

            $failureLabel = New-Object System.Windows.Forms.Label
            $failureLabel.Text = $failureText
            $failureLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $failureLabel.ForeColor = $failureColor
            $failureLabel.AutoSize = $true
            $failureLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
            $insightsTable.Controls.Add($failureLabel, 0, 3)
            $insightsTable.SetColumnSpan($failureLabel, 2)

            $diagFlow.Controls.Add($networkInsightsContainer)

            # Spacer after network insights
            $spacerNetworkInsights = New-Object System.Windows.Forms.Panel
            $spacerNetworkInsights.Height = 10
            $spacerNetworkInsights.AutoSize = $false
            $spacerNetworkInsights.Dock = [System.Windows.Forms.DockStyle]::Top
            $diagFlow.Controls.Add($spacerNetworkInsights)
        }

        # Add Session Actions Timeline section
        $actionsLabel = New-Object System.Windows.Forms.Label
        $actionsLabel.Text = "Actions Executed This Run:"
        $actionsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $actionsLabel.ForeColor = $tabColor
        $actionsLabel.AutoSize = $true
        $actionsLabel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
        $diagFlow.Controls.Add($actionsLabel)

        # Create container for actions (refreshed on tab switch)
        $actionsContainer = New-Object System.Windows.Forms.FlowLayoutPanel
        $actionsContainer.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $actionsContainer.WrapContents = $false
        $actionsContainer.AutoSize = $true
        $actionsContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $actionsContainer.Dock = [System.Windows.Forms.DockStyle]::Top
        $diagFlow.Controls.Add($actionsContainer)

        # Store reference for refresh
        $script:DiagActionsContainer = $actionsContainer

        # Initial population
        Update-DiagActionsDisplay

        # Add spacer before button
        $spacer2 = New-Object System.Windows.Forms.Panel
        $spacer2.Height = 20
        $spacer2.AutoSize = $false
        $spacer2.Dock = [System.Windows.Forms.DockStyle]::Top
        $diagFlow.Controls.Add($spacer2)

        # Add "Copy to Clipboard" button
        $copyDiagButton = New-Object System.Windows.Forms.Button
        $copyDiagButton.Text = "Copy to Clipboard"
        $copyDiagButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $copyDiagButton.BackColor = $tabColor
        $copyDiagButton.ForeColor = $textColor
        $copyDiagButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $copyDiagButton.AutoSize = $true
        # EXEMPT-CONTRACT-001: Clipboard operations, no Switch-DiagnosticResult usage
        $copyDiagButton.Add_Click({
            # Get machine info for clipboard
            $clipMachineInfo = Get-WinConfigMachineInfo

            # Determine log file display text for clipboard
            $clipLogFileDisplay = switch ($script:LogPathInfo.Status) {
                "Active"      { $script:LogPathInfo.Path }
                "Initialized" { "Initialized (no actions logged yet)" }
                "Disabled"    { "Logging disabled for this run" }
                default       { "Logging disabled for this run" }
            }

            # Get session actions for clipboard
            $clipSessionActions = if (Get-Command Get-WinConfigSessionActions -ErrorAction SilentlyContinue) {
                Get-WinConfigSessionActions
            } else {
                @()
            }

            # === Build Network Insights section for clipboard ===
            $clipNetworkActions = $clipSessionActions | Where-Object {
                $_.Action -in @("Network Test", "Connectivity Test Complete") -and $_.Evidence
            }

            $networkInsightsText = ""
            if ($clipNetworkActions.Count -gt 0) {
                # Get country info
                $clipLatestNetworkAction = $clipNetworkActions | Sort-Object Timestamp -Descending | Select-Object -First 1
                $clipCountryInfo = if ($clipLatestNetworkAction.Evidence.Country) {
                    $clipLatestNetworkAction.Evidence.Country
                } else {
                    @{ CountryCode = "XX"; CountryName = "Unknown"; CountryFlag = "" }
                }

                # Collect metrics
                $clipLatencyValues = @()
                $clipLinkSpeeds = @()
                $clipDnsFailures = 0
                $clipPortFailures = 0
                $clipTlsInterceptions = 0
                $clipConnectionTypes = @()

                foreach ($action in $clipNetworkActions) {
                    if ($action.Evidence.LatencyMs -and $action.Evidence.LatencyMs -gt 0) {
                        $clipLatencyValues += $action.Evidence.LatencyMs
                    }
                    if ($action.Evidence.LinkSpeedMbps -and $action.Evidence.LinkSpeedMbps -gt 0) {
                        $clipLinkSpeeds += $action.Evidence.LinkSpeedMbps
                    }
                    if ($action.Evidence.DNS -eq $false) { $clipDnsFailures++ }
                    if ($action.Evidence.Ports -eq $false) { $clipPortFailures++ }
                    if ($action.Evidence.TLSIntercepted -eq $true) { $clipTlsInterceptions++ }
                    if ($action.Evidence.ConnectionType -and $action.Evidence.ConnectionType -ne "None") {
                        $clipConnectionTypes += $action.Evidence.ConnectionType
                    }
                }

                $clipAvgLatency = if ($clipLatencyValues.Count -gt 0) {
                    [math]::Round(($clipLatencyValues | Measure-Object -Average).Average, 1)
                } else { $null }

                $clipAvgLinkSpeed = if ($clipLinkSpeeds.Count -gt 0) {
                    [math]::Round(($clipLinkSpeeds | Measure-Object -Average).Average, 0)
                } else { $null }

                $clipLatencyQuality = if ($null -ne $clipAvgLatency) {
                    if ($clipAvgLatency -le 50) { "good" } elseif ($clipAvgLatency -le 150) { "average" } else { "slow" }
                } else { "N/A" }

                $clipLinkSpeedText = if ($null -ne $clipAvgLinkSpeed) {
                    if ($clipAvgLinkSpeed -ge 1000) { "$([math]::Round($clipAvgLinkSpeed / 1000, 1)) Gbps" } else { "${clipAvgLinkSpeed} Mbps" }
                } else { "N/A" }

                $clipConnectionText = if ($clipConnectionTypes.Count -gt 0) {
                    $clipConnectionTypes | Select-Object -Unique | Select-Object -First 1
                } else { "Unknown" }

                $clipFailureSummary = @()
                if ($clipDnsFailures -gt 0) { $clipFailureSummary += "DNS: $clipDnsFailures" }
                if ($clipPortFailures -gt 0) { $clipFailureSummary += "Ports: $clipPortFailures" }
                if ($clipTlsInterceptions -gt 0) { $clipFailureSummary += "TLS Intercept: $clipTlsInterceptions" }
                $clipIssuesText = if ($clipFailureSummary.Count -gt 0) { $clipFailureSummary -join " | " } else { "None detected" }

                $networkInsightsText = @"

Network Insights (This Session):
  Region:       $($clipCountryInfo.CountryFlag) $($clipCountryInfo.CountryName)
  Avg Latency:  $(if ($null -ne $clipAvgLatency) { "${clipAvgLatency}ms ($clipLatencyQuality)" } else { "N/A" })
  Link Speed:   $clipLinkSpeedText
  Connection:   $clipConnectionText
  Issues:       $clipIssuesText

"@
            }

            # Build actions section
            $actionsText = ""
            if ($clipSessionActions.Count -eq 0) {
                $actionsText = "  (No actions executed yet)"
            } else {
                foreach ($action in $clipSessionActions) {
                    $timeStr = $action.Timestamp.ToString("HH:mm:ss")
                    $actionsText += "  * $timeStr - $($action.Action)`n"
                    $actionsText += "      $($action.Detail)`n"
                }
                $actionsText = $actionsText.TrimEnd("`n")
            }

            # Get source commit for clipboard
            $clipSourceCommit = if ($env:WINCONFIG_SOURCE_COMMIT) {
                $env:WINCONFIG_SOURCE_COMMIT.Substring(0, 7)
            } else { "unknown" }

            # === Generate PPF (Problem Pattern Fingerprint) ===
            $ppfText = ""
            try {
                $ppfFunction = Get-Command New-WinConfigProblemPatternFingerprint -ErrorAction SilentlyContinue
                if (-not $ppfFunction) {
                    $ppfFunction = Get-Command New-ProblemPatternFingerprint -ErrorAction SilentlyContinue
                }

                if ($ppfFunction) {
                    # Get operations from ledger
                    $ledgerOps = if (Get-Command Get-WinConfigLedgerOperations -ErrorAction SilentlyContinue) {
                        @(Get-WinConfigLedgerOperations)
                    } else { @() }

                    $ppf = & $ppfFunction -Operations $ledgerOps
                    if ($ppf) {
                        $ppfText = @"

Problem Pattern Fingerprint:
  PPF ID:        $($ppf.Id)
  OS Bucket:     $($ppf.OsBucket)
  Network Class: $($ppf.NetworkClass)
  Failures:      $($ppf.FailureCount)

"@
                    }
                }
            }
            catch {
                # PPF generation failed - non-fatal, continue without it
            }

            $diagText = @"
NO Support Tool Diagnostics
===========================

Support Tool Run ID:      $($script:SessionId)
NO Support Tool Version:  $AppVersion [$clipSourceCommit]
Started:                  $($script:SessionStartTime)

Device Name:              $($clipMachineInfo.DeviceName)
Serial Number:            $($clipMachineInfo.SerialNumber)

Log File:
  $clipLogFileDisplay
$networkInsightsText$ppfText
Actions Executed This Run:
$actionsText
"@
            [System.Windows.Forms.Clipboard]::SetText($diagText)
            [System.Windows.Forms.MessageBox]::Show(
                "Diagnostics copied to clipboard.",
                "Copied",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        })
        $diagFlow.Controls.Add($copyDiagButton)

        # Add export checkbox (Cloudflare R2 ingest is always available)
        if ($true) {
            $spacer3 = New-Object System.Windows.Forms.Panel
            $spacer3.Height = 15
            $spacer3.AutoSize = $false
            $spacer3.Dock = [System.Windows.Forms.DockStyle]::Top
            $diagFlow.Controls.Add($spacer3)

            $script:chkExportDiagnostics = New-Object System.Windows.Forms.CheckBox
            $script:chkExportDiagnostics.Text = "Share anonymized network diagnostics for internal analysis"
            $script:chkExportDiagnostics.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $script:chkExportDiagnostics.ForeColor = [System.Drawing.Color]::DimGray
            $script:chkExportDiagnostics.AutoSize = $true
            $script:chkExportDiagnostics.Checked = $true
            $diagFlow.Controls.Add($script:chkExportDiagnostics)

            # Tooltip explaining export behavior
            $exportTooltip = New-Object System.Windows.Forms.ToolTip
            $exportTooltip.SetToolTip($script:chkExportDiagnostics, @"
Export happens only at session end.
Data is anonymized (country-level only).
Uploaded directly to Cloudflare R2 via HTTPS.
No local files are retained after upload.
"@)

            # Status line (visible only when checkbox is checked)
            $script:lblExportStatus = New-Object System.Windows.Forms.Label
            $script:lblExportStatus.Text = "Analytics export: Enabled (ephemeral, no local files retained)"
            $script:lblExportStatus.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
            $script:lblExportStatus.ForeColor = [System.Drawing.Color]::ForestGreen
            $script:lblExportStatus.AutoSize = $true
            $script:lblExportStatus.Visible = $false
            $script:lblExportStatus.Margin = New-Object System.Windows.Forms.Padding(20, 2, 0, 0)
            $diagFlow.Controls.Add($script:lblExportStatus)

            # Toggle status line visibility when checkbox changes
            $script:chkExportDiagnostics.Add_CheckedChanged({
                $script:lblExportStatus.Visible = $script:chkExportDiagnostics.Checked
            })
        }
    }
}


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

# Refresh actions display when switching to Diagnostics tab
# EXEMPT-CONTRACT-001: Simple UI refresh, no diagnostic functions
$tabControl.Add_SelectedIndexChanged({
    $selectedTab = $tabControl.SelectedTab
    if ($selectedTab -and $selectedTab.Text -eq "Diagnostics") {
        Update-DiagActionsDisplay
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
            $forbiddenKeys = @('IPAddress', 'IP', 'IPv4', 'IPv6', 'Hostname', 'ComputerName', 'MachineName',
                               'DeviceName', 'SerialNumber', 'MACAddress', 'MAC', 'Username', 'User',
                               'ISP', 'ASN', 'Organization', 'Org')

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

            $payload = @{
                SchemaVersion = "1.0"
                ExportedAt = (Get-Date).ToString("o")
                SessionId = $script:SessionId
                AppVersion = $AppVersion
                Iteration = $Iteration
                SessionStartTime = $script:SessionStartTime
                Actions = @($exportSessionActions)
                ppf = $exportPpf
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

# ============================================================================
# PERF-001: Lazy tab initialization handler
# Populates deferred tabs on first selection (Bluetooth, Diagnostics)
# ============================================================================
$tabControl.Add_SelectedIndexChanged({
    # Import in event handler runspace (WinForms delegates don't inherit modules)
    Import-Module (Join-Path $PSScriptRoot 'Modules\DiagnosticTypes.psm1') -Force

    $selectedTab = $tabControl.SelectedTab
    if ($null -eq $selectedTab) { return }

    # Bluetooth tab lazy initialization
    if ($selectedTab.Text -eq "Bluetooth" -and $selectedTab.Tag -eq "NeedsInit") {
        $selectedTab.Tag = $null
        $script:BluetoothTabInitialized = $true

        # Clear placeholder and load module
        $selectedTab.Controls.Clear()
        Ensure-BluetoothModule

        # Check if module loaded successfully
        $btModuleAvailable = Get-Command Get-WinConfigBluetoothDiagnostics -ErrorAction SilentlyContinue

        if (-not $btModuleAvailable) {
            $noModuleLabel = New-Object System.Windows.Forms.Label
            $noModuleLabel.Text = "Bluetooth diagnostics module could not be loaded."
            $noModuleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
            $noModuleLabel.ForeColor = [System.Drawing.Color]::Gray
            $noModuleLabel.AutoSize = $true
            $noModuleLabel.Padding = New-Object System.Windows.Forms.Padding(20)
            $selectedTab.Controls.Add($noModuleLabel)
        } else {
            # Build Bluetooth tab content directly
            # === ROOT LAYOUT: TableLayoutPanel with 2 columns (60%/40%) ===
            $btLayout = New-Object System.Windows.Forms.TableLayoutPanel
            $btLayout.Dock = [System.Windows.Forms.DockStyle]::Fill
            $btLayout.ColumnCount = 2
            $btLayout.RowCount = 1
            $btLayout.Padding = New-Object System.Windows.Forms.Padding(15)
            [void]$btLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 60)))
            [void]$btLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 40)))
            [void]$btLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
            $selectedTab.Controls.Add($btLayout)

            # === LEFT COLUMN ===
            $leftPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $leftPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
            $leftPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $leftPanel.WrapContents = $false
            $leftPanel.AutoScroll = $true
            $leftPanel.Padding = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
            $btLayout.Controls.Add($leftPanel, 0, 0)

            # === RIGHT COLUMN ===
            $rightPanel = New-Object System.Windows.Forms.FlowLayoutPanel
            $rightPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
            $rightPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
            $rightPanel.WrapContents = $false
            $rightPanel.AutoScroll = $true
            $rightPanel.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
            $rightPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
            $btLayout.Controls.Add($rightPanel, 1, 0)

            # Collect diagnostics
            $btDiagnostics = Get-WinConfigBluetoothDiagnostics

            # === LEFT: Findings ===
            if ($btDiagnostics.Findings.Count -gt 0) {
                $findingsHeadline = New-Headline "Findings"
                $leftPanel.Controls.Add($findingsHeadline)

                foreach ($finding in $btDiagnostics.Findings) {
                    $findingPanel = New-Object System.Windows.Forms.FlowLayoutPanel
                    $findingPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
                    $findingPanel.WrapContents = $false
                    $findingPanel.AutoSize = $true
                    $findingPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
                    $findingPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
                    $findingPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 5)
                    $findingPanel.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)

                    $titleLabel = New-Object System.Windows.Forms.Label
                    $titleLabel.Text = "[$($finding.Result)] $($finding.Title)"
                    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                    $titleLabel.ForeColor = Switch-DiagnosticResult -Result $finding.Result -Cases @{
                        'PASS'    = { [System.Drawing.Color]::ForestGreen }
                        'WARN'    = { [System.Drawing.Color]::DarkOrange }
                        'FAIL'    = { [System.Drawing.Color]::Crimson }
                        'NOT_RUN' = { [System.Drawing.Color]::FromArgb(60, 60, 60) }
                    }
                    $titleLabel.AutoSize = $true
                    $findingPanel.Controls.Add($titleLabel)

                    if ($finding.ActionHint) {
                        $hintLabel = New-Object System.Windows.Forms.Label
                        $hintLabel.Text = "-> $($finding.ActionHint)"
                        $hintLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
                        $hintLabel.ForeColor = $tabColor
                        $hintLabel.AutoSize = $true
                        $findingPanel.Controls.Add($hintLabel)
                    }

                    $leftPanel.Controls.Add($findingPanel)
                }
            } else {
                $noFindingsLabel = New-Object System.Windows.Forms.Label
                $noFindingsLabel.Text = "No Bluetooth issues detected."
                $noFindingsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11)
                $noFindingsLabel.ForeColor = [System.Drawing.Color]::DimGray
                $noFindingsLabel.AutoSize = $true
                $noFindingsLabel.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 10)
                $leftPanel.Controls.Add($noFindingsLabel)
            }

            # === RIGHT: Adapter Info ===
            if ($btDiagnostics.Adapter) {
                $adapterHeadline = New-Headline "Bluetooth Adapter"
                $rightPanel.Controls.Add($adapterHeadline)

                $adapterInfo = New-Object System.Windows.Forms.Label
                $adapterInfo.Text = "$($btDiagnostics.Adapter.Name)`nStatus: $($btDiagnostics.Adapter.Status)"
                $adapterInfo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $adapterInfo.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                $adapterInfo.AutoSize = $true
                $adapterInfo.Padding = New-Object System.Windows.Forms.Padding(0, 5, 0, 10)
                $rightPanel.Controls.Add($adapterInfo)
            }

            # === RIGHT: Connected Devices ===
            if ($btDiagnostics.ConnectedDevices.Count -gt 0) {
                $devicesHeadline = New-Headline "Connected Devices"
                $rightPanel.Controls.Add($devicesHeadline)

                foreach ($device in $btDiagnostics.ConnectedDevices) {
                    $deviceLabel = New-Object System.Windows.Forms.Label
                    $deviceLabel.Text = "$($device.Name) ($($device.Type))"
                    $deviceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                    $deviceLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                    $deviceLabel.AutoSize = $true
                    $deviceLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
                    $rightPanel.Controls.Add($deviceLabel)
                }
            }

            $selectedTab.Refresh()
        }
    }
})

# ============================================================================
# STARTUP INVARIANT GUARDRAILS (PERF-001)
# Prevents regression: deferred modules must NOT be loaded before ShowDialog()
# ============================================================================
$deferredModules = @('Bluetooth', 'Network.Diagnostics')
foreach ($moduleName in $deferredModules) {
    if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
        Write-Warning "PERF-001 VIOLATION: $moduleName loaded during startup - performance regression"
        # In debug mode, this could throw. In prod, just warn.
        # throw "PERF-001: $moduleName loaded during startup — regression"
    }
}

# Show the form
$form.ShowDialog() | Out-Null

# WinConfig.Tools.psd1 - Sealed Tool Registry
#
# CONTRACT:
#   - Every tool that mutates system state MUST be declared here
#   - SupportsDryRun MUST be explicitly declared (no defaults)
#   - CI fails if a tool is missing from this registry
#   - Classification determines CI enforcement rules
#
# POLICY: DRY-RUN SCOPE (FROZEN)
#   Dry Run is a safety & intent system for high-blast, irreversible operations.
#   It covers: driver removal, network reset, service restarts, GPO/policy
#   changes, system repair (SFC/DISM), and any future admin-level mutation.
#
#   Low-blast, reversible hygiene tasks (disk cleanup, layout config, taskbar
#   pinning) are permanently exempt. They provide no decision leverage.
#
#   Tools marked DryRunExempt = $true are excluded from Guardrail B debt
#   tracking. This is a deliberate, frozen policy decision — not technical debt.
#
# CLASSIFICATION RULES:
#   MutatesSystem = $true if the tool:
#     - Modifies registry keys
#     - Changes service state (start/stop/restart)
#     - Writes to system files
#     - Modifies device drivers
#     - Changes network configuration
#     - Requires admin privileges to execute
#     - Has irreversible or user-visible effects
#
#   MutatesSystem = $false if the tool:
#     - Is read-only
#     - Only gathers diagnostics
#     - Only reports state
#     - Opens external applications without modification
#
# SCHEMA VERSION: 1.1.0
# SCHEMA INVARIANTS:
#   - schema_version: Must be declared
#   - tools: Array of tool definitions
#   - Each tool must have: Id, Name, Category, MutatesSystem, SupportsDryRun
#   - If SupportsDryRun = $true AND MutatesSystem = $true, a plan generator MUST exist (Guardrail E)
#   - MutatesSystem = $true without SupportsDryRun = $true is planned debt (Guardrail B)
#   - DryRunExempt = $true permanently excludes a tool from Guardrail B (must have DryRunExemptReason)

@{
    schema_version = "1.1.0"

    # Tool classification rules (for documentation and CI validation)
    classification_rules = @{
        # Tools are Dry-Run Applicable if they:
        dry_run_applicable = @(
            "Mutates system state (services, devices, registry, files, drivers)"
            "Restarts, resets, removes, disables, or modifies anything"
            "Requires admin privileges to execute"
            "Has irreversible or user-visible effects"
        )

        # Tools are NOT Dry-Run Applicable if they:
        not_dry_run_applicable = @(
            "Is read-only"
            "Only gathers diagnostics"
            "Only reports state"
            "Opens external applications for viewing only"
        )
    }

    # Sealed tool registry
    # Each tool must declare all fields explicitly - no defaults
    tools = @(
        # =========================================================================
        # BLUETOOTH TOOLS
        # =========================================================================
        @{
            Id             = "bluetooth-diagnostics"
            Name           = "Bluetooth Diagnostics"
            Category       = "Bluetooth"
            ToolCategory   = "Bluetooth"
            MutatesSystem  = $false
            SupportsDryRun = $false  # Read-only diagnostic
            Description    = "Gathers Bluetooth adapter and device information"
        }
        @{
            Id             = "bluetooth-service-restart"
            Name           = "Restart Bluetooth Service"
            Category       = "Bluetooth"
            ToolCategory   = "Bluetooth"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Mutates service state
            Description    = "Restarts the Bluetooth Support Service"
            RequiresAdmin  = $true
        }
        @{
            Id             = "bluetooth-driver-reinstall"
            Name           = "Reinstall Bluetooth Driver"
            Category       = "Bluetooth"
            ToolCategory   = "Bluetooth"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: High-blast driver removal
            Description    = "Removes and reinstalls the Bluetooth adapter driver"
            RequiresAdmin  = $true
        }

        # =========================================================================
        # NETWORK TOOLS
        # =========================================================================
        @{
            Id             = "network-diagnostics"
            Name           = "Network Diagnostics"
            Category       = "Network"
            ToolCategory   = "Network"
            MutatesSystem  = $false
            SupportsDryRun = $false  # Read-only diagnostic
            Description    = "Tests DNS resolution, port connectivity, and latency"
        }
        @{
            Id             = "network-reset"
            Name           = "Network Reset"
            Category       = "Network"
            ToolCategory   = "Network"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Resets network stack
            Description    = "Resets TCP/IP stack, Winsock catalog, and DNS cache"
            RequiresAdmin  = $true
        }
        @{
            Id             = "dns-cache-flush"
            Name           = "Flush DNS Cache"
            Category       = "Network"
            ToolCategory   = "Network"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Clears system cache
            Description    = "Clears the DNS resolver cache"
            RequiresAdmin  = $false
        }

        # =========================================================================
        # SYSTEM TOOLS
        # =========================================================================
        @{
            Id             = "dism-restore-health"
            Name           = "DISM RestoreHealth"
            Category       = "System"
            ToolCategory   = "System"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: High-blast system repair
            Description    = "Repairs Windows component store using DISM"
            RequiresAdmin  = $true
        }
        @{
            Id             = "sfc-scannow"
            Name           = "SFC Scan"
            Category       = "System"
            ToolCategory   = "System"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: High-blast system repair
            Description    = "Scans and repairs protected Windows files"
            RequiresAdmin  = $true
        }
        @{
            Id             = "device-manager"
            Name           = "Open Device Manager"
            Category       = "System"
            ToolCategory   = "System"
            MutatesSystem  = $false
            SupportsDryRun = $false  # Opens external app, no mutation
            Description    = "Opens Windows Device Manager"
        }
        @{
            Id             = "intel-sst-removal"
            Name           = "Remove Intel SST Driver"
            Category       = "System"
            ToolCategory   = "System"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Removes driver
            Description    = "Removes problematic Intel Smart Sound Technology driver"
            RequiresAdmin  = $true
        }

        # =========================================================================
        # ZAMP TOOLS
        # =========================================================================
        @{
            Id             = "zamp-driver-uninstall"
            Name           = "Uninstall zAmp Drivers"
            Category       = "zAmp"
            ToolCategory   = "Audio"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Removes driver packages
            Description    = "Canonical Zengar driver removal"
            RequiresAdmin  = $true
        }

        # =========================================================================
        # AUDIO TOOLS
        # =========================================================================
        @{
            Id             = "audio-diagnostics"
            Name           = "Audio Diagnostics"
            Category       = "Audio"
            ToolCategory   = "Audio"
            MutatesSystem  = $false
            SupportsDryRun = $false  # Read-only diagnostic
            Description    = "Gathers audio device and driver information"
        }
        @{
            Id             = "audio-service-restart"
            Name           = "Restart Audio Service"
            Category       = "Audio"
            ToolCategory   = "Audio"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: Mutates service state
            Description    = "Restarts Windows Audio Service"
            RequiresAdmin  = $true
        }

        # =========================================================================
        # MAINTENANCE TOOLS
        # =========================================================================
        @{
            Id             = "disk-cleanup"
            Name           = "Disk Cleanup"
            Category       = "Maintenance"
            ToolCategory   = "Maintenance"
            MutatesSystem  = $true
            SupportsDryRun = $false
            DryRunExempt   = $true   # FROZEN: Low-blast, reversible hygiene — no decision leverage
            DryRunExemptReason = "Low-blast reversible hygiene task"
            Description    = "Removes temporary files and system cache"
            RequiresAdmin  = $false
        }
        @{
            Id             = "empty-recycle-bin"
            Name           = "Empty Recycle Bin"
            Category       = "Maintenance"
            ToolCategory   = "Maintenance"
            MutatesSystem  = $true
            SupportsDryRun = $true
            Description    = "Permanently deletes files in the Recycle Bin"
            RequiresAdmin  = $false
        }

        # =========================================================================
        # CONFIGURATION TOOLS
        # =========================================================================
        @{
            Id             = "start-menu-apply"
            Name           = "Apply Start Menu Configuration"
            Category       = "Configuration"
            ToolCategory   = "Other"
            MutatesSystem  = $true
            SupportsDryRun = $false
            DryRunExempt   = $true   # FROZEN: Low-blast, reversible cosmetic config
            DryRunExemptReason = "Low-blast reversible cosmetic configuration"
            Description    = "Applies custom Start Menu layout"
            RequiresAdmin  = $false
        }
        @{
            Id             = "taskbar-pinning"
            Name           = "Configure Taskbar Pinning"
            Category       = "Configuration"
            ToolCategory   = "Other"
            MutatesSystem  = $true
            SupportsDryRun = $false
            DryRunExempt   = $true   # FROZEN: Low-blast, reversible cosmetic config
            DryRunExemptReason = "Low-blast reversible cosmetic configuration"
            Description    = "Configures pinned applications on the taskbar"
            RequiresAdmin  = $false
        }
        @{
            Id             = "gpo-enable"
            Name           = "Enable Group Policy"
            Category       = "AdminChange"
            ToolCategory   = "Other"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: High-blast policy change
            Description    = "Enables specified Group Policy settings"
            RequiresAdmin  = $true
        }
        @{
            Id             = "gpo-disable"
            Name           = "Disable Group Policy"
            Category       = "AdminChange"
            ToolCategory   = "Other"
            MutatesSystem  = $true
            SupportsDryRun = $true   # REQUIRED: High-blast policy change
            Description    = "Disables specified Group Policy settings"
            RequiresAdmin  = $true
        }
    )
}

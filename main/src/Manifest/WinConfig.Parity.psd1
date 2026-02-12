# =====================================================
# SSOT PARITY MANIFEST - Debug ↔ Production
# =====================================================
# This file is the single source of truth for:
# - Categories (order matters)
# - Tools per category
# - Tool definitions (descriptions, groups)
#
# INVARIANTS:
# - NO scriptblocks (pure data only)
# - Both Win11Config.App.ps1 and Win11Config.App.Debug.ps1 derive from this
# - CI checks enforce parity between manifest and implementations
# =====================================================

@{
    # Version for parity checking
    ManifestVersion = "1.0.0"

    # Categories in display order (SSOT)
    Categories = @(
        "Network"
        "Updates"
        "NO Shortcuts"
        "Disk"
        "System"
        "Bluetooth"
        "Audio"
        "zAmp"
        "Zengar UI"
    )

    # Tools per category (SSOT)
    CategoryTools = @{
        "Network" = @(
            "Run Network Test"
            "Domain, IP && Ports Test"
            "Network Reset"
            "Flush DNS Cache"
            "Open Speedtest.net"
        )
        "Bluetooth" = @(
            "BT Quick Check"
            "Check Adapter"
            "Check Services"
            "List Paired"
            "Power Settings"
            "Restart Bluetooth Service"
            "Bluetooth Settings"
        )
        "Audio" = @(
            "Remove Intel SST Audio Driver"
            "Restart Audio Service"
            "Sound Panel"
        )
        "System" = @(
            "Copy System Info"
            "Copy Device Name"
            "Copy Serial Number"
            "Device Manager"
            "Task Manager"
            "Control Panel"
        )
        "zAmp" = @(
            "Uninstall zAmp Drivers"
        )
        "Zengar UI" = @(
            "Apply Win 11 Start Menu"
            "Apply branding colors"
            "Pin Taskbar Icons"
            "Apply Win Update Icon"
        )
        "Updates" = @(
            "MS Store Updates"
            "Update Surface Drivers"
            "Microsoft Update Catalog"
            "Windows Insider"
        )
        "Disk" = @(
            "DISM Restore Health"
            "/sfc scannow"
            "Defrag && Optimize"
            "Delete old backups"
            "Disk Cleanup"
            "Empty Recycle Bin"
        )
        "NO Shortcuts" = @(
            "%programdata%"
            "%localappdata%"
            "C:\zengar"
            "Documents\ScreenConnect"
        )
    }

    # Tool definitions with metadata (SSOT)
    ToolDefinitions = @{
        # Network tools
        "Run Network Test" = @{
            Description = "Full network diagnostics"
            Group = "Diagnostics"
        }
        "Domain, IP && Ports Test" = @{
            Description = "Domain resolution and port checks"
            Group = "Diagnostics"
        }
        "Network Reset" = @{
            Description = "Reset network adapter stack"
            Group = "Actions"
        }
        "Flush DNS Cache" = @{
            Description = "Clear DNS resolver cache"
            Group = "Actions"
        }
        "Open Speedtest.net" = @{
            Description = "Launch browser speed test"
            Group = "External"
        }

        # Bluetooth tools
        "BT Quick Check" = @{
            Description = "Run all Bluetooth checks"
            Group = "Preset"
        }
        "Check Adapter" = @{
            Description = "Verify Bluetooth adapter status"
            Group = "Diagnostics"
        }
        "Check Services" = @{
            Description = "Check Bluetooth service state"
            Group = "Diagnostics"
        }
        "List Paired" = @{
            Description = "Show paired devices"
            Group = "Diagnostics"
        }
        "Power Settings" = @{
            Description = "Review power management"
            Group = "Diagnostics"
        }
        "Restart Bluetooth Service" = @{
            Description = "Restart Bluetooth support service"
            Group = "Actions"
        }
        "Bluetooth Settings" = @{
            Description = "Open Windows BT settings"
            Group = "Settings"
        }

        # Audio tools
        "Remove Intel SST Audio Driver" = @{
            Description = "Uninstall problematic SST driver"
            Group = "Actions"
        }
        "Restart Audio Service" = @{
            Description = "Restart Windows Audio service"
            Group = "Actions"
        }
        "Sound Panel" = @{
            Description = "Open sound control panel"
            Group = "Settings"
        }

        # System tools
        "Copy System Info" = @{
            Description = "Copy system details to clipboard"
            Group = "Info"
        }
        "Copy Device Name" = @{
            Description = "Copy computer name"
            Group = "Info"
        }
        "Copy Serial Number" = @{
            Description = "Copy BIOS serial number"
            Group = "Info"
        }
        "Device Manager" = @{
            Description = "Open device manager"
            Group = "Settings"
        }
        "Task Manager" = @{
            Description = "Open task manager"
            Group = "Settings"
        }
        "Control Panel" = @{
            Description = "Open control panel"
            Group = "Settings"
        }

        # zAmp tools
        "Uninstall zAmp Drivers" = @{
            Description = "Canonical Zengar driver removal"
            Group = "Actions"
        }

        # Zengar UI tools
        "Apply Win 11 Start Menu" = @{
            Description = "Apply custom Start Menu layout"
            Group = "UI"
        }
        "Apply branding colors" = @{
            Description = "Apply Zengar brand colors"
            Group = "UI"
        }
        "Pin Taskbar Icons" = @{
            Description = "Pin standard icons to taskbar"
            Group = "UI"
        }
        "Apply Win Update Icon" = @{
            Description = "Apply Windows Update icon"
            Group = "UI"
        }

        # Updates tools
        "MS Store Updates" = @{
            Description = "Check Microsoft Store updates"
            Group = "Updates"
        }
        "Update Surface Drivers" = @{
            Description = "Update Surface firmware"
            Group = "Updates"
        }
        "Microsoft Update Catalog" = @{
            Description = "Open MS Update Catalog"
            Group = "Updates"
        }
        "Windows Insider" = @{
            Description = "Open Windows Insider settings"
            Group = "Updates"
        }

        # Disk tools
        "DISM Restore Health" = @{
            Description = "Repair Windows component store"
            Group = "Repair"
        }
        "/sfc scannow" = @{
            Description = "Scan and repair system files"
            Group = "Repair"
        }
        "Defrag && Optimize" = @{
            Description = "Optimize drive performance"
            Group = "Cleanup"
        }
        "Delete old backups" = @{
            Description = "Remove Zengar backup files"
            Group = "Cleanup"
        }
        "Disk Cleanup" = @{
            Description = "Windows disk cleanup utility"
            Group = "Cleanup"
        }
        "Empty Recycle Bin" = @{
            Description = "Clear recycle bin contents"
            Group = "Cleanup"
        }

        # NO Shortcuts tools
        "%programdata%" = @{
            Description = "Open ProgramData folder"
            Group = "Shortcuts"
        }
        "%localappdata%" = @{
            Description = "Open LocalAppData folder"
            Group = "Shortcuts"
        }
        "C:\zengar" = @{
            Description = "Open Zengar folder"
            Group = "Shortcuts"
        }
        "Documents\ScreenConnect" = @{
            Description = "Open ScreenConnect folder"
            Group = "Shortcuts"
        }
    }

    # Presets (tools that trigger multiple operations)
    Presets = @(
        "BT Quick Check"
    )

    # Expected tab structure
    Tabs = @(
        "Tools"
        "Details"
    )
}

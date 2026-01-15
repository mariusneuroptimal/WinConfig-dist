# Console.psm1 - Canonical console color system for diagnostic output
# Enforces semantic colors, prefix contract, and consistent styling across all shells

# CONTRACT:
# Every diagnostic line MUST use a semantic level with matching prefix.
# Color alone is insufficient - prefixes ensure accessibility and parseability.
# Levels: OK (success), WARN (degraded), FAIL (hard failure), INFO (neutral),
#         STEP (section/phase), ACTION (user hint), DIM (metadata/noise)
#
# INVARIANTS:
# - Palette is frozen at module load (no runtime mutation)
# - Initialize-Console is exactly-once (idempotent guard)
# - Invalid levels fail closed (throw, not fallback)
# - Write before init is a contract violation

# Script-scoped state
$script:ConsoleInitialized = $false

# Frozen canonical color palette - synchronized to prevent mutation
$script:ConsoleColors = [hashtable]::Synchronized(@{
    OK     = "Green"
    WARN   = "Yellow"
    FAIL   = "Red"
    INFO   = "Gray"
    STEP   = "Cyan"
    ACTION = "Magenta"
    DIM    = "DarkGray"
})

# Valid levels for fail-closed validation
$script:ValidLevels = @("OK", "WARN", "FAIL", "INFO", "STEP", "ACTION", "DIM")

# Canonical WinForms color palette (hex) - mirrors console palette for GUI surfaces
# Background: #0E0E11 (near-black), Foreground: #D0D0D6 (light gray)
$script:GuiColors = [hashtable]::Synchronized(@{
    Background = "#0E0E11"
    Foreground = "#D0D0D6"
    OK         = "#3CCF4E"
    WARN       = "#F5C542"
    FAIL       = "#FF5F56"
    INFO       = "#D0D0D6"
    STEP       = "#3ABFF8"
    ACTION     = "#B392F0"
    DIM        = "#7A7A85"
})

function Initialize-Console {
    <#
    .SYNOPSIS
        Initializes the console with canonical color settings.
    .DESCRIPTION
        Sets background to black, foreground to gray, and clears the screen.
        Exactly-once semantics: subsequent calls are no-ops.
    .PARAMETER NoClear
        If specified, skips the Clear-Host call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$NoClear
    )

    # Exactly-once guard
    if ($script:ConsoleInitialized) {
        return
    }
    $script:ConsoleInitialized = $true

    try {
        $Host.UI.RawUI.BackgroundColor = "Black"
        $Host.UI.RawUI.ForegroundColor = "Gray"

        if (-not $NoClear) {
            Clear-Host
        }
    }
    catch {
        # Non-interactive hosts may not support RawUI - still mark as initialized
        # to prevent retry loops, but the visual styling won't apply
    }
}

function Test-ConsoleInitialized {
    <#
    .SYNOPSIS
        Returns whether the console has been initialized.
    .DESCRIPTION
        Use this to verify the console contract before diagnostic output.
    #>
    [CmdletBinding()]
    param()

    return [bool]$script:ConsoleInitialized
}

function Write-Diagnostic {
    <#
    .SYNOPSIS
        Writes a diagnostic message with semantic color and prefix.
    .DESCRIPTION
        Outputs a message with the format: [LEVEL] Message
        Color is applied based on the semantic level. This is the MANDATORY
        output helper for all diagnostic console output.

        FAILS CLOSED: Invalid levels throw, not fallback.

        Levels:
        - OK:     Green  - Explicit success only
        - WARN:   Yellow - Degraded / attention needed
        - FAIL:   Red    - Hard failures only
        - INFO:   Gray   - Normal informational output
        - STEP:   Cyan   - Major phases / section titles
        - ACTION: Purple - Suggested user action
        - DIM:    Gray   - Timestamps, debug noise, metadata
    .PARAMETER Level
        The semantic level: OK, WARN, FAIL, INFO, STEP, ACTION, or DIM
    .PARAMETER Message
        The message to display
    .PARAMETER NoNewline
        If specified, does not append a newline after the message
    .EXAMPLE
        Write-Diagnostic STEP "Starting network diagnostics"
        Write-Diagnostic OK "DNS resolution successful"
        Write-Diagnostic WARN "High latency detected"
        Write-Diagnostic FAIL "Cannot reach endpoint"
        Write-Diagnostic ACTION "If using VPN, disconnect and retry"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("OK", "WARN", "FAIL", "INFO", "STEP", "ACTION", "DIM")]
        [string]$Level,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )

    # Fail closed: validate level exists in palette (belt + suspenders with ValidateSet)
    if (-not $script:ConsoleColors.ContainsKey($Level)) {
        throw "Invalid diagnostic level: $Level. Valid levels: $($script:ValidLevels -join ', ')"
    }

    $color = $script:ConsoleColors[$Level]
    $prefix = "[{0}]" -f $Level.PadRight(6)
    $output = "{0} {1}" -f $prefix, $Message

    if ($NoNewline) {
        Write-Host $output -ForegroundColor $color -NoNewline
    }
    else {
        Write-Host $output -ForegroundColor $color
    }
}

function Write-ConsoleSeparator {
    <#
    .SYNOPSIS
        Writes a visual separator line for console output.
    .DESCRIPTION
        Outputs a horizontal line of dashes in DIM color. Use between sections.
    .PARAMETER Width
        Width of the separator line. Defaults to 50.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Width = 50
    )

    Write-Host ("-" * $Width) -ForegroundColor $script:ConsoleColors["DIM"]
}

function Write-ConsoleHeader {
    <#
    .SYNOPSIS
        Writes a standardized context header for button-triggered windows.
    .DESCRIPTION
        Outputs a context header with tool name, session ID, and mode.
        Use this at the start of every button-triggered console window
        to prevent "mystery windows" with no context.
    .PARAMETER Title
        The tool/operation title (e.g., "Network Diagnostics")
    .PARAMETER SessionId
        Session identifier for correlation
    .PARAMETER Mode
        Operating mode description (e.g., "Read-only diagnostics")
    .PARAMETER ToolName
        Optional tool name prefix. Defaults to "NO Support Tool"
    .EXAMPLE
        Write-ConsoleHeader -Title "Network Diagnostics" -SessionId "NST-C30C1509" -Mode "Read-only diagnostics"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$SessionId = "",

        [Parameter(Mandatory = $false)]
        [string]$Mode = "",

        [Parameter(Mandatory = $false)]
        [string]$ToolName = "NO Support Tool"
    )

    Write-Diagnostic STEP "$ToolName - $Title"

    if ($SessionId) {
        Write-Diagnostic INFO "Run: $SessionId"
    }

    if ($Mode) {
        Write-Diagnostic INFO "Mode: $Mode"
    }

    Write-ConsoleSeparator
}

function Get-ConsoleColors {
    <#
    .SYNOPSIS
        Returns a COPY of the canonical console color palette.
    .DESCRIPTION
        Returns a cloned hashtable mapping semantic levels to PowerShell console colors.
        Clone prevents external mutation of the frozen palette.
    #>
    [CmdletBinding()]
    param()

    # Return a copy, not a reference - prevents palette mutation
    return @{} + $script:ConsoleColors
}

# ═══════════════════════════════════════════════════════════════════════════════
# WINFORMS RENDERING SURFACE
# ═══════════════════════════════════════════════════════════════════════════════
# The diagnostic color system is semantic, not console-specific.
# WinForms RichTextBox is another rendering target of the same contract.

function Initialize-GuiDiagnosticBox {
    <#
    .SYNOPSIS
        Initializes a RichTextBox with canonical diagnostic colors.
    .DESCRIPTION
        Configures a RichTextBox control with the canonical color scheme:
        - Background: #0E0E11 (near-black)
        - Foreground: #D0D0D6 (light gray)
        - Font: Consolas 9pt
        - ReadOnly: true

        MANDATORY: All diagnostic GUI output MUST use an initialized RichTextBox.
        TextBox is structurally incompatible (single color only).
    .PARAMETER Box
        The RichTextBox control to initialize
    .EXAMPLE
        $outputBox = New-Object System.Windows.Forms.RichTextBox
        Initialize-GuiDiagnosticBox -Box $outputBox
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$Box
    )

    $Box.BackColor = [System.Drawing.ColorTranslator]::FromHtml($script:GuiColors["Background"])
    $Box.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($script:GuiColors["Foreground"])
    $Box.Font = New-Object System.Drawing.Font("Consolas", 9)
    $Box.ReadOnly = $true
}

function Write-GuiDiagnostic {
    <#
    .SYNOPSIS
        Writes a diagnostic message to a RichTextBox with semantic color.
    .DESCRIPTION
        Outputs a message with the format: [LEVEL] Message
        Color is applied based on the semantic level. This is the MANDATORY
        output helper for all diagnostic GUI output.

        FAILS CLOSED: Invalid levels throw, not fallback.

        Levels:
        - OK:     #3CCF4E (green)  - Explicit success only
        - WARN:   #F5C542 (gold)   - Degraded / attention needed
        - FAIL:   #FF5F56 (red)    - Hard failures only
        - INFO:   #D0D0D6 (gray)   - Normal informational output
        - STEP:   #3ABFF8 (cyan)   - Major phases / section titles
        - ACTION: #B392F0 (purple) - Suggested user action
        - DIM:    #7A7A85 (dim)    - Timestamps, debug noise, metadata
    .PARAMETER Level
        The semantic level: OK, WARN, FAIL, INFO, STEP, ACTION, or DIM
    .PARAMETER Message
        The message to display
    .PARAMETER Box
        The RichTextBox control to write to
    .PARAMETER NoPrefix
        If specified, omits the [LEVEL] prefix (use for continuation lines)
    .EXAMPLE
        Write-GuiDiagnostic -Level STEP -Message "Starting network diagnostics" -Box $outputBox
        Write-GuiDiagnostic -Level OK -Message "DNS resolution successful" -Box $outputBox
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("OK", "WARN", "FAIL", "INFO", "STEP", "ACTION", "DIM")]
        [string]$Level,

        [Parameter(Mandatory = $true, Position = 1)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$Box,

        [Parameter(Mandatory = $false)]
        [switch]$NoPrefix
    )

    # Fail closed: validate level exists in palette
    if (-not $script:GuiColors.ContainsKey($Level)) {
        throw "Invalid diagnostic level: $Level. Valid levels: $($script:ValidLevels -join ', ')"
    }

    $color = [System.Drawing.ColorTranslator]::FromHtml($script:GuiColors[$Level])

    # Format output with or without prefix
    $output = if ($NoPrefix) {
        "$Message`r`n"
    } else {
        "[{0}] {1}`r`n" -f $Level.PadRight(6), $Message
    }

    # Append with color
    $Box.SelectionStart = $Box.TextLength
    $Box.SelectionLength = 0
    $Box.SelectionColor = $color
    $Box.AppendText($output)
    $Box.SelectionColor = $Box.ForeColor
    $Box.ScrollToCaret()
}

function Write-GuiSeparator {
    <#
    .SYNOPSIS
        Writes a visual separator line to a RichTextBox.
    .DESCRIPTION
        Outputs a horizontal line of dashes in DIM color. Use between sections.
    .PARAMETER Box
        The RichTextBox control to write to
    .PARAMETER Width
        Width of the separator line. Defaults to 60.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$Box,

        [Parameter(Mandatory = $false)]
        [int]$Width = 60
    )

    Write-GuiDiagnostic -Level DIM -Message ("-" * $Width) -Box $Box -NoPrefix
}

function Get-GuiColors {
    <#
    .SYNOPSIS
        Returns a COPY of the canonical GUI color palette.
    .DESCRIPTION
        Returns a cloned hashtable mapping semantic levels to hex color codes.
        Clone prevents external mutation of the frozen palette.
    #>
    [CmdletBinding()]
    param()

    return @{} + $script:GuiColors
}

# Export public functions
Export-ModuleMember -Function Initialize-Console, Write-Diagnostic, Write-ConsoleSeparator, Write-ConsoleHeader, Get-ConsoleColors, Test-ConsoleInitialized, Initialize-GuiDiagnosticBox, Write-GuiDiagnostic, Write-GuiSeparator, Get-GuiColors

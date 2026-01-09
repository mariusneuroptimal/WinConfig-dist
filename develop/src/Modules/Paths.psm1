# Paths.psm1 - Path helpers for WinConfig
# Phase 2C: Modularization for maintainability

function Get-WinConfigProgramDataRoot {
    <#
    .SYNOPSIS
        Returns the WinConfig data directory under ProgramData.
    .DESCRIPTION
        Returns %ProgramData%\WinConfig (e.g., C:\ProgramData\WinConfig)
    #>
    [CmdletBinding()]
    param()

    return Join-Path $env:ProgramData "WinConfig"
}

function Get-WinConfigLogsPath {
    <#
    .SYNOPSIS
        Returns the WinConfig logs directory.
    .DESCRIPTION
        Returns %ProgramData%\WinConfig\logs
    #>
    [CmdletBinding()]
    param()

    return Join-Path (Get-WinConfigProgramDataRoot) "logs"
}

function Initialize-WinConfigDirectories {
    <#
    .SYNOPSIS
        Creates required WinConfig directories if they don't exist.
    .DESCRIPTION
        Creates:
        - %ProgramData%\WinConfig
        - %ProgramData%\WinConfig\logs
        Fails gracefully if creation fails (no exception thrown).
    .OUTPUTS
        $true if directories exist or were created, $false on failure.
    #>
    [CmdletBinding()]
    param()

    $root = Get-WinConfigProgramDataRoot
    $logs = Get-WinConfigLogsPath

    try {
        if (-not (Test-Path $root)) {
            New-Item -Path $root -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $logs)) {
            New-Item -Path $logs -ItemType Directory -Force | Out-Null
        }
        return $true
    }
    catch {
        # Fail gracefully - caller can check return value
        return $false
    }
}

# Export public functions
Export-ModuleMember -Function Get-WinConfigProgramDataRoot, Get-WinConfigLogsPath, Initialize-WinConfigDirectories

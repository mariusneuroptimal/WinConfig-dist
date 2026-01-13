# Paths.psm1 - Ephemeral path helpers for WinConfig
# Phase 2C: Zero-footprint support tool architecture
#
# CONTRACT:
# - All files live under a single temp root
# - Root is unique per session (GUID-based)
# - Root is deleted on normal exit
# - Root is deleted on abnormal exit (best-effort)
# - No writes to ProgramData, AppData, Registry, or disk outside temp
#
# INVARIANT:
# The support tool must leave no persistent artifacts after termination.
#
# ENFORCEMENT:
# - Assert-EphemeralPath throws if any forbidden root is detected
# - All path getters are the SINGLE SOURCE OF TRUTH
# - Direct path construction outside this module is a bug

# =============================================================================
# FORBIDDEN ROOTS - These paths are NEVER allowed
# =============================================================================
$script:ForbiddenRoots = @(
    $env:ProgramData,
    $env:APPDATA,
    $env:LOCALAPPDATA,
    [System.Environment]::GetFolderPath('CommonApplicationData'),  # ProgramData
    [System.Environment]::GetFolderPath('ApplicationData'),        # Roaming AppData
    [System.Environment]::GetFolderPath('LocalApplicationData'),   # Local AppData
    [System.Environment]::GetFolderPath('MyDocuments'),            # Documents
    [System.Environment]::GetFolderPath('Desktop')                 # Desktop
) | Where-Object { $_ }  # Filter out nulls

# =============================================================================
# SCRIPT-SCOPED STATE (Single Source of Truth)
# =============================================================================
$script:SessionTempRoot = $null
$script:SessionId = $null
$script:TempPaths = $null
$script:PathsInitialized = $false

# =============================================================================
# PATH VALIDATION (Fail-Fast Guard)
# =============================================================================

function Assert-EphemeralPath {
    <#
    .SYNOPSIS
        Validates that a path is ephemeral (not in forbidden roots).
    .DESCRIPTION
        THROWS immediately if the path is under any forbidden root.
        Call this at path-construction time, NOT after writes.
        This is a hard guard to prevent regression.
    .PARAMETER Path
        The path to validate.
    .PARAMETER Context
        Optional context for error message (e.g., "Logger", "SessionLedger").
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Context = "Unknown"
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return  # Empty paths are allowed (will fail elsewhere)
    }

    # Normalize path for comparison
    $normalizedPath = $Path.TrimEnd('\', '/')

    foreach ($forbidden in $script:ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($forbidden)) { continue }

        $normalizedForbidden = $forbidden.TrimEnd('\', '/')

        # Check if path starts with forbidden root
        if ($normalizedPath -like "$normalizedForbidden*") {
            throw "FATAL: Persistent path usage detected in [$Context]: $Path`nForbidden root: $forbidden`nThis violates the zero-footprint contract. All paths must be under `$env:TEMP."
        }
    }

    # Also check for hardcoded drive roots (except temp)
    $tempDrive = (Split-Path $env:TEMP -Qualifier) + "\"
    if ($normalizedPath -match '^[A-Za-z]:\\' -and -not $normalizedPath.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase)) {
        # Allow paths that are reading system locations (not writing)
        # But warn for any path not under TEMP
        # This is a softer check - the forbidden roots above are the hard guard
    }
}

function Test-EphemeralPath {
    <#
    .SYNOPSIS
        Tests if a path is ephemeral (non-throwing version).
    .DESCRIPTION
        Returns $true if path is safe, $false if it's under a forbidden root.
        Use Assert-EphemeralPath for fail-fast behavior.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Assert-EphemeralPath -Path $Path -Context "Test"
        return $true
    }
    catch {
        return $false
    }
}

function Initialize-WinConfigPaths {
    <#
    .SYNOPSIS
        Initializes the ephemeral session-scoped temp root.
    .DESCRIPTION
        Creates a unique temp directory under $env:TEMP for this session.
        All WinConfig artifacts (logs, exports, cache, runtime) live here.
        Registers cleanup handlers for normal and abnormal exit.
    .OUTPUTS
        $true if initialization succeeded, $false on failure.
    #>
    [CmdletBinding()]
    param()

    # Guard against double-initialization
    if ($script:PathsInitialized) {
        return $true
    }

    # Clean up orphaned sessions from previous runs (best-effort)
    Remove-OrphanedSessions

    # Generate unique session ID
    $script:SessionId = [guid]::NewGuid().ToString()

    # Create session-scoped temp root: $env:TEMP\WinConfig-<GUID>
    $script:SessionTempRoot = Join-Path $env:TEMP "WinConfig-$($script:SessionId)"

    try {
        # Create root directory
        if (-not (Test-Path $script:SessionTempRoot)) {
            New-Item -ItemType Directory -Path $script:SessionTempRoot -Force | Out-Null
        }

        # Create mandatory subfolders (all ephemeral)
        $script:TempPaths = @{
            Root     = $script:SessionTempRoot
            Logs     = Join-Path $script:SessionTempRoot "logs"
            Sessions = Join-Path $script:SessionTempRoot "sessions"
            Exports  = Join-Path $script:SessionTempRoot "exports"
            Cache    = Join-Path $script:SessionTempRoot "cache"
            Runtime  = Join-Path $script:SessionTempRoot "runtime"
        }

        foreach ($path in $script:TempPaths.Values) {
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }

        # Register cleanup handler for PowerShell exit (covers console close, exit command)
        Register-EngineEvent PowerShell.Exiting -Action {
            Remove-WinConfigTempRoot
        } -SupportEvent | Out-Null

        $script:PathsInitialized = $true
        return $true
    }
    catch {
        # Fail gracefully - caller can check return value
        $script:PathsInitialized = $false
        return $false
    }
}

function Get-WinConfigTempRoot {
    <#
    .SYNOPSIS
        Returns the session-scoped temp root directory.
    .DESCRIPTION
        Returns the path to the ephemeral root directory for this session.
        All WinConfig artifacts should be stored under this path.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    return $script:SessionTempRoot
}

function Get-WinConfigLogsPath {
    <#
    .SYNOPSIS
        Returns the session-scoped logs directory.
    .DESCRIPTION
        Returns the path where JSONL logs should be stored for this session.
        Path is ephemeral and will be deleted on exit.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    if ($script:TempPaths) {
        return $script:TempPaths.Logs
    }

    # Fallback if paths not initialized
    return Join-Path $env:TEMP "WinConfig-fallback\logs"
}

function Get-WinConfigSessionsPath {
    <#
    .SYNOPSIS
        Returns the session-scoped sessions directory.
    .DESCRIPTION
        Returns the path where session ledger data should be stored.
        Path is ephemeral and will be deleted on exit.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    if ($script:TempPaths) {
        return $script:TempPaths.Sessions
    }

    # Fallback if paths not initialized
    return Join-Path $env:TEMP "WinConfig-fallback\sessions"
}

function Get-WinConfigExportsPath {
    <#
    .SYNOPSIS
        Returns the session-scoped exports directory.
    .DESCRIPTION
        Returns the path where diagnostic exports should be stored.
        Path is ephemeral and will be deleted on exit.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    if ($script:TempPaths) {
        return $script:TempPaths.Exports
    }

    # Fallback if paths not initialized
    return Join-Path $env:TEMP "WinConfig-fallback\exports"
}

function Get-WinConfigCachePath {
    <#
    .SYNOPSIS
        Returns the session-scoped cache directory.
    .DESCRIPTION
        Returns the path for temporary cache files.
        Path is ephemeral and will be deleted on exit.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    if ($script:TempPaths) {
        return $script:TempPaths.Cache
    }

    # Fallback if paths not initialized
    return Join-Path $env:TEMP "WinConfig-fallback\cache"
}

function Get-WinConfigRuntimePath {
    <#
    .SYNOPSIS
        Returns the session-scoped runtime directory.
    .DESCRIPTION
        Returns the path for runtime artifacts (provisioning files, etc).
        Path is ephemeral and will be deleted on exit.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    if ($script:TempPaths) {
        return $script:TempPaths.Runtime
    }

    # Fallback if paths not initialized
    return Join-Path $env:TEMP "WinConfig-fallback\runtime"
}

function Get-WinConfigSessionId {
    <#
    .SYNOPSIS
        Returns the current session's unique identifier.
    #>
    [CmdletBinding()]
    param()

    return $script:SessionId
}

function Remove-WinConfigTempRoot {
    <#
    .SYNOPSIS
        Removes the session temp root and all contents.
    .DESCRIPTION
        Called automatically on exit. Can also be called manually.
        Fails silently - cleanup should never cause errors.
    #>
    [CmdletBinding()]
    param()

    if ($script:SessionTempRoot -and (Test-Path $script:SessionTempRoot)) {
        try {
            Remove-Item $script:SessionTempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Fail silently - cleanup errors should not propagate
        }
    }
}

function Remove-OrphanedSessions {
    <#
    .SYNOPSIS
        Removes orphaned WinConfig temp directories from previous sessions.
    .DESCRIPTION
        On launch, cleans up any WinConfig-* directories older than 6 hours.
        This handles cases where cleanup failed due to:
        - Power loss
        - Task Manager kill
        - System crash
    #>
    [CmdletBinding()]
    param()

    try {
        $cutoffTime = (Get-Date).AddHours(-6)

        Get-ChildItem $env:TEMP -Directory -Filter "WinConfig-*" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffTime } |
            ForEach-Object {
                try {
                    Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {
                    # Silently continue - orphan cleanup is best-effort
                }
            }
    }
    catch {
        # Silently fail - orphan cleanup is opportunistic
    }
}

function Register-WinConfigFormCleanup {
    <#
    .SYNOPSIS
        Registers cleanup handler for WinForms/WPF form closing.
    .DESCRIPTION
        Must be called after form is created to ensure cleanup on GUI close.
    .PARAMETER Form
        The Windows Form object to register cleanup for.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Form]$Form
    )

    $Form.Add_FormClosing({
        Remove-WinConfigTempRoot
    })
}

# DEPRECATED: Legacy function for backward compatibility
# Maps to new ephemeral temp root instead of ProgramData
function Get-WinConfigProgramDataRoot {
    <#
    .SYNOPSIS
        DEPRECATED: Returns the session temp root (not ProgramData).
    .DESCRIPTION
        This function is deprecated. It now returns the ephemeral temp root
        instead of a ProgramData path. Use Get-WinConfigTempRoot instead.
    #>
    [CmdletBinding()]
    param()

    Write-Warning "Get-WinConfigProgramDataRoot is deprecated. Use Get-WinConfigTempRoot instead."
    return Get-WinConfigTempRoot
}

# DEPRECATED: Legacy function for backward compatibility
function Initialize-WinConfigDirectories {
    <#
    .SYNOPSIS
        DEPRECATED: Initializes ephemeral session directories.
    .DESCRIPTION
        This function is deprecated. It now calls Initialize-WinConfigPaths
        which creates ephemeral directories instead of persistent ones.
    #>
    [CmdletBinding()]
    param()

    return Initialize-WinConfigPaths
}

# =============================================================================
# SINGLE SOURCE OF TRUTH ACCESSOR
# =============================================================================

function Get-WinConfigPathContext {
    <#
    .SYNOPSIS
        Returns the complete path context as a single object.
    .DESCRIPTION
        This is the SINGLE SOURCE OF TRUTH for all WinConfig paths.
        Any code constructing paths outside this context is a bug.
        Use this for validation, debugging, and path discovery.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PathsInitialized) {
        Initialize-WinConfigPaths | Out-Null
    }

    return [PSCustomObject]@{
        Root        = $script:TempPaths.Root
        Logs        = $script:TempPaths.Logs
        Sessions    = $script:TempPaths.Sessions
        Exports     = $script:TempPaths.Exports
        Cache       = $script:TempPaths.Cache
        Runtime     = $script:TempPaths.Runtime
        SessionId   = $script:SessionId
        Initialized = $script:PathsInitialized
    }
}

# Export public functions
Export-ModuleMember -Function @(
    # Core functions
    'Initialize-WinConfigPaths',
    'Get-WinConfigTempRoot',
    'Get-WinConfigLogsPath',
    'Get-WinConfigSessionsPath',
    'Get-WinConfigExportsPath',
    'Get-WinConfigCachePath',
    'Get-WinConfigRuntimePath',
    'Get-WinConfigSessionId',
    'Get-WinConfigPathContext',
    # Cleanup functions
    'Remove-WinConfigTempRoot',
    'Remove-OrphanedSessions',
    'Register-WinConfigFormCleanup',
    # Validation functions (guards)
    'Assert-EphemeralPath',
    'Test-EphemeralPath',
    # Deprecated (backward compatibility)
    'Get-WinConfigProgramDataRoot',
    'Initialize-WinConfigDirectories'
)

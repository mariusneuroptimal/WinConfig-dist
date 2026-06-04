# DiagnosticsUpload.psm1
# Uploads a WinConfig diagnostic package to a configured destination.
#
# PROVIDER SUPPORT (Phase 8):
# - LocalFolder: copies ZIP to a local path or UNC share
#
# CONFIGURATION (precedence order):
# 1. $env:WINCONFIG_DIAGNOSTICS_DEST — path string enables LocalFolder upload
# 2. Default — upload disabled
#
# BOUNDARY: This module owns transport. The Bluetooth probe module must not import
# or depend on this module.

function Get-WinConfigDiagnosticsUploadConfig {
    <#
    .SYNOPSIS
        Returns the active upload configuration.
    .OUTPUTS
        Hashtable: Enabled, Provider, DestinationPath
    #>
    [CmdletBinding()]
    param()

    $dest = $env:WINCONFIG_DIAGNOSTICS_DEST
    if (-not $dest) {
        $dest = Join-Path $env:USERPROFILE "Documents\WinConfigDiagnostics"
    }
    return @{
        Enabled         = $true
        Provider        = 'LocalFolder'
        DestinationPath = $dest
    }
}

function Send-WinConfigDiagnosticPackage {
    <#
    .SYNOPSIS
        Sends a diagnostic package to the configured destination.
    .OUTPUTS
        PSCustomObject: Status, Provider, Destination, RemotePath, UploadedAtUtc, Sha256, Error
        Status values: Uploaded | Skipped | Failed
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [hashtable]$Metadata = @{}
    )

    if (-not $Config.Enabled) {
        return [PSCustomObject]@{
            Status        = 'Skipped'
            Provider      = $Config.Provider
            Destination   = ''
            RemotePath    = $null
            UploadedAtUtc = $null
            Sha256        = $null
            Error         = $null
        }
    }

    if (-not (Test-Path $PackagePath)) {
        return [PSCustomObject]@{
            Status        = 'Failed'
            Provider      = $Config.Provider
            Destination   = $Config.DestinationPath
            RemotePath    = $null
            UploadedAtUtc = $null
            Sha256        = $null
            Error         = "Package not found: $PackagePath"
        }
    }

    switch ($Config.Provider) {
        'LocalFolder' {
            try {
                $destDir = $Config.DestinationPath
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                $fileName   = Split-Path $PackagePath -Leaf
                $remotePath = Join-Path $destDir $fileName
                Copy-Item $PackagePath $remotePath -Force
                $sha256 = (Get-FileHash $PackagePath -Algorithm SHA256).Hash
                return [PSCustomObject]@{
                    Status        = 'Uploaded'
                    Provider      = 'LocalFolder'
                    Destination   = $destDir
                    RemotePath    = $remotePath
                    UploadedAtUtc = [datetime]::UtcNow.ToString("o")
                    Sha256        = $sha256
                    Error         = $null
                }
            } catch {
                return [PSCustomObject]@{
                    Status        = 'Failed'
                    Provider      = 'LocalFolder'
                    Destination   = $Config.DestinationPath
                    RemotePath    = $null
                    UploadedAtUtc = $null
                    Sha256        = $null
                    Error         = $_.Exception.Message
                }
            }
        }
        default {
            return [PSCustomObject]@{
                Status        = 'Failed'
                Provider      = $Config.Provider
                Destination   = $Config.DestinationPath
                RemotePath    = $null
                UploadedAtUtc = $null
                Sha256        = $null
                Error         = "Unknown provider: $($Config.Provider)"
            }
        }
    }
}

Export-ModuleMember -Function @(
    'Get-WinConfigDiagnosticsUploadConfig'
    'Send-WinConfigDiagnosticPackage'
)

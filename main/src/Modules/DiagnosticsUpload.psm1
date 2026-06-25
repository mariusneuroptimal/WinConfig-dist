# DiagnosticsUpload.psm1
# Uploads a WinConfig diagnostic package to Cloudflare R2.
#
# PROVIDER SUPPORT:
# - R2 (primary): S3-compatible PUT with AWS Sig V4 signing, pure PowerShell
# - LocalFolder (fallback): copies ZIP to Documents\WinConfigDiagnostics
#
# CONFIGURATION:
# Real R2 credentials are injected into src/Config/WinConfig.DiagnosticsConfig.psd1
# by the publish-dist CI job. The module locates this file relative to $PSScriptRoot.
# Override the destination folder with $env:WINCONFIG_DIAGNOSTICS_DEST.
#
# BOUNDARY: This module owns transport. The Bluetooth probe module must not import
# or depend on this module.

#region Private: AWS Sig V4 helpers

function Get-HmacSha256Bytes {
    param([byte[]]$Key, [string]$Data)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Key
    return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Data))
}

function Get-Sha256HexBytes {
    param([byte[]]$Data)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash($Data)
    $sha.Dispose()
    return ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-Sha256HexString {
    param([string]$Data)
    return Get-Sha256HexBytes ([System.Text.Encoding]::UTF8.GetBytes($Data))
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return ($Bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Invoke-R2Put {
    <#
    .SYNOPSIS
        PUTs a file to an R2 bucket using AWS Sig V4. Returns $true on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string]$AccountId,
        [Parameter(Mandatory)] [string]$BucketName,
        [Parameter(Mandatory)] [string]$ObjectKey,
        [Parameter(Mandatory)] [string]$AccessKeyId,
        [Parameter(Mandatory)] [string]$SecretKey
    )

    $fileBytes    = [System.IO.File]::ReadAllBytes($FilePath)
    $contentType  = 'application/zip'
    $region       = 'auto'
    $service      = 's3'
    $host         = "$AccountId.r2.cloudflarestorage.com"
    $endpointUrl  = "https://$host/$BucketName/$ObjectKey"

    $now          = [datetime]::UtcNow
    $dateStamp    = $now.ToString('yyyyMMdd')
    $amzDate      = $now.ToString('yyyyMMddTHHmmssZ')
    $payloadHash  = Get-Sha256HexBytes $fileBytes

    # Canonical request
    $canonicalUri     = "/$BucketName/$ObjectKey"
    $canonicalHeaders = "content-type:$contentType`nhost:$host`nx-amz-content-sha256:$payloadHash`nx-amz-date:$amzDate`n"
    $signedHeaders    = 'content-type;host;x-amz-content-sha256;x-amz-date'
    $canonicalRequest = "PUT`n$canonicalUri`n`n$canonicalHeaders`n$signedHeaders`n$payloadHash"

    # String to sign
    $credentialScope = "$dateStamp/$region/$service/aws4_request"
    $stringToSign    = "AWS4-HMAC-SHA256`n$amzDate`n$credentialScope`n$(Get-Sha256HexString $canonicalRequest)"

    # Signing key
    $kSecret  = [System.Text.Encoding]::UTF8.GetBytes("AWS4$SecretKey")
    $kDate    = Get-HmacSha256Bytes $kSecret    $dateStamp
    $kRegion  = Get-HmacSha256Bytes $kDate      $region
    $kService = Get-HmacSha256Bytes $kRegion    $service
    $kSign    = Get-HmacSha256Bytes $kService   'aws4_request'
    $sig      = ConvertTo-HexString (Get-HmacSha256Bytes $kSign $stringToSign)

    $authHeader = "AWS4-HMAC-SHA256 Credential=$AccessKeyId/$credentialScope, SignedHeaders=$signedHeaders, Signature=$sig"

    $headers = @{
        'Authorization'       = $authHeader
        'x-amz-date'          = $amzDate
        'x-amz-content-sha256'= $payloadHash
        'Content-Type'        = $contentType
    }

    $response = Invoke-WebRequest -Uri $endpointUrl -Method PUT -Headers $headers -Body $fileBytes -UseBasicParsing -ErrorAction Stop
    return $response.StatusCode -in 200, 201, 204
}

#endregion

#region Public API

function Get-WinConfigDiagnosticsUploadConfig {
    <#
    .SYNOPSIS
        Returns the active upload configuration, loaded from the bundled config file.
    .OUTPUTS
        Hashtable: Provider, R2 (sub-hashtable), DestinationPath, Enabled
    #>
    [CmdletBinding()]
    param()

    # Locate bundled config (staged next to Modules/ at src/Config/)
    $configPath = Join-Path $PSScriptRoot '..\Config\WinConfig.DiagnosticsConfig.psd1'
    $r2Config   = $null

    if (Test-Path $configPath) {
        try {
            $raw = Import-PowerShellDataFile $configPath -ErrorAction Stop
            $r2  = $raw.R2
            if ($r2 -and
                $r2.AccountId   -and $r2.AccountId   -ne 'PLACEHOLDER' -and
                $r2.AccessKeyId -and $r2.AccessKeyId -ne 'PLACEHOLDER' -and
                $r2.SecretKey   -and $r2.SecretKey   -ne 'PLACEHOLDER') {
                $r2Config = $r2
            }
        } catch { }
    }

    $destOverride = $env:WINCONFIG_DIAGNOSTICS_DEST
    $destPath = if ($destOverride) {
        $destOverride
    } else {
        Join-Path $env:USERPROFILE 'Documents\WinConfigDiagnostics'
    }

    # Uploads are enabled only when a real destination exists: either R2 credentials
    # were injected at publish time, or an explicit local destination was set via
    # WINCONFIG_DIAGNOSTICS_DEST. In plain source (placeholder creds, no override)
    # uploads are disabled, so dev/test runs do not silently write to Documents.
    return @{
        Enabled         = ([bool]$r2Config) -or ([bool]$destOverride)
        Provider        = if ($r2Config) { 'R2' } else { 'LocalFolder' }
        R2              = $r2Config
        DestinationPath = $destPath
    }
}

function Send-WinConfigDiagnosticPackage {
    <#
    .SYNOPSIS
        Sends a diagnostic package to R2, falling back to a local folder on failure.
    .OUTPUTS
        PSCustomObject: Status, Provider, Destination, RemotePath, UploadedAtUtc, Sha256, Error
        Status values:
          Uploaded  - reached its intended destination (R2 cloud, or an intended LocalFolder)
          LocalOnly - R2 upload FAILED; package saved on this PC only (operator must retry/send)
          Skipped   - uploads disabled (no destination configured)
          Failed    - could not be saved anywhere; the package did not survive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [hashtable]$Config,
        [hashtable]$Metadata = @{},
        [string]$FolderPrefix = ''
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
            Destination   = ''
            RemotePath    = $null
            UploadedAtUtc = $null
            Sha256        = $null
            Error         = "Package not found: $PackagePath"
        }
    }

    $sha256 = (Get-FileHash $PackagePath -Algorithm SHA256).Hash
    $fileName = Split-Path $PackagePath -Leaf

    # --- R2 upload (retried before giving up) ---
    $r2Error = $null
    if ($Config.Provider -eq 'R2' -and $Config.R2) {
        $objectKey   = if ($FolderPrefix) { "$FolderPrefix/$fileName" } else { $fileName }
        $maxAttempts = 3
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                $ok = Invoke-R2Put `
                    -FilePath    $PackagePath `
                    -AccountId   $Config.R2.AccountId `
                    -BucketName  $Config.R2.BucketName `
                    -ObjectKey   $objectKey `
                    -AccessKeyId $Config.R2.AccessKeyId `
                    -SecretKey   $Config.R2.SecretKey

                if ($ok) {
                    return [PSCustomObject]@{
                        Status        = 'Uploaded'
                        Provider      = 'R2'
                        Destination   = "r2://$($Config.R2.BucketName)"
                        RemotePath    = "$($Config.R2.BucketName)/$objectKey"
                        UploadedAtUtc = [datetime]::UtcNow.ToString('o')
                        Sha256        = $sha256
                        Error         = $null
                    }
                }
                $r2Error = "R2 returned a non-success HTTP status"
            } catch {
                $r2Error = $_.Exception.Message
            }
            if ($attempt -lt $maxAttempts) { Start-Sleep -Milliseconds (1000 * $attempt) }
        }
        # All R2 attempts failed — fall through to the local safety net below.
    }

    # --- Local save ---
    # For an intended LocalFolder provider, this IS the destination -> Status=Uploaded.
    # For an R2 provider whose upload failed, this is only a SAFETY NET: the data did NOT
    # reach the cloud, so report LocalOnly so the operator knows to retry / send it manually.
    try {
        $destDir = $Config.DestinationPath
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        $localPath = Join-Path $destDir $fileName
        Copy-Item $PackagePath $localPath -Force

        if ($Config.Provider -eq 'R2') {
            return [PSCustomObject]@{
                Status        = 'LocalOnly'
                Provider      = 'LocalFolder(R2Fallback)'
                Destination   = $destDir
                RemotePath    = $localPath
                UploadedAtUtc = [datetime]::UtcNow.ToString('o')
                Sha256        = $sha256
                Error         = if ($r2Error) { "Cloud upload failed: $r2Error" } else { 'Cloud upload failed' }
            }
        }

        return [PSCustomObject]@{
            Status        = 'Uploaded'
            Provider      = 'LocalFolder'
            Destination   = $destDir
            RemotePath    = $localPath
            UploadedAtUtc = [datetime]::UtcNow.ToString('o')
            Sha256        = $sha256
            Error         = $null
        }
    } catch {
        return [PSCustomObject]@{
            Status        = 'Failed'
            Provider      = $Config.Provider
            Destination   = $Config.DestinationPath
            RemotePath    = $null
            UploadedAtUtc = $null
            Sha256        = $null
            Error         = $_.Exception.Message
        }
    }
}

#endregion

Export-ModuleMember -Function @(
    'Get-WinConfigDiagnosticsUploadConfig'
    'Send-WinConfigDiagnosticPackage'
)

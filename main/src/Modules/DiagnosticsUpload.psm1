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
    .PARAMETER Channel
        Which credential block to use. 'Default' (the existing R2 block —
        Bluetooth diagnostics, bucket winconfig-diagnostics) or 'Support'
        (the SupportR2 block — support bundles, bucket winconfig-support).
        Omitting the parameter is byte-for-byte the pre-Channel behaviour.
    .OUTPUTS
        Hashtable: Provider, R2 (sub-hashtable), DestinationPath, Enabled, Channel
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Default', 'Support')]
        [string]$Channel = 'Default'
    )

    # Locate bundled config (staged next to Modules/ at src/Config/)
    $configPath = Join-Path $PSScriptRoot '..\Config\WinConfig.DiagnosticsConfig.psd1'
    $r2Config   = $null

    if (Test-Path $configPath) {
        try {
            $raw = Import-PowerShellDataFile $configPath -ErrorAction Stop
            $r2  = if ($Channel -eq 'Support') { $raw.SupportR2 } else { $raw.R2 }
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
        Channel         = $Channel
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

#region Large files: S3 multipart upload (NO-LAUNCH-001)
# Invoke-R2Put reads the whole file into memory and sends one request -- fine
# for a 60 KB bundle, not for a 1 GB memory dump on a client's connection. A
# multipart upload sends fixed-size parts, retries a failed part on its own,
# and aborts cleanly so R2 does not keep orphaned parts.

# Seam for tests: replaced with a recorder so the request sequence and the
# signing can be checked without a network. Signature of the real one:
# param($Method, $Uri, $Headers, [byte[]]$Body) -> @{ StatusCode; Content; Headers }
$script:R2Transport = {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [byte[]]$Body)
    $oldPref = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'   # PS 5.1 progress rendering slows large bodies badly
    try {
        $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
        if ($Body -and $Body.Length -gt 0) { $params.Body = $Body }
        $resp = Invoke-WebRequest @params
        return @{ StatusCode = [int]$resp.StatusCode; Content = [string]$resp.Content; Headers = $resp.Headers }
    } finally {
        $ProgressPreference = $oldPref
    }
}

function ConvertTo-R2CanonicalQuery {
    <# RFC 3986-encoded, key-sorted query string as SigV4 requires. #>
    param([hashtable]$Query)
    if (-not $Query -or $Query.Count -eq 0) { return '' }
    $pairs = foreach ($k in ($Query.Keys | Sort-Object { [string]$_ } -CaseSensitive)) {
        '{0}={1}' -f [Uri]::EscapeDataString([string]$k), [Uri]::EscapeDataString([string]$Query[$k])
    }
    return ($pairs -join '&')
}

function Get-R2SignedRequest {
    <#
    .SYNOPSIS
        Builds the URI and SigV4 headers for one R2 request. Pure: the clock is a parameter.
    #>
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter(Mandatory)] [hashtable]$R2,
        [Parameter(Mandatory)] [string]$ObjectKey,
        [hashtable]$Query = @{},
        [byte[]]$Body = [byte[]]@(),
        [string]$ContentType = 'application/octet-stream',
        [datetime]$UtcNow = [datetime]::UtcNow
    )
    $r2Host       = "$($R2.AccountId).r2.cloudflarestorage.com"
    $canonicalUri = "/$($R2.BucketName)/$ObjectKey"
    $queryString  = ConvertTo-R2CanonicalQuery $Query
    $amzDate      = $UtcNow.ToString('yyyyMMddTHHmmssZ')
    $dateStamp    = $UtcNow.ToString('yyyyMMdd')
    $payloadHash  = Get-Sha256HexBytes $Body

    $canonicalHeaders = "content-type:$ContentType`nhost:$r2Host`nx-amz-content-sha256:$payloadHash`nx-amz-date:$amzDate`n"
    $signedHeaders    = 'content-type;host;x-amz-content-sha256;x-amz-date'
    $canonicalRequest = "$Method`n$canonicalUri`n$queryString`n$canonicalHeaders`n$signedHeaders`n$payloadHash"
    $credentialScope  = "$dateStamp/auto/s3/aws4_request"
    $stringToSign     = "AWS4-HMAC-SHA256`n$amzDate`n$credentialScope`n$(Get-Sha256HexString $canonicalRequest)"

    $kDate    = Get-HmacSha256Bytes ([System.Text.Encoding]::UTF8.GetBytes("AWS4$($R2.SecretKey)")) $dateStamp
    $kRegion  = Get-HmacSha256Bytes $kDate 'auto'
    $kService = Get-HmacSha256Bytes $kRegion 's3'
    $kSign    = Get-HmacSha256Bytes $kService 'aws4_request'
    $sig      = ConvertTo-HexString (Get-HmacSha256Bytes $kSign $stringToSign)

    return @{
        Uri              = "https://$r2Host$canonicalUri$(if ($queryString) { "?$queryString" })"
        CanonicalRequest = $canonicalRequest
        Headers          = @{
            'Authorization'        = "AWS4-HMAC-SHA256 Credential=$($R2.AccessKeyId)/$credentialScope, SignedHeaders=$signedHeaders, Signature=$sig"
            'x-amz-date'           = $amzDate
            'x-amz-content-sha256' = $payloadHash
            'Content-Type'         = $ContentType
        }
    }
}

function Invoke-R2Request {
    param([string]$Method, [hashtable]$R2, [string]$ObjectKey, [hashtable]$Query = @{}, [byte[]]$Body = [byte[]]@(), [string]$ContentType = 'application/octet-stream')
    $req = Get-R2SignedRequest -Method $Method -R2 $R2 -ObjectKey $ObjectKey -Query $Query -Body $Body -ContentType $ContentType
    return (& $script:R2Transport $Method $req.Uri $req.Headers $Body)
}

function Send-WinConfigLargeFile {
    <#
    .SYNOPSIS
        Uploads one large file to R2 as an S3 multipart upload. Never copies it anywhere else.
    .DESCRIPTION
        The file stays where it is; on failure the caller still has it. Each part is
        retried on its own; a failed upload is aborted so R2 keeps no orphaned parts.
    .OUTPUTS
        PSCustomObject: Status (Uploaded | Skipped | Failed), RemotePath, Bytes, Parts, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [hashtable]$Config,
        [Parameter(Mandatory)] [string]$ObjectKey,
        [ValidateRange(5MB, 512MB)] [int]$PartSize = 32MB,
        [int]$MaxAttemptsPerPart = 4,
        [scriptblock]$OnProgress = $null
    )
    $result = [ordered]@{ Status = 'Failed'; RemotePath = $null; Bytes = 0; Parts = 0; Error = $null }
    if (-not $Config.Enabled -or $Config.Provider -ne 'R2' -or -not $Config.R2) {
        $result.Status = 'Skipped'; $result.Error = 'Cloud upload is not configured in this build'
        return [pscustomobject]$result
    }
    if (-not (Test-Path -LiteralPath $FilePath)) { $result.Error = "File not found: $FilePath"; return [pscustomobject]$result }
    if ($ObjectKey -notmatch '^[A-Za-z0-9_\-\./]+$') { $result.Error = "Object key has characters outside [A-Za-z0-9_-./]: $ObjectKey"; return [pscustomobject]$result }

    $r2 = $Config.R2
    $total = (Get-Item -LiteralPath $FilePath).Length
    $result.Bytes = $total
    $uploadId = $null
    $stream = $null
    try {
        $init = Invoke-R2Request -Method 'POST' -R2 $r2 -ObjectKey $ObjectKey -Query @{ uploads = '' }
        $uploadId = ([xml]$init.Content).InitiateMultipartUploadResult.UploadId
        if (-not $uploadId) { throw 'R2 did not return an UploadId' }

        $etags = New-Object System.Collections.ArrayList
        $stream = [System.IO.File]::OpenRead($FilePath)
        $buffer = New-Object byte[] $PartSize
        $partNumber = 0
        $sent = [int64]0
        while ($true) {
            $read = 0
            while ($read -lt $PartSize) {
                $n = $stream.Read($buffer, $read, $PartSize - $read)
                if ($n -le 0) { break }
                $read += $n
            }
            if ($read -le 0 -and $partNumber -gt 0) { break }
            $partNumber++
            # Assigned inside the branches, never as an if-expression: that would
            # unroll the byte[] through the pipeline into one object per byte.
            if ($read -eq $PartSize) { $body = $buffer } else { $body = New-Object byte[] $read; [Array]::Copy($buffer, $body, $read) }
            $etag = $null
            $lastErr = $null
            for ($attempt = 1; $attempt -le $MaxAttemptsPerPart -and -not $etag; $attempt++) {
                try {
                    $resp = Invoke-R2Request -Method 'PUT' -R2 $r2 -ObjectKey $ObjectKey -Query @{ partNumber = "$partNumber"; uploadId = $uploadId } -Body $body
                    $etag = [string]($resp.Headers['ETag'])
                    if (-not $etag) { $lastErr = "part $partNumber returned no ETag" }
                } catch { $lastErr = $_.Exception.Message }
                if (-not $etag -and $attempt -lt $MaxAttemptsPerPart) { Start-Sleep -Seconds ([Math]::Min(30, 2 * $attempt * $attempt)) }
            }
            if (-not $etag) { throw "Part $partNumber failed after $MaxAttemptsPerPart attempts: $lastErr" }
            [void]$etags.Add(@{ PartNumber = $partNumber; ETag = $etag })
            $sent += $read
            if ($OnProgress) { try { & $OnProgress $sent $total } catch { } }
            if ($read -lt $PartSize) { break }
        }

        $xml = '<CompleteMultipartUpload>' + (($etags | ForEach-Object { '<Part><PartNumber>{0}</PartNumber><ETag>{1}</ETag></Part>' -f $_.PartNumber, [System.Security.SecurityElement]::Escape($_.ETag) }) -join '') + '</CompleteMultipartUpload>'
        $null = Invoke-R2Request -Method 'POST' -R2 $r2 -ObjectKey $ObjectKey -Query @{ uploadId = $uploadId } -Body ([System.Text.Encoding]::UTF8.GetBytes($xml)) -ContentType 'application/xml'
        $result.Status = 'Uploaded'
        $result.RemotePath = "$($r2.BucketName)/$ObjectKey"
        $result.Parts = $etags.Count
    } catch {
        $result.Error = $_.Exception.Message
        if ($uploadId) { try { $null = Invoke-R2Request -Method 'DELETE' -R2 $r2 -ObjectKey $ObjectKey -Query @{ uploadId = $uploadId } } catch { } }
    } finally {
        if ($stream) { $stream.Dispose() }
    }
    return [pscustomobject]$result
}

#endregion

Export-ModuleMember -Function @(
    'Get-WinConfigDiagnosticsUploadConfig'
    'Send-WinConfigDiagnosticPackage'
    'Send-WinConfigLargeFile'
)

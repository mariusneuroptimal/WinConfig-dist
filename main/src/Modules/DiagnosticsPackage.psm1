# DiagnosticsPackage.psm1
# Packages WinConfig diagnostic run artifacts into a transportable ZIP.
#
# CONTRACT:
# - All paths are ephemeral (under $env:TEMP via Paths.psm1)
# - Callers own upload/retention decisions
# - This module does not write outside the session temp root

function New-WinConfigDiagnosticRun {
    <#
    .SYNOPSIS
        Creates a scoped folder for one diagnostic run.
    .OUTPUTS
        Hashtable: RunId, RunFolder, ExportsRoot, ToolId, StartedAtUtc
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ToolId
    )

    $exportsPath = if (Get-Command Get-WinConfigExportsPath -ErrorAction SilentlyContinue) {
        Get-WinConfigExportsPath
    } else {
        Join-Path $env:TEMP "WinConfig-fallback\exports"
    }

    $runId = [guid]::NewGuid().ToString("N").Substring(0, 12).ToUpper()
    $runsDir = Join-Path $exportsPath "runs"
    $runFolder = Join-Path $runsDir $runId

    foreach ($dir in @($runsDir, $runFolder)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    return @{
        RunId        = $runId
        RunFolder    = $runFolder
        ExportsRoot  = $exportsPath
        ToolId       = $ToolId
        StartedAtUtc = [datetime]::UtcNow.ToString("o")
    }
}

function Add-WinConfigDiagnosticArtifact {
    <#
    .SYNOPSIS
        Writes a JSON artifact to the run folder.
    .PARAMETER Depth
        ConvertTo-Json depth. Defaults to 5 (the original behaviour). Callers
        with nested collector output MUST pass a higher depth explicitly —
        ConvertTo-Json silently flattens anything below its depth limit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RunFolder,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Data,

        [int]$Depth = 5
    )

    if (-not (Test-Path $RunFolder)) {
        throw "Run folder not found: $RunFolder"
    }

    $filePath = Join-Path $RunFolder $Name
    $Data | ConvertTo-Json -Depth $Depth | Out-File -FilePath $filePath -Encoding UTF8 -Force
}

function Add-WinConfigDiagnosticFile {
    <#
    .SYNOPSIS
        Copies a raw file into the run folder (Add-WinConfigDiagnosticArtifact
        only writes JSON; some bundles must carry files verbatim).
    .DESCRIPTION
        Enforces the clinical-data deny-list at the shared-module level as
        defence in depth: no diagnostic bundle, present or future, may package
        anything under C:\zengar\sessions or C:\zengar\BLT_data.
    .OUTPUTS
        The destination path of the copied file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RunFolder,

        [Parameter(Mandatory)]
        [string]$SourcePath,

        # Leaf name for the copy; defaults to the source file name.
        [string]$TargetName = ''
    )

    # Deny-list first: a denied path is refused as denied whether or not it exists
    $full = [System.IO.Path]::GetFullPath($SourcePath)
    foreach ($denied in @('C:\zengar\sessions', 'C:\zengar\BLT_data')) {
        if ($full.TrimEnd('\') -eq $denied -or $full -like "$denied\*") {
            throw "Denied: '$SourcePath' is under the clinical-data deny-list ($denied)"
        }
    }

    if (-not (Test-Path $RunFolder)) {
        throw "Run folder not found: $RunFolder"
    }
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Source file not found: $SourcePath"
    }

    $leaf = if ($TargetName) { Split-Path $TargetName -Leaf } else { Split-Path $SourcePath -Leaf }
    $destination = Join-Path $RunFolder $leaf
    Copy-Item -LiteralPath $SourcePath -Destination $destination -Force
    return $destination
}

function Compress-WinConfigDiagnosticRun {
    <#
    .SYNOPSIS
        Compresses a run folder into a ZIP under ExportsRoot.
    .OUTPUTS
        Hashtable: ZipPath, SizeBytes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RunFolder,

        [Parameter(Mandatory)]
        [string]$ExportsRoot,

        [string]$Label = '',

        # Filename prefix. Defaults to 'bt' so every existing Bluetooth call
        # site produces byte-identical names. The support bundle passes 'support'.
        [string]$Prefix = 'bt'
    )

    if (-not (Test-Path $RunFolder)) {
        throw "Run folder not found: $RunFolder"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $runId   = Split-Path $RunFolder -Leaf
    $stem    = if ($Label) { "${Prefix}_${Label}_${runId}" } else { "${Prefix}_$runId" }
    $zipPath = Join-Path $ExportsRoot "$stem.zip"

    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }

    [System.IO.Compression.ZipFile]::CreateFromDirectory($RunFolder, $zipPath)

    return @{
        ZipPath   = $zipPath
        SizeBytes = (Get-Item $zipPath).Length
    }
}

Export-ModuleMember -Function @(
    'New-WinConfigDiagnosticRun'
    'Add-WinConfigDiagnosticArtifact'
    'Add-WinConfigDiagnosticFile'
    'Compress-WinConfigDiagnosticRun'
)

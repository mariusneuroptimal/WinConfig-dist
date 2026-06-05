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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RunFolder,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Data
    )

    if (-not (Test-Path $RunFolder)) {
        throw "Run folder not found: $RunFolder"
    }

    $filePath = Join-Path $RunFolder $Name
    $Data | ConvertTo-Json -Depth 5 | Out-File -FilePath $filePath -Encoding UTF8 -Force
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

        [string]$Label = ''
    )

    if (-not (Test-Path $RunFolder)) {
        throw "Run folder not found: $RunFolder"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $runId   = Split-Path $RunFolder -Leaf
    $stem    = if ($Label) { "bt_${Label}_${runId}" } else { "bt_$runId" }
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
    'Compress-WinConfigDiagnosticRun'
)

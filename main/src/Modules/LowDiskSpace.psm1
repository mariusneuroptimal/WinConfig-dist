#Requires -Version 5.1
<#
.SYNOPSIS
    LOW-DISK-001: reversible low-disk-space simulation for application testing.

.DESCRIPTION
    The field method this replaces was a .bat file that called
    "fsutil file createnew C:\test.txt <MB>". It works, but it answers the
    wrong question and leaves the wrong trace:

      * It is sized in MEGABYTES TO CONSUME. A tester who wants "500 MB free"
        has to read the free space, subtract, and retype the arithmetic --
        on every machine, every time, and again after Windows moves a GB
        underneath them. This module is sized in FREE SPACE TO LEAVE, which
        is the number test cases are actually written against.

      * It leaves C:\test.txt behind. Nothing on the box says what that is,
        which tool made it, or that deleting it is safe -- and nothing finds
        it again after a reboot on a different tech's shift. This module
        writes one clearly-named folder per volume holding numbered chunks, a
        state file, a README, and a RESTORE-FREE-SPACE.cmd that undoes
        everything by double-click WITHOUT WinConfig -- which matters
        precisely because a full disk is a state in which applications fail
        to start.

      * It requires elevation, because fsutil does. Allocation through the
        file system API does not. Creating the folder at the volume root
        still may, so elevation is reported as a precondition, not assumed.

    HOW THE SPACE IS TAKEN. [IO.FileStream]::SetLength extends a file to a
    length without writing its contents; on NTFS the clusters are allocated
    immediately, so free space drops at memory speed (measured: 512 MB in
    10 ms) and the volume reports exactly what the application under test
    will read back from GetDiskFreeSpaceEx.

    THE ALLOCATION IS ALWAYS VERIFIED, NEVER ASSUMED. On a volume with NTFS
    compression, sparse semantics, or data deduplication, an unwritten extent
    can cost less than its length. Every chunk is measured against the
    volume's own free-space counter, and a chunk that did not cost what it
    claims is discarded and re-made by writing incompressible bytes. The
    result object says which method actually paid for the space.

    SAFETY. Filler lives in exactly one folder per volume, and only files
    matching this module's own names are ever deleted -- a corrupt or
    hand-edited state file cannot turn cleanup into data loss. The root is
    refused outright if it resolves to a volume root, a Windows or Program
    Files path, or anything under a Zengar clinical data folder.

.NOTES
    Surface: Tools -> Disk -> Low Disk Space Testing (WinConfig GUI).
    Every function here is pure or measured; the window decides only how a
    line is painted.
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# One folder name, one chunk name shape. Cleanup trusts these and nothing else.
$script:LowDiskFolderName   = 'WinConfig-LowDiskSpace-Test'
$script:LowDiskStateFile    = 'lowdisk-state.json'
$script:LowDiskEscapeFile   = 'RESTORE-FREE-SPACE.cmd'
$script:LowDiskReadmeFile   = 'README-FIRST.txt'
$script:LowDiskChunkPattern = '^filler-\d{3,}\.bin$'

# Default chunk size. Small enough that releasing space is fine-grained,
# large enough that a 500 GB volume does not become 500 000 files.
$script:LowDiskDefaultChunkBytes = 1GB
$script:LowDiskMaxChunks         = 512

# Below this, Windows itself starts to misbehave (no room for the page file to
# grow, servicing failures, profile load failures). The tool still goes there
# on request -- that is the whole point -- but it says so first.
$script:LowDiskMinRecommendedFreeBytes = 250MB

# Test seam. Production never sets this; the round-trip suite points the filler
# root at a temp folder so it can fill and restore for real without writing to
# a volume root on a build agent.
$script:LowDiskRootOverride = $null

# ---------------------------------------------------------------------------
# FORMATTING
# ---------------------------------------------------------------------------

function Format-LowDiskBytes {
    <#
    .SYNOPSIS
        Formats a byte count the way a tester reads it back to someone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[long]]$Bytes
    )

    if ($null -eq $Bytes) { return 'n/a' }

    $abs = [Math]::Abs($Bytes)
    if     ($abs -ge 1TB) { return ('{0:0.00} TB' -f ($Bytes / 1TB)) }
    elseif ($abs -ge 1GB) { return ('{0:0.00} GB' -f ($Bytes / 1GB)) }
    elseif ($abs -ge 1MB) { return ('{0:0.0} MB'  -f ($Bytes / 1MB)) }
    elseif ($abs -ge 1KB) { return ('{0:0} KB'    -f ($Bytes / 1KB)) }
    else                  { return ("$Bytes bytes") }
}

function Get-LowDiskTargetPresets {
    <#
    .SYNOPSIS
        The free-space levels a tester actually asks for, with what each means.
    .DESCRIPTION
        Sized in FREE SPACE REMAINING, not bytes consumed. The Note is what the
        level is for -- a preset without a reason is just a number in a list.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{ Label = '10 GB free';  FreeBytes = 10GB;  Note = 'Installer / update headroom gone; large exports start failing' }
        [PSCustomObject]@{ Label = '5 GB free';   FreeBytes = 5GB;   Note = 'A long session can still run, but with no margin' }
        [PSCustomObject]@{ Label = '2 GB free';   FreeBytes = 2GB;   Note = 'Windows starts reclaiming; app-level warnings expected here' }
        [PSCustomObject]@{ Label = '1 GB free';   FreeBytes = 1GB;   Note = 'Session writes begin to fail mid-run' }
        [PSCustomObject]@{ Label = '500 MB free'; FreeBytes = 500MB; Note = 'Windows low-disk notification territory' }
        [PSCustomObject]@{ Label = '250 MB free'; FreeBytes = 250MB; Note = 'Floor of what Windows tolerates; expect OS-level errors' }
        [PSCustomObject]@{ Label = '100 MB free'; FreeBytes = 100MB; Note = 'Hostile: page file cannot grow, some apps will not launch' }
        [PSCustomObject]@{ Label = '0 bytes free (disk full)'; FreeBytes = 0L; Note = 'Restore before doing anything else on this box' }
    )
}

function Get-LowDiskMinRecommendedFreeBytes {
    [CmdletBinding()]
    param()
    return [long]$script:LowDiskMinRecommendedFreeBytes
}

function Get-LowDiskPercentPresets {
    <#
    .SYNOPSIS
        Free-space levels expressed as a PERCENTAGE of the volume.
    .DESCRIPTION
        WHY BOTH UNITS EXIST. An absolute target does not travel between
        machines: "leave 5 GB free" is a comfortable margin on a 1 TB disk and
        an emergency on a 128 GB one. A percentage does travel, and it is also
        how several of the behaviours under test are actually written --
        Windows' own low-disk warning, Storage Sense, and any application check
        phrased as "less than N % free".

        The percentage is of TOTAL VOLUME SIZE, which is what those checks use,
        not of currently free space.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{ Label = '25 % free'; Percent = 25.0; Note = 'Comfortable, but past the point updates and defragmentation prefer' }
        [PSCustomObject]@{ Label = '15 % free'; Percent = 15.0; Note = 'Windows Update and servicing start to feel it' }
        [PSCustomObject]@{ Label = '10 % free'; Percent = 10.0; Note = 'The classic low-disk threshold applications test against' }
        [PSCustomObject]@{ Label = '5 % free';  Percent = 5.0;  Note = 'Storage Sense territory; warnings expected' }
        [PSCustomObject]@{ Label = '2 % free';  Percent = 2.0;  Note = 'Sustained writes begin to fail, even on a large volume' }
        [PSCustomObject]@{ Label = '1 % free';  Percent = 1.0;  Note = 'Severe; on a small disk this is already hostile' }
    )
}

function ConvertTo-LowDiskFreeBytesFromPercent {
    <#
    .SYNOPSIS
        Turns "leave N % free" into bytes for one volume. Pure arithmetic.
    .DESCRIPTION
        Of TOTAL SIZE, not of free space: "10 % free" means the volume reports
        a tenth of its capacity available, which is the shape of the checks
        this simulates. On a 951.80 GB volume that is 95.18 GB -- and on a
        237.95 GB volume it is 23.80 GB, which is the entire point of offering
        the unit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [long]$SizeBytes,
        [Parameter(Mandatory = $true)] [ValidateRange(0.0, 100.0)] [double]$Percent
    )

    if ($SizeBytes -le 0) { return 0L }
    return [long][Math]::Round($SizeBytes * ($Percent / 100.0))
}

# ---------------------------------------------------------------------------
# PATHS AND SAFETY
# ---------------------------------------------------------------------------

function Get-LowDiskByteSum {
    <#
    .SYNOPSIS
        Sums the Bytes of a chunk list, including when the list is empty.
    .DESCRIPTION
        Measure-Object -Property over an empty pipeline emits NOTHING under
        Set-StrictMode, so the idiomatic (... | Measure-Object -Sum).Sum throws
        on exactly the case that matters most here -- a volume with no filler.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Chunks
    )

    $sum = 0L
    foreach ($chunk in @($Chunks)) {
        if ($null -ne $chunk -and $null -ne $chunk.Bytes) { $sum += [long]$chunk.Bytes }
    }
    return $sum
}

function ConvertTo-LowDiskCanonicalPath {
    <#
    .SYNOPSIS
        One spelling for one path, so that two of them can be compared.
    .DESCRIPTION
        REAL DEFECT THIS FIXES. The deletion gate compares a file's parent
        folder against the filler root. Those two strings arrive from different
        places, and Windows will happily hand back the SAME folder under two
        spellings: "C:\Users\ZENGAR~1\..." from an environment variable and
        "C:\Users\Zengar User\..." from directory enumeration. Compared as
        text they are not equal, so the gate refused to delete the very files
        this module had just created and Restore reported everything skipped.

        [IO.Path]::GetFullPath expands 8.3 short names and normalises
        separators; Resolve-Path does NOT expand them, which is why it is not
        used here. A path that cannot be canonicalised is returned unchanged --
        the gate then fails closed, which is the safe direction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try { return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\') } catch { return $Path.TrimEnd('\') }
}

function Get-LowDiskFillerRoot {
    <#
    .SYNOPSIS
        The one folder on a volume that may ever hold filler.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    if ($script:LowDiskRootOverride) { return (ConvertTo-LowDiskCanonicalPath -Path $script:LowDiskRootOverride) }

    $letter = $DriveLetter.Trim().TrimEnd(':', '\')
    return (ConvertTo-LowDiskCanonicalPath -Path ('{0}:\{1}' -f $letter, $script:LowDiskFolderName))
}

function Test-LowDiskRootAcceptable {
    <#
    .SYNOPSIS
        Refuses a filler root that could put deletion anywhere that matters.
    .DESCRIPTION
        Returns @{ Acceptable = bool; Reason = string }. The reason is written
        into the result, not swallowed: a refusal a tester cannot read is a
        tool that "just does nothing".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    # SHAPE IS CHECKED ON THE RAW INPUT, BEFORE CANONICALISATION. A bare drive
    # spec like "C:" is not the root of C: -- [IO.Path]::GetFullPath expands it
    # to the PROCESS WORKING DIRECTORY, so canonicalising first would turn an
    # obviously-invalid root into a plausible-looking folder full of somebody's
    # real files. Anything that is not <letter>:\<something> is refused here.
    if ($Root -notmatch '^[A-Za-z]:\\[^\\]') {
        return @{ Acceptable = $false; Reason = "Filler root must be a folder on a local drive, such as C:\WinConfig-LowDiskSpace-Test (got '$Root')" }
    }

    $normalized = ConvertTo-LowDiskCanonicalPath -Path $Root
    $lower = $normalized.ToLowerInvariant()

    if ($normalized -match '^[A-Za-z]:\\?$') {
        return @{ Acceptable = $false; Reason = 'Filler root must not be a volume root' }
    }

    # Clinical data and OS trees are never a place this tool writes or deletes.
    foreach ($forbidden in @('\zengar\sessions', '\zengar\blt_data', '\windows', '\program files', '\programdata\neuroptimal')) {
        if ($lower -like ('*' + $forbidden + '*')) {
            return @{ Acceptable = $false; Reason = "Filler root resolves inside a protected path ('$forbidden')" }
        }
    }

    return @{ Acceptable = $true; Reason = 'OK' }
}

function Test-LowDiskManagedFile {
    <#
    .SYNOPSIS
        True only for a file this module created, inside a root it accepts.
    .DESCRIPTION
        THE ONLY GATE DELETION USES. Cleanup never trusts the state file's list
        of paths; it re-checks every path through here first, so a corrupted,
        stale, or hand-edited state file cannot widen the blast radius beyond
        this module's own chunk names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $rootCheck = Test-LowDiskRootAcceptable -Root $Root
    if (-not $rootCheck.Acceptable) { return $false }

    $rootNorm = ConvertTo-LowDiskCanonicalPath -Path $Root
    $parent = Split-Path $Path -Parent
    if (-not $parent) { return $false }
    $parentNorm = ConvertTo-LowDiskCanonicalPath -Path $parent
    if ($parentNorm.ToLowerInvariant() -ne $rootNorm.ToLowerInvariant()) { return $false }

    $name = Split-Path $Path -Leaf
    if ($name -match $script:LowDiskChunkPattern) { return $true }
    if ($name -in @($script:LowDiskStateFile, $script:LowDiskEscapeFile, $script:LowDiskReadmeFile)) { return $true }

    return $false
}

# ---------------------------------------------------------------------------
# VOLUMES
# ---------------------------------------------------------------------------

function Get-LowDiskVolume {
    <#
    .SYNOPSIS
        Fixed volumes with the free space an application under test will read.
    .DESCRIPTION
        AvailableFreeSpace, not TotalFreeSpace: it honours a per-user quota,
        which is what GetDiskFreeSpaceEx reports to the process being tested.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DriveLetter
    )

    $systemLetter = ($env:SystemDrive).TrimEnd(':', '\').ToUpperInvariant()
    $rows = @()

    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) { continue }
            if (-not $drive.IsReady) { continue }
        } catch { continue }

        $letter = $drive.Name.TrimEnd('\').TrimEnd(':').ToUpperInvariant()
        if ($DriveLetter) {
            $wanted = $DriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant()
            if ($letter -ne $wanted) { continue }
        }

        $size = [long]$drive.TotalSize
        $free = [long]$drive.AvailableFreeSpace

        $rows += [PSCustomObject]@{
            PSTypeName     = 'WinConfig.LowDisk.Volume'
            DriveLetter    = $letter
            Root           = ($letter + ':\')
            Label          = $(try { $drive.VolumeLabel } catch { '' })
            FileSystem     = $(try { $drive.DriveFormat } catch { 'unknown' })
            SizeBytes      = $size
            FreeBytes      = $free
            UsedBytes      = ($size - $free)
            FreePercent    = $(if ($size -gt 0) { [Math]::Round(($free / $size) * 100, 1) } else { 0 })
            IsSystemVolume = ($letter -eq $systemLetter)
            FillerRoot     = (Get-LowDiskFillerRoot -DriveLetter $letter)
        }
    }

    return @($rows)
}

function Get-LowDiskFreeBytes {
    <#
    .SYNOPSIS
        One live free-space read. Every measurement in this module goes through here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    $letter = $DriveLetter.Trim().TrimEnd(':', '\')
    $info = New-Object System.IO.DriveInfo ($letter + ':\')
    return [long]$info.AvailableFreeSpace
}

# ---------------------------------------------------------------------------
# STATE
# ---------------------------------------------------------------------------

function Get-LowDiskFillerState {
    <#
    .SYNOPSIS
        What filler currently exists on a volume, read from the disk itself.
    .DESCRIPTION
        THE FILES ARE THE TRUTH, THE STATE FILE IS THE STORY. Chunks are
        enumerated from the folder, not from the JSON, so a missing or corrupt
        state file still yields a complete, deletable inventory -- which is the
        state this tool is most likely to be found in (different tech,
        different shift, after a reboot).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    $letter = $DriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant()
    $root = Get-LowDiskFillerRoot -DriveLetter $letter
    $statePath = Join-Path $root $script:LowDiskStateFile

    $result = [PSCustomObject]@{
        PSTypeName      = 'WinConfig.LowDisk.State'
        DriveLetter     = $letter
        Root            = $root
        RootExists      = (Test-Path -LiteralPath $root)
        Present         = $false
        Chunks          = @()
        ChunkCount      = 0
        AllocatedBytes  = 0L
        StateReadable   = $false
        StatePath       = $statePath
        CreatedUtc      = $null
        TargetFreeBytes = $null
        Method          = $null
        CreatedBy       = $null
        UnmanagedFiles  = @()
    }

    if (-not $result.RootExists) { return $result }

    $chunks = @()
    $unmanaged = @()
    foreach ($file in (Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue)) {
        if ($file.Name -match $script:LowDiskChunkPattern) {
            $chunks += [PSCustomObject]@{ Path = $file.FullName; Name = $file.Name; Bytes = [long]$file.Length }
        } elseif ($file.Name -notin @($script:LowDiskStateFile, $script:LowDiskEscapeFile, $script:LowDiskReadmeFile)) {
            $unmanaged += $file.FullName
        }
    }

    $chunks = @($chunks | Sort-Object Name)
    $result.Chunks = $chunks
    $result.ChunkCount = @($chunks).Count
    $result.AllocatedBytes = Get-LowDiskByteSum -Chunks $chunks
    $result.Present = (@($chunks).Count -gt 0)
    $result.UnmanagedFiles = @($unmanaged)

    if (Test-Path -LiteralPath $statePath) {
        try {
            $json = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $result.StateReadable   = $true
            $result.CreatedUtc      = $json.createdUtc
            $result.TargetFreeBytes = $(if ($null -ne $json.targetFreeBytes) { [long]$json.targetFreeBytes } else { $null })
            $result.Method          = $json.method
            $result.CreatedBy       = $json.createdBy
        } catch {
            $result.StateReadable = $false
        }
    }

    return $result
}

function Save-LowDiskFillerState {
    <#
    .SYNOPSIS
        Records what is held, atomically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Root,
        [Parameter(Mandatory = $true)] [string]$DriveLetter,
        [Parameter(Mandatory = $true)] [long]$TargetFreeBytes,
        [Parameter(Mandatory = $true)] [string]$Method,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [array]$Chunks
    )

    $statePath = Join-Path $Root $script:LowDiskStateFile
    $payload = [ordered]@{
        schema          = 'winconfig-lowdisk-state/1'
        toolId          = 'low-disk-space-test'
        driveLetter     = $DriveLetter
        createdUtc      = [datetime]::UtcNow.ToString('o')
        createdBy       = ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)
        targetFreeBytes = $TargetFreeBytes
        method          = $Method
        chunkCount      = @($Chunks).Count
        allocatedBytes  = (Get-LowDiskByteSum -Chunks $Chunks)
        chunks          = @(@($Chunks) | ForEach-Object { @{ name = $_.Name; bytes = $_.Bytes } })
        restoreHint     = ('Double-click {0} in this folder, or use WinConfig -> Tools -> Disk -> Low Disk Space Testing -> Restore Free Space.' -f $script:LowDiskEscapeFile)
    }

    # Temp file then move: a half-written state file during a disk-full test is
    # exactly the condition this tool creates, so it must not be able to eat
    # its own inventory.
    $tempPath = $statePath + '.tmp'
    ($payload | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $tempPath -Encoding UTF8 -Force
    Move-Item -LiteralPath $tempPath -Destination $statePath -Force
    return $statePath
}

function Write-LowDiskEscapeHatch {
    <#
    .SYNOPSIS
        Writes the double-click restore script and the README beside the filler.
    .DESCRIPTION
        WINCONFIG MAY NOT BE THE THING THAT CLEANS THIS UP. A box with 0 bytes
        free is a box where applications fail to launch -- including this one.
        The escape hatch is plain cmd.exe, deletes only this module's own file
        names, and works from Explorer with no tool installed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $cmdPath = Join-Path $Root $script:LowDiskEscapeFile
    $cmd = @(
        '@echo off'
        'REM WinConfig Low Disk Space Testing - restore free space.'
        'REM Deletes ONLY the filler files this folder was created to hold.'
        'setlocal'
        'echo.'
        'echo Removing WinConfig low-disk test filler from "%~dp0" ...'
        'del /f /q "%~dp0filler-*.bin" 2>nul'
        ('del /f /q "%~dp0{0}" 2>nul' -f $script:LowDiskStateFile)
        'echo.'
        'echo Free space restored. This folder can now be deleted.'
        'echo.'
        'pause'
    ) -join "`r`n"
    Set-Content -LiteralPath $cmdPath -Value $cmd -Encoding ASCII -Force

    $readmePath = Join-Path $Root $script:LowDiskReadmeFile
    $readme = @(
        'WinConfig - Low Disk Space Testing'
        '=================================='
        ''
        'This folder is NOT user data and contains NO application data.'
        'It holds placeholder files whose only purpose is to occupy disk space'
        'so that low-disk-space behaviour can be tested on this machine.'
        ''
        'TO GIVE THE SPACE BACK, do any one of these:'
        ('  1. Double-click {0} in this folder, or' -f $script:LowDiskEscapeFile)
        '  2. Open WinConfig -> Tools -> Disk -> Low Disk Space Testing'
        '     and click "Restore Free Space", or'
        '  3. Delete this entire folder.'
        ''
        'All three are safe and equivalent. Nothing else on this machine'
        'depends on these files.'
        ''
        ('Created: {0} UTC by {1}\{2}' -f [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'), $env:USERDOMAIN, $env:USERNAME)
    ) -join "`r`n"
    Set-Content -LiteralPath $readmePath -Value $readme -Encoding ASCII -Force

    return @{ EscapePath = $cmdPath; ReadmePath = $readmePath }
}

# ---------------------------------------------------------------------------
# PLANNING (pure)
# ---------------------------------------------------------------------------

function Get-LowDiskChunkSizes {
    <#
    .SYNOPSIS
        Splits a byte total into chunk sizes. Pure arithmetic, no I/O.
    .DESCRIPTION
        Chunks exist so the tester can hand space back a piece at a time, and so
        a failed allocation costs one chunk rather than the run. The chunk size
        grows when it has to: a 4 TB volume must not become half a million files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [long]$TotalBytes,
        [Parameter(Mandatory = $false)] [long]$ChunkSizeBytes = 0,
        [Parameter(Mandatory = $false)] [int]$MaxChunks = 0
    )

    if ($TotalBytes -le 0) { return @() }
    if ($ChunkSizeBytes -le 0) { $ChunkSizeBytes = [long]$script:LowDiskDefaultChunkBytes }
    if ($MaxChunks -le 0) { $MaxChunks = $script:LowDiskMaxChunks }

    if ([Math]::Ceiling($TotalBytes / $ChunkSizeBytes) -gt $MaxChunks) {
        $needed = [long][Math]::Ceiling($TotalBytes / [double]$MaxChunks)
        # Round up to a whole 64 MB so chunk sizes stay readable in a report.
        $ChunkSizeBytes = [long]([Math]::Ceiling($needed / 64MB) * 64MB)
    }

    $sizes = @()
    $remaining = $TotalBytes
    while ($remaining -gt 0) {
        $take = [Math]::Min($ChunkSizeBytes, $remaining)
        $sizes += [long]$take
        $remaining -= $take
    }
    return @($sizes)
}

function Get-LowDiskMaxReachableFreeBytes {
    <#
    .SYNOPSIS
        The highest free space this tool can produce on a volume. Pure arithmetic.
    .DESCRIPTION
        THE CEILING IS THE ONE NUMBER THE TESTER NEEDS AND NEVER HAD. This tool
        only ever takes free space away and hands back what it took, so the most
        it can leave free is what is free now plus what it is holding. Every
        target at or below this number is reachable; every target above it is
        not, and no amount of retrying changes that.

        It exists as a named function because the window and the planner must
        agree about it. A window that offers a target the planner will refuse is
        the defect this closes: the refusal arrived in a modal AFTER the click,
        phrased as what the tool cannot do rather than what the tester can pick.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [long]$FreeBytes,
        [Parameter(Mandatory = $false)] [long]$AllocatedBytes = 0
    )

    if ($AllocatedBytes -lt 0) { $AllocatedBytes = 0L }
    return [long]($FreeBytes + $AllocatedBytes)
}

function New-LowDiskAllocationPlan {
    <#
    .SYNOPSIS
        Decides what must happen to reach a target free space. Pure arithmetic.
    .DESCRIPTION
        Action is one of:
          Fill    - allocate more filler to bring free space DOWN to the target
          Release - delete filler to bring free space UP to the target
          None    - already there (within tolerance)
          Blocked - the target cannot be reached by this tool

        Blocked is the honest answer to "leave 50 GB free" on a box that has
        20 GB free and no filler to give back: this tool takes space, it cannot
        manufacture it. Saying so beats silently doing nothing.

        BLOCKED SAYS WHAT IS TRUE AND WHAT TO PICK. The first wording of this
        refusal was correct and useless: "this tool consumes space; it cannot
        create it" tells a tester who asked for 25 % free on a disk sitting at
        5 % nothing they can act on. Two facts turn it into an answer -- the
        disk is ALREADY below the level they wanted to test, and the highest
        target reachable here is MaxReachableFreeBytes. Both ride on every plan
        shape, not just this one, so the window can render the ceiling without
        re-deriving it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [long]$FreeBytes,
        [Parameter(Mandatory = $true)] [long]$TargetFreeBytes,
        [Parameter(Mandatory = $false)] [long]$AllocatedBytes = 0,
        [Parameter(Mandatory = $false)] [long]$ChunkSizeBytes = 0,
        [Parameter(Mandatory = $false)] [long]$ToleranceBytes = 16MB
    )

    $delta = $FreeBytes - $TargetFreeBytes
    $maxReachable = Get-LowDiskMaxReachableFreeBytes -FreeBytes $FreeBytes -AllocatedBytes $AllocatedBytes

    if ([Math]::Abs($delta) -le $ToleranceBytes) {
        return [PSCustomObject]@{
            PSTypeName      = 'WinConfig.LowDisk.AllocationPlan'
            Action          = 'None'
            BytesToFill     = 0L
            BytesToRelease  = 0L
            ChunkSizes      = @()
            FreeBytes       = $FreeBytes
            TargetFreeBytes = $TargetFreeBytes
            ProjectedFree   = $FreeBytes
            MaxReachableFreeBytes = $maxReachable
            ShortfallBytes  = 0L
            Reason          = 'Free space is already at the requested level'
        }
    }

    if ($delta -gt 0) {
        $sizes = Get-LowDiskChunkSizes -TotalBytes $delta -ChunkSizeBytes $ChunkSizeBytes
        return [PSCustomObject]@{
            PSTypeName      = 'WinConfig.LowDisk.AllocationPlan'
            Action          = 'Fill'
            BytesToFill     = [long]$delta
            BytesToRelease  = 0L
            ChunkSizes      = $sizes
            FreeBytes       = $FreeBytes
            TargetFreeBytes = $TargetFreeBytes
            ProjectedFree   = $TargetFreeBytes
            MaxReachableFreeBytes = $maxReachable
            ShortfallBytes  = 0L
            Reason          = ('Allocate {0} in {1} chunk(s)' -f (Format-LowDiskBytes -Bytes $delta), @($sizes).Count)
        }
    }

    $wanted = [long](-$delta)
    if ($AllocatedBytes -le 0) {
        return [PSCustomObject]@{
            PSTypeName      = 'WinConfig.LowDisk.AllocationPlan'
            Action          = 'Blocked'
            BytesToFill     = 0L
            BytesToRelease  = 0L
            ChunkSizes      = @()
            FreeBytes       = $FreeBytes
            TargetFreeBytes = $TargetFreeBytes
            ProjectedFree   = $FreeBytes
            MaxReachableFreeBytes = $maxReachable
            ShortfallBytes  = $wanted
            Reason          = ('Already below the target: {0} free now, {1} asked for, and this tool is holding no filler to give back. It can only take free space away, never create it, so the most it can leave free here is {0}. Pick {0} or less, or free up real space first.' -f (Format-LowDiskBytes -Bytes $maxReachable), (Format-LowDiskBytes -Bytes $TargetFreeBytes))
        }
    }

    $release = [long][Math]::Min($wanted, $AllocatedBytes)
    $reason = ('Release {0} of filler' -f (Format-LowDiskBytes -Bytes $release))
    if ($release -lt $wanted) {
        $reason = ('Release all {0} of filler; that is {1} short of the target, because the rest of the space was never taken by this tool.' -f (Format-LowDiskBytes -Bytes $release), (Format-LowDiskBytes -Bytes ($wanted - $release)))
    }

    return [PSCustomObject]@{
        PSTypeName      = 'WinConfig.LowDisk.AllocationPlan'
        Action          = 'Release'
        BytesToFill     = 0L
        BytesToRelease  = $release
        ChunkSizes      = @()
        FreeBytes       = $FreeBytes
        TargetFreeBytes = $TargetFreeBytes
        ProjectedFree   = [long]($FreeBytes + $release)
        MaxReachableFreeBytes = $maxReachable
        ShortfallBytes  = [long]($wanted - $release)
        Reason          = $reason
    }
}

function Get-LowDiskPlan {
    <#
    .SYNOPSIS
        The full, read-only plan for one volume: arithmetic plus preconditions.
    .DESCRIPTION
        Read-only by contract -- this is what the Dry Run button renders, so it
        must not create the folder it is planning to write into.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    param(
        [Parameter(Mandatory = $true)] [string]$DriveLetter,

        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')]
        [long]$TargetFreeBytes,

        # ONE RESOLUTION, AND IT HAPPENS HERE. A percentage becomes bytes
        # exactly once, against this volume's size, and everything downstream --
        # the confirmation, the fill, the report -- uses the resolved number.
        # Resolving it twice is how a preview and an execution end up
        # describing different work.
        [Parameter(Mandatory = $true, ParameterSetName = 'Percent')]
        [ValidateRange(0.0, 100.0)]
        [double]$TargetPercent,

        [Parameter(Mandatory = $false)] [long]$ChunkSizeBytes = 0
    )

    $letter = $DriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant()
    $volume = @(Get-LowDiskVolume -DriveLetter $letter) | Select-Object -First 1
    $state = Get-LowDiskFillerState -DriveLetter $letter
    $root = Get-LowDiskFillerRoot -DriveLetter $letter

    $usedPercent = ($PSCmdlet.ParameterSetName -eq 'Percent')
    if ($usedPercent) {
        $TargetFreeBytes = $(if ($volume) { ConvertTo-LowDiskFreeBytesFromPercent -SizeBytes $volume.SizeBytes -Percent $TargetPercent } else { 0L })
    }
    $rootCheck = Test-LowDiskRootAcceptable -Root $root

    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $isAdmin = $false }

    $core = $null
    $warnings = @()
    $blockers = @()

    if (-not $volume) {
        $blockers += ("Volume {0}: is not a ready fixed disk" -f $letter)
    } else {
        $core = New-LowDiskAllocationPlan -FreeBytes $volume.FreeBytes -TargetFreeBytes $TargetFreeBytes -AllocatedBytes $state.AllocatedBytes -ChunkSizeBytes $ChunkSizeBytes

        if ($TargetFreeBytes -lt (Get-LowDiskMinRecommendedFreeBytes)) {
            $warnings += ('Target of {0} is below the {1} Windows needs to stay healthy. Expect OS-level errors, not just application ones -- that may be the point, but restore promptly.' -f (Format-LowDiskBytes -Bytes $TargetFreeBytes), (Format-LowDiskBytes -Bytes (Get-LowDiskMinRecommendedFreeBytes)))
        }
        if ($volume.IsSystemVolume) {
            $warnings += 'This is the system volume. The page file, Windows Update and crash dumps compete for the same free space, so the number will drift a little on its own.'
        }
        if ($volume.FileSystem -and $volume.FileSystem -notin @('NTFS', 'ReFS')) {
            $warnings += ('Volume is {0}, not NTFS. Instant allocation is unlikely to work; the tool will fall back to writing real data, which is slow.' -f $volume.FileSystem)
        }
        if ($state.Present) {
            $warnings += ('{0} of filler from an earlier run is already present ({1} chunk(s)). It is counted, not duplicated.' -f (Format-LowDiskBytes -Bytes $state.AllocatedBytes), $state.ChunkCount)
        }
        if (@($state.UnmanagedFiles).Count -gt 0) {
            $warnings += ('{0} file(s) in the filler folder were not created by this tool and will be left alone.' -f @($state.UnmanagedFiles).Count)
        }
    }

    if (-not $rootCheck.Acceptable) { $blockers += $rootCheck.Reason }
    if (-not $isAdmin -and -not $state.RootExists) {
        $warnings += ('Not elevated. Creating {0} at the volume root may be denied; if it is, restart WinConfig as Administrator.' -f $root)
    }

    return [PSCustomObject]@{
        PSTypeName      = 'WinConfig.LowDisk.Plan'
        DriveLetter     = $letter
        Volume          = $volume
        Root            = $root
        State           = $state
        TargetFreeBytes = [long]$TargetFreeBytes
        TargetPercent   = $(if ($usedPercent) { [double]$TargetPercent } else { $null })
        TargetUnit      = $(if ($usedPercent) { 'Percent' } else { 'Bytes' })
        TargetLabel     = $(if ($usedPercent) { ('{0:0.##} % of {1} = {2}' -f $TargetPercent, (Format-LowDiskBytes -Bytes $(if ($volume) { $volume.SizeBytes } else { 0L })), (Format-LowDiskBytes -Bytes $TargetFreeBytes)) } else { (Format-LowDiskBytes -Bytes $TargetFreeBytes) })
        Action          = $(if ($core) { $core.Action } else { 'Blocked' })
        BytesToFill     = $(if ($core) { $core.BytesToFill } else { 0L })
        BytesToRelease  = $(if ($core) { $core.BytesToRelease } else { 0L })
        ChunkSizes      = $(if ($core) { $core.ChunkSizes } else { @() })
        ProjectedFree   = $(if ($core) { $core.ProjectedFree } else { $null })
        # The ceiling rides on the plan so the window never re-derives it.
        MaxReachableFreeBytes = $(if ($core) { [long]$core.MaxReachableFreeBytes } else { $null })
        ShortfallBytes  = $(if ($core) { [long]$core.ShortfallBytes } else { $null })
        Reason          = $(if ($core) { $core.Reason } else { 'No plan: volume unavailable' })
        Warnings        = @($warnings)
        Blockers        = @($blockers)
        IsAdmin         = $isAdmin
        Executable      = (@($blockers).Count -eq 0)
    }
}

# ---------------------------------------------------------------------------
# EXECUTION
# ---------------------------------------------------------------------------

function New-LowDiskChunkFile {
    <#
    .SYNOPSIS
        Creates one filler file of an exact length.
    .DESCRIPTION
        Allocate: SetLength extends the file without writing content. On NTFS
        the clusters are committed immediately -- 512 MB in about 10 ms.

        Write: real incompressible bytes, for volumes where an unwritten extent
        does not cost what it claims (NTFS compression, dedup, sparse files).
        Orders of magnitude slower, used only when measurement demands it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [long]$Bytes,
        [Parameter(Mandatory = $false)] [ValidateSet('Allocate', 'Write')] [string]$Method = 'Allocate'
    )

    if ($Method -eq 'Allocate') {
        $stream = [System.IO.File]::Create($Path)
        try {
            $stream.SetLength($Bytes)
            # THE FILL MUST SURVIVE A REBOOT. That is the requirement the whole
            # tool is built on: a test case that says "boot this machine with
            # 500 MB free" has to still be true after the boot. Flush($true)
            # pushes the allocation through to the disk rather than leaving it
            # in the cache, so even a hard power cut during a low-disk test
            # comes back up still low on disk instead of silently healed.
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        return
    }

    # Cryptographic bytes, freshly drawn for EVERY chunk. Two chunks of the
    # same pseudo-random buffer are a gift to data deduplication, which would
    # then collapse them and hand the space straight back -- the exact failure
    # this fallback exists to avoid.
    $bufferSize = 4MB
    $buffer = New-Object byte[] $bufferSize
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }

    $stream = [System.IO.File]::Create($Path)
    try {
        $written = 0L
        while ($written -lt $Bytes) {
            $take = [int][Math]::Min([long]$bufferSize, ($Bytes - $written))
            $stream.Write($buffer, 0, $take)
            $written += $take
        }
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Test-LowDiskChunkDurable {
    <#
    .SYNOPSIS
        Will this chunk still be costing its length after the machine reboots?
    .DESCRIPTION
        THE FILL IS REQUIRED TO SURVIVE A REBOOT, so the two attributes that
        would quietly break that are checked on the file itself rather than
        assumed from how it was made:

          SparseFile - an extent that reads as zeroes and occupies nothing.
                       Free space comes back on its own.
          Temporary  - a hint that the contents may be held in cache and the
                       file discarded; not what a persistent fixture wants.

        Compressed is reported but is NOT a durability failure: compression
        changes what a chunk COSTS, and cost is already verified against the
        volume's own free-space counter at creation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $attributes = [System.IO.File]::GetAttributes($Path)
    $sparse     = (($attributes -band [System.IO.FileAttributes]::SparseFile) -ne 0)
    $temporary  = (($attributes -band [System.IO.FileAttributes]::Temporary) -ne 0)
    $compressed = (($attributes -band [System.IO.FileAttributes]::Compressed) -ne 0)

    return [PSCustomObject]@{
        PSTypeName = 'WinConfig.LowDisk.Durability'
        Path       = $Path
        Durable    = (-not ($sparse -or $temporary))
        Sparse     = $sparse
        Temporary  = $temporary
        Compressed = $compressed
        Attributes = $attributes.ToString()
    }
}

function Invoke-LowDiskFill {
    <#
    .SYNOPSIS
        Brings a volume's free space DOWN to a target, verifying every chunk.
    .DESCRIPTION
        The loop re-reads free space after each chunk rather than trusting its
        own arithmetic. Two things make that necessary rather than paranoid:
        another process may take or give back space mid-run, and an allocation
        that did not cost what it claimed must be caught at the chunk that
        caused it -- not at the end, with a wrong answer already reported.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$DriveLetter,
        [Parameter(Mandatory = $true)] [long]$TargetFreeBytes,
        [Parameter(Mandatory = $false)] [long]$ChunkSizeBytes = 0,
        [Parameter(Mandatory = $false)] [long]$ToleranceBytes = 16MB,
        [Parameter(Mandatory = $false)] [scriptblock]$OnProgress
    )

    $letter = $DriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant()
    $root = Get-LowDiskFillerRoot -DriveLetter $letter
    $started = Get-Date
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()

    $report = {
        param($Level, $Message)
        if ($OnProgress) { & $OnProgress @{ Level = $Level; Message = $Message } }
    }

    $result = [PSCustomObject]@{
        PSTypeName      = 'WinConfig.LowDisk.FillResult'
        DriveLetter     = $letter
        Root            = $root
        Succeeded       = $false
        Reason          = ''
        TargetFreeBytes = [long]$TargetFreeBytes
        FreeBefore      = $null
        FreeAfter       = $null
        AllocatedBytes  = 0L
        ChunksCreated   = 0
        Method          = 'Allocate'
        PersistsAcrossReboot = $false
        DurationMs      = 0
        StartedUtc      = $started.ToUniversalTime().ToString('o')
        Warnings        = @()
    }

    $rootCheck = Test-LowDiskRootAcceptable -Root $root
    if (-not $rootCheck.Acceptable) {
        $result.Reason = $rootCheck.Reason
        return $result
    }

    $freeBefore = Get-LowDiskFreeBytes -DriveLetter $letter
    $result.FreeBefore = $freeBefore
    $result.FreeAfter = $freeBefore

    if (($freeBefore - $TargetFreeBytes) -le $ToleranceBytes) {
        $result.Succeeded = $true
        $result.Reason = 'Free space is already at or below the target; nothing allocated'
        return $result
    }

    if (-not (Test-Path -LiteralPath $root)) {
        try {
            New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
        } catch {
            $result.Reason = ("Could not create '{0}': {1} Restart WinConfig as Administrator and try again." -f $root, $_.Exception.Message)
            return $result
        }
    }

    # Continue the existing numbering, so a second run adds to the filler
    # instead of colliding with it.
    $existing = @((Get-LowDiskFillerState -DriveLetter $letter).Chunks)
    $index = 0
    foreach ($chunk in $existing) {
        if ($chunk.Name -match '(\d+)') {
            $n = [int]$Matches[1]
            if ($n -gt $index) { $index = $n }
        }
    }

    $method = 'Allocate'
    $created = @()
    $iterations = 0
    $free = $freeBefore

    while (($free - $TargetFreeBytes) -gt $ToleranceBytes) {
        $iterations++
        if ($iterations -gt 4096) {
            $result.Warnings += 'Stopped after 4096 chunks as a runaway guard'
            break
        }

        $needed = $free - $TargetFreeBytes
        $sizes = Get-LowDiskChunkSizes -TotalBytes $needed -ChunkSizeBytes $ChunkSizeBytes
        $chunkTarget = $(if (@($sizes).Count -gt 0) { [long]@($sizes)[0] } else { [long]$needed })

        $index++
        $chunkPath = Join-Path $root ('filler-{0:000}.bin' -f $index)
        $freeBeforeChunk = $free
        $placed = $false
        $attemptBytes = [long]$chunkTarget

        while (-not $placed -and $attemptBytes -ge 1MB) {
            try {
                New-LowDiskChunkFile -Path $chunkPath -Bytes $attemptBytes -Method $method
                $placed = $true
            } catch {
                # "There is not enough space on the disk" while aiming at a very
                # low target is expected, not exceptional. Halve and try again.
                if (Test-Path -LiteralPath $chunkPath) { Remove-Item -LiteralPath $chunkPath -Force -ErrorAction SilentlyContinue }
                $attemptBytes = [long]($attemptBytes / 2)
            }
        }

        if (-not $placed) {
            $free = Get-LowDiskFreeBytes -DriveLetter $letter
            $result.Warnings += ('Could not allocate any further; stopped {0} above the target.' -f (Format-LowDiskBytes -Bytes ($free - $TargetFreeBytes)))
            break
        }

        $free = Get-LowDiskFreeBytes -DriveLetter $letter
        $paid = $freeBeforeChunk - $free

        # THE MEASUREMENT, NOT THE CLAIM. If the extent did not cost what it
        # says, this volume compresses, dedupes or sparsifies it: drop the
        # chunk and switch this run to writing real bytes.
        if ($paid -lt ($attemptBytes * 0.9)) {
            Remove-Item -LiteralPath $chunkPath -Force -ErrorAction SilentlyContinue
            $free = Get-LowDiskFreeBytes -DriveLetter $letter
            $index--
            if ($method -eq 'Allocate') {
                $method = 'Write'
                $result.Method = 'Write'
                $warning = ('Instant allocation only cost {0} of {1} on this volume (compression, dedup or sparse files). Switched to writing real data, which is slower.' -f (Format-LowDiskBytes -Bytes $paid), (Format-LowDiskBytes -Bytes $attemptBytes))
                $result.Warnings += $warning
                & $report 'WARN' $warning
                continue
            }
            $result.Reason = 'Neither allocation nor writing reduced free space on this volume; it may be deduplicated or quota-managed'
            break
        }

        # A chunk that would evaporate over a reboot is worse than no chunk:
        # the test case reads as set up and the machine comes back healthy.
        $durability = Test-LowDiskChunkDurable -Path $chunkPath
        if (-not $durability.Durable) {
            Remove-Item -LiteralPath $chunkPath -Force -ErrorAction SilentlyContinue
            $free = Get-LowDiskFreeBytes -DriveLetter $letter
            $index--
            if ($method -eq 'Allocate') {
                $method = 'Write'
                $result.Method = 'Write'
                $warning = ('The volume made the chunk sparse or temporary ({0}), which would give the space back at the next reboot. Switched to writing real data.' -f $durability.Attributes)
                $result.Warnings += $warning
                & $report 'WARN' $warning
                continue
            }
            $result.Reason = ('Chunks on this volume come out {0}; the fill would not survive a reboot, so nothing was kept.' -f $durability.Attributes)
            break
        }

        $created += [PSCustomObject]@{ Name = (Split-Path $chunkPath -Leaf); Path = $chunkPath; Bytes = $attemptBytes }
        & $report 'OK' ('Allocated {0} ({1}) - free now {2}' -f (Split-Path $chunkPath -Leaf), (Format-LowDiskBytes -Bytes $attemptBytes), (Format-LowDiskBytes -Bytes $free))
    }

    $stopwatch.Stop()
    $result.FreeAfter = Get-LowDiskFreeBytes -DriveLetter $letter
    $result.ChunksCreated = @($created).Count
    $result.AllocatedBytes = Get-LowDiskByteSum -Chunks $created
    $result.DurationMs = [int]$stopwatch.ElapsedMilliseconds

    $allChunks = @((Get-LowDiskFillerState -DriveLetter $letter).Chunks)

    # Claimed on evidence, not on intent: every chunk actually on the volume is
    # re-checked, including any left by an earlier run this one added to.
    $notDurable = @(@($allChunks) | Where-Object { -not (Test-LowDiskChunkDurable -Path $_.Path).Durable })
    $result.PersistsAcrossReboot = ((@($allChunks).Count -gt 0) -and (@($notDurable).Count -eq 0))

    if (@($allChunks).Count -gt 0) {
        # The escape hatch is written BEFORE the run is reported as finished:
        # the moment space is taken is the moment someone may need it back.
        Write-LowDiskEscapeHatch -Root $root | Out-Null
        Save-LowDiskFillerState -Root $root -DriveLetter $letter -TargetFreeBytes $TargetFreeBytes -Method $method -Chunks $allChunks | Out-Null
    }

    if (-not $result.Reason) {
        $missBy = $result.FreeAfter - $TargetFreeBytes
        if ([Math]::Abs($missBy) -le ($ToleranceBytes * 4)) {
            $result.Succeeded = $true
            $result.Reason = ('Free space is now {0}' -f (Format-LowDiskBytes -Bytes $result.FreeAfter))
        } else {
            $result.Reason = ('Stopped at {0} free, {1} off the {2} target' -f (Format-LowDiskBytes -Bytes $result.FreeAfter), (Format-LowDiskBytes -Bytes $missBy), (Format-LowDiskBytes -Bytes $TargetFreeBytes))
        }
    }

    return $result
}

function Restore-LowDiskFreeSpace {
    <#
    .SYNOPSIS
        Gives the space back. Deletes only files this module made.
    .DESCRIPTION
        -ReleaseBytes releases approximately that much and keeps the rest,
        which is how a tester steps free space back up one level without
        starting over. Omit it to remove everything and delete the folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$DriveLetter,
        [Parameter(Mandatory = $false)] [long]$ReleaseBytes = 0,
        [Parameter(Mandatory = $false)] [scriptblock]$OnProgress
    )

    $letter = $DriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant()
    $root = Get-LowDiskFillerRoot -DriveLetter $letter
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()

    $report = {
        param($Level, $Message)
        if ($OnProgress) { & $OnProgress @{ Level = $Level; Message = $Message } }
    }

    $result = [PSCustomObject]@{
        PSTypeName     = 'WinConfig.LowDisk.RestoreResult'
        DriveLetter    = $letter
        Root           = $root
        Succeeded      = $false
        Reason         = ''
        FreeBefore     = (Get-LowDiskFreeBytes -DriveLetter $letter)
        FreeAfter      = $null
        ReclaimedBytes = 0L
        FilesRemoved   = 0
        FilesSkipped   = @()
        FolderRemoved  = $false
        DurationMs     = 0
    }

    $rootCheck = Test-LowDiskRootAcceptable -Root $root
    if (-not $rootCheck.Acceptable) {
        $result.Reason = $rootCheck.Reason
        $result.FreeAfter = $result.FreeBefore
        return $result
    }

    $state = Get-LowDiskFillerState -DriveLetter $letter
    if (-not $state.RootExists) {
        $result.Succeeded = $true
        $result.Reason = 'No filler folder on this volume; nothing to restore'
        $result.FreeAfter = $result.FreeBefore
        return $result
    }

    # Newest chunk first: a partial release should undo the most recent step.
    $chunks = @($state.Chunks | Sort-Object Name -Descending)
    $releasedSoFar = 0L

    foreach ($chunk in $chunks) {
        if ($ReleaseBytes -gt 0 -and $releasedSoFar -ge $ReleaseBytes) { break }

        if (-not (Test-LowDiskManagedFile -Path $chunk.Path -Root $root)) {
            $result.FilesSkipped += $chunk.Path
            continue
        }
        try {
            Remove-Item -LiteralPath $chunk.Path -Force -ErrorAction Stop
            $releasedSoFar += $chunk.Bytes
            $result.FilesRemoved++
            & $report 'OK' ('Removed {0} ({1})' -f $chunk.Name, (Format-LowDiskBytes -Bytes $chunk.Bytes))
        } catch {
            $result.FilesSkipped += ('{0} ({1})' -f $chunk.Path, $_.Exception.Message)
        }
    }

    $remaining = Get-LowDiskFillerState -DriveLetter $letter
    if ($remaining.ChunkCount -gt 0) {
        # Partial release: keep the folder and re-state what is still held.
        Write-LowDiskEscapeHatch -Root $root | Out-Null
        $keptTarget = $(if ($null -ne $state.TargetFreeBytes) { [long]$state.TargetFreeBytes } else { 0L })
        Save-LowDiskFillerState -Root $root -DriveLetter $letter -TargetFreeBytes $keptTarget -Method 'Allocate' -Chunks @($remaining.Chunks) | Out-Null
    } else {
        foreach ($name in @($script:LowDiskStateFile, $script:LowDiskEscapeFile, $script:LowDiskReadmeFile)) {
            $path = Join-Path $root $name
            if ((Test-Path -LiteralPath $path) -and (Test-LowDiskManagedFile -Path $path -Root $root)) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                $result.FilesRemoved++
            }
        }
        $leftovers = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)
        if (@($leftovers).Count -eq 0) {
            try {
                Remove-Item -LiteralPath $root -Force -ErrorAction Stop
                $result.FolderRemoved = $true
            } catch {
                $result.FilesSkipped += ('{0} ({1})' -f $root, $_.Exception.Message)
            }
        } else {
            # Something else put files here. Leave them, and say so.
            $result.FilesSkipped += @($leftovers | ForEach-Object { $_.FullName })
        }
    }

    $stopwatch.Stop()
    $result.FreeAfter = Get-LowDiskFreeBytes -DriveLetter $letter
    $result.ReclaimedBytes = [long]($result.FreeAfter - $result.FreeBefore)
    $result.DurationMs = [int]$stopwatch.ElapsedMilliseconds
    $result.Succeeded = (@($result.FilesSkipped).Count -eq 0)
    $result.Reason = $(if ($result.Succeeded) {
        ('Reclaimed {0}; free space is now {1}' -f (Format-LowDiskBytes -Bytes $result.ReclaimedBytes), (Format-LowDiskBytes -Bytes $result.FreeAfter))
    } else {
        ('Reclaimed {0}, but {1} item(s) could not be removed' -f (Format-LowDiskBytes -Bytes $result.ReclaimedBytes), @($result.FilesSkipped).Count)
    })

    return $result
}

function Find-LowDiskLeftovers {
    <#
    .SYNOPSIS
        Every volume still holding filler, from any session and any tech.
    .DESCRIPTION
        Read when the window opens, so a box left filled on a previous shift
        announces itself instead of being rediscovered as "the disk is full".
    #>
    [CmdletBinding()]
    param()

    $found = @()
    foreach ($volume in (Get-LowDiskVolume)) {
        $state = Get-LowDiskFillerState -DriveLetter $volume.DriveLetter
        if ($state.Present) {
            $found += [PSCustomObject]@{
                DriveLetter    = $volume.DriveLetter
                Root           = $state.Root
                AllocatedBytes = $state.AllocatedBytes
                ChunkCount     = $state.ChunkCount
                CreatedUtc     = $state.CreatedUtc
                CreatedBy      = $state.CreatedBy
                FreeBytes      = $volume.FreeBytes
            }
        }
    }
    return @($found)
}

Export-ModuleMember -Function @(
    'Format-LowDiskBytes'
    'Get-LowDiskByteSum'
    'ConvertTo-LowDiskCanonicalPath'
    'Get-LowDiskTargetPresets'
    'Get-LowDiskPercentPresets'
    'ConvertTo-LowDiskFreeBytesFromPercent'
    'Get-LowDiskMinRecommendedFreeBytes'
    'Get-LowDiskFillerRoot'
    'Test-LowDiskRootAcceptable'
    'Test-LowDiskManagedFile'
    'Get-LowDiskVolume'
    'Get-LowDiskFreeBytes'
    'Get-LowDiskFillerState'
    'Save-LowDiskFillerState'
    'Write-LowDiskEscapeHatch'
    'Get-LowDiskChunkSizes'
    'Get-LowDiskMaxReachableFreeBytes'
    'New-LowDiskAllocationPlan'
    'Get-LowDiskPlan'
    'New-LowDiskChunkFile'
    'Test-LowDiskChunkDurable'
    'Invoke-LowDiskFill'
    'Restore-LowDiskFreeSpace'
    'Find-LowDiskLeftovers'
)

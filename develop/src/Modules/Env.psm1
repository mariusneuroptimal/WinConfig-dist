# Env.psm1 - Environment and system info helpers for WinConfig
# Phase 2C: Modularization for maintainability

function Get-WinConfigRepoRoot {
    <#
    .SYNOPSIS
        Returns the repository root directory.
    .DESCRIPTION
        Navigates up from the Modules directory to find the repo root.
    #>
    [CmdletBinding()]
    param()

    # From src/Modules/ go up two levels to repo root
    $modulePath = $PSScriptRoot
    $srcPath = Split-Path $modulePath -Parent
    $repoRoot = Split-Path $srcPath -Parent

    return $repoRoot
}

function Test-WinConfigIsAdmin {
    <#
    .SYNOPSIS
        Returns $true if the current process is running as Administrator.
    #>
    [CmdletBinding()]
    param()

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-WinConfigIsAdmin {
    <#
    .SYNOPSIS
        Checks if running as admin; shows MessageBox and returns $false if not.
    .DESCRIPTION
        Use this in button click handlers. If not admin, shows a warning dialog
        and returns $false so the handler can exit early with 'return'.
    .EXAMPLE
        if (-not (Assert-WinConfigIsAdmin)) { return }
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-WinConfigIsAdmin)) {
        [System.Windows.Forms.MessageBox]::Show(
            "This operation requires administrator privileges. Please run the script as an administrator.",
            "Administrator Rights Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $false
    }

    return $true
}

# PERF-001: CIM query cache - these values never change during a session
$script:CimCache = $null

function Get-WinConfigMachineInfo {
    <#
    .SYNOPSIS
        Returns cached machine information as a PSObject.
    .DESCRIPTION
        PERF-001: CIM queries execute AT MOST ONCE per session.
        First call populates cache, subsequent calls return cached data instantly.
        Eliminates 500-1000ms delays from repeated WMI queries.
    .OUTPUTS
        PSObject with properties: DeviceName, SerialNumber, WindowsCaption, BuildNumber, RevisionNumber, FormattedVersion
    #>
    [CmdletBinding()]
    param()

    # Return cached result if available (PERF-001: CIM queries once per session)
    if ($null -ne $script:CimCache) {
        return $script:CimCache
    }

    # First call - populate cache
    try {
        $deviceName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Name
        $serialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $windowsCaption = $osInfo.Caption
        $buildNumber = $osInfo.BuildNumber
        $revisionNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR -ErrorAction Stop).UBR

        $formattedCaption = $windowsCaption -replace "Microsoft Windows", "Windows"
        $formattedVersion = "$formattedCaption $buildNumber.$revisionNumber"

        $script:CimCache = [PSCustomObject]@{
            DeviceName       = $deviceName
            SerialNumber     = $serialNumber
            WindowsCaption   = $windowsCaption
            BuildNumber      = $buildNumber
            RevisionNumber   = $revisionNumber
            FormattedVersion = $formattedVersion
        }
    }
    catch {
        # Graceful degradation - return placeholder on error
        $script:CimCache = [PSCustomObject]@{
            DeviceName       = "Unknown"
            SerialNumber     = "Unknown"
            WindowsCaption   = "Unknown"
            BuildNumber      = "Unknown"
            RevisionNumber   = "Unknown"
            FormattedVersion = "Unknown"
        }
    }

    return $script:CimCache
}

function Get-SessionCountryInfo {
    <#
    .SYNOPSIS
        Returns country information based on Windows locale/region settings.
    .DESCRIPTION
        Uses Windows system region settings to determine country context.
        No external API calls - purely local detection for privacy and reliability.
        Designed for aggregation-ready evidence collection in network diagnostics.
    .OUTPUTS
        Hashtable with keys: CountryCode, CountryName, CountryFlag
    .EXAMPLE
        $country = Get-SessionCountryInfo
        # Returns: @{ CountryCode = "CA"; CountryName = "Canada"; CountryFlag = "" }
    #>
    [CmdletBinding()]
    param()

    try {
        # Get region info from Windows system locale
        $region = [System.Globalization.RegionInfo]::CurrentRegion

        $countryCode = $region.TwoLetterISORegionName
        $countryName = $region.EnglishName

        return @{
            CountryCode = $countryCode
            CountryName = $countryName
            CountryFlag = ""
        }
    }
    catch {
        # Fail gracefully with unknown values
        return @{
            CountryCode = "XX"
            CountryName = "Unknown"
            CountryFlag = ""
        }
    }
}

# Export public functions
Export-ModuleMember -Function Get-WinConfigRepoRoot, Test-WinConfigIsAdmin, Assert-WinConfigIsAdmin, Get-WinConfigMachineInfo, Get-SessionCountryInfo

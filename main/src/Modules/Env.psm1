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

function Get-WinConfigMachineInfo {
    <#
    .SYNOPSIS
        Returns machine information as a PSObject.
    .DESCRIPTION
        Fetches device name, serial number, OS caption, build number, and revision.
        Consolidates repeated CimInstance calls.
    .OUTPUTS
        PSObject with properties: DeviceName, SerialNumber, WindowsCaption, BuildNumber, RevisionNumber, FormattedVersion
    #>
    [CmdletBinding()]
    param()

    $deviceName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $windowsCaption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    $buildNumber = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    $revisionNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR).UBR

    $formattedCaption = $windowsCaption -replace "Microsoft Windows", "Windows"
    $formattedVersion = "$formattedCaption $buildNumber.$revisionNumber"

    return [PSCustomObject]@{
        DeviceName       = $deviceName
        SerialNumber     = $serialNumber
        WindowsCaption   = $windowsCaption
        BuildNumber      = $buildNumber
        RevisionNumber   = $revisionNumber
        FormattedVersion = $formattedVersion
    }
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

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

# Values OEMs leave in the SMBIOS model/manufacturer fields when nobody filled
# them in. They read as data but carry none, so each one has to fall through to
# the next source rather than land on a tech's clipboard.
$script:ComputerModelPlaceholders = @(
    'To Be Filled By O.E.M.', 'To be filled by O.E.M.', 'Default string',
    'System Product Name', 'System manufacturer', 'System Version',
    'Product Name', 'Not Applicable', 'Not Specified', 'Unknown', 'None',
    'OEM', 'O.E.M.', 'INVALID', 'Chassis Manufacture', 'Type1ProductConfigId'
)

function Test-WinConfigModelValue {
    <#
    .SYNOPSIS
        Returns $true when a CIM string is a real value, not an OEM placeholder.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $trimmed = $Value.Trim()
    foreach ($placeholder in $script:ComputerModelPlaceholders) {
        if ($trimmed -eq $placeholder) { return $false }
    }
    return $true
}

function Format-WinConfigComputerModel {
    <#
    .SYNOPSIS
        Joins manufacturer and model into one line without repeating the brand.
    .DESCRIPTION
        'Dell Inc.' + 'Latitude 5420' reads as 'Dell Latitude 5420'; 'LENOVO'
        becomes 'Lenovo'; and a model that already names its brand ('Surface
        Laptop Studio' under 'Microsoft Corporation') is left alone rather than
        doubled. The legal-entity tail is dropped because it is noise in a
        ticket, and because it is what makes the repetition check below miss.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Manufacturer,
        [AllowNull()][AllowEmptyString()][string]$Model
    )

    $hasVendor = (Test-WinConfigModelValue $Manufacturer) -and $Manufacturer -ne "Unknown"
    $hasModel = (Test-WinConfigModelValue $Model) -and $Model -ne "Unknown"

    if (-not $hasModel) {
        if ($hasVendor) { return "$($Manufacturer.Trim()) (model not reported)" }
        return "Unknown"
    }
    if (-not $hasVendor) { return $Model.Trim() }

    $brand = ($Manufacturer -replace '(?i)\s*\b(corporation|corp|incorporated|inc|company|co|ltd|limited|llc|gmbh|technologies|technology|computer|computers|electronics|international)\b\.?', '').Trim()
    $brand = ($brand -replace '[,\s]+$', '').Trim()
    if (-not $brand) { $brand = $Manufacturer.Trim() }

    # LENOVO / ASUSTEK arrive in shout case. Title-case anything longer than an
    # acronym so the copied line reads as a name.
    if ($brand -cmatch '^[A-Z][A-Z0-9\.\-]{3,}$') {
        $brand = [System.Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($brand.ToLowerInvariant())
    }

    $modelTrimmed = $Model.Trim()
    if ($modelTrimmed -match ('(?i)^' + [regex]::Escape($brand) + '\b')) { return $modelTrimmed }

    return "$brand $modelTrimmed"
}

function Get-WinConfigComputerModel {
    <#
    .SYNOPSIS
        Resolves this computer's make and model into one display string.
    .DESCRIPTION
        Win32_ComputerSystem.Model is the primary source - the same value
        'Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Model'
        returns - but it is not dependable on its own:

        - Whitebox and some desktop OEMs leave it as an SMBIOS placeholder
          ('To Be Filled By O.E.M.', 'System Product Name'), so it falls back to
          Win32_ComputerSystemProduct.Name, then SystemFamily, then the
          baseboard product.
        - Lenovo puts the machine-type-model code in Model and the name a tech
          would recognise ('ThinkPad X1 Carbon Gen 9') in
          Win32_ComputerSystemProduct.Version, so Lenovo boxes prefer Version
          and keep the MTM as the SKU.

        The fallback classes are queried only when the primary value is unusable,
        so the common case costs one CIM query. Callers holding a
        Win32_ComputerSystem instance already can pass it in for zero.

        Read-only: nothing here mutates, so there is no dry-run path.
    .PARAMETER ComputerSystem
        An existing Win32_ComputerSystem instance. Queried when omitted.
    .PARAMETER ComputerSystemProduct
        An existing Win32_ComputerSystemProduct instance. Queried only if needed.
    .PARAMETER BaseBoard
        An existing Win32_BaseBoard instance. Queried only if needed.
    .OUTPUTS
        PSObject with properties: Display, Manufacturer, Model, SystemFamily, SystemSku, Source
    #>
    [CmdletBinding()]
    param(
        [object]$ComputerSystem,
        [object]$ComputerSystemProduct,
        [object]$BaseBoard
    )

    $result = [PSCustomObject]@{
        Display      = "Unknown"
        Manufacturer = "Unknown"
        Model        = "Unknown"
        SystemFamily = $null
        SystemSku    = $null
        Source       = "None"
    }

    if (-not $PSBoundParameters.ContainsKey('ComputerSystem')) {
        try { $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { $ComputerSystem = $null }
    }

    $csModel  = if ($ComputerSystem) { [string]$ComputerSystem.Model } else { '' }
    $csVendor = if ($ComputerSystem) { [string]$ComputerSystem.Manufacturer } else { '' }
    $csFamily = if ($ComputerSystem) { [string]$ComputerSystem.SystemFamily } else { '' }
    $csSku    = if ($ComputerSystem) { [string]$ComputerSystem.SystemSKUNumber } else { '' }

    if (Test-WinConfigModelValue $csFamily) { $result.SystemFamily = $csFamily.Trim() }
    if (Test-WinConfigModelValue $csSku) { $result.SystemSku = $csSku.Trim() }

    # One lazy fetch, decided up front: the product class is only worth a query
    # when a primary field is unusable, or when the vendor is Lenovo (whose
    # readable name lives there by design, not by omission).
    $needProduct = (-not (Test-WinConfigModelValue $csModel)) -or (-not (Test-WinConfigModelValue $csVendor)) -or ($csVendor -match '(?i)lenovo')
    if ($needProduct -and -not $PSBoundParameters.ContainsKey('ComputerSystemProduct')) {
        try { $ComputerSystemProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop } catch { $ComputerSystemProduct = $null }
    }

    # --- Manufacturer -------------------------------------------------------
    if (Test-WinConfigModelValue $csVendor) {
        $result.Manufacturer = $csVendor.Trim()
    } elseif ($ComputerSystemProduct -and (Test-WinConfigModelValue ([string]$ComputerSystemProduct.Vendor))) {
        $result.Manufacturer = ([string]$ComputerSystemProduct.Vendor).Trim()
    }

    # --- Model --------------------------------------------------------------
    if ($result.Manufacturer -match '(?i)lenovo' -and $ComputerSystemProduct -and (Test-WinConfigModelValue ([string]$ComputerSystemProduct.Version))) {
        $result.Model = ([string]$ComputerSystemProduct.Version).Trim()
        $result.Source = "Win32_ComputerSystemProduct.Version (Lenovo)"
        if (-not $result.SystemSku -and (Test-WinConfigModelValue $csModel)) { $result.SystemSku = $csModel.Trim() }
    }

    if ($result.Source -eq "None" -and (Test-WinConfigModelValue $csModel)) {
        $result.Model = $csModel.Trim()
        $result.Source = "Win32_ComputerSystem.Model"
    }

    if ($result.Source -eq "None" -and $ComputerSystemProduct -and (Test-WinConfigModelValue ([string]$ComputerSystemProduct.Name))) {
        $result.Model = ([string]$ComputerSystemProduct.Name).Trim()
        $result.Source = "Win32_ComputerSystemProduct.Name"
    }

    if ($result.Source -eq "None" -and $result.SystemFamily) {
        $result.Model = $result.SystemFamily
        $result.Source = "Win32_ComputerSystem.SystemFamily"
    }

    # Last resort: the board. Only reached when every system-level field was a
    # placeholder, which is exactly the whitebox case this exists for.
    if ($result.Source -eq "None" -or $result.Manufacturer -eq "Unknown") {
        if (-not $PSBoundParameters.ContainsKey('BaseBoard')) {
            try { $BaseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop } catch { $BaseBoard = $null }
        }
        if ($BaseBoard) {
            if ($result.Source -eq "None" -and (Test-WinConfigModelValue ([string]$BaseBoard.Product))) {
                $result.Model = ([string]$BaseBoard.Product).Trim()
                $result.Source = "Win32_BaseBoard.Product"
            }
            if ($result.Manufacturer -eq "Unknown" -and (Test-WinConfigModelValue ([string]$BaseBoard.Manufacturer))) {
                $result.Manufacturer = ([string]$BaseBoard.Manufacturer).Trim()
            }
        }
    }

    $result.Display = Format-WinConfigComputerModel -Manufacturer $result.Manufacturer -Model $result.Model
    return $result
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
        PSObject with properties: DeviceName, SerialNumber, Manufacturer, Model,
        ComputerModel, ComputerModelSource, SystemFamily, SystemSku,
        WindowsCaption, BuildNumber, RevisionNumber, FormattedVersion
    #>
    [CmdletBinding()]
    param()

    # Return cached result if available (PERF-001: CIM queries once per session)
    if ($null -ne $script:CimCache) {
        return $script:CimCache
    }

    # First call - populate cache
    try {
        # One Win32_ComputerSystem instance serves both the device name and the
        # make/model resolution - no second query for the model.
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $deviceName = $computerSystem.Name
        $modelInfo = Get-WinConfigComputerModel -ComputerSystem $computerSystem
        $serialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $windowsCaption = $osInfo.Caption
        $buildNumber = $osInfo.BuildNumber
        $revisionNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR -ErrorAction Stop).UBR

        $formattedCaption = $windowsCaption -replace "Microsoft Windows", "Windows"
        $formattedVersion = "$formattedCaption $buildNumber.$revisionNumber"

        $script:CimCache = [PSCustomObject]@{
            DeviceName          = $deviceName
            SerialNumber        = $serialNumber
            Manufacturer        = $modelInfo.Manufacturer
            Model               = $modelInfo.Model
            ComputerModel       = $modelInfo.Display
            ComputerModelSource = $modelInfo.Source
            SystemFamily        = $modelInfo.SystemFamily
            SystemSku           = $modelInfo.SystemSku
            WindowsCaption      = $windowsCaption
            BuildNumber         = $buildNumber
            RevisionNumber      = $revisionNumber
            FormattedVersion    = $formattedVersion
        }
    }
    catch {
        # Graceful degradation - return placeholder on error
        $script:CimCache = [PSCustomObject]@{
            DeviceName          = "Unknown"
            SerialNumber        = "Unknown"
            Manufacturer        = "Unknown"
            Model               = "Unknown"
            ComputerModel       = "Unknown"
            ComputerModelSource = "None"
            SystemFamily        = $null
            SystemSku           = $null
            WindowsCaption      = "Unknown"
            BuildNumber         = "Unknown"
            RevisionNumber      = "Unknown"
            FormattedVersion    = "Unknown"
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

# =============================================================================
# SAFETY GUARDS - Reboot and System Mutation Protection
# =============================================================================

function Get-ActiveUserSessions {
    <#
    .SYNOPSIS
        Returns interactive user sessions that could have unsaved work.
    .DESCRIPTION
        Queries Win32_LogonSession for interactive sessions:
        - LogonType 2: Interactive (console)
        - LogonType 10: RemoteInteractive (RDP)
        - LogonType 11: CachedInteractive (cached credentials)

        FAIL-SAFE: If CIM query fails, returns QueryFailed=$true so caller can block.

        NOTE: We detect ALL interactive sessions including the current user's other sessions
        (e.g., disconnected RDP). Same user with multiple sessions still has data loss risk.
    .OUTPUTS
        Hashtable with: QueryFailed (bool), Error (string), Sessions (array)
    #>
    [CmdletBinding()]
    param()

    try {
        # Get current process session ID to identify our own session
        $currentSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId

        # Query interactive sessions (2=Interactive, 10=RemoteInteractive, 11=CachedInteractive)
        $sessions = Get-CimInstance -ClassName Win32_LogonSession `
            -Filter "LogonType=2 OR LogonType=10 OR LogonType=11" -ErrorAction Stop

        if (-not $sessions) {
            return @{
                QueryFailed = $false
                Error       = $null
                Sessions    = @()
            }
        }

        # Get session-to-user mapping
        $logonUsers = Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop

        # Map LogonId to Windows Session ID via process enumeration
        # This is more reliable than string parsing
        $processToSession = @{}
        Get-CimInstance -ClassName Win32_Process -Property SessionId, Handle -ErrorAction SilentlyContinue |
            ForEach-Object { $processToSession[$_.Handle] = $_.SessionId }

        $otherSessions = @()
        foreach ($session in $sessions) {
            # Find user for this logon session
            $userMapping = $logonUsers | Where-Object {
                $_.Dependent.LogonId -eq $session.LogonId
            } | Select-Object -First 1

            $userName = "Unknown"
            $domain = ""
            if ($userMapping) {
                $userName = $userMapping.Antecedent.Name
                $domain = $userMapping.Antecedent.Domain
            }

            # Skip SYSTEM and service accounts - they don't have unsaved user work
            if ($userName -in @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")) {
                continue
            }

            # Determine session type for display
            $sessionType = switch ($session.LogonType) {
                2  { "Console" }
                10 { "RDP" }
                11 { "Cached" }
                default { "Interactive" }
            }

            # Try to determine if this is our current session
            # We can't perfectly map LogonId to SessionId, so we use heuristics:
            # - Same username AND recent start time AND console type = likely current
            $isLikelyCurrentSession = $false
            if ($userName -eq $env:USERNAME -and $session.LogonType -eq 2) {
                # Console session for current user - check if it's recent
                $sessionAge = (Get-Date) - $session.StartTime
                if ($sessionAge.TotalMinutes -lt 5) {
                    $isLikelyCurrentSession = $true
                }
            }

            $otherSessions += [PSCustomObject]@{
                LogonId              = $session.LogonId
                LogonType            = $session.LogonType
                SessionType          = $sessionType
                StartTime            = $session.StartTime
                UserName             = $userName
                Domain               = $domain
                IsLikelyCurrentSession = $isLikelyCurrentSession
            }
        }

        return @{
            QueryFailed = $false
            Error       = $null
            Sessions    = $otherSessions
        }
    }
    catch {
        # FAIL-SAFE: If we can't query, return failure so caller blocks
        return @{
            QueryFailed = $true
            Error       = $_.Exception.Message
            Sessions    = @()
        }
    }
}

function Test-WinConfigSafeToReboot {
    <#
    .SYNOPSIS
        Checks if it's safe to reboot the system.
    .DESCRIPTION
        Detects other interactive sessions that could lose unsaved work.

        FAIL-SAFE BEHAVIOR:
        - If CIM query fails: Safe=$false (block by default)
        - If other sessions detected: Safe=$false
        - Only Safe=$true if query succeeds AND no other sessions found

        Returns QueryFailed flag so caller knows if this is a fail-safe block
        vs a detected-sessions block.
    .OUTPUTS
        Hashtable with: Safe (bool), Reason (string), Sessions (array), QueryFailed (bool)
    #>
    [CmdletBinding()]
    param()

    $result = Get-ActiveUserSessions

    # FAIL-SAFE: If query failed, block with explanation
    if ($result.QueryFailed) {
        return @{
            Safe        = $false
            Reason      = "Cannot verify session state (query failed: $($result.Error)). Blocking reboot as safety precaution."
            Sessions    = @()
            QueryFailed = $true
        }
    }

    # Filter to sessions that aren't likely our current session
    $otherSessions = $result.Sessions | Where-Object { -not $_.IsLikelyCurrentSession }

    if ($otherSessions.Count -gt 0) {
        # Build detailed session list for warning
        $sessionDetails = $otherSessions | ForEach-Object {
            "$($_.UserName) ($($_.SessionType))"
        }
        $sessionList = $sessionDetails -join ", "

        return @{
            Safe        = $false
            Reason      = "Other interactive sessions detected: $sessionList. These sessions may have unsaved work."
            Sessions    = $otherSessions
            QueryFailed = $false
        }
    }

    return @{
        Safe        = $true
        Reason      = $null
        Sessions    = @()
        QueryFailed = $false
    }
}

function Test-SystemProtectionEnabled {
    <#
    .SYNOPSIS
        Checks if System Protection (System Restore) is enabled on the system drive.
    .OUTPUTS
        Hashtable with: Enabled (bool), Reason (string)
    #>
    [CmdletBinding()]
    param()

    try {
        # Check via WMI/CIM - SystemRestoreConfig class
        $systemDrive = $env:SystemDrive
        $restoreConfig = Get-CimInstance -Namespace "root\default" -ClassName "SystemRestoreConfig" -ErrorAction Stop

        if ($restoreConfig.RPSessionInterval -eq 0) {
            return @{ Enabled = $false; Reason = "System Protection is disabled (RPSessionInterval=0)" }
        }

        # Also check via vssadmin if available
        $vssOutput = vssadmin list shadowstorage 2>&1 | Out-String
        if ($vssOutput -match "No shadow copies") {
            return @{ Enabled = $false; Reason = "No shadow storage allocated for System Restore" }
        }

        return @{ Enabled = $true; Reason = $null }
    }
    catch {
        # If we can't determine, assume it might work
        return @{ Enabled = $true; Reason = "Status unknown (query failed)" }
    }
}

function New-WinConfigSafetyRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before risky operations.
    .DESCRIPTION
        Checks if System Protection is enabled, then creates a restore point.
        Returns detailed status including whether System Protection is available.

        NOTE: Windows may throttle restore point creation (one per 24 hours by default).
        If throttled, this will appear as success but no new restore point is created.
    .PARAMETER Description
        Description for the restore point (prefixed with "WinConfig: ")
    .OUTPUTS
        Hashtable with: Success (bool), Error (string), SystemProtectionEnabled (bool), Throttled (bool)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $result = @{
        Success                  = $false
        Error                    = $null
        SystemProtectionEnabled  = $false
        Throttled                = $false
    }

    try {
        # Must be admin
        if (-not (Test-WinConfigIsAdmin)) {
            $result.Error = "Administrator privileges required"
            return $result
        }

        # Check if System Protection is enabled
        $protectionStatus = Test-SystemProtectionEnabled
        $result.SystemProtectionEnabled = $protectionStatus.Enabled

        if (-not $protectionStatus.Enabled) {
            $result.Error = "System Protection is not enabled: $($protectionStatus.Reason)"
            return $result
        }

        # Try to create restore point
        # Capture the before state to detect throttling
        $beforePoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        $beforeCount = $beforePoints.Count

        Checkpoint-Computer -Description "WinConfig: $Description" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop

        # Check if a new restore point was actually created (throttling detection)
        Start-Sleep -Milliseconds 500  # Brief wait for system to register
        $afterPoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        $afterCount = $afterPoints.Count

        if ($afterCount -le $beforeCount) {
            # No new restore point - likely throttled
            $result.Success = $true  # Command succeeded, just throttled
            $result.Throttled = $true
            $result.Error = "Restore point creation was throttled (Windows limits to one per 24 hours). A recent restore point may already exist."
        }
        else {
            $result.Success = $true
        }

        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
        return $result
    }
}

function Export-WinConfigDriverBackup {
    <#
    .SYNOPSIS
        Exports driver packages as a backup before removal.
    .DESCRIPTION
        Uses pnputil /export-driver to create a backup of driver packages.
        This provides a real rollback path independent of System Restore.
    .PARAMETER DriverNames
        Array of driver names (oem*.inf) to export
    .PARAMETER BackupPath
        Directory to export drivers to
    .OUTPUTS
        Hashtable with: Success (bool), ExportedCount (int), Error (string), BackupPath (string)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$DriverNames,

        [Parameter(Mandatory = $false)]
        [string]$BackupPath
    )

    $result = @{
        Success       = $false
        ExportedCount = 0
        Error         = $null
        BackupPath    = $null
        Drivers       = @()
    }

    try {
        # Generate backup path if not provided
        if (-not $BackupPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $BackupPath = Join-Path $env:TEMP "WinConfig-DriverBackup-$timestamp"
        }

        # Create backup directory
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }

        $result.BackupPath = $BackupPath

        foreach ($driverName in $DriverNames) {
            try {
                # Export using pnputil
                $exportResult = pnputil /export-driver $driverName $BackupPath 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $result.ExportedCount++
                    $result.Drivers += @{ Name = $driverName; Status = "Exported" }
                }
                else {
                    $result.Drivers += @{ Name = $driverName; Status = "Failed"; Error = $exportResult }
                }
            }
            catch {
                $result.Drivers += @{ Name = $driverName; Status = "Error"; Error = $_.Exception.Message }
            }
        }

        $result.Success = $result.ExportedCount -gt 0
        if ($result.ExportedCount -eq 0) {
            $result.Error = "No drivers were exported successfully"
        }

        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
        return $result
    }
}

# Export public functions
Export-ModuleMember -Function @(
    'Get-WinConfigRepoRoot',
    'Test-WinConfigIsAdmin',
    'Assert-WinConfigIsAdmin',
    'Get-WinConfigMachineInfo',
    'Get-WinConfigComputerModel',
    'Format-WinConfigComputerModel',
    'Test-WinConfigModelValue',
    'Get-SessionCountryInfo',
    'Get-ActiveUserSessions',
    'Test-WinConfigSafeToReboot',
    'Test-SystemProtectionEnabled',
    'New-WinConfigSafetyRestorePoint',
    'Export-WinConfigDriverBackup'
)

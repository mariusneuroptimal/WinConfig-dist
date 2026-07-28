# MachineIdentifiers.psm1
# "Machine Identifiers" - reproduces the hardware fingerprint the Zengar
# licensing application displays (MAC Addresses / ProcessorID / DiskID) and,
# when a value is missing or untrustworthy, names the reason.
#
# WHY THIS EXISTS:
# Licensing keys a machine off three WMI-derived values. When activation fails
# with "cannot read machine identifiers" the tech has no way to see what the
# licensing app saw. This module reads the same sources, shows the same values,
# and - when a value is empty, changed, or fragile - reports the actual cause
# rather than "unknown error".
#
# SOURCE OF TRUTH (verified against the licensing UI on MMEVOLD_06, 2026-07-28):
#   MAC Addresses : Win32_NetworkAdapter, MACAddress present, PhysicalAdapter,
#                   PNPDeviceID not ROOT-enumerated, ascending Index.
#                   Reproduces the licensing list exactly - same three entries,
#                   same order. VMware/Wi-Fi Direct/WAN-miniport/Hyper-V
#                   adapters are excluded by that predicate.
#   ProcessorID   : Win32_Processor.ProcessorId (first socket).
#   DiskID        : Win32_DiskDrive Index 0 SerialNumber, normalized by
#                   stripping non-alphanumerics ("ACE4_2E00_..._0001." ->
#                   "ACE42E00...0001"). Identical to the MSFT_Disk UniqueId
#                   with its "eui." prefix removed.
#
# READ-ONLY CONTRACT: every code path here is a query. The WMI repository check
# runs winmgmt /verifyrepository, which only reports consistency - this module
# must NEVER call /salvagerepository or /resetrepository, both of which mutate.

Set-StrictMode -Off

# =============================================================================
# CONSTANTS
# =============================================================================

# WMI/COM HRESULTs seen in the field when identifier reads fail. Mapped to a
# cause a tech can act on, because the raw text ("Generic failure") is useless.
$script:IdentifierErrorCauses = @{
    '0x80041003' = @{
        Cause = 'WMI denied access to the class (running as a standard user, or the WMI namespace ACL was tightened by policy).'
        Fix   = 'Re-run the licensing app elevated. If it still fails elevated, check the root\CIMV2 namespace security (wmimgmt.msc) and any hardening GPO.'
    }
    '0x80041001' = @{
        Cause = 'WMI generic failure - the provider that serves this class crashed or is unregistered.'
        Fix   = 'Check Application event log for WMI provider errors, then verify the repository (winmgmt /verifyrepository).'
    }
    '0x80041010' = @{
        Cause = 'WMI reports the class does not exist - the repository is damaged or the provider MOF is not registered.'
        Fix   = 'Run winmgmt /verifyrepository. If it reports inconsistent, escalate before repairing - repository repair is not a read-only action.'
    }
    '0x8004100E' = @{
        Cause = 'WMI namespace missing (root\CIMV2 not present) - repository damage.'
        Fix   = 'Run winmgmt /verifyrepository and escalate. Do not repair from the field without a backup.'
    }
    '0x800706BA' = @{
        Cause = 'RPC server unavailable - the Windows Management Instrumentation service is stopped or wedged.'
        Fix   = 'Check the Winmgmt service. If it is stopped, start it and re-run the licensing app.'
    }
    '0x80080005' = @{
        Cause = 'COM server execution failed - the WMI host process (WmiPrvSE.exe) could not start.'
        Fix   = 'Check for third-party AV blocking WmiPrvSE.exe, then reboot and retry.'
    }
    '0x80070005' = @{
        Cause = 'Access denied by Windows (not by WMI) - the calling account lacks rights to the underlying device.'
        Fix   = 'Re-run elevated.'
    }
}

# PNPDeviceID prefix -> bus. Determines whether an identifier is stable
# (soldered PCI part) or removable (USB dongle, dock, Bluetooth radio).
$script:IdentifierBusPrefixes = [ordered]@{
    'PCI\'  = 'PCI'
    'USB\'  = 'USB'
    'BTH\'  = 'Bluetooth'
    'ROOT\' = 'Software'
    'SWD\'  = 'Software'
}

# =============================================================================
# PRIMITIVES
# =============================================================================

function ConvertTo-WinConfigIdentifierValue {
    <#
    .SYNOPSIS
        Normalizes a raw WMI identifier the way the licensing app displays it.
    .DESCRIPTION
        Windows returns disk serials in several cosmetic shapes for the same
        drive - "ACE4_2E00_2507_6DBC_2EE4_AC00_0000_0001." from Win32_DiskDrive,
        "eui.ACE42E0025076DBC2EE4AC0000000001" from MSFT_Disk. Stripping the
        "eui." prefix and every non-alphanumeric collapses both to the single
        value licensing stores, which is what makes cross-source comparison
        possible at all.
    #>
    [CmdletBinding()]
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

    $trimmed = $Value.Trim()
    if ($trimmed -match '^(?i)eui\.(.+)$') { $trimmed = $Matches[1] }

    return ($trimmed -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
}

function Test-WinConfigIdentifierIsUsable {
    <#
    .SYNOPSIS
        True when a normalized identifier carries real information.
    .DESCRIPTION
        Firmware that does not implement a serial still answers the query - it
        returns zeros, or a vendor placeholder. Those read as "present" to a
        naive check and then collide across every machine of that model, which
        is far worse for licensing than an empty value.
    #>
    [CmdletBinding()]
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -match '^0+$') { return $false }
    if ($Value -match '^(?i)(NONE|NULL|DEFAULTSTRING|TOBEFILLEDBYOEM|SYSTEMSERIALNUMBER)$') { return $false }
    return $true
}

function Format-WinConfigMacAddress {
    <#
    .SYNOPSIS
        Renders a MAC the way the licensing UI does: uppercase, dash-separated.
    #>
    [CmdletBinding()]
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

    $hex = ($Value -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return $Value.ToUpperInvariant() }

    $pairs = for ($i = 0; $i -lt 12; $i += 2) { $hex.Substring($i, 2) }
    return ($pairs -join '-')
}

function Get-WinConfigIdentifierBus {
    <#
    .SYNOPSIS
        Maps a PNPDeviceID to the bus that enumerated the device.
    #>
    [CmdletBinding()]
    param([string]$PnpDeviceId)

    if ([string]::IsNullOrWhiteSpace($PnpDeviceId)) { return 'Unknown' }

    foreach ($prefix in $script:IdentifierBusPrefixes.Keys) {
        if ($PnpDeviceId.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $script:IdentifierBusPrefixes[$prefix]
        }
    }
    return 'Other'
}

function Get-WinConfigCimFailureInfo {
    <#
    .SYNOPSIS
        Turns a CIM exception into a named cause plus a remediation step.
    .OUTPUTS
        Hashtable: Message, HResult, Cause, Fix.
    #>
    [CmdletBinding()]
    param($ErrorRecord)

    $message = 'Unknown failure'
    $hresult = ''

    if ($ErrorRecord) {
        try { $message = [string]$ErrorRecord.Exception.Message } catch { }
        try {
            $raw = $ErrorRecord.Exception.HResult
            if ($raw) { $hresult = '0x{0:X8}' -f $raw }
        } catch { }
        # CIM cmdlets surface the WMI status code on the error record itself
        # when the exception HResult is a generic wrapper.
        if (-not $hresult) {
            try {
                $status = $ErrorRecord.Exception.StatusCode
                if ($null -ne $status) { $hresult = '0x{0:X8}' -f $status }
            } catch { }
        }
    }

    $known = $null
    if ($hresult -and $script:IdentifierErrorCauses.ContainsKey($hresult)) {
        $known = $script:IdentifierErrorCauses[$hresult]
    }

    if (-not $known) {
        # Some providers report the code only in the message text.
        foreach ($code in $script:IdentifierErrorCauses.Keys) {
            if ($message -match [regex]::Escape($code)) {
                $known = $script:IdentifierErrorCauses[$code]
                $hresult = $code
                break
            }
        }
    }

    return @{
        Message = $message
        HResult = $hresult
        Cause   = $(if ($known) { $known.Cause } else { 'WMI returned an error that is not in the known-cause table. Treat the raw message as the lead.' })
        Fix     = $(if ($known) { $known.Fix } else { 'Capture the raw message and HRESULT and escalate.' })
    }
}

# =============================================================================
# ENVIRONMENT
# =============================================================================

function Get-WinConfigIdentifierEnvironment {
    <#
    .SYNOPSIS
        Facts about the box that change how identifier failures are read.
    .DESCRIPTION
        Elevation, virtualization and WMI service health each explain a whole
        class of identifier failure, so they are collected once up front and
        referenced by every finding rather than re-derived per identifier.
    #>
    [CmdletBinding()]
    param()

    $context = @{
        ComputerName        = $env:COMPUTERNAME
        IsElevated          = $false
        OsArchitecture      = ''
        IsVirtualMachine    = $false
        VirtualizationHint  = ''
        WmiServiceStatus    = 'Unknown'
        WmiServiceStartType = 'Unknown'
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $context.IsElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $model = [string]$cs.Model
        $manufacturer = [string]$cs.Manufacturer
        $context.OsArchitecture = [string]$cs.SystemType
        $hint = "$manufacturer $model"
        if ($hint -match '(?i)virtual|vmware|hyper-v|kvm|qemu|xen|parallels|innotek|virtualbox') {
            $context.IsVirtualMachine = $true
            $context.VirtualizationHint = $hint.Trim()
        }
    } catch { }

    try {
        $svc = Get-Service -Name Winmgmt -ErrorAction Stop
        $context.WmiServiceStatus = [string]$svc.Status
        $context.WmiServiceStartType = [string]$svc.StartType
    } catch { }

    return $context
}

function Get-WinConfigWmiRepositoryState {
    <#
    .SYNOPSIS
        Reports whether the WMI repository is self-consistent.
    .DESCRIPTION
        Only meaningful when an identifier read has already failed, and only
        answerable when elevated - winmgmt /verifyrepository returns access
        denied (0x80041003) to a standard user, which must not be reported as
        repository damage.

        READ-ONLY: /verifyrepository inspects. /salvagerepository and
        /resetrepository mutate and are never invoked from this module.
    #>
    [CmdletBinding()]
    param([switch]$Elevated)

    if (-not $Elevated) {
        return @{ Status = 'NotChecked'; Detail = 'Repository verification requires elevation; WinConfig is not running elevated.' }
    }

    $exe = Join-Path $env:SystemRoot 'System32\wbem\WinMgmt.exe'
    if (-not (Test-Path $exe)) {
        return @{ Status = 'NotChecked'; Detail = "WinMgmt.exe not found at $exe" }
    }

    try {
        $output = & $exe /verifyrepository 2>&1
        $exit = $LASTEXITCODE
        $text = ($output | Out-String).Trim()
        if ($exit -eq 0) {
            return @{ Status = 'Consistent'; Detail = $text }
        }
        return @{ Status = 'Inconsistent'; Detail = $text }
    } catch {
        return @{ Status = 'NotChecked'; Detail = "Verification could not run: $($_.Exception.Message)" }
    }
}

# =============================================================================
# IDENTIFIER: MAC ADDRESSES
# =============================================================================

function Get-WinConfigMachineMacAddressInfo {
    <#
    .SYNOPSIS
        Enumerates every adapter that carries a MAC and marks the licensing set.
    .DESCRIPTION
        Returns ALL adapters, not just the licensing set. The excluded ones are
        what let a tech answer "why does licensing show three MACs when
        ipconfig shows nine" without guessing.

        Current MAC vs PermanentAddress comes from the NetAdapter provider
        (root\StandardCimv2). A difference means the address was overridden in
        the adapter's advanced properties or by registry NetworkAddress - the
        machine then presents a MAC the license was never issued against.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Status   = 'Ok'
        Values   = @()
        Adapters = @()
        Error    = $null
    }

    $adapters = $null
    try {
        $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop |
            Where-Object { $_.MACAddress } |
            Sort-Object Index)
    } catch {
        $result.Status = 'Error'
        $result.Error = Get-WinConfigCimFailureInfo -ErrorRecord $_
        return $result
    }

    # IP binding state decides whether an IPEnabled-filtered reader (a common
    # licensing implementation) sees anything at all on an offline machine.
    $configByIndex = @{}
    try {
        foreach ($cfg in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)) {
            $configByIndex[[string]$cfg.Index] = $cfg
        }
    } catch { }

    # PermanentAddress is only exposed by the NetAdapter provider.
    $netAdapterByMac = @{}
    try {
        foreach ($na in @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetAdapter -ErrorAction Stop)) {
            $key = ConvertTo-WinConfigIdentifierValue -Value ([string]$na.MacAddress)
            if ($key) { $netAdapterByMac[$key] = $na }
        }
    } catch { }

    $rows = New-Object System.Collections.Generic.List[hashtable]
    foreach ($adapter in $adapters) {
        $pnp = [string]$adapter.PNPDeviceID
        $bus = Get-WinConfigIdentifierBus -PnpDeviceId $pnp
        $isPhysical = [bool]$adapter.PhysicalAdapter
        $isRootEnumerated = $pnp -and $pnp.StartsWith('ROOT\', [System.StringComparison]::OrdinalIgnoreCase)

        $included = $isPhysical -and -not $isRootEnumerated
        $excludedReason = ''
        if (-not $included) {
            $excludedReason = if (-not $isPhysical) {
                'Not a physical adapter (Win32_NetworkAdapter.PhysicalAdapter = False)'
            } else {
                'Software-enumerated adapter (PNPDeviceID starts with ROOT\)'
            }
        }

        $current = Format-WinConfigMacAddress -Value ([string]$adapter.MACAddress)
        $permanent = ''
        $overridden = $false
        $na = $netAdapterByMac[(ConvertTo-WinConfigIdentifierValue -Value $current)]
        if ($na) {
            $permanent = Format-WinConfigMacAddress -Value ([string]$na.PermanentAddress)
            if ($permanent -and $permanent -ne $current) { $overridden = $true }
        }

        $cfg = $configByIndex[[string]$adapter.Index]

        $rows.Add(@{
            Index             = [int]$adapter.Index
            Name              = [string]$adapter.Name
            ConnectionName    = [string]$adapter.NetConnectionID
            Address           = $current
            PermanentAddress  = $permanent
            AddressOverridden = $overridden
            Bus               = $bus
            PnpDeviceId       = $pnp
            PhysicalAdapter   = $isPhysical
            Included          = $included
            ExcludedReason    = $excludedReason
            Enabled           = $(if ($null -ne $adapter.NetEnabled) { [bool]$adapter.NetEnabled } else { $null })
            Connected         = ([int]$adapter.NetConnectionStatus -eq 2)
            IpEnabled         = $(if ($cfg) { [bool]$cfg.IPEnabled } else { $false })
        })
    }

    $result.Adapters = @($rows)
    $result.Values = @($rows | Where-Object { $_.Included } | ForEach-Object { $_.Address })
    if ($result.Values.Count -eq 0) { $result.Status = 'Empty' }

    return $result
}

# =============================================================================
# IDENTIFIER: PROCESSOR ID
# =============================================================================

function Get-WinConfigMachineProcessorIdInfo {
    <#
    .SYNOPSIS
        Reads Win32_Processor.ProcessorId for the first socket.
    .DESCRIPTION
        ProcessorId is the CPUID feature/signature word, not a per-unit serial:
        every machine with the same CPU stepping reports the same value. That
        is expected behaviour and is surfaced as a note so nobody escalates a
        "duplicate identifier" that is working as designed.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Status      = 'Ok'
        Value       = ''
        RawValue    = ''
        Source      = 'Win32_Processor.ProcessorId'
        Name        = ''
        SocketCount = 0
        Error       = $null
    }

    try {
        $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Sort-Object DeviceID)
    } catch {
        $result.Status = 'Error'
        $result.Error = Get-WinConfigCimFailureInfo -ErrorRecord $_
        return $result
    }

    $result.SocketCount = $processors.Count
    if ($processors.Count -eq 0) {
        $result.Status = 'Empty'
        return $result
    }

    $first = $processors[0]
    $result.Name = [string]$first.Name
    $result.RawValue = [string]$first.ProcessorId
    $result.Value = ConvertTo-WinConfigIdentifierValue -Value $result.RawValue

    if (-not (Test-WinConfigIdentifierIsUsable -Value $result.Value)) {
        $result.Status = 'Empty'
    }

    return $result
}

# =============================================================================
# IDENTIFIER: DISK ID
# =============================================================================

function Get-WinConfigMachineDiskIdInfo {
    <#
    .SYNOPSIS
        Reads the physical disk serial the licensing app fingerprints.
    .DESCRIPTION
        Primary source is Win32_DiskDrive Index 0. Two fallbacks follow -
        Win32_PhysicalMedia, then MSFT_Disk (UniqueId/SerialNumber) - and the
        source that answered is reported. That is the diagnosis, not a detail:
        when the primary is blank and a fallback is populated, the storage
        stack knows the serial and only the class licensing reads is empty.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Status         = 'Ok'
        Value          = ''
        RawValue       = ''
        Source         = ''
        Model          = ''
        DiskIndex      = 0
        BootDiskIndex  = $null
        IsBootDisk     = $true
        InterfaceType  = ''
        FallbackUsed   = $false
        Error          = $null
    }

    $disk0 = $null
    try {
        $disk0 = Get-CimInstance -ClassName Win32_DiskDrive -Filter 'Index = 0' -ErrorAction Stop | Select-Object -First 1
    } catch {
        $result.Status = 'Error'
        $result.Error = Get-WinConfigCimFailureInfo -ErrorRecord $_
        return $result
    }

    if (-not $disk0) {
        $result.Status = 'Empty'
        $result.Error = @{
            Message = 'Win32_DiskDrive returned no disk at index 0'
            HResult = ''
            Cause   = 'The storage provider enumerated no physical disks. Seen with RAID/VMD controllers whose driver does not expose member disks, and on boxes where the storage WMI provider is unregistered.'
            Fix     = 'Confirm the disk appears under Disk Management, then check the storage controller driver.'
        }
        return $result
    }

    $result.Model = [string]$disk0.Model
    $result.InterfaceType = [string]$disk0.InterfaceType
    $result.RawValue = [string]$disk0.SerialNumber
    $result.Value = ConvertTo-WinConfigIdentifierValue -Value $result.RawValue
    $result.Source = 'Win32_DiskDrive.SerialNumber (Index 0)'

    if (-not (Test-WinConfigIdentifierIsUsable -Value $result.Value)) {
        # Fallback 1: Win32_PhysicalMedia keys off the same device path.
        try {
            $media = Get-CimInstance -ClassName Win32_PhysicalMedia -ErrorAction Stop |
                Where-Object { $_.Tag -eq '\\.\PHYSICALDRIVE0' } | Select-Object -First 1
            if ($media) {
                $candidate = ConvertTo-WinConfigIdentifierValue -Value ([string]$media.SerialNumber)
                if (Test-WinConfigIdentifierIsUsable -Value $candidate) {
                    $result.Value = $candidate
                    $result.RawValue = [string]$media.SerialNumber
                    $result.Source = 'Win32_PhysicalMedia.SerialNumber (fallback)'
                    $result.FallbackUsed = $true
                }
            }
        } catch { }
    }

    if (-not (Test-WinConfigIdentifierIsUsable -Value $result.Value)) {
        # Fallback 2: the modern storage stack. UniqueId carries the NVMe EUI
        # even on drives whose ATA serial never reaches Win32_DiskDrive.
        try {
            $msftDisk = Get-CimInstance -Namespace 'root/Microsoft/Windows/Storage' -ClassName MSFT_Disk -ErrorAction Stop |
                Where-Object { [int]$_.Number -eq 0 } | Select-Object -First 1
            if ($msftDisk) {
                foreach ($candidateRaw in @([string]$msftDisk.SerialNumber, [string]$msftDisk.UniqueId)) {
                    $candidate = ConvertTo-WinConfigIdentifierValue -Value $candidateRaw
                    if (Test-WinConfigIdentifierIsUsable -Value $candidate) {
                        $result.Value = $candidate
                        $result.RawValue = $candidateRaw
                        $result.Source = 'MSFT_Disk (fallback)'
                        $result.FallbackUsed = $true
                        break
                    }
                }
            }
        } catch { }
    }

    if (-not (Test-WinConfigIdentifierIsUsable -Value $result.Value)) {
        $result.Status = 'Empty'
    }

    # Disk 0 is not guaranteed to be the OS disk. When it is not, licensing is
    # fingerprinting a drive the operator can remove without noticing.
    try {
        $systemDrive = $env:SystemDrive
        $logical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -ErrorAction Stop | Select-Object -First 1
        if ($logical) {
            $partition = Get-CimAssociatedInstance -InputObject $logical -ResultClassName Win32_DiskPartition -ErrorAction Stop | Select-Object -First 1
            if ($partition) {
                $bootDrive = Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_DiskDrive -ErrorAction Stop | Select-Object -First 1
                if ($bootDrive) {
                    $result.BootDiskIndex = [int]$bootDrive.Index
                    $result.IsBootDisk = ([int]$bootDrive.Index -eq 0)
                }
            }
        }
    } catch { }

    return $result
}

# =============================================================================
# FINDINGS - the "why" layer
# =============================================================================

function Get-WinConfigMachineIdentifierFindings {
    <#
    .SYNOPSIS
        Derives named causes from the collected identifier facts.
    .DESCRIPTION
        Every finding states what is wrong, what caused it, and what to do.
        Findings are additive: a machine can be fine today and still get an
        Info finding warning that its licensed MAC lives on a USB dock.
    .OUTPUTS
        Array of hashtables: Identifier, Severity (Fail|Warn|Info), Title,
        Cause, Fix.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Mac,
        [hashtable]$Processor,
        [hashtable]$Disk,
        [hashtable]$Environment,
        [hashtable]$Repository
    )

    $findings = New-Object System.Collections.Generic.List[hashtable]

    $wmiBroken = ($Environment.WmiServiceStatus -and $Environment.WmiServiceStatus -ne 'Running')
    $repoBad = ($Repository -and $Repository.Status -eq 'Inconsistent')

    # --- Shared root causes, reported once rather than per identifier --------
    if ($wmiBroken) {
        $findings.Add(@{
            Identifier = 'All'
            Severity   = 'Fail'
            Title      = "Windows Management Instrumentation service is $($Environment.WmiServiceStatus)"
            Cause      = 'Every machine identifier is read through WMI. With the Winmgmt service down, the licensing app gets nothing back for all three values at once.'
            Fix        = 'Start the Winmgmt service (it is Automatic by default) and re-run the licensing app.'
        })
    }
    if ($repoBad) {
        $findings.Add(@{
            Identifier = 'All'
            Severity   = 'Fail'
            Title      = 'WMI repository reports as inconsistent'
            Cause      = "winmgmt /verifyrepository failed: $($Repository.Detail)"
            Fix        = 'Escalate before repairing. Repository salvage/reset is a mutating operation and is deliberately not offered by WinConfig.'
        })
    }

    # --- MAC addresses ------------------------------------------------------
    if ($Mac.Status -eq 'Error') {
        $findings.Add(@{
            Identifier = 'MAC Addresses'
            Severity   = 'Fail'
            Title      = 'Adapter enumeration failed'
            Cause      = "$($Mac.Error.Cause) (WMI said: $($Mac.Error.Message))"
            Fix        = $Mac.Error.Fix
        })
    }
    elseif ($Mac.Status -eq 'Empty') {
        $withMac = @($Mac.Adapters).Count
        $cause = if ($withMac -eq 0) {
            'No network adapter of any kind reports a MAC address. The licensing app has nothing to read.'
        } else {
            "Windows sees $withMac adapter(s) with a MAC, but every one of them is virtual or software-enumerated (VMware, Hyper-V, Wi-Fi Direct, WAN miniport). The licensing app only counts physical adapters, so its list comes back empty."
        }
        $findings.Add(@{
            Identifier = 'MAC Addresses'
            Severity   = 'Fail'
            Title      = 'No MAC address qualifies for licensing'
            Cause      = $cause
            Fix        = 'Re-enable or reinstall the physical network adapter (Device Manager > Network adapters > Show hidden devices). A laptop with only a USB NIC needs that NIC plugged in.'
        })
    }
    else {
        foreach ($adapter in @($Mac.Adapters | Where-Object { $_.Included })) {
            if ($adapter.AddressOverridden) {
                $findings.Add(@{
                    Identifier = 'MAC Addresses'
                    Severity   = 'Warn'
                    Title      = "MAC address overridden on $(if ($adapter.ConnectionName) { $adapter.ConnectionName } else { $adapter.Name })"
                    Cause      = "The adapter reports $($adapter.Address) but its burned-in address is $($adapter.PermanentAddress). Something set a NetworkAddress override (adapter advanced properties, a dock with MAC pass-through, or imaging software). A license issued against the permanent address will not match."
                    Fix        = "Clear 'Network Address'/'Locally Administered Address' in the adapter's Advanced properties, reboot, and confirm the value returns to $($adapter.PermanentAddress)."
                })
            }
            if ($adapter.Bus -eq 'USB') {
                $findings.Add(@{
                    Identifier = 'MAC Addresses'
                    Severity   = 'Info'
                    Title      = "Licensed MAC $($adapter.Address) belongs to a USB adapter"
                    Cause      = "$($adapter.Name) is enumerated over USB, so this identifier disappears the moment the dongle or dock is unplugged. Identifier sets that change between activation and validation are a common cause of licence mismatch on docked laptops."
                    Fix        = 'Activate and validate with the same dock/dongle attached, or prefer the built-in adapter.'
                })
            }
            if ($adapter.Bus -eq 'Bluetooth') {
                $findings.Add(@{
                    Identifier = 'MAC Addresses'
                    Severity   = 'Info'
                    Title      = "Licensed MAC $($adapter.Address) belongs to the Bluetooth PAN adapter"
                    Cause      = 'This entry exists only while the Bluetooth Personal Area Network adapter is installed. Disabling the Bluetooth radio, uninstalling the BT driver, or a full Bluetooth stack reset removes it and shrinks the identifier set.'
                    Fix        = 'Expect this value to vanish after Bluetooth repair work. Re-check licensing after any Bluetooth stack reset.'
                })
            }
        }

        $ipEnabledCount = @($Mac.Adapters | Where-Object { $_.Included -and $_.IpEnabled }).Count
        if ($ipEnabledCount -eq 0) {
            $findings.Add(@{
                Identifier = 'MAC Addresses'
                Severity   = 'Warn'
                Title      = 'No licensed adapter currently has IP bound'
                Cause      = 'Every physical adapter is disconnected or unbound. Readers that filter on IPEnabled - a common licensing implementation - return an empty MAC list in this state even though the adapters exist, which is why the failure looks intermittent and tracks connectivity.'
                Fix        = 'Connect the machine to a network (or plug in the Ethernet cable) and retry the licensing operation.'
            })
        }
    }

    # --- ProcessorID --------------------------------------------------------
    if ($Processor.Status -eq 'Error') {
        $findings.Add(@{
            Identifier = 'ProcessorID'
            Severity   = 'Fail'
            Title      = 'Processor query failed'
            Cause      = "$($Processor.Error.Cause) (WMI said: $($Processor.Error.Message))"
            Fix        = $Processor.Error.Fix
        })
    }
    elseif ($Processor.Status -eq 'Empty') {
        $cause = if ($Environment.OsArchitecture -match '(?i)arm') {
            'Windows on ARM does not populate Win32_Processor.ProcessorId - there is no x86 CPUID word to report. The value is permanently blank on this hardware, not broken.'
        } elseif ($Environment.IsVirtualMachine) {
            "This is a virtual machine ($($Environment.VirtualizationHint)). Several hypervisors leave ProcessorId blank or hand the same value to every guest."
        } else {
            'Win32_Processor answered but ProcessorId came back blank. That points at the CIM provider rather than the CPU - the class is registered but returning no data.'
        }
        $findings.Add(@{
            Identifier = 'ProcessorID'
            Severity   = 'Fail'
            Title      = 'ProcessorID is empty'
            Cause      = $cause
            Fix        = 'Confirm with: Get-CimInstance Win32_Processor | Select-Object ProcessorId. If that is blank too, the value is unavailable on this machine and licensing must key off the remaining identifiers.'
        })
    }
    else {
        if ($Processor.SocketCount -gt 1) {
            $findings.Add(@{
                Identifier = 'ProcessorID'
                Severity   = 'Info'
                Title      = "$($Processor.SocketCount) processor sockets present"
                Cause      = 'The displayed value is socket 0. A reader that does not sort sockets can pick a different one between runs, producing an identifier that appears to change on its own.'
                Fix        = 'Note the multi-socket configuration if licensing reports a changed ProcessorID.'
            })
        }
        $findings.Add(@{
            Identifier = 'ProcessorID'
            Severity   = 'Info'
            Title      = 'ProcessorID is a CPU model signature, not a serial number'
            Cause      = "$($Processor.Value) is the CPUID feature word plus family/model/stepping. Every machine carrying the same CPU stepping reports exactly this value - identical ProcessorIDs across two identical laptops are expected."
            Fix        = 'Do not escalate duplicate ProcessorIDs on identical hardware. Machine uniqueness comes from the MAC and disk identifiers.'
        })
    }

    # --- DiskID -------------------------------------------------------------
    if ($Disk.Status -eq 'Error') {
        $findings.Add(@{
            Identifier = 'DiskID'
            Severity   = 'Fail'
            Title      = 'Disk query failed'
            Cause      = "$($Disk.Error.Cause) (WMI said: $($Disk.Error.Message))"
            Fix        = $Disk.Error.Fix
        })
    }
    elseif ($Disk.Status -eq 'Empty') {
        $cause = if ($Disk.Error) {
            $Disk.Error.Cause
        } elseif ($Environment.IsVirtualMachine) {
            "Virtual disks routinely report no serial number ($($Environment.VirtualizationHint)). There is no physical medium to read one from."
        } else {
            "The storage driver for $($Disk.Model) does not pass a serial number up to WMI. Seen with RAID/Intel VMD controllers, USB-bridged drives, and some NVMe drivers - the drive works normally, but the identifier layer is blank."
        }
        $findings.Add(@{
            Identifier = 'DiskID'
            Severity   = 'Fail'
            Title      = 'DiskID is empty'
            Cause      = $cause
            Fix        = 'Check whether the controller is in RAID/VMD mode in firmware; AHCI exposes serials that VMD hides. Confirm with: Get-Disk | Select-Object Number, SerialNumber, UniqueId.'
        })
    }
    else {
        if ($Disk.FallbackUsed) {
            $findings.Add(@{
                Identifier = 'DiskID'
                Severity   = 'Warn'
                Title      = 'DiskID came from a fallback source'
                Cause      = "Win32_DiskDrive.SerialNumber - the class licensing reads - was blank, and the value shown came from $($Disk.Source) instead. The serial exists in the storage stack but is not reaching the class the licensing app queries."
                Fix        = 'Expect the licensing app to report a missing DiskID even though this tool shows one. Update the storage controller driver, then re-check Win32_DiskDrive directly.'
            })
        }
        if (-not $Disk.IsBootDisk) {
            $findings.Add(@{
                Identifier = 'DiskID'
                Severity   = 'Warn'
                Title      = "Disk 0 is not the Windows disk (Windows is on disk $($Disk.BootDiskIndex))"
                Cause      = "Licensing fingerprints physical disk 0, which on this machine is $($Disk.Model) - not the drive Windows boots from. Removing or reordering that drive changes the identifier without touching Windows."
                Fix        = 'Record which drive holds the licensed identifier before any disk swap, and keep the disk order stable.'
            })
        }
    }

    # --- Cross-cutting context ---------------------------------------------
    if ($Environment.IsVirtualMachine -and $Mac.Status -eq 'Ok') {
        $findings.Add(@{
            Identifier = 'All'
            Severity   = 'Info'
            Title      = "Virtual machine detected ($($Environment.VirtualizationHint))"
            Cause      = 'Cloned VMs inherit disk and processor identifiers from their template, and MAC addresses are assigned by the hypervisor. Two guests can present the same fingerprint.'
            Fix        = 'Treat identifier collisions between VMs as a cloning artefact, not a licensing defect.'
        })
    }

    return @($findings)
}

# =============================================================================
# ORCHESTRATOR
# =============================================================================

function Get-WinConfigMachineIdentifiers {
    <#
    .SYNOPSIS
        Collects the machine identifiers the licensing app displays, with causes.
    .DESCRIPTION
        Read-only. Returns the three identifier groups, the full adapter list
        behind the MAC group, environment context, and a findings array naming
        the cause of anything missing or fragile.

        The WMI repository check is skipped unless something actually failed -
        it costs a second and tells you nothing when the reads all succeeded.
    .OUTPUTS
        Hashtable: CollectedAt, MacAddresses, ProcessorId, DiskId, Environment,
        Repository, Findings.
    .EXAMPLE
        $ids = Get-WinConfigMachineIdentifiers
        $ids.MacAddresses.Values
        $ids.DiskId.Value
    #>
    [CmdletBinding()]
    param()

    $environment = Get-WinConfigIdentifierEnvironment
    $mac = Get-WinConfigMachineMacAddressInfo
    $processor = Get-WinConfigMachineProcessorIdInfo
    $disk = Get-WinConfigMachineDiskIdInfo

    $anyFailure = @(@($mac.Status, $processor.Status, $disk.Status) | Where-Object { $_ -ne 'Ok' })
    $isElevated = [bool]$environment.IsElevated
    $repository = if ($anyFailure.Count -gt 0) {
        Get-WinConfigWmiRepositoryState -Elevated:$isElevated
    } else {
        @{ Status = 'NotChecked'; Detail = 'All identifiers read successfully; repository verification not needed.' }
    }

    $findings = Get-WinConfigMachineIdentifierFindings `
        -Mac $mac -Processor $processor -Disk $disk `
        -Environment $environment -Repository $repository

    return @{
        CollectedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        MacAddresses = $mac
        ProcessorId  = $processor
        DiskId       = $disk
        Environment  = $environment
        Repository   = $repository
        Findings     = @($findings)
    }
}

function Format-WinConfigMachineIdentifierReport {
    <#
    .SYNOPSIS
        Renders collected identifiers as plain text for the clipboard/ticket.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Identifiers)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Machine Identifiers - $($Identifiers.Environment.ComputerName) - $($Identifiers.CollectedAt)")
    $lines.Add('')

    $lines.Add('MAC Addresses')
    if (@($Identifiers.MacAddresses.Values).Count -gt 0) {
        foreach ($adapter in @($Identifiers.MacAddresses.Adapters | Where-Object { $_.Included })) {
            $label = if ($adapter.ConnectionName) { $adapter.ConnectionName } else { $adapter.Name }
            $lines.Add("  $($adapter.Address)   $label [$($adapter.Bus)]")
        }
    } else {
        $lines.Add('  (none)')
    }
    $lines.Add('')

    $procValue = if ($Identifiers.ProcessorId.Value) { $Identifiers.ProcessorId.Value } else { '(empty)' }
    $diskValue = if ($Identifiers.DiskId.Value) { $Identifiers.DiskId.Value } else { '(empty)' }
    $lines.Add("ProcessorID  $procValue")
    $lines.Add("DiskID       $diskValue")
    $lines.Add('')

    $lines.Add("Elevated: $($Identifiers.Environment.IsElevated)   WMI service: $($Identifiers.Environment.WmiServiceStatus)")
    if ($Identifiers.Repository.Status -ne 'NotChecked') {
        $lines.Add("WMI repository: $($Identifiers.Repository.Status)")
    }

    $findings = @($Identifiers.Findings)
    if ($findings.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Findings')
        foreach ($finding in $findings) {
            $lines.Add("  [$($finding.Severity.ToUpperInvariant())] $($finding.Identifier): $($finding.Title)")
            $lines.Add("      Cause: $($finding.Cause)")
            $lines.Add("      Fix:   $($finding.Fix)")
        }
    }

    # Excluded adapters are the answer to "why doesn't this match ipconfig",
    # so they ship with the report rather than living only on screen.
    $excluded = @($Identifiers.MacAddresses.Adapters | Where-Object { -not $_.Included })
    if ($excluded.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Adapters excluded from the licensing view')
        foreach ($adapter in $excluded) {
            $lines.Add("  $($adapter.Address)   $($adapter.Name) - $($adapter.ExcludedReason)")
        }
    }

    return ($lines -join "`r`n")
}

Export-ModuleMember -Function @(
    'ConvertTo-WinConfigIdentifierValue'
    'Test-WinConfigIdentifierIsUsable'
    'Format-WinConfigMacAddress'
    'Get-WinConfigIdentifierBus'
    'Get-WinConfigCimFailureInfo'
    'Get-WinConfigIdentifierEnvironment'
    'Get-WinConfigWmiRepositoryState'
    'Get-WinConfigMachineMacAddressInfo'
    'Get-WinConfigMachineProcessorIdInfo'
    'Get-WinConfigMachineDiskIdInfo'
    'Get-WinConfigMachineIdentifierFindings'
    'Get-WinConfigMachineIdentifiers'
    'Format-WinConfigMachineIdentifierReport'
)

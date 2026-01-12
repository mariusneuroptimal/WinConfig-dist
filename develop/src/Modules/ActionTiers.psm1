# ActionTiers.psm1
# Context-Aware Action Contract Implementation
# Provides tiered, evidence-based recommendations following the lowest-cost-first principle

<#
.SYNOPSIS
    Action Tier Model for context-aware recommendations.

.DESCRIPTION
    Implements the Context-Aware Action Contract which ensures:
    - Lowest-cost action is always recommended first
    - Escalation is never the default
    - All recommendations are evidence-driven

    Tier Model:
    0 - No Action Required     : System is operational
    1 - Local User Action      : Restart, retry, toggle, re-run
    2 - Alternate Context      : Different network, user, device
    3 - Guided Technical Step  : Flush cache, rerun test, reapply config
    4 - Local IT/Admin         : Managed network / permissions required
    5 - External Escalation    : ISP/Vendor - only when evidence supports
#>

# Action Tier Definitions
$script:ActionTiers = @{
    0 = @{Label = "No Action Required"; Description = "System is operational"}
    1 = @{Label = "Local User Action"; Description = "Restart, retry, toggle, re-run"}
    2 = @{Label = "Alternate Context"; Description = "Different network, user, device"}
    3 = @{Label = "Guided Technical Step"; Description = "Flush cache, rerun test, reapply config"}
    4 = @{Label = "Local IT/Admin Escalation"; Description = "Managed network / permissions required"}
    5 = @{Label = "External Escalation"; Description = "ISP/Vendor - only when evidence supports"}
}

function Resolve-ContextAwareActions {
    <#
    .SYNOPSIS
        Generates context-aware, tiered recommendations based on test evidence.

    .DESCRIPTION
        Analyzes test results and returns the minimum valid action tier with
        ordered recommendations. Escalation is never recommended without evidence.

    .PARAMETER Category
        The category of operation: Diagnostics, Configuration, AdminChange, Maintenance

    .PARAMETER Result
        The test result: PASS, WARN, FAIL

    .PARAMETER Evidence
        A hashtable containing structured evidence from tests.
        For Network tests: @{DNS=$true; Ports=$true; Time=$true; TLSIntercepted=$false}

    .PARAMETER Context
        Optional context hints: @{IsManagedNetwork=$false; HasInternetAccess=$true}

    .OUTPUTS
        Returns a hashtable with:
        - Classification: Human-readable status label
        - Status: PASS/WARN/FAIL
        - MinimumTier: The lowest valid action tier (0-5)
        - Recommendations: Ordered array of recommendation strings
        - OperationalImpact: Blocking, NonBlocking, Informational

    .EXAMPLE
        $evidence = @{DNS=$true; Ports=$true; Time=$true; TLSIntercepted=$false}
        $result = Resolve-ContextAwareActions -Category "Diagnostics" -Result "PASS" -Evidence $evidence

    .NOTES
        Canonical Principle: Always recommend the lowest-cost, lowest-authority
        next action that is consistent with observed evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Diagnostics", "Configuration", "AdminChange", "Maintenance")]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "WARN", "FAIL", "INSUFFICIENT_SIGNAL")]
        [string]$Result,

        [Parameter(Mandatory = $true)]
        [hashtable]$Evidence,

        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )

    # Initialize response structure
    $response = @{
        Classification    = ""
        Status            = $Result
        MinimumTier       = 0
        Recommendations   = @()
        OperationalImpact = "Informational"
    }

    # Route to category-specific resolver
    switch ($Category) {
        "Diagnostics" {
            $response = Resolve-DiagnosticsActions -Result $Result -Evidence $Evidence -Context $Context
        }
        "Configuration" {
            $response = Resolve-ConfigurationActions -Result $Result -Evidence $Evidence -Context $Context
        }
        "AdminChange" {
            $response = Resolve-AdminChangeActions -Result $Result -Evidence $Evidence -Context $Context
        }
        "Maintenance" {
            $response = Resolve-MaintenanceActions -Result $Result -Evidence $Evidence -Context $Context
        }
    }

    return $response
}

function Resolve-DiagnosticsActions {
    <#
    .SYNOPSIS
        Resolves actions for Diagnostics category (Network Tests).
    #>
    [CmdletBinding()]
    param(
        [string]$Result,
        [hashtable]$Evidence,
        [hashtable]$Context
    )

    $response = @{
        Classification    = ""
        Status            = $Result
        MinimumTier       = 0
        Recommendations   = @()
        OperationalImpact = "Informational"
    }

    # Extract evidence with defaults
    $dnsOK = if ($Evidence.ContainsKey('DNS')) { $Evidence.DNS } else { $true }
    $portsOK = if ($Evidence.ContainsKey('Ports')) { $Evidence.Ports } else { $true }
    $timeOK = if ($Evidence.ContainsKey('Time')) { $Evidence.Time } else { $true }
    $tlsIntercepted = if ($Evidence.ContainsKey('TLSIntercepted')) { $Evidence.TLSIntercepted } else { $false }
    $isManagedNetwork = if ($Context.ContainsKey('IsManagedNetwork')) { $Context.IsManagedNetwork } else { $false }

    # Handle INSUFFICIENT_SIGNAL before evidence checks (evidence may be incomplete)
    if ($Result -eq "INSUFFICIENT_SIGNAL") {
        $response.Classification = "Undetermined - Retest Recommended"
        $response.Status = "INSUFFICIENT_SIGNAL"
        $response.MinimumTier = 1
        $response.OperationalImpact = "Informational"
        $response.Recommendations = @(
            "Wait a moment and run the test again",
            "The test did not gather enough evidence to make a determination",
            "If retests consistently show this result, check network stability"
        )
        return $response
    }

    # Decision matrix - determines classification and minimum tier
    if ($dnsOK -and $portsOK -and $timeOK) {
        if ($tlsIntercepted) {
            $response.Classification = "Operational - SSL Inspection Detected"
            $response.Status = "WARN"
            $response.MinimumTier = 0
            $response.OperationalImpact = "NonBlocking"
            $response.Recommendations = @(
                "No action required - NeurOptimal should function normally",
                "SSL inspection detected but does not block operation",
                "If connection issues occur, try a mobile hotspot to bypass proxy",
                "Escalate only if NeurOptimal reports persistent connectivity errors"
            )
        }
        else {
            $response.Classification = "Fully Operational"
            $response.Status = "PASS"
            $response.MinimumTier = 0
            $response.OperationalImpact = "Informational"
            $response.Recommendations = @(
                "No action required - NeurOptimal should function normally",
                "All connectivity tests passed successfully",
                "Escalate only if NeurOptimal reports connectivity errors despite this result"
            )
        }
    }
    elseif ($dnsOK -and $portsOK -and -not $timeOK) {
        $response.Classification = "Time Sync Required"
        $response.Status = "FAIL"
        $response.MinimumTier = 1
        $response.OperationalImpact = "Blocking"
        $response.Recommendations = @(
            "Sync system clock: Settings > Time & Language > Date & time > Sync now",
            "If sync fails, check internet connection and retry",
            "Incorrect system time breaks TLS certificates and licensing",
            "No escalation needed - this is a local fix"
        )
    }
    elseif (-not $dnsOK -and $portsOK) {
        $response.Classification = "DNS Issue Detected"
        $response.Status = "WARN"
        $response.MinimumTier = 1
        $response.OperationalImpact = "NonBlocking"
        $response.Recommendations = @(
            "Restart modem/router if you have access to it",
            "Check for captive portal: open a browser and see if a login page appears",
            "Try a different network (mobile hotspot) to test if DNS works elsewhere",
            "Run: ipconfig /flushdns in Command Prompt (Start > type 'cmd' > Enter)"
        )
        # Add conditional escalation only if lower tiers are exhausted
        if ($isManagedNetwork) {
            $response.Recommendations += "If above steps fail on a managed network: provide these results to IT"
        }
    }
    elseif (-not $portsOK) {
        # Ports blocked - requires careful tier assessment
        $response.Classification = "Required Ports Blocked"
        $response.Status = "FAIL"
        $response.OperationalImpact = "Blocking"

        # Start with lowest tier actions
        $recommendations = @(
            "Try a different network (mobile hotspot) to verify if ports are blocked locally",
            "Restart modem/router if you have access - some routers block unusual ports by default"
        )

        # Only after Tier 1-2 actions are listed, mention potential escalation
        if ($isManagedNetwork) {
            $response.MinimumTier = 2
            $recommendations += "If mobile hotspot works: the managed network is blocking ports 7000-7002"
            $recommendations += "Provide these test results to IT - they need to allow outbound ports 7000-7002 to blt-server.neuroptimal.com"
        }
        else {
            $response.MinimumTier = 2
            $recommendations += "If a different network works: check router settings for port blocking or contact your ISP only after confirming the issue persists"
            $recommendations += "Required ports: 7000, 7001, 7002 (BLT Server) and 443 (Updates)"
        }

        $response.Recommendations = $recommendations
    }
    else {
        # Multiple issues
        $response.Classification = "Multiple Connectivity Issues"
        $response.Status = "FAIL"
        $response.MinimumTier = 1
        $response.OperationalImpact = "Blocking"
        $response.Recommendations = @(
            "Restart modem/router if you have access to it",
            "Verify basic internet access: open a browser and try to reach google.com",
            "Try a different network (mobile hotspot) to isolate the issue",
            "If basic internet works but tests fail: check for VPN or proxy interference"
        )
        if ($isManagedNetwork) {
            $response.Recommendations += "If issue persists across networks: provide these results for further review"
        }
    }

    return $response
}

function Resolve-ConfigurationActions {
    <#
    .SYNOPSIS
        Resolves actions for Configuration category.
    #>
    [CmdletBinding()]
    param(
        [string]$Result,
        [hashtable]$Evidence,
        [hashtable]$Context
    )

    # Placeholder for Configuration category - extend as needed
    return @{
        Classification    = "Configuration"
        Status            = $Result
        MinimumTier       = 0
        Recommendations   = @("Configuration action completed")
        OperationalImpact = "Informational"
    }
}

function Resolve-AdminChangeActions {
    <#
    .SYNOPSIS
        Resolves actions for AdminChange category.
    #>
    [CmdletBinding()]
    param(
        [string]$Result,
        [hashtable]$Evidence,
        [hashtable]$Context
    )

    # Placeholder for AdminChange category - extend as needed
    return @{
        Classification    = "AdminChange"
        Status            = $Result
        MinimumTier       = 0
        Recommendations   = @("Administrative change completed")
        OperationalImpact = "Informational"
    }
}

function Resolve-MaintenanceActions {
    <#
    .SYNOPSIS
        Resolves actions for Maintenance category.
    #>
    [CmdletBinding()]
    param(
        [string]$Result,
        [hashtable]$Evidence,
        [hashtable]$Context
    )

    # Placeholder for Maintenance category - extend as needed
    return @{
        Classification    = "Maintenance"
        Status            = $Result
        MinimumTier       = 0
        Recommendations   = @("Maintenance action completed")
        OperationalImpact = "Informational"
    }
}

function Get-ActionTierLabel {
    <#
    .SYNOPSIS
        Returns the human-readable label for an action tier.

    .PARAMETER Tier
        The tier number (0-5)

    .OUTPUTS
        String label for the tier
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 5)]
        [int]$Tier
    )

    return $script:ActionTiers[$Tier].Label
}

function Format-RecommendationsForDisplay {
    <#
    .SYNOPSIS
        Formats recommendations for display in the UI.

    .PARAMETER Recommendations
        Array of recommendation strings

    .PARAMETER BulletStyle
        The bullet character to use (default: "*")

    .OUTPUTS
        Formatted string with bulleted recommendations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Recommendations,

        [Parameter(Mandatory = $false)]
        [string]$BulletStyle = "*"
    )

    $formatted = @()
    foreach ($rec in $Recommendations) {
        $formatted += "$BulletStyle $rec"
    }
    return $formatted -join "`r`n"
}

# Export module members
Export-ModuleMember -Function @(
    'Resolve-ContextAwareActions',
    'Get-ActionTierLabel',
    'Format-RecommendationsForDisplay'
)

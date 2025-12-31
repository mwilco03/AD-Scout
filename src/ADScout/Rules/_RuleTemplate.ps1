<#
.SYNOPSIS
    [Brief description of what this rule checks]

.DESCRIPTION
    [Detailed description including security implications]

.NOTES
    Rule ID    : [CATEGORY]-[Name]
    Category   : [Anomalies|StaleObjects|PrivilegedAccounts|Trusts]
    Author     : [Your Name]
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "X-RuleName"
    Name        = "Human Readable Rule Name"
    Category    = "Category"              # Anomalies | StaleObjects | PrivilegedAccounts | Trusts
    Model       = "SubCategory"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"           # TriggerOnPresence | PerDiscover | TriggerOnThreshold | TriggerIfLessThan
    Points      = 1                        # Points per finding (or total for TriggerOnPresence)
    MaxPoints   = 100                      # Cap for cumulative scoring
    Threshold   = $null                    # For threshold-based rules

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @()                      # e.g., @("T1078.002", "T1558.003")
    CIS         = @()                      # e.g., @("5.1.2")
    STIG        = @()                      # e.g., @("V-8527")
    ANSSI       = @()                      # e.g., @("R36")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Return objects that violate this rule
        # These become the finding details
        $ADData.Users | Where-Object {
            # Your condition here
            $false
        } | Select-Object SamAccountName, DistinguishedName
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName")
    DetailFormat     = "{SamAccountName}"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.SamAccountName)
# Add remediation commands here

"@
    }

    # === DOCUMENTATION ===
    Description = "Brief description for reports."

    TechnicalExplanation = @"
Detailed technical explanation of:
- Why this is a security issue
- How attackers exploit this
- What the impact could be
"@

    References = @(
        # "https://example.com/reference1"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $true  # Return $false to skip this rule
    }

    AppliesTo = @("OnPremises", "Hybrid")  # OnPremises | Hybrid | CloudOnly
}

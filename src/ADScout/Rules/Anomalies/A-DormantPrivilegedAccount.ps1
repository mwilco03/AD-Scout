<#
.SYNOPSIS
    Detects privileged accounts with no recent logon activity.

.DESCRIPTION
    Identifies accounts with AdminCount=1 (indicating privileged group
    membership, current or historical) that have not logged in recently.
    These dormant privileged accounts represent high-value targets for
    attackers and should be disabled or removed.

.NOTES
    Rule ID    : A-DormantPrivilegedAccount
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.0.0

    Uses AdminCount attribute and LastLogonTimestamp for detection.
    LastLogonTimestamp has ~14 day replication lag but is reliable for
    detecting long-term inactivity.
#>

@{
    # === IDENTITY ===
    Id          = "A-DormantPrivilegedAccount"
    Name        = "Dormant Privileged Account"
    Category    = "Anomalies"
    Model       = "FrequencyAnalysis"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 8
    MaxPoints   = 80
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002", "T1078.001")  # Valid Accounts: Domain, Default
    CIS         = @("5.4.1")  # Ensure inactive accounts are disabled
    STIG        = @()
    ANSSI       = @("R36")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Configuration
        $inactiveDays = 90  # Days without logon to be considered dormant
        $thresholdDate = (Get-Date).AddDays(-$inactiveDays)

        # Find privileged accounts (AdminCount = 1)
        $privilegedUsers = @($ADData.Users | Where-Object {
            $_.AdminCount -eq 1 -and $_.Enabled -eq $true
        })

        if ($privilegedUsers.Count -eq 0) {
            Write-Verbose "No privileged accounts found (AdminCount=1)"
            return @()
        }

        # Find dormant privileged accounts
        $privilegedUsers | Where-Object {
            # No logon ever, or last logon before threshold
            -not $_.LastLogonDate -or $_.LastLogonDate -lt $thresholdDate
        } | ForEach-Object {
            $daysSinceLogon = if ($_.LastLogonDate) {
                [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays, 0)
            } else {
                "Never"
            }

            # Calculate severity based on dormancy period
            $severity = if ($daysSinceLogon -eq "Never") {
                'Critical'
            } elseif ($daysSinceLogon -gt 180) {
                'Critical'
            } elseif ($daysSinceLogon -gt 120) {
                'High'
            } else {
                'Medium'
            }

            [PSCustomObject]@{
                SamAccountName     = $_.SamAccountName
                DistinguishedName  = $_.DistinguishedName
                DisplayName        = $_.DisplayName
                LastLogonDate      = $_.LastLogonDate
                DaysSinceLogon     = $daysSinceLogon
                AdminCount         = $_.AdminCount
                WhenCreated        = $_.WhenCreated
                PasswordLastSet    = $_.PasswordLastSet
                Severity           = $severity
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DaysSinceLogon", "LastLogonDate", "Severity")
    DetailFormat     = "{SamAccountName}: Last logon {DaysSinceLogon} days ago [{Severity}]"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Dormant privileged account: $($Finding.SamAccountName)
# Last logon: $($Finding.LastLogonDate) ($($Finding.DaysSinceLogon) days ago)
# AdminCount: $($Finding.AdminCount) (indicates privileged group membership)

# STEP 1: Verify the account is still needed
# Check with account owner or manager

# STEP 2: If no longer needed, disable the account:
Disable-ADAccount -Identity '$($Finding.SamAccountName)'

# STEP 3: If needed but dormant, investigate why:
# - Is this a service account that should use a different credential type?
# - Is this a break-glass account that should be monitored?
# - Has the user left the organization?

# STEP 4: Consider removing from privileged groups if account must remain:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf

"@
    }

    # === DOCUMENTATION ===
    Description = "Privileged accounts (AdminCount=1) with no logon activity in the last 90 days."

    TechnicalExplanation = @"
This rule identifies accounts that have (or had) privileged group membership
but show no recent logon activity. The AdminCount attribute is set to 1
when an account is added to a protected group (Domain Admins, etc.) and
remains set even after removal from those groups.

Why dormant privileged accounts are dangerous:
- Attack surface: Unused accounts are less likely to be monitored
- Credential theft: Old passwords may be weaker or compromised
- No active owner: No one notices if the account is misused
- Compliance risk: Violates least privilege and access review requirements

Detection criteria:
- AdminCount = 1 (privileged, current or historical)
- Enabled = true (disabled accounts are expected to be dormant)
- LastLogonTimestamp > 90 days ago or null

Note: LastLogonTimestamp has ~14 day replication lag, so accounts logging
in within the last 2 weeks may not reflect immediately.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1078/002/"
        "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
        "https://adsecurity.org/?p=3658"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

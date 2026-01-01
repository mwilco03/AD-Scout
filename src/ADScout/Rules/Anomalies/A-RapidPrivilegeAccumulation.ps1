<#
.SYNOPSIS
    Detects new accounts with above-average group memberships.

.DESCRIPTION
    Identifies accounts created recently (within threshold) that already
    have more group memberships than the environment average. This can indicate:
    - Cloned accounts from highly privileged templates
    - Rapid privilege escalation after account creation
    - Compromised account creation process
    - Improper provisioning procedures

.NOTES
    Rule ID    : A-RapidPrivilegeAccumulation
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.0.0

    Detection combines account age with group membership statistics.
#>

@{
    # === IDENTITY ===
    Id          = "A-RapidPrivilegeAccumulation"
    Name        = "Rapid Privilege Accumulation"
    Category    = "Anomalies"
    Model       = "FrequencyAnalysis"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 5
    MaxPoints   = 50
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1136.002", "T1098")  # Create Account: Domain, Account Manipulation
    CIS         = @()
    STIG        = @()
    ANSSI       = @()

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Configuration
        $newAccountDays = 30  # Accounts created within last N days
        $thresholdDate = (Get-Date).AddDays(-$newAccountDays)

        # Get enabled users
        $allUsers = @($ADData.Users | Where-Object { $_.Enabled -eq $true })

        if ($allUsers.Count -lt 10) {
            Write-Verbose "Insufficient users for statistical analysis"
            return @()
        }

        # Calculate environment baseline (all users)
        $allGroupCounts = @($allUsers | ForEach-Object { @($_.MemberOf).Count })
        $stats = Get-ADScoutStatistics -Values $allGroupCounts

        # Find new accounts
        $newAccounts = $allUsers | Where-Object {
            $_.WhenCreated -and $_.WhenCreated -gt $thresholdDate
        }

        if ($newAccounts.Count -eq 0) {
            Write-Verbose "No accounts created in the last $newAccountDays days"
            return @()
        }

        # Flag new accounts with above-average group membership
        # Using mean + 0.5*stddev as threshold for new accounts (stricter than general population)
        $newAccountThreshold = $stats.Mean + (0.5 * $stats.StdDev)

        $newAccounts | Where-Object {
            $groupCount = @($_.MemberOf).Count
            $groupCount -gt $newAccountThreshold
        } | ForEach-Object {
            $groupCount = @($_.MemberOf).Count
            $accountAgeDays = ((Get-Date) - $_.WhenCreated).Days
            $zscore = if ($stats.StdDev -gt 0) {
                ($groupCount - $stats.Mean) / $stats.StdDev
            } else { 0 }

            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                DisplayName       = $_.DisplayName
                WhenCreated       = $_.WhenCreated
                AccountAgeDays    = $accountAgeDays
                GroupCount        = $groupCount
                EnvironmentMean   = [math]::Round($stats.Mean, 1)
                ZScore            = [math]::Round($zscore, 2)
                Severity          = if ($zscore -gt 2) { 'High' } elseif ($zscore -gt 1) { 'Medium' } else { 'Low' }
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "AccountAgeDays", "GroupCount", "EnvironmentMean", "Severity")
    DetailFormat     = "{SamAccountName}: {GroupCount} groups at {AccountAgeDays} days old (mean={EnvironmentMean})"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Investigate rapid privilege accumulation for: $($Finding.SamAccountName)
# Account created: $($Finding.WhenCreated) ($($Finding.AccountAgeDays) days ago)
# Current groups: $($Finding.GroupCount) (environment average: $($Finding.EnvironmentMean))

# Check who created this account:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties Created, Modified, modifyTimeStamp |
    Select-Object SamAccountName, Created, Modified

# List current group memberships:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf |
    ForEach-Object { (Get-ADGroup `$_).Name } |
    Sort-Object

# Review if all these groups are necessary for a new account

"@
    }

    # === DOCUMENTATION ===
    Description = "Recently created accounts with above-average group memberships, indicating potential rapid privilege escalation."

    TechnicalExplanation = @"
This rule identifies accounts created within the last 30 days that already
have more group memberships than the environment average. New accounts
typically should start with minimal permissions and gain access over time
as needed.

Why this matters:
- Cloned accounts: Copying from privileged templates grants excessive access
- Compromised provisioning: Attackers with account creation rights may
  immediately add to privileged groups
- Policy violations: Bypassing proper access request procedures
- Insider threat: Rapid self-escalation after account creation

Detection logic:
1. Calculate mean group membership across all enabled users
2. Identify accounts created within last 30 days
3. Flag new accounts exceeding mean + 0.5 standard deviations

This is stricter than general population because new accounts should
start with fewer permissions, not more.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1136/002/"
        "https://attack.mitre.org/techniques/T1098/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

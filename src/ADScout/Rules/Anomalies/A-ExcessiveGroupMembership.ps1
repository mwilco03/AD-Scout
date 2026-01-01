<#
.SYNOPSIS
    Detects users with statistically excessive group memberships.

.DESCRIPTION
    Uses Z-score analysis to identify users who belong to significantly
    more groups than their peers. This can indicate:
    - Privilege creep over time
    - Over-provisioned accounts
    - Potential compromise (attacker adding to groups)
    - Service accounts misused as user accounts

.NOTES
    Rule ID    : A-ExcessiveGroupMembership
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.0.0

    Statistical Method: Z-Score with threshold of 2.0 (≈95th percentile)
    Minimum users required: 10 (for meaningful statistics)
#>

@{
    # === IDENTITY ===
    Id          = "A-ExcessiveGroupMembership"
    Name        = "Excessive Group Membership"
    Category    = "Anomalies"
    Model       = "FrequencyAnalysis"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 3
    MaxPoints   = 30
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002", "T1098")  # Valid Accounts: Domain, Account Manipulation
    CIS         = @()
    STIG        = @()
    ANSSI       = @()

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Get enabled users only
        $users = @($ADData.Users | Where-Object { $_.Enabled -eq $true })

        # Need minimum sample size for meaningful statistics
        if ($users.Count -lt 10) {
            Write-Verbose "Insufficient users for statistical analysis (need 10+, have $($users.Count))"
            return @()
        }

        # Calculate group counts for each user
        $userGroupData = $users | ForEach-Object {
            @{
                User       = $_
                GroupCount = @($_.MemberOf).Count
            }
        }

        # Get statistics
        $groupCounts = @($userGroupData | ForEach-Object { $_.GroupCount })
        $stats = Get-ADScoutStatistics -Values $groupCounts

        # Handle edge case: everyone has same number of groups
        if ($stats.StdDev -eq 0) {
            Write-Verbose "No variation in group membership counts"
            return @()
        }

        # Z-score threshold (2.0 = ~95th percentile)
        $zThreshold = 2.0

        # Find outliers
        $userGroupData | Where-Object {
            $zscore = ($_.GroupCount - $stats.Mean) / $stats.StdDev
            $zscore -gt $zThreshold
        } | ForEach-Object {
            $zscore = ($_.GroupCount - $stats.Mean) / $stats.StdDev

            [PSCustomObject]@{
                SamAccountName    = $_.User.SamAccountName
                DistinguishedName = $_.User.DistinguishedName
                DisplayName       = $_.User.DisplayName
                GroupCount        = $_.GroupCount
                ZScore            = [math]::Round($zscore, 2)
                EnvironmentMean   = [math]::Round($stats.Mean, 1)
                EnvironmentStdDev = [math]::Round($stats.StdDev, 1)
                Threshold         = [math]::Round($stats.Mean + ($zThreshold * $stats.StdDev), 0)
                Severity          = if ($zscore -gt 3) { 'Critical' } elseif ($zscore -gt 2.5) { 'High' } else { 'Medium' }
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "GroupCount", "ZScore", "EnvironmentMean", "Severity")
    DetailFormat     = "{SamAccountName}: {GroupCount} groups (Z={ZScore}, mean={EnvironmentMean})"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Review group memberships for: $($Finding.SamAccountName)
# Current: $($Finding.GroupCount) groups (environment average: $($Finding.EnvironmentMean))

# List current group memberships:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf |
    ForEach-Object { (Get-ADGroup `$_).Name } |
    Sort-Object

# Review and remove unnecessary memberships:
# Remove-ADGroupMember -Identity 'GroupName' -Members '$($Finding.SamAccountName)' -Confirm

"@
    }

    # === DOCUMENTATION ===
    Description = "Users with group membership counts significantly above the environment average."

    TechnicalExplanation = @"
This rule uses statistical analysis (Z-score) to identify users who belong to
an unusually high number of groups compared to their peers in the environment.

Why this matters:
- Privilege creep: Users accumulate group memberships over time as they change
  roles, but old memberships are rarely removed
- Attack indicator: Compromised accounts may be added to multiple groups by
  attackers for lateral movement or persistence
- Least privilege violation: Users should only have access necessary for their
  role

Statistical method:
- Z-score measures how many standard deviations a value is from the mean
- Threshold of 2.0 means flagging users in the top ~5% of group counts
- This adapts to your environment - a user in 50 groups might be normal in one
  org but anomalous in another

Example:
- Environment mean: 5 groups, StdDev: 3
- User with 15 groups: Z = (15-5)/3 = 3.33 → Flagged as anomaly
"@

    References = @(
        "https://attack.mitre.org/techniques/T1078/002/"
        "https://attack.mitre.org/techniques/T1098/"
        "https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        # Need user data with MemberOf
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

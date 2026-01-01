<#
.SYNOPSIS
    Detects users with statistically excessive group memberships.

.DESCRIPTION
    Uses Z-score analysis to identify users who belong to significantly
    more groups than their peers. Supports two comparison modes:

    1. Peer comparison (default): Compares users within the same OU
       - IT staff compared to IT staff, HR to HR, etc.
       - Reduces false positives from legitimate role differences

    2. Global comparison (fallback): Compares against all users
       - Used when OU has fewer than 5 users
       - Provides domain-wide baseline

.NOTES
    Rule ID    : A-ExcessiveGroupMembership
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.1.0

    Statistical Method: Z-Score with threshold of 2.0 (≈95th percentile)
    Peer comparison requires 5+ users per OU, otherwise falls back to global
#>

@{
    # === IDENTITY ===
    Id          = "A-ExcessiveGroupMembership"
    Name        = "Excessive Group Membership"
    Category    = "Anomalies"
    Model       = "FrequencyAnalysis"
    Version     = "1.1.0"

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

        # Configuration
        $zThreshold = 2.0           # Z-score threshold for outlier detection
        $minPeerGroupSize = 5       # Minimum users in OU for peer comparison
        $minGlobalSize = 10         # Minimum users for global comparison

        # Get enabled users only
        $users = @($ADData.Users | Where-Object { $_.Enabled -eq $true })

        if ($users.Count -lt $minGlobalSize) {
            Write-Verbose "Insufficient users for statistical analysis (need $minGlobalSize+, have $($users.Count))"
            return @()
        }

        # Calculate global statistics as fallback
        $globalGroupCounts = @($users | ForEach-Object { @($_.MemberOf).Count })
        $globalStats = Get-ADScoutStatistics -Values $globalGroupCounts

        if ($globalStats.StdDev -eq 0) {
            Write-Verbose "No variation in group membership counts globally"
            return @()
        }

        # Group users by OU for peer comparison
        $peerGroups = Get-ADScoutPeerBaseline -Objects $users -ValueProperty { @($_.MemberOf).Count }

        $findings = @()

        foreach ($peerGroup in $peerGroups) {
            $ouPath = $peerGroup.OUPath
            $ouUsers = $peerGroup.Objects
            $ouStats = $peerGroup.Statistics

            # Determine comparison mode
            $usePeerComparison = ($peerGroup.ObjectCount -ge $minPeerGroupSize) -and ($ouStats.StdDev -gt 0)

            if ($usePeerComparison) {
                $comparisonMode = "Peer"
                $stats = $ouStats
            }
            else {
                $comparisonMode = "Global"
                $stats = $globalStats
            }

            # Analyze each user in this OU
            foreach ($user in $ouUsers) {
                $groupCount = @($user.MemberOf).Count

                # Skip if stats invalid
                if ($stats.StdDev -eq 0) { continue }

                $zscore = ($groupCount - $stats.Mean) / $stats.StdDev

                if ($zscore -gt $zThreshold) {
                    $findings += [PSCustomObject]@{
                        SamAccountName    = $user.SamAccountName
                        DistinguishedName = $user.DistinguishedName
                        DisplayName       = $user.DisplayName
                        GroupCount        = $groupCount
                        ZScore            = [math]::Round($zscore, 2)
                        ComparisonMode    = $comparisonMode
                        PeerGroup         = if ($comparisonMode -eq "Peer") { $ouPath } else { "All Users" }
                        PeerGroupSize     = if ($comparisonMode -eq "Peer") { $peerGroup.ObjectCount } else { $users.Count }
                        PeerMean          = [math]::Round($stats.Mean, 1)
                        PeerStdDev        = [math]::Round($stats.StdDev, 1)
                        Threshold         = [math]::Round($stats.Mean + ($zThreshold * $stats.StdDev), 0)
                        Severity          = if ($zscore -gt 3) { 'Critical' } elseif ($zscore -gt 2.5) { 'High' } else { 'Medium' }
                    }
                }
            }
        }

        return $findings
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "GroupCount", "ZScore", "ComparisonMode", "PeerMean", "Severity")
    DetailFormat     = "{SamAccountName}: {GroupCount} groups (Z={ZScore} vs {ComparisonMode} mean={PeerMean})"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Review group memberships for: $($Finding.SamAccountName)
# Current: $($Finding.GroupCount) groups
# Comparison: $($Finding.ComparisonMode) ($($Finding.PeerGroup), $($Finding.PeerGroupSize) users)
# Peer average: $($Finding.PeerMean) groups

# List current group memberships:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf |
    ForEach-Object { (Get-ADGroup `$_).Name } |
    Sort-Object

# Compare to a typical peer in the same OU:
# Get-ADUser -Filter * -SearchBase '$($Finding.PeerGroup)' -Properties MemberOf |
#     Select-Object SamAccountName, @{N='GroupCount';E={@(`$_.MemberOf).Count}} |
#     Sort-Object GroupCount -Descending | Select-Object -First 10

# Review and remove unnecessary memberships:
# Remove-ADGroupMember -Identity 'GroupName' -Members '$($Finding.SamAccountName)' -Confirm

"@
    }

    # === DOCUMENTATION ===
    Description = "Users with group membership counts significantly above their peer group average."

    TechnicalExplanation = @"
This rule uses statistical analysis (Z-score) to identify users who belong to
an unusually high number of groups compared to their peers.

PEER COMPARISON MODE (v1.1.0):
Users are now compared against peers in the same OU, not the entire domain.
This dramatically reduces false positives because:
- IT administrators legitimately have more groups than HR staff
- Service desk has different access needs than accounting
- Comparing within peer groups reveals TRUE outliers

Comparison logic:
1. Group users by their OU (first level)
2. If OU has 5+ users: compare within OU (Peer mode)
3. If OU has <5 users: compare against all users (Global mode)
4. Flag users with Z-score > 2.0 in their comparison group

Why this matters:
- Privilege creep: Users accumulate group memberships over time as they change
  roles, but old memberships are rarely removed
- Attack indicator: Compromised accounts may be added to multiple groups by
  attackers for lateral movement or persistence
- Least privilege violation: Users should only have access necessary for their
  role

Example:
- IT OU mean: 25 groups, StdDev: 5
- IT user with 45 groups: Z = (45-25)/5 = 4.0 → Flagged as Critical
- Same user globally might not stand out (global mean might be 10)
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

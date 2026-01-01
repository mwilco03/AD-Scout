<#
.SYNOPSIS
    Detects users with statistically anomalous logon counts.

.DESCRIPTION
    Uses Z-score analysis to identify users with unusually high or low
    logon counts compared to peers. This can indicate:
    - High: Shared accounts, service accounts misused, brute force success
    - Low: Dormant accounts that occasionally activate (suspicious)

.NOTES
    Rule ID    : A-LogonCountAnomaly
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.0.0

    IMPORTANT: The logonCount attribute behavior varies by environment:
    - Replicated periodically (not real-time)
    - May not be populated in all environments
    - More reliable in smaller, single-DC environments

    This rule is marked as optional and will skip if data is insufficient.
#>

@{
    # === IDENTITY ===
    Id          = "A-LogonCountAnomaly"
    Name        = "Logon Count Anomaly"
    Category    = "Anomalies"
    Model       = "FrequencyAnalysis"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 2
    MaxPoints   = 20
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078", "T1110")  # Valid Accounts, Brute Force
    CIS         = @()
    STIG        = @()
    ANSSI       = @()

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Get enabled users with logon count data
        $usersWithLogonCount = @($ADData.Users | Where-Object {
            $_.Enabled -eq $true -and
            $null -ne $_.LogonCount -and
            $_.LogonCount -gt 0
        })

        # Need sufficient data for meaningful analysis
        if ($usersWithLogonCount.Count -lt 20) {
            Write-Verbose "Insufficient logonCount data for analysis (need 20+, have $($usersWithLogonCount.Count))"
            return @()
        }

        # Calculate statistics
        $logonCounts = @($usersWithLogonCount | ForEach-Object { [double]$_.LogonCount })
        $stats = Get-ADScoutStatistics -Values $logonCounts

        if ($stats.StdDev -eq 0) {
            Write-Verbose "No variation in logon counts"
            return @()
        }

        # Z-score thresholds
        $highThreshold = 3.0   # Unusually high logon count
        $lowThreshold = -2.0   # Unusually low (but still some logons)

        # Find anomalies
        $usersWithLogonCount | ForEach-Object {
            $zscore = ($_.LogonCount - $stats.Mean) / $stats.StdDev

            if ($zscore -gt $highThreshold -or $zscore -lt $lowThreshold) {
                $anomalyType = if ($zscore -gt $highThreshold) { 'HighLogonCount' } else { 'LowLogonCount' }
                $severity = if ([math]::Abs($zscore) -gt 4) { 'High' } else { 'Medium' }

                [PSCustomObject]@{
                    SamAccountName    = $_.SamAccountName
                    DistinguishedName = $_.DistinguishedName
                    DisplayName       = $_.DisplayName
                    LogonCount        = $_.LogonCount
                    ZScore            = [math]::Round($zscore, 2)
                    AnomalyType       = $anomalyType
                    EnvironmentMean   = [math]::Round($stats.Mean, 0)
                    EnvironmentMax    = $stats.Max
                    LastLogonDate     = $_.LastLogonDate
                    Severity          = $severity
                }
            }
        } | Where-Object { $_ }  # Filter nulls
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "LogonCount", "AnomalyType", "ZScore", "EnvironmentMean")
    DetailFormat     = "{SamAccountName}: {LogonCount} logons ({AnomalyType}, Z={ZScore}, mean={EnvironmentMean})"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Logon count anomaly for: $($Finding.SamAccountName)
# Logon count: $($Finding.LogonCount) (environment mean: $($Finding.EnvironmentMean))
# Anomaly type: $($Finding.AnomalyType)

$(if ($Finding.AnomalyType -eq 'HighLogonCount') {
@"
# HIGH LOGON COUNT - Possible causes:
# - Shared account used by multiple people
# - Service account logging in frequently
# - Automated process using interactive logon
# - Previously compromised account

# Investigate:
# 1. Check if this should be a service account with different auth
# 2. Review if account is shared (policy violation)
# 3. Check security logs for logon patterns
"@
} else {
@"
# LOW LOGON COUNT - Possible causes:
# - Dormant account occasionally used (suspicious)
# - Recently created account
# - Account used for non-interactive purposes

# Investigate:
# 1. When was this account created?
# 2. What triggered the few logons?
# 3. Is this account still needed?
"@
})

# Get account details:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties LogonCount, LastLogonDate, WhenCreated |
    Select-Object SamAccountName, LogonCount, LastLogonDate, WhenCreated

"@
    }

    # === DOCUMENTATION ===
    Description = "Accounts with logon counts significantly different from the environment norm."

    TechnicalExplanation = @"
This rule analyzes the logonCount attribute to identify accounts with
unusual login patterns compared to peers.

High logon count anomalies may indicate:
- Shared accounts: Multiple users sharing one credential
- Service account misuse: Interactive logon instead of service auth
- Automation: Scripts logging in as users instead of service accounts
- Historical compromise: Account was heavily used by attackers

Low logon count anomalies may indicate:
- Dormant accounts: Rarely used but occasionally activated
- Test accounts: Created but seldom used
- Suspicious activity: Account created for one-time malicious use

Important caveats:
- logonCount is not real-time; it replicates periodically between DCs
- Not all environments populate this reliably
- The attribute counts interactive logons, not all authentication events
- Results should be correlated with security event logs for full picture

This rule requires at least 20 users with logonCount data to produce
meaningful statistical analysis.
"@

    References = @(
        "https://docs.microsoft.com/en-us/windows/win32/adschema/a-logoncount"
        "https://attack.mitre.org/techniques/T1078/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        # Check if we have enough users with logonCount data
        $withLogonCount = @($ADData.Users | Where-Object {
            $_.Enabled -and $null -ne $_.LogonCount -and $_.LogonCount -gt 0
        })
        $withLogonCount.Count -ge 20
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

<#
.SYNOPSIS
    Detects Active Directory replication failures between Domain Controllers.

.DESCRIPTION
    AD replication failures can indicate infrastructure issues, network problems,
    or security concerns. Persistent failures may lead to data inconsistency
    and authentication problems.

.NOTES
    Rule ID    : I-DCReplicationFailure
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-DCReplicationFailure'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'Domain Controller Replication Failures'
    Description = 'Identifies Domain Controllers with Active Directory replication failures, which may indicate infrastructure issues or potential security concerns.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'AD Replication Troubleshooting'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/troubleshoot/troubleshooting-active-directory-replication-problems' }
        @{ Title = 'Repadmin Reference'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc770963(v=ws.11)' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1489')   # Service Stop
    }

    CIS   = @('4.1')
    STIG  = @('V-36432')
    ANSSI = @('R15')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    # Use repadmin to check replication status
                    $replResult = repadmin /showrepl $dcName /csv 2>&1

                    if ($replResult -is [string]) {
                        $replResult = $replResult -split "`n"
                    }

                    # Parse CSV output
                    $csvData = $replResult | ConvertFrom-Csv -ErrorAction SilentlyContinue

                    foreach ($entry in $csvData) {
                        $lastResult = $entry.'Last Failure Status'
                        $consecutiveFailures = $entry.'Number of Failures'
                        $lastSuccess = $entry.'Last Success Time'
                        $lastFailure = $entry.'Last Failure Time'

                        if ($lastResult -and $lastResult -ne '0' -and $consecutiveFailures -gt 0) {
                            $findings += [PSCustomObject]@{
                                SourceDC            = $dcName
                                DestinationDC       = $entry.'Source DC'
                                NamingContext       = $entry.'Naming Context'
                                LastFailureStatus   = $lastResult
                                FailureCount        = $consecutiveFailures
                                LastSuccessTime     = $lastSuccess
                                LastFailureTime     = $lastFailure
                                RiskLevel           = if ([int]$consecutiveFailures -gt 5) { 'Critical' } else { 'High' }
                                Impact              = 'AD data inconsistency, authentication failures possible'
                                DistinguishedName   = $dc.DistinguishedName
                            }
                        }
                    }
                } catch {
                    # Try alternative method using Get-ADReplicationPartnerMetadata
                    try {
                        $replPartners = Get-ADReplicationPartnerMetadata -Target $dcName -ErrorAction Stop

                        foreach ($partner in $replPartners) {
                            if ($partner.LastReplicationResult -ne 0 -or $partner.ConsecutiveReplicationFailures -gt 0) {
                                $findings += [PSCustomObject]@{
                                    SourceDC            = $dcName
                                    DestinationDC       = $partner.Partner
                                    NamingContext       = $partner.Partition
                                    LastFailureStatus   = $partner.LastReplicationResult
                                    FailureCount        = $partner.ConsecutiveReplicationFailures
                                    LastSuccessTime     = $partner.LastReplicationSuccess
                                    LastFailureTime     = $partner.LastReplicationAttempt
                                    RiskLevel           = if ($partner.ConsecutiveReplicationFailures -gt 5) { 'Critical' } else { 'High' }
                                    Impact              = 'AD data inconsistency, authentication failures possible'
                                    DistinguishedName   = $dc.DistinguishedName
                                }
                            }
                        }
                    } catch {
                        # Log that we couldn't check this DC
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Investigate and resolve AD replication failures. Common causes include network connectivity, DNS issues, time sync problems, or tombstone lifetime expiration.'
        Impact      = 'Medium - Troubleshooting may require DC restarts or network changes.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Active Directory Replication Failure Remediation
#############################################################################
#
# Replication failures can cause:
# - Inconsistent data across Domain Controllers
# - Authentication failures when using affected DCs
# - GPO application inconsistencies
# - Potential lingering object issues
#
# Affected Replication Links:
$($Finding.Findings | ForEach-Object { "# - $($_.SourceDC) -> $($_.DestinationDC): $($_.FailureCount) failures" } | Out-String)

#############################################################################
# Step 1: Diagnose Replication Issues
#############################################################################

# View replication summary
repadmin /replsummary

# View detailed replication status
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object { $_.'Number of Failures' -gt 0 }

# Check for replication queue
repadmin /queue

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

#############################################################################
# Replication Link: $($item.SourceDC) -> $($item.DestinationDC)
# Failures: $($item.FailureCount)
# Error Code: $($item.LastFailureStatus)
#############################################################################

# Force replication between these DCs
repadmin /replicate $($item.SourceDC) $($item.DestinationDC) "$($item.NamingContext)"

# Check network connectivity
Test-NetConnection -ComputerName $($item.DestinationDC) -Port 389
Test-NetConnection -ComputerName $($item.DestinationDC) -Port 135
Test-NetConnection -ComputerName $($item.DestinationDC) -Port 445

# Check DNS resolution
Resolve-DnsName -Name $($item.DestinationDC) -Type A
Resolve-DnsName -Name $($item.DestinationDC) -Type AAAA

# Check time synchronization
w32tm /stripchart /computer:$($item.DestinationDC) /samples:3

"@
            }

            $commands += @"

#############################################################################
# Common Error Codes and Solutions
#############################################################################

# Error 8453 (0x2105) - Replication access was denied
# - Check security group membership
# - Verify computer account is not disabled
# - Check for lingering objects

# Error 8524 (0x214c) - DNS lookup failure
# - Verify DNS records for source DC
# - Check _msdcs DNS zone
# - Run: dcdiag /test:dns

# Error 8456/8457 - Source/destination server is currently rejecting
# - Check if DC is in restore mode
# - Verify DC is advertising as DC: dcdiag /test:advertising

# Error 8452 - Naming context is in the process of being removed
# - Wait for removal to complete
# - Check AD Sites and Services for orphaned objects

# Error 1722 (RPC server unavailable)
# - Check network connectivity
# - Verify RPC endpoint mapper (port 135)
# - Check for firewall blocking

#############################################################################
# Advanced Diagnostics
#############################################################################

# Run comprehensive DC diagnostics
dcdiag /v /e /c

# Check for lingering objects
repadmin /removelingeringobjects $($Finding.Findings[0].SourceDC) `
    <source-dc-guid> "DC=contoso,DC=com" /advisory_mode

# Force KCC to recalculate topology
repadmin /kcc

# Synchronize all DCs
repadmin /syncall /e /A /P /d

"@
            return $commands
        }
    }
}

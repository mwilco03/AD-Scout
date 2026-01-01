<#
.SYNOPSIS
    Detects Domain Controller time synchronization issues.

.DESCRIPTION
    Kerberos authentication fails when time difference exceeds 5 minutes.
    Time skew between DCs can cause authentication failures, replication
    issues, and security problems.

.NOTES
    Rule ID    : I-DCTimeSkew
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-DCTimeSkew'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'Domain Controller Time Synchronization Issues'
    Description = 'Identifies Domain Controllers with time synchronization problems that can cause Kerberos authentication failures and replication issues.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Windows Time Service'; Url = 'https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top' }
        @{ Title = 'Kerberos Time Requirements'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization' }
        @{ Title = 'Time Sync Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/support-boundary' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1498')   # Resource Hijacking (time manipulation)
    }

    CIS   = @('2.3')
    STIG  = @('V-73307')
    ANSSI = @('R15')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $referenceTime = Get-Date
        $maxSkewSeconds = 300  # 5 minutes (Kerberos default)
        $warningSkewSeconds = 120  # 2 minutes

        if ($Data.DomainControllers) {
            # Get PDC emulator as time reference
            $pdcEmulator = $null
            try {
                $pdcEmulator = (Get-ADDomain).PDCEmulator
            } catch {
                $pdcEmulator = $Data.DomainControllers | Where-Object { $_.OperationMasterRoles -contains 'PDCEmulator' } | Select-Object -First 1
            }

            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    # Get time from DC
                    $dcTime = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        Get-Date
                    } -ErrorAction Stop

                    $localTime = Get-Date
                    $skewSeconds = [Math]::Abs(($dcTime - $localTime).TotalSeconds)

                    # Also check w32tm status
                    $timeStatus = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $source = w32tm /query /source 2>&1
                        $status = w32tm /query /status 2>&1

                        @{
                            Source = $source
                            Status = $status -join "`n"
                        }
                    } -ErrorAction SilentlyContinue

                    $timeSource = if ($timeStatus) { $timeStatus.Source } else { 'Unknown' }

                    # Determine issue severity
                    $hasIssue = $false
                    $riskLevel = 'Low'
                    $issue = ''

                    if ($skewSeconds -gt $maxSkewSeconds) {
                        $hasIssue = $true
                        $riskLevel = 'Critical'
                        $issue = "Time skew of $([Math]::Round($skewSeconds)) seconds exceeds Kerberos tolerance (5 min)"
                    } elseif ($skewSeconds -gt $warningSkewSeconds) {
                        $hasIssue = $true
                        $riskLevel = 'High'
                        $issue = "Time skew of $([Math]::Round($skewSeconds)) seconds approaching Kerberos limit"
                    } elseif ($timeSource -match 'error|Local CMOS|Free-Running') {
                        $hasIssue = $true
                        $riskLevel = 'High'
                        $issue = "DC not synchronized to reliable time source: $timeSource"
                    }

                    if ($hasIssue) {
                        $findings += [PSCustomObject]@{
                            DomainController    = $dcName
                            TimeSkewSeconds     = [Math]::Round($skewSeconds, 2)
                            DCTime              = $dcTime.ToString('yyyy-MM-dd HH:mm:ss')
                            TimeSource          = $timeSource
                            Issue               = $issue
                            RiskLevel           = $riskLevel
                            IsPDCEmulator       = ($dcName -eq $pdcEmulator -or $dc.OperationMasterRoles -contains 'PDCEmulator')
                            Impact              = if ($skewSeconds -gt $maxSkewSeconds) { 'Kerberos authentication may fail' } else { 'Potential for authentication issues' }
                            DistinguishedName   = $dc.DistinguishedName
                        }
                    }

                } catch {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        TimeSkewSeconds     = 'Unable to measure'
                        DCTime              = 'Unknown'
                        TimeSource          = 'Unable to query'
                        Issue               = 'Cannot connect to verify time synchronization'
                        RiskLevel           = 'Medium'
                        IsPDCEmulator       = $false
                        Impact              = 'Time sync status unknown'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure proper time synchronization hierarchy with PDC Emulator syncing to external source and other DCs syncing to it.'
        Impact      = 'Low - Time changes are generally safe but may cause brief authentication issues during correction.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Domain Controller Time Synchronization
#############################################################################
#
# Kerberos requires time within 5 minutes (300 seconds) between client and server.
# Time skew causes:
# - Authentication failures ("Clock skew too great")
# - Replication issues
# - Event log timestamp inconsistencies
# - Security audit problems
#
# Time Sync Hierarchy:
# 1. PDC Emulator -> External NTP (or hardware source)
# 2. Other DCs -> PDC Emulator
# 3. Domain Members -> Any DC
#
# Issues Found:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issue) (Skew: $($_.TimeSkewSeconds)s)" } | Out-String)

#############################################################################
# Step 1: Identify PDC Emulator
#############################################################################

`$pdcEmulator = (Get-ADDomain).PDCEmulator
Write-Host "PDC Emulator: `$pdcEmulator" -ForegroundColor Cyan

#############################################################################
# Step 2: Configure PDC Emulator for External Time Source
#############################################################################

# On the PDC Emulator, configure external NTP servers
# Use reliable sources like time.windows.com, pool.ntp.org, or internal GPS

Invoke-Command -ComputerName `$pdcEmulator -ScriptBlock {
    # Configure external NTP sources
    w32tm /config /manualpeerlist:"time.windows.com,0x8 time.nist.gov,0x8" /syncfromflags:manual /reliable:yes /update

    # Restart time service
    Restart-Service w32time

    # Force sync
    w32tm /resync /rediscover

    Write-Host "PDC Emulator configured for external NTP" -ForegroundColor Green
}

#############################################################################
# Step 3: Configure Other DCs to Sync from Domain Hierarchy
#############################################################################

"@

            foreach ($item in $Finding.Findings | Where-Object { -not $_.IsPDCEmulator }) {
                $commands += @"

# Configure time sync on: $($item.DomainController)
Invoke-Command -ComputerName '$($item.DomainController)' -ScriptBlock {
    # Set to sync from domain hierarchy (NT5DS)
    w32tm /config /syncfromflags:domhier /update

    # Restart time service
    Restart-Service w32time

    # Force sync
    w32tm /resync /rediscover

    Write-Host "Configured to sync from domain hierarchy" -ForegroundColor Green
}

"@
            }

            $commands += @"

#############################################################################
# Step 4: Verify Time Synchronization
#############################################################################

# Check time source on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    `$source = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        w32tm /query /source
    } -ErrorAction SilentlyContinue
    Write-Host "`$(`$_.HostName): `$source"
}

# Check time offset on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    `$offset = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        w32tm /query /status /verbose | Select-String "Root Dispersion|Skew"
    } -ErrorAction SilentlyContinue
    Write-Host "`n`$(`$_.HostName):`n`$offset"
}

# Compare time between DCs
`$referenceTime = Get-Date
Get-ADDomainController -Filter * | ForEach-Object {
    `$dcTime = Invoke-Command -ComputerName `$_.HostName -ScriptBlock { Get-Date }
    `$skew = (`$dcTime - `$referenceTime).TotalSeconds
    `$color = if ([Math]::Abs(`$skew) -gt 300) { 'Red' } elseif ([Math]::Abs(`$skew) -gt 60) { 'Yellow' } else { 'Green' }
    Write-Host "`$(`$_.HostName): `$([Math]::Round(`$skew,1))s skew" -ForegroundColor `$color
}

#############################################################################
# Group Policy Configuration (Recommended)
#############################################################################

# Create GPO for PDC Emulator:
# Computer Configuration > Policies > Administrative Templates >
#   System > Windows Time Service > Time Providers

# Configure Windows NTP Client:
# - Enabled: Yes
# - NtpServer: time.windows.com,0x9 time.nist.gov,0x9
# - Type: NTP

# Create GPO for other DCs:
# Configure Windows NTP Client:
# - Type: NT5DS (sync from domain hierarchy)

#############################################################################
# Monitoring
#############################################################################

# Event Log: System
# Source: Microsoft-Windows-Time-Service
# Event ID 129: NTP client failed to synchronize
# Event ID 142: Time sync error

# Check for time sync warnings:
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Time-Service'} `
    -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message

"@
            return $commands
        }
    }
}

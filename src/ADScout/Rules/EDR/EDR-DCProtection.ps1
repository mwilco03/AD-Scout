<#
.SYNOPSIS
    Verifies EDR protection on Domain Controllers.

.DESCRIPTION
    Ensures all Domain Controllers have active EDR agent protection.
    Domain Controllers are high-value targets that require continuous
    monitoring for credential theft, lateral movement, and persistence.

.NOTES
    Rule ID    : EDR-DCProtection
    Category   : EDR
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EDR-DCProtection'
    Version     = '1.0.0'
    Category    = 'EDR'
    Title       = 'Domain Controller EDR Protection'
    Description = 'Verifies that all Domain Controllers have active EDR agent protection with recent check-in, ensuring visibility into the most critical AD infrastructure.'
    Severity    = 'Critical'
    Weight      = 75
    DataSource  = 'DomainControllers,EDRHosts'

    References  = @(
        @{ Title = 'MITRE ATT&CK: Valid Accounts - Domain Accounts'; Url = 'https://attack.mitre.org/techniques/T1078/002/' }
        @{ Title = 'CISA: Domain Controller Protection'; Url = 'https://www.cisa.gov/sites/default/files/publications/Mitigating%20AD%20Attacks_508c.pdf' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003', 'TA0005')  # Credential Access, Persistence, Defense Evasion
        Techniques = @('T1003.006', 'T1558')  # DCSync, Steal/Forge Kerberos Tickets
    }

    CIS   = @('1.1', '10.1', '10.5')
    STIG  = @('V-254238')
    ANSSI = @('R1', 'R52')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
        Max     = 100
    }

    Prerequisites = {
        param($Data, $Domain)
        return Test-ADScoutEDRConnection
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $edrProvider = Get-ADScoutEDRProvider -Active
        if (-not $edrProvider) {
            return $findings
        }

        try {
            # Get EDR-managed hosts
            $edrHosts = $edrProvider.GetAvailableHosts(@{ Platform = 'Windows' })
            $edrHostMap = @{}

            foreach ($host in $edrHosts) {
                $hostname = ($host.Hostname -split '\.')[0].ToLower()
                $edrHostMap[$hostname] = $host
            }

            # Check each Domain Controller
            $dcs = @()
            if ($Data.DomainControllers) {
                $dcs = $Data.DomainControllers
            }
            elseif ($Data.Computers) {
                $dcs = $Data.Computers | Where-Object {
                    $_.DistinguishedName -match 'OU=Domain Controllers' -or
                    $_.PrimaryGroupID -eq 516  # Domain Controllers group
                }
            }

            foreach ($dc in $dcs) {
                $dcName = if ($dc.Name) { $dc.Name } else { $dc.SamAccountName -replace '\$$', '' }
                $dcNameLower = $dcName.ToLower()

                $edrStatus = $null
                if ($edrHostMap.ContainsKey($dcNameLower)) {
                    $edrStatus = $edrHostMap[$dcNameLower]
                }

                $issues = @()
                $severity = 'Info'

                if (-not $edrStatus) {
                    $issues += 'No EDR agent detected'
                    $severity = 'Critical'
                }
                else {
                    # Check if agent is online/active
                    if ($edrStatus.Status -and $edrStatus.Status -notin @('online', 'active', 'Active', 'Online')) {
                        $issues += "Agent status: $($edrStatus.Status)"
                        $severity = 'High'
                    }

                    # Check last seen time
                    if ($edrStatus.LastSeen) {
                        $lastSeen = [DateTime]$edrStatus.LastSeen
                        $hoursSinceLastSeen = ((Get-Date) - $lastSeen).TotalHours

                        if ($hoursSinceLastSeen -gt 24) {
                            $issues += "Agent last seen $([int]$hoursSinceLastSeen) hours ago"
                            if ($hoursSinceLastSeen -gt 168) {  # 7 days
                                $severity = 'Critical'
                            } else {
                                $severity = 'High'
                            }
                        }
                    }

                    # Check agent version (if we can determine if outdated)
                    if ($edrStatus.AgentVersion -and $edrStatus.AgentVersion -match '^[0-5]\.' ) {
                        $issues += "Potentially outdated agent version: $($edrStatus.AgentVersion)"
                        if ($severity -eq 'Info') { $severity = 'Medium' }
                    }
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        DomainController  = $dcName
                        FQDN              = $dc.DnsHostName
                        OperatingSystem   = $dc.OperatingSystem
                        EDRProvider       = $edrProvider.Name
                        EDRStatus         = if ($edrStatus) { $edrStatus.Status } else { 'Not Found' }
                        AgentVersion      = if ($edrStatus) { $edrStatus.AgentVersion } else { 'N/A' }
                        LastSeen          = if ($edrStatus -and $edrStatus.LastSeen) { $edrStatus.LastSeen } else { 'Never' }
                        Issues            = $issues -join '; '
                        Severity          = $severity
                        Impact            = 'Domain Controller lacks proper EDR visibility - high-value target unprotected'
                        DistinguishedName = $dc.DistinguishedName
                    }
                }
            }
        }
        catch {
            Write-Warning "EDR-DCProtection: Failed to verify DC protection: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Immediately deploy and verify EDR agent on all Domain Controllers.'
        Impact      = 'Low - EDR agents have minimal performance impact on modern DCs.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# CRITICAL: Domain Controller EDR Protection
#############################################################################
#
# Domain Controllers with EDR issues:
#

$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues) [Severity: $($_.Severity)]" } | Out-String)

#############################################################################
# IMMEDIATE ACTIONS REQUIRED
#############################################################################

# 1. Domain Controllers are primary targets for:
#    - DCSync attacks (credential theft)
#    - Golden Ticket creation
#    - DCShadow persistence
#    - Lateral movement pivoting
#
# 2. Without EDR, you have NO visibility into:
#    - Process execution on DCs
#    - Network connections to/from DCs
#    - File modifications
#    - Credential access attempts

#############################################################################
# Step 1: Verify Current State
#############################################################################

`$affectedDCs = @(
$($Finding.Findings | ForEach-Object { "    '$($_.DomainController)'" } | Out-String))

foreach (`$dc in `$affectedDCs) {
    Write-Host "Checking `$dc..."

    # Verify DC is reachable
    if (Test-Connection -ComputerName `$dc -Count 1 -Quiet) {
        Write-Host "  [OK] Reachable" -ForegroundColor Green

        # Check for existing EDR services
        `$services = Invoke-Command -ComputerName `$dc -ScriptBlock {
            @{
                CrowdStrike = (Get-Service 'CSFalconService' -ErrorAction SilentlyContinue).Status
                MDE = (Get-Service 'Sense' -ErrorAction SilentlyContinue).Status
                WinDefend = (Get-Service 'WinDefend' -ErrorAction SilentlyContinue).Status
            }
        } -ErrorAction SilentlyContinue

        if (`$services) {
            Write-Host "  CrowdStrike: `$(`$services.CrowdStrike)"
            Write-Host "  MDE Sense: `$(`$services.MDE)"
            Write-Host "  WinDefend: `$(`$services.WinDefend)"
        }
    } else {
        Write-Host "  [ERROR] Not reachable!" -ForegroundColor Red
    }
}

#############################################################################
# Step 2: Deploy EDR Agent
#############################################################################

# CrowdStrike Falcon Deployment:
<#
foreach (`$dc in `$affectedDCs) {
    # Copy installer
    Copy-Item -Path 'C:\EDR\CsInstall.exe' -Destination "\\`$dc\C$\Temp\" -Force

    # Run installer with CID
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        & C:\Temp\CsInstall.exe /install /quiet /norestart CID=<YOUR_CID>
    }
}
#>

# Microsoft Defender for Endpoint Deployment:
<#
foreach (`$dc in `$affectedDCs) {
    # Copy onboarding script
    Copy-Item -Path 'C:\EDR\WindowsDefenderATPOnboardingScript.cmd' -Destination "\\`$dc\C$\Temp\" -Force

    # Run onboarding
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        & C:\Temp\WindowsDefenderATPOnboardingScript.cmd
    }
}
#>

#############################################################################
# Step 3: Verify Agent Registration
#############################################################################

# Wait for agent to register (typically 5-15 minutes)
Start-Sleep -Seconds 300

# Re-check EDR console for DC presence
# Connect-ADScoutEDR -Provider PSFalcon ...
# Get-ADScoutEDRHost -DomainControllers

#############################################################################
# Step 4: Enable DC-Specific Detections
#############################################################################

# Ensure the following are enabled in your EDR:
#
# CrowdStrike:
# - Credential Theft Protection
# - Lateral Movement Detection
# - Kerberos Attack Prevention
#
# Microsoft Defender:
# - Advanced hunting queries for DC attacks
# - Custom detection rules for DCSync patterns
# - Attack Surface Reduction rules

#############################################################################
# Step 5: Baseline and Monitor
#############################################################################

# Create baseline of normal DC behavior:
# - Expected processes
# - Normal network connections
# - Scheduled tasks
# - Service accounts

# Set up alerts for:
# - lsass.exe memory access
# - replication traffic from non-DCs
# - New scheduled tasks
# - Service installation
# - Unusual child processes of DC services

"@
            return $commands
        }
    }
}

<#
.SYNOPSIS
    Detects EDR agents that have not checked in recently.

.DESCRIPTION
    Identifies endpoints with EDR agents that are offline or have not
    communicated with the EDR platform recently. Stale agents may indicate
    compromised systems, network isolation, or agent failures.

.NOTES
    Rule ID    : EDR-StaleAgents
    Category   : EDR
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EDR-StaleAgents'
    Version     = '1.0.0'
    Category    = 'EDR'
    Title       = 'Stale EDR Agents'
    Description = 'Identifies endpoints with EDR agents that have not communicated recently, potentially indicating compromised or isolated systems.'
    Severity    = 'Medium'
    Weight      = 30
    DataSource  = 'EDRHosts'

    References  = @(
        @{ Title = 'MITRE ATT&CK: Impair Defenses'; Url = 'https://attack.mitre.org/techniques/T1562/' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.001')  # Disable or Modify Tools
    }

    CIS   = @('10.1', '10.2')
    STIG  = @()
    ANSSI = @()

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 3
        Max     = 60
    }

    Parameters = @{
        StaleDaysThreshold = @{
            Type        = 'int'
            Default     = 7
            Description = 'Number of days without check-in to consider agent stale'
        }
        CriticalDaysThreshold = @{
            Type        = 'int'
            Default     = 30
            Description = 'Number of days without check-in to consider critical'
        }
    }

    Prerequisites = {
        param($Data, $Domain)
        return Test-ADScoutEDRConnection
    }

    Detect = {
        param($Data, $Domain, $Parameters)

        $staleDays = if ($Parameters.StaleDaysThreshold) { $Parameters.StaleDaysThreshold } else { 7 }
        $criticalDays = if ($Parameters.CriticalDaysThreshold) { $Parameters.CriticalDaysThreshold } else { 30 }

        $findings = @()

        $edrProvider = Get-ADScoutEDRProvider -Active
        if (-not $edrProvider) {
            return $findings
        }

        try {
            $edrHosts = $edrProvider.GetAvailableHosts(@{})
            $staleThreshold = (Get-Date).AddDays(-$staleDays)
            $criticalThreshold = (Get-Date).AddDays(-$criticalDays)

            foreach ($host in $edrHosts) {
                $lastSeen = $null
                if ($host.LastSeen) {
                    $lastSeen = [DateTime]$host.LastSeen
                }

                if ($lastSeen -and $lastSeen -lt $staleThreshold) {
                    $daysSinceLastSeen = [int]((Get-Date) - $lastSeen).TotalDays

                    $severity = if ($lastSeen -lt $criticalThreshold) { 'High' } else { 'Medium' }

                    $findings += [PSCustomObject]@{
                        Hostname          = $host.Hostname
                        DeviceId          = if ($host.DeviceId) { $host.DeviceId } else { $host.MachineId }
                        Platform          = $host.Platform
                        OSVersion         = $host.OSVersion
                        LastSeen          = $lastSeen
                        DaysSinceLastSeen = $daysSinceLastSeen
                        Status            = $host.Status
                        AgentVersion      = $host.AgentVersion
                        Severity          = $severity
                        EDRProvider       = $edrProvider.Name
                        Impact            = if ($severity -eq 'High') {
                                                'Extended offline period - may indicate compromise or decommissioning'
                                            } else {
                                                'Agent not communicating - reduced visibility'
                                            }
                    }
                }
            }

            # Sort by days since last seen (most stale first)
            $findings = $findings | Sort-Object DaysSinceLastSeen -Descending
        }
        catch {
            Write-Warning "EDR-StaleAgents: Failed to check agent status: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Investigate stale EDR agents to determine if systems are decommissioned, isolated, or compromised.'
        Impact      = 'None - Investigation only'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Stale EDR Agent Investigation
#############################################################################
#
# The following systems have EDR agents that have not checked in recently:
#

$($Finding.Findings | ForEach-Object { "# - $($_.Hostname): Last seen $($_.DaysSinceLastSeen) days ago ($($_.LastSeen))" } | Out-String)

#############################################################################
# Step 1: Verify System Status in AD
#############################################################################

`$staleHosts = @(
$($Finding.Findings | ForEach-Object { "    '$($_.Hostname -split '\.' | Select-Object -First 1)'" } | Out-String))

foreach (`$hostname in `$staleHosts) {
    `$computer = Get-ADComputer -Identity `$hostname -Properties LastLogonDate, Enabled, OperatingSystem -ErrorAction SilentlyContinue
    if (`$computer) {
        Write-Host "`$hostname :"
        Write-Host "  AD Enabled: `$(`$computer.Enabled)"
        Write-Host "  AD Last Logon: `$(`$computer.LastLogonDate)"
        Write-Host "  OS: `$(`$computer.OperatingSystem)"
    } else {
        Write-Host "`$hostname : Not found in AD (possibly decommissioned)"
    }
}

#############################################################################
# Step 2: Attempt Network Connectivity Test
#############################################################################

foreach (`$hostname in `$staleHosts) {
    `$ping = Test-Connection -ComputerName `$hostname -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (`$ping) {
        Write-Host "`$hostname : ONLINE (reachable via ping)"
        # If online but EDR stale, agent may be disabled/crashed
    } else {
        Write-Host "`$hostname : OFFLINE"
    }
}

#############################################################################
# Step 3: Investigate Online Systems with Stale Agents
#############################################################################

# For systems that respond to ping but have stale EDR:
# 1. Check if EDR service is running
# 2. Check for agent tampering
# 3. Review security logs for suspicious activity

foreach (`$hostname in `$staleHosts) {
    if (Test-Connection -ComputerName `$hostname -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        try {
            `$result = Invoke-Command -ComputerName `$hostname -ScriptBlock {
                # CrowdStrike Falcon
                `$falcon = Get-Service -Name 'CSFalconService' -ErrorAction SilentlyContinue

                # Microsoft Defender for Endpoint
                `$sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue

                # Windows Defender
                `$defender = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue

                @{
                    CrowdStrike = if (`$falcon) { `$falcon.Status } else { 'Not Installed' }
                    MDESense = if (`$sense) { `$sense.Status } else { 'Not Installed' }
                    WinDefend = if (`$defender) { `$defender.Status } else { 'Not Installed' }
                }
            } -ErrorAction SilentlyContinue

            Write-Host "`$hostname EDR Services:"
            Write-Host "  CrowdStrike: `$(`$result.CrowdStrike)"
            Write-Host "  MDE Sense: `$(`$result.MDESense)"
            Write-Host "  WinDefend: `$(`$result.WinDefend)"
        } catch {
            Write-Host "`$hostname : Remote query failed - `$_"
        }
    }
}

#############################################################################
# Step 4: Actions Based on Findings
#############################################################################

# For decommissioned systems:
# - Remove from EDR console to clean up inventory
# - Disable AD computer account if not already done

# For isolated systems:
# - Investigate network configuration
# - Check for proxy/firewall blocking EDR traffic

# For compromised systems (online but agent disabled):
# - Isolate from network immediately
# - Begin incident response procedures
# - Preserve evidence for forensics

# For agent failures:
# - Attempt agent restart remotely
# - If failed, plan for agent reinstall

#############################################################################
# Step 5: Restart Stale Agents (if safe)
#############################################################################

# CrowdStrike Falcon restart:
Invoke-Command -ComputerName `$hostname -ScriptBlock {
    Restart-Service -Name 'CSFalconService' -Force
}

# Microsoft Defender for Endpoint restart:
Invoke-Command -ComputerName `$hostname -ScriptBlock {
    Restart-Service -Name 'Sense' -Force
}

"@
            return $commands
        }
    }
}

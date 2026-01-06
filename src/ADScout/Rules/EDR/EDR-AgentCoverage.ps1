<#
.SYNOPSIS
    Detects Active Directory computers without EDR agent coverage.

.DESCRIPTION
    Compares AD computer objects against EDR-managed endpoints to identify
    systems that may lack endpoint protection and monitoring. Missing EDR
    coverage creates blind spots for security operations.

.NOTES
    Rule ID    : EDR-AgentCoverage
    Category   : EDR
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EDR-AgentCoverage'
    Version     = '1.0.0'
    Category    = 'EDR'
    Title       = 'Systems Missing EDR Agent Coverage'
    Description = 'Identifies Active Directory computer accounts that do not have a corresponding EDR agent, indicating potential gaps in endpoint protection and visibility.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'Computers,EDRHosts'

    References  = @(
        @{ Title = 'MITRE ATT&CK: Defense Evasion'; Url = 'https://attack.mitre.org/tactics/TA0005/' }
        @{ Title = 'CIS Controls v8: Inventory and Control of Enterprise Assets'; Url = 'https://www.cisecurity.org/controls/cis-controls-list' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562')   # Impair Defenses
    }

    CIS   = @('1.1', '10.1')
    STIG  = @()
    ANSSI = @('R1')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 5
        Max     = 100
    }

    Prerequisites = {
        param($Data, $Domain)
        # Requires EDR connection
        return Test-ADScoutEDRConnection
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get EDR-managed hosts
        $edrProvider = Get-ADScoutEDRProvider -Active
        if (-not $edrProvider) {
            Write-Warning "EDR-AgentCoverage: No active EDR provider"
            return $findings
        }

        try {
            $edrHosts = $edrProvider.GetAvailableHosts(@{ Platform = 'Windows' })
            $edrHostnames = @{}

            foreach ($host in $edrHosts) {
                $hostname = ($host.Hostname -split '\.')[0].ToLower()
                $edrHostnames[$hostname] = $host
            }

            Write-Verbose "EDR-AgentCoverage: Found $($edrHostnames.Count) EDR-managed Windows hosts"

            # Compare with AD computers
            if ($Data.Computers) {
                foreach ($computer in $Data.Computers) {
                    $computerName = $computer.SamAccountName -replace '\$$', ''
                    $computerNameLower = $computerName.ToLower()

                    # Skip disabled computers
                    if ($computer.Enabled -eq $false) { continue }

                    # Skip computers that haven't logged on in 90+ days (likely stale)
                    if ($computer.LastLogonDate) {
                        $daysSinceLogon = ((Get-Date) - $computer.LastLogonDate).Days
                        if ($daysSinceLogon -gt 90) { continue }
                    }

                    # Check if computer has EDR agent
                    if (-not $edrHostnames.ContainsKey($computerNameLower)) {
                        $computerType = 'Workstation'
                        if ($computer.DistinguishedName -match 'Domain Controllers') {
                            $computerType = 'Domain Controller'
                        }
                        elseif ($computer.OperatingSystem -match 'Server') {
                            $computerType = 'Server'
                        }

                        $severity = switch ($computerType) {
                            'Domain Controller' { 'Critical' }
                            'Server' { 'High' }
                            default { 'Medium' }
                        }

                        $findings += [PSCustomObject]@{
                            ComputerName      = $computerName
                            OperatingSystem   = $computer.OperatingSystem
                            ComputerType      = $computerType
                            LastLogonDate     = $computer.LastLogonDate
                            Enabled           = $computer.Enabled
                            Severity          = $severity
                            EDRProvider       = $edrProvider.Name
                            Impact            = 'No endpoint visibility - potential blind spot for threat detection'
                            DistinguishedName = $computer.DistinguishedName
                        }
                    }
                }
            }

            # Summary logging
            $dcCount = ($findings | Where-Object { $_.ComputerType -eq 'Domain Controller' }).Count
            $serverCount = ($findings | Where-Object { $_.ComputerType -eq 'Server' }).Count
            $wsCount = ($findings | Where-Object { $_.ComputerType -eq 'Workstation' }).Count

            if ($findings.Count -gt 0) {
                Write-Verbose "EDR-AgentCoverage: $($findings.Count) computers missing EDR ($dcCount DCs, $serverCount servers, $wsCount workstations)"
            }
        }
        catch {
            Write-Warning "EDR-AgentCoverage: Failed to check EDR coverage: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy EDR agent to all systems, prioritizing Domain Controllers and servers.'
        Impact      = 'Low - EDR agents are designed for minimal performance impact.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# EDR Agent Deployment
#############################################################################
#
# The following systems are missing EDR agent coverage:
#

$($Finding.Findings | ForEach-Object { "# - $($_.ComputerName) ($($_.ComputerType)): $($_.OperatingSystem)" } | Out-String)

#############################################################################
# Step 1: Prioritize Deployment
#############################################################################

# Priority 1: Domain Controllers (Critical)
`$dcs = @(
$($Finding.Findings | Where-Object { $_.ComputerType -eq 'Domain Controller' } | ForEach-Object { "    '$($_.ComputerName)'" } | Out-String))

# Priority 2: Servers (High)
`$servers = @(
$($Finding.Findings | Where-Object { $_.ComputerType -eq 'Server' } | ForEach-Object { "    '$($_.ComputerName)'" } | Out-String))

# Priority 3: Workstations (Medium)
`$workstations = @(
$($Finding.Findings | Where-Object { $_.ComputerType -eq 'Workstation' } | ForEach-Object { "    '$($_.ComputerName)'" } | Out-String))

#############################################################################
# Step 2: Verify Connectivity
#############################################################################

foreach (`$computer in (`$dcs + `$servers + `$workstations)) {
    `$reachable = Test-Connection -ComputerName `$computer -Count 1 -Quiet
    Write-Host "`$computer : `$(if (`$reachable) { 'Reachable' } else { 'Offline' })"
}

#############################################################################
# Step 3: Deploy EDR Agent (Provider-Specific)
#############################################################################

# For CrowdStrike Falcon:
# Use host groups or policies for automated deployment
# Manual: Copy and run CsInstall.exe on each system

# For Microsoft Defender for Endpoint:

# Option A: Intune/SCCM deployment (recommended)
# Configure onboarding package in Microsoft 365 Defender portal

# Option B: Group Policy (GPO deployment)
# Create GPO with startup script to run onboarding script

# Option C: Manual PowerShell onboarding
# Download onboarding script from M365 Defender portal:
# https://security.microsoft.com/preferences2/onboarding

# Example for remote deployment:
`$onboardingScript = 'C:\Temp\WindowsDefenderATPOnboardingScript.cmd'

foreach (`$computer in (`$dcs + `$servers)) {
    if (Test-Connection -ComputerName `$computer -Count 1 -Quiet) {
        Copy-Item -Path `$onboardingScript -Destination "\\`$computer\C$\Temp\" -Force
        Invoke-Command -ComputerName `$computer -ScriptBlock {
            & C:\Temp\WindowsDefenderATPOnboardingScript.cmd
        }
    }
}

#############################################################################
# Step 4: Verify Deployment
#############################################################################

# After deployment, verify in EDR console or via AD-Scout:
# Connect-ADScoutEDR -Provider DefenderATP -TenantId `$tenantId -ClientId `$clientId ...
# Get-ADScoutEDRHost -Filter @{ Platform = 'Windows' }

"@
            return $commands
        }
    }
}

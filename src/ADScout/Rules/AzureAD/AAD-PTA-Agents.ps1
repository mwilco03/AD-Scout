<#
.SYNOPSIS
    Detects Pass-through Authentication agent security issues.

.DESCRIPTION
    PTA agents validate authentication requests against on-premises AD. These
    agents are high-value targets as they process credentials. This rule checks
    for PTA agent security issues.

.NOTES
    Rule ID    : AAD-PTA-Agents
    Category   : AzureAD
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AAD-PTA-Agents'
    Version     = '1.0.0'
    Category    = 'AzureAD'
    Title       = 'Pass-through Authentication Agent Security'
    Description = 'Identifies security issues with Azure AD Pass-through Authentication agents that validate credentials against on-premises AD.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'PTA Overview'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta' }
        @{ Title = 'PTA Security'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-security-deep-dive' }
        @{ Title = 'PTA Agent Attacks'; Url = 'https://aadinternals.com/post/pta/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1556.007', 'T1550')  # Hybrid Identity, Use Alternate Authentication Material
    }

    CIS   = @('5.1.6')
    STIG  = @('V-254460')
    ANSSI = @('R54')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Find PTA agent servers
            # PTA agents register as service principals in Azure AD
            # On-prem, look for the PTA connector service

            # Check for computers with PTA agent installed
            $potentialPTAServers = @()

            # Method 1: Check for AAD Connect servers (often run PTA)
            $aadServers = Get-ADComputer -Filter {
                Description -like '*Azure AD Connect*' -or
                Description -like '*PTA*' -or
                Description -like '*Pass-through*'
            } -Properties * -ErrorAction SilentlyContinue

            $potentialPTAServers += $aadServers

            # Method 2: Check computers in known locations
            $adminComputers = Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=domain,DC=com" `
                -Properties * -ErrorAction SilentlyContinue | Select-Object -First 50

            foreach ($computer in ($potentialPTAServers + $aadServers)) {
                if (-not $computer) { continue }

                $serverName = $computer.Name
                $issues = @()
                $riskLevel = 'Medium'
                $hasPTA = $false

                try {
                    $ptaStatus = Invoke-Command -ComputerName $serverName -ScriptBlock {
                        $result = @{
                            PTAInstalled = $false
                            PTAServiceRunning = $false
                            PTAVersion = $null
                            CertificateExpiry = $null
                            LastActivity = $null
                        }

                        # Check for PTA connector service
                        $ptaService = Get-Service -Name 'AzureADConnectAuthenticationAgent' -ErrorAction SilentlyContinue
                        if ($ptaService) {
                            $result.PTAInstalled = $true
                            $result.PTAServiceRunning = $ptaService.Status -eq 'Running'
                        }

                        # Check for PTA certificate
                        $ptaCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
                            $_.Subject -match 'Azure|AAD|Microsoft' -and
                            $_.EnhancedKeyUsageList.FriendlyName -contains 'Client Authentication'
                        }

                        if ($ptaCerts) {
                            $result.CertificateExpiry = ($ptaCerts | Sort-Object NotAfter | Select-Object -First 1).NotAfter
                        }

                        # Check PTA agent executable
                        $ptaPath = 'C:\Program Files\Microsoft Azure AD Connect Authentication Agent'
                        if (Test-Path $ptaPath) {
                            $result.PTAInstalled = $true
                            $agentExe = Get-ChildItem "$ptaPath\AzureADConnectAuthenticationAgentService.exe" -ErrorAction SilentlyContinue
                            if ($agentExe) {
                                $result.PTAVersion = $agentExe.VersionInfo.FileVersion
                            }
                        }

                        return $result
                    } -ErrorAction SilentlyContinue

                    if ($ptaStatus.PTAInstalled) {
                        $hasPTA = $true

                        if (-not $ptaStatus.PTAServiceRunning) {
                            $issues += 'PTA service NOT running'
                            $riskLevel = 'High'
                        }

                        # Check certificate expiry
                        if ($ptaStatus.CertificateExpiry) {
                            $daysToExpiry = ($ptaStatus.CertificateExpiry - (Get-Date)).Days
                            if ($daysToExpiry -lt 30) {
                                $issues += "Certificate expires in $daysToExpiry days"
                                $riskLevel = 'High'
                            } elseif ($daysToExpiry -lt 90) {
                                $issues += "Certificate expires in $daysToExpiry days"
                            }
                        }

                        # Check server security
                        if ($computer.TrustedForDelegation) {
                            $issues += 'Server trusted for delegation (security risk)'
                            $riskLevel = 'High'
                        }

                        if ($computer.DistinguishedName -notmatch 'Tier.?0|Admin|Privileged') {
                            $issues += 'Not in Tier 0/Admin OU'
                            $riskLevel = 'High'
                        }

                        # Check OS version
                        if ($computer.OperatingSystem -match '2012|2008') {
                            $issues += "Old OS: $($computer.OperatingSystem)"
                            $riskLevel = 'High'
                        }
                    }

                } catch {
                    if ($aadServers.Name -contains $serverName) {
                        # Expected to have PTA, but check failed
                        $hasPTA = $true
                        $issues += 'Unable to verify PTA status'
                        $riskLevel = 'Medium'
                    }
                }

                if ($hasPTA -and ($issues.Count -gt 0)) {
                    $findings += [PSCustomObject]@{
                        ServerName        = $serverName
                        PTAInstalled      = $ptaStatus.PTAInstalled
                        PTARunning        = $ptaStatus.PTAServiceRunning
                        PTAVersion        = $ptaStatus.PTAVersion
                        CertExpiry        = $ptaStatus.CertificateExpiry
                        OperatingSystem   = $computer.OperatingSystem
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        SecurityNote      = 'PTA agents process credentials - treat as Tier 0'
                        DistinguishedName = $computer.DistinguishedName
                    }
                }
            }

            # General PTA security findings
            if ($findings.Count -eq 0) {
                # Check if PTA might be in use but we couldn't detect agents
                $aadUsers = Get-ADUser -Filter { SamAccountName -like 'AAD_*' } -ErrorAction SilentlyContinue
                if ($aadUsers) {
                    $findings += [PSCustomObject]@{
                        ServerName        = 'Unknown'
                        PTAInstalled      = 'Possibly'
                        PTARunning        = 'Unknown'
                        PTAVersion        = 'Unknown'
                        CertExpiry        = 'Unknown'
                        OperatingSystem   = 'N/A'
                        Issues            = 'AAD connector accounts exist but PTA agents not found'
                        RiskLevel         = 'Low'
                        SecurityNote      = 'Manual verification required'
                        DistinguishedName = 'N/A'
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                ServerName        = 'Error'
                PTAInstalled      = 'Unknown'
                PTARunning        = 'Unknown'
                PTAVersion        = 'Unknown'
                CertExpiry        = 'Unknown'
                OperatingSystem   = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                SecurityNote      = 'Manual verification required'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Secure PTA agents with Tier 0 protections and monitor for abuse.'
        Impact      = 'Low - Security hardening does not affect authentication functionality.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Pass-through Authentication Agent Security
#############################################################################
#
# PTA agents are critical security components:
# - They validate user credentials against on-prem AD
# - They have access to plaintext passwords during validation
# - Compromised agents can intercept/forge authentications
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.ServerName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Inventory PTA Agents
#############################################################################

# Find all servers with PTA agent:
`$servers = Get-ADComputer -Filter { Description -like '*Azure*' -or Description -like '*PTA*' }

foreach (`$server in `$servers) {
    `$status = Invoke-Command -ComputerName `$server.Name -ScriptBlock {
        `$svc = Get-Service 'AzureADConnectAuthenticationAgent' -ErrorAction SilentlyContinue
        @{
            Name = `$env:COMPUTERNAME
            PTAInstalled = `$null -ne `$svc
            Status = `$svc.Status
        }
    } -ErrorAction SilentlyContinue

    if (`$status.PTAInstalled) {
        Write-Host "`$(`$status.Name): PTA Agent - `$(`$status.Status)" -ForegroundColor Cyan
    }
}

# Also check Azure AD for registered agents:
# In Azure Portal: Azure AD -> Azure AD Connect -> Pass-through authentication

#############################################################################
# Step 2: Deploy Multiple PTA Agents
#############################################################################

# Microsoft recommends 3+ PTA agents for:
# - High availability
# - Load distribution
# - If one is compromised, others still work

# Download additional PTA agents from:
# Azure Portal -> Azure AD -> Azure AD Connect -> Pass-through authentication
# -> Download Agent

#############################################################################
# Step 3: Secure PTA Agent Servers
#############################################################################

# PTA servers must be treated as Tier 0:

# Move to Tier 0 OU:
`$ptaServer = Get-ADComputer -Identity 'PTAServer01'
`$tier0OU = "OU=Tier0,OU=Admin,DC=domain,DC=com"
# Move-ADObject -Identity `$ptaServer.DistinguishedName -TargetPath `$tier0OU

# Restrict logon rights:
# Only Tier 0 admins should access PTA servers
# Configure via GPO: User Rights Assignment

# Block internet (except Azure AD endpoints):
# PTA only needs outbound to:
# - *.msappproxy.net (port 443)
# - *.servicebus.windows.net (port 443)

# Enable Credential Guard:
# Protects credentials in memory

#############################################################################
# Step 4: Monitor PTA Agent Activity
#############################################################################

# PTA agents log to:
# - Application Event Log (Azure AD Connect source)
# - C:\ProgramData\Microsoft\Azure AD Connect Authentication Agent\Trace

# Key events to monitor:
# - Agent startup/shutdown
# - Authentication failures
# - Connection issues to Azure AD

# Check agent logs:
Invoke-Command -ComputerName 'PTAServer01' -ScriptBlock {
    Get-WinEvent -LogName 'Application' -MaxEvents 100 |
        Where-Object { `$_.ProviderName -match 'Azure|AAD' } |
        Select-Object TimeCreated, Id, Message
}

#############################################################################
# Step 5: Certificate Management
#############################################################################

# PTA agents use certificates to authenticate to Azure AD
# Certificates auto-renew but should be monitored

# Check certificate expiry:
Invoke-Command -ComputerName 'PTAServer01' -ScriptBlock {
    Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { `$_.Subject -match 'Azure|AAD' } |
        Select-Object Subject, NotAfter,
            @{N='DaysLeft';E={(`$_.NotAfter - (Get-Date)).Days}}
}

# Alert if certificates expire within 30 days

#############################################################################
# Step 6: Prevent PTA Agent Abuse
#############################################################################

# Attackers can abuse PTA agents to:
# 1. Harvest credentials (intercept auth requests)
# 2. Bypass authentication (forge responses)
# 3. Maintain persistence

# Mitigations:
# - Restrict who can install/modify PTA agents
# - Monitor agent binaries for changes
# - Use code signing verification
# - Enable Credential Guard

# Check PTA binary integrity:
Invoke-Command -ComputerName 'PTAServer01' -ScriptBlock {
    `$agentPath = 'C:\Program Files\Microsoft Azure AD Connect Authentication Agent'
    Get-ChildItem `$agentPath -Recurse |
        Get-FileHash |
        Select-Object Path, Hash
} | Export-Csv 'C:\Baseline\PTA_Hashes.csv'

#############################################################################
# Step 7: Consider Hybrid Identity Alternatives
#############################################################################

# PTA tradeoffs vs other methods:
#
# PTA:
# + No password hashes in cloud
# + Real-time policy evaluation
# - Requires on-prem agents
# - Agent is attack target
#
# Password Hash Sync:
# + Simpler architecture
# + Works during on-prem outage
# - Hashes stored in cloud
#
# Federation (ADFS):
# + Most control
# - Most complex
# - On-prem dependency

#############################################################################
# Verification
#############################################################################

# Verify all PTA agents are healthy:
# Azure Portal -> Azure AD -> Azure AD Connect -> Pass-through authentication

# Check agent status locally:
foreach (`$server in `$servers) {
    `$status = Invoke-Command -ComputerName `$server.Name -ScriptBlock {
        `$svc = Get-Service 'AzureADConnectAuthenticationAgent' -EA SilentlyContinue
        `$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -match 'Azure' } |
            Sort-Object NotAfter | Select-Object -First 1
        @{
            Name = `$env:COMPUTERNAME
            Status = `$svc.Status
            CertExpiry = `$cert.NotAfter
        }
    } -ErrorAction SilentlyContinue

    if (`$status) {
        Write-Host "`$(`$status.Name): `$(`$status.Status), Cert: `$(`$status.CertExpiry)"
    }
}

"@
            return $commands
        }
    }
}

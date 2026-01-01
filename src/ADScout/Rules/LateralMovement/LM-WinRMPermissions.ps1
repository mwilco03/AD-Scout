<#
.SYNOPSIS
    Detects overly permissive WinRM access that enables lateral movement.

.DESCRIPTION
    WinRM (Windows Remote Management) is commonly used for legitimate administration
    but can enable lateral movement if permissions are too broad. This rule checks
    for WinRM exposure on sensitive systems.

.NOTES
    Rule ID    : LM-WinRMPermissions
    Category   : LateralMovement
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'LM-WinRMPermissions'
    Version     = '1.0.0'
    Category    = 'LateralMovement'
    Title       = 'Overly Permissive WinRM Access'
    Description = 'Identifies systems with overly permissive WinRM configurations that could enable lateral movement attacks.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'DomainControllers,Computers'

    References  = @(
        @{ Title = 'WinRM Security'; Url = 'https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' }
        @{ Title = 'Lateral Movement via WinRM'; Url = 'https://attack.mitre.org/techniques/T1021/006/' }
        @{ Title = 'WinRM Hardening'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-calls-to-sam' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0002')  # Lateral Movement, Execution
        Techniques = @('T1021.006', 'T1059.001')  # Remote Services: WinRM, PowerShell
    }

    CIS   = @('18.9.97.2.1')
    STIG  = @('V-254449')
    ANSSI = @('R37')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check Domain Controllers first
        $systemsToCheck = @()
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $systemsToCheck += @{
                    Name = if ($dc.Name) { $dc.Name } else { $dc.DnsHostName }
                    Type = 'DomainController'
                    DN = $dc.DistinguishedName
                    Critical = $true
                }
            }
        }

        foreach ($system in $systemsToCheck) {
            if (-not $system.Name) { continue }

            try {
                $winrmConfig = Invoke-Command -ComputerName $system.Name -ScriptBlock {
                    $result = @{
                        WinRMEnabled = $false
                        HTTPEnabled = $false
                        HTTPSEnabled = $false
                        AllowUnencrypted = $false
                        TrustedHosts = $null
                        AuthMethods = @()
                        IPFilterEnabled = $false
                        Permissions = @()
                    }

                    # Check if WinRM is running
                    $winrmService = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
                    $result.WinRMEnabled = $winrmService.Status -eq 'Running'

                    if ($result.WinRMEnabled) {
                        # Check listeners
                        $listeners = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue
                        foreach ($listener in $listeners) {
                            if ($listener.Transport -eq 'HTTP') {
                                $result.HTTPEnabled = $true
                            }
                            if ($listener.Transport -eq 'HTTPS') {
                                $result.HTTPSEnabled = $true
                            }
                        }

                        # Check if unencrypted traffic is allowed
                        $config = Get-WSManInstance -ResourceURI winrm/config/service -ErrorAction SilentlyContinue
                        if ($config) {
                            $result.AllowUnencrypted = $config.AllowUnencrypted
                        }

                        # Check trusted hosts
                        $trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
                        $result.TrustedHosts = $trustedHosts

                        # Check authentication methods
                        $auth = Get-Item WSMan:\localhost\Service\Auth\* -ErrorAction SilentlyContinue
                        $result.AuthMethods = $auth | Where-Object { $_.Value -eq 'true' } | Select-Object -ExpandProperty Name

                        # Check IP filter
                        $ipFilter = (Get-Item WSMan:\localhost\Service\IPv4Filter -ErrorAction SilentlyContinue).Value
                        $result.IPFilterEnabled = ($ipFilter -and $ipFilter -ne '*')

                        # Get WinRM permissions (SDDL)
                        try {
                            $rootSDDL = (Get-Item WSMan:\localhost\Service\RootSDDL -ErrorAction SilentlyContinue).Value
                            if ($rootSDDL) {
                                $sd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($true, $false, $rootSDDL)
                                foreach ($ace in $sd.DiscretionaryAcl) {
                                    try {
                                        $sid = $ace.SecurityIdentifier
                                        $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
                                        $result.Permissions += "$account"
                                    } catch {
                                        $result.Permissions += $ace.SecurityIdentifier.Value
                                    }
                                }
                            }
                        } catch {}
                    }

                    return $result
                } -ErrorAction SilentlyContinue

                $issues = @()
                $isVulnerable = $false

                if ($winrmConfig.WinRMEnabled) {
                    # Check for HTTP without HTTPS
                    if ($winrmConfig.HTTPEnabled -and -not $winrmConfig.HTTPSEnabled) {
                        $issues += 'WinRM HTTP enabled without HTTPS'
                        $isVulnerable = $true
                    }

                    # Check for unencrypted traffic
                    if ($winrmConfig.AllowUnencrypted) {
                        $issues += 'Unencrypted WinRM traffic allowed'
                        $isVulnerable = $true
                    }

                    # Check trusted hosts
                    if ($winrmConfig.TrustedHosts -eq '*') {
                        $issues += 'TrustedHosts = * (any host trusted)'
                        $isVulnerable = $true
                    }

                    # Check for Basic auth (credentials sent in clear)
                    if ($winrmConfig.AuthMethods -contains 'Basic') {
                        $issues += 'Basic authentication enabled'
                        $isVulnerable = $true
                    }

                    # Check for no IP filter on critical systems
                    if ($system.Critical -and -not $winrmConfig.IPFilterEnabled) {
                        $issues += 'No IP filter - WinRM accessible from any IP'
                        $isVulnerable = $true
                    }

                    # Check for overly broad permissions
                    $dangerousGroups = @('Everyone', 'Authenticated Users', 'Domain Users', 'Users')
                    foreach ($perm in $winrmConfig.Permissions) {
                        foreach ($group in $dangerousGroups) {
                            if ($perm -match $group) {
                                $issues += "WinRM accessible by $group"
                                $isVulnerable = $true
                            }
                        }
                    }
                }

                if ($isVulnerable) {
                    $findings += [PSCustomObject]@{
                        ComputerName     = $system.Name
                        SystemType       = $system.Type
                        WinRMEnabled     = $winrmConfig.WinRMEnabled
                        HTTPEnabled      = $winrmConfig.HTTPEnabled
                        HTTPSEnabled     = $winrmConfig.HTTPSEnabled
                        AllowUnencrypted = $winrmConfig.AllowUnencrypted
                        TrustedHosts     = if ($winrmConfig.TrustedHosts) { $winrmConfig.TrustedHosts } else { 'Not set' }
                        AuthMethods      = ($winrmConfig.AuthMethods -join ', ')
                        IPFilter         = $winrmConfig.IPFilterEnabled
                        Issues           = ($issues -join '; ')
                        RiskLevel        = if ($system.Critical) { 'High' } else { 'Medium' }
                        DistinguishedName = $system.DN
                    }
                }

            } catch {
                # WinRM check failed - this might mean WinRM is not enabled
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict WinRM access to authorized administrators and management systems only.'
        Impact      = 'Medium - May affect remote management. Test access requirements before implementing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# WinRM Security Hardening
#############################################################################
#
# WinRM enables remote PowerShell and management capabilities.
# Overly permissive configurations allow lateral movement.
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.ComputerName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Enable HTTPS and Disable HTTP (If Possible)
#############################################################################

# Create HTTPS listener with certificate:
`$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
    `$_.Subject -match `$env:COMPUTERNAME -and
    `$_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication'
} | Select-Object -First 1

if (`$cert) {
    New-WSManInstance -ResourceURI winrm/config/Listener `
        -SelectorSet @{Address='*'; Transport='HTTPS'} `
        -ValueSet @{CertificateThumbprint=`$cert.Thumbprint}

    # Disable HTTP listener:
    Remove-WSManInstance -ResourceURI winrm/config/Listener `
        -SelectorSet @{Address='*'; Transport='HTTP'}
}

#############################################################################
# Step 2: Disable Unencrypted Traffic
#############################################################################

# Ensure all traffic is encrypted:
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value `$false

# Require encryption for client connections:
Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value `$false

#############################################################################
# Step 3: Configure Trusted Hosts Properly
#############################################################################

# Clear wildcard trusted hosts:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force

# Only trust specific management systems if needed:
# Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'mgmtserver1.domain.com,mgmtserver2.domain.com'

#############################################################################
# Step 4: Disable Basic Authentication
#############################################################################

# Disable Basic auth (sends credentials in clear):
Set-Item WSMan:\localhost\Service\Auth\Basic -Value `$false
Set-Item WSMan:\localhost\Client\Auth\Basic -Value `$false

# Enable Kerberos and Negotiate:
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value `$true
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value `$true

# Disable CredSSP if not needed:
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value `$false

#############################################################################
# Step 5: Restrict WinRM Permissions
#############################################################################

# Get current SDDL:
`$currentSDDL = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
Write-Host "Current SDDL: `$currentSDDL"

# Create restrictive SDDL (only Domain Admins and Remote Management Users):
# O:NS - Owner: Network Service
# G:BA - Group: Built-in Administrators
# D: - DACL
# (A;;GA;;;BA) - Full access for Built-in Administrators
# (A;;GA;;;DA) - Full access for Domain Admins
# (A;;GR;;;RM) - Read access for Remote Management Users

`$restrictedSDDL = 'O:NSG:BAD:(A;;GA;;;BA)(A;;GA;;;DA)'

# Apply new SDDL:
Set-Item WSMan:\localhost\Service\RootSDDL -Value `$restrictedSDDL

#############################################################################
# Step 6: Configure IP Filters
#############################################################################

# Restrict WinRM to specific management subnets:
# Set-Item WSMan:\localhost\Service\IPv4Filter -Value '192.168.10.0-192.168.10.255,10.0.0.1-10.0.0.50'
# Set-Item WSMan:\localhost\Service\IPv6Filter -Value ''

# For Domain Controllers, only allow from management subnet:
`$mgmtSubnet = '192.168.10.0-192.168.10.255'  # Adjust to your environment
Set-Item WSMan:\localhost\Service\IPv4Filter -Value `$mgmtSubnet

#############################################################################
# Step 7: Use GPO for Consistent Configuration
#############################################################################

# Configure WinRM via Group Policy:
# Computer Configuration -> Administrative Templates -> Windows Components
# -> Windows Remote Management (WinRM) -> WinRM Service

# Key settings:
# - Allow remote server management through WinRM: Enabled (with IP filters)
# - Allow Basic authentication: Disabled
# - Allow unencrypted traffic: Disabled
# - Disallow Negotiate authentication: Disabled (needed for Kerberos)

#############################################################################
# Step 8: Enable WinRM Logging
#############################################################################

# Enable operational logging:
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true

# Enable analytic logging (verbose):
wevtutil sl Microsoft-Windows-WinRM/Analytic /e:true

# Monitor for suspicious activity:
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message

#############################################################################
# Verification
#############################################################################

# Verify WinRM configuration:
winrm get winrm/config

# Test connectivity:
Test-WSMan -ComputerName localhost

"@
            return $commands
        }
    }
}

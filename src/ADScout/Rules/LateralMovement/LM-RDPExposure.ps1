<#
.SYNOPSIS
    Detects RDP exposure on sensitive systems like Domain Controllers.

.DESCRIPTION
    RDP on Domain Controllers and other Tier 0 systems increases attack surface.
    This rule checks for RDP enabled on sensitive systems and identifies
    overly permissive RDP configurations.

.NOTES
    Rule ID    : LM-RDPExposure
    Category   : LateralMovement
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'LM-RDPExposure'
    Version     = '1.0.0'
    Category    = 'LateralMovement'
    Title       = 'RDP Enabled on Sensitive Systems'
    Description = 'Identifies Domain Controllers and sensitive systems with RDP enabled, which increases attack surface for lateral movement and credential theft.'
    Severity    = 'Medium'
    Weight      = 40
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'RDP Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-security' }
        @{ Title = 'Lateral Movement via RDP'; Url = 'https://attack.mitre.org/techniques/T1021/001/' }
        @{ Title = 'Tier 0 Hardening'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0006')  # Lateral Movement, Credential Access
        Techniques = @('T1021.001', 'T1563.002')  # RDP, RDP Hijacking
    }

    CIS   = @('18.9.60.1')
    STIG  = @('V-254450')
    ANSSI = @('R38')

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
                    $rdpConfig = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            RDPEnabled = $false
                            NLA = $false
                            Port = 3389
                            SecurityLayer = $null
                            EncryptionLevel = $null
                            FirewallOpen = $false
                            AllowedGroups = @()
                            RestrictedAdmin = $false
                            RemoteCredentialGuard = $false
                        }

                        # Check if RDP is enabled
                        $rdpKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
                        $result.RDPEnabled = $rdpKey.fDenyTSConnections -eq 0

                        if ($result.RDPEnabled) {
                            # Check NLA requirement
                            $nlaKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                            $result.NLA = $nlaKey.UserAuthentication -eq 1

                            # Check security layer
                            $secLayer = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -ErrorAction SilentlyContinue
                            $result.SecurityLayer = switch ($secLayer.SecurityLayer) {
                                0 { 'Native RDP (Weak)' }
                                1 { 'Negotiate' }
                                2 { 'TLS (Recommended)' }
                                default { 'Unknown' }
                            }

                            # Check encryption level
                            $encLevel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue
                            $result.EncryptionLevel = switch ($encLevel.MinEncryptionLevel) {
                                1 { 'Low' }
                                2 { 'Client Compatible' }
                                3 { 'High' }
                                4 { 'FIPS' }
                                default { 'Unknown' }
                            }

                            # Check port
                            $portKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction SilentlyContinue
                            $result.Port = $portKey.PortNumber

                            # Check firewall rule
                            $fwRule = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
                                Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }
                            $result.FirewallOpen = $null -ne $fwRule

                            # Get allowed groups
                            $rdpUsers = net localgroup 'Remote Desktop Users' 2>$null
                            $result.AllowedGroups = $rdpUsers | Where-Object { $_ -match '^\w' -and $_ -notmatch 'Members|command completed|---' }

                            # Check Restricted Admin mode
                            $restrictedAdmin = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableRestrictedAdmin' -ErrorAction SilentlyContinue
                            $result.RestrictedAdmin = $restrictedAdmin.DisableRestrictedAdmin -eq 0

                            # Check Remote Credential Guard
                            $rcg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableRestrictedAdminOutboundCreds' -ErrorAction SilentlyContinue
                            $result.RemoteCredentialGuard = $rcg.DisableRestrictedAdminOutboundCreds -eq 1
                        }

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()
                    $isVulnerable = $false

                    if ($rdpConfig.RDPEnabled) {
                        $issues += 'RDP is ENABLED on Domain Controller'
                        $isVulnerable = $true

                        if (-not $rdpConfig.NLA) {
                            $issues += 'Network Level Authentication (NLA) not required'
                        }

                        if ($rdpConfig.SecurityLayer -eq 'Native RDP (Weak)') {
                            $issues += 'Using weak Native RDP security layer'
                        }

                        if ($rdpConfig.EncryptionLevel -in @('Low', 'Client Compatible')) {
                            $issues += "Weak encryption level: $($rdpConfig.EncryptionLevel)"
                        }

                        if (-not $rdpConfig.RestrictedAdmin -and -not $rdpConfig.RemoteCredentialGuard) {
                            $issues += 'Neither Restricted Admin nor Remote Credential Guard enabled'
                        }

                        # Check for dangerous groups
                        $dangerousGroups = @('Everyone', 'Authenticated Users', 'Domain Users', 'Users')
                        foreach ($group in $rdpConfig.AllowedGroups) {
                            foreach ($dangerous in $dangerousGroups) {
                                if ($group -match $dangerous) {
                                    $issues += "Overly permissive RDP access: $group"
                                }
                            }
                        }
                    }

                    if ($isVulnerable) {
                        $findings += [PSCustomObject]@{
                            DomainController       = $dcName
                            RDPEnabled             = $rdpConfig.RDPEnabled
                            NLARequired            = $rdpConfig.NLA
                            SecurityLayer          = $rdpConfig.SecurityLayer
                            EncryptionLevel        = $rdpConfig.EncryptionLevel
                            Port                   = $rdpConfig.Port
                            AllowedGroups          = ($rdpConfig.AllowedGroups -join ', ')
                            RestrictedAdmin        = $rdpConfig.RestrictedAdmin
                            RemoteCredentialGuard  = $rdpConfig.RemoteCredentialGuard
                            Issues                 = ($issues -join '; ')
                            RiskLevel              = 'Medium'
                            DistinguishedName      = $dc.DistinguishedName
                        }
                    }

                } catch {
                    # RDP check failed
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable RDP on Domain Controllers or implement strong RDP security controls.'
        Impact      = 'Medium - May affect remote administration workflows. Use alternative methods like Windows Admin Center.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# RDP Security Hardening for Domain Controllers
#############################################################################
#
# RDP on Domain Controllers increases attack surface:
# - Credential exposure (unless Restricted Admin/RCG enabled)
# - RDP Hijacking attacks
# - Brute force attacks
# - Lateral movement path
#
# Current exposure:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# Option 1: Disable RDP on Domain Controllers (Recommended)
#############################################################################

# Domain Controllers should be managed via:
# - PowerShell Remoting (WinRM)
# - Windows Admin Center
# - Server Manager
# - RSAT tools

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Disable RDP
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' -Value 1 -Type DWord

        # Disable RDP firewall rule
        Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'

        Write-Host "Disabled RDP on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Option 2: Harden RDP If It Must Be Enabled
#############################################################################

# If RDP must remain enabled, implement these controls:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Require NLA
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'UserAuthentication' -Value 1 -Type DWord

        # Use TLS security layer
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'SecurityLayer' -Value 2 -Type DWord

        # Require High encryption
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'MinEncryptionLevel' -Value 3 -Type DWord

        # Enable Restricted Admin mode
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'DisableRestrictedAdmin' -Value 0 -Type DWord

        Write-Host "Hardened RDP on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

#############################################################################
# Step 3: Restrict RDP Access
#############################################################################

# Remove broad groups from Remote Desktop Users:
`$groupsToRemove = @('Domain Users', 'Users', 'Authenticated Users')

foreach (`$dc in `$dcs) {
    foreach (`$group in `$groupsToRemove) {
        Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
            param(`$groupName)
            net localgroup 'Remote Desktop Users' `$groupName /delete 2>$null
        } -ArgumentList `$group
    }
}

# Add only specific admin group:
# net localgroup 'Remote Desktop Users' 'Domain Admins' /add

#############################################################################
# Step 4: Configure IP Restrictions
#############################################################################

# Restrict RDP to specific management subnets:
`$managementSubnet = '192.168.10.0/24'  # Adjust to your environment

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        param(`$subnet)

        # Remove default RDP rule
        Get-NetFirewallRule -DisplayGroup 'Remote Desktop' |
            Disable-NetFirewallRule

        # Create restrictive rule
        New-NetFirewallRule -DisplayName 'RDP - Admin Subnet Only' `
            -Direction Inbound -Protocol TCP -LocalPort 3389 `
            -RemoteAddress `$subnet -Action Allow

    } -ArgumentList `$managementSubnet
}

#############################################################################
# Step 5: Enable RDP Auditing
#############################################################################

# Enable detailed RDP logging:
# Event ID 4624: Logon (Type 10 = RemoteInteractive)
# Event ID 4625: Failed logon
# Event ID 4778: Session reconnected
# Event ID 4779: Session disconnected

# Monitor for suspicious RDP activity:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 100 | Where-Object {
    `$_.Message -match 'Logon Type:\s+10'
} | Select-Object TimeCreated, @{N='User';E={`$_.Properties[5].Value}},
    @{N='SourceIP';E={`$_.Properties[18].Value}}

#############################################################################
# Step 6: Use Remote Credential Guard
#############################################################################

# For clients connecting to DCs (when RDP is enabled):
# Forces RDP to use Kerberos delegation instead of sending credentials

# On client computers (via GPO):
# Computer Configuration -> Admin Templates -> System -> Credentials Delegation
# -> Restrict delegation of credentials to remote servers: Enabled
# -> Use the following restricted mode: Require Remote Credential Guard

# Registry (on clients):
# Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
#     -Name 'RestrictedRemoteAdministration' -Value 1 -Type DWord

#############################################################################
# Verification
#############################################################################

# Verify RDP status on all DCs:
foreach (`$dc in `$dcs) {
    `$status = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
        `$nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
        @{
            ComputerName = `$env:COMPUTERNAME
            RDPDisabled = `$rdp.fDenyTSConnections -eq 1
            NLARequired = `$nla.UserAuthentication -eq 1
        }
    }
    `$color = if (`$status.RDPDisabled) { 'Green' } else { 'Red' }
    Write-Host "`$(`$status.ComputerName): RDPDisabled=`$(`$status.RDPDisabled), NLA=`$(`$status.NLARequired)" -ForegroundColor `$color
}

"@
            return $commands
        }
    }
}

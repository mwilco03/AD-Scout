<#
.SYNOPSIS
    Detects domain controllers with LDAP Channel Binding not enforced.

.DESCRIPTION
    LDAP Channel Binding prevents NTLM relay attacks against LDAP/S. Without this
    protection, attackers can relay credentials to create privileged accounts or
    modify AD objects. Microsoft is enforcing this in 2025+.

.NOTES
    Rule ID    : A-DCLdapChannelBinding
    Category   : Anomalies
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'A-DCLdapChannelBinding'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAP Channel Binding Not Enforced'
    Description = 'Identifies domain controllers that do not enforce LDAP Channel Binding, making them vulnerable to NTLM relay attacks against LDAP services.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'KB4520412 - LDAP Channel Binding'; Url = 'https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a' }
        @{ Title = 'LDAP Relay Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/' }
        @{ Title = 'Microsoft Enforcement Timeline'; Url = 'https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/ldap-channel-binding-and-ldap-signing-requirements-march-2020/ba-p/921536' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001')  # LLMNR/NBT-NS Poisoning and SMB Relay
    }

    CIS   = @('5.5')
    STIG  = @('V-36687')
    ANSSI = @('R29')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
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
                    $ldapSettings = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            ChannelBinding = $null
                            LdapSigning = $null
                            OSVersion = [Environment]::OSVersion.Version.ToString()
                        }

                        # LDAP Channel Binding (LdapEnforceChannelBinding)
                        # 0 = Never (Vulnerable)
                        # 1 = When supported (Default - still allows bypass)
                        # 2 = Always (Secure)
                        $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                        $cbValue = Get-ItemProperty -Path $ntdsPath -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue
                        $result.ChannelBinding = $cbValue.LdapEnforceChannelBinding

                        # LDAP Signing (LDAPServerIntegrity)
                        # 0 = None
                        # 1 = Require signing (Secure for signing)
                        # 2 = Require signing (also secure)
                        $signingValue = Get-ItemProperty -Path $ntdsPath -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue
                        $result.LdapSigning = $signingValue.LDAPServerIntegrity

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()
                    $isVulnerable = $false

                    # Check Channel Binding
                    if ($null -eq $ldapSettings.ChannelBinding -or $ldapSettings.ChannelBinding -eq 0) {
                        $issues += 'LDAP Channel Binding not configured or disabled (vulnerable to relay)'
                        $isVulnerable = $true
                    } elseif ($ldapSettings.ChannelBinding -eq 1) {
                        $issues += 'LDAP Channel Binding = 1 (when supported) - clients can bypass'
                        $isVulnerable = $true
                    }
                    # Value 2 = Always (secure)

                    # Check LDAP Signing
                    if ($null -eq $ldapSettings.LdapSigning -or $ldapSettings.LdapSigning -lt 1) {
                        $issues += 'LDAP Signing not required'
                    }

                    if ($isVulnerable) {
                        $findings += [PSCustomObject]@{
                            DomainController    = $dcName
                            ChannelBinding      = if ($null -eq $ldapSettings.ChannelBinding) { 'Not set (0)' } else { $ldapSettings.ChannelBinding }
                            LdapSigning         = if ($null -eq $ldapSettings.LdapSigning) { 'Not set' } else { $ldapSettings.LdapSigning }
                            Issues              = ($issues -join '; ')
                            OSVersion           = $ldapSettings.OSVersion
                            RiskLevel           = if ($ldapSettings.ChannelBinding -eq 0 -or $null -eq $ldapSettings.ChannelBinding) { 'Critical' } else { 'High' }
                            AttackPath          = 'NTLM relay to LDAP -> Create admin user or modify ACLs'
                            MSEnforcement       = 'Microsoft will enforce Channel Binding in 2025'
                            DistinguishedName   = $dc.DistinguishedName
                        }
                    }

                } catch {
                    # Can't check this DC, report for manual review
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        ChannelBinding      = 'Unknown (check failed)'
                        LdapSigning         = 'Unknown'
                        Issues              = 'Unable to verify LDAP security settings'
                        OSVersion           = 'Unknown'
                        RiskLevel           = 'High'
                        AttackPath          = 'Manual verification required'
                        MSEnforcement       = 'Microsoft will enforce Channel Binding in 2025'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        # If no DCs could be checked but we have DC data, report general finding
        if ($findings.Count -eq 0 -and $Data.DomainControllers.Count -gt 0) {
            # Check via GPO instead
            try {
                $gpos = Get-GPO -All -ErrorAction SilentlyContinue | Where-Object {
                    $_.DisplayName -match 'Domain Controller|DC|LDAP'
                }

                $ldapConfiguredViaGPO = $false
                foreach ($gpo in $gpos) {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                    if ($gpoReport -match 'LdapEnforceChannelBinding' -and $gpoReport -match '2') {
                        $ldapConfiguredViaGPO = $true
                        break
                    }
                }

                if (-not $ldapConfiguredViaGPO) {
                    $findings += [PSCustomObject]@{
                        DomainController    = 'All Domain Controllers'
                        ChannelBinding      = 'No GPO enforcement found'
                        LdapSigning         = 'Unknown'
                        Issues              = 'LDAP Channel Binding not enforced via GPO'
                        OSVersion           = 'Various'
                        RiskLevel           = 'High'
                        AttackPath          = 'NTLM relay to LDAP possible'
                        MSEnforcement       = 'Microsoft will enforce Channel Binding in 2025'
                        DistinguishedName   = 'N/A'
                    }
                }
            } catch {}
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable LDAP Channel Binding and LDAP Signing on all domain controllers.'
        Impact      = 'Medium - May break legacy clients that do not support channel binding. Test in compatibility mode first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# LDAP Channel Binding and Signing Remediation
#############################################################################
#
# LDAP Channel Binding prevents NTLM relay attacks against AD LDAP services.
# Without this protection, attackers can:
# - Relay captured NTLM credentials to LDAP
# - Create new privileged users
# - Modify object permissions
# - Add users to privileged groups
#
# Microsoft Enforcement Timeline:
# - 2020: Updates released with audit capabilities
# - 2024: Compatibility mode with extended audit
# - 2025: Full enforcement becomes mandatory
#
# Affected DCs:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Enable Auditing (Before Enforcement)
#############################################################################

# First, enable LDAP interface events to identify incompatible clients:

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Enable LDAP Interface Events
        # 16 = Log LDAP binds that would fail with channel binding
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
            -Name '16 LDAP Interface Events' -Value 2 -Type DWord

        Write-Host "Enabled LDAP Interface logging on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

# Monitor for Event ID 3039 (LDAP bind would fail with channel binding):
Get-WinEvent -FilterHashtable @{
    LogName = 'Directory Service'
    ID = 3039
} -MaxEvents 100 | Select-Object TimeCreated, Message

#############################################################################
# Step 2: Configure Channel Binding (Compatibility Mode First)
#############################################################################

# Enable Channel Binding in "When Supported" mode first:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LdapEnforceChannelBinding' -Value 1 -Type DWord

        Write-Host "Enabled Channel Binding (When Supported) on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

# Monitor Event ID 3039 for clients that will break with full enforcement

#############################################################################
# Step 3: Enable Full Channel Binding Enforcement
#############################################################################

# After verifying no critical applications will break:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord

        Write-Host "Enabled Full Channel Binding on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 4: Enable LDAP Signing
#############################################################################

# Require LDAP Signing on all DCs:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LDAPServerIntegrity' -Value 2 -Type DWord

        Write-Host "Enabled LDAP Signing on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 5: Configure via Group Policy (Recommended)
#############################################################################

# Create a GPO for Domain Controllers:
# Computer Configuration -> Policies -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options

# Configure:
# - Domain controller: LDAP server signing requirements = Require signing
# - Domain controller: LDAP server channel binding token requirements = Always

# PowerShell to create GPO:
`$gpoName = 'DC Security - LDAP Protection'
`$gpo = New-GPO -Name `$gpoName -Comment 'Enforces LDAP signing and channel binding'

# Link to Domain Controllers OU:
`$dcOU = "OU=Domain Controllers,`$(Get-ADDomain).DistinguishedName"
New-GPLink -Guid `$gpo.Id -Target `$dcOU

# Set registry values via GPO preferences:
# (Use GPMC or Set-GPRegistryValue)

#############################################################################
# Step 6: Verify Configuration
#############################################################################

# Check all DCs:
foreach (`$dc in `$dcs) {
    `$settings = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        @{
            ComputerName = `$env:COMPUTERNAME
            ChannelBinding = (Get-ItemProperty -Path `$ntdsPath -Name 'LdapEnforceChannelBinding' -EA SilentlyContinue).LdapEnforceChannelBinding
            LDAPSigning = (Get-ItemProperty -Path `$ntdsPath -Name 'LDAPServerIntegrity' -EA SilentlyContinue).LDAPServerIntegrity
        }
    }

    `$cbStatus = switch (`$settings.ChannelBinding) {
        0 { 'Never (VULNERABLE)' }
        1 { 'When Supported' }
        2 { 'Always (SECURE)' }
        default { 'Not Set (VULNERABLE)' }
    }

    Write-Host "`$(`$settings.ComputerName): Channel Binding = `$cbStatus, Signing = `$(`$settings.LDAPSigning)"
}

#############################################################################
# Client Compatibility Notes
#############################################################################

# Clients that may have issues with Channel Binding:
# - Older Linux LDAP clients (update to support CBT)
# - Legacy applications using simple LDAP binds
# - Some network devices and appliances
# - LDAP authentication proxies

# For incompatible clients:
# 1. Update the client software
# 2. Configure TLS (LDAPS) which has different binding requirements
# 3. As last resort, use certificate-based authentication

# DO NOT weaken channel binding to accommodate old clients
# Plan upgrades before Microsoft enforces in 2025

"@
            return $commands
        }
    }
}

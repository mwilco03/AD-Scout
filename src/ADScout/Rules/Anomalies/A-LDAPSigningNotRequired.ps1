@{
    Id          = 'A-LDAPSigningNotRequired'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAP Signing Not Required'
    Description = 'Detects when LDAP signing is not required on Domain Controllers. Without LDAP signing, attackers can perform LDAP relay attacks to authenticate as captured users and modify AD objects, potentially escalating privileges.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'LDAP Relay Attack'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'Microsoft - LDAP Signing Requirements'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server' }
        @{ Title = 'CVE-2017-8563 LDAP Relay'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-8563' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1557.001', 'T1484')  # LLMNR/NBT-NS Poisoning, Domain Policy Modification
    }

    CIS   = @('2.3.11.8', '2.3.11.9')
    STIG  = @('V-220942', 'V-220943')
    ANSSI = @('R38')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $ldapSettings = $Data.NetworkSecurity.LDAPSigningSettings

        if ($ldapSettings) {
            if (-not $ldapSettings.LDAPServerSigningRequired) {
                $findings += [PSCustomObject]@{
                    Finding                 = 'LDAP Server Signing Not Required'
                    CurrentState            = 'LDAP signing is not required on DCs'
                    RiskLevel               = 'Critical'
                    AttackVector            = 'LDAP relay via Responder/ntlmrelayx'
                    Impact                  = @(
                        'Modify AD objects (add users to groups)',
                        'Create new privileged accounts',
                        'Modify ACLs for persistence',
                        'Change service account passwords'
                    ) -join '; '
                    Vulnerabilities         = ($ldapSettings.Vulnerabilities -join '; ')
                    RequiredGPOSetting      = @{
                        Path  = 'Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options'
                        Name  = 'Domain controller: LDAP server signing requirements'
                        Value = 'Require signing'
                    }
                }
            }

            if (-not $ldapSettings.LDAPChannelBindingRequired) {
                $findings += [PSCustomObject]@{
                    Finding                 = 'LDAP Channel Binding Not Required'
                    CurrentState            = 'LDAP channel binding is not enforced'
                    RiskLevel               = 'High'
                    Impact                  = 'LDAPS connections can be relayed'
                    RegistryFix             = @{
                        Path  = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                        Name  = 'LdapEnforceChannelBinding'
                        Value = 2
                        Type  = 'DWORD'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable required LDAP signing via Group Policy on all Domain Controllers.'
        Impact      = 'Medium - May break legacy applications not supporting LDAP signing'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: LDAP SIGNING NOT REQUIRED
# ================================================================
# Without LDAP signing, attackers can relay NTLM authentication
# to LDAP and modify Active Directory objects.

# Attack example:
# 1. Capture NTLM auth via Responder/mitm6
# 2. Relay to LDAP on DC (ntlmrelayx --escalate-user)
# 3. Add user to Domain Admins or modify ACLs
# 4. Full domain compromise

# ================================================================
# ENABLE LDAP SIGNING (Domain Controllers)
# ================================================================

# Option 1: Group Policy (Recommended)
# Path: Computer Configuration > Policies > Windows Settings >
#       Security Settings > Local Policies > Security Options
#
# Setting: "Domain controller: LDAP server signing requirements"
# Value: "Require signing"

# Option 2: Registry (immediate fix)
# On each Domain Controller:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f

# Values:
# 0 = None (not recommended)
# 1 = Signing supported (negotiate)
# 2 = Signing required

# ================================================================
# ENABLE LDAP CHANNEL BINDING
# ================================================================

# Prevents LDAPS relay attacks
# On each Domain Controller:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f

# Values:
# 0 = Never
# 1 = When supported
# 2 = Always (recommended)

# ================================================================
# CLIENT-SIDE LDAP SIGNING
# ================================================================

# Also require signing from clients:
# GPO Path: Computer Configuration > Policies > Windows Settings >
#           Security Settings > Local Policies > Security Options
#
# Setting: "Network security: LDAP client signing requirements"
# Value: "Require signing"

# ================================================================
# VERIFY CONFIGURATION
# ================================================================

# Check DC registry:
`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    Write-Host "`nDC: `$(`$dc.Name)"
    Invoke-Command -ComputerName `$dc.Name -ScriptBlock {
        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
            Select-Object LDAPServerIntegrity, LdapEnforceChannelBinding
    }
}

# Test LDAP signing requirement:
# ldapsearch -H ldap://dc.domain.com -x -D "user@domain.com" -W -b "DC=domain,DC=com"
# Should fail if signing required and client doesn't support

"@
            return $commands
        }
    }
}

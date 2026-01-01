<#
.SYNOPSIS
    Detects if the MachineAccountQuota allows users to create computer accounts.

.DESCRIPTION
    By default, any authenticated user can add up to 10 computer accounts to the domain.
    This enables RBCD attacks and other privilege escalation techniques.

.NOTES
    Rule ID    : P-MachineAccountQuota
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-MachineAccountQuota'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'MachineAccountQuota Allows Computer Account Creation'
    Description = 'Detects if ms-DS-MachineAccountQuota allows authenticated users to create computer accounts, enabling RBCD and other attacks.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'RBCD Attack'; Url = 'https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a' }
        @{ Title = 'MachineAccountQuota Attack'; Url = 'https://www.yourwaf.com/blog/maq-and-rbcd/' }
        @{ Title = 'Microsoft - Computer Account Creation'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1098', 'T1136.002')  # Account Manipulation, Create Domain Account
    }

    CIS   = @('2.2.2')
    STIG  = @('V-63441')
    ANSSI = @('R17')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get the domain object
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            }

            $domainObj = [ADSI]"LDAP://$domainDN"
            $maq = $domainObj.'ms-DS-MachineAccountQuota'

            if ($null -eq $maq) {
                $maq = 10  # Default value
            }

            if ($maq -gt 0) {
                $findings += [PSCustomObject]@{
                    Setting             = 'ms-DS-MachineAccountQuota'
                    CurrentValue        = $maq
                    RecommendedValue    = 0
                    Issue               = "Any authenticated user can create $maq computer account(s)"
                    RiskLevel           = if ($maq -ge 10) { 'High' } else { 'Medium' }
                    AttackPath          = @"
1. Attacker creates computer account (they control the password)
2. Attacker configures RBCD on target using their computer
3. Attacker requests service ticket as any user to target
4. Full compromise of target system
"@
                    DistinguishedName   = $domainDN
                }
            }
        } catch {
            # Error accessing domain object
        }

        return $findings
    }

    Remediation = @{
        Description = 'Set MachineAccountQuota to 0 to prevent users from creating computer accounts. Delegate computer account creation to specific admins.'
        Impact      = 'Medium - Self-service domain join will no longer work. Admins must pre-stage or delegate permissions.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable MachineAccountQuota
#############################################################################
#
# By default, any authenticated user can create up to 10 computer accounts.
# This enables several attacks:
#
# 1. Resource-Based Constrained Delegation (RBCD) Attack
#    - Create computer account
#    - Set msDS-AllowedToActOnBehalfOfOtherIdentity on target
#    - Request S4U2Self ticket as any user
#    - Compromise target
#
# 2. Machine Account Relay
#    - Create computer account
#    - Use for NTLM relay targets
#
# 3. Kerberos Attack Chain
#    - Use computer account for various Kerberos attacks
#
# Current Setting: $($Finding.Findings[0].CurrentValue) accounts allowed
#
#############################################################################

# Set MachineAccountQuota to 0
Set-ADDomain -Identity '$((Get-ADDomain).DNSRoot)' -Replace @{'ms-DS-MachineAccountQuota'=0}

# Verify the change
Get-ADDomain | Select-Object @{N='MachineAccountQuota';E={
    (Get-ADObject `$_.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
}}

#############################################################################
# Alternative: Use PowerShell with ADSI
#############################################################################

`$domainDN = (Get-ADDomain).DistinguishedName
`$domain = [ADSI]"LDAP://`$domainDN"
`$domain.'ms-DS-MachineAccountQuota' = 0
`$domain.SetInfo()

Write-Host "MachineAccountQuota set to 0" -ForegroundColor Green

#############################################################################
# Delegate Computer Account Creation (Recommended Approach)
#############################################################################

# Create a security group for users who can join computers to domain
# New-ADGroup -Name 'Computer Join Operators' -GroupScope Global -GroupCategory Security

# Grant permissions on specific OUs
`$ou = 'OU=Workstations,DC=domain,DC=com'
`$group = 'DOMAIN\Computer Join Operators'

# Grant Create Computer Objects permission
dsacls `$ou /G "`${group}:CC;computer"

# Grant Delete Computer Objects permission (optional)
dsacls `$ou /G "`${group}:DC;computer"

# Grant Write permissions on computer objects
dsacls `$ou /G "`${group}:WP;computer"

#############################################################################
# Pre-stage Computer Accounts (Best Practice)
#############################################################################

# Create computer accounts before deploying
New-ADComputer -Name 'WORKSTATION01' -Path 'OU=Workstations,DC=domain,DC=com' `
    -ManagedBy 'HelpDesk' -Description 'Pre-staged by admin'

# Then technicians can join without needing create permissions

#############################################################################
# Detect Existing Attack Usage
#############################################################################

# Find computer accounts created by non-admins
Get-ADComputer -Filter * -Properties mS-DS-CreatorSID | ForEach-Object {
    `$creatorSID = `$_.'mS-DS-CreatorSID'
    if (`$creatorSID) {
        try {
            `$creator = (New-Object System.Security.Principal.SecurityIdentifier(`$creatorSID)).Translate([System.Security.Principal.NTAccount])
            if (`$creator -notmatch 'Domain Admins|SYSTEM|Administrator') {
                [PSCustomObject]@{
                    Computer = `$_.Name
                    Creator = `$creator.Value
                    Created = `$_.Created
                }
            }
        } catch {}
    }
} | Format-Table

"@
            return $commands
        }
    }
}

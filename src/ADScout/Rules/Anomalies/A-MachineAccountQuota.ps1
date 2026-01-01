@{
    Id          = 'A-MachineAccountQuota'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Machine Account Quota Allows User Computer Creation'
    Description = 'Detects when ms-DS-MachineAccountQuota is greater than 0, allowing any authenticated user to create computer accounts. This enables attacks like resource-based constrained delegation (RBCD) abuse and can be used for privilege escalation.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'MachineAccountQuota Abuse'; Url = 'https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd' }
        @{ Title = 'Resource-Based Constrained Delegation'; Url = 'https://attack.mitre.org/techniques/T1134/001/' }
        @{ Title = 'Microsoft Documentation'; Url = 'https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1134.001', 'T1136.002')  # Token Impersonation, Domain Account Creation
    }

    CIS   = @('2.1.1')
    STIG  = @('V-220955')
    ANSSI = @('R54')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check the domain's ms-DS-MachineAccountQuota
        try {
            $domainObj = Get-ADDomain -ErrorAction SilentlyContinue
            $quota = (Get-ADObject -Identity $domainObj.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'

            if ($quota -gt 0) {
                $findings += [PSCustomObject]@{
                    Setting             = 'ms-DS-MachineAccountQuota'
                    CurrentValue        = $quota
                    RecommendedValue    = 0
                    DomainDN            = $domainObj.DistinguishedName
                    RiskLevel           = if ($quota -ge 10) { 'Critical' } else { 'High' }
                    Impact              = @(
                        'Any user can create up to ' + $quota + ' computer accounts',
                        'Enables resource-based constrained delegation (RBCD) attacks',
                        'Can be used for privilege escalation',
                        'Attacker creates computer, configures delegation, takes over targets'
                    ) -join '; '
                    AttackScenario      = @(
                        '1. Attacker (any user) creates computer account',
                        '2. Attacker has full control over created computer',
                        '3. Configures RBCD on target they can write to',
                        '4. Requests ticket as computer, impersonates privileged user',
                        '5. Gains access to target system'
                    ) -join ' -> '
                }
            }
        }
        catch {
            # Alternative check using ADSI
            try {
                $root = [ADSI]"LDAP://RootDSE"
                $domainDN = $root.defaultNamingContext
                $domain = [ADSI]"LDAP://$domainDN"
                $quota = $domain.'ms-DS-MachineAccountQuota'[0]

                if ($quota -gt 0) {
                    $findings += [PSCustomObject]@{
                        Setting             = 'ms-DS-MachineAccountQuota'
                        CurrentValue        = $quota
                        RecommendedValue    = 0
                        DomainDN            = $domainDN
                        RiskLevel           = 'High'
                        Impact              = "Any user can create $quota computer accounts"
                    }
                }
            }
            catch {
                # Could not determine quota
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Set ms-DS-MachineAccountQuota to 0 to prevent users from creating computer accounts.'
        Impact      = 'Low - Only affects ability to domain-join computers without delegation'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# MACHINE ACCOUNT QUOTA
# ================================================================
# By default, any authenticated user can create up to 10 computer
# accounts in Active Directory. This enables serious attacks:
#
# ATTACK: Resource-Based Constrained Delegation (RBCD)
# 1. User creates computer account (they control it fully)
# 2. User finds target they can write msDS-AllowedToActOnBehalfOfOtherIdentity
# 3. Configures RBCD from their computer to target
# 4. Uses S4U2Self + S4U2Proxy to impersonate admin on target
# 5. Full access to target system

# ================================================================
# CURRENT STATUS
# ================================================================

# Check current value:
Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota' | ``
    Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'

# Current value: $($Finding.Findings[0].CurrentValue) (should be 0)

# ================================================================
# SET TO ZERO
# ================================================================

# Using PowerShell:
Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0}

# Verify:
Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota'

# ================================================================
# ALTERNATIVE: ADSIEDIT
# ================================================================

# 1. Open ADSIEDIT.msc
# 2. Connect to Default naming context
# 3. Right-click domain node > Properties
# 4. Find ms-DS-MachineAccountQuota
# 5. Change value to 0

# ================================================================
# DELEGATION FOR DOMAIN JOIN
# ================================================================

# After setting to 0, only delegated accounts can join computers.
# Create a service account for domain joining:

# 1. Create service account
New-ADUser -Name "svc-domainjoin" -SamAccountName "svc-domainjoin" ``
    -Description "Service account for domain join operations" ``
    -Path "OU=Service Accounts,DC=domain,DC=com" ``
    -PasswordNeverExpires `$false ``
    -Enabled `$true

# 2. Delegate permission on Computers OU:
# Grant "Create Computer objects" to svc-domainjoin

# 3. Use this account in deployment tools (SCCM, MDT, Intune)

# ================================================================
# FIND ROGUE COMPUTER ACCOUNTS
# ================================================================

# Find computers created by non-admins:
Get-ADComputer -Filter * -Properties mS-DS-CreatorSID, WhenCreated | ``
    ForEach-Object {
        `$creator = if (`$_.'mS-DS-CreatorSID') {
            try { (New-Object Security.Principal.SecurityIdentifier(`$_.'mS-DS-CreatorSID')).Translate([Security.Principal.NTAccount]) }
            catch { `$_.'mS-DS-CreatorSID' }
        } else { 'Unknown' }

        [PSCustomObject]@{
            Name = `$_.Name
            Creator = `$creator
            Created = `$_.WhenCreated
        }
    } | Where-Object { `$_.Creator -notmatch 'SYSTEM|Administrator' }

"@
            return $commands
        }
    }
}

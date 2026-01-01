<#
.SYNOPSIS
    Detects non-admin accounts with rights to add members to privileged groups.

.DESCRIPTION
    The ability to add members to privileged groups like Domain Admins is a direct
    path to privilege escalation. This rule identifies accounts with WriteProperty
    on the member attribute of sensitive groups.

.NOTES
    Rule ID    : P-AddMember
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-AddMember'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Non-Admin Can Add Members to Privileged Groups'
    Description = 'Identifies accounts that can add members to privileged groups like Domain Admins, enabling direct privilege escalation.'
    Severity    = 'Critical'
    Weight      = 85
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'BloodHound AddMember Edge'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addmember' }
        @{ Title = 'Group Membership Abuse'; Url = 'https://attack.mitre.org/techniques/T1098/002/' }
        @{ Title = 'AD Privilege Escalation'; Url = 'https://adsecurity.org/?p=1906' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1098.002')  # Account Manipulation: Add Account to Group
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_addmember')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # GUID for member attribute
        $memberGUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2'

        # Privileged groups to check
        $privilegedGroups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Backup Operators'
            'Server Operators'
            'Print Operators'
            'DnsAdmins'
        )

        # Legitimate principals
        $legitimatePrincipals = @(
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'SYSTEM'
            'Account Operators'  # Expected for some groups
        )

        if ($Data.Groups) {
            foreach ($groupName in $privilegedGroups) {
                $group = $Data.Groups | Where-Object {
                    $_.SamAccountName -eq $groupName -or $_.Name -eq $groupName
                } | Select-Object -First 1

                if (-not $group) { continue }

                $groupDN = $group.DistinguishedName
                if (-not $groupDN) { continue }

                try {
                    $adsiObj = [ADSI]"LDAP://$groupDN"
                    $acl = $adsiObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()
                        $objectType = $ace.ObjectType.ToString().ToLower()

                        # Check for rights that allow adding members
                        $canAddMember = $false

                        # GenericAll or GenericWrite
                        if ($rights -match 'GenericAll|GenericWrite') {
                            $canAddMember = $true
                        }

                        # WriteProperty on member attribute
                        if ($rights -match 'WriteProperty') {
                            if ($objectType -eq $memberGUID.ToLower() -or
                                $objectType -eq '00000000-0000-0000-0000-000000000000') {
                                $canAddMember = $true
                            }
                        }

                        # Self (can add self to group)
                        if ($rights -match 'Self') {
                            $canAddMember = $true
                        }

                        if (-not $canAddMember) { continue }

                        # Check if principal is legitimate
                        $isLegitimate = $false
                        foreach ($legit in $legitimatePrincipals) {
                            if ($identity -like "*$legit*") {
                                $isLegitimate = $true
                                break
                            }
                        }

                        # Special case: Account Operators should only manage non-privileged groups
                        if ($identity -match 'Account Operators' -and $groupName -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators') {
                            $isLegitimate = $false  # This is suspicious
                        }

                        if (-not $isLegitimate) {
                            $findings += [PSCustomObject]@{
                                TargetGroup         = $groupName
                                Principal           = $identity
                                Rights              = $rights
                                ObjectType          = if ($objectType -eq $memberGUID.ToLower()) { 'member attribute' } else { 'All properties' }
                                Inherited           = $ace.IsInherited
                                AttackPath          = "Add self or controlled account to $groupName -> Instant privilege escalation"
                                RiskLevel           = if ($groupName -match 'Domain Admins|Enterprise Admins') { 'Critical' } else { 'High' }
                                DistinguishedName   = $groupDN
                            }
                        }
                    }
                } catch {
                    # Can't access group ACL
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove the ability to add members to privileged groups from non-admin accounts.'
        Impact      = 'Medium - May affect delegated group management. Review each permission before removal.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# AddMember Privilege Escalation Remediation
#############################################################################
#
# The ability to add members to privileged groups is a direct escalation path:
# 1. Attacker has AddMember rights on Domain Admins
# 2. Attacker adds their controlled account
# 3. Attacker is now a Domain Admin
#
# This is one of the simplest and most direct privilege escalation attacks.
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal) can add members to $($_.TargetGroup)" } | Out-String)

#############################################################################
# Step 1: Remove Dangerous ACL Entries
#############################################################################

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove AddMember rights from: $($item.Principal) on $($item.TargetGroup)
`$groupDN = '$($item.DistinguishedName)'
`$group = [ADSI]"LDAP://`$groupDN"
`$acl = `$group.ObjectSecurity

# Find and remove the ACE
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)' -and
    (`$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|Self')
}

foreach (`$ace in `$aceToRemove) {
    Write-Host "Removing: $($item.Principal) from $($item.TargetGroup)" -ForegroundColor Yellow
    `$acl.RemoveAccessRule(`$ace) | Out-Null
}

`$group.ObjectSecurity = `$acl
`$group.CommitChanges()

"@
            }

            $commands += @"

#############################################################################
# Step 2: Audit All Privileged Group ACLs
#############################################################################

`$privilegedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Backup Operators'
    'DnsAdmins'
)

foreach (`$groupName in `$privilegedGroups) {
    `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
    if (-not `$group) { continue }

    Write-Host "`n=== `$groupName ===" -ForegroundColor Cyan

    `$acl = Get-Acl "AD:\`$(`$group.DistinguishedName)"
    `$acl.Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|Self' -and
        `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators'
    } | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table
}

#############################################################################
# Step 3: Use BloodHound to Find All Paths
#############################################################################

# Run SharpHound to collect data:
# SharpHound.exe -c All

# BloodHound query to find AddMember paths:
# MATCH p=(n)-[r:AddMember|GenericAll|GenericWrite]->(g:Group)
# WHERE g.highvalue = true
# RETURN p

#############################################################################
# Step 4: Implement Least Privilege for Group Management
#############################################################################

# If delegation is required, use specific permissions:

# Create a custom delegated group:
# New-ADGroup -Name 'HelpDesk Group Managers' -GroupScope Global

# Grant limited group management (non-privileged groups only):
`$delegatedOU = 'OU=User Groups,DC=domain,DC=com'
dsacls `$delegatedOU /G "DOMAIN\HelpDesk Group Managers:WP;member"

# NEVER grant group management on privileged groups to non-admins

#############################################################################
# Monitoring
#############################################################################

# Enable auditing on privileged groups:
# Event ID 4728 - Member added to security-enabled global group
# Event ID 4732 - Member added to security-enabled local group
# Event ID 4756 - Member added to security-enabled universal group

# Create alerts for these events on privileged groups

"@
            return $commands
        }
    }
}

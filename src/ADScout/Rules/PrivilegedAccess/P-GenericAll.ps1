<#
.SYNOPSIS
    Detects non-admin accounts with GenericAll permissions on critical objects.

.DESCRIPTION
    GenericAll grants full control over an object, allowing password resets,
    group membership changes, and any other modifications. This is a common
    privilege escalation vector.

.NOTES
    Rule ID    : P-GenericAll
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-GenericAll'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'GenericAll Rights on Critical Objects'
    Description = 'Identifies non-privileged accounts with GenericAll (full control) permissions on users, groups, computers, or GPOs enabling privilege escalation.'
    Severity    = 'Critical'
    Weight      = 80
    DataSource  = 'Users,Groups,Computers'

    References  = @(
        @{ Title = 'BloodHound GenericAll Edge'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall' }
        @{ Title = 'AD ACL Abuse'; Url = 'https://attack.mitre.org/techniques/T1222/001/' }
        @{ Title = 'ACL Attack Paths'; Url = 'https://wald0.com/?p=112' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1222.001', 'T1098')  # File Permissions Modification, Account Manipulation
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_genericall')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Legitimate principals that may have GenericAll
        $legitimatePrincipals = @(
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'SYSTEM'
            'SELF'
            'Account Operators'
            'CREATOR OWNER'
        )

        $legitimateSIDPatterns = @(
            'S-1-5-32-544'      # Administrators
            'S-1-5-18'          # SYSTEM
            'S-1-5-10'          # SELF
            'S-1-3-0'           # Creator Owner
            'S-1-5-9'           # Enterprise DCs
        )

        # Check privileged users
        if ($Data.Users) {
            $privilegedUsers = $Data.Users | Where-Object {
                $_.AdminCount -eq 1 -or
                $_.SamAccountName -match '^(Administrator|krbtgt)$'
            } | Select-Object -First 20  # Limit for performance

            foreach ($user in $privilegedUsers) {
                try {
                    $userDN = $user.DistinguishedName
                    if (-not $userDN) { continue }

                    $adsiObj = [ADSI]"LDAP://$userDN"
                    $acl = $adsiObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        if ($ace.ActiveDirectoryRights -notmatch 'GenericAll') { continue }

                        $identity = $ace.IdentityReference.Value

                        # Check if legitimate
                        $isLegitimate = $false
                        foreach ($legit in $legitimatePrincipals) {
                            if ($identity -like "*$legit*") {
                                $isLegitimate = $true
                                break
                            }
                        }

                        if (-not $isLegitimate) {
                            $findings += [PSCustomObject]@{
                                TargetObject        = $user.SamAccountName
                                TargetType          = 'Privileged User'
                                Principal           = $identity
                                Rights              = 'GenericAll'
                                Inherited           = $ace.IsInherited
                                AttackPath          = 'Can reset password, set SPN for Kerberoasting, or modify account'
                                RiskLevel           = 'Critical'
                                DistinguishedName   = $userDN
                            }
                        }
                    }
                } catch {
                    # Skip objects we can't access
                }
            }
        }

        # Check privileged groups
        if ($Data.Groups) {
            $privilegedGroups = $Data.Groups | Where-Object {
                $_.SamAccountName -match '^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators)$' -or
                $_.AdminCount -eq 1
            }

            foreach ($group in $privilegedGroups) {
                try {
                    $groupDN = $group.DistinguishedName
                    if (-not $groupDN) { continue }

                    $adsiObj = [ADSI]"LDAP://$groupDN"
                    $acl = $adsiObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        if ($ace.ActiveDirectoryRights -notmatch 'GenericAll') { continue }

                        $identity = $ace.IdentityReference.Value

                        # Check if legitimate
                        $isLegitimate = $false
                        foreach ($legit in $legitimatePrincipals) {
                            if ($identity -like "*$legit*") {
                                $isLegitimate = $true
                                break
                            }
                        }

                        if (-not $isLegitimate) {
                            $findings += [PSCustomObject]@{
                                TargetObject        = $group.SamAccountName
                                TargetType          = 'Privileged Group'
                                Principal           = $identity
                                Rights              = 'GenericAll'
                                Inherited           = $ace.IsInherited
                                AttackPath          = 'Can add members to gain group privileges'
                                RiskLevel           = 'Critical'
                                DistinguishedName   = $groupDN
                            }
                        }
                    }
                } catch {
                    # Skip objects we can't access
                }
            }
        }

        # Check Domain Controllers
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $dcDN = $dc.DistinguishedName
                    if (-not $dcDN) { continue }

                    $adsiObj = [ADSI]"LDAP://$dcDN"
                    $acl = $adsiObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        if ($ace.ActiveDirectoryRights -notmatch 'GenericAll') { continue }

                        $identity = $ace.IdentityReference.Value

                        # Check if legitimate
                        $isLegitimate = $false
                        foreach ($legit in $legitimatePrincipals) {
                            if ($identity -like "*$legit*") {
                                $isLegitimate = $true
                                break
                            }
                        }

                        if (-not $isLegitimate) {
                            $findings += [PSCustomObject]@{
                                TargetObject        = $dc.Name
                                TargetType          = 'Domain Controller'
                                Principal           = $identity
                                Rights              = 'GenericAll'
                                Inherited           = $ace.IsInherited
                                AttackPath          = 'Can configure RBCD for DC takeover, or modify DC object'
                                RiskLevel           = 'Critical'
                                DistinguishedName   = $dcDN
                            }
                        }
                    }
                } catch {
                    # Skip objects we can't access
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove GenericAll permissions from non-privileged accounts on sensitive AD objects.'
        Impact      = 'Medium - May affect delegated administration. Verify each permission before removal.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# GenericAll Privilege Escalation Remediation
#############################################################################
#
# GenericAll (Full Control) allows:
# - Resetting user passwords
# - Adding members to groups
# - Modifying any attribute
# - Changing permissions (WriteDACL)
# - Taking ownership (WriteOwner)
# - Setting SPNs for Kerberoasting
# - Configuring RBCD for impersonation
#
# This is the most dangerous permission in Active Directory.
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.TargetObject) ($($_.TargetType)): $($_.Principal) has GenericAll" } | Out-String)

#############################################################################
# Step 1: Review and Remove Dangerous ACLs
#############################################################################

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

# Target: $($item.TargetObject) ($($item.TargetType))
# Principal: $($item.Principal)
# Attack Path: $($item.AttackPath)

`$objDN = '$($item.DistinguishedName)'
`$obj = [ADSI]"LDAP://`$objDN"
`$acl = `$obj.ObjectSecurity

# Find and remove the GenericAll ACE
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)' -and
    `$_.ActiveDirectoryRights -match 'GenericAll'
}

foreach (`$ace in `$aceToRemove) {
    Write-Host "Removing GenericAll from $($item.Principal) on $($item.TargetObject)" -ForegroundColor Yellow
    `$acl.RemoveAccessRule(`$ace) | Out-Null
}

`$obj.ObjectSecurity = `$acl
`$obj.CommitChanges()

"@
            }

            $commands += @"

#############################################################################
# Step 2: Use BloodHound to Find All Attack Paths
#############################################################################

# Run SharpHound to collect ACL data:
# SharpHound.exe -c All,ACL

# BloodHound queries to find GenericAll:
# MATCH p=(n)-[r:GenericAll]->(m) WHERE NOT n.name CONTAINS 'ADMIN' RETURN p

# Focus on paths to Domain Admins:
# MATCH p=shortestPath((n:User)-[r*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}))
# WHERE n.enabled = true RETURN p

#############################################################################
# Step 3: Implement Least Privilege
#############################################################################

# Instead of GenericAll, grant specific permissions:

# To allow password reset only:
# dsacls "CN=User,OU=Users,DC=domain,DC=com" /G "HelpDesk:CA;Reset Password"

# To allow group membership management:
# dsacls "CN=Group,OU=Groups,DC=domain,DC=com" /G "GroupAdmins:WP;member"

# To allow specific attribute modification:
# dsacls "CN=User,OU=Users,DC=domain,DC=com" /G "HRTeam:WP;telephoneNumber"

#############################################################################
# Step 4: Regular ACL Auditing
#############################################################################

# Schedule regular ACL reviews:
`$sensitiveObjects = @(
    (Get-ADGroup 'Domain Admins').DistinguishedName
    (Get-ADGroup 'Enterprise Admins').DistinguishedName
    (Get-ADUser 'Administrator').DistinguishedName
    (Get-ADUser 'krbtgt').DistinguishedName
)

foreach (`$dn in `$sensitiveObjects) {
    Write-Host "`n=== `$dn ===" -ForegroundColor Cyan
    (Get-Acl "AD:\`$dn").Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'GenericAll' -and
        `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators'
    } | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
}

#############################################################################
# Detection and Monitoring
#############################################################################

# Enable AD object modification auditing:
# Event ID 5136 - Directory service object was modified
# Event ID 4662 - Operation was performed on an object

# Alert on ACL changes to sensitive objects

"@
            return $commands
        }
    }
}

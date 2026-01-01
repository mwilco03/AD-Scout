<#
.SYNOPSIS
    Detects non-admin accounts with WriteDACL rights on sensitive objects.

.DESCRIPTION
    WriteDACL permissions allow modifying the access control list of an object,
    enabling privilege escalation by granting additional rights.

.NOTES
    Rule ID    : P-WriteDACL
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-WriteDACL'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'WriteDACL Rights on Sensitive Objects'
    Description = 'Identifies non-privileged accounts with WriteDACL permissions on sensitive AD objects, enabling privilege escalation via ACL modification.'
    Severity    = 'Critical'
    Weight      = 70
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AD ACL Abuse'; Url = 'https://attack.mitre.org/techniques/T1222/001/' }
        @{ Title = 'BloodHound WriteDACL Edge'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl' }
        @{ Title = 'ACL Privilege Escalation'; Url = 'https://www.yourwaf.com/blog/abusing-active-directory-acls-aces/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1222.001', 'T1098')  # File/Directory Permissions Modification, Account Manipulation
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_dangerous_acl')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Define legitimate privileged principals
        $legitimatePrincipals = @(
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'SYSTEM'
            'Account Operators'
            'CREATOR OWNER'
        )

        $legitimateSIDPatterns = @(
            'S-1-5-32-544'      # Administrators
            'S-1-5-18'          # SYSTEM
            'S-1-5-9'           # Enterprise DCs
            'S-1-3-0'           # Creator Owner
        )

        # Sensitive objects to check
        $sensitiveObjects = @()

        try {
            # Domain root
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            }
            $sensitiveObjects += @{ DN = $domainDN; Name = 'Domain Root'; Type = 'Domain' }

            # AdminSDHolder
            $sensitiveObjects += @{ DN = "CN=AdminSDHolder,CN=System,$domainDN"; Name = 'AdminSDHolder'; Type = 'Container' }

            # Domain Controllers OU
            $sensitiveObjects += @{ DN = "OU=Domain Controllers,$domainDN"; Name = 'Domain Controllers OU'; Type = 'OU' }

            # Check privileged groups
            if ($Data.Groups) {
                $privGroups = $Data.Groups | Where-Object {
                    $_.SamAccountName -match '^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators)$'
                }
                foreach ($group in $privGroups) {
                    $sensitiveObjects += @{ DN = $group.DistinguishedName; Name = $group.SamAccountName; Type = 'Privileged Group' }
                }
            }

            # Check privileged users
            if ($Data.Users) {
                $privUsers = $Data.Users | Where-Object { $_.AdminCount -eq 1 }
                foreach ($user in $privUsers | Select-Object -First 10) {  # Limit to avoid performance issues
                    $sensitiveObjects += @{ DN = $user.DistinguishedName; Name = $user.SamAccountName; Type = 'Privileged User' }
                }
            }

        } catch {
            # Error building sensitive objects list
        }

        # Check ACLs on sensitive objects
        foreach ($obj in $sensitiveObjects) {
            try {
                $adsiObj = [ADSI]"LDAP://$($obj.DN)"
                $acl = $adsiObj.ObjectSecurity

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    $rights = $ace.ActiveDirectoryRights.ToString()

                    # Check for WriteDACL or permissions that include it
                    if ($rights -notmatch 'WriteDacl|GenericAll|GenericWrite') { continue }

                    $identity = $ace.IdentityReference.Value

                    # Check if principal is legitimate
                    $isLegitimate = $false

                    foreach ($legitPrincipal in $legitimatePrincipals) {
                        if ($identity -like "*\$legitPrincipal" -or $identity -eq $legitPrincipal) {
                            $isLegitimate = $true
                            break
                        }
                    }

                    if (-not $isLegitimate) {
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                            foreach ($legitSID in $legitimateSIDPatterns) {
                                if ($sid -eq $legitSID -or $sid -like "$legitSID*") {
                                    $isLegitimate = $true
                                    break
                                }
                            }

                            # Check domain-relative privileged SIDs
                            if ($sid -match '-512$' -or $sid -match '-519$' -or $sid -match '-518$') {
                                $isLegitimate = $true
                            }
                        } catch {
                            # If we can't resolve, assume not legitimate
                        }
                    }

                    if (-not $isLegitimate) {
                        $specificRight = if ($rights -match 'WriteDacl' -and $rights -notmatch 'GenericAll') {
                            'WriteDACL'
                        } elseif ($rights -match 'GenericAll') {
                            'GenericAll (includes WriteDACL)'
                        } else {
                            $rights
                        }

                        $findings += [PSCustomObject]@{
                            TargetObject        = $obj.Name
                            TargetType          = $obj.Type
                            Principal           = $identity
                            Rights              = $specificRight
                            Inherited           = $ace.IsInherited
                            AttackPath          = 'Can grant self full control, then DCSync, reset passwords, etc.'
                            RiskLevel           = 'Critical'
                            DistinguishedName   = $obj.DN
                        }
                    }
                }
            } catch {
                # Skip objects we can't access
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove WriteDACL permissions from non-privileged accounts on sensitive AD objects.'
        Impact      = 'Medium - May affect delegated administration. Verify each removal.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# WriteDACL Privilege Escalation Remediation
#############################################################################
#
# WriteDACL allows modifying object permissions. An attacker can:
# 1. Grant themselves full control
# 2. Add DCSync rights to extract passwords
# 3. Reset any user's password
# 4. Add themselves to privileged groups
#
# This is a common privilege escalation path in AD attacks.
#
# Affected Objects:
$($Finding.Findings | ForEach-Object { "# - $($_.TargetObject): $($_.Principal) has $($_.Rights)" } | Out-String)

#############################################################################
# Remove Dangerous ACL Entries
#############################################################################

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

# Object: $($item.TargetObject) ($($item.TargetType))
# Principal: $($item.Principal)
# Rights: $($item.Rights)
# Inherited: $($item.Inherited)

`$objDN = '$($item.DistinguishedName)'
`$obj = [ADSI]"LDAP://`$objDN"
`$acl = `$obj.ObjectSecurity

# Find the ACE to remove
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)' -and
    `$_.ActiveDirectoryRights -match 'WriteDacl|GenericAll'
}

foreach (`$ace in `$aceToRemove) {
    `$acl.RemoveAccessRule(`$ace) | Out-Null
}
`$obj.ObjectSecurity = `$acl
`$obj.CommitChanges()

Write-Host "Removed $($item.Rights) from $($item.Principal) on $($item.TargetObject)" -ForegroundColor Green

"@
            }

            $commands += @"

#############################################################################
# Detection and Monitoring
#############################################################################

# Use BloodHound to visualize attack paths:
# SharpHound.exe -c All
# Import into BloodHound and review "WriteDACL" edges

# Enable auditing on sensitive objects:
# Event ID 5136 - Directory Service Object Modification
# Event ID 4662 - Operation performed on object

# PowerShell audit script:
`$sensitiveObjects = @(
    (Get-ADDomain).DistinguishedName,
    "CN=AdminSDHolder,CN=System,`$((Get-ADDomain).DistinguishedName)"
)

foreach (`$dn in `$sensitiveObjects) {
    `$acl = Get-Acl "AD:\`$dn"
    `$acl.Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'WriteDacl|GenericAll' -and
        `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators'
    } | Select-Object IdentityReference, ActiveDirectoryRights
}

"@
            return $commands
        }
    }
}

@{
    Id          = 'P-DelegationEveryone'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Dangerous Delegation to Everyone/Authenticated Users'
    Description = 'Critical AD permissions (GenericAll, WriteDACL, DCSync, etc.) have been granted to Everyone, Authenticated Users, or Domain Users. This allows any user to compromise the domain.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AD Permission Abuse'; Url = 'https://attack.mitre.org/techniques/T1003/006/' }
        @{ Title = 'DCSync Attack'; Url = 'https://adsecurity.org/?p=1729' }
        @{ Title = 'Bloodhound - ACL Analysis'; Url = 'https://bloodhound.readthedocs.io/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1003.006')          # OS Credential Dumping: DCSync
    }

    CIS   = @('5.5')
    STIG  = @('V-36455')
    ANSSI = @('vuln1_delegation_everyone')
    NIST  = @('AC-3', 'AC-6(1)')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous principals
        $dangerousPrincipals = @(
            'S-1-1-0'        # Everyone
            'S-1-5-7'        # Anonymous
            'S-1-5-11'       # Authenticated Users
            '*-513'          # Domain Users
            '*-515'          # Domain Computers
        )

        # Dangerous rights
        $dangerousRights = @(
            'GenericAll'
            'GenericWrite'
            'WriteDacl'
            'WriteOwner'
            'WriteProperty'
            'ExtendedRight'
        )

        # Dangerous extended rights (GUIDs)
        $dangerousExtendedRights = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
            '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
        }

        # Check domain object ACL
        if ($Data.ACL) {
            foreach ($ace in $Data.ACL) {
                $isDangerous = $false
                $principal = $ace.IdentityReference.Value

                # Check if principal is dangerous
                foreach ($pattern in $dangerousPrincipals) {
                    if ($principal -like "*$pattern*" -or $ace.SecurityIdentifier -like $pattern) {
                        $isDangerous = $true
                        break
                    }
                }

                if ($isDangerous -and $ace.AccessControlType -eq 'Allow') {
                    # Check for dangerous rights
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $hasDangerousRight = $false

                    foreach ($right in $dangerousRights) {
                        if ($rights -match $right) {
                            $hasDangerousRight = $true
                            break
                        }
                    }

                    # Check extended rights
                    $extendedRightName = $null
                    if ($ace.ObjectType -and $dangerousExtendedRights.ContainsKey($ace.ObjectType.Guid.ToString())) {
                        $extendedRightName = $dangerousExtendedRights[$ace.ObjectType.Guid.ToString()]
                        $hasDangerousRight = $true
                    }

                    if ($hasDangerousRight) {
                        $findings += [PSCustomObject]@{
                            Principal       = $principal
                            Rights          = $rights
                            ExtendedRight   = $extendedRightName
                            ObjectType      = $ace.ObjectType
                            Inherited       = $ace.IsInherited
                            Risk            = if ($extendedRightName -match 'Replication') { 'Critical - DCSync possible' } else { 'High - Domain compromise possible' }
                        }
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove dangerous permissions from Everyone, Authenticated Users, and Domain Users. These groups should never have write access to domain objects.'
        Impact      = 'Low - Only removes excessive permissions'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: Dangerous permissions granted to Everyone/Authenticated Users
# These permissions allow ANY user to compromise the domain

# WARNING: Before making changes, document current ACLs:
# (Get-Acl "AD:\`$((Get-ADDomain).DistinguishedName)").Access | Export-Csv "DomainACL_Backup.csv"

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Principal: $($item.Principal)
# Rights: $($item.Rights)
# Extended Right: $($item.ExtendedRight)
# Risk: $($item.Risk)

# Remove the ACE using ADSI:
# `$domain = [ADSI]"LDAP://`$((Get-ADDomain).DistinguishedName)"
# `$acl = `$domain.ObjectSecurity
# `$aceToRemove = `$acl.Access | Where-Object { `$_.IdentityReference -eq '$($item.Principal)' -and `$_.ActiveDirectoryRights -match '$($item.Rights)' }
# `$acl.RemoveAccessRule(`$aceToRemove)
# `$domain.CommitChanges()

"@
            }

            $commands += @"

# Alternative: Use dsacls to view and modify:
# dsacls "\\domain.com\DC=domain,DC=com"

# To specifically revoke DCSync rights from Everyone/Authenticated Users:
# This is CRITICAL and should be done immediately if found

# Verify with BloodHound or manual ACL review after changes

"@
            return $commands
        }
    }
}

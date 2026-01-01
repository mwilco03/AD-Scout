@{
    Id          = 'P-GenericAllAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'GenericAll Permission on Users/Computers/Groups'
    Description = 'Detects principals with GenericAll (Full Control) permission on user accounts, computer accounts, or security groups. GenericAll provides complete control including password reset, group membership modification, and attribute changes.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'GenericAll Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
        @{ Title = 'BloodHound GenericAll'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003', 'TA0006')
        Techniques = @('T1098', 'T1078')
    }

    CIS   = @('5.4.2')
    STIG  = @('V-220981')
    ANSSI = @('R46')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check privileged users
            $privilegedUsers = $Data.Users | Where-Object {
                $_.AdminCount -eq 1 -or
                $_.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators'
            }

            foreach ($user in $privilegedUsers) {
                try {
                    $acl = Get-Acl "AD:$($user.DistinguishedName)" -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                            $principal = $ace.IdentityReference.Value

                            # Skip expected principals
                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|SELF|Account Operators') {
                                continue
                            }

                            $findings += [PSCustomObject]@{
                                TargetType          = 'Privileged User'
                                TargetAccount       = $user.SamAccountName
                                TargetDN            = $user.DistinguishedName
                                Principal           = $principal
                                Permission          = 'GenericAll'
                                RiskLevel           = 'Critical'
                                Inherited           = $ace.IsInherited
                                AbusePaths          = @(
                                    'Reset password and logon as user',
                                    'Add SPN for Kerberoasting',
                                    'Shadow Credentials attack',
                                    'Targeted DCSync if user has replication rights'
                                ) -join '; '
                            }
                        }
                    }
                }
                catch { }
            }

            # Check privileged groups
            $privilegedGroups = @(
                'Domain Admins',
                'Enterprise Admins',
                'Schema Admins',
                'Administrators',
                'Account Operators',
                'Backup Operators',
                'Server Operators',
                'DnsAdmins'
            )

            foreach ($groupName in $privilegedGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                    if (-not $group) { continue }

                    $acl = Get-Acl "AD:$($group.DistinguishedName)" -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                            $principal = $ace.IdentityReference.Value

                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators') {
                                continue
                            }

                            $findings += [PSCustomObject]@{
                                TargetType          = 'Privileged Group'
                                TargetAccount       = $groupName
                                TargetDN            = $group.DistinguishedName
                                Principal           = $principal
                                Permission          = 'GenericAll'
                                RiskLevel           = 'Critical'
                                Inherited           = $ace.IsInherited
                                AbusePaths          = @(
                                    'Add any user to the group',
                                    'Immediate privilege escalation'
                                ) -join '; '
                            }
                        }
                    }
                }
                catch { }
            }

            # Check Domain Controllers
            $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } -Properties DistinguishedName -ErrorAction SilentlyContinue

            foreach ($dc in $dcs) {
                try {
                    $acl = Get-Acl "AD:$($dc.DistinguishedName)" -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                            $principal = $ace.IdentityReference.Value

                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Domain Controllers') {
                                continue
                            }

                            $findings += [PSCustomObject]@{
                                TargetType          = 'Domain Controller'
                                TargetAccount       = $dc.Name
                                TargetDN            = $dc.DistinguishedName
                                Principal           = $principal
                                Permission          = 'GenericAll'
                                RiskLevel           = 'Critical'
                                Inherited           = $ace.IsInherited
                                AbusePaths          = @(
                                    'RBCD attack for DC compromise',
                                    'Shadow Credentials attack',
                                    'Credential theft'
                                ) -join '; '
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            # Error accessing objects
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove GenericAll permissions from non-administrative principals on sensitive AD objects.'
        Impact      = 'Medium - Review delegated administration before removing'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GENERICALL PERMISSION ABUSE
# ================================================================
# GenericAll = Full Control over the object
#
# On Users:
# - Reset password, logon as user
# - Add SPN (Kerberoasting)
# - Write msDS-KeyCredentialLink (Shadow Credentials)
#
# On Groups:
# - Add/remove members
# - Instant privilege escalation
#
# On Computers (especially DCs):
# - RBCD attack
# - Shadow Credentials

# ================================================================
# VULNERABLE OBJECTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Target: $($item.TargetType) - $($item.TargetAccount)
# DN: $($item.TargetDN)
# Principal with GenericAll: $($item.Principal)
# Abuse Paths: $($item.AbusePaths)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove GenericAll from: $($item.Principal)
`$targetDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$targetDN"

`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    `$_.ActiveDirectoryRights -match 'GenericAll'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$targetDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# IF DELEGATION IS REQUIRED
# ================================================================

# Instead of GenericAll, grant only specific permissions needed:

# For password reset delegation:
# - ExtendedRight: Reset Password (00299570-246d-11d0-a768-00aa006e0529)

# For group membership management:
# - WriteProperty: Member attribute (bf9679c0-0de6-11d0-a285-00aa003049e2)

# For user attribute management:
# - WriteProperty: Specific attributes only

# Example: Grant password reset only
# `$resetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"
# `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
#     [System.Security.Principal.NTAccount]"DOMAIN\HelpDesk",
#     "ExtendedRight",
#     "Allow",
#     `$resetPasswordGuid
# )
# `$acl.AddAccessRule(`$ace)

"@
            return $commands
        }
    }
}

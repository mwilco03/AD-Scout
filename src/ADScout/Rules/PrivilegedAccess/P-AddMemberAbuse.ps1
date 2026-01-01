@{
    Id          = 'P-AddMemberAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'AddMember Rights on Privileged Groups'
    Description = 'Detects principals with WriteProperty on the member attribute of privileged groups. This permission allows adding users to groups like Domain Admins without having full control over the group, enabling privilege escalation.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'WriteProperty Member Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
        @{ Title = 'BloodHound AddMember'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addmember' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')
        Techniques = @('T1098', 'T1078')
    }

    CIS   = @('5.4.3')
    STIG  = @('V-220982')
    ANSSI = @('R47')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Member attribute GUID
        $memberGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'

        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'DnsAdmins',
            'Group Policy Creator Owners',
            'Cert Publishers'
        )

        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                if (-not $group) { continue }

                $acl = Get-Acl "AD:$($group.DistinguishedName)" -ErrorAction SilentlyContinue
                if (-not $acl) { continue }

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    # Check for write access to member attribute
                    $canAddMember = $false

                    # GenericAll or GenericWrite includes AddMember
                    if ($ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite') {
                        $canAddMember = $true
                    }

                    # WriteProperty on member attribute specifically
                    if ($ace.ActiveDirectoryRights -match 'WriteProperty') {
                        if ($ace.ObjectType -eq [Guid]::Empty -or
                            $ace.ObjectType -eq $memberGuid) {
                            $canAddMember = $true
                        }
                    }

                    if (-not $canAddMember) { continue }

                    $principal = $ace.IdentityReference.Value

                    # Skip expected principals
                    if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|BUILTIN\\Administrators') {
                        continue
                    }

                    # Determine if principal is low-privileged
                    $isLowPriv = $principal -match 'Domain Users|Authenticated Users|Everyone|Users'

                    $findings += [PSCustomObject]@{
                        TargetGroup         = $groupName
                        TargetDN            = $group.DistinguishedName
                        Principal           = $principal
                        Permission          = $ace.ActiveDirectoryRights.ToString()
                        SpecificAttribute   = if ($ace.ObjectType -eq $memberGuid) { 'Member attribute' } else { 'All properties' }
                        IsLowPrivileged     = $isLowPriv
                        RiskLevel           = 'Critical'
                        Inherited           = $ace.IsInherited
                        Impact              = "Can add any user to $groupName"
                    }
                }
            }
            catch { }
        }

        return $findings | Sort-Object TargetGroup
    }

    Remediation = @{
        Description = 'Remove WriteProperty on member attribute from non-administrative principals on privileged groups.'
        Impact      = 'Medium - May affect delegated group management'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ADDMEMBER PERMISSION ABUSE
# ================================================================
# WriteProperty on the 'member' attribute allows adding users
# to groups without full control.
#
# Attack: Add self to Domain Admins -> Instant DA

# ================================================================
# VULNERABLE GROUPS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Group: $($item.TargetGroup)
# Principal with AddMember: $($item.Principal)
# Permission: $($item.Permission)
# Specific Attribute: $($item.SpecificAttribute)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove AddMember from: $($item.Principal) on $($item.TargetGroup)
`$groupDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$groupDN"

# Find WriteProperty ACEs for this principal:
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    `$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$groupDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# ADMINCOUNT AND SDPROP
# ================================================================

# Privileged groups are protected by AdminSDHolder (SDProp).
# Every 60 minutes, SDProp overwrites their ACL with AdminSDHolder's ACL.
#
# If you find persistent unauthorized ACEs, check AdminSDHolder:

`$adminSDHolder = "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"
(Get-Acl "AD:`$adminSDHolder").Access |
    Where-Object { `$_.ActiveDirectoryRights -match 'WriteProperty' } |
    Select-Object IdentityReference, ActiveDirectoryRights

# If AdminSDHolder has the bad ACE, it will keep propagating!
# Fix AdminSDHolder FIRST, then wait for SDProp (or run manually):
# Start-Process dsquery.exe -ArgumentList "* domainroot -limit 0 -filter `"(adminCount=1)`""

"@
            return $commands
        }
    }
}

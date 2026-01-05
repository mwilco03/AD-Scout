@{
    Id          = 'P-PasswordResetDelegation'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Excessive Password Reset Delegation'
    Description = 'Detects principals with password reset rights (ExtendedRight: Reset Password) on privileged user accounts. This allows resetting passwords of Domain Admins or other privileged users, enabling immediate account takeover.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Password Reset Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
        @{ Title = 'BloodHound ForceChangePassword'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')
        Techniques = @('T1098', 'T1110')
    }

    CIS   = @('5.4.4')
    STIG  = @('V-220983')
    ANSSI = @('R48')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Reset Password GUID
        $resetPasswordGuid = '00299570-246d-11d0-a768-00aa006e0529'

        # Check privileged users
        $privilegedUsers = $Data.Users | Where-Object {
            $_.AdminCount -eq 1 -or
            $_.MemberOf -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators'
        }

        foreach ($user in $privilegedUsers) {
            try {
                $acl = Get-Acl "AD:$($user.DistinguishedName)" -ErrorAction SilentlyContinue
                if (-not $acl) { continue }

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    $canResetPassword = $false

                    # GenericAll includes password reset
                    if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                        $canResetPassword = $true
                    }

                    # ExtendedRight for Reset Password
                    if ($ace.ActiveDirectoryRights -match 'ExtendedRight') {
                        if ($ace.ObjectType -eq [Guid]::Empty -or
                            $ace.ObjectType -eq $resetPasswordGuid) {
                            $canResetPassword = $true
                        }
                    }

                    if (-not $canResetPassword) { continue }

                    $principal = $ace.IdentityReference.Value

                    # Skip expected principals
                    if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Account Operators|SELF') {
                        continue
                    }

                    # Check if it's a service desk / help desk type group (might be legitimate)
                    $potentiallyLegitimate = $principal -match 'Help.?Desk|Service.?Desk|IT.?Support|Password.?Reset'

                    $findings += [PSCustomObject]@{
                        TargetAccount       = $user.SamAccountName
                        TargetDN            = $user.DistinguishedName
                        TargetMemberships   = ($user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '
                        Principal           = $principal
                        Permission          = if ($ace.ObjectType -eq $resetPasswordGuid) { 'Reset Password' } else { $ace.ActiveDirectoryRights.ToString() }
                        RiskLevel           = if ($potentiallyLegitimate) { 'High' } else { 'Critical' }
                        Inherited           = $ace.IsInherited
                        PotentiallyLegit    = $potentiallyLegitimate
                        Impact              = "Can reset password and login as $($user.SamAccountName)"
                    }
                }
            }
            catch { }
        }

        return $findings | Sort-Object RiskLevel, TargetAccount
    }

    Remediation = @{
        Description = 'Review and remove password reset delegation on privileged accounts. Use tiered administration model.'
        Impact      = 'High - Affects help desk operations if not carefully reviewed'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# PASSWORD RESET DELEGATION ON PRIVILEGED ACCOUNTS
# ================================================================
# Password reset on privileged users = account takeover
#
# Best practice: No one should be able to reset Domain Admin passwords
# except other Domain Admins. Help desks should only reset
# standard user passwords (Tier 2 model).

# ================================================================
# VULNERABLE ACCOUNTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.TargetAccount)
# Memberships: $($item.TargetMemberships)
# Principal with reset rights: $($item.Principal)
# Potentially Legitimate: $($item.PotentiallyLegit)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# Reset Password GUID:
`$resetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove password reset from: $($item.Principal) on $($item.TargetAccount)
`$userDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$userDN"

`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    (`$_.ActiveDirectoryRights -match 'GenericAll|ExtendedRight')
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$userDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# TIERED ADMINISTRATION MODEL
# ================================================================

# Implement three tiers:
# Tier 0: Domain Admins, DCs - Only Tier 0 admins manage
# Tier 1: Servers - Tier 1 admins manage, no password reset on Tier 0
# Tier 2: Workstations, Users - Help Desk manages

# Create separate OUs for each tier:
# OU=Tier 0 Accounts,DC=domain,DC=com
# OU=Tier 1 Accounts,DC=domain,DC=com
# OU=Tier 2 Accounts,DC=domain,DC=com

# Delegate password reset at the OU level:
# Help Desk group gets password reset on Tier 2 OU only

# ================================================================
# ADMINCOUNT PROTECTION
# ================================================================

# Users with adminCount=1 are protected by SDProp.
# SDProp runs every 60 minutes and resets ACLs based on AdminSDHolder.
#
# Verify AdminSDHolder doesn't have password reset delegation:

`$adminSDHolder = "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"
(Get-Acl "AD:`$adminSDHolder").Access |
    Where-Object {
        `$_.ActiveDirectoryRights -match 'ExtendedRight' -and
        `$_.ObjectType -eq [Guid]"00299570-246d-11d0-a768-00aa006e0529"
    } | Select-Object IdentityReference

"@
            return $commands
        }
    }
}

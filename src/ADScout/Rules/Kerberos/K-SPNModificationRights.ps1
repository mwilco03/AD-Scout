@{
    Id          = 'K-SPNModificationRights'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'SPN Modification Rights (Kerberoasting Setup)'
    Description = 'Detects principals with WriteProperty on servicePrincipalName for user accounts. This allows setting SPNs on accounts, making them Kerberoastable. If attacker can set SPN on privileged account, they can request TGS and crack password offline.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Targeted Kerberoasting'; Url = 'https://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/' }
        @{ Title = 'WriteSPN Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1558.003')  # Kerberoasting
    }

    CIS   = @('5.4.6')
    STIG  = @('V-220985')
    ANSSI = @('R50')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # servicePrincipalName attribute GUID
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'

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

                    $canWriteSPN = $false

                    # GenericAll or GenericWrite includes SPN modification
                    if ($ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite') {
                        $canWriteSPN = $true
                    }

                    # WriteProperty on SPN specifically
                    if ($ace.ActiveDirectoryRights -match 'WriteProperty') {
                        if ($ace.ObjectType -eq [Guid]::Empty -or
                            $ace.ObjectType -eq $spnGuid) {
                            $canWriteSPN = $true
                        }
                    }

                    # Self-service includes SPN modification in some cases
                    if ($ace.ActiveDirectoryRights -match 'Self') {
                        $canWriteSPN = $true
                    }

                    if (-not $canWriteSPN) { continue }

                    $principal = $ace.IdentityReference.Value

                    # Skip expected principals
                    if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Account Operators') {
                        continue
                    }

                    # Check if account already has SPN
                    $hasSPN = $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0

                    $findings += [PSCustomObject]@{
                        TargetAccount       = $user.SamAccountName
                        TargetDN            = $user.DistinguishedName
                        Principal           = $principal
                        Permission          = $ace.ActiveDirectoryRights.ToString()
                        AlreadyHasSPN       = $hasSPN
                        CurrentSPNs         = if ($hasSPN) { $user.ServicePrincipalName -join '; ' } else { 'None' }
                        RiskLevel           = if ($hasSPN) { 'Medium' } else { 'High' }
                        Inherited           = $ace.IsInherited
                        AttackPath          = @(
                            '1. Attacker sets SPN on privileged user',
                            '2. Requests TGS for that SPN',
                            '3. TGS is encrypted with user password hash',
                            '4. Offline crack -> password recovery',
                            '5. Login as privileged user'
                        ) -join ' -> '
                    }
                }
            }
            catch { }
        }

        return $findings | Sort-Object RiskLevel, TargetAccount
    }

    Remediation = @{
        Description = 'Remove WriteProperty on servicePrincipalName from non-administrative principals on privileged accounts.'
        Impact      = 'Low - SPN modification is rarely delegated'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SPN MODIFICATION RIGHTS (TARGETED KERBEROASTING)
# ================================================================
# WriteProperty on servicePrincipalName allows setting SPNs.
# Accounts with SPNs can be Kerberoasted (TGS password cracking).
#
# Attack:
# 1. Set SPN on Domain Admin: MSSQLSvc/fake:1433
# 2. Request TGS: Add-Type -AssemblyName System.IdentityModel; ...
# 3. Crack TGS offline with hashcat/john
# 4. Recover Domain Admin password

# ================================================================
# VULNERABLE ACCOUNTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.TargetAccount)
# Principal with WriteSPN: $($item.Principal)
# Already has SPN: $($item.AlreadyHasSPN)
# Current SPNs: $($item.CurrentSPNs)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# SPN attribute GUID:
`$spnGuid = [Guid]"f3a64788-5306-11d1-a9c5-0000f80367c1"

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove WriteSPN from: $($item.Principal) on $($item.TargetAccount)
`$userDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$userDN"

`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    (`$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|Self')
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$userDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# DETECTION
# ================================================================

# Monitor for SPN changes on privileged accounts:
# Event ID 5136 (Directory Service Changes)
# Attribute: servicePrincipalName
# Filter for accounts with adminCount=1

# Find all users with SPNs (Kerberoastable):
Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName, AdminCount |
    Where-Object { `$_.AdminCount -eq 1 } |
    Select-Object SamAccountName, ServicePrincipalName

# ================================================================
# MITIGATION: PROTECTED ACCOUNTS
# ================================================================

# For accounts in Protected Users group:
# - Cannot have SPN set
# - TGT has 4-hour lifetime
# - No NTLM, DES, or RC4 encryption

# Add critical accounts to Protected Users:
# Add-ADGroupMember -Identity "Protected Users" -Members "AdminAccount"

# ================================================================
# STRONG PASSWORDS
# ================================================================

# Even if account has SPN, strong password prevents cracking:
# - 25+ character passwords for service accounts
# - Use Group Managed Service Accounts (gMSA) where possible

"@
            return $commands
        }
    }
}

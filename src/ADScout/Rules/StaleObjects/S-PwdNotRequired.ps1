@{
    Id          = 'S-PwdNotRequired'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Accounts Without Password Requirement'
    Description = 'User accounts configured with the PASSWD_NOTREQD flag, allowing them to have blank or no passwords. These accounts can be accessed without authentication.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'UserAccountControl Flags'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties' }
        @{ Title = 'Blank Password Access'; Url = 'https://attack.mitre.org/techniques/T1078/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.1.3')
    STIG  = @('V-36453')
    ANSSI = @('vuln1_pwd_not_required')
    NIST  = @('IA-2', 'IA-5(1)')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # PASSWD_NOTREQD = 0x0020 (32)
        $PASSWD_NOTREQD = 32

        foreach ($user in $Data) {
            if ($user.UserAccountControl -band $PASSWD_NOTREQD) {
                $findings += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    PasswordLastSet   = $user.PasswordLastSet
                    LastLogon         = $user.LastLogonDate
                    AdminCount        = $user.AdminCount
                    DistinguishedName = $user.DistinguishedName
                    Risk              = if ($user.AdminCount) { 'Critical - Privileged account with no password required' } else { 'High - Account can have blank password' }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove the PASSWD_NOTREQD flag from all accounts and set strong passwords. Audit why this flag was set.'
        Impact      = 'Medium - Accounts may need password reset'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Accounts with PASSWD_NOTREQD flag detected
# These accounts can have blank passwords - immediate remediation required

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Enabled: $($item.Enabled)
# Risk Level: $($item.Risk)

# Remove the PASSWD_NOTREQD flag:
Set-ADUser -Identity '$($item.SamAccountName)' -PasswordNotRequired `$false

# Force password change at next logon:
Set-ADUser -Identity '$($item.SamAccountName)' -ChangePasswordAtLogon `$true

# Or set a new password directly:
# Set-ADAccountPassword -Identity '$($item.SamAccountName)' -Reset -NewPassword (ConvertTo-SecureString 'NewSecureP@ssw0rd!' -AsPlainText -Force)

"@
            }

            $commands += @"

# Bulk fix - remove flag from all affected accounts:
# Get-ADUser -Filter * -Properties UserAccountControl |
#     Where-Object { `$_.UserAccountControl -band 32 } |
#     Set-ADUser -PasswordNotRequired `$false

# Verify the change:
Get-ADUser -Filter * -Properties UserAccountControl |
    Where-Object { `$_.UserAccountControl -band 32 } |
    Select-Object SamAccountName, UserAccountControl

"@
            return $commands
        }
    }
}

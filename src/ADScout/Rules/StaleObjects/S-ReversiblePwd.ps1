@{
    Id          = 'S-ReversiblePwd'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Reversible Password Encryption'
    Description = 'Accounts configured to store passwords with reversible encryption. These passwords can be decrypted by domain administrators.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Store passwords using reversible encryption'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption' }
        @{ Title = 'Password Storage'; Url = 'https://attack.mitre.org/techniques/T1552/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1552.001')  # Unsecured Credentials: Credentials In Files
    }

    CIS   = @('1.1.5')
    STIG  = @('V-36456')
    ANSSI = @('vuln1_reversible_pwd')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080 (128)
        $ENCRYPTED_TEXT_PWD = 128

        foreach ($user in $Data) {
            if ($user.UserAccountControl -band $ENCRYPTED_TEXT_PWD) {
                $findings += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    AdminCount        = $user.AdminCount
                    PasswordLastSet   = $user.PasswordLastSet
                    DistinguishedName = $user.DistinguishedName
                    Risk              = if ($user.AdminCount) { 'Critical - Admin password recoverable' } else { 'High - Password can be decrypted' }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove the reversible encryption flag and have users change passwords. The new password will be stored securely.'
        Impact      = 'Medium - Users must change passwords for new storage method to apply'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Accounts with reversible password encryption detected
# These passwords can be decrypted by anyone with DC access

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Enabled: $($item.Enabled)
# Risk: $($item.Risk)

# Remove reversible encryption flag:
Set-ADUser -Identity '$($item.SamAccountName)' -AllowReversiblePasswordEncryption `$false

# Force password change (required for new storage to take effect):
Set-ADUser -Identity '$($item.SamAccountName)' -ChangePasswordAtLogon `$true

"@
            }

            $commands += @"

# Also ensure GPO doesn't enable reversible encryption:
# Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy
# "Store passwords using reversible encryption" = Disabled

# Bulk remediation:
# Get-ADUser -Filter * -Properties UserAccountControl |
#     Where-Object { `$_.UserAccountControl -band 128 } |
#     Set-ADUser -AllowReversiblePasswordEncryption `$false

"@
            return $commands
        }
    }
}

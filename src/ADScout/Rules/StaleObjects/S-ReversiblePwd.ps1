@{
    Id          = 'S-ReversiblePwd'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Reversible Password Encryption'
    Description = 'Accounts configured to store passwords with reversible encryption. Checks both domain password policy AND individual account flags to ensure reversible encryption is blocked everywhere.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users,Domain'

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
    NIST  = @('IA-5(1)')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080 (128)
        $ENCRYPTED_TEXT_PWD = 128

        # ========================================================================
        # BELT: Check domain password policy for reversible encryption setting
        # ========================================================================
        try {
            $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
            if ($domainPolicy -and $domainPolicy.ReversibleEncryptionEnabled) {
                $findings += [PSCustomObject]@{
                    ObjectType        = 'Domain Policy'
                    SamAccountName    = 'Default Domain Policy'
                    DisplayName       = 'Domain Password Policy'
                    UserAccountControl = 'N/A'
                    Enabled           = 'N/A'
                    AdminCount        = 'N/A'
                    PasswordLastSet   = 'N/A'
                    DistinguishedName = "DC=$($Domain -replace '\.',',DC=')"
                    Risk              = 'CRITICAL: Domain policy enables reversible encryption for ALL new passwords'
                    PolicySource      = 'Default Domain Policy'
                }
            }
        } catch {
            # Try alternative method - check GPO directly
            try {
                $gpoPath = "\\$Domain\SYSVOL\$Domain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $gpoPath -ErrorAction SilentlyContinue) {
                    $content = Get-Content $gpoPath -Raw -ErrorAction SilentlyContinue
                    # ClearTextPassword = 1 means reversible encryption enabled
                    if ($content -match 'ClearTextPassword\s*=\s*1') {
                        $findings += [PSCustomObject]@{
                            ObjectType        = 'Domain Policy'
                            SamAccountName    = 'Default Domain Policy'
                            DisplayName       = 'Domain Password Policy (GPO)'
                            UserAccountControl = 'N/A'
                            Enabled           = 'N/A'
                            AdminCount        = 'N/A'
                            PasswordLastSet   = 'N/A'
                            DistinguishedName = $gpoPath
                            Risk              = 'CRITICAL: Domain GPO enables reversible encryption'
                            PolicySource      = 'GPO'
                        }
                    }
                }
            } catch {
                Write-Verbose "S-ReversiblePwd: Could not check domain password policy: $_"
            }
        }

        # Also check Fine-Grained Password Policies (PSOs)
        try {
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
            foreach ($fgpp in $fgpps) {
                if ($fgpp.ReversibleEncryptionEnabled) {
                    $findings += [PSCustomObject]@{
                        ObjectType        = 'Fine-Grained Password Policy'
                        SamAccountName    = $fgpp.Name
                        DisplayName       = $fgpp.Name
                        UserAccountControl = 'N/A'
                        Enabled           = 'N/A'
                        AdminCount        = 'N/A'
                        PasswordLastSet   = 'N/A'
                        DistinguishedName = $fgpp.DistinguishedName
                        Risk              = "HIGH: FGPP '$($fgpp.Name)' enables reversible encryption"
                        PolicySource      = 'Fine-Grained Password Policy'
                    }
                }
            }
        } catch {
            Write-Verbose "S-ReversiblePwd: Could not check Fine-Grained Password Policies: $_"
        }

        # ========================================================================
        # SUSPENDERS: Check individual accounts for reversible encryption flag
        # ========================================================================
        $users = if ($Data.Users) { $Data.Users } else { $Data }

        foreach ($user in $users) {
            if ($user.UserAccountControl -band $ENCRYPTED_TEXT_PWD) {
                $findings += [PSCustomObject]@{
                    ObjectType        = 'User Account'
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    AdminCount        = $user.AdminCount
                    PasswordLastSet   = $user.PasswordLastSet
                    DistinguishedName = $user.DistinguishedName
                    Risk              = if ($user.AdminCount) { 'Critical - Admin password recoverable' } else { 'High - Password can be decrypted' }
                    PolicySource      = 'Account Flag'
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

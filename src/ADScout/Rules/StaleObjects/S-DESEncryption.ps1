@{
    Id          = 'S-DESEncryption'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'DES Kerberos Encryption Enabled'
    Description = 'Accounts configured to use weak DES encryption for Kerberos authentication. DES is cryptographically broken and provides no security.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Kerberos Encryption Types'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-supported-encryption-types' }
        @{ Title = 'DES Deprecation'; Url = 'https://attack.mitre.org/techniques/T1558/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558')   # Steal or Forge Kerberos Tickets
    }

    CIS   = @('5.12')
    STIG  = @('V-36454')
    ANSSI = @('vuln1_des_encryption')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # USE_DES_KEY_ONLY = 0x200000 (2097152)
        $USE_DES_KEY_ONLY = 2097152

        foreach ($user in $Data) {
            if ($user.UserAccountControl -band $USE_DES_KEY_ONLY) {
                $findings += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    PasswordLastSet   = $user.PasswordLastSet
                    DistinguishedName = $user.DistinguishedName
                    Risk              = 'DES encryption is cryptographically broken'
                }
            }

            # Also check msDS-SupportedEncryptionTypes for DES (0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5)
            if ($user.'msDS-SupportedEncryptionTypes') {
                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                if ($encTypes -band 0x3) {
                    $findings += [PSCustomObject]@{
                        SamAccountName      = $user.SamAccountName
                        DisplayName         = $user.DisplayName
                        EncryptionTypes     = $encTypes
                        DESEnabled          = $true
                        Enabled             = $user.Enabled
                        DistinguishedName   = $user.DistinguishedName
                        Risk                = 'Account supports DES encryption types'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove DES encryption support from all accounts. Update to use AES encryption only.'
        Impact      = 'Medium - Very old systems may lose Kerberos authentication'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Accounts using weak DES Kerberos encryption detected
# DES is cryptographically broken and should never be used

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Current encryption types: $($item.EncryptionTypes)

# Remove USE_DES_KEY_ONLY flag (if set):
Set-ADAccountControl -Identity '$($item.SamAccountName)' -UseDESKeyOnly `$false

# Set to use AES only:
Set-ADUser -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES128,AES256'

"@
            }

            $commands += @"

# Bulk remediation - set all accounts to use AES encryption:
# Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
#     Where-Object { `$_.'msDS-SupportedEncryptionTypes' -band 3 } |
#     Set-ADUser -KerberosEncryptionType 'AES128,AES256'

# Domain-wide: Disable DES encryption via Group Policy
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Network security: Configure encryption types allowed for Kerberos"
# Enable only: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

# Verify:
Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
    Where-Object { `$_.'msDS-SupportedEncryptionTypes' -band 3 } |
    Select-Object SamAccountName, 'msDS-SupportedEncryptionTypes'

"@
            return $commands
        }
    }
}

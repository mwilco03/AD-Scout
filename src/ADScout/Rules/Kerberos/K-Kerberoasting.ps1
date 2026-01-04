@{
    Id          = 'K-Kerberoasting'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Kerberoastable Service Accounts'
    Description = 'Identifies user accounts with Service Principal Names (SPNs) that are vulnerable to Kerberoasting attacks. Attackers can request TGS tickets and crack passwords offline.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Kerberoasting'; Url = 'https://attack.mitre.org/techniques/T1558/003/' }
        @{ Title = 'Detecting Kerberoasting Activity'; Url = 'https://adsecurity.org/?p=3458' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558.003')  # Steal or Forge Kerberos Tickets: Kerberoasting
    }

    CIS   = @('5.12')
    STIG  = @('V-36444')
    ANSSI = @('vuln1_kerberoasting')
    NIST  = @('IA-2', 'IA-5(1)')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($user in $Data) {
            # Check for SPNs on user accounts (not computer accounts)
            if ($user.ObjectClass -eq 'user' -and
                $user.ServicePrincipalName -and
                $user.ServicePrincipalName.Count -gt 0) {

                # Calculate password age
                $passwordAge = if ($user.PasswordLastSet) {
                    (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
                } else { 'Never Set' }

                # Check encryption types for Kerberoasting risk
                # Encryption type flags:
                # 0x01 = DES-CBC-CRC, 0x02 = DES-CBC-MD5, 0x04 = RC4-HMAC (all weak/crackable)
                # 0x08 = AES128-CTS-HMAC-SHA1-96, 0x10 = AES256-CTS-HMAC-SHA1-96 (strong)
                #
                # IMPORTANT: Even if AES is enabled, attackers can request RC4 tickets
                # if the account supports RC4. The KDC will honor the request.
                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                $hasAES = $false
                $hasRC4 = $false
                $hasDES = $false
                $encryptionRisk = 'Unknown'

                if ($encTypes) {
                    $hasAES = ($encTypes -band 0x18) -ne 0  # AES128 or AES256
                    $hasRC4 = ($encTypes -band 0x04) -ne 0  # RC4-HMAC
                    $hasDES = ($encTypes -band 0x03) -ne 0  # DES-CBC-CRC or DES-CBC-MD5

                    if (-not $hasAES) {
                        # No AES at all - critical risk
                        $encryptionRisk = 'Critical - No AES support'
                    } elseif ($hasRC4 -or $hasDES) {
                        # Has AES but also weak types - still vulnerable
                        $encryptionRisk = 'High - RC4/DES enabled alongside AES'
                    } else {
                        # AES only - best configuration
                        $encryptionRisk = 'Low - AES only'
                    }
                } else {
                    # No encryption types set = defaults to RC4 only
                    $hasRC4 = $true
                    $encryptionRisk = 'Critical - Defaults to RC4 only'
                }

                # Flag as weak if RC4 or DES is available (attackers can request these)
                $weakEncryption = $hasRC4 -or $hasDES -or (-not $hasAES)

                $findings += [PSCustomObject]@{
                    SamAccountName     = $user.SamAccountName
                    DisplayName        = $user.DisplayName
                    SPNs               = ($user.ServicePrincipalName -join ', ')
                    SPNCount           = $user.ServicePrincipalName.Count
                    PasswordAgeDays    = $passwordAge
                    WeakEncryption     = $weakEncryption
                    EncryptionRisk     = $encryptionRisk
                    EncryptionTypes    = $encTypes
                    HasAES             = $hasAES
                    HasRC4             = $hasRC4
                    HasDES             = $hasDES
                    Enabled            = $user.Enabled
                    AdminCount         = $user.AdminCount
                    DistinguishedName  = $user.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Migrate SPNs to Group Managed Service Accounts (gMSA). For existing accounts, use long complex passwords (25+ chars) and enable AES encryption. Consider removing unnecessary SPNs.'
        Impact      = 'Medium - Requires service reconfiguration'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Kerberoastable accounts detected
# Priority remediation: accounts with weak encryption and old passwords

# For each account, consider:
# 1. Migrate to gMSA (preferred)
# 2. Set 25+ character random password
# 3. Enable AES-only encryption
# 4. Remove unnecessary SPNs

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# SPNs: $($item.SPNs)
# Password Age: $($item.PasswordAgeDays) days
# Weak Encryption: $($item.WeakEncryption)

# Set AES-256 only encryption:
Set-ADUser -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES256'

# Or to include AES-128:
# Set-ADUser -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES128,AES256'

# Generate and set new complex password:

`$newPassword = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 32 | ForEach-Object { [char]`$_ })
Set-ADAccountPassword -Identity '$($item.SamAccountName)' -NewPassword (ConvertTo-SecureString `$newPassword -AsPlainText -Force) -Reset

"@
            }
            return $commands
        }
    }
}

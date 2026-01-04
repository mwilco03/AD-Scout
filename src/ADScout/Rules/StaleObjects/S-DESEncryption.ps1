@{
    Id          = 'S-DESEncryption'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'DES Kerberos Encryption Enabled'
    Description = 'Accounts configured to use weak DES encryption for Kerberos authentication. DES is cryptographically broken and provides no security. Also checks KDC policy to ensure DES is blocked domain-wide.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users,DomainControllers'

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
    NIST  = @('CM-7', 'IA-5(2)', 'SC-13')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # USE_DES_KEY_ONLY = 0x200000 (2097152)
        $USE_DES_KEY_ONLY = 2097152
        $DES_FLAGS = 0x3  # DES-CBC-CRC (0x1) + DES-CBC-MD5 (0x2)

        # ========================================================================
        # BELT: Check KDC policy - does the domain allow DES at all?
        # ========================================================================
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $kdcPolicy = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
                        $defaultPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'

                        $result = @{ SupportedEncryptionTypes = $null; DefaultEncTypes = $null }

                        if (Test-Path $regPath) {
                            $policy = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                            if ($policy.SupportedEncryptionTypes) {
                                $result.SupportedEncryptionTypes = $policy.SupportedEncryptionTypes
                            }
                        }
                        if (Test-Path $defaultPath) {
                            $defaults = Get-ItemProperty -Path $defaultPath -ErrorAction SilentlyContinue
                            if ($defaults.DefaultDomainSupportedEncTypes) {
                                $result.DefaultEncTypes = $defaults.DefaultDomainSupportedEncTypes
                            }
                        }
                        return $result
                    } -ErrorAction SilentlyContinue

                    if ($kdcPolicy) {
                        $kdcEncTypes = $kdcPolicy.SupportedEncryptionTypes ?? $kdcPolicy.DefaultEncTypes
                        $policySource = if ($kdcPolicy.SupportedEncryptionTypes) { 'GPO' } else { 'Default' }

                        if ($kdcEncTypes -and ($kdcEncTypes -band $DES_FLAGS)) {
                            $findings += [PSCustomObject]@{
                                ObjectType        = 'KDC Policy'
                                SamAccountName    = $dc.Name
                                DisplayName       = 'Domain Controller KDC Policy'
                                EncryptionTypes   = "0x$($kdcEncTypes.ToString('X'))"
                                DESEnabled        = $true
                                Enabled           = 'N/A'
                                DistinguishedName = $dc.DistinguishedName
                                Risk              = 'CRITICAL: KDC accepts DES requests domain-wide'
                                PolicySource      = $policySource
                            }
                        } elseif (-not $kdcEncTypes) {
                            # No explicit policy - older DFLs may allow DES by default
                            $findings += [PSCustomObject]@{
                                ObjectType        = 'KDC Policy'
                                SamAccountName    = $dc.Name
                                DisplayName       = 'Domain Controller KDC Policy'
                                EncryptionTypes   = 'Not Configured'
                                DESEnabled        = 'Unknown'
                                Enabled           = 'N/A'
                                DistinguishedName = $dc.DistinguishedName
                                Risk              = 'No explicit encryption policy - may allow DES depending on DFL'
                                PolicySource      = 'None'
                            }
                        }
                    }
                } catch {
                    Write-Verbose "S-DESEncryption: Could not query KDC policy on $($dc.Name): $_"
                }
            }
        }

        # ========================================================================
        # SUSPENDERS: Check individual accounts for DES configuration
        # ========================================================================
        $users = if ($Data.Users) { $Data.Users } else { $Data }

        foreach ($user in $users) {
            # Skip if this is a DC object (already checked above)
            if ($user.ObjectClass -eq 'computer') { continue }

            # Check UAC flag USE_DES_KEY_ONLY
            if ($user.UserAccountControl -band $USE_DES_KEY_ONLY) {
                $findings += [PSCustomObject]@{
                    ObjectType        = 'User Account'
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    PasswordLastSet   = $user.PasswordLastSet
                    DistinguishedName = $user.DistinguishedName
                    Risk              = 'USE_DES_KEY_ONLY flag set - DES is cryptographically broken'
                    PolicySource      = 'Account Flag'
                }
            }

            # Check msDS-SupportedEncryptionTypes for DES
            $encTypes = $user.'msDS-SupportedEncryptionTypes'
            if ($encTypes -and ($encTypes -band $DES_FLAGS)) {
                $findings += [PSCustomObject]@{
                    ObjectType        = 'User Account'
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    EncryptionTypes   = "0x$($encTypes.ToString('X'))"
                    DESEnabled        = $true
                    Enabled           = $user.Enabled
                    DistinguishedName = $user.DistinguishedName
                    Risk              = 'Account explicitly supports DES encryption types'
                    PolicySource      = 'msDS-SupportedEncryptionTypes'
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

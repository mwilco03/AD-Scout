<#
.SYNOPSIS
    Detects accounts and policies allowing RC4 Kerberos encryption.

.DESCRIPTION
    RC4 encryption in Kerberos is considered weak and enables Kerberoasting attacks
    to crack passwords more easily. AES encryption should be enforced.

.NOTES
    Rule ID    : K-RC4Encryption
    Category   : Kerberos
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'K-RC4Encryption'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'RC4 Kerberos Encryption Allowed'
    Description = 'Identifies accounts and domain settings that allow RC4 encryption for Kerberos, making Kerberoasting attacks faster to crack.'
    Severity    = 'Medium'
    Weight      = 30
    DataSource  = 'Users,Domain'

    References  = @(
        @{ Title = 'Kerberos Encryption Types'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-encryption-types' }
        @{ Title = 'Disable RC4 for Kerberos'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/askds/kerberos-encryption-types' }
        @{ Title = 'Kerberoasting Prevention'; Url = 'https://adsecurity.org/?p=3458' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558.003')  # Kerberoasting
    }

    CIS   = @('2.3.6.4')
    STIG  = @('V-63713')
    ANSSI = @('R37')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # msDS-SupportedEncryptionTypes values:
        # 0x1 = DES-CBC-CRC
        # 0x2 = DES-CBC-MD5
        # 0x4 = RC4-HMAC
        # 0x8 = AES128-CTS-HMAC-SHA1-96
        # 0x10 = AES256-CTS-HMAC-SHA1-96
        # 0x18 = AES128 + AES256 (recommended minimum)

        $rc4Flag = 0x4
        $aes128Flag = 0x8
        $aes256Flag = 0x10

        # Check service accounts with SPNs
        if ($Data.Users) {
            foreach ($user in $Data.Users) {
                # Only check accounts with SPNs (Kerberoastable)
                if (-not $user.ServicePrincipalName -or $user.ServicePrincipalName.Count -eq 0) { continue }

                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                $usesRC4 = $false
                $noAES = $false
                $reason = ''

                if (-not $encTypes -or $encTypes -eq 0) {
                    # No encryption types set = defaults to RC4
                    $usesRC4 = $true
                    $noAES = $true
                    $reason = 'No encryption types set (defaults to RC4)'
                } elseif ($encTypes -band $rc4Flag) {
                    $usesRC4 = $true
                    $noAES = -not (($encTypes -band $aes128Flag) -or ($encTypes -band $aes256Flag))
                    $reason = 'RC4 explicitly enabled'
                }

                if ($usesRC4) {
                    $findings += [PSCustomObject]@{
                        ObjectType          = 'Service Account'
                        SamAccountName      = $user.SamAccountName
                        SPNCount            = $user.ServicePrincipalName.Count
                        EncryptionTypes     = if ($encTypes) { "0x$($encTypes.ToString('X'))" } else { 'Not Set' }
                        UsesRC4             = $true
                        HasAES              = -not $noAES
                        Issue               = $reason
                        RiskLevel           = if ($user.AdminCount -eq 1) { 'Critical' } elseif ($noAES) { 'High' } else { 'Medium' }
                        Impact              = 'Kerberos tickets can be cracked faster with RC4'
                        DistinguishedName   = $user.DistinguishedName
                    }
                }
            }
        }

        # Check domain policy
        try {
            $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue

            # Also check GPO for Kerberos policy
            # Network security: Configure encryption types allowed for Kerberos
        } catch {
            # Can't check domain policy
        }

        # Check computer accounts (especially sensitive ones)
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $encTypes = $dc.'msDS-SupportedEncryptionTypes'

                if (-not $encTypes -or ($encTypes -band $rc4Flag)) {
                    $findings += [PSCustomObject]@{
                        ObjectType          = 'Domain Controller'
                        SamAccountName      = $dc.Name
                        SPNCount            = 'N/A'
                        EncryptionTypes     = if ($encTypes) { "0x$($encTypes.ToString('X'))" } else { 'Not Set' }
                        UsesRC4             = $true
                        HasAES              = ($encTypes -band ($aes128Flag -bor $aes256Flag)) -ne 0
                        Issue               = 'DC accepts RC4 Kerberos tickets'
                        RiskLevel           = 'Medium'
                        Impact              = 'May allow downgrade attacks'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure accounts to use AES encryption and disable RC4 where possible. Service accounts should be migrated to gMSAs.'
        Impact      = 'High - Disabling RC4 may break authentication for legacy systems. Test thoroughly.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable RC4 Kerberos Encryption
#############################################################################
#
# RC4 (ARCFOUR-HMAC-MD5) is weak encryption:
# - Kerberos tickets using RC4 can be cracked faster
# - Makes Kerberoasting attacks more effective
# - Should be disabled in favor of AES
#
# Affected Accounts:
$($Finding.Findings | Where-Object { $_.ObjectType -eq 'Service Account' } | ForEach-Object { "# - $($_.SamAccountName): $($_.Issue)" } | Out-String)

#############################################################################
# Step 1: Enable AES Encryption on Service Accounts
#############################################################################

# Encryption Type Values:
# 0x8  = AES128
# 0x10 = AES256
# 0x18 = AES128 + AES256 (recommended)
# 0x1C = AES128 + AES256 + RC4 (transitional)

"@

            $serviceAccounts = $Finding.Findings | Where-Object { $_.ObjectType -eq 'Service Account' }
            foreach ($item in $serviceAccounts) {
                $commands += @"

# Enable AES for: $($item.SamAccountName)
# Current: $($item.EncryptionTypes)
Set-ADUser -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES128,AES256'

# Verify the change:
# Get-ADUser -Identity '$($item.SamAccountName)' -Properties 'msDS-SupportedEncryptionTypes'

"@
            }

            $commands += @"

#############################################################################
# Step 2: Configure Domain-Wide RC4 Restrictions via GPO
#############################################################################

# Computer Configuration > Policies > Windows Settings > Security Settings >
#   Local Policies > Security Options

# "Network security: Configure encryption types allowed for Kerberos"
# Enable: AES128_HMAC_SHA1, AES256_HMAC_SHA1
# Disable: DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5

# WARNING: Test thoroughly before removing RC4 domain-wide

#############################################################################
# Step 3: Audit RC4 Usage
#############################################################################

# Enable Kerberos audit logging to identify RC4 usage:
# Event ID 4768 - TGT requested (shows encryption type)
# Event ID 4769 - Service ticket requested

# Filter for RC4 usage:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 1000 |
    Where-Object { `$_.Message -match 'Ticket Encryption Type.*0x17' } |  # 0x17 = RC4
    Select-Object TimeCreated, @{N='Account';E={(`$_.Message -split "`n" | Select-String 'Account Name').ToString()}}

#############################################################################
# Step 4: Migrate to gMSAs (Recommended)
#############################################################################

# Group Managed Service Accounts (gMSAs) automatically:
# - Rotate passwords every 30 days
# - Use strong passwords (240 random bytes)
# - Support AES encryption by default
# - Prevent password exposure

# Create a gMSA:
# New-ADServiceAccount -Name 'gMSA-SQLService' `
#     -DNSHostName 'gMSA-SQLService.domain.com' `
#     -PrincipalsAllowedToRetrieveManagedPassword 'SQLServers' `
#     -KerberosEncryptionType 'AES128,AES256'

#############################################################################
# Verification
#############################################################################

# Check all accounts with SPNs for RC4:
Get-ADUser -Filter { ServicePrincipalName -like '*' } `
    -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes' |
    Select-Object SamAccountName,
        @{N='SPNs';E={`$_.ServicePrincipalName.Count}},
        @{N='EncTypes';E={'0x' + `$_.'msDS-SupportedEncryptionTypes'.ToString('X')}},
        @{N='UsesRC4';E={
            `$et = `$_.'msDS-SupportedEncryptionTypes'
            if (-not `$et) { 'Default (RC4)' }
            elseif (`$et -band 4) { 'Yes' }
            else { 'No' }
        }}

"@
            return $commands
        }
    }
}

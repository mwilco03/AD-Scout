@{
    Id          = 'S-DesEnabled'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Accounts Using DES Kerberos Encryption'
    Description = 'Detects accounts with the USE_DES_KEY_ONLY flag enabled or DES encryption types configured. DES is a deprecated, weak encryption algorithm that can be cracked relatively easily.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Kerberos Encryption Types'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos' }
        @{ Title = 'DES Deprecation'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys' }
        @{ Title = 'PingCastle Rule S-DesEnabled'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558', 'T1557')  # Steal or Forge Kerberos Tickets, MITM
    }

    CIS   = @('18.3.4')
    STIG  = @('V-63629')
    ANSSI = @('R46')
    NIST  = @('SC-13', 'IA-5')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 10
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # USE_DES_KEY_ONLY = 0x200000 = 2097152
        $USE_DES_KEY_ONLY = 2097152
        $ACCOUNTDISABLE = 2

        # msDS-SupportedEncryptionTypes values
        # DES-CBC-CRC = 1
        # DES-CBC-MD5 = 2
        $DES_TYPES = 3  # 1 + 2

        try {
            # Check users
            foreach ($user in $Data.Users) {
                $uac = 0
                if ($user.userAccountControl) {
                    $uac = [int]$user.userAccountControl
                } elseif ($user.UserAccountControl) {
                    $uac = [int]$user.UserAccountControl
                }

                $isEnabled = -not ($uac -band $ACCOUNTDISABLE)

                # Check USE_DES_KEY_ONLY flag
                if ($uac -band $USE_DES_KEY_ONLY) {
                    $findings += [PSCustomObject]@{
                        ObjectType          = 'User'
                        Name                = $user.Name ?? $user.name
                        SamAccountName      = $user.SamAccountName ?? $user.sAMAccountName
                        DistinguishedName   = $user.DistinguishedName ?? $user.distinguishedName
                        Enabled             = $isEnabled
                        Issue               = 'USE_DES_KEY_ONLY flag set'
                        EncryptionTypes     = 'DES only'
                        Severity            = if ($isEnabled) { 'High' } else { 'Medium' }
                        Risk                = 'Account forces DES-only Kerberos encryption'
                        Impact              = 'Kerberos tickets can be cracked offline'
                    }
                }

                # Check msDS-SupportedEncryptionTypes
                $encTypes = $user.'msDS-SupportedEncryptionTypes' ?? $user.msDSSupportedEncryptionTypes
                if ($encTypes -and ($encTypes -band $DES_TYPES)) {
                    $findings += [PSCustomObject]@{
                        ObjectType          = 'User'
                        Name                = $user.Name ?? $user.name
                        SamAccountName      = $user.SamAccountName ?? $user.sAMAccountName
                        DistinguishedName   = $user.DistinguishedName ?? $user.distinguishedName
                        Enabled             = $isEnabled
                        Issue               = 'DES encryption enabled via msDS-SupportedEncryptionTypes'
                        EncryptionTypes     = $encTypes
                        Severity            = if ($isEnabled) { 'High' } else { 'Medium' }
                        Risk                = 'Account allows DES Kerberos encryption'
                        Impact              = 'Weak encryption increases attack surface'
                    }
                }
            }

            # Check computers (especially DCs)
            foreach ($computer in $Data.Computers) {
                $encTypes = $computer.'msDS-SupportedEncryptionTypes' ?? $computer.msDSSupportedEncryptionTypes

                if ($encTypes -and ($encTypes -band $DES_TYPES)) {
                    $isDC = $computer.PrimaryGroupID -eq 516 -or
                            ($computer.DistinguishedName ?? $computer.distinguishedName) -match 'Domain Controllers'

                    $findings += [PSCustomObject]@{
                        ObjectType          = if ($isDC) { 'Domain Controller' } else { 'Computer' }
                        Name                = $computer.Name ?? $computer.name
                        SamAccountName      = $computer.SamAccountName ?? $computer.sAMAccountName
                        DistinguishedName   = $computer.DistinguishedName ?? $computer.distinguishedName
                        Issue               = 'DES encryption enabled'
                        EncryptionTypes     = $encTypes
                        Severity            = if ($isDC) { 'Critical' } else { 'High' }
                        Risk                = 'Computer allows DES Kerberos encryption'
                        Impact              = if ($isDC) { 'DC Kerberos tickets vulnerable' } else { 'Weak encryption enabled' }
                    }
                }
            }

            # Check domain DCs directly
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $dcObj = [ADSI]"LDAP://$($dc.DistinguishedName)"
                    $encTypes = $dcObj.'msDS-SupportedEncryptionTypes'

                    if ($encTypes -and ($encTypes[0] -band $DES_TYPES)) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = 'Domain Controller'
                            Name                = $dc.Name
                            DistinguishedName   = $dc.DistinguishedName
                            Issue               = 'DES encryption enabled on DC'
                            EncryptionTypes     = $encTypes[0]
                            Severity            = 'Critical'
                            Risk                = 'Domain Controller allows DES encryption'
                            Impact              = 'All Kerberos operations may use weak encryption'
                        }
                    }
                } catch { }
            }

        } catch {
            Write-Verbose "S-DesEnabled: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove DES encryption support from all accounts. Update msDS-SupportedEncryptionTypes to only include AES encryption types.'
        Impact      = 'Medium - May break very old systems. Test with legacy applications before deploying widely.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# DES Encryption Remediation
#
# Objects with DES enabled:
$($Finding.Findings | ForEach-Object { "# - $($_.ObjectType): $($_.Name) - $($_.Issue)" } | Out-String)

# DES (Data Encryption Standard) is:
# - 56-bit key (effectively ~40-bit)
# - Crackable in hours on modern hardware
# - Deprecated since Windows Server 2008 R2

# STEP 1: Find all objects with USE_DES_KEY_ONLY flag
Write-Host "Accounts with USE_DES_KEY_ONLY flag:" -ForegroundColor Yellow
Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" -Properties userAccountControl |
    Select-Object Name, SamAccountName, Enabled | Format-Table -AutoSize

# STEP 2: Remove USE_DES_KEY_ONLY flag
`$desUsers = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" -Properties userAccountControl

foreach (`$user in `$desUsers) {
    `$newUAC = `$user.userAccountControl -band (-bnot 2097152)
    Set-ADUser -Identity `$user -Replace @{userAccountControl = `$newUAC}
    Write-Host "Removed USE_DES_KEY_ONLY from: `$(`$user.SamAccountName)" -ForegroundColor Green
}

# STEP 3: Check msDS-SupportedEncryptionTypes
# Bit flags:
# 1 = DES-CBC-CRC
# 2 = DES-CBC-MD5
# 4 = RC4-HMAC
# 8 = AES128-CTS-HMAC-SHA1-96
# 16 = AES256-CTS-HMAC-SHA1-96

# Recommended value: 24 (AES128 + AES256) or 28 (AES + RC4 for compatibility)
`$recommendedEncTypes = 24  # AES only
# `$recommendedEncTypes = 28  # AES + RC4 for compatibility

# Find objects with DES enabled
Write-Host "`nObjects with DES in msDS-SupportedEncryptionTypes:" -ForegroundColor Yellow
Get-ADObject -LDAPFilter "(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=3)" -Properties msDS-SupportedEncryptionTypes, objectClass |
    Select-Object Name, objectClass, msDS-SupportedEncryptionTypes | Format-Table -AutoSize

# STEP 4: Update encryption types for each object
$($Finding.Findings | Where-Object { $_.Issue -match 'msDS-SupportedEncryptionTypes' } | ForEach-Object { @"
# Update $($_.Name)
Set-ADObject -Identity "$($_.DistinguishedName)" -Replace @{'msDS-SupportedEncryptionTypes' = 24}
Write-Host "Updated encryption types for: $($_.Name)"

"@ })

# STEP 5: Disable DES domain-wide via GPO
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
# "Network security: Configure encryption types allowed for Kerberos"
# Uncheck DES_CBC_CRC and DES_CBC_MD5

# STEP 6: Update default domain controller policy
Write-Host "`nUpdating Default Domain Controllers Policy..."
# Via registry:
`$gpoName = "Default Domain Controllers Policy"
Set-GPRegistryValue -Name `$gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -ValueName "SupportedEncryptionTypes" -Type DWord -Value 24

# STEP 7: Verify no DES remains
Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" | Measure-Object
Get-ADObject -LDAPFilter "(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=3)" | Measure-Object

# STEP 8: Test Kerberos after changes
# klist purge
# klist get krbtgt

Write-Host @"

After removing DES support:
1. Purge Kerberos tickets on clients: klist purge
2. Test authentication to domain resources
3. Monitor for Kerberos errors in event logs
4. Event ID 4768/4769 failures may indicate compatibility issues

"@ -ForegroundColor Yellow

"@
            return $commands
        }
    }
}

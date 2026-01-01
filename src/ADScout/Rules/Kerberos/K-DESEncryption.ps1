<#
.SYNOPSIS
    Detects accounts with DES Kerberos encryption enabled.

.DESCRIPTION
    DES encryption is obsolete and can be cracked almost instantly.
    Accounts with "Use DES encryption types" flag or DES in supported
    encryption types are vulnerable.

.NOTES
    Rule ID    : K-DESEncryption
    Category   : Kerberos
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'K-DESEncryption'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'DES Kerberos Encryption Enabled'
    Description = 'Identifies accounts with DES encryption enabled for Kerberos. DES is cryptographically broken and can be cracked instantly.'
    Severity    = 'High'
    Weight      = 45
    DataSource  = 'Users,Computers'

    References  = @(
        @{ Title = 'Kerberos Encryption Types'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-encryption-types' }
        @{ Title = 'DES Deprecation'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/askds/des-is-dead' }
        @{ Title = 'Cracking DES'; Url = 'https://www.yourwaf.com/des-kerberos-attacks' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558')   # Steal or Forge Kerberos Tickets
    }

    CIS   = @('2.3.6.3')
    STIG  = @('V-63713')
    ANSSI = @('R37')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # UserAccountControl flag for USE_DES_KEY_ONLY
        $USE_DES_KEY_ONLY = 0x200000  # 2097152

        # msDS-SupportedEncryptionTypes flags
        $DES_CBC_CRC = 0x1
        $DES_CBC_MD5 = 0x2
        $DES_FLAGS = 0x3  # Both DES types

        # Check users
        if ($Data.Users) {
            foreach ($user in $Data.Users) {
                $hasDES = $false
                $desSource = ''

                # Check UserAccountControl for USE_DES_KEY_ONLY
                $uac = $user.UserAccountControl
                if ($uac -band $USE_DES_KEY_ONLY) {
                    $hasDES = $true
                    $desSource = 'USE_DES_KEY_ONLY flag in UAC'
                }

                # Check msDS-SupportedEncryptionTypes
                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                if ($encTypes -band $DES_FLAGS) {
                    $hasDES = $true
                    if ($desSource) {
                        $desSource += ' + DES in SupportedEncryptionTypes'
                    } else {
                        $desSource = 'DES in msDS-SupportedEncryptionTypes'
                    }
                }

                if ($hasDES) {
                    $isPrivileged = $user.AdminCount -eq 1
                    $hasSPN = $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0

                    $riskLevel = 'High'
                    if ($isPrivileged) { $riskLevel = 'Critical' }

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'User'
                        SamAccountName      = $user.SamAccountName
                        Enabled             = $user.Enabled
                        IsPrivileged        = $isPrivileged
                        HasSPN              = $hasSPN
                        DESSource           = $desSource
                        EncryptionTypes     = if ($encTypes) { "0x$($encTypes.ToString('X'))" } else { 'Not Set' }
                        RiskLevel           = $riskLevel
                        Impact              = 'Kerberos tickets can be cracked almost instantly'
                        DistinguishedName   = $user.DistinguishedName
                    }
                }
            }
        }

        # Check computers
        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                $hasDES = $false
                $desSource = ''

                $encTypes = $computer.'msDS-SupportedEncryptionTypes'
                if ($encTypes -band $DES_FLAGS) {
                    $hasDES = $true
                    $desSource = 'DES in msDS-SupportedEncryptionTypes'
                }

                if ($hasDES) {
                    $isDC = $computer.PrimaryGroupID -eq 516

                    $findings += [PSCustomObject]@{
                        ObjectType          = if ($isDC) { 'Domain Controller' } else { 'Computer' }
                        SamAccountName      = $computer.Name
                        Enabled             = $computer.Enabled
                        IsPrivileged        = $isDC
                        HasSPN              = $true  # All computers have SPNs
                        DESSource           = $desSource
                        EncryptionTypes     = "0x$($encTypes.ToString('X'))"
                        RiskLevel           = if ($isDC) { 'Critical' } else { 'High' }
                        Impact              = 'Kerberos tickets can be cracked almost instantly'
                        DistinguishedName   = $computer.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove DES encryption from all accounts. Configure AES-only encryption for Kerberos.'
        Impact      = 'Medium - Very old systems may require DES. Most modern systems work with AES only.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable DES Kerberos Encryption
#############################################################################
#
# DES (Data Encryption Standard) is BROKEN:
# - 56-bit key length
# - Can be brute-forced in hours on modern hardware
# - Rainbow tables make cracking instant
# - Deprecated since Windows Server 2008 R2
#
# Any Kerberos ticket encrypted with DES can be cracked trivially.
#
# Affected Accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.SamAccountName) ($($_.ObjectType)): $($_.DESSource)" } | Out-String)

#############################################################################
# Step 1: Remove DES Flag from User Accounts
#############################################################################

"@

            $userFindings = $Finding.Findings | Where-Object { $_.ObjectType -eq 'User' }
            foreach ($item in $userFindings) {
                $commands += @"

# Remove DES from: $($item.SamAccountName)
# Clear USE_DES_KEY_ONLY flag and set AES encryption only

`$user = Get-ADUser -Identity '$($item.SamAccountName)' -Properties UserAccountControl, 'msDS-SupportedEncryptionTypes'

# Remove USE_DES_KEY_ONLY from UserAccountControl
`$newUAC = `$user.UserAccountControl -band (-bnot 0x200000)
Set-ADUser -Identity '$($item.SamAccountName)' -Replace @{UserAccountControl = `$newUAC}

# Set encryption to AES only (0x18 = AES128 + AES256)
Set-ADUser -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES128,AES256'

Write-Host "Removed DES from $($item.SamAccountName)" -ForegroundColor Green

"@
            }

            $computerFindings = $Finding.Findings | Where-Object { $_.ObjectType -match 'Computer|Domain Controller' }
            foreach ($item in $computerFindings) {
                $commands += @"

# Remove DES from computer: $($item.SamAccountName)
Set-ADComputer -Identity '$($item.SamAccountName)' -KerberosEncryptionType 'AES128,AES256'
Write-Host "Set AES-only encryption on $($item.SamAccountName)" -ForegroundColor Green

"@
            }

            $commands += @"

#############################################################################
# Step 2: Disable DES Domain-Wide via Group Policy
#############################################################################

# Computer Configuration > Policies > Windows Settings > Security Settings >
#   Local Policies > Security Options

# "Network security: Configure encryption types allowed for Kerberos"
# Uncheck: DES_CBC_CRC, DES_CBC_MD5
# Check: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

# Registry equivalent:
`$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
# Value: SupportedEncryptionTypes = 0x18 (AES only) or 0x1C (AES + RC4)

#############################################################################
# Step 3: Find All DES-Enabled Accounts
#############################################################################

# Find users with USE_DES_KEY_ONLY flag
Get-ADUser -Filter { UserAccountControl -band 0x200000 } -Properties UserAccountControl |
    Select-Object SamAccountName, Enabled, @{N='UAC';E={'0x' + `$_.UserAccountControl.ToString('X')}}

# Find accounts with DES in supported encryption types
Get-ADUser -Filter { 'msDS-SupportedEncryptionTypes' -band 3 } `
    -Properties 'msDS-SupportedEncryptionTypes' |
    Select-Object SamAccountName, @{N='EncTypes';E={'0x' + `$_.'msDS-SupportedEncryptionTypes'.ToString('X')}}

# Check computers
Get-ADComputer -Filter { 'msDS-SupportedEncryptionTypes' -band 3 } `
    -Properties 'msDS-SupportedEncryptionTypes' |
    Select-Object Name, @{N='EncTypes';E={'0x' + `$_.'msDS-SupportedEncryptionTypes'.ToString('X')}}

#############################################################################
# Step 4: Verify No DES Remains
#############################################################################

# Count accounts still using DES
`$desUsers = (Get-ADUser -Filter { UserAccountControl -band 0x200000 }).Count
`$desEncUsers = (Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
    Where-Object { `$_.'msDS-SupportedEncryptionTypes' -band 3 }).Count

Write-Host "Users with USE_DES_KEY_ONLY: `$desUsers"
Write-Host "Users with DES encryption types: `$desEncUsers"

#############################################################################
# Troubleshooting Legacy Systems
#############################################################################

# If a system requires DES (very rare):
# 1. Identify the system and application
# 2. Plan upgrade/migration
# 3. If impossible to upgrade, isolate the system
# 4. Create exception documentation
# 5. Monitor for Kerberoasting attempts

# Check for DES Kerberos tickets in event logs:
# Event ID 4768 (TGT) and 4769 (TGS) with encryption type 0x1, 0x2, or 0x3

"@
            return $commands
        }
    }
}

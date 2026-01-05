@{
    Id          = 'G-GPPPassword'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Group Policy Preferences with Embedded Passwords (cpassword)'
    Description = 'Detects Group Policy Preferences (GPP) that contain embedded passwords in the cpassword field. The encryption key for these passwords was published by Microsoft, making any cpassword instantly decryptable by any domain user.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'MS14-025'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025' }
        @{ Title = 'GPP Password Decryption'; Url = 'https://attack.mitre.org/techniques/T1552/006/' }
        @{ Title = 'Get-GPPPassword'; Url = 'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1552.006')  # Unsecured Credentials: Group Policy Preferences
    }

    CIS   = @('18.9.59.1')
    STIG  = @('V-220940')
    ANSSI = @('R43')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $domainDN = (Get-ADDomain).DistinguishedName
            $domainName = (Get-ADDomain).DNSRoot

            # GPP files to check
            $gppFiles = @(
                'Groups\Groups.xml',
                'Services\Services.xml',
                'ScheduledTasks\ScheduledTasks.xml',
                'DataSources\DataSources.xml',
                'Drives\Drives.xml',
                'Printers\Printers.xml'
            )

            # Path to SYSVOL
            $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"

            # Get all GPOs
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                $gpoPath = Join-Path $sysvolPath "{$($gpo.Id)}"

                foreach ($type in @('Machine', 'User')) {
                    foreach ($gppFile in $gppFiles) {
                        $fullPath = Join-Path $gpoPath "$type\Preferences\$gppFile"

                        if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                            try {
                                [xml]$xml = Get-Content $fullPath -ErrorAction SilentlyContinue

                                # Search for cpassword attributes
                                $cpasswordNodes = $xml.SelectNodes("//*[@cpassword]")

                                foreach ($node in $cpasswordNodes) {
                                    $cpassword = $node.cpassword
                                    if ($cpassword -and $cpassword.Length -gt 0) {
                                        # Decrypt the password (the key is public)
                                        $decryptedPassword = ''
                                        try {
                                            $key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                                           0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
                                            $cpasswordBytes = [System.Convert]::FromBase64String($cpassword)
                                            $aes = [System.Security.Cryptography.Aes]::Create()
                                            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                                            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                                            $aes.Key = $key
                                            $aes.IV = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                                            $decryptor = $aes.CreateDecryptor()
                                            $decryptedBytes = $decryptor.TransformFinalBlock($cpasswordBytes, 0, $cpasswordBytes.Length)
                                            $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($decryptedBytes)
                                        }
                                        catch {
                                            $decryptedPassword = '[Decryption failed - but password IS recoverable]'
                                        }

                                        $userName = $node.userName ?? $node.name ?? $node.accountName ?? 'Unknown'

                                        $findings += [PSCustomObject]@{
                                            GPOName             = $gpo.DisplayName
                                            GPOID               = $gpo.Id
                                            FilePath            = $fullPath
                                            SettingType         = $gppFile -replace '\\.*',''
                                            UserName            = $userName
                                            PasswordRecoverable = $true
                                            PasswordLength      = if ($decryptedPassword) { $decryptedPassword.Length } else { 'Unknown' }
                                            RiskLevel           = 'Critical'
                                            Issue               = 'Password can be instantly decrypted by any domain user'
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
        }
        catch {
            # Could not check GPOs
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all GPP files containing cpassword. Use LAPS, gMSA, or other secure methods for credential management.'
        Impact      = 'High - Credential deployment method must be changed'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GPP PASSWORDS (cpassword)
# ================================================================
# Microsoft published the AES key used to "encrypt" GPP passwords.
# ANY domain user can read SYSVOL and decrypt these passwords.
#
# This is as good as plaintext. Remove immediately!

# ================================================================
# VULNERABLE GPOs
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName)
# File: $($item.FilePath)
# Setting Type: $($item.SettingType)
# User Name: $($item.UserName)
# Password Recoverable: YES

"@
            }

            $commands += @"

# ================================================================
# IMMEDIATE ACTIONS
# ================================================================

# 1. DELETE THE VULNERABLE GPP FILES
# For each affected GPO, delete the Preferences XML files

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Delete: $($item.FilePath)
# Remove-Item -Path "$($item.FilePath)" -Force

"@
            }

            $commands += @"

# 2. CHANGE ALL EXPOSED PASSWORDS
# Any password that was in GPP should be considered COMPROMISED
# Change immediately:
# - Local admin passwords -> Deploy LAPS instead
# - Service account passwords -> Use gMSA or manual secure deployment
# - Mapped drive passwords -> Use Kerberos/SSO instead

# 3. INSTALL MS14-025 (if not already)
# This update prevents NEW GPP passwords from being created
# But does NOT remove existing ones!

# ================================================================
# SECURE ALTERNATIVES
# ================================================================

# For Local Admin Passwords:
# - Use LAPS (Local Administrator Password Solution)
# - Passwords stored in AD, encrypted, access-controlled

# For Service Accounts:
# - Use Group Managed Service Accounts (gMSA)
# - Password managed automatically by AD

# For Mapped Drives:
# - Use Kerberos authentication (SSO)
# - No stored passwords needed

# For Scheduled Tasks:
# - Run as SYSTEM or use gMSA
# - If user context needed, use credential-free methods

# ================================================================
# DETECTION SCRIPT
# ================================================================

# Find all GPP files with passwords:
`$domainName = (Get-ADDomain).DNSRoot
`$sysvolPath = "\\`$domainName\SYSVOL\`$domainName\Policies"

Get-ChildItem -Path `$sysvolPath -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Drives.xml,Printers.xml -ErrorAction SilentlyContinue |
    ForEach-Object {
        [xml]`$xml = Get-Content `$_.FullName
        if (`$xml.SelectNodes("//*[@cpassword]").Count -gt 0) {
            Write-Warning "Found cpassword in: `$(`$_.FullName)"
        }
    }

# ================================================================
# GET-GPPPASSWORD (PowerSploit)
# ================================================================

# Attackers use this to harvest all GPP passwords:
# Import-Module PowerSploit
# Get-GPPPassword

# This returns all passwords in seconds. Assume attackers have them.

"@
            return $commands
        }
    }
}

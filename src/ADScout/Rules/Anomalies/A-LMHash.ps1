@{
    Id          = 'A-LMHash'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LM Hash Storage Enabled'
    Description = 'The domain allows storage of LM password hashes. LM hashes are trivially crackable and should never be stored.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Network security: Do not store LAN Manager hash'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change' }
        @{ Title = 'LM Hash Vulnerability'; Url = 'https://attack.mitre.org/techniques/T1003/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.002')  # OS Credential Dumping: Security Account Manager
    }

    CIS   = @('2.3.11.5')
    STIG  = @('V-1153')
    ANSSI = @('vuln1_lm_hash')
    NIST  = @('CM-6', 'CM-7', 'IA-2', 'IA-5(1)', 'SC-13')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($gpo in $Data) {
            # Check for NoLMHash setting in security policy
            # Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash should be 1
            if ($gpo.SecuritySettings) {
                $lmHashSetting = $gpo.SecuritySettings | Where-Object {
                    $_.Name -match 'NoLMHash' -or $_.KeyName -match 'NoLMHash'
                }

                if ($lmHashSetting -and $lmHashSetting.Value -eq 0) {
                    $findings += [PSCustomObject]@{
                        GPOName       = $gpo.DisplayName
                        GPOId         = $gpo.Id
                        Setting       = 'NoLMHash'
                        CurrentValue  = 0
                        ExpectedValue = 1
                        Risk          = 'LM hashes will be stored on password change'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable the "Network security: Do not store LAN Manager hash value on next password change" policy. All users should change passwords after enabling.'
        Impact      = 'Low - Very old systems (Windows 95/98/ME) may lose access'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable NoLMHash via Group Policy or registry
# GPO Path: Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
# Setting: "Network security: Do not store LAN Manager hash value on next password change" = Enabled

# Via Registry (apply to all DCs and member servers):
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Type DWord

# IMPORTANT: After enabling, all users should change their passwords
# to clear existing LM hashes from the database

# Force password change for all users (optional, high impact):

# Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon `$true

# Verify the setting:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash'

"@
            return $commands
        }
    }
}

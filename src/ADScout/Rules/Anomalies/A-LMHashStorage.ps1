@{
    Id          = 'A-LMHashStorage'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LM Hash Storage Enabled'
    Description = 'Detects if LM (LAN Manager) hash storage is enabled. LM hashes use extremely weak encryption and can be cracked in minutes. If passwords are changed while LM storage is enabled, the LM hash is stored alongside the NT hash.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'LM Hash Weakness'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change' }
        @{ Title = 'LM Hash Cracking'; Url = 'https://attack.mitre.org/techniques/T1003/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.002')  # Security Account Manager
    }

    CIS   = @('2.3.11.5')
    STIG  = @('V-220937')
    ANSSI = @('R36')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check local registry
            $noLMHash = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue

            if ($null -eq $noLMHash -or $noLMHash.NoLMHash -ne 1) {
                $findings += [PSCustomObject]@{
                    CheckLocation       = 'Local Registry'
                    RegistryPath        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash'
                    CurrentValue        = if ($noLMHash) { $noLMHash.NoLMHash } else { 'Not Set (defaults to enabled)' }
                    RequiredValue       = '1 (Disabled)'
                    RiskLevel           = 'Critical'
                    Issue               = 'LM hash storage is enabled - passwords can be cracked in minutes'
                }
            }

            # Check GPOs for this setting
            $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $allGPOs) {
                try {
                    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                    if ($report) {
                        $noLMSetting = $report.SelectNodes("//*[contains(@Name, 'NoLMHash') or contains(text(), 'Do not store LAN Manager')]")
                        if ($noLMSetting -and $noLMSetting.Count -gt 0) {
                            $findings += [PSCustomObject]@{
                                PolicyName      = $gpo.DisplayName
                                GPOID           = $gpo.Id
                                SettingFound    = 'LM Hash storage setting configured'
                                RiskLevel       = 'Verify Value'
                                Note            = 'Verify setting is Enabled (NoLMHash = 1)'
                            }
                        }
                    }
                }
                catch { }
            }

            # Check for users that might have LM hashes
            # LM hash will be aad3b435b51404eeaad3b435b51404ee if empty/not stored
            $emptyLMHash = 'aad3b435b51404eeaad3b435b51404ee'

            foreach ($user in $Data.Users) {
                if ($user.LMHash -and $user.LMHash -ne $emptyLMHash) {
                    $findings += [PSCustomObject]@{
                        CheckLocation       = 'User Account'
                        SamAccountName      = $user.SamAccountName
                        RiskLevel           = 'Critical'
                        Issue               = 'User has LM hash stored - password crackable in minutes'
                        Remediation         = 'Enable NoLMHash policy, then force password change'
                    }
                }
            }
        }
        catch {
            # Could not check settings
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable "Do not store LAN Manager hash" setting and force password changes for affected accounts.'
        Impact      = 'Low - LM hashes are not needed in modern environments'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# LM HASH STORAGE
# ================================================================
# LM hashes split password into two 7-character chunks and use DES.
# A 14-character password = two 7-character passwords to crack.
# Modern hardware: seconds to minutes for any LM hash.

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Check: $($item.CheckLocation)
# Current Value: $($item.CurrentValue ?? $item.SamAccountName)
# Risk: $($item.RiskLevel)
# Issue: $($item.Issue)

"@
            }

            $commands += @"

# ================================================================
# CHECK CURRENT SETTING
# ================================================================

# Check registry:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue

# Value should be: 1 (do not store LM hash)

# ================================================================
# REMEDIATION VIA GPO
# ================================================================

# 1. Open Group Policy Management
# 2. Edit Default Domain Policy
# 3. Navigate to:
#    Computer Configuration
#    -> Policies
#    -> Windows Settings
#    -> Security Settings
#    -> Local Policies
#    -> Security Options
# 4. Configure:
#    "Network security: Do not store LAN Manager hash value on next password change"
#    Value: Enabled

# PowerShell (direct registry):
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Type DWord

# ================================================================
# CLEAR EXISTING LM HASHES
# ================================================================

# After enabling the policy, users must change passwords
# to clear their LM hashes.

# Force password change on next logon:
# Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon `$true

# Or expire all passwords:
# Get-ADUser -Filter * -Properties PasswordLastSet |
#     Set-ADUser -Replace @{pwdLastSet=0}

# ================================================================
# VERIFY NO LM HASHES
# ================================================================

# Using PowerShell (requires DSInternals module):
# Install-Module DSInternals
# Get-ADReplAccount -All -Server DC01 |
#     Where-Object { `$_.LMHash -and `$_.LMHash -ne 'aad3b435b51404eeaad3b435b51404ee' } |
#     Select-Object SamAccountName

# The LM hash 'aad3b435b51404eeaad3b435b51404ee' means empty/not stored

"@
            return $commands
        }
    }
}

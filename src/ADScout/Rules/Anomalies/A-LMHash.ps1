@{
    Id          = 'A-LMHash'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LM Hash Storage Enabled'
    Description = 'Detects if LM hash storage is allowed. Checks both GPO policy AND DC registry to ensure NoLMHash is enforced consistently across all systems.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs,DomainControllers'

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
        $gpos = if ($Data.GPOs) { $Data.GPOs } else { $Data }
        $dcs = $Data.DomainControllers

        # ========================================================================
        # BELT: Check GPO enforcement for NoLMHash
        # ========================================================================
        $gpoEnforcesNoLMHash = $false

        foreach ($gpo in $gpos) {
            # Check for NoLMHash setting in security policy
            if ($gpo.SecuritySettings) {
                $lmHashSetting = $gpo.SecuritySettings | Where-Object {
                    $_.Name -match 'NoLMHash' -or $_.KeyName -match 'NoLMHash'
                }

                if ($lmHashSetting -and $lmHashSetting.Value -eq 0) {
                    $findings += [PSCustomObject]@{
                        ObjectType    = 'GPO Policy'
                        Computer      = $gpo.DisplayName
                        GPOId         = $gpo.Id
                        Setting       = 'NoLMHash'
                        CurrentValue  = 0
                        ExpectedValue = 1
                        RiskLevel     = 'High'
                        Risk          = 'GPO explicitly allows LM hash storage'
                        ConfigSource  = 'GPO'
                    }
                } elseif ($lmHashSetting -and $lmHashSetting.Value -eq 1) {
                    $gpoEnforcesNoLMHash = $true
                }
            }

            # Also check GptTmpl.inf for NoLMHash
            try {
                $gpoPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $gpoPath -ErrorAction SilentlyContinue) {
                    $content = Get-Content $gpoPath -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'NoLMHash\s*=\s*1') {
                        $gpoEnforcesNoLMHash = $true
                    }
                }
            } catch {}
        }

        if (-not $gpoEnforcesNoLMHash) {
            $findings += [PSCustomObject]@{
                ObjectType    = 'GPO Policy'
                Computer      = 'Domain-wide'
                GPOId         = 'N/A'
                Setting       = 'NoLMHash'
                CurrentValue  = 'Not Enforced'
                ExpectedValue = 1
                RiskLevel     = 'High'
                Risk          = 'No GPO enforces NoLMHash - DC configurations may drift'
                ConfigSource  = 'Missing GPO'
            }
        }

        # ========================================================================
        # SUSPENDERS: Check each DC's actual NoLMHash registry value
        # ========================================================================
        if ($dcs) {
            foreach ($dc in $dcs) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $noLMHash = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                        (Get-ItemProperty -Path $lsaPath -Name 'NoLMHash' -ErrorAction SilentlyContinue).NoLMHash
                    } -ErrorAction Stop

                    # NoLMHash should be 1 (disabled)
                    if ($noLMHash -ne 1) {
                        $findings += [PSCustomObject]@{
                            ObjectType    = 'DC Configuration'
                            Computer      = $dcName
                            GPOId         = 'N/A'
                            Setting       = 'NoLMHash'
                            CurrentValue  = if ($null -eq $noLMHash) { 'Not Set (defaults to 1 on modern OS)' } else { $noLMHash }
                            ExpectedValue = 1
                            RiskLevel     = if ($noLMHash -eq 0) { 'Critical' } else { 'Medium' }
                            Risk          = if ($noLMHash -eq 0) { 'LM hashes ARE being stored!' } else { 'NoLMHash not explicitly configured' }
                            ConfigSource  = 'Registry'
                        }
                    }
                } catch {
                    $findings += [PSCustomObject]@{
                        ObjectType    = 'DC Configuration'
                        Computer      = $dcName
                        GPOId         = 'N/A'
                        Setting       = 'NoLMHash'
                        CurrentValue  = 'Unable to check'
                        ExpectedValue = 1
                        RiskLevel     = 'Unknown'
                        Risk          = 'Could not verify NoLMHash setting'
                        ConfigSource  = 'Unknown'
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

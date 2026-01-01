@{
    Id          = 'A-NTLMv1Allowed'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'NTLMv1 Authentication Allowed'
    Description = 'Detects if NTLMv1 authentication is allowed in the domain. NTLMv1 uses weak cryptography that can be cracked in seconds. Attackers can downgrade NTLM sessions to NTLMv1 and crack the captured hashes to recover plaintext passwords.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'NTLMv1 Weaknesses'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
        @{ Title = 'Cracking NTLMv1'; Url = 'https://crack.sh/' }
        @{ Title = 'NTLM Relay Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1557.001', 'T1040')
    }

    CIS   = @('2.3.11.7')
    STIG  = @('V-220938')
    ANSSI = @('R37')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check domain GPO for LmCompatibilityLevel
            # Values: 0-2 allow NTLMv1, 3-5 require NTLMv2
            # Ideal: 5 (Send NTLMv2 response only. Refuse LM & NTLM)

            $defaultDomainPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue

            if ($defaultDomainPolicy) {
                # We can't directly read the setting, but we can flag for manual check
                $findings += [PSCustomObject]@{
                    PolicyName              = 'Default Domain Policy'
                    SettingToCheck          = 'Network security: LAN Manager authentication level'
                    RegistryPath            = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
                    RecommendedValue        = '5 (Send NTLMv2 response only. Refuse LM & NTLM)'
                    DangerousValues         = '0, 1, 2 (Allow NTLMv1)'
                    RiskLevel               = 'Requires Verification'
                    Impact                  = 'NTLMv1 can be cracked in seconds using rainbow tables or dedicated services'
                }
            }

            # Check for any GPOs that might set this value
            $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $allGPOs) {
                try {
                    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                    if ($report) {
                        $lmLevel = $report.SelectNodes("//*[contains(@Name, 'LmCompatibilityLevel') or contains(text(), 'LAN Manager authentication level')]")
                        if ($lmLevel -and $lmLevel.Count -gt 0) {
                            $findings += [PSCustomObject]@{
                                PolicyName              = $gpo.DisplayName
                                GPOID                   = $gpo.Id
                                SettingFound            = 'LAN Manager authentication level configured'
                                RiskLevel               = 'Verify Value'
                                Note                    = 'Manually verify value is 3 or higher (ideally 5)'
                            }
                        }
                    }
                }
                catch { }
            }

            # Also check local registry if available (for local scans)
            try {
                $lmLevel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue

                if ($lmLevel) {
                    $isVulnerable = $lmLevel.LmCompatibilityLevel -lt 3

                    $levelDescription = switch ($lmLevel.LmCompatibilityLevel) {
                        0 { 'Send LM & NTLM responses' }
                        1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
                        2 { 'Send NTLM response only' }
                        3 { 'Send NTLMv2 response only' }
                        4 { 'Send NTLMv2 response only. Refuse LM' }
                        5 { 'Send NTLMv2 response only. Refuse LM & NTLM' }
                        default { 'Unknown' }
                    }

                    if ($isVulnerable) {
                        $findings += [PSCustomObject]@{
                            CheckLocation           = 'Local Registry'
                            CurrentValue            = $lmLevel.LmCompatibilityLevel
                            CurrentDescription      = $levelDescription
                            RiskLevel               = 'Critical'
                            Issue                   = 'NTLMv1 is allowed - hashes can be cracked in seconds'
                            Remediation             = 'Set LmCompatibilityLevel to 5 via GPO'
                        }
                    }
                }
            }
            catch { }
        }
        catch {
            # Could not check GPO settings
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure LAN Manager authentication level to only allow NTLMv2 (value 5). Test application compatibility first.'
        Impact      = 'High - Legacy applications/devices may fail authentication'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# NTLMV1 AUTHENTICATION WEAKNESS
# ================================================================
# NTLMv1 uses DES-based cryptography that can be cracked instantly.
#
# Attack:
# 1. Attacker performs MITM or forces NTLM auth
# 2. Downgrades to NTLMv1
# 3. Submits challenge/response to crack.sh or uses rainbow tables
# 4. Password cracked in seconds
# 5. Use password for lateral movement

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Check: $($item.PolicyName ?? $item.CheckLocation)
# Setting: $($item.SettingToCheck ?? $item.CurrentDescription)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# CHECK CURRENT SETTING
# ================================================================

# Check via registry:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue

# Values:
# 0 = Send LM & NTLM responses (VERY DANGEROUS)
# 1 = Send LM & NTLM, use NTLMv2 session security if negotiated
# 2 = Send NTLM response only
# 3 = Send NTLMv2 response only (Minimum acceptable)
# 4 = Send NTLMv2 response only, refuse LM
# 5 = Send NTLMv2 response only, refuse LM & NTLM (RECOMMENDED)

# ================================================================
# REMEDIATION VIA GPO
# ================================================================

# 1. Open Group Policy Management
# 2. Edit Default Domain Policy (or create new GPO)
# 3. Navigate to:
#    Computer Configuration
#    -> Policies
#    -> Windows Settings
#    -> Security Settings
#    -> Local Policies
#    -> Security Options
# 4. Configure:
#    "Network security: LAN Manager authentication level"
#    Value: "Send NTLMv2 response only. Refuse LM & NTLM"

# PowerShell (direct registry - test first):
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5

# ================================================================
# COMPATIBILITY TESTING
# ================================================================

# Before enforcing, test with:
# 1. Audit mode: Set LmCompatibilityLevel to 3 first
# 2. Monitor for authentication failures
# 3. Event ID 4776 (Credential Validation) with error
# 4. Fix legacy applications

# Common issues:
# - Old NAS devices
# - Legacy printers
# - Old Linux/Samba versions
# - Ancient applications

# ================================================================
# ADDITIONAL HARDENING
# ================================================================

# Also disable LM hash storage:
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1

# Restrict NTLM:
# GPO: Network security: Restrict NTLM: Audit/Deny NTLM authentication

"@
            return $commands
        }
    }
}

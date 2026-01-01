<#
.SYNOPSIS
    Detects when NTLMv1 is not disabled in the domain.

.DESCRIPTION
    NTLMv1 uses weak cryptography and is vulnerable to cracking and relay attacks.
    Modern environments should disable NTLMv1 and require NTLMv2 at minimum.

.NOTES
    Rule ID    : AUTH-NTLMv1Enabled
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-NTLMv1Enabled'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'NTLMv1 Authentication Enabled'
    Description = 'Detects when NTLMv1 authentication is not disabled. NTLMv1 uses weak cryptography vulnerable to offline cracking and relay attacks.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Network Security: LAN Manager Authentication Level'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
        @{ Title = 'NTLM Security Concerns'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/ntlm-security-settings' }
        @{ Title = 'Cracking NTLMv1 Hashes'; Url = 'https://crack.sh/netntlm/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1110')  # LLMNR/NBT-NS Poisoning, Brute Force
    }

    CIS   = @('2.3.11.7')
    STIG  = @('V-63797')
    ANSSI = @('R68')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # LmCompatibilityLevel values:
        # 0 = Send LM & NTLM responses
        # 1 = Send LM & NTLM - use NTLMv2 session security if negotiated
        # 2 = Send NTLM response only
        # 3 = Send NTLMv2 response only
        # 4 = Send NTLMv2 response only. Refuse LM
        # 5 = Send NTLMv2 response only. Refuse LM & NTLM (most secure)

        $ntlmLevelFound = $false
        $currentLevel = $null
        $sourcePolicies = @()

        if ($Data.GPOs) {
            foreach ($gpo in $Data.GPOs) {
                # Check for LmCompatibilityLevel setting in GPO
                $gpoSettings = $gpo.Settings
                if (-not $gpoSettings) { continue }

                # Check Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
                # "Network security: LAN Manager authentication level"

                $lmSetting = $null
                if ($gpoSettings.SecurityOptions) {
                    $lmSetting = $gpoSettings.SecurityOptions | Where-Object {
                        $_.KeyName -match 'LmCompatibilityLevel' -or
                        $_.Name -match 'LAN Manager authentication level'
                    }
                }

                if ($lmSetting) {
                    $ntlmLevelFound = $true
                    $level = $lmSetting.Value
                    if ($null -eq $currentLevel -or $level -lt $currentLevel) {
                        $currentLevel = $level
                    }
                    $sourcePolicies += @{
                        GPOName = $gpo.DisplayName
                        Level = $level
                    }
                }
            }
        }

        # Also check registry on DCs if available
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $dcName = $dc.Name
                    if (-not $dcName) { $dcName = $dc.DnsHostName }

                    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                    $result = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        Get-ItemProperty -Path $using:regPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue

                    if ($result -and $result.LmCompatibilityLevel) {
                        $ntlmLevelFound = $true
                        $level = $result.LmCompatibilityLevel
                        if ($null -eq $currentLevel -or $level -lt $currentLevel) {
                            $currentLevel = $level
                        }
                        $sourcePolicies += @{
                            GPOName = "DC Registry: $dcName"
                            Level = $level
                        }
                    }
                } catch {
                    # Can't check this DC
                }
            }
        }

        # Determine if vulnerable
        $isVulnerable = $false
        $recommendation = ''

        if (-not $ntlmLevelFound) {
            # Default Windows behavior allows NTLMv1
            $isVulnerable = $true
            $currentLevel = 'Not configured (defaults to 0)'
            $recommendation = 'Configure LmCompatibilityLevel via GPO. Set to 5 (Send NTLMv2 only, refuse LM & NTLM)'
        } elseif ($currentLevel -lt 3) {
            $isVulnerable = $true
            $recommendation = "Current level $currentLevel allows NTLMv1. Increase to 5 (Send NTLMv2 only, refuse LM & NTLM)"
        }

        if ($isVulnerable) {
            $levelDescription = switch ($currentLevel) {
                0 { 'Send LM & NTLM responses' }
                1 { 'Send LM & NTLM, use NTLMv2 session security if negotiated' }
                2 { 'Send NTLM response only' }
                3 { 'Send NTLMv2 response only' }
                4 { 'Send NTLMv2 only, refuse LM' }
                5 { 'Send NTLMv2 only, refuse LM & NTLM' }
                default { "Unknown ($currentLevel)" }
            }

            $findings += [PSCustomObject]@{
                Setting             = 'LAN Manager Authentication Level'
                CurrentValue        = $currentLevel
                CurrentDescription  = $levelDescription
                RecommendedValue    = 5
                RecommendedDesc     = 'Send NTLMv2 response only. Refuse LM & NTLM.'
                SourcePolicies      = ($sourcePolicies | ForEach-Object { "$($_.GPOName): Level $($_.Level)" }) -join '; '
                Risk                = 'NTLMv1 can be cracked offline in seconds with rainbow tables'
                AttackPath          = 'Attacker captures NTLMv1 hash via poisoning, cracks password, gains access'
                RiskLevel           = if ($currentLevel -lt 2) { 'Critical' } else { 'High' }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure the domain to require NTLMv2 and refuse legacy LM and NTLM authentication.'
        Impact      = 'High - Legacy applications and systems may break. Test thoroughly before deploying.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable NTLMv1 and Legacy LAN Manager Authentication
#############################################################################
#
# NTLMv1 vulnerabilities:
# - Uses DES encryption (56-bit) - crackable in seconds
# - Susceptible to rainbow table attacks
# - NTLM relay attacks
# - Pass-the-hash attacks
#
# Current Configuration:
$($Finding.Findings | ForEach-Object { "# - $($_.Setting): $($_.CurrentValue) ($($_.CurrentDescription))" } | Out-String)

#############################################################################
# Step 1: Audit NTLM Usage Before Making Changes
#############################################################################

# Enable NTLM auditing via GPO or registry
# This logs all NTLM authentication attempts

# GPO Path: Computer Configuration > Policies > Windows Settings >
#           Security Settings > Local Policies > Security Options

# "Network security: Restrict NTLM: Audit NTLM authentication in this domain"
# Set to: "Enable all"

# Registry (on DCs):
# HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
# AuditNTLMInDomain = 7 (Audit all accounts)

# Review Event Log for NTLM events (Event ID 8001, 8002, 8003, 8004)

#############################################################################
# Step 2: Configure LAN Manager Authentication Level
#############################################################################

# Create or edit GPO linked to Domain Controllers and all computers

# GPO Path: Computer Configuration > Policies > Windows Settings >
#           Security Settings > Local Policies > Security Options

# Setting: "Network security: LAN Manager authentication level"
# Value: "Send NTLMv2 response only. Refuse LM & NTLM" (Level 5)

# PowerShell (direct registry - use GPO for production):
`$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-ItemProperty -Path `$regPath -Name 'LmCompatibilityLevel' -Value 5 -Type DWord

#############################################################################
# Step 3: Prevent LM Hash Storage
#############################################################################

# GPO Path: Computer Configuration > Policies > Windows Settings >
#           Security Settings > Local Policies > Security Options

# Setting: "Network security: Do not store LAN Manager hash value on next password change"
# Value: Enabled

# Registry:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Type DWord

#############################################################################
# Step 4: Configure Minimum Session Security
#############################################################################

# GPO Settings:
# "Network security: Minimum session security for NTLM SSP clients"
#   - Enable: Require NTLMv2 session security
#   - Enable: Require 128-bit encryption

# "Network security: Minimum session security for NTLM SSP servers"
#   - Enable: Require NTLMv2 session security
#   - Enable: Require 128-bit encryption

# Registry:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value 0x20080000 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value 0x20080000 -Type DWord

#############################################################################
# Testing Before Full Deployment
#############################################################################

# 1. Deploy to a test OU first
# 2. Monitor Event Log for authentication failures
# 3. Check application compatibility
# 4. Known incompatible scenarios:
#    - Very old Linux/Unix Samba clients
#    - Legacy network devices
#    - Old NAS appliances
#    - Some legacy LOB applications

# Rollback if needed:
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 3

"@
            return $commands
        }
    }
}

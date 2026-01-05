@{
    Id          = 'A-WinRMExposure'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'WinRM/PSRemoting Unrestricted Access'
    Description = 'Checks for computers where WinRM (Windows Remote Management) may be configured with excessive access. WinRM enables remote PowerShell execution, which attackers use for lateral movement after compromising credentials.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'WinRM Security'; Url = 'https://docs.microsoft.com/en-us/windows/win32/winrm/winrm-security' }
        @{ Title = 'PowerShell Remoting'; Url = 'https://attack.mitre.org/techniques/T1021/006/' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0002')  # Lateral Movement, Execution
        Techniques = @('T1021.006')  # Remote Services: Windows Remote Management
    }

    CIS   = @('18.9.102.1')
    STIG  = @('V-220952')
    ANSSI = @('R54')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check GPOs for WinRM configuration
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                try {
                    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue

                    # Check for WinRM settings
                    $winrmSettings = $report.SelectNodes("//*[contains(local-name(), 'WinRM') or contains(@Name, 'WinRM') or contains(@Name, 'RemoteShell') or contains(@Name, 'Remote Management')]")

                    if ($winrmSettings.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            GPOName             = $gpo.DisplayName
                            GPOID               = $gpo.Id
                            ConfigurationType   = 'WinRM GPO Settings'
                            RiskLevel           = 'Medium'
                            Review              = 'Verify WinRM is only enabled where needed with proper restrictions'
                        }
                    }

                    # Check for Firewall rules allowing WinRM
                    $firewallRules = $report.SelectNodes("//FirewallRules/*[contains(local-name(), 'Rule')]")
                    foreach ($rule in $firewallRules) {
                        if ($rule.Name -match 'WinRM|Windows Remote Management|5985|5986') {
                            $findings += [PSCustomObject]@{
                                GPOName             = $gpo.DisplayName
                                GPOID               = $gpo.Id
                                ConfigurationType   = 'Firewall Rule for WinRM'
                                RuleName            = $rule.Name
                                RiskLevel           = 'Medium'
                                Review              = 'Verify WinRM firewall rules are appropriately scoped'
                            }
                        }
                    }
                }
                catch { }
            }

            # Check Trusted Hosts if we can access local config
            try {
                $trustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue
                if ($trustedHosts -and $trustedHosts.Value -match '\*') {
                    $findings += [PSCustomObject]@{
                        ConfigurationType   = 'TrustedHosts Wildcard'
                        CurrentValue        = $trustedHosts.Value
                        RiskLevel           = 'High'
                        Issue               = 'WinRM TrustedHosts contains wildcard - allows connection to any host'
                        Impact              = 'Enables credential relay to any remote host'
                    }
                }
            }
            catch { }
        }
        catch {
            # Could not check WinRM settings
        }

        # Always add informational finding about WinRM importance
        if ($findings.Count -eq 0) {
            $findings += [PSCustomObject]@{
                ConfigurationType   = 'WinRM Assessment'
                RiskLevel           = 'Info'
                Note                = 'Review WinRM configuration across environment. By default, WinRM allows all Domain Admins remote access to all domain computers.'
                Recommendation      = 'Use JEA (Just Enough Administration) to restrict remote commands'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict WinRM access using firewall rules, JEA, and proper authentication requirements.'
        Impact      = 'Medium - May affect legitimate remote management workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# WINRM / POWERSHELL REMOTING SECURITY
# ================================================================
# WinRM enables remote PowerShell execution - powerful for admins,
# but equally powerful for attackers with credentials.
#
# By default, Domain Admins can PSRemote to any domain computer.

# ================================================================
# CURRENT FINDINGS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Type: $($item.ConfigurationType)
# GPO/Setting: $($item.GPOName ?? $item.CurrentValue ?? 'N/A')
# Risk: $($item.RiskLevel)
# Note: $($item.Review ?? $item.Issue ?? $item.Note)

"@
            }

            $commands += @"

# ================================================================
# CHECK CURRENT WINRM STATUS
# ================================================================

# Check if WinRM is running:
Get-Service WinRM

# Check WinRM configuration:
winrm get winrm/config

# Check TrustedHosts:
Get-Item WSMan:\localhost\Client\TrustedHosts

# Check who can connect:
Get-PSSessionConfiguration | Select-Object Name, Permission

# ================================================================
# HARDENING RECOMMENDATIONS
# ================================================================

# 1. RESTRICT BY FIREWALL
# Only allow WinRM from specific subnets (admin networks):

# Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Set-NetFirewallRule -RemoteAddress '10.0.1.0/24'

# 2. REQUIRE HTTPS
# Disable HTTP (5985), only allow HTTPS (5986):

# winrm set winrm/config/service '@{AllowUnencrypted="false"}'
# Configure certificate-based WinRM

# 3. USE JEA (JUST ENOUGH ADMINISTRATION)
# Create constrained endpoints with limited commands:

# Example JEA configuration:
# Register-PSSessionConfiguration -Name "LimitedAdmin" -SessionType RestrictedRemoteServer

# 4. CLEAR TRUSTEDHOSTS WILDCARD
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force

# 5. ENABLE LOGGING
# Configure WinRM event logging for detection:
# - Event ID 91 (Session Created)
# - Event ID 142 (WSMan operation)
# - Event ID 169 (User authenticated)

# Enable PowerShell transcription:
# GPO: Administrative Templates > Windows Components > Windows PowerShell

# ================================================================
# TIERED ACCESS MODEL
# ================================================================

# Tier 0: Only Tier 0 admins can PSRemote to DCs
# Tier 1: Only Tier 1 admins can PSRemote to servers
# Tier 2: Only Tier 2 admins can PSRemote to workstations

# Implement via:
# - GPO firewall rules
# - JEA endpoints
# - Credential Guard to prevent credential theft

# ================================================================
# DETECTION
# ================================================================

# Monitor for:
# - Event ID 4648 (Explicit credential logon) with WinRM
# - Event ID 4624 Type 3 (Network logon) on sensitive systems
# - PowerShell ScriptBlock logging for suspicious commands
# - WinRM from unexpected sources

"@
            return $commands
        }
    }
}

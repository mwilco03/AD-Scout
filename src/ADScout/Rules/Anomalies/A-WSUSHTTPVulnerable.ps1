@{
    Id          = 'A-WSUSHTTPVulnerable'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'WSUS Configuration Over HTTP (WSUS Attack)'
    Description = 'Detects if Windows Server Update Services (WSUS) is configured to use HTTP instead of HTTPS. WSUS over HTTP enables man-in-the-middle attacks where attackers can inject malicious updates to compromise SYSTEM-level access on all WSUS clients.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'WSUS Attack'; Url = 'https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/' }
        @{ Title = 'WSUSpendu'; Url = 'https://github.com/AlsidOfficial/WSUSpendu' }
        @{ Title = 'SharpWSUS'; Url = 'https://github.com/nettitude/SharpWSUS' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0004')  # Lateral Movement, Privilege Escalation
        Techniques = @('T1557', 'T1072')  # MITM, Software Deployment Tools
    }

    CIS   = @('18.9.105.2')
    STIG  = @('V-220955')
    ANSSI = @('R57')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check GPOs for WSUS settings
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                try {
                    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue

                    # Look for WSUS URL configuration
                    $wsusSettings = $report.SelectNodes("//*[contains(local-name(), 'WUServer') or contains(@Name, 'WUServer')]")

                    foreach ($setting in $wsusSettings) {
                        $value = $setting.InnerText ?? $setting.Value ?? $setting.'#text'

                        if ($value -match 'http://') {
                            $findings += [PSCustomObject]@{
                                GPOName             = $gpo.DisplayName
                                GPOID               = $gpo.Id
                                SettingName         = 'WSUS Server URL'
                                CurrentValue        = $value
                                RiskLevel           = 'Critical'
                                Issue               = 'WSUS configured over HTTP - vulnerable to MITM attacks'
                                Impact              = 'Attackers can inject malicious updates to gain SYSTEM on all clients'
                            }
                        }
                    }

                    # Also check for Windows Update settings that might indicate WSUS
                    $wuSettings = $report.SelectNodes("//*[contains(local-name(), 'WindowsUpdate') or contains(@Name, 'Windows Update')]")
                    if ($wuSettings.Count -gt 0) {
                        # GPO has Windows Update settings, flag for review
                    }
                }
                catch { }
            }

            # Check local registry
            try {
                $wsusServer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer' -ErrorAction SilentlyContinue
                $wsusStatusServer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUStatusServer' -ErrorAction SilentlyContinue

                if ($wsusServer -and $wsusServer.WUServer -match 'http://') {
                    $findings += [PSCustomObject]@{
                        CheckType           = 'Local Registry'
                        SettingName         = 'WUServer'
                        CurrentValue        = $wsusServer.WUServer
                        RiskLevel           = 'Critical'
                        Issue               = 'Local WSUS configuration uses HTTP'
                    }
                }

                if ($wsusStatusServer -and $wsusStatusServer.WUStatusServer -match 'http://') {
                    $findings += [PSCustomObject]@{
                        CheckType           = 'Local Registry'
                        SettingName         = 'WUStatusServer'
                        CurrentValue        = $wsusStatusServer.WUStatusServer
                        RiskLevel           = 'Critical'
                        Issue               = 'Local WSUS status server uses HTTP'
                    }
                }
            }
            catch { }
        }
        catch {
            # Could not check WSUS settings
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure WSUS to use HTTPS. Install SSL certificate on WSUS server and update GPO settings.'
        Impact      = 'Medium - Requires certificate deployment and GPO update'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# WSUS HTTP VULNERABILITY
# ================================================================
# WSUS over HTTP is vulnerable to man-in-the-middle attacks.
#
# Attack (WSUSpect/SharpWSUS):
# 1. Attacker positions on network path (ARP spoof, etc.)
# 2. Intercepts WSUS HTTP traffic
# 3. Injects malicious "update" (actually attacker executable)
# 4. Client downloads and runs with SYSTEM privileges
# 5. Instant SYSTEM access on all WSUS clients

# ================================================================
# VULNERABLE CONFIGURATION DETECTED
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Source: $($item.GPOName ?? $item.CheckType)
# Setting: $($item.SettingName)
# Current Value: $($item.CurrentValue)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# IMMEDIATE MITIGATION
# ================================================================

# If you can't deploy HTTPS immediately:
# 1. Restrict network path between clients and WSUS
# 2. Use IPsec to encrypt WSUS traffic
# 3. Monitor for ARP spoofing attempts

# ================================================================
# REMEDIATION: ENABLE HTTPS ON WSUS
# ================================================================

# Step 1: Obtain SSL certificate for WSUS server
# - Use internal CA or purchase certificate
# - Subject name should match WSUS server FQDN

# Step 2: Configure IIS on WSUS server
# - Open IIS Manager on WSUS server
# - Select WSUS website
# - Add HTTPS binding with certificate
# - Require SSL on the following virtual directories:
#   - SimpleAuthWebService
#   - DSSAuthWebService
#   - ServerSyncWebService
#   - ClientWebService
#   - APIRemoting30

# Step 3: Configure WSUS to use SSL
# On WSUS server (elevated PowerShell):
# wsusutil configuressl <wsusservername>

# Step 4: Update GPO
# Change WSUS URL from:
# http://wsus.domain.com:8530
# To:
# https://wsus.domain.com:8531

# GPO Location:
# Computer Configuration
# -> Policies
# -> Administrative Templates
# -> Windows Components
# -> Windows Update
# -> Specify intranet Microsoft update service location

# ================================================================
# VERIFICATION
# ================================================================

# On a client, verify HTTPS is used:
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' |
    Select-Object WUServer, WUStatusServer

# Should show https:// URLs

# ================================================================
# DETECTION
# ================================================================

# Monitor for WSUS attack indicators:
# - Unusual PsExec-like updates
# - Updates with strange names/publishers
# - WSUS client reporting to unknown servers

# Network monitoring:
# - HTTP traffic to port 8530 should not exist after HTTPS migration
# - ARP anomalies near WSUS traffic path

"@
            return $commands
        }
    }
}

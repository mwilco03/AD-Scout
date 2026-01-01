@{
    Id          = 'E-RemoteDomainAutoForward'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Remote Domain Auto-Forward Enabled'
    Description = 'Detects remote domain configurations that allow automatic email forwarding. The default remote domain (*) should have auto-forwarding disabled to prevent data exfiltration.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'MailFlow'

    References  = @(
        @{ Title = 'Configure Remote Domain Settings'; Url = 'https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/remote-domains/remote-domains' }
        @{ Title = 'Block External Forwarding'; Url = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/external-email-forwarding' }
    )

    MITRE = @{
        Tactics    = @('TA0010')  # Exfiltration
        Techniques = @('T1114.003')  # Email Collection: Email Forwarding Rule
    }

    CIS   = @('6.1.1')
    STIG  = @('O365-EX-000006')
    ANSSI = @('vuln1_autoforward_enabled')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($remoteDomain in $Data.MailFlow.RemoteDomains) {
            if ($remoteDomain.AutoForwardEnabled) {
                $riskLevel = 'Medium'

                # Default domain (*) with forwarding enabled is higher risk
                if ($remoteDomain.DomainName -eq '*') {
                    $riskLevel = 'Critical'
                }

                $findings += [PSCustomObject]@{
                    RemoteDomainName    = $remoteDomain.Name
                    DomainName          = $remoteDomain.DomainName
                    AutoForwardEnabled  = $remoteDomain.AutoForwardEnabled
                    AllowedOOFType      = $remoteDomain.AllowedOOFType
                    RiskLevel           = $riskLevel
                    Impact              = if ($remoteDomain.DomainName -eq '*') {
                        'All external auto-forwarding is allowed organization-wide'
                    } else {
                        "Auto-forwarding to $($remoteDomain.DomainName) is allowed"
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable auto-forwarding on remote domains, especially the default (*) domain.'
        Impact      = 'Medium - Legitimate auto-forwarding will stop working'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# REMOTE DOMAIN AUTO-FORWARD SETTINGS
# ================================================================
# Auto-forwarding should be DISABLED for the default remote domain (*)
# This is a critical security control against data exfiltration.

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Remote Domain: $($item.RemoteDomainName) ($($item.DomainName))
# Auto-Forward: ENABLED (should be disabled)
# Risk Level: $($item.RiskLevel)
# Impact: $($item.Impact)
# ================================================================

# Disable auto-forwarding:
Set-RemoteDomain -Identity '$($item.RemoteDomainName)' -AutoForwardEnabled `$false

"@
            }

            $commands += @"

# ================================================================
# RECOMMENDED: Disable on default domain
# ================================================================
Set-RemoteDomain -Identity 'Default' -AutoForwardEnabled `$false

# Verify all remote domains:
Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled | Format-Table -AutoSize

"@
            return $commands
        }
    }
}

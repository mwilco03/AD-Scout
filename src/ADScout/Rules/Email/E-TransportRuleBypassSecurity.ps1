@{
    Id          = 'E-TransportRuleBypassSecurity'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Transport Rules Bypassing Security Controls'
    Description = 'Detects transport rules that bypass spam filtering, malware scanning, or other security controls. Attackers create these rules to ensure malicious emails reach targets without inspection.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection'; Url = 'https://attack.mitre.org/techniques/T1114/' }
        @{ Title = 'Mail Flow Rule Security'; Url = 'https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' }
    )

    MITRE = @{
        Tactics    = @('TA0005', 'TA0003')  # Defense Evasion, Persistence
        Techniques = @('T1562.001')          # Impair Defenses: Disable or Modify Tools
    }

    CIS   = @('6.4.1')
    STIG  = @('O365-EX-000010')
    ANSSI = @('vuln1_transport_bypass')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($rule in $Data.TransportRules) {
            $isSuspicious = $false
            $bypassTypes = @()

            # Check for SCL bypass (spam confidence level set to -1)
            if ($rule.SetSCL -eq -1) {
                $isSuspicious = $true
                $bypassTypes += 'Spam Filter Bypass (SCL=-1)'
            }

            # Check for header manipulation that might bypass filtering
            if ($rule.SetHeaderName -match 'X-MS-Exchange-Organization-SCL|X-Spam|X-Forefront') {
                $isSuspicious = $true
                $bypassTypes += 'Header Manipulation'
            }

            # Note: Additional properties would need to be collected:
            # - SetAuditSeverity
            # - SenderAddressLocation
            # - SmtpRejectMessageRejectText (clearing security notices)

            if ($isSuspicious) {
                $findings += [PSCustomObject]@{
                    RuleName            = $rule.Name
                    RuleIdentity        = $rule.Identity
                    State               = $rule.State
                    Priority            = $rule.Priority
                    BypassTypes         = ($bypassTypes -join '; ')
                    FromCondition       = $rule.From
                    SentToCondition     = $rule.SentTo
                    SCLSetting          = $rule.SetSCL
                    WhenChanged         = $rule.WhenChanged
                    RiskLevel           = 'Critical'
                    SecurityImpact      = 'Allows emails to bypass security scanning'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable or remove transport rules that bypass security controls. Investigate who created them and why.'
        Impact      = 'Medium - Legitimate mail may be subjected to additional filtering'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: TRANSPORT RULES BYPASSING SECURITY
# ================================================================
# These rules allow emails to bypass spam/malware filtering.
# This is a SERIOUS security risk.

# Query audit logs to find who created these rules:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-180) -EndDate (Get-Date) ``
    -RecordType ExchangeAdmin -Operations 'New-TransportRule','Set-TransportRule' ``
    -ResultSize 5000 | Format-List

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Rule: $($item.RuleName)
# State: $($item.State)
# Priority: $($item.Priority)
# Bypass Types: $($item.BypassTypes)
# Security Impact: $($item.SecurityImpact)
# ================================================================

# View full rule details:
Get-TransportRule -Identity '$($item.RuleIdentity)' | Format-List *

# DISABLE immediately (preserves for investigation):
Disable-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

# Or REMOVE completely:
# Remove-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

"@
            }

            return $commands
        }
    }
}

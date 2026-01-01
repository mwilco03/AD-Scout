@{
    Id          = 'E-TransportRuleRedirect'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Transport Rules Redirecting Email'
    Description = 'Detects transport rules that redirect emails to different recipients. Unlike forwarding, redirection replaces the original recipient entirely, which can intercept communications covertly.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection'; Url = 'https://attack.mitre.org/techniques/T1114/' }
        @{ Title = 'Mail Flow Rules'; Url = 'https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' }
    )

    MITRE = @{
        Tactics    = @('TA0009', 'TA0010')  # Collection, Exfiltration
        Techniques = @('T1114.003')          # Email Collection: Email Forwarding Rule
    }

    CIS   = @('6.4.3')
    STIG  = @('O365-EX-000012')
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($rule in $Data.TransportRules) {
            if ($rule.RedirectMessageTo) {
                $findings += [PSCustomObject]@{
                    RuleName            = $rule.Name
                    RuleIdentity        = $rule.Identity
                    State               = $rule.State
                    Priority            = $rule.Priority
                    RedirectTarget      = $rule.RedirectMessageTo
                    FromCondition       = $rule.From
                    SentToCondition     = $rule.SentTo
                    WhenChanged         = $rule.WhenChanged
                    RiskLevel           = 'High'
                    Impact              = 'Original recipients will NOT receive emails'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review redirect transport rules to ensure they are authorized. Remove any unauthorized redirections.'
        Impact      = 'Medium - May affect legitimate mail routing'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# TRANSPORT RULES REDIRECTING EMAIL
# ================================================================
# WARNING: Redirected mail does NOT reach the original recipient.
# This is different from forwarding which sends a copy.

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Rule: $($item.RuleName)
# Redirects To: $($item.RedirectTarget)
# Scope: From=$($item.FromCondition), To=$($item.SentToCondition)
# Impact: $($item.Impact)
# ================================================================

# View rule details:
Get-TransportRule -Identity '$($item.RuleIdentity)' | Format-List *

# To disable:
Disable-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

# To remove:
# Remove-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

"@
            }

            return $commands
        }
    }
}

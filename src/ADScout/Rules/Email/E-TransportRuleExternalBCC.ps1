@{
    Id          = 'E-TransportRuleExternalBCC'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Transport Rules with External BCC'
    Description = 'Detects transport rules that blind copy (BCC) emails to external addresses. This is a data exfiltration technique that silently copies all matching emails outside the organization.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection: Email Forwarding Rule'; Url = 'https://attack.mitre.org/techniques/T1114/003/' }
        @{ Title = 'Automated Exfiltration'; Url = 'https://attack.mitre.org/techniques/T1020/' }
    )

    MITRE = @{
        Tactics    = @('TA0010', 'TA0009')  # Exfiltration, Collection
        Techniques = @('T1114.003', 'T1020')  # Email Forwarding Rule, Automated Exfiltration
    }

    CIS   = @('6.4.2')
    STIG  = @('O365-EX-000011')
    ANSSI = @('vuln1_transport_bcc')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $internalDomains = $Data.InternalDomains

        foreach ($rule in $Data.TransportRules) {
            if ($rule.BlindCopyTo) {
                $bccAddresses = $rule.BlindCopyTo -split ';' | ForEach-Object { $_.Trim() }

                # Check if any BCC address is external
                $externalBCC = @()
                foreach ($addr in $bccAddresses) {
                    $isExternal = $true
                    if ($internalDomains) {
                        foreach ($domain in $internalDomains) {
                            if ($addr -like "*@$domain") {
                                $isExternal = $false
                                break
                            }
                        }
                    }
                    if ($isExternal) {
                        $externalBCC += $addr
                    }
                }

                if ($externalBCC.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        RuleName            = $rule.Name
                        RuleIdentity        = $rule.Identity
                        State               = $rule.State
                        Priority            = $rule.Priority
                        ExternalBCCTargets  = ($externalBCC -join '; ')
                        FromCondition       = $rule.From
                        SentToCondition     = $rule.SentTo
                        WhenChanged         = $rule.WhenChanged
                        RiskLevel           = 'Critical'
                        DataAtRisk          = 'All emails matching this rule are copied externally'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove external BCC targets from transport rules immediately. This is likely a data exfiltration attempt.'
        Impact      = 'Low - Stops unauthorized data copying'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: EXTERNAL BCC IN TRANSPORT RULES
# ================================================================
# These rules silently copy emails to external addresses.
# This is almost certainly malicious or unauthorized.

# INVESTIGATE IMMEDIATELY:
# - Who created the rule?
# - What emails have been copied?
# - Is this a known data breach?

# Check audit logs:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-180) -EndDate (Get-Date) ``
    -RecordType ExchangeAdmin -Operations 'New-TransportRule','Set-TransportRule' ``
    -ResultSize 5000 | Where-Object { `$_.AuditData -like '*BlindCopyTo*' }

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# CRITICAL FINDING
# Rule: $($item.RuleName)
# External BCC: $($item.ExternalBCCTargets)
# Scope: From=$($item.FromCondition), To=$($item.SentToCondition)
# ================================================================

# DISABLE IMMEDIATELY:
Disable-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

# View message trace to see what was exfiltrated (last 10 days):
Get-MessageTrace -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) ``
    -RecipientAddress '$($item.ExternalBCCTargets.Split(';')[0].Trim())'

# REMOVE the rule after investigation:
# Remove-TransportRule -Identity '$($item.RuleIdentity)' -Confirm:`$false

"@
            }

            $commands += @"

# ================================================================
# PREVENTION
# ================================================================

# Block external BCC at the organization level using RBAC:
# Limit who can create/modify transport rules

# Set up alerts for transport rule changes:
# In Security & Compliance Center > Alerts > Alert Policies

"@
            return $commands
        }
    }
}

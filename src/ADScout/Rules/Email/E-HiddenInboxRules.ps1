@{
    Id          = 'E-HiddenInboxRules'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Suspicious Hidden Inbox Rules'
    Description = 'Detects inbox rules that forward, redirect, or delete emails. Attackers often create these rules to exfiltrate data or hide evidence of compromise. Rules that mark messages as read and delete them are particularly suspicious.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Forwarding Rule'; Url = 'https://attack.mitre.org/techniques/T1114/003/' }
        @{ Title = 'Email Hiding Rules'; Url = 'https://attack.mitre.org/techniques/T1564/008/' }
        @{ Title = 'Hunting for Suspicious Inbox Rules'; Url = 'https://www.microsoft.com/en-us/security/blog/2020/06/18/hunting-for-o365-suspicious-inbox-rules/' }
    )

    MITRE = @{
        Tactics    = @('TA0005', 'TA0009', 'TA0010')  # Defense Evasion, Collection, Exfiltration
        Techniques = @('T1114.003', 'T1564.008')      # Email Forwarding, Email Hiding Rules
    }

    CIS   = @('6.2.3')
    STIG  = @('O365-EX-000002')
    ANSSI = @('vuln1_hidden_inbox_rules')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($rule in $Data.InboxRules) {
            # Only flag suspicious rules
            if ($rule.IsSuspicious -or $rule.ForwardTo -or $rule.RedirectTo -or
                $rule.ForwardAsAttachmentTo -or $rule.DeleteMessage) {

                # Calculate threat score
                $threatScore = 0
                $indicators = @()

                if ($rule.ForwardTo -or $rule.RedirectTo) {
                    $threatScore += 30
                    $indicators += 'Forwards/Redirects mail'
                }
                if ($rule.ForwardAsAttachmentTo) {
                    $threatScore += 35
                    $indicators += 'Forwards as attachment (evades DLP)'
                }
                if ($rule.DeleteMessage) {
                    $threatScore += 25
                    $indicators += 'Deletes messages'
                }
                if ($rule.MarkAsRead) {
                    $threatScore += 15
                    $indicators += 'Marks as read (stealth)'
                }
                if ($rule.SuspiciousReasons -like '*BroadScope*') {
                    $threatScore += 20
                    $indicators += 'Applies to all mail (no filters)'
                }

                # Determine if target is external
                $forwardTarget = $rule.ForwardTo, $rule.RedirectTo, $rule.ForwardAsAttachmentTo |
                    Where-Object { $_ } | Select-Object -First 1

                $isExternal = $false
                if ($forwardTarget -and $Data.InternalDomains) {
                    $isExternal = $true
                    foreach ($domain in $Data.InternalDomains) {
                        if ($forwardTarget -like "*@$domain*") {
                            $isExternal = $false
                            break
                        }
                    }
                }

                if ($isExternal) {
                    $threatScore += 25
                    $indicators += 'External destination'
                }

                $findings += [PSCustomObject]@{
                    MailboxAddress          = $rule.MailboxAddress
                    RuleName                = $rule.RuleName
                    Enabled                 = $rule.Enabled
                    Priority                = $rule.Priority
                    ForwardTo               = $rule.ForwardTo
                    RedirectTo              = $rule.RedirectTo
                    ForwardAsAttachmentTo   = $rule.ForwardAsAttachmentTo
                    DeleteMessage           = $rule.DeleteMessage
                    MarkAsRead              = $rule.MarkAsRead
                    FromFilter              = $rule.From
                    SubjectFilter           = $rule.SubjectContainsWords
                    ThreatScore             = $threatScore
                    ThreatIndicators        = ($indicators -join '; ')
                    IsExternalTarget        = $isExternal
                    RiskLevel               = switch ($threatScore) {
                        { $_ -ge 70 } { 'Critical' }
                        { $_ -ge 50 } { 'High' }
                        { $_ -ge 30 } { 'Medium' }
                        default { 'Low' }
                    }
                }
            }
        }

        # Sort by threat score descending
        return $findings | Sort-Object -Property ThreatScore -Descending
    }

    Remediation = @{
        Description = 'Disable or remove suspicious inbox rules immediately. Investigate account compromise and check audit logs for rule creation.'
        Impact      = 'Low - Removes malicious email rules'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SUSPICIOUS INBOX RULES DETECTED
# ================================================================
# These rules may indicate account compromise or insider threat.
# INVESTIGATE IMMEDIATELY before removing.

# Query audit logs to find who created these rules:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) ``
    -RecordType ExchangeItem -Operations 'New-InboxRule','Set-InboxRule' ``
    -ResultSize 5000 | Format-List

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.MailboxAddress)
# Rule: $($item.RuleName)
# Threat Score: $($item.ThreatScore) ($($item.RiskLevel))
# Indicators: $($item.ThreatIndicators)
# ================================================================

# View rule details:
Get-InboxRule -Mailbox '$($item.MailboxAddress)' -Identity '$($item.RuleName)' | Format-List *

# Disable the rule (preserves for investigation):
Disable-InboxRule -Mailbox '$($item.MailboxAddress)' -Identity '$($item.RuleName)' -Confirm:`$false

# Or remove completely:
# Remove-InboxRule -Mailbox '$($item.MailboxAddress)' -Identity '$($item.RuleName)' -Confirm:`$false

"@
            }

            $commands += @"

# ================================================================
# PREVENTION: Block inbox rule creation via OWA
# ================================================================

# Create OWA mailbox policy that disables rule creation:

# Set-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' ``
#     -AllowOfflineOn NoComputers ``
#     -OWALightEnabled `$false

"@
            return $commands
        }
    }
}

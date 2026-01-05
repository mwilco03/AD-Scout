@{
    Id          = 'E-ExternalForwarding'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'External Email Forwarding Configured'
    Description = 'Detects mailboxes with forwarding configured to external email addresses. This is a common data exfiltration technique where attackers set up auto-forwarding to siphon emails to external accounts.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection: Email Forwarding Rule'; Url = 'https://attack.mitre.org/techniques/T1114/003/' }
        @{ Title = 'Detecting and Remediating Illicit Consent Grants'; Url = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants' }
        @{ Title = 'BEC Attack Using Forwarding Rules'; Url = 'https://www.microsoft.com/en-us/security/blog/2021/06/14/behind-the-scenes-of-business-email-compromise/' }
    )

    MITRE = @{
        Tactics    = @('TA0009', 'TA0010')  # Collection, Exfiltration
        Techniques = @('T1114.003')          # Email Collection: Email Forwarding Rule
    }

    CIS   = @('6.2.1')
    STIG  = @('O365-EX-000001')
    ANSSI = @('vuln1_email_forwarding')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $internalDomains = $Data.InternalDomains

        # Check mailbox-level forwarding
        foreach ($forwarding in $Data.ForwardingRules) {
            if ($forwarding.IsExternal) {
                $findings += [PSCustomObject]@{
                    MailboxAddress          = $forwarding.MailboxAddress
                    DisplayName             = $forwarding.DisplayName
                    ForwardingType          = $forwarding.ForwardingType
                    ForwardingTarget        = $forwarding.ForwardingTarget
                    KeepsCopy               = $forwarding.DeliverToMailboxAndForward
                    RiskLevel               = if ($forwarding.DeliverToMailboxAndForward) { 'High' } else { 'Critical' }
                    RiskReason              = if ($forwarding.DeliverToMailboxAndForward) {
                        'External forwarding with local copy (possible legitimate use)'
                    } else {
                        'External forwarding without local copy (likely malicious)'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove external forwarding and investigate why it was configured. Check audit logs to determine who enabled the forwarding.'
        Impact      = 'Low - Removes unauthorized email forwarding'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# External Email Forwarding Detected
# CRITICAL: Investigate immediately - this is a common attack technique

# Audit log query to find who configured forwarding:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) ``
    -RecordType ExchangeAdmin -Operations Set-Mailbox ``
    -ResultSize 5000 | Where-Object { `$_.AuditData -like '*ForwardingSmtpAddress*' }

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.DisplayName) <$($item.MailboxAddress)>
# Forwarding To: $($item.ForwardingTarget)
# Risk Level: $($item.RiskLevel)
# ================================================================

# Remove forwarding:
Set-Mailbox -Identity '$($item.MailboxAddress)' -ForwardingSmtpAddress `$null -ForwardingAddress `$null -DeliverToMailboxAndForward `$false

# Block external forwarding for this mailbox:
Set-Mailbox -Identity '$($item.MailboxAddress)' -ForwardingSmtpAddress `$null
Set-TransportRule -Identity 'Block External Forwarding' -ExceptIfFrom '$($item.MailboxAddress)'

# Check for any inbox rules also forwarding:
Get-InboxRule -Mailbox '$($item.MailboxAddress)' | Where-Object { `$_.ForwardTo -or `$_.RedirectTo }

"@
            }

            $commands += @"

# ================================================================
# ORGANIZATION-WIDE PROTECTION
# ================================================================

# Block all external auto-forwarding at the organization level:
Set-RemoteDomain Default -AutoForwardEnabled `$false

# Create transport rule to block external forwarding:
New-TransportRule -Name 'Block External Auto-Forward' ``
    -FromScope InOrganization ``
    -SentToScope NotInOrganization ``
    -MessageTypeMatches AutoForward ``
    -RejectMessageReasonText 'External auto-forwarding is not allowed'

"@
            return $commands
        }
    }
}

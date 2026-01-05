@{
    Id          = 'E-FullAccessDelegation'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Mailbox Full Access Delegation'
    Description = 'Detects mailboxes with Full Access permissions granted to other users. Full Access allows complete control over the mailbox including reading, deleting, and sending emails. Excessive or unauthorized delegations can enable data theft or impersonation.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection: Remote Email Collection'; Url = 'https://attack.mitre.org/techniques/T1114/002/' }
        @{ Title = 'Managing Mailbox Permissions'; Url = 'https://learn.microsoft.com/en-us/exchange/recipients/mailbox-permissions' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0009')  # Initial Access, Collection
        Techniques = @('T1114.002', 'T1078.002')  # Remote Email Collection, Domain Accounts
    }

    CIS   = @('6.3.1')
    STIG  = @('O365-EX-000003')
    ANSSI = @('vuln1_mailbox_delegation')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Group permissions by mailbox to find excessive delegations
        $mailboxDelegations = $Data.MailboxPermissions | Group-Object MailboxIdentity

        foreach ($mbxGroup in $mailboxDelegations) {
            $delegateCount = ($mbxGroup.Group | Measure-Object).Count

            foreach ($perm in $mbxGroup.Group) {
                $riskLevel = 'Medium'
                $riskFactors = @()

                # Check for excessive delegations
                if ($delegateCount -gt 5) {
                    $riskLevel = 'High'
                    $riskFactors += "Excessive delegates ($delegateCount)"
                }

                # Check if delegate is a service account
                if ($perm.Trustee -match 'svc|service|admin|system') {
                    $riskFactors += 'Service/Admin account'
                }

                # Check if mailbox belongs to VIP/Executive (would need VIP list)
                # This would be enhanced with a VIP mailbox list configuration

                $findings += [PSCustomObject]@{
                    MailboxAddress      = $perm.MailboxAddress
                    MailboxDisplayName  = $perm.DisplayName
                    Delegate            = $perm.Trustee
                    AccessRights        = $perm.AccessRights
                    IsInherited         = $perm.IsInherited
                    TotalDelegates      = $delegateCount
                    RiskLevel           = $riskLevel
                    RiskFactors         = ($riskFactors -join '; ')
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove unnecessary Full Access permissions. Document approved delegations and implement regular access reviews.'
        Impact      = 'Medium - Users may lose access to shared mailboxes'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# MAILBOX FULL ACCESS DELEGATION REVIEW
# ================================================================
# Full Access allows complete mailbox control including:
# - Reading all emails
# - Deleting emails
# - Sending emails (with separate permission)

# List all delegations for review:
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | ``
    Where-Object { `$_.User -notlike '*SELF*' -and -not `$_.IsInherited } | ``
    Select-Object Identity, User, AccessRights | ``
    Export-Csv -Path 'MailboxDelegations.csv' -NoTypeInformation

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Delegate: $($item.Delegate)
# Total Delegates: $($item.TotalDelegates)
# Risk: $($item.RiskLevel) - $($item.RiskFactors)
# ================================================================

# Remove Full Access permission:
Remove-MailboxPermission -Identity '$($item.MailboxAddress)' -User '$($item.Delegate)' -AccessRights FullAccess -Confirm:`$false

# Or to document as approved (skip in next scan):
# Add approved delegate to exception list

"@
            }

            $commands += @"

# ================================================================
# AUDIT: Find when permissions were granted
# ================================================================
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-180) -EndDate (Get-Date) ``
    -RecordType ExchangeAdmin -Operations 'Add-MailboxPermission' ``
    -ResultSize 5000 | Export-Csv -Path 'DelegationAudit.csv' -NoTypeInformation

"@
            return $commands
        }
    }
}

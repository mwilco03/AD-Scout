@{
    Id          = 'E-SendAsPermission'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Send As Permission Granted'
    Description = 'Detects mailboxes where Send As permission has been granted. Send As allows users to send emails that appear to come directly from another mailbox with no indication of the actual sender. This is commonly abused for impersonation and phishing.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection'; Url = 'https://attack.mitre.org/techniques/T1114/' }
        @{ Title = 'Manage Send As Permissions'; Url = 'https://learn.microsoft.com/en-us/exchange/recipients/mailbox-permissions' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0043')  # Initial Access, Reconnaissance
        Techniques = @('T1534', 'T1078.002')  # Internal Spearphishing, Domain Accounts
    }

    CIS   = @('6.3.2')
    STIG  = @('O365-EX-000004')
    ANSSI = @('vuln1_sendas_permission')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($perm in $Data.SendAsPermissions) {
            $riskLevel = 'Medium'
            $riskFactors = @()

            # Higher risk if granted to non-standard accounts
            if ($perm.Trustee -match 'svc|service|external|guest') {
                $riskLevel = 'High'
                $riskFactors += 'Non-standard account type'
            }

            # Check for executive/VIP mailboxes would go here

            $findings += [PSCustomObject]@{
                MailboxAddress      = $perm.MailboxAddress
                MailboxDisplayName  = $perm.DisplayName
                Trustee             = $perm.Trustee
                AccessControlType   = $perm.AccessControlType
                PermissionType      = 'SendAs'
                RiskLevel           = $riskLevel
                RiskFactors         = ($riskFactors -join '; ')
                ImpersonationRisk   = 'Can send email as this user with no recipient visibility'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove unnecessary Send As permissions. Consider using Send on Behalf instead which shows the actual sender.'
        Impact      = 'Medium - Users may lose ability to send as shared mailboxes'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SEND AS PERMISSION REVIEW
# ================================================================
# Send As is HIGH RISK because:
# - Recipient sees email as coming from the mailbox owner
# - No indication that someone else sent it
# - Perfect for impersonation attacks

# CONSIDER: Using 'Send on Behalf' instead (shows actual sender)

# Export all Send As permissions:
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-RecipientPermission -Identity `$_.Identity | ``
        Where-Object { `$_.Trustee -notlike '*SELF*' -and `$_.AccessRights -contains 'SendAs' }
} | Export-Csv -Path 'SendAsPermissions.csv' -NoTypeInformation

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Can Send As: $($item.Trustee)
# Risk: $($item.RiskLevel)
# ================================================================

# Remove Send As permission:
Remove-RecipientPermission -Identity '$($item.MailboxAddress)' -Trustee '$($item.Trustee)' -AccessRights SendAs -Confirm:`$false

# Convert to Send on Behalf (safer - shows actual sender):
Set-Mailbox -Identity '$($item.MailboxAddress)' -GrantSendOnBehalfTo @{Add='$($item.Trustee)'}

"@
            }

            return $commands
        }
    }
}

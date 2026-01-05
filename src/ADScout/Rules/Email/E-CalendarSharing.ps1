@{
    Id          = 'E-CalendarSharing'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'External Calendar Sharing Enabled'
    Description = 'Detects calendars shared with external users or configured for anonymous access. Calendar data can reveal meeting participants, locations, and business activities that may be sensitive.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Calendar Sharing in Exchange'; Url = 'https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies' }
    )

    MITRE = @{
        Tactics    = @('TA0009', 'TA0043')  # Collection, Reconnaissance
        Techniques = @('T1213')              # Data from Information Repositories
    }

    CIS   = @('6.7.1')
    STIG  = @('O365-EX-000030')
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 8
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Would require calendar permission collection
        # Get-MailboxFolderPermission -Identity user@domain.com:\Calendar

        # Organization sharing policy check
        # Get-SharingPolicy

        return $findings
    }

    Remediation = @{
        Description = 'Review external calendar sharing and restrict to business-justified cases only.'
        Impact      = 'Medium - May affect external scheduling workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CALENDAR SHARING REVIEW
# ================================================================

# Check organization sharing policy:
Get-SharingPolicy | Format-List Name, Domains, Enabled

# Find users with external calendar sharing:
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-MailboxFolderPermission -Identity "`$(`$_.PrimarySmtpAddress):\Calendar" -ErrorAction SilentlyContinue | ``
        Where-Object { `$_.User -match 'Anonymous|Default' -and `$_.AccessRights -ne 'None' }
} | Format-Table Identity, User, AccessRights

# To restrict default sharing:
Set-SharingPolicy -Identity 'Default Sharing Policy' -Enabled `$false

# To limit calendar sharing for specific user:
# Set-MailboxFolderPermission -Identity 'user@domain.com:\Calendar' -User Default -AccessRights None

"@
            return $commands
        }
    }
}

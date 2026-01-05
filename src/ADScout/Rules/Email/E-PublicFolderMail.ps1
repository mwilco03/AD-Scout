@{
    Id          = 'E-PublicFolderMail'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Mail-Enabled Public Folders'
    Description = 'Detects mail-enabled public folders that can receive external email. These folders are often forgotten about and can become vectors for spam, phishing, or data exposure.'
    Severity    = 'Low'
    Weight      = 10
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Public Folders in Exchange'; Url = 'https://learn.microsoft.com/en-us/exchange/collaboration/public-folders/public-folders' }
    )

    MITRE = @{
        Tactics    = @('TA0009')  # Collection
        Techniques = @('T1213')    # Data from Information Repositories
    }

    CIS   = @('6.6.1')
    STIG  = @()
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Would need to collect public folder data
        # Get-MailPublicFolder -ResultSize Unlimited

        # This is a placeholder for the detection logic
        # The collector would need to be extended to include public folders

        return $findings
    }

    Remediation = @{
        Description = 'Review mail-enabled public folders and disable external mail reception where not needed.'
        Impact      = 'Low - May affect legacy workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# MAIL-ENABLED PUBLIC FOLDERS
# ================================================================

# List all mail-enabled public folders:
Get-MailPublicFolder -ResultSize Unlimited | ``
    Select-Object Name, PrimarySmtpAddress, Alias | ``
    Format-Table -AutoSize

# For each folder, consider:
# 1. Is external mail needed?
# 2. Who has access?
# 3. Is the content still relevant?

# To disable external mail on a public folder:
# Set-MailPublicFolder -Identity '<folder>' -AcceptMessagesOnlyFromSendersOrMembers @{Add='<internal-group>'}

"@
            return $commands
        }
    }
}

@{
    Id          = 'E-SendOnBehalfPermission'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Send on Behalf Permission Granted'
    Description = 'Detects mailboxes where Send on Behalf permission has been granted. Unlike Send As, this shows "Sender on behalf of Mailbox" to recipients. While less risky than Send As, excessive delegation should be reviewed.'
    Severity    = 'Low'
    Weight      = 10
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Mailbox Delegation'; Url = 'https://learn.microsoft.com/en-us/exchange/recipients/mailbox-permissions' }
    )

    MITRE = @{
        Tactics    = @('TA0009')  # Collection
        Techniques = @('T1114.002')  # Remote Email Collection
    }

    CIS   = @('6.3.3')
    STIG  = @()
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 3
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($perm in $Data.SendOnBehalfPermissions) {
            $findings += [PSCustomObject]@{
                MailboxAddress      = $perm.MailboxAddress
                MailboxDisplayName  = $perm.DisplayName
                Delegate            = $perm.Delegate
                PermissionType      = 'SendOnBehalf'
                TransparencyLevel   = 'Visible to recipients (safer than SendAs)'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review Send on Behalf permissions to ensure they are necessary and properly documented.'
        Impact      = 'Low - Informational review'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SEND ON BEHALF PERMISSION REVIEW
# ================================================================
# This is LOWER RISK than Send As because recipients can see
# the actual sender in the "From" field.

# Export for review:
Get-Mailbox -ResultSize Unlimited | ``
    Where-Object { `$_.GrantSendOnBehalfTo } | ``
    Select-Object DisplayName, PrimarySmtpAddress, @{N='Delegates';E={`$_.GrantSendOnBehalfTo -join ';'}} | ``
    Export-Csv -Path 'SendOnBehalfPermissions.csv' -NoTypeInformation

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Delegate: $($item.Delegate)
# To remove: Set-Mailbox -Identity '$($item.MailboxAddress)' -GrantSendOnBehalfTo @{Remove='$($item.Delegate)'}

"@
            }

            return $commands
        }
    }
}

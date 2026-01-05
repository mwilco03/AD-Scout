@{
    Id          = 'E-InternalForwarding'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Internal Email Forwarding Configured'
    Description = 'Detects mailboxes with forwarding configured to internal addresses. While often legitimate, this can indicate insider threats, compromised delegation, or improper access patterns.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Email Collection: Email Forwarding Rule'; Url = 'https://attack.mitre.org/techniques/T1114/003/' }
    )

    MITRE = @{
        Tactics    = @('TA0009')  # Collection
        Techniques = @('T1114.003')
    }

    CIS   = @('6.2.2')
    STIG  = @()
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check mailbox-level forwarding (internal only)
        foreach ($forwarding in $Data.ForwardingRules) {
            if (-not $forwarding.IsExternal) {
                $findings += [PSCustomObject]@{
                    MailboxAddress          = $forwarding.MailboxAddress
                    DisplayName             = $forwarding.DisplayName
                    ForwardingType          = $forwarding.ForwardingType
                    ForwardingTarget        = $forwarding.ForwardingTarget
                    KeepsCopy               = $forwarding.DeliverToMailboxAndForward
                    ConfigurationType       = 'MailboxForwarding'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review internal forwarding to ensure it is authorized and necessary. Document approved forwarding configurations.'
        Impact      = 'Low - Review action only'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Internal Email Forwarding Detected
# Review these to ensure they are authorized business configurations

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Mailbox: $($item.DisplayName) <$($item.MailboxAddress)>
# Forwards To: $($item.ForwardingTarget)
# Keeps Copy: $($item.KeepsCopy)

# To remove if unauthorized:
# Set-Mailbox -Identity '$($item.MailboxAddress)' -ForwardingAddress `$null

# To document as approved (add to exception list):
# Add-Content -Path 'ApprovedForwarding.txt' -Value '$($item.MailboxAddress) -> $($item.ForwardingTarget)'

"@
            }
            return $commands
        }
    }
}

@{
    Id          = 'E-LegacyAuthProtocols'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Legacy Authentication Protocols Enabled'
    Description = 'Detects mailboxes or organization settings that allow legacy authentication protocols (POP3, IMAP, Basic Auth). These protocols bypass modern authentication and MFA, making accounts vulnerable to password spray and brute force attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Block Legacy Authentication'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication' }
        @{ Title = 'Disable Basic Auth in Exchange Online'; Url = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0006')  # Initial Access, Credential Access
        Techniques = @('T1110', 'T1078.002')  # Brute Force, Valid Accounts
    }

    CIS   = @('5.1.1', '5.1.2')
    STIG  = @('O365-EX-000020')
    ANSSI = @('vuln1_legacy_auth')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 8
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # This would need mailbox CAS settings from Get-CASMailbox
        # For now, we'll check what data is available

        # Check for organization-level settings
        # This would require additional collector for:
        # Get-AuthenticationPolicy
        # Get-OrganizationConfig

        foreach ($mbx in $Data.Mailboxes) {
            # Note: These properties would need to be collected via Get-CASMailbox
            # PopEnabled, ImapEnabled, ActiveSyncEnabled, OWAEnabled, MAPIEnabled

            # Placeholder for when CAS data is available
            if ($mbx.PopEnabled -or $mbx.ImapEnabled) {
                $enabledProtocols = @()
                if ($mbx.PopEnabled) { $enabledProtocols += 'POP3' }
                if ($mbx.ImapEnabled) { $enabledProtocols += 'IMAP' }

                $findings += [PSCustomObject]@{
                    MailboxAddress      = $mbx.PrimarySmtpAddress
                    DisplayName         = $mbx.DisplayName
                    EnabledProtocols    = ($enabledProtocols -join ', ')
                    PopEnabled          = $mbx.PopEnabled
                    ImapEnabled         = $mbx.ImapEnabled
                    RiskLevel           = 'High'
                    Risk                = 'Bypasses MFA, vulnerable to password attacks'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable legacy authentication protocols. Configure Conditional Access policies to block legacy auth organization-wide.'
        Impact      = 'High - Users relying on legacy protocols will lose access until they switch to modern apps'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# LEGACY AUTHENTICATION PROTOCOLS
# ================================================================
# Legacy auth (POP3, IMAP, Basic Auth) bypasses MFA and is
# the #1 attack vector for account compromise.

# Check organization-wide legacy auth status:
Get-OrganizationConfig | Select-Object *OAuth*, *BasicAuth*

# List all mailboxes with legacy protocols enabled:
Get-CASMailbox -ResultSize Unlimited | ``
    Where-Object { `$_.PopEnabled -or `$_.ImapEnabled } | ``
    Select-Object DisplayName, PrimarySmtpAddress, PopEnabled, ImapEnabled

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.DisplayName) <$($item.MailboxAddress)>
# Enabled Protocols: $($item.EnabledProtocols)
# ================================================================

# Disable legacy protocols for this mailbox:
Set-CASMailbox -Identity '$($item.MailboxAddress)' ``
    -PopEnabled `$false ``
    -ImapEnabled `$false

"@
            }

            $commands += @"

# ================================================================
# ORGANIZATION-WIDE PROTECTION
# ================================================================

# Disable legacy protocols for ALL mailboxes:
Get-CASMailbox -ResultSize Unlimited | Set-CASMailbox ``
    -PopEnabled `$false ``
    -ImapEnabled `$false

# Create Authentication Policy to block legacy auth:
New-AuthenticationPolicy -Name 'Block Legacy Auth' -AllowBasicAuthPop:`$false -AllowBasicAuthImap:`$false

# Apply to all users:
Get-User -ResultSize Unlimited | Set-User -AuthenticationPolicy 'Block Legacy Auth'

# Set as organization default:
Set-OrganizationConfig -DefaultAuthenticationPolicy 'Block Legacy Auth'

# BEST PRACTICE: Use Conditional Access in Azure AD to block legacy auth

"@
            return $commands
        }
    }
}

@{
    Id          = 'E-OAuthAppAccess'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Third-Party App Mailbox Access'
    Description = 'Detects third-party applications with OAuth consent to access mailboxes. Malicious OAuth apps are a common attack vector where users are tricked into granting mail access to attacker-controlled applications.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Detecting Illicit Consent Grants'; Url = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants' }
        @{ Title = 'OAuth App Attack'; Url = 'https://attack.mitre.org/techniques/T1550/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0009', 'TA0003')  # Collection, Persistence
        Techniques = @('T1550.001', 'T1114')  # Application Access Token, Email Collection
    }

    CIS   = @('5.2.1')
    STIG  = @('O365-EX-000035')
    ANSSI = @('vuln1_oauth_abuse')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # This would require Azure AD data for OAuth consents
        # Get-AzureADServicePrincipal
        # Get-AzureADOAuth2PermissionGrant

        # Mail-related permissions to look for:
        # Mail.Read, Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite

        return $findings
    }

    Remediation = @{
        Description = 'Review OAuth application consents and remove unauthorized apps with mail access. Implement app consent policies.'
        Impact      = 'Medium - May break integrations using unauthorized apps'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# OAUTH APPLICATION MAILBOX ACCESS
# ================================================================
# Third-party apps with mail permissions can:
# - Read all emails
# - Send emails as the user
# - Access attachments
# - Exfiltrate data silently

# AZURE AD: List service principals with mail permissions:
Connect-AzureAD
Get-AzureADServicePrincipal -All `$true | ForEach-Object {
    `$sp = `$_
    Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId `$sp.ObjectId | ``
        Where-Object { `$_.Scope -match 'Mail\.' }
} | Select-Object ClientId, ResourceId, Scope

# List user consents:
Get-AzureADOAuth2PermissionGrant -All `$true | ``
    Where-Object { `$_.Scope -match 'Mail\.' } | ``
    Format-Table ConsentType, ClientId, PrincipalId, Scope

# REMOVAL: Revoke specific consent:
# Remove-AzureADOAuth2PermissionGrant -ObjectId <grant-id>

# PREVENTION: Require admin consent for all apps:
# In Azure AD > Enterprise Applications > User Settings:
# - Set 'Users can consent to apps' to 'No'

# Block risky apps automatically:
# Enable 'Microsoft Cloud App Security' integration

"@
            return $commands
        }
    }
}

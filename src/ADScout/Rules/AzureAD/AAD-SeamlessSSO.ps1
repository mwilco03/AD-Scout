<#
.SYNOPSIS
    Detects Azure AD Seamless SSO security issues.

.DESCRIPTION
    Azure AD Seamless SSO uses a computer account (AZUREADSSOACC) whose Kerberos
    decryption key enables Silver Ticket attacks if compromised. This rule checks
    for security issues with the Seamless SSO configuration.

.NOTES
    Rule ID    : AAD-SeamlessSSO
    Category   : AzureAD
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AAD-SeamlessSSO'
    Version     = '1.0.0'
    Category    = 'AzureAD'
    Title       = 'Azure AD Seamless SSO Security'
    Description = 'Identifies security issues with the Azure AD Seamless SSO computer account which can be used for Silver Ticket attacks if its password is not rotated.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Seamless SSO Security'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso-faq' }
        @{ Title = 'AZUREADSSOACC Attacks'; Url = 'https://adsecurity.org/?p=4056' }
        @{ Title = 'Password Rollover'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the-azureadssoacc-computer-account' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1558.002', 'T1550.003')  # Silver Ticket, Pass the Ticket
    }

    CIS   = @('5.1')
    STIG  = @('V-36661')
    ANSSI = @('R42')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find AZUREADSSOACC computer accounts
        try {
            $ssoAccounts = Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } `
                -Properties * -ErrorAction SilentlyContinue

            foreach ($account in $ssoAccounts) {
                $issues = @()
                $riskLevel = 'Medium'

                # Check password age
                $pwdLastSet = $account.PasswordLastSet
                if ($pwdLastSet) {
                    $pwdAge = ((Get-Date) - $pwdLastSet).Days
                    if ($pwdAge -gt 30) {
                        $issues += "Password is $pwdAge days old (should rotate every 30 days)"
                        $riskLevel = 'High'
                    }
                    if ($pwdAge -gt 90) {
                        $issues += 'Password over 90 days - HIGH RISK'
                        $riskLevel = 'Critical'
                    }
                } else {
                    $issues += 'Password age unknown'
                }

                # Check if in expected OU
                if ($account.DistinguishedName -notmatch 'Computers|Azure|Cloud') {
                    # May be in an unusual location
                    $issues += 'Account in unexpected OU'
                }

                # Check for multiple SSO accounts (might indicate compromise/replacement)
                $allSSOAccounts = Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } -ErrorAction SilentlyContinue
                if ($allSSOAccounts.Count -gt 1) {
                    $issues += "Multiple AZUREADSSOACC accounts found ($($allSSOAccounts.Count))"
                    $riskLevel = 'High'
                }

                # Check SPNs
                if ($account.ServicePrincipalName) {
                    $expectedSPN = "HTTP/autologon.microsoftazuread-sso.com"
                    if ($account.ServicePrincipalName -notcontains $expectedSPN) {
                        $issues += 'Unexpected SPNs configured'
                    }
                }

                # Check if account is enabled
                if (-not $account.Enabled) {
                    $issues += 'Account is DISABLED'
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        AccountName       = $account.Name
                        Enabled           = $account.Enabled
                        Created           = $account.Created
                        PasswordLastSet   = $account.PasswordLastSet
                        PasswordAge       = if ($pwdAge) { "$pwdAge days" } else { 'Unknown' }
                        SPNs              = ($account.ServicePrincipalName -join '; ')
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        AttackPath        = 'Compromised key enables Silver Ticket -> Impersonate any Azure AD user'
                        DistinguishedName = $account.DistinguishedName
                    }
                }
            }

            # If no SSO account found but AAD Connect exists, flag it
            if ($ssoAccounts.Count -eq 0) {
                $aadConnectAccounts = Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } -ErrorAction SilentlyContinue
                if ($aadConnectAccounts) {
                    # AAD Connect exists but no Seamless SSO - might be intentional
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                AccountName       = 'Error'
                Enabled           = 'N/A'
                Created           = 'N/A'
                PasswordLastSet   = 'N/A'
                PasswordAge       = 'N/A'
                SPNs              = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                AttackPath        = 'N/A'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Rotate the AZUREADSSOACC Kerberos decryption key regularly (every 30 days) and monitor for abuse.'
        Impact      = 'Low - Key rotation is seamless and does not affect users.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Azure AD Seamless SSO Security
#############################################################################
#
# The AZUREADSSOACC computer account holds the Kerberos decryption key for
# Seamless SSO. If this key is compromised, attackers can forge Silver Tickets
# to impersonate any Azure AD user.
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Check Current Password Age
#############################################################################

# Find AZUREADSSOACC accounts and check password age:
Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet,
        @{N='PasswordAge';E={((Get-Date) - `$_.PasswordLastSet).Days}} |
    Format-Table -AutoSize

#############################################################################
# Step 2: Rotate Kerberos Decryption Key
#############################################################################

# On the Azure AD Connect server, run:
# (Requires Azure AD Global Admin or Hybrid Identity Admin)

# Method 1: Using Azure AD Connect PowerShell
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'

# Get current context
`$creds = Get-Credential -Message "Enter Azure AD Global Admin credentials"
New-AzureADSSOAuthenticationContext -CloudCredentials `$creds

# Check current status
Get-AzureADSSOStatus | ConvertFrom-Json

# Rotate the key (will create new key in AD)
Update-AzureADSSOForest -OnPremCredentials (Get-Credential -Message "Enter on-prem Domain Admin credentials")

# Verify rotation
Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet

#############################################################################
# Step 3: Automate Key Rotation
#############################################################################

# Create a scheduled task to rotate the key every 30 days:

`$rotationScript = @'
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'

# Use stored credentials or managed identity
`$azureCreds = Get-StoredCredential -Target 'AzureAD-SSO-Rotation'
`$onPremCreds = Get-StoredCredential -Target 'OnPrem-SSO-Rotation'

New-AzureADSSOAuthenticationContext -CloudCredentials `$azureCreds
Update-AzureADSSOForest -OnPremCredentials `$onPremCreds

# Log rotation
Add-Content -Path 'C:\Logs\SSO-Rotation.log' -Value "`$(Get-Date): Key rotated successfully"
'@

# Note: Store credentials securely or use managed identity

#############################################################################
# Step 4: Monitor for Abuse
#############################################################################

# Monitor Kerberos ticket requests for the AZUREADSSOACC account:
# - Unusual source IPs
# - High volume of ticket requests
# - Tickets requested outside of Azure AD Connect server

# Event ID 4769: Kerberos Service Ticket requested
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4769
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match 'AZUREADSSOACC'
} | Select-Object TimeCreated, Message

# Alert on ticket requests from non-AAD Connect servers

#############################################################################
# Step 5: Protect the Account
#############################################################################

# Add AZUREADSSOACC to Protected Users group:
# WARNING: Test this first - may affect Seamless SSO functionality
# Add-ADGroupMember -Identity 'Protected Users' -Members 'AZUREADSSOACC$'

# Restrict delegation:
Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } |
    Set-ADComputer -TrustedForDelegation `$false

# Move to protected OU:
# Move-ADObject -Identity (Get-ADComputer 'AZUREADSSOACC').DistinguishedName `
#     -TargetPath 'OU=Tier0,OU=Admin,DC=domain,DC=com'

#############################################################################
# Step 6: Alternative - Disable Seamless SSO
#############################################################################

# If Seamless SSO is not needed, disable it:
# This eliminates the attack surface entirely

# On Azure AD Connect server:
# Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'
# `$creds = Get-Credential
# New-AzureADSSOAuthenticationContext -CloudCredentials `$creds
# Disable-AzureADSSO -OnPremCredentials (Get-Credential)

# Then delete the AZUREADSSOACC account:
# Remove-ADComputer -Identity 'AZUREADSSOACC' -Confirm:`$false

#############################################################################
# Verification
#############################################################################

# Verify password was rotated:
Get-ADComputer -Filter { Name -like 'AZUREADSSOACC*' } -Properties PasswordLastSet,Created |
    Select-Object Name, Created, PasswordLastSet,
        @{N='PasswordAge';E={((Get-Date) - `$_.PasswordLastSet).Days}} |
    Format-Table -AutoSize

# Verify Seamless SSO is still working:
# Test from a domain-joined workstation by accessing Azure AD resources

"@
            return $commands
        }
    }
}

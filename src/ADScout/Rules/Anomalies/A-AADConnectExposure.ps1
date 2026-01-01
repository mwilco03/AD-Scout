@{
    Id          = 'A-AADConnectExposure'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Azure AD Connect Server Security Exposure'
    Description = 'Detects Azure AD Connect servers and evaluates their security posture. AAD Connect servers contain credentials that can sync password hashes and have extensive permissions in both AD and Azure AD. Compromise leads to full hybrid environment takeover.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'AAD Connect Security'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-prerequisites' }
        @{ Title = 'Extracting AAD Connect Credentials'; Url = 'https://blog.xpnsec.com/azuread-connect-for-redteam/' }
        @{ Title = 'AAD Connect Attack Paths'; Url = 'https://attack.mitre.org/techniques/T1003/006/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1003.006', 'T1021')  # DCSync (AAD equivalent), Remote Services
    }

    CIS   = @('5.2.4')
    STIG  = @('V-220960')
    ANSSI = @('R58')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Find AAD Connect servers by checking for the ADSync service account
            $aadConnectAccounts = Get-ADUser -Filter "SamAccountName -like 'MSOL_*' -or SamAccountName -like 'AAD_*'" -Properties * -ErrorAction SilentlyContinue

            foreach ($account in $aadConnectAccounts) {
                # The account name often contains the server name
                $serverName = $null
                if ($account.SamAccountName -match 'MSOL_([a-fA-F0-9]+)') {
                    # Try to find the server
                    $serverName = "AAD Connect Server (ID: $($Matches[1]))"
                }

                $findings += [PSCustomObject]@{
                    AccountName         = $account.SamAccountName
                    AccountDN           = $account.DistinguishedName
                    Description         = $account.Description
                    Created             = $account.WhenCreated
                    LastLogon           = $account.LastLogonDate
                    PasswordLastSet     = $account.PasswordLastSet
                    RiskLevel           = 'Critical'
                    AttackCapabilities  = @(
                        'Contains encrypted Azure AD credentials',
                        'Has DCSync-equivalent permissions',
                        'Can extract all synced password hashes',
                        'Can modify cloud user attributes',
                        'Database contains plaintext credentials'
                    ) -join '; '
                    SecurityConcerns    = @(
                        'Server should be Tier 0 protected',
                        'No regular users should have local admin',
                        'Should not be used for other purposes',
                        'Database should be backed up securely'
                    ) -join '; '
                }
            }

            # Also check for computers with AAD Connect installed
            $aadConnectComputers = Get-ADComputer -Filter "servicePrincipalName -like '*ADSync*'" -Properties * -ErrorAction SilentlyContinue

            foreach ($computer in $aadConnectComputers) {
                # Check if this server is in a protected OU
                $inProtectedOU = $computer.DistinguishedName -match 'Tier.?0|Protected|Domain Controllers|Secure'

                $findings += [PSCustomObject]@{
                    ComputerName        = $computer.Name
                    ComputerDN          = $computer.DistinguishedName
                    OperatingSystem     = $computer.OperatingSystem
                    Created             = $computer.WhenCreated
                    LastLogon           = $computer.LastLogonDate
                    InProtectedOU       = $inProtectedOU
                    RiskLevel           = if (-not $inProtectedOU) { 'Critical' } else { 'High' }
                    Issue               = if (-not $inProtectedOU) {
                        'AAD Connect server not in protected/Tier 0 OU'
                    } else {
                        'AAD Connect server detected - verify security controls'
                    }
                }
            }

            # Check for the AZUREADSSOACC computer account (Seamless SSO)
            $ssoAccount = Get-ADComputer -Filter "Name -eq 'AZUREADSSOACC'" -Properties * -ErrorAction SilentlyContinue

            if ($ssoAccount) {
                $passwordAge = if ($ssoAccount.PasswordLastSet) {
                    (Get-Date) - $ssoAccount.PasswordLastSet
                } else { $null }

                $findings += [PSCustomObject]@{
                    AccountName         = 'AZUREADSSOACC'
                    AccountType         = 'Seamless SSO Computer Account'
                    PasswordLastSet     = $ssoAccount.PasswordLastSet
                    PasswordAgeDays     = if ($passwordAge) { [int]$passwordAge.TotalDays } else { 'Unknown' }
                    RiskLevel           = if ($passwordAge -and $passwordAge.TotalDays -gt 30) { 'Critical' } else { 'High' }
                    Issue               = if ($passwordAge -and $passwordAge.TotalDays -gt 30) {
                        "Password is $([int]$passwordAge.TotalDays) days old - enables Silver Ticket attacks"
                    } else {
                        'Seamless SSO enabled - password should be rotated every 30 days'
                    }
                    AttackCapability    = 'Compromised password enables forging Kerberos tickets for any Azure AD user'
                }
            }
        }
        catch {
            # AAD Connect may not be present
        }

        return $findings
    }

    Remediation = @{
        Description = 'Secure Azure AD Connect servers as Tier 0 assets. Rotate AZUREADSSOACC password regularly. Implement monitoring for credential extraction.'
        Impact      = 'Medium - Requires careful planning to avoid sync disruption'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# AZURE AD CONNECT SECURITY
# ================================================================
# AAD Connect is a CRITICAL hybrid identity component.
# Compromise = Full control of both on-prem AD and Azure AD
#
# Attack vectors:
# 1. Extract credentials from AADSync database
# 2. Use MSOL account for DCSync-like operations
# 3. Forge Seamless SSO tickets (AZUREADSSOACC)
# 4. Modify cloud attributes to escalate privileges

# ================================================================
# DETECTED AAD CONNECT COMPONENTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                if ($item.ComputerName) {
                    $commands += @"

# Server: $($item.ComputerName)
# Location: $($item.ComputerDN)
# Protected OU: $($item.InProtectedOU)
# Risk: $($item.RiskLevel)

"@
                } elseif ($item.AccountName -eq 'AZUREADSSOACC') {
                    $commands += @"

# Seamless SSO Account: $($item.AccountName)
# Password Age: $($item.PasswordAgeDays) days
# Risk: $($item.RiskLevel)
# Issue: $($item.Issue)

"@
                } else {
                    $commands += @"

# Service Account: $($item.AccountName)
# Created: $($item.Created)
# Last Logon: $($item.LastLogon)

"@
                }
            }

            $commands += @"

# ================================================================
# TIER 0 PROTECTION FOR AAD CONNECT
# ================================================================

# 1. MOVE TO PROTECTED OU
# Create Tier 0 OU if not exists
New-ADOrganizationalUnit -Name "Tier 0 Servers" -Path "DC=domain,DC=com" -ErrorAction SilentlyContinue

# Move AAD Connect server
# Move-ADObject -Identity "CN=AADConnect,OU=Servers,DC=domain,DC=com" -TargetPath "OU=Tier 0 Servers,DC=domain,DC=com"

# 2. RESTRICT LOCAL ADMINISTRATORS
# Only Tier 0 admins should have access
# Remove all non-essential local admins
# Use PAW for administration

# 3. BLOCK INTERNET ACCESS (except required endpoints)
# AAD Connect only needs:
# - *.microsoftonline.com
# - *.windows.net
# - *.msftncsi.com

# ================================================================
# ROTATE SEAMLESS SSO PASSWORD
# ================================================================

# The AZUREADSSOACC password should be rotated every 30 days
# Run on AAD Connect server:

# Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1"
# New-AzureADSSOAuthenticationContext
# Update-AzureADSSOForest -OnPremCredentials `$creds -PreserveCustomPermissionsOnDesktopSsoAccount

# ================================================================
# MONITORING
# ================================================================

# Monitor for credential extraction attempts:
# - ADSync database access (*.mdf files)
# - dpapi.dll loading in unusual contexts
# - Azure AD audit logs for suspicious activities
# - Event ID 4624 on AAD Connect server

# Export current sync rules (for baseline):
# Get-ADSyncRule | Export-Clixml "C:\Backup\ADSyncRules.xml"

# ================================================================
# CREDENTIAL EXTRACTION DETECTION
# ================================================================

# Check for signs of credential extraction:
# - Unusual processes accessing LocalDB
# - mcrypt.dll usage outside of sync context
# - New local admin accounts

"@
            return $commands
        }
    }
}

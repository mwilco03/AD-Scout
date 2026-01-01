@{
    Id          = 'A-AccountsWithoutEmail'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Active Accounts Without Email Address'
    Description = 'Detects enabled user accounts that do not have an associated email address. This may indicate service accounts, orphaned accounts, or non-compliant configurations. Many security standards require accounts to have email addresses for accountability and notification purposes.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'NIST SP 800-53 IA-4 Identifier Management'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'CIS Controls - Account Management'; Url = 'https://www.cisecurity.org/controls/account-management' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.1', '5.3')
    STIG  = @('V-36432')
    ANSSI = @('R30')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 3
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Service account patterns to flag separately
        $servicePatterns = @(
            '^svc[-_]',
            '^service[-_]',
            '[-_]svc$',
            '[-_]service$',
            '^sa[-_]',
            '^app[-_]',
            '^sys[-_]',
            '^task[-_]',
            '^batch[-_]',
            '^sql[-_]',
            '^iis[-_]',
            '^ftp[-_]',
            '^backup[-_]',
            '^scan[-_]'
        )

        foreach ($user in $Data) {
            # Only check enabled accounts
            if (-not $user.Enabled) { continue }

            # Check if account has no email
            if (-not $user.HasEmail -and -not $user.Mail -and -not $user.EmailAddress) {

                # Determine if this looks like a service account
                $isServiceAccount = $false
                $serviceIndicators = @()

                foreach ($pattern in $servicePatterns) {
                    if ($user.SamAccountName -match $pattern) {
                        $isServiceAccount = $true
                        $serviceIndicators += 'Name pattern matches service account'
                        break
                    }
                }

                # Check for SPNs (service principal names)
                if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                    $isServiceAccount = $true
                    $serviceIndicators += "Has $($user.ServicePrincipalNames.Count) SPNs"
                }

                # Check description for service keywords
                if ($user.Description -match 'service|automated|batch|scheduler|backup|replication') {
                    $isServiceAccount = $true
                    $serviceIndicators += 'Description indicates service use'
                }

                # Check for missing human attributes
                if (-not $user.Manager -and -not $user.Department -and -not $user.Title) {
                    $serviceIndicators += 'Missing organizational attributes'
                }

                # Determine account type and risk
                $accountType = if ($isServiceAccount) { 'Service Account' }
                              elseif ($user.AdminCount -eq 1) { 'Privileged Account' }
                              else { 'User Account' }

                $riskLevel = switch ($accountType) {
                    'Privileged Account' { 'High' }
                    'Service Account'    { 'Medium' }
                    default              { 'Low' }
                }

                $findings += [PSCustomObject]@{
                    SamAccountName      = $user.SamAccountName
                    DisplayName         = $user.DisplayName
                    UserPrincipalName   = $user.UserPrincipalName
                    DistinguishedName   = $user.DistinguishedName
                    AccountType         = $accountType
                    IsServiceAccount    = $isServiceAccount
                    ServiceIndicators   = ($serviceIndicators -join '; ')
                    HasSPNs             = ($user.ServicePrincipalNames.Count -gt 0)
                    SPNCount            = $user.ServicePrincipalNames.Count
                    Description         = $user.Description
                    Department          = $user.Department
                    Manager             = $user.Manager
                    AdminCount          = $user.AdminCount
                    WhenCreated         = $user.WhenCreated
                    LastLogonDate       = $user.LastLogonDate
                    RiskLevel           = $riskLevel
                    ComplianceIssue     = 'Account lacks email address for notifications and accountability'
                }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}, SamAccountName
    }

    Remediation = @{
        Description = 'Add email addresses to accounts or document as approved exceptions. For service accounts, ensure proper documentation and ownership assignment.'
        Impact      = 'Low - Documentation and configuration update'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ACCOUNTS WITHOUT EMAIL ADDRESS
# ================================================================
# These accounts lack email addresses which may violate:
# - NIST 800-53 IA-4 (Identifier Management)
# - CIS Controls for Account Management
# - Organizational notification policies

# Export for review:
`$findings | Export-Csv -Path 'AccountsWithoutEmail.csv' -NoTypeInformation

"@
            # Group by account type
            $serviceAccounts = $Finding.Findings | Where-Object { $_.IsServiceAccount }
            $privilegedAccounts = $Finding.Findings | Where-Object { $_.AccountType -eq 'Privileged Account' }
            $userAccounts = $Finding.Findings | Where-Object { $_.AccountType -eq 'User Account' -and -not $_.IsServiceAccount }

            if ($privilegedAccounts) {
                $commands += @"

# ================================================================
# PRIVILEGED ACCOUNTS (HIGH PRIORITY)
# ================================================================
# These privileged accounts MUST have email for security notifications

"@
                foreach ($item in $privilegedAccounts) {
                    $commands += @"
# Account: $($item.SamAccountName) - $($item.DisplayName)
# Risk: $($item.RiskLevel)
Set-ADUser -Identity '$($item.SamAccountName)' -EmailAddress '<owner-email>@domain.com'

"@
                }
            }

            if ($serviceAccounts) {
                $commands += @"

# ================================================================
# SERVICE ACCOUNTS
# ================================================================
# Service accounts should have:
# 1. Owner/team email for notifications
# 2. Description documenting purpose
# 3. Manager field set to owner

"@
                foreach ($item in $serviceAccounts) {
                    $commands += @"
# Account: $($item.SamAccountName)
# Indicators: $($item.ServiceIndicators)
# SPNs: $($item.SPNCount)

# Set owner email and documentation:
Set-ADUser -Identity '$($item.SamAccountName)' ``
    -EmailAddress 'teamname@domain.com' ``
    -Description 'Service account for <purpose>. Owner: <team>'

# Consider converting to gMSA:
# New-ADServiceAccount -Name '$($item.SamAccountName)-gMSA' -DNSHostName 'server.domain.com'

"@
                }
            }

            if ($userAccounts) {
                $commands += @"

# ================================================================
# USER ACCOUNTS
# ================================================================
# These appear to be user accounts without email - investigate

"@
                foreach ($item in $userAccounts) {
                    $commands += @"
# Account: $($item.SamAccountName) - $($item.DisplayName)
# Created: $($item.WhenCreated)
# Last Login: $($item.LastLogonDate)
# Action: Set email or disable if orphaned

Set-ADUser -Identity '$($item.SamAccountName)' -EmailAddress '<user>@domain.com'
# Or if orphaned: Disable-ADAccount -Identity '$($item.SamAccountName)'

"@
                }
            }

            return $commands
        }
    }
}

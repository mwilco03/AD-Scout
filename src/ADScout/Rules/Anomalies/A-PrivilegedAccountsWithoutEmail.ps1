@{
    Id          = 'A-PrivilegedAccountsWithoutEmail'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Privileged Accounts Without Email Address'
    Description = 'Detects privileged accounts (AdminCount=1 or members of admin groups) that lack email addresses. Privileged accounts require email for security notifications, password reset, and MFA enrollment. This is a compliance violation in most security frameworks.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'NIST 800-53 AC-6 Least Privilege'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'CIS Control 5 Account Management'; Url = 'https://www.cisecurity.org/controls/account-management' }
        @{ Title = 'Securing Privileged Access'; Url = 'https://learn.microsoft.com/en-us/security/compass/overview' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.4.1', '5.4.2')
    STIG  = @('V-36432', 'V-36434')
    ANSSI = @('R29', 'R30')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Privileged group patterns
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators'
        )

        foreach ($user in $Data) {
            # Only check enabled accounts
            if (-not $user.Enabled) { continue }

            # Check if account has no email
            if ($user.Mail -or $user.EmailAddress -or $user.HasEmail) { continue }

            # Check if privileged
            $isPrivileged = $false
            $privilegeIndicators = @()

            # Check AdminCount
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
                $privilegeIndicators += 'AdminCount=1 (protected by AdminSDHolder)'
            }

            # Check group membership
            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match $privGroup) {
                            $isPrivileged = $true
                            $privilegeIndicators += "Member of $privGroup"
                        }
                    }
                }
            }

            # Skip non-privileged accounts
            if (-not $isPrivileged) { continue }

            # Check for service account patterns
            $isServiceAccount = $user.ServicePrincipalNames.Count -gt 0 -or
                               $user.SamAccountName -match 'svc|service|app|sys|batch|sql'

            $findings += [PSCustomObject]@{
                SamAccountName          = $user.SamAccountName
                DisplayName             = $user.DisplayName
                UserPrincipalName       = $user.UserPrincipalName
                DistinguishedName       = $user.DistinguishedName
                PrivilegeIndicators     = ($privilegeIndicators -join '; ')
                AdminCount              = $user.AdminCount
                IsServiceAccount        = $isServiceAccount
                Description             = $user.Description
                Manager                 = $user.Manager
                Department              = $user.Department
                Title                   = $user.Title
                WhenCreated             = $user.WhenCreated
                LastLogonDate           = $user.LastLogonDate
                PasswordNeverExpires    = $user.PasswordNeverExpires
                RiskLevel               = 'Critical'
                ComplianceViolation     = @(
                    'NIST 800-53 IA-4: Identifier Management',
                    'CIS Control 5.4: Restrict Administrator Privileges',
                    'Missing email for security notifications'
                ) -join '; '
            }
        }

        return $findings | Sort-Object SamAccountName
    }

    Remediation = @{
        Description = 'Add email addresses to all privileged accounts immediately. This is required for security notifications, MFA enrollment, and password reset capabilities.'
        Impact      = 'Low - Configuration update with significant security benefit'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: PRIVILEGED ACCOUNTS WITHOUT EMAIL
# ================================================================
# These privileged accounts lack email addresses, violating:
# - NIST 800-53 IA-4 (Identifier Management)
# - CIS Control 5.4 (Administrator Privileges)
# - Security notification requirements
#
# EMAIL IS REQUIRED FOR:
# - Password reset and recovery
# - MFA enrollment and recovery
# - Security alerts and notifications
# - Audit trail and accountability

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Account: $($item.SamAccountName)
# Privileges: $($item.PrivilegeIndicators)
# Is Service Account: $($item.IsServiceAccount)
# ================================================================

"@
                if ($item.IsServiceAccount) {
                    $commands += @"
# This is a SERVICE ACCOUNT with admin privileges
# Set owner/team email for notifications:
Set-ADUser -Identity '$($item.SamAccountName)' ``
    -EmailAddress 'admin-team@domain.com' ``
    -Description 'Privileged service account. Owner: <TEAM>. Purpose: <DESCRIBE>'

# CRITICAL: Review if admin privileges are necessary for this service
# Consider using a non-privileged service account + specific delegations

"@
                }
                else {
                    $commands += @"
# This is a USER account with admin privileges
# Set user's email address:
Set-ADUser -Identity '$($item.SamAccountName)' -EmailAddress '<user>@domain.com'

# Verify MFA is enabled (Azure AD / Conditional Access)
# Verify account has a documented owner/manager:
Set-ADUser -Identity '$($item.SamAccountName)' -Manager '<manager-dn>'

"@
                }
            }

            $commands += @"

# ================================================================
# ENFORCEMENT: Prevent future violations
# ================================================================

# 1. Create monitoring report for privileged accounts:
Get-ADUser -Filter { AdminCount -eq 1 } -Properties Mail, Manager, Description | ``
    Where-Object { -not `$_.Mail } | ``
    Select-Object SamAccountName, Manager, Description | ``
    Export-Csv 'PrivilegedAccountsWithoutEmail.csv'

# 2. Set up scheduled task to alert on new violations

# 3. Update privileged account creation process to require email

"@
            return $commands
        }
    }
}

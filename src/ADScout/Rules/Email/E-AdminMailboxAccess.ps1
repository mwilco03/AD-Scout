@{
    Id          = 'E-AdminMailboxAccess'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Administrative Access to User Mailboxes'
    Description = 'Detects elevated permissions that allow administrators or service accounts to access user mailboxes. While sometimes necessary, this access should be monitored and time-limited.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Principle of Least Privilege'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/secure-least-privileged-access' }
        @{ Title = 'Application Impersonation'; Url = 'https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/impersonation-and-ews-in-exchange' }
    )

    MITRE = @{
        Tactics    = @('TA0009', 'TA0003')  # Collection, Persistence
        Techniques = @('T1114.002')          # Remote Email Collection
    }

    CIS   = @('6.5.1')
    STIG  = @('O365-EX-000025')
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Look for admin/service account patterns with mailbox access
        $adminPatterns = @(
            'admin',
            'svc',
            'service',
            'system',
            'helpdesk',
            'support',
            'backup',
            'migration'
        )

        foreach ($perm in $Data.MailboxPermissions) {
            $isAdminAccount = $false
            foreach ($pattern in $adminPatterns) {
                if ($perm.Trustee -match $pattern) {
                    $isAdminAccount = $true
                    break
                }
            }

            if ($isAdminAccount) {
                $findings += [PSCustomObject]@{
                    MailboxAddress      = $perm.MailboxAddress
                    MailboxDisplayName  = $perm.DisplayName
                    AdminAccount        = $perm.Trustee
                    AccessRights        = $perm.AccessRights
                    PermissionType      = $perm.PermissionType
                    RiskLevel           = 'Medium'
                    Concern             = 'Admin/Service account has mailbox access - verify necessity'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review administrative mailbox access permissions. Remove unnecessary access and implement Just-In-Time access for required scenarios.'
        Impact      = 'Medium - May affect admin workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ADMINISTRATIVE MAILBOX ACCESS REVIEW
# ================================================================
# Admin and service accounts with mailbox access should be:
# - Documented and approved
# - Time-limited where possible
# - Audited regularly

# Query admin activity in mailboxes:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) ``
    -Operations MailItemsAccessed ``
    -ResultSize 5000 | ``
    Where-Object { `$_.UserIds -match 'admin|svc|service' }

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Admin Account: $($item.AdminAccount)
# Access: $($item.AccessRights)
# ================================================================

# Review why this access exists, then remove if not needed:
# Remove-MailboxPermission -Identity '$($item.MailboxAddress)' -User '$($item.AdminAccount)' -AccessRights FullAccess

"@
            }

            $commands += @"

# ================================================================
# BEST PRACTICES
# ================================================================

# 1. Use Privileged Access Management (PAM) for Just-In-Time access
# 2. Enable audit logging for all mailbox access
# 3. Review ApplicationImpersonation role assignments:

Get-ManagementRoleAssignment -Role ApplicationImpersonation | Format-List

# 4. Monitor for suspicious mailbox access patterns

"@
            return $commands
        }
    }
}

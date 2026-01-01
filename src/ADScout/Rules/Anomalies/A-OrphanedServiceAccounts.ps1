@{
    Id          = 'A-OrphanedServiceAccounts'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Orphaned Service Accounts'
    Description = 'Detects service accounts with no documented owner (Manager field empty), no email for notifications, and no recent activity. These orphaned accounts are security risks as no one is responsible for their security posture.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Orphaned Account Management'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'CIS Control 5.3 Disable Dormant Accounts'; Url = 'https://www.cisecurity.org/controls/account-management' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0001')  # Persistence, Initial Access
        Techniques = @('T1078.002', 'T1078.001')  # Valid Accounts
    }

    CIS   = @('5.3', '5.4')
    STIG  = @('V-36435')
    ANSSI = @('R68')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $inactivityThreshold = 90  # days

        foreach ($user in $Data) {
            # Only check enabled accounts that appear to be service accounts
            if (-not $user.Enabled) { continue }

            $isServiceAccount = $false
            $serviceIndicators = @()

            # Check for SPNs
            if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                $isServiceAccount = $true
                $serviceIndicators += 'Has SPNs'
            }

            # Check naming patterns
            if ($user.SamAccountName -match '^(svc|service|sa|app|sys|task|batch|sql|iis|ftp|backup)[-_]' -or
                $user.SamAccountName -match '[-_](svc|service)$') {
                $isServiceAccount = $true
                $serviceIndicators += 'Service naming pattern'
            }

            # Check if password never expires (common for service accounts)
            if ($user.PasswordNeverExpires -and -not $user.Manager) {
                $serviceIndicators += 'Password never expires'
            }

            # Skip if not a service account
            if (-not $isServiceAccount) { continue }

            # Check for orphan indicators
            $orphanScore = 0
            $orphanReasons = @()

            # No manager = no owner
            if (-not $user.Manager) {
                $orphanScore += 40
                $orphanReasons += 'No owner/manager assigned'
            }

            # No email = no way to contact owner
            if (-not $user.Mail -and -not $user.EmailAddress) {
                $orphanScore += 30
                $orphanReasons += 'No contact email'
            }

            # No description = no documentation
            if (-not $user.Description -or $user.Description.Length -lt 5) {
                $orphanScore += 15
                $orphanReasons += 'No description/documentation'
            }

            # Check inactivity
            $daysInactive = $null
            if ($user.LastLogonDate) {
                $daysInactive = (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days
                if ($daysInactive -gt $inactivityThreshold) {
                    $orphanScore += 15
                    $orphanReasons += "Inactive for $daysInactive days"
                }
            }
            else {
                $orphanScore += 10
                $orphanReasons += 'No login history recorded'
            }

            # Only report if orphan score is significant
            if ($orphanScore -lt 40) { continue }

            $riskLevel = switch ($true) {
                { $user.AdminCount -eq 1 } { 'Critical' }
                { $user.TrustedForDelegation } { 'Critical' }
                { $orphanScore -ge 80 } { 'High' }
                { $orphanScore -ge 60 } { 'Medium' }
                default { 'Low' }
            }

            $findings += [PSCustomObject]@{
                SamAccountName          = $user.SamAccountName
                DisplayName             = $user.DisplayName
                DistinguishedName       = $user.DistinguishedName
                ServiceIndicators       = ($serviceIndicators -join '; ')
                OrphanScore             = $orphanScore
                OrphanReasons           = ($orphanReasons -join '; ')
                Description             = $user.Description
                Manager                 = $user.Manager
                HasEmail                = [bool]($user.Mail -or $user.EmailAddress)
                DaysInactive            = $daysInactive
                LastLogonDate           = $user.LastLogonDate
                PasswordLastSet         = $user.PasswordLastSet
                PasswordNeverExpires    = $user.PasswordNeverExpires
                TrustedForDelegation    = $user.TrustedForDelegation
                SPNCount                = $user.ServicePrincipalNames.Count
                AdminCount              = $user.AdminCount
                WhenCreated             = $user.WhenCreated
                RiskLevel               = $riskLevel
                Recommendation          = if ($daysInactive -gt 180) { 'Consider disabling - extended inactivity' }
                                         elseif ($orphanScore -ge 80) { 'Urgent: Assign owner or disable' }
                                         else { 'Assign owner and document purpose' }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}, OrphanScore -Descending
    }

    Remediation = @{
        Description = 'Assign owners to orphaned service accounts, document their purpose, or disable if no longer needed. Implement service account lifecycle management.'
        Impact      = 'Medium - May require research to identify account owners and dependencies'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ORPHANED SERVICE ACCOUNTS
# ================================================================
# These service accounts have NO DOCUMENTED OWNER.
# This means:
# - No one is responsible for their security
# - Password rotation is likely not happening
# - Dependencies are unknown
# - They may be targets for attackers

"@
            $critical = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'Critical' }
            $high = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'High' }
            $other = $Finding.Findings | Where-Object { $_.RiskLevel -notin 'Critical','High' }

            if ($critical) {
                $commands += @"

# ================================================================
# CRITICAL - PRIVILEGED ORPHANED ACCOUNTS
# ================================================================
# These have admin privileges AND no owner - EXTREME RISK

"@
                foreach ($item in $critical) {
                    $commands += @"
# Account: $($item.SamAccountName)
# Reasons: $($item.OrphanReasons)
# Admin: $($item.AdminCount -eq 1), Delegation: $($item.TrustedForDelegation)
# Inactive: $($item.DaysInactive) days

# IMMEDIATE ACTION REQUIRED:
# 1. Identify purpose by checking SPNs:
Get-ADUser -Identity '$($item.SamAccountName)' -Properties ServicePrincipalName | Select -Expand ServicePrincipalName

# 2. Check what systems use this account:
# (Review event logs, connection logs, application configs)

# 3. Either assign owner or disable:
# Set-ADUser -Identity '$($item.SamAccountName)' -Manager '<owner-dn>' -EmailAddress 'owner@domain.com'
# OR
# Disable-ADAccount -Identity '$($item.SamAccountName)'

"@
                }
            }

            if ($high) {
                $commands += @"

# ================================================================
# HIGH RISK - ORPHANED SERVICE ACCOUNTS
# ================================================================

"@
                foreach ($item in $high) {
                    $commands += @"
# Account: $($item.SamAccountName)
# Score: $($item.OrphanScore)
# Reasons: $($item.OrphanReasons)
# Recommendation: $($item.Recommendation)

Set-ADUser -Identity '$($item.SamAccountName)' ``
    -Manager '<owner-dn>' ``
    -EmailAddress 'team@domain.com' ``
    -Description 'Service account for <PURPOSE>. Owner: <TEAM>'

"@
                }
            }

            $commands += @"

# ================================================================
# SERVICE ACCOUNT LIFECYCLE MANAGEMENT
# ================================================================

# 1. Create service account inventory:
Get-ADUser -Filter { ServicePrincipalName -like '*' -or SamAccountName -like 'svc*' } ``
    -Properties Manager, Description, Mail, ServicePrincipalName, PasswordLastSet, LastLogonDate | ``
    Select-Object SamAccountName, Manager, Description, Mail, ``
        @{N='SPNs';E={`$_.ServicePrincipalName -join ';'}}, ``
        PasswordLastSet, LastLogonDate | ``
    Export-Csv 'ServiceAccountInventory.csv' -NoTypeInformation

# 2. Set up quarterly service account reviews

# 3. Create alert for service accounts without recent login:
Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties LastLogonDate | ``
    Where-Object { `$_.LastLogonDate -lt (Get-Date).AddDays(-90) }

# 4. Consider Group Managed Service Accounts (gMSA):
# https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview

"@
            return $commands
        }
    }
}

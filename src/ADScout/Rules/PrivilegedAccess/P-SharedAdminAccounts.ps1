@{
    Id          = 'P-SharedAdminAccounts'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Shared or Generic Administrative Accounts'
    Description = 'Detects administrative accounts that appear to be shared between multiple users (generic names, no owner). Shared accounts violate accountability requirements and increase security risk as multiple people know the credentials.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'NIST Account Management'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'CIS Privileged Access'; Url = 'https://www.cisecurity.org/controls/privileged-access-management' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.4.1', '5.4.2')
    STIG  = @('V-220954')
    ANSSI = @('R53')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Patterns that suggest shared/generic accounts
        $genericPatterns = @(
            '^admin$',
            '^administrator$',
            '^domainadmin$',
            '^da$',
            '^serviceadmin$',
            '^sqladmin$',
            '^helpdeskadmin$',
            '^backup$',
            '^tempuser$',
            '^test(admin|user)?$',
            '^training$',
            '^shared',
            '^generic',
            '^common',
            'admin\d+$',        # admin1, admin2, etc.
            '^itadmin$',
            '^itops$',
            '^nocadmin$'
        )

        foreach ($user in $Data.Users) {
            if (-not $user.Enabled) { continue }
            if (-not ($user.AdminCount -eq 1 -or $user.MemberOf -match 'Admin|Operator')) { continue }

            $isGeneric = $false
            $genericIndicators = @()

            # Check name patterns
            foreach ($pattern in $genericPatterns) {
                if ($user.SamAccountName -match $pattern) {
                    $isGeneric = $true
                    $genericIndicators += "Name matches generic pattern: $pattern"
                    break
                }
            }

            # Check for missing personal information
            if (-not $user.Manager) {
                $genericIndicators += 'No manager assigned'
            }
            if (-not $user.Mail -and -not $user.EmailAddress) {
                $genericIndicators += 'No email address'
            }
            if (-not $user.DisplayName -or $user.DisplayName -eq $user.SamAccountName) {
                $genericIndicators += 'No proper display name'
            }
            if (-not $user.Department) {
                $genericIndicators += 'No department'
            }

            # Description containing "shared" or "generic"
            if ($user.Description -match 'shared|generic|multiple|team|common') {
                $isGeneric = $true
                $genericIndicators += "Description indicates shared use: $($user.Description)"
            }

            # Score the account
            $score = $genericIndicators.Count
            if ($isGeneric) { $score += 3 }

            if ($score -ge 3) {
                $findings += [PSCustomObject]@{
                    SamAccountName          = $user.SamAccountName
                    DisplayName             = $user.DisplayName
                    Description             = $user.Description
                    DistinguishedName       = $user.DistinguishedName
                    AdminCount              = $user.AdminCount
                    Manager                 = $user.Manager
                    Department              = $user.Department
                    GenericScore            = $score
                    GenericIndicators       = ($genericIndicators -join '; ')
                    RiskLevel               = if ($score -ge 5) { 'High' }
                                             elseif ($score -ge 4) { 'Medium' }
                                             else { 'Low' }
                    AccountabilityIssue     = 'Cannot determine who is responsible for account actions'
                    Recommendation          = 'Create individual named admin accounts per administrator'
                }
            }
        }

        return $findings | Sort-Object -Property GenericScore -Descending
    }

    Remediation = @{
        Description = 'Replace shared administrative accounts with individual named accounts. Implement proper accountability tracking.'
        Impact      = 'Medium - Requires creating new accounts and updating access'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SHARED/GENERIC ADMINISTRATIVE ACCOUNTS
# ================================================================
# Shared admin accounts violate:
# - Accountability requirements (who did what?)
# - Password management (how to rotate?)
# - Access control (who has access?)
# - Audit trail (which person performed action?)

# ================================================================
# DETECTED ACCOUNTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Generic Score: $($item.GenericScore)
# Indicators: $($item.GenericIndicators)
# Description: $($item.Description)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION STEPS
# ================================================================

# For each shared account:

# 1. IDENTIFY ALL USERS
# Who currently knows this password?
# Who should have admin access?

# 2. CREATE INDIVIDUAL ACCOUNTS
# Format: firstname.lastname-admin or flastname_a

`$admins = @("John Smith", "Jane Doe")  # People who need admin access
foreach (`$admin in `$admins) {
    `$parts = `$admin -split ' '
    `$sam = "`$(`$parts[0].Substring(0,1).ToLower())`$(`$parts[1].ToLower())-admin"

    New-ADUser -Name "`$admin (Admin)" ``
        -SamAccountName `$sam ``
        -UserPrincipalName "`$sam@domain.com" ``
        -GivenName `$parts[0] ``
        -Surname `$parts[1] ``
        -DisplayName "`$admin (Admin)" ``
        -Description "Individual admin account for `$admin" ``
        -Path "OU=Admin Accounts,DC=domain,DC=com" ``
        -Enabled `$true

    # Copy group memberships from shared account
    # Get-ADUser -Identity "SharedAdmin" -Properties MemberOf |
    #     Select-Object -ExpandProperty MemberOf |
    #     ForEach-Object { Add-ADGroupMember -Identity `$_ -Members `$sam }
}

# 3. TRANSITION PERIOD
# - Notify all users of new accounts
# - Set deadline for shared account disable
# - Monitor shared account for usage

# 4. DISABLE SHARED ACCOUNT
# After transition:
# Disable-ADAccount -Identity "SharedAdmin"

# 5. DOCUMENT
# Update runbooks and procedures to reference individual accounts

# ================================================================
# BEST PRACTICES
# ================================================================

# - Every admin must have their own named account
# - Admin accounts should not be used for daily activities
# - Admin accounts should not have email
# - Use PAM/PIM for just-in-time access
# - Rotate passwords on schedule

"@
            return $commands
        }
    }
}

@{
    Id          = 'P-TieringViolation'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Administrative Tiering Model Violations'
    Description = 'Detects violations of the administrative tiering model where Tier 0 (domain) admin accounts are used on lower-tier systems. This exposes privileged credentials to theft from less-secure workstations and servers.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Privileged Access Model'; Url = 'https://learn.microsoft.com/en-us/security/compass/privileged-access-access-model' }
        @{ Title = 'Securing Privileged Access'; Url = 'https://learn.microsoft.com/en-us/security/compass/overview' }
        @{ Title = 'Credential Theft'; Url = 'https://attack.mitre.org/techniques/T1003/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1078.002', 'T1003')  # Valid Accounts: Domain, Credential Dumping
    }

    CIS   = @('5.8.1')
    STIG  = @('V-220953')
    ANSSI = @('R51', 'R52')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Tier 0 groups - should ONLY be used on Tier 0 systems (DCs, PAWs)
        $tier0Groups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'Server Operators',
            'Print Operators',
            'DnsAdmins'
        )

        foreach ($user in $Data.Users) {
            if (-not $user.Enabled) { continue }

            $isTier0 = $false
            $tier0Memberships = @()

            # Check group memberships
            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($t0Group in $tier0Groups) {
                        if ($group -match $t0Group) {
                            $isTier0 = $true
                            $tier0Memberships += $t0Group
                        }
                    }
                }
            }

            # Also check AdminCount
            if ($user.AdminCount -eq 1) {
                $isTier0 = $true
            }

            if (-not $isTier0) { continue }

            # Now check for violations
            $violations = @()

            # Violation 1: Has email/mailbox (can be phished)
            if ($user.Mail -or $user.EmailAddress -or $user.HasEmail) {
                $violations += [PSCustomObject]@{
                    Type        = 'Email on Tier 0 Account'
                    Detail      = "Email: $($user.Mail)"
                    Risk        = 'Account can be phished, exposing credentials'
                    Severity    = 'High'
                }
            }

            # Violation 2: Has UPN that looks like email (often means mailbox)
            if ($user.UserPrincipalName -match '@' -and $user.UserPrincipalName -notmatch '\.local$|\.internal$') {
                $violations += [PSCustomObject]@{
                    Type        = 'Internet-routable UPN on Tier 0 Account'
                    Detail      = "UPN: $($user.UserPrincipalName)"
                    Risk        = 'May indicate cloud sync or email capability'
                    Severity    = 'Medium'
                }
            }

            # Violation 3: Named like a regular user (not -admin or svc pattern)
            if ($user.SamAccountName -notmatch 'admin|adm|_a$|-a$|\.a$|svc|service') {
                $violations += [PSCustomObject]@{
                    Type        = 'Tier 0 Account Without Admin Naming'
                    Detail      = "Name: $($user.SamAccountName)"
                    Risk        = 'May be used as daily driver account'
                    Severity    = 'Medium'
                }
            }

            # Violation 4: Recent logon from non-DC (would need logon data)
            # This would require event log analysis

            if ($violations.Count -gt 0) {
                foreach ($violation in $violations) {
                    $findings += [PSCustomObject]@{
                        SamAccountName      = $user.SamAccountName
                        DisplayName         = $user.DisplayName
                        DistinguishedName   = $user.DistinguishedName
                        Tier0Memberships    = ($tier0Memberships -join ', ')
                        ViolationType       = $violation.Type
                        ViolationDetail     = $violation.Detail
                        Risk                = $violation.Risk
                        RiskLevel           = $violation.Severity
                        Recommendation      = 'Separate Tier 0 admin accounts from daily-use accounts'
                    }
                }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}, SamAccountName
    }

    Remediation = @{
        Description = 'Implement proper tiering model with separate admin accounts that have no email and are only used on privileged access workstations.'
        Impact      = 'High - Requires creating separate admin accounts and changing admin practices'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ADMINISTRATIVE TIERING MODEL
# ================================================================
# Microsoft's tiering model separates privileged accounts:
#
# TIER 0: Domain Controllers, PKI, AD management
#         - Domain Admins, Enterprise Admins, Schema Admins
#         - Only use from Privileged Access Workstations (PAW)
#
# TIER 1: Member servers, applications
#         - Server Admins, specific server local admins
#         - Use from designated admin workstations
#
# TIER 2: Workstations, standard users
#         - Helpdesk, workstation local admins
#         - Can use from managed workstations

# ================================================================
# VIOLATIONS DETECTED
# ================================================================

"@
            $grouped = $Finding.Findings | Group-Object SamAccountName

            foreach ($group in $grouped) {
                $account = $group.Group[0]
                $violations = $group.Group.ViolationType -join ', '

                $commands += @"

# Account: $($account.SamAccountName)
# Tier 0 Groups: $($account.Tier0Memberships)
# Violations: $violations

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION STEPS
# ================================================================

# 1. CREATE SEPARATE ADMIN ACCOUNTS

# For each Tier 0 user, create dedicated admin account:
# Naming: username-t0 or username_admin
# Example:
# New-ADUser -Name "jsmith-t0" -SamAccountName "jsmith-t0" ``
#     -UserPrincipalName "jsmith-t0@domain.local" ``
#     -Path "OU=Tier0 Admins,OU=Admin Accounts,DC=domain,DC=com" ``
#     -Description "Tier 0 admin account for John Smith"

# 2. REMOVE EMAIL FROM ADMIN ACCOUNTS

Get-ADUser -Filter { AdminCount -eq 1 } -Properties Mail | ``
    Where-Object { `$_.Mail } | ``
    ForEach-Object {
        Set-ADUser -Identity `$_.SamAccountName -Clear Mail
        Write-Host "Removed email from `$(`$_.SamAccountName)"
    }

# 3. ADD TO PROTECTED USERS GROUP

Get-ADUser -Filter { AdminCount -eq 1 } | ``
    ForEach-Object {
        Add-ADGroupMember -Identity "Protected Users" -Members `$_.SamAccountName
    }

# 4. SET ACCOUNT RESTRICTIONS

# Deny logon to non-Tier 0 systems via GPO:
# Computer Configuration > Policies > Windows Settings >
# Security Settings > Local Policies > User Rights Assignment
# "Deny log on locally" = Tier 0 Admin Groups
# "Deny log on through Remote Desktop Services" = Tier 0 Admin Groups

# ================================================================
# PRIVILEGED ACCESS WORKSTATIONS (PAW)
# ================================================================

# Tier 0 accounts should ONLY be used from:
# 1. Dedicated PAW workstations
# 2. Domain Controllers (for AD management)
# 3. Jump servers with proper security

# PAW Requirements:
# - No internet access
# - No email client
# - Hardened OS configuration
# - Separate from daily-use workstations

"@
            return $commands
        }
    }
}

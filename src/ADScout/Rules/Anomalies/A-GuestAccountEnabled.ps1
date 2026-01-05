@{
    Id          = 'A-GuestAccountEnabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Guest Account Enabled'
    Description = 'Detects if the built-in Guest account is enabled. The Guest account provides unauthenticated or loosely authenticated access to resources. This is rarely needed and creates significant security risk.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Guest Account Security'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#guest-account' }
        @{ Title = 'CIS Benchmark'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.001')  # Valid Accounts: Default Accounts
    }

    CIS   = @('2.3.1.2')
    STIG  = @('V-220905')
    ANSSI = @('R22')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check domain Guest account
            $guestAccount = Get-ADUser -Identity 'Guest' -Properties * -ErrorAction SilentlyContinue

            if ($guestAccount -and $guestAccount.Enabled) {
                $findings += [PSCustomObject]@{
                    AccountType         = 'Domain Guest'
                    SamAccountName      = $guestAccount.SamAccountName
                    Enabled             = $true
                    LastLogon           = $guestAccount.LastLogonDate
                    PasswordLastSet     = $guestAccount.PasswordLastSet
                    PasswordNeverExpires= $guestAccount.PasswordNeverExpires
                    MemberOf            = ($guestAccount.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '
                    RiskLevel           = 'High'
                    Issue               = 'Domain Guest account is enabled'
                    Impact              = 'Allows anonymous/unauthenticated access to domain resources'
                }
            }

            # Check for accounts in Guests group that are enabled
            $guestsGroup = Get-ADGroup -Identity 'Guests' -ErrorAction SilentlyContinue
            if ($guestsGroup) {
                $guestMembers = Get-ADGroupMember -Identity $guestsGroup -ErrorAction SilentlyContinue

                foreach ($member in $guestMembers) {
                    if ($member.objectClass -eq 'user') {
                        $memberDetails = Get-ADUser -Identity $member.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
                        if ($memberDetails -and $memberDetails.Enabled -and $member.SamAccountName -ne 'Guest') {
                            $findings += [PSCustomObject]@{
                                AccountType         = 'Member of Guests'
                                SamAccountName      = $member.SamAccountName
                                Enabled             = $true
                                RiskLevel           = 'Medium'
                                Issue               = 'Enabled account is member of Guests group'
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Could not check guest account
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the Guest account and remove unnecessary members from the Guests group.'
        Impact      = 'Low - Guest access should not be used in enterprise environments'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GUEST ACCOUNT SECURITY
# ================================================================
# The Guest account allows access without proper authentication.
# This is almost never needed and creates unnecessary risk.

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Type: $($item.AccountType)
# Enabled: $($item.Enabled)
# Risk: $($item.RiskLevel)
# Issue: $($item.Issue)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# Disable the Guest account:
Disable-ADAccount -Identity "Guest"

# Verify:
Get-ADUser -Identity "Guest" -Properties Enabled | Select-Object SamAccountName, Enabled

# ================================================================
# GPO SETTING
# ================================================================

# Enforce via GPO:
# Computer Configuration
# -> Policies
# -> Windows Settings
# -> Security Settings
# -> Local Policies
# -> Security Options
# -> Accounts: Guest account status = Disabled

# ================================================================
# ADDITIONAL HARDENING
# ================================================================

# 1. Rename the Guest account (obscurity, not security):
# Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"

# 2. Set a long random password:
`$randomPassword = [System.Web.Security.Membership]::GeneratePassword(128, 32)
# Set-ADAccountPassword -Identity "Guest" -NewPassword (ConvertTo-SecureString `$randomPassword -AsPlainText -Force)

# 3. Ensure it's in no groups (except Domain Guests which is default):
Get-ADUser -Identity "Guest" -Properties MemberOf | Select-Object -ExpandProperty MemberOf

# ================================================================
# MONITORING
# ================================================================

# Alert on:
# - Event ID 4722 (User account enabled) for Guest
# - Event ID 4624 (Successful logon) for Guest
# - Any logon activity for the Guest account

"@
            return $commands
        }
    }
}

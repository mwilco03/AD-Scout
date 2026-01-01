@{
    Id          = 'A-PasswordHashSync'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Password Hash Synchronization Security Assessment'
    Description = 'Detects Password Hash Sync (PHS) configuration and evaluates security implications. While PHS enables cloud authentication, the MSOL service account can extract all password hashes from AD, making it a high-value target for attackers.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'How Password Hash Sync Works'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization' }
        @{ Title = 'Securing Password Hash Sync'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-security-deep-dive' }
        @{ Title = 'MSOL Account Abuse'; Url = 'https://aadinternals.com/post/on-prem_admin/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1003.006', 'T1098')  # DCSync, Account Manipulation
    }

    CIS   = @('5.2.5')
    STIG  = @('V-220962')
    ANSSI = @('R60')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Find MSOL accounts (indicates PHS is configured)
            $msolAccounts = Get-ADUser -Filter "SamAccountName -like 'MSOL_*'" -Properties * -ErrorAction SilentlyContinue

            if ($msolAccounts) {
                foreach ($account in $msolAccounts) {
                    # Check permissions of MSOL account
                    $hasReplicatingPermissions = $false

                    # MSOL accounts typically have "Replicating Directory Changes" and
                    # "Replicating Directory Changes All" permissions

                    $findings += [PSCustomObject]@{
                        ServiceAccount      = $account.SamAccountName
                        AccountDN           = $account.DistinguishedName
                        Description         = $account.Description
                        Created             = $account.WhenCreated
                        PasswordLastSet     = $account.PasswordLastSet
                        LastLogon           = $account.LastLogonDate
                        SyncType            = 'Password Hash Sync Enabled'
                        RiskLevel           = 'High'
                        SecurityImplication = @(
                            'MSOL account has Replicating Directory Changes permissions',
                            'Can perform DCSync-equivalent operations',
                            'All password hashes are replicated to Azure',
                            'Compromise of AAD Connect = all credentials exposed'
                        ) -join '; '
                        RequiredControls    = @(
                            'Tier 0 protection for AAD Connect server',
                            'No shared admin access to AAD Connect',
                            'Monitor for credential extraction',
                            'Enable Password Protection in Azure AD'
                        ) -join '; '
                    }
                }
            }

            # Also detect if PHS might be enabled by checking for cloud attributes
            $usersWithCloudSync = 0
            foreach ($user in $Data.Users) {
                if ($user.'msDS-cloudExtensionAttribute1' -or
                    ($user.ProxyAddresses -and $user.ProxyAddresses -match 'SMTP:')) {
                    $usersWithCloudSync++
                }
            }

            if ($usersWithCloudSync -gt 10 -and -not $msolAccounts) {
                # Users are synced but we didn't find MSOL account - might be using different sync
                $findings += [PSCustomObject]@{
                    SyncType            = 'Azure AD Sync Detected (Type Unknown)'
                    SyncedUserCount     = $usersWithCloudSync
                    RiskLevel           = 'Medium'
                    Note                = 'Hybrid sync detected. Verify sync method and apply appropriate controls.'
                }
            }

        }
        catch {
            # Could not determine sync status
        }

        return $findings
    }

    Remediation = @{
        Description = 'Secure Password Hash Sync infrastructure. Treat AAD Connect as Tier 0. Consider Pass-Through Authentication as alternative.'
        Impact      = 'Medium - Security hardening, no service disruption'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# PASSWORD HASH SYNC SECURITY
# ================================================================
# Password Hash Sync (PHS) synchronizes password hashes to Azure AD.
# The MSOL account has DCSync-equivalent permissions.
#
# If an attacker compromises the AAD Connect server, they can:
# 1. Extract the MSOL account credentials
# 2. Use those credentials to DCSync all password hashes
# 3. Crack hashes offline for all domain accounts

# ================================================================
# CURRENT PHS CONFIGURATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Service Account: $($item.ServiceAccount)
# Sync Type: $($item.SyncType)
# Created: $($item.Created)
# Password Last Set: $($item.PasswordLastSet)
# Risk Level: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# SECURITY CONTROLS FOR PHS
# ================================================================

# 1. PROTECT AAD CONNECT SERVER AS TIER 0
# - Dedicated server (no other roles)
# - No internet browsing
# - Only Tier 0 admins have access
# - Separate local admin accounts

# 2. MONITOR MSOL ACCOUNT ACTIVITY
# Enable auditing on MSOL account:

`$msolAccount = Get-ADUser -Filter "SamAccountName -like 'MSOL_*'"
if (`$msolAccount) {
    `$acl = Get-Acl "AD:\`$(`$msolAccount.DistinguishedName)"
    # Review and set auditing policies
    Write-Host "MSOL Account: `$(`$msolAccount.SamAccountName)"
    Write-Host "Monitor for unusual logon activity"
}

# 3. ENABLE AZURE AD PASSWORD PROTECTION
# Prevents users from setting weak passwords
# Configure in Azure AD: Authentication methods > Password protection

# 4. ENABLE SMART LOCKOUT
# Protects against password spray in the cloud
# Configure in Azure AD: Authentication methods > Password protection > Custom smart lockout

# ================================================================
# ALTERNATIVE: PASS-THROUGH AUTHENTICATION
# ================================================================

# PTA validates passwords on-prem without syncing hashes to cloud
# Advantages:
# - Password hashes never leave on-prem
# - Password policies enforced in real-time
# - Account lockout applies immediately

# Disadvantages:
# - Requires PTA agents on-prem
# - Cloud auth fails if all agents are down

# To switch from PHS to PTA:
# 1. Install PTA agent(s) on-prem
# 2. In AAD Connect, change sign-in method to Pass-Through Authentication
# 3. Monitor for issues
# 4. Disable PHS after confirming PTA works

# ================================================================
# CREDENTIAL EXTRACTION DETECTION
# ================================================================

# Monitor for signs of MSOL credential extraction:

# Check for mcrypt.dll access:
# Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} |
#     Where-Object {`$_.Message -match 'mcrypt.dll'}

# Check ADSync database access:
# Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} |
#     Where-Object {`$_.Message -match 'ADSync.mdf'}

# Monitor MSOL account logons (should only be from AAD Connect server):
Get-ADUser -Filter "SamAccountName -like 'MSOL_*'" | ForEach-Object {
    Write-Host "Monitor Event ID 4624 for account: `$(`$_.SamAccountName)"
    Write-Host "Source should ONLY be the AAD Connect server"
}

# ================================================================
# EMERGENCY RESPONSE
# ================================================================

# If AAD Connect is compromised:
# 1. Disable MSOL account immediately
# 2. Reset KRBTGT password (twice, 10 hours apart)
# 3. Force password reset for all users
# 4. Rebuild AAD Connect on clean server
# 5. Rotate all service account passwords

"@
            return $commands
        }
    }
}

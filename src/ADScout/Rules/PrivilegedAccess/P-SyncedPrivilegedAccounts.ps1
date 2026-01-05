@{
    Id          = 'P-SyncedPrivilegedAccounts'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Privileged Accounts Synced to Azure AD'
    Description = 'Detects administrative accounts that are synced to Azure AD. Domain Admins and other privileged accounts should be cloud-only or not synced to reduce attack surface. Synced admin accounts can be compromised from either environment.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Securing Privileged Access'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning' }
        @{ Title = 'Hybrid Identity Security'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/hybrid/plan-hybrid-identity-design-considerations' }
        @{ Title = 'Microsoft Best Practices'; Url = 'https://learn.microsoft.com/en-us/security/compass/privileged-access-accounts' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1078.004', 'T1550.001')  # Cloud Accounts, Application Access Token
    }

    CIS   = @('5.4.5')
    STIG  = @('V-220961')
    ANSSI = @('R59')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Privileged groups to check
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

        foreach ($user in $Data.Users) {
            if (-not $user.Enabled) { continue }

            # Check if user is in privileged groups
            $isPrivileged = $false
            $privilegedMemberships = @()

            foreach ($group in $privilegedGroups) {
                if ($user.MemberOf -match $group) {
                    $isPrivileged = $true
                    $privilegedMemberships += $group
                }
            }

            # Also check AdminCount
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
            }

            if (-not $isPrivileged) { continue }

            # Check if synced to Azure AD (multiple indicators)
            $isSynced = $false
            $syncIndicators = @()

            # Check for msDS-cloudExtensionAttribute (set by AAD Connect)
            if ($user.'msDS-cloudExtensionAttribute1' -or
                $user.'msDS-cloudExtensionAttribute2') {
                $isSynced = $true
                $syncIndicators += 'Has cloud extension attributes'
            }

            # Check if UPN matches a verified Azure AD domain
            # (This is a heuristic - UPNs with verified domains are typically synced)
            if ($user.UserPrincipalName -notmatch '\.local$|\.internal$|\.corp$|\.lan$') {
                $syncIndicators += 'UPN uses external domain (likely synced)'
            }

            # Check for proxyAddresses (often populated during sync)
            if ($user.ProxyAddresses -and $user.ProxyAddresses.Count -gt 0) {
                $syncIndicators += 'Has proxy addresses'
            }

            # Check for mail attribute
            if ($user.Mail -or $user.EmailAddress) {
                $syncIndicators += 'Has email address'
            }

            # Not in a filtered OU
            $inFilteredOU = $user.DistinguishedName -match 'OU=Excluded|OU=NoSync|OU=Admin'
            if (-not $inFilteredOU) {
                $syncIndicators += 'Not in excluded sync OU'
            }

            # If we have enough sync indicators, flag it
            if ($syncIndicators.Count -ge 2 -or $isSynced) {
                $findings += [PSCustomObject]@{
                    SamAccountName          = $user.SamAccountName
                    UserPrincipalName       = $user.UserPrincipalName
                    DisplayName             = $user.DisplayName
                    DistinguishedName       = $user.DistinguishedName
                    PrivilegedGroups        = ($privilegedMemberships -join ', ')
                    AdminCount              = $user.AdminCount
                    SyncIndicators          = ($syncIndicators -join '; ')
                    RiskLevel               = if ($privilegedMemberships -match 'Domain Admins|Enterprise Admins') {
                        'Critical'
                    } else { 'High' }
                    SecurityRisk            = @(
                        'Account can be attacked from cloud or on-prem',
                        'Password spray attacks in Azure affect on-prem',
                        'Phishing in cloud compromises on-prem admin',
                        'Increases hybrid identity attack surface'
                    ) -join '; '
                    Recommendation          = 'Use separate cloud-only admin accounts for Azure AD'
                }
            }
        }

        return $findings | Sort-Object -Property RiskLevel -Descending
    }

    Remediation = @{
        Description = 'Exclude privileged accounts from Azure AD sync. Create separate cloud-only accounts for Azure AD administration.'
        Impact      = 'Medium - Requires creating new cloud admin accounts'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SYNCED PRIVILEGED ACCOUNTS
# ================================================================
# Best practice: DO NOT sync Domain Admins to Azure AD
#
# Why this is risky:
# - Password attacks in cloud affect on-prem
# - Cloud compromise = domain compromise
# - Violates zero trust principles
# - Increases attack surface significantly

# ================================================================
# DETECTED SYNCED PRIVILEGED ACCOUNTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# UPN: $($item.UserPrincipalName)
# Privileged Groups: $($item.PrivilegedGroups)
# Sync Indicators: $($item.SyncIndicators)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# OPTION 1: EXCLUDE FROM SYNC (Recommended)
# ================================================================

# Create OU for admin accounts that won't sync
New-ADOrganizationalUnit -Name "Admin Accounts - No Sync" -Path "DC=domain,DC=com"

# Move admin accounts to this OU
# Move-ADObject -Identity "CN=AdminUser,OU=Users,DC=domain,DC=com" ``
#     -TargetPath "OU=Admin Accounts - No Sync,DC=domain,DC=com"

# Update AAD Connect OU filtering to exclude this OU
# In AAD Connect wizard: Customize synchronization options > Domain/OU filtering

# ================================================================
# OPTION 2: ATTRIBUTE-BASED FILTERING
# ================================================================

# Set attribute on admin accounts to exclude from sync
# For each admin account:
Set-ADUser -Identity "AdminUser" -Replace @{adminDescription = "NoSync"}

# Configure AAD Connect sync rule:
# - Create inbound sync rule
# - Condition: adminDescription equals "NoSync"
# - Flow: cloudFiltered = True

# ================================================================
# OPTION 3: CREATE CLOUD-ONLY ADMINS
# ================================================================

# Best practice for Azure AD administration:
# 1. Create cloud-only accounts in Azure portal
# 2. Assign Azure AD roles to cloud-only accounts
# 3. Keep on-prem admins separate

# PowerShell (Azure AD module):
# Connect-AzureAD
# `$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
# `$PasswordProfile.Password = (New-Guid).ToString()  # Temporary
# New-AzureADUser -DisplayName "John Smith (Cloud Admin)" ``
#     -UserPrincipalName "jsmith-admin@tenant.onmicrosoft.com" ``
#     -PasswordProfile `$PasswordProfile ``
#     -MailNickName "jsmith-admin" ``
#     -AccountEnabled `$true

# ================================================================
# VERIFICATION
# ================================================================

# Check what's being synced:
Get-ADUser -Filter "adminCount -eq 1" -Properties UserPrincipalName, MemberOf |
    Select-Object SamAccountName, UserPrincipalName,
    @{N='InSync'; E={`$_.DistinguishedName -notmatch 'OU=Admin Accounts - No Sync'}}

# After AAD Connect sync, verify in Azure AD:
# Get-AzureADUser -Filter "displayName eq 'Domain Admin'" | Select ImmutableId

"@
            return $commands
        }
    }
}

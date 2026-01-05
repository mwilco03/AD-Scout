@{
    Id          = 'A-HybridIdentityMisconfiguration'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Hybrid Identity Security Misconfigurations'
    Description = 'Detects common hybrid identity misconfigurations that can lead to privilege escalation between on-premises AD and Azure AD. Includes soft-match vulnerabilities, ImmutableID manipulation risks, and cloud-to-on-prem attack paths.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Hybrid Identity Attack Paths'; Url = 'https://posts.specterops.io/azure-ad-connect-for-red-teamers-f1ae6e79b61e' }
        @{ Title = 'Azure AD Security Best Practices'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-ops-guide-iam' }
        @{ Title = 'Directory Synchronization Security'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/hybrid/security-considerations' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004', 'TA0005')  # Persistence, Privilege Escalation, Defense Evasion
        Techniques = @('T1098.001', 'T1484')  # Additional Cloud Credentials, Domain Policy Modification
    }

    CIS   = @('5.2.6')
    STIG  = @('V-220963')
    ANSSI = @('R61')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check for accounts vulnerable to soft-match takeover
            # Soft-match uses proxyAddresses/SMTP to match accounts
            # If attacker can set proxyAddresses, they can potentially hijack cloud accounts

            $writePropertyDelegations = @()

            # Find who can modify proxyAddresses on users
            # This is a simplified check - full ACL analysis would be more comprehensive
            foreach ($user in $Data.Users) {
                if (-not $user.Enabled) { continue }

                # Check for suspicious proxyAddress configurations
                if ($user.ProxyAddresses) {
                    # Multiple SMTP addresses with external domains
                    $externalSmtp = @($user.ProxyAddresses | Where-Object {
                        $_ -match '^smtp:' -and $_ -notmatch '\.local$|\.internal$'
                    })

                    if ($externalSmtp.Count -gt 3) {
                        $findings += [PSCustomObject]@{
                            Type                = 'Excessive External SMTP Addresses'
                            SamAccountName      = $user.SamAccountName
                            ProxyAddressCount   = $externalSmtp.Count
                            RiskLevel           = 'Medium'
                            Issue               = 'Multiple external SMTP addresses may indicate misconfiguration or preparation for soft-match attack'
                        }
                    }
                }

                # Check for accounts with mS-DS-ConsistencyGuid set (ImmutableID source)
                if ($user.'mS-DS-ConsistencyGuid') {
                    # This is normal, but if it's recently modified, could indicate attack
                }
            }

            # Check for on-prem accounts that match Global Admin naming patterns
            $potentialGlobalAdmins = $Data.Users | Where-Object {
                $_.SamAccountName -match 'globaladmin|cloudadmin|azureadmin|aadadmin' -and
                $_.Enabled
            }

            foreach ($admin in $potentialGlobalAdmins) {
                $findings += [PSCustomObject]@{
                    Type                = 'Potential Synced Global Admin'
                    SamAccountName      = $admin.SamAccountName
                    UserPrincipalName   = $admin.UserPrincipalName
                    DistinguishedName   = $admin.DistinguishedName
                    RiskLevel           = 'High'
                    Issue               = 'Account naming suggests Azure AD Global Admin that may be synced from on-prem'
                    Risk                = 'Compromise of on-prem account = Azure AD tenant compromise'
                }
            }

            # Check for service accounts used by hybrid identity
            $hybridServiceAccounts = @(
                'MSOL_*',        # Password Hash Sync
                'AAD_*',         # AAD Connect
                'Sync_*',        # Sync service
                'ADSync*'        # ADSync variations
            )

            foreach ($pattern in $hybridServiceAccounts) {
                $accounts = Get-ADUser -Filter "SamAccountName -like '$pattern'" -Properties * -ErrorAction SilentlyContinue

                foreach ($account in $accounts) {
                    # Check if password is old
                    $passwordAge = if ($account.PasswordLastSet) {
                        (Get-Date) - $account.PasswordLastSet
                    } else { $null }

                    if ($passwordAge -and $passwordAge.TotalDays -gt 365) {
                        $findings += [PSCustomObject]@{
                            Type                = 'Hybrid Service Account Password Age'
                            SamAccountName      = $account.SamAccountName
                            PasswordAgeDays     = [int]$passwordAge.TotalDays
                            PasswordLastSet     = $account.PasswordLastSet
                            RiskLevel           = 'High'
                            Issue               = "Service account password is $([int]$passwordAge.TotalDays) days old"
                            Recommendation      = 'Rotate hybrid identity service account passwords annually'
                        }
                    }
                }
            }

            # Check for AADConnect sync rules that might be dangerous
            # (This is informational - actual rules are in AAD Connect)
            $domainObj = Get-ADDomain -ErrorAction SilentlyContinue
            if ($domainObj) {
                # Check if domain has any cloud-related attributes set
                $cloudAttrs = Get-ADObject -Identity $domainObj.DistinguishedName -Properties 'msDS-cloudExtensionAttribute*' -ErrorAction SilentlyContinue

                if ($cloudAttrs) {
                    $findings += [PSCustomObject]@{
                        Type                = 'Hybrid Identity Enabled'
                        DomainDN            = $domainObj.DistinguishedName
                        RiskLevel           = 'Info'
                        Note                = 'Domain has hybrid identity configured. Verify sync rules and security controls.'
                    }
                }
            }
        }
        catch {
            # Hybrid identity may not be configured
        }

        return $findings | Where-Object { $_.RiskLevel -ne 'Info' }
    }

    Remediation = @{
        Description = 'Review and secure hybrid identity configuration. Implement proper access controls for sync-related attributes.'
        Impact      = 'Low - Configuration review and hardening'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# HYBRID IDENTITY SECURITY REVIEW
# ================================================================
# Hybrid environments create bidirectional attack paths:
# - On-prem compromise can lead to cloud takeover
# - Cloud compromise can lead to on-prem takeover
#
# Key attack vectors:
# 1. AAD Connect server compromise
# 2. Soft-match account hijacking
# 3. ImmutableID manipulation
# 4. Password hash extraction

# ================================================================
# DETECTED ISSUES
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Type: $($item.Type)
# Account: $($item.SamAccountName)
# Risk Level: $($item.RiskLevel)
# Issue: $($item.Issue)

"@
            }

            $commands += @"

# ================================================================
# SOFT-MATCH PROTECTION
# ================================================================

# Soft-match uses SMTP address to match on-prem and cloud accounts.
# If attacker can set proxyAddresses, they may hijack cloud accounts.

# 1. Restrict who can modify proxyAddresses:
# This should only be mail admins or automated systems

# Check current delegation:
Get-ADUser -Filter * -Properties nTSecurityDescriptor |
    ForEach-Object {
        `$acl = Get-Acl "AD:\`$(`$_.DistinguishedName)"
        `$acl.Access | Where-Object {
            `$_.ObjectType -eq '00000000-0000-0000-0000-000000000000' -or
            `$_.ObjectType -match 'proxyAddresses'
        }
    }

# 2. Disable soft-match (use hard-match only):
# In Azure AD: Set-MsolDirSyncFeature -Feature BlockSoftMatch -Enable `$true

# ================================================================
# IMMUTABLEID PROTECTION
# ================================================================

# ImmutableID links on-prem to cloud accounts.
# Source: mS-DS-ConsistencyGuid or ObjectGUID

# 1. Protect the source attribute:
# Restrict write access to mS-DS-ConsistencyGuid

# 2. Monitor for changes:
# Enable auditing on this attribute for privileged users

# ================================================================
# SERVICE ACCOUNT HARDENING
# ================================================================

# Hybrid identity service accounts should:
# - Have long, complex passwords
# - Be in protected OUs
# - Have logon restrictions
# - Be monitored for unusual activity

# Password rotation for MSOL account:
# Must be done through AAD Connect - reinstall or repair

# Check current service account status:
Get-ADUser -Filter "SamAccountName -like 'MSOL_*' -or SamAccountName -like 'AAD_*'" ``
    -Properties PasswordLastSet, LastLogonDate, Enabled |
    Select-Object SamAccountName, PasswordLastSet, LastLogonDate, Enabled

# ================================================================
# ATTACK PATH ANALYSIS
# ================================================================

# Review for these attack paths:

# 1. On-Prem to Cloud:
# - Compromise AAD Connect -> Extract MSOL creds -> Access Azure AD
# - Compromise admin account -> If synced, access cloud too
# - Modify synced user's proxyAddresses -> Soft-match takeover

# 2. Cloud to On-Prem:
# - Compromise Azure AD admin -> Modify sync rules
# - Add cloud-to-on-prem writeback -> Modify on-prem objects
# - Password writeback abuse -> Reset on-prem passwords

# ================================================================
# MONITORING RECOMMENDATIONS
# ================================================================

# 1. Monitor AAD Connect sync changes:
# Get-ADSyncConnectorRunStatus
# Get-ADSyncScheduler

# 2. Monitor Azure AD Audit Logs:
# - Suspicious sync activities
# - Role assignments to synced accounts
# - Password changes for privileged accounts

# 3. Monitor on-prem for:
# - Changes to proxyAddresses
# - Changes to mS-DS-ConsistencyGuid
# - MSOL account logons from unexpected sources

"@
            return $commands
        }
    }
}

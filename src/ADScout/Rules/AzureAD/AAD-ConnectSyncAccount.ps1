<#
.SYNOPSIS
    Detects Azure AD Connect sync account security issues.

.DESCRIPTION
    The Azure AD Connect sync account (MSOL_*) has DCSync-equivalent rights and is
    a prime target for attackers. This rule checks for security issues with the
    sync account and related configurations.

.NOTES
    Rule ID    : AAD-ConnectSyncAccount
    Category   : AzureAD
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AAD-ConnectSyncAccount'
    Version     = '1.0.0'
    Category    = 'AzureAD'
    Title       = 'Azure AD Connect Sync Account Security'
    Description = 'Identifies security issues with Azure AD Connect sync accounts which have DCSync-equivalent privileges and can be used to compromise the entire forest.'
    Severity    = 'Critical'
    Weight      = 80
    DataSource  = 'Users,DomainControllers'

    References  = @(
        @{ Title = 'Azure AD Connect Security'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-configure-ad-ds-connector-account' }
        @{ Title = 'AADInternals'; Url = 'https://aadinternals.com/post/on-prem_admin/' }
        @{ Title = 'Securing Azure AD Connect'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-security' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1003.006', 'T1078.002')  # DCSync, Domain Accounts
    }

    CIS   = @('5.1')
    STIG  = @('V-36661')
    ANSSI = @('R42')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find Azure AD Connect accounts (MSOL_* and AAD_*)
        $syncAccounts = @()

        if ($Data.Users) {
            $syncAccounts = $Data.Users | Where-Object {
                $_.SamAccountName -match '^MSOL_|^AAD_' -or
                $_.Description -match 'Azure AD Connect|AAD Connect|Directory Sync'
            }
        }

        # Also search directly if not in data
        if ($syncAccounts.Count -eq 0) {
            try {
                $syncAccounts = Get-ADUser -Filter {
                    SamAccountName -like 'MSOL_*' -or
                    SamAccountName -like 'AAD_*'
                } -Properties * -ErrorAction SilentlyContinue
            } catch {}
        }

        foreach ($account in $syncAccounts) {
            $issues = @()
            $riskLevel = 'High'

            # Check if account is enabled
            if ($account.Enabled) {
                # Enabled sync account - check for security issues

                # Check password age
                $pwdLastSet = $account.PasswordLastSet
                if ($pwdLastSet) {
                    $pwdAge = (Get-Date) - $pwdLastSet
                    if ($pwdAge.Days -gt 365) {
                        $issues += "Password is $($pwdAge.Days) days old (over 1 year)"
                        $riskLevel = 'Critical'
                    }
                }

                # Check if password never expires
                if ($account.PasswordNeverExpires) {
                    $issues += 'Password never expires'
                }

                # Check if in Protected Users group (should NOT be - breaks sync)
                try {
                    $protectedUsers = Get-ADGroupMember -Identity 'Protected Users' -ErrorAction SilentlyContinue
                    if ($protectedUsers.SamAccountName -contains $account.SamAccountName) {
                        $issues += 'Account in Protected Users (may break sync)'
                    }
                } catch {}

                # Check for excessive group memberships
                $groups = $account.MemberOf
                if ($groups.Count -gt 2) {
                    $issues += "Member of $($groups.Count) groups (should be minimal)"
                }

                # Check if AdminCount is set (should not be)
                if ($account.AdminCount -eq 1) {
                    $issues += 'AdminCount = 1 (unusual for sync account)'
                }

                # Check SPN for Kerberoasting risk
                if ($account.ServicePrincipalName) {
                    $issues += 'Has SPN - vulnerable to Kerberoasting'
                    $riskLevel = 'Critical'
                }

            } else {
                $issues += 'Account is DISABLED (check if sync is still needed)'
            }

            # Check replication permissions (DCSync rights)
            try {
                $domainDN = (Get-ADDomain).DistinguishedName
                $acl = Get-Acl "AD:\$domainDN"
                $syncRights = $acl.Access | Where-Object {
                    $_.IdentityReference -match $account.SamAccountName -and
                    ($_.ActiveDirectoryRights -match 'ExtendedRight' -or
                     $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or  # DS-Replication-Get-Changes
                     $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')     # DS-Replication-Get-Changes-All
                }

                if ($syncRights) {
                    $issues += 'Has DCSync replication rights (expected but high-value target)'
                }
            } catch {}

            if ($issues.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    AccountName        = $account.SamAccountName
                    DisplayName        = $account.DisplayName
                    Enabled            = $account.Enabled
                    Created            = $account.Created
                    PasswordLastSet    = $account.PasswordLastSet
                    PasswordAge        = if ($pwdLastSet) { "$($pwdAge.Days) days" } else { 'Unknown' }
                    LastLogonDate      = $account.LastLogonDate
                    HasSPN             = [bool]$account.ServicePrincipalName
                    Issues             = ($issues -join '; ')
                    RiskLevel          = $riskLevel
                    Note               = 'Sync accounts have DCSync rights - treat as Tier 0'
                    DistinguishedName  = $account.DistinguishedName
                }
            }
        }

        # Check for Azure AD Connect server
        try {
            $aadConnectComputers = Get-ADComputer -Filter {
                ServicePrincipalName -like '*ADSync*' -or
                Description -like '*Azure AD Connect*'
            } -Properties ServicePrincipalName, Description -ErrorAction SilentlyContinue

            foreach ($server in $aadConnectComputers) {
                # Check if server is properly secured
                $serverIssues = @()

                # Check if in Tier 0 OU
                if ($server.DistinguishedName -notmatch 'Tier.?0|Admin|Privileged') {
                    $serverIssues += 'Not in Tier 0/Admin OU'
                }

                if ($serverIssues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        AccountName        = $server.Name
                        DisplayName        = 'Azure AD Connect Server'
                        Enabled            = $true
                        Created            = $server.Created
                        PasswordLastSet    = 'N/A'
                        PasswordAge        = 'N/A'
                        LastLogonDate      = $server.LastLogonDate
                        HasSPN             = $true
                        Issues             = ($serverIssues -join '; ')
                        RiskLevel          = 'High'
                        Note               = 'AAD Connect server should be treated as Tier 0'
                        DistinguishedName  = $server.DistinguishedName
                    }
                }
            }
        } catch {}

        return $findings
    }

    Remediation = @{
        Description = 'Secure Azure AD Connect sync accounts and servers with Tier 0 protections.'
        Impact      = 'Low - Security hardening does not affect sync functionality.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Azure AD Connect Security Hardening
#############################################################################
#
# Azure AD Connect sync accounts (MSOL_*, AAD_*) have DCSync rights.
# Compromising these accounts gives full domain access.
#
# Identified issues:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Identify Sync Accounts
#############################################################################

# Find all Azure AD Connect related accounts:
`$syncAccounts = Get-ADUser -Filter {
    SamAccountName -like 'MSOL_*' -or
    SamAccountName -like 'AAD_*'
} -Properties *

`$syncAccounts | Select-Object Name, SamAccountName, Enabled, PasswordLastSet, Created |
    Format-Table -AutoSize

#############################################################################
# Step 2: Rotate Sync Account Password
#############################################################################

# Use Azure AD Connect wizard to rotate the password:
# 1. Open Azure AD Connect on the sync server
# 2. Click "Configure"
# 3. Select "Customize synchronization options"
# 4. Re-enter credentials when prompted (generates new password)

# Alternative - use PowerShell on AAD Connect server:
# Import-Module ADSync
# Set-ADSyncAutoUpgrade -AutoUpgradeState Suspended
# Invoke-ADSyncDiagnostics -PasswordSync

# NEVER manually change the password - it will break sync!

#############################################################################
# Step 3: Protect Sync Server (Tier 0)
#############################################################################

# Move AAD Connect server to Tier 0 protected OU:
`$aadServer = Get-ADComputer -Filter { Description -like '*Azure AD Connect*' }
`$tier0OU = "OU=Tier0,OU=Admin,DC=domain,DC=com"  # Adjust path

# Move-ADObject -Identity `$aadServer.DistinguishedName -TargetPath `$tier0OU

# Apply Tier 0 security:
# - Only Tier 0 admins can log in
# - Block internet access (except to Azure AD endpoints)
# - Enable Windows Defender Credential Guard
# - Monitor all access and changes

#############################################################################
# Step 4: Restrict Sync Account Permissions
#############################################################################

# The sync account needs specific permissions only.
# Verify it doesn't have excessive rights:

`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-Acl "AD:\`$domainDN"

foreach (`$account in `$syncAccounts) {
    `$perms = `$acl.Access | Where-Object {
        `$_.IdentityReference -match `$account.SamAccountName
    }
    Write-Host "`n`$(`$account.SamAccountName) permissions:" -ForegroundColor Cyan
    `$perms | Select-Object ActiveDirectoryRights, AccessControlType | Format-Table
}

# Required permissions for Password Hash Sync:
# - Replicating Directory Changes
# - Replicating Directory Changes All

# Required permissions for Password Writeback:
# - Reset Password
# - Write lockoutTime
# - Write pwdLastSet

#############################################################################
# Step 5: Monitor Sync Account Activity
#############################################################################

# Monitor for suspicious activity:
# - Logins from non-sync server
# - Password changes
# - Group membership changes
# - Permission modifications

# Create alert for sync account logins:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match 'MSOL_|AAD_'
} | Select-Object TimeCreated, Message

# Alert if sync account logs in from unexpected location

#############################################################################
# Step 6: Disable Unused Sync Accounts
#############################################################################

# If Azure AD Connect has been reinstalled, old accounts may remain:

# Find old/unused sync accounts:
`$oldAccounts = Get-ADUser -Filter {
    SamAccountName -like 'MSOL_*' -or
    SamAccountName -like 'AAD_*'
} -Properties LastLogonDate | Where-Object {
    `$_.LastLogonDate -lt (Get-Date).AddDays(-30)
}

# Disable unused accounts:
# foreach (`$acct in `$oldAccounts) {
#     Disable-ADAccount -Identity `$acct
#     Write-Host "Disabled `$(`$acct.SamAccountName)" -ForegroundColor Yellow
# }

#############################################################################
# Step 7: Additional Security Measures
#############################################################################

# 1. Use dedicated AD account with minimal permissions
# 2. Enable Azure AD Connect Health for monitoring
# 3. Use PIM for privileged access to sync server
# 4. Implement network segmentation
# 5. Consider using cloud-only Azure AD for new deployments

# Check current sync configuration:
# On AAD Connect server:
# Import-Module ADSync
# Get-ADSyncConnector | Select-Object Name, Type
# Get-ADSyncScheduler

"@
            return $commands
        }
    }
}

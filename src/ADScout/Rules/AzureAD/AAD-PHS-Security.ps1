<#
.SYNOPSIS
    Detects Password Hash Sync (PHS) security issues.

.DESCRIPTION
    Password Hash Sync synchronizes password hashes from on-premises AD to Azure AD.
    This rule checks for security issues related to PHS configuration and the
    sync account.

.NOTES
    Rule ID    : AAD-PHS-Security
    Category   : AzureAD
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AAD-PHS-Security'
    Version     = '1.0.0'
    Category    = 'AzureAD'
    Title       = 'Password Hash Sync Security'
    Description = 'Identifies security issues with Azure AD Connect Password Hash Synchronization that could expose credential data.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers,Users'

    References  = @(
        @{ Title = 'PHS Overview'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whats-phs' }
        @{ Title = 'PHS Security'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization' }
        @{ Title = 'AAD Connect Security'; Url = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-security' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1003.006', 'T1552')  # DCSync, Unsecured Credentials
    }

    CIS   = @('5.1.5')
    STIG  = @('V-254459')
    ANSSI = @('R53')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check if PHS is enabled by looking for MSOL accounts
            $msolAccounts = Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } `
                -Properties * -ErrorAction SilentlyContinue

            if ($msolAccounts) {
                foreach ($msol in $msolAccounts) {
                    $issues = @()
                    $riskLevel = 'Medium'

                    # Check if account is enabled
                    if ($msol.Enabled) {
                        # Password Hash Sync is likely enabled

                        # Check for DCSync permissions (required for PHS)
                        $domainDN = (Get-ADDomain).DistinguishedName
                        $acl = Get-Acl "AD:\$domainDN" -ErrorAction SilentlyContinue

                        $hasDCSync = $acl.Access | Where-Object {
                            $_.IdentityReference -match $msol.SamAccountName -and
                            ($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or
                             $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                        }

                        if ($hasDCSync) {
                            $issues += 'Has DCSync rights (expected for PHS)'
                        }

                        # Check password age
                        if ($msol.PasswordLastSet) {
                            $pwdAge = ((Get-Date) - $msol.PasswordLastSet).Days
                            if ($pwdAge -gt 365) {
                                $issues += "Sync account password $pwdAge days old"
                                $riskLevel = 'High'
                            }
                        }

                        # Check if password never expires (common for service accounts)
                        if ($msol.PasswordNeverExpires) {
                            $issues += 'Password never expires'
                        }

                        # Check last logon (should be recent if sync is active)
                        if ($msol.LastLogonDate) {
                            $daysSinceLogon = ((Get-Date) - $msol.LastLogonDate).Days
                            if ($daysSinceLogon -gt 7) {
                                $issues += "Last logon $daysSinceLogon days ago (sync may be broken)"
                            }
                        }

                        # Check for SPNs (shouldn't have any typically)
                        if ($msol.ServicePrincipalName) {
                            $issues += 'Has SPNs (unusual, Kerberoasting risk)'
                            $riskLevel = 'High'
                        }
                    } else {
                        $issues += 'Sync account DISABLED (PHS may be inactive)'
                    }

                    if ($issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            AccountName       = $msol.SamAccountName
                            DisplayName       = $msol.DisplayName
                            Enabled           = $msol.Enabled
                            Created           = $msol.Created
                            PasswordLastSet   = $msol.PasswordLastSet
                            LastLogonDate     = $msol.LastLogonDate
                            Description       = $msol.Description
                            Issues            = ($issues -join '; ')
                            RiskLevel         = $riskLevel
                            PHSStatus         = if ($msol.Enabled) { 'Likely Active' } else { 'Likely Inactive' }
                            SecurityNote      = 'PHS sync account has DCSync rights - treat as Tier 0'
                            DistinguishedName = $msol.DistinguishedName
                        }
                    }
                }
            }

            # Check for AAD Connect server configuration
            $aadConnectServers = Get-ADComputer -Filter { Description -like '*Azure AD Connect*' -or ServicePrincipalName -like '*ADSync*' } `
                -Properties * -ErrorAction SilentlyContinue

            foreach ($server in $aadConnectServers) {
                $serverIssues = @()

                # Check if in Tier 0 OU
                if ($server.DistinguishedName -notmatch 'Tier.?0|Admin|Privileged') {
                    $serverIssues += 'Not in Tier 0/Admin OU'
                }

                # Check delegation
                if ($server.TrustedForDelegation) {
                    $serverIssues += 'Trusted for delegation (security risk)'
                }

                if ($serverIssues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        AccountName       = $server.Name
                        DisplayName       = 'AAD Connect Server'
                        Enabled           = $server.Enabled
                        Created           = $server.Created
                        PasswordLastSet   = $server.PasswordLastSet
                        LastLogonDate     = $server.LastLogonDate
                        Description       = $server.Description
                        Issues            = ($serverIssues -join '; ')
                        RiskLevel         = 'High'
                        PHSStatus         = 'Server hosts PHS sync'
                        SecurityNote      = 'Server stores encrypted credentials - must be Tier 0'
                        DistinguishedName = $server.DistinguishedName
                    }
                }
            }

            # Check for multiple MSOL accounts (could indicate compromise)
            if ($msolAccounts.Count -gt 1) {
                $findings += [PSCustomObject]@{
                    AccountName       = 'Multiple MSOL Accounts'
                    DisplayName       = "$($msolAccounts.Count) accounts found"
                    Enabled           = 'Mixed'
                    Created           = 'Various'
                    PasswordLastSet   = 'Various'
                    LastLogonDate     = 'Various'
                    Description       = 'Multiple sync accounts exist'
                    Issues            = 'Multiple MSOL accounts - possible reinstall or compromise'
                    RiskLevel         = 'High'
                    PHSStatus         = 'Review required'
                    SecurityNote      = 'Only one active MSOL account should exist'
                    DistinguishedName = 'N/A'
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                AccountName       = 'Error'
                DisplayName       = 'Check Failed'
                Enabled           = 'N/A'
                Created           = 'N/A'
                PasswordLastSet   = 'N/A'
                LastLogonDate     = 'N/A'
                Description       = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                PHSStatus         = 'Unknown'
                SecurityNote      = 'Manual verification required'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Secure Password Hash Sync configuration and protect the sync account.'
        Impact      = 'Low - Security hardening does not affect sync functionality.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Password Hash Sync Security
#############################################################################
#
# PHS synchronizes password hashes from on-prem AD to Azure AD.
# The sync account (MSOL_*) has DCSync rights and is highly privileged.
#
# Risks:
# - Compromised sync account = DCSync = full domain compromise
# - AAD Connect server stores encrypted credentials
# - PHS exposes hashes to cloud (though encrypted)
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Inventory PHS Components
#############################################################################

# Find all MSOL accounts:
Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } -Properties * |
    Select-Object Name, SamAccountName, Enabled, Created, PasswordLastSet, LastLogonDate |
    Format-Table -AutoSize

# Find AAD Connect servers:
Get-ADComputer -Filter { Description -like '*Azure AD Connect*' } -Properties * |
    Select-Object Name, Description, OperatingSystem |
    Format-Table -AutoSize

#############################################################################
# Step 2: Rotate Sync Account Password
#############################################################################

# On the AAD Connect server, use the wizard:
# 1. Open Azure AD Connect
# 2. Click "Configure"
# 3. Select "Customize synchronization options"
# 4. Re-enter credentials to rotate password

# Or via PowerShell (on AAD Connect server):
# Import-Module ADSync
# Set-ADSyncAutoUpgrade -AutoUpgradeState Suspended
# Reset-ADSyncScheduler
# Then re-run the wizard

#############################################################################
# Step 3: Protect AAD Connect Server
#############################################################################

# Move to Tier 0 OU:
`$aadServer = Get-ADComputer -Filter { Description -like '*Azure AD Connect*' }
`$tier0OU = "OU=Tier0,OU=Admin,DC=domain,DC=com"  # Adjust

# Move-ADObject -Identity `$aadServer.DistinguishedName -TargetPath `$tier0OU

# Apply Tier 0 security:
# - Restrict who can log in (Tier 0 admins only)
# - Block internet except Azure AD endpoints
# - Enable Credential Guard
# - Deploy EDR/Sysmon
# - Monitor all access

#############################################################################
# Step 4: Disable Unused MSOL Accounts
#############################################################################

# If multiple MSOL accounts exist, disable old ones:
Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } -Properties LastLogonDate |
    Where-Object { `$_.LastLogonDate -lt (Get-Date).AddDays(-30) } |
    ForEach-Object {
        Write-Host "Old MSOL account: `$(`$_.SamAccountName), Last logon: `$(`$_.LastLogonDate)" -ForegroundColor Yellow
        # Disable-ADAccount -Identity `$_
    }

#############################################################################
# Step 5: Monitor Sync Account Activity
#############################################################################

# The sync account should only log on from the AAD Connect server
# Alert on logins from other locations

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match 'MSOL_'
} | Select-Object TimeCreated, @{N='Source';E={`$_.Properties[18].Value}} |
    Group-Object Source | Sort-Object Count -Descending

#############################################################################
# Step 6: Consider PHS Alternatives
#############################################################################

# PHS alternatives with different security tradeoffs:
#
# Pass-through Authentication (PTA):
# - Passwords validated on-prem
# - No hashes in cloud
# - Requires PTA agents (additional attack surface)
#
# Federation (ADFS):
# - Full control over authentication
# - Complex infrastructure
# - On-prem dependency
#
# Cloud-only:
# - No sync needed
# - Separate cloud identities

#############################################################################
# Step 7: Enable PHS Auditing
#############################################################################

# On AAD Connect server, enable detailed logging:
# Azure AD Connect Health provides monitoring

# Check sync status:
# On AAD Connect server:
# Import-Module ADSync
# Get-ADSyncScheduler
# Get-ADSyncConnectorRunStatus

#############################################################################
# Verification
#############################################################################

# Verify single active MSOL account:
Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } -Properties Enabled |
    Select-Object Name, SamAccountName, Enabled |
    Format-Table -AutoSize

# Verify AAD Connect server is in Tier 0:
Get-ADComputer -Filter { Description -like '*Azure AD Connect*' } |
    Select-Object Name, DistinguishedName |
    Format-Table -AutoSize

"@
            return $commands
        }
    }
}

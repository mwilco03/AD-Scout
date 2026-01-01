@{
    Id          = 'E-StaleDelegation'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Stale Mailbox Delegations'
    Description = 'Detects mailbox permissions granted to disabled, deleted, or inactive user accounts. These stale delegations indicate poor access hygiene and can be exploited if accounts are re-enabled.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Access Reviews Best Practices'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('6.3.5')
    STIG  = @()
    ANSSI = @('vuln1_stale_permissions')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 8
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get list of enabled users for comparison
        # This would cross-reference with AD user data
        $enabledUsers = @{}
        if ($Data.Users) {
            foreach ($user in $Data.Users) {
                if ($user.Enabled) {
                    $enabledUsers[$user.SamAccountName] = $true
                    $enabledUsers[$user.UserPrincipalName] = $true
                }
            }
        }

        # Check all permission types for stale references
        $allPermissions = @()
        $allPermissions += $Data.MailboxPermissions | ForEach-Object {
            [PSCustomObject]@{
                MailboxAddress = $_.MailboxAddress
                DisplayName    = $_.DisplayName
                Trustee        = $_.Trustee
                PermissionType = 'FullAccess'
            }
        }
        $allPermissions += $Data.SendAsPermissions | ForEach-Object {
            [PSCustomObject]@{
                MailboxAddress = $_.MailboxAddress
                DisplayName    = $_.DisplayName
                Trustee        = $_.Trustee
                PermissionType = 'SendAs'
            }
        }
        $allPermissions += $Data.SendOnBehalfPermissions | ForEach-Object {
            [PSCustomObject]@{
                MailboxAddress = $_.MailboxAddress
                DisplayName    = $_.DisplayName
                Trustee        = $_.Delegate
                PermissionType = 'SendOnBehalf'
            }
        }

        foreach ($perm in $allPermissions) {
            $isStale = $false
            $staleReason = ''

            # Check if trustee exists in enabled users
            $trusteeName = $perm.Trustee -replace '^.*\\', ''  # Remove domain prefix

            if ($enabledUsers.Count -gt 0 -and -not $enabledUsers.ContainsKey($trusteeName)) {
                $isStale = $true
                $staleReason = 'User not found or disabled in AD'
            }

            # Check for common patterns indicating deleted accounts
            if ($perm.Trustee -match 'S-1-5-21-\d+-\d+-\d+-\d+') {
                $isStale = $true
                $staleReason = 'Orphaned SID (account deleted)'
            }

            if ($perm.Trustee -match 'NT User:') {
                $isStale = $true
                $staleReason = 'Unresolved NT User reference'
            }

            if ($isStale) {
                $findings += [PSCustomObject]@{
                    MailboxAddress      = $perm.MailboxAddress
                    MailboxDisplayName  = $perm.DisplayName
                    StaleTrustee        = $perm.Trustee
                    PermissionType      = $perm.PermissionType
                    StaleReason         = $staleReason
                    RiskLevel           = if ($perm.PermissionType -eq 'FullAccess') { 'High' }
                                         elseif ($perm.PermissionType -eq 'SendAs') { 'High' }
                                         else { 'Medium' }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove permissions for deleted or disabled accounts. Implement regular access reviews to prevent stale permissions.'
        Impact      = 'Low - Removes permissions for non-existent accounts'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# STALE MAILBOX DELEGATION CLEANUP
# ================================================================
# These permissions reference accounts that no longer exist or are disabled.
# SAFE TO REMOVE - no active user will lose access.

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Stale Trustee: $($item.StaleTrustee)
# Permission: $($item.PermissionType)
# Reason: $($item.StaleReason)

"@
                switch ($item.PermissionType) {
                    'FullAccess' {
                        $commands += "Remove-MailboxPermission -Identity '$($item.MailboxAddress)' -User '$($item.StaleTrustee)' -AccessRights FullAccess -Confirm:`$false`n"
                    }
                    'SendAs' {
                        $commands += "Remove-RecipientPermission -Identity '$($item.MailboxAddress)' -Trustee '$($item.StaleTrustee)' -AccessRights SendAs -Confirm:`$false`n"
                    }
                    'SendOnBehalf' {
                        $commands += "Set-Mailbox -Identity '$($item.MailboxAddress)' -GrantSendOnBehalfTo @{Remove='$($item.StaleTrustee)'}`n"
                    }
                }
            }

            $commands += @"

# ================================================================
# PREVENTION: Set up regular access reviews
# ================================================================
# In Azure AD, configure Access Reviews for mail-enabled groups
# https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview

"@
            return $commands
        }
    }
}

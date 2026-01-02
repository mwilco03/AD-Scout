<#
.SYNOPSIS
    Detects stale user accounts in Entra ID.

.DESCRIPTION
    User accounts that haven't signed in for extended periods may belong to
    former employees, abandoned accounts, or compromised credentials. This
    rule identifies inactive accounts that should be reviewed.

.NOTES
    Rule ID    : EID-StaleUsers
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-StaleUsers'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Stale User Accounts'
    Description = 'Identifies enabled user accounts that have not signed in for 90 days or more.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'EntraUsers'

    References  = @(
        @{ Title = 'How to manage inactive users'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-manage-inactive-user-accounts' }
        @{ Title = 'Access reviews'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.004')          # Cloud Accounts
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 1
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-StaleUsers."
            return @()
        }

        $findings = @()
        $staleThresholdDays = 90

        try {
            $users = Get-ADScoutEntraUserData

            # Filter to stale member accounts
            $staleUsers = $users | Where-Object {
                $_.UserType -eq 'Member' -and
                $_.AccountEnabled -eq $true -and
                $_.HasLicenses -eq $true -and  # Focus on licensed users
                (
                    $null -eq $_.LastSignInDateTime -or
                    $_.DaysSinceLastSignIn -gt $staleThresholdDays
                )
            }

            foreach ($user in $staleUsers) {
                $neverSignedIn = $null -eq $user.LastSignInDateTime

                # Higher risk for privileged stale accounts
                $riskLevel = if ($user.IsPrivileged) { 'High' }
                             elseif ($neverSignedIn -and $user.AccountAgeDays -gt 30) { 'Medium' }
                             elseif ($user.DaysSinceLastSignIn -gt 180) { 'Medium' }
                             else { 'Low' }

                $findings += [PSCustomObject]@{
                    UserPrincipalName    = $user.UserPrincipalName
                    DisplayName          = $user.DisplayName
                    AccountEnabled       = $user.AccountEnabled
                    HasLicenses          = $user.HasLicenses
                    LicenseCount         = $user.LicenseCount
                    IsPrivileged         = $user.IsPrivileged
                    DirectoryRoles       = $user.DirectoryRoles -join '; '
                    IsHybrid             = $user.IsHybrid
                    CreatedDateTime      = $user.CreatedDateTime
                    AccountAgeDays       = $user.AccountAgeDays
                    LastSignInDateTime   = $user.LastSignInDateTime
                    DaysSinceLastSignIn  = $user.DaysSinceLastSignIn
                    NeverSignedIn        = $neverSignedIn
                    RiskLevel            = $riskLevel
                    Recommendation       = if ($user.IsPrivileged) {
                        'Review immediately - privileged stale account'
                    }
                    elseif ($neverSignedIn) {
                        'Verify account is needed - never signed in'
                    }
                    else {
                        'Review for disablement or license removal'
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-StaleUsers: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review stale accounts and disable or remove those no longer needed.'
        Impact      = 'Low - Inactive users will lose access.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Manage Stale User Accounts
#############################################################################
#
# Found stale accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.UserPrincipalName) (Last sign-in: $(if ($_.NeverSignedIn) { 'Never' } else { $_.LastSignInDateTime }))" } | Out-String)
#
#############################################################################
# Step 1: Generate Full Stale Account Report
#############################################################################

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"

# Get all users with sign-in activity
`$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity,AssignedLicenses,CreatedDateTime

`$staleReport = `$users | Where-Object { `$_.AccountEnabled -eq `$true } | ForEach-Object {
    `$lastSignIn = `$_.SignInActivity.LastSignInDateTime
    if (-not `$lastSignIn) { `$lastSignIn = `$_.SignInActivity.LastNonInteractiveSignInDateTime }

    `$daysSince = if (`$lastSignIn) { ((Get-Date) - `$lastSignIn).Days } else { 999 }

    [PSCustomObject]@{
        UPN = `$_.UserPrincipalName
        DisplayName = `$_.DisplayName
        Created = `$_.CreatedDateTime
        LastSignIn = `$lastSignIn
        DaysSinceSignIn = `$daysSince
        HasLicenses = (`$_.AssignedLicenses.Count -gt 0)
        Status = if (`$null -eq `$lastSignIn) { 'Never signed in' }
                 elseif (`$daysSince -gt 180) { 'Very stale (180+ days)' }
                 elseif (`$daysSince -gt 90) { 'Stale (90+ days)' }
                 else { 'Active' }
    }
} | Where-Object { `$_.Status -ne 'Active' }

`$staleReport | Sort-Object DaysSinceSignIn -Descending | Format-Table -AutoSize

#############################################################################
# Step 2: Disable Stale Accounts
#############################################################################

Connect-MgGraph -Scopes "User.ReadWrite.All"

# Disable accounts inactive for 180+ days
`$toDisable = `$staleReport | Where-Object { `$_.DaysSinceSignIn -gt 180 }

foreach (`$user in `$toDisable) {
    Write-Host "Would disable: `$(`$user.UPN)" -ForegroundColor Yellow
    # Update-MgUser -UserId `$user.UPN -AccountEnabled:`$false
}

#############################################################################
# Step 3: Remove Licenses from Disabled Accounts
#############################################################################

# Save license costs by removing from disabled users
`$disabledWithLicenses = Get-MgUser -Filter "accountEnabled eq false" -Property Id,DisplayName,UserPrincipalName,AssignedLicenses -All |
    Where-Object { `$_.AssignedLicenses.Count -gt 0 }

foreach (`$user in `$disabledWithLicenses) {
    Write-Host "Would remove licenses from: `$(`$user.UserPrincipalName)" -ForegroundColor Yellow
    # foreach (`$license in `$user.AssignedLicenses) {
    #     Set-MgUserLicense -UserId `$user.Id -RemoveLicenses @(`$license.SkuId) -AddLicenses @()
    # }
}

#############################################################################
# Step 4: Set Up Automated Access Reviews
#############################################################################

# Create access review for stale accounts (requires P2)
# Access reviews can automatically disable accounts not confirmed

# Example: Review all users with no sign-in in 90 days
`$reviewDefinition = @{
    displayName = "Quarterly Stale Account Review"
    descriptionForAdmins = "Review accounts with no sign-in activity"
    scope = @{
        query = "/users?`$filter=(signInActivity/lastSignInDateTime le 2024-01-01)"
        queryType = "MicrosoftGraph"
    }
    reviewers = @(
        @{ query = "/users/{manager-id}"; queryType = "MicrosoftGraph" }
    )
    settings = @{
        defaultDecisionEnabled = `$true
        defaultDecision = "Deny"  # Disable if not confirmed
        autoApplyDecisionsEnabled = `$true
    }
}

#############################################################################
# Step 5: Implement Lifecycle Policies
#############################################################################

# Consider implementing:
# - Automatic account expiration for contractors
# - HR-driven account provisioning/deprovisioning
# - Azure AD Identity Governance workflows
# - Integration with HRIS for employee lifecycle

Write-Host "Review stale accounts and disable those no longer needed." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

<#
.SYNOPSIS
    Detects stale guest (B2B) accounts in Entra ID.

.DESCRIPTION
    Guest accounts that haven't signed in for extended periods represent
    a security risk. They may belong to former contractors, partners, or
    employees of external organizations who no longer need access.

.NOTES
    Rule ID    : EID-StaleGuestAccounts
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-StaleGuestAccounts'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Stale Guest Accounts'
    Description = 'Identifies guest (B2B) accounts that have not signed in for 90 days or more, or have never signed in.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'EntraUsers'

    References  = @(
        @{ Title = 'Manage guest access with access reviews'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/governance/manage-guest-access-with-access-reviews' }
        @{ Title = 'B2B collaboration overview'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.004')          # Cloud Accounts
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 2
        MaxPoints = 40
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-StaleGuestAccounts."
            return @()
        }

        $findings = @()
        $staleThresholdDays = 90

        try {
            # Get all users including guests
            $users = Get-ADScoutEntraUserData -IncludeGuests

            # Filter to stale guests
            $staleGuests = $users | Where-Object {
                $_.UserType -eq 'Guest' -and
                $_.AccountEnabled -eq $true -and
                (
                    $null -eq $_.LastSignInDateTime -or
                    $_.DaysSinceLastSignIn -gt $staleThresholdDays
                )
            }

            foreach ($guest in $staleGuests) {
                $neverSignedIn = $null -eq $guest.LastSignInDateTime

                $riskLevel = if ($neverSignedIn -and $guest.AccountAgeDays -gt 180) {
                    'High'
                }
                elseif ($guest.DaysSinceLastSignIn -gt 180) {
                    'High'
                }
                else {
                    'Medium'
                }

                $findings += [PSCustomObject]@{
                    UserPrincipalName     = $guest.UserPrincipalName
                    DisplayName           = $guest.DisplayName
                    Mail                  = $guest.Mail
                    UserType              = $guest.UserType
                    AccountEnabled        = $guest.AccountEnabled
                    CreatedDateTime       = $guest.CreatedDateTime
                    AccountAgeDays        = $guest.AccountAgeDays
                    LastSignInDateTime    = $guest.LastSignInDateTime
                    DaysSinceLastSignIn   = $guest.DaysSinceLastSignIn
                    NeverSignedIn         = $neverSignedIn
                    RiskLevel             = $riskLevel
                    Recommendation        = if ($neverSignedIn) {
                        'Consider removing - never signed in'
                    }
                    else {
                        'Review for removal - inactive for over 90 days'
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-StaleGuestAccounts: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove stale guest accounts, implement access reviews.'
        Impact      = 'Low - External users lose access.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Remove Stale Guest Accounts
#############################################################################
#
# Found stale guest accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.UserPrincipalName) (Last sign-in: $(if ($_.NeverSignedIn) { 'Never' } else { $_.LastSignInDateTime }))" } | Out-String)
#
#############################################################################
# Step 1: Review Guest Access
#############################################################################

Connect-MgGraph -Scopes "User.ReadWrite.All"

# List all guest accounts with sign-in activity
Get-MgUser -Filter "userType eq 'Guest'" -Property Id,DisplayName,Mail,SignInActivity,CreatedDateTime -All |
    Select-Object DisplayName, Mail, CreatedDateTime,
        @{N='LastSignIn';E={`$_.SignInActivity.LastSignInDateTime}},
        @{N='DaysSinceSignIn';E={if(`$_.SignInActivity.LastSignInDateTime){((Get-Date) - `$_.SignInActivity.LastSignInDateTime).Days}else{'Never'}}} |
    Sort-Object DaysSinceSignIn -Descending |
    Format-Table -AutoSize

#############################################################################
# Step 2: Remove Specific Guest Accounts
#############################################################################

# Remove individual guest account
# `$guestToRemove = Get-MgUser -Filter "userPrincipalName eq 'guest#EXT#@domain.onmicrosoft.com'"
# Remove-MgUser -UserId `$guestToRemove.Id

# Remove guests that never signed in and are older than 30 days
`$oldNeverSignedIn = Get-MgUser -Filter "userType eq 'Guest'" -Property Id,DisplayName,SignInActivity,CreatedDateTime -All |
    Where-Object {
        `$null -eq `$_.SignInActivity.LastSignInDateTime -and
        `$_.CreatedDateTime -lt (Get-Date).AddDays(-30)
    }

foreach (`$guest in `$oldNeverSignedIn) {
    Write-Host "Would remove: `$(`$guest.DisplayName)" -ForegroundColor Yellow
    # Remove-MgUser -UserId `$guest.Id -Confirm
}

#############################################################################
# Step 3: Set Up Recurring Access Reviews
#############################################################################

# Create access review for all guests (requires P2 license)
# Access reviews automatically prompt reviewers to confirm guest access

`$reviewDefinition = @{
    displayName = "Quarterly Guest Access Review"
    descriptionForAdmins = "Review all guest accounts quarterly"
    descriptionForReviewers = "Please review if this guest user still needs access"
    scope = @{
        query = "/users?`$filter=(userType eq 'Guest')"
        queryType = "MicrosoftGraph"
    }
    reviewers = @(
        @{
            query = "/users/{manager-id}"
            queryType = "MicrosoftGraph"
        }
    )
    settings = @{
        mailNotificationsEnabled = `$true
        reminderNotificationsEnabled = `$true
        justificationRequiredOnApproval = `$true
        defaultDecisionEnabled = `$true
        defaultDecision = "Deny"
        instanceDurationInDays = 14
        autoApplyDecisionsEnabled = `$true
        recommendationsEnabled = `$true
        recurrence = @{
            pattern = @{
                type = "absoluteMonthly"
                interval = 3
            }
            range = @{
                type = "noEnd"
                startDate = (Get-Date).ToString("yyyy-MM-dd")
            }
        }
    }
}

# New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter `$reviewDefinition

#############################################################################
# Step 4: Implement Guest Lifecycle Policies
#############################################################################

# Configure guest invitation settings:
# - Limit who can invite guests
# - Require approval for certain domains
# - Set guest expiration policies

Write-Host "Review and remove stale guests. Consider implementing access reviews." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

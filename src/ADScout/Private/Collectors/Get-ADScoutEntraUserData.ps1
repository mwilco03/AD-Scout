function Get-ADScoutEntraUserData {
    <#
    .SYNOPSIS
        Collects user data from Entra ID (Azure AD) via Microsoft Graph.

    .DESCRIPTION
        Retrieves user accounts with security-relevant properties from Entra ID.
        Requires active Microsoft Graph connection via Connect-ADScoutGraph.

    .PARAMETER IncludeGuests
        Include guest/B2B users in the results.

    .PARAMETER IncludeMFAStatus
        Include MFA registration status (requires additional API call).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeGuests,

        [Parameter()]
        [switch]$IncludeMFAStatus
    )

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected. Skipping Entra ID user collection."
        return @()
    }

    # Check cache
    $cacheKey = "EntraUsers:$IncludeGuests`:$IncludeMFAStatus"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached Entra ID user data"
        return $cached
    }

    Write-Verbose "Collecting user data from Entra ID"

    try {
        # Import required module
        Import-Module Microsoft.Graph.Users -ErrorAction Stop

        # Build filter
        $filter = if (-not $IncludeGuests) {
            "userType eq 'Member'"
        }
        else {
            $null
        }

        # Properties to retrieve
        $properties = @(
            'Id'
            'UserPrincipalName'
            'DisplayName'
            'Mail'
            'AccountEnabled'
            'CreatedDateTime'
            'LastSignInDateTime'
            'UserType'
            'OnPremisesSyncEnabled'
            'OnPremisesSamAccountName'
            'OnPremisesDistinguishedName'
            'AssignedLicenses'
            'AssignedPlans'
            'PasswordPolicies'
            'SignInActivity'
        )

        $params = @{
            All      = $true
            Property = $properties
        }

        if ($filter) {
            $params.Filter = $filter
        }

        $users = Get-MgUser @params -ErrorAction Stop

        # Get MFA status if requested
        $mfaStatus = @{}
        if ($IncludeMFAStatus) {
            try {
                Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
                $mfaReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction SilentlyContinue

                foreach ($record in $mfaReport) {
                    $mfaStatus[$record.UserPrincipalName] = @{
                        IsMfaRegistered  = $record.IsMfaRegistered
                        IsMfaCapable     = $record.IsMfaCapable
                        DefaultMfaMethod = $record.DefaultMfaMethod
                        MethodsRegistered = $record.MethodsRegistered
                        IsPasswordlessCapable = $record.IsPasswordlessCapable
                    }
                }
            }
            catch {
                Write-Warning "Could not retrieve MFA status: $_"
            }
        }

        # Get directory roles for privilege detection
        $privilegedUsers = @{}
        try {
            Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
            $roles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue

            foreach ($role in $roles) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    if (-not $privilegedUsers.ContainsKey($member.Id)) {
                        $privilegedUsers[$member.Id] = @()
                    }
                    $privilegedUsers[$member.Id] += $role.DisplayName
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve role assignments: $_"
        }

        # Normalize to consistent format
        $normalizedUsers = foreach ($user in $users) {
            $userMfa = $mfaStatus[$user.UserPrincipalName]
            $userRoles = $privilegedUsers[$user.Id]

            # Calculate last sign-in
            $lastSignIn = $null
            if ($user.SignInActivity) {
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
                if (-not $lastSignIn) {
                    $lastSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
                }
            }

            # Determine if privileged
            $isPrivileged = $userRoles.Count -gt 0
            $isGlobalAdmin = $userRoles -contains 'Global Administrator'

            # Calculate account age
            $accountAge = if ($user.CreatedDateTime) {
                (Get-Date) - $user.CreatedDateTime
            }
            else { $null }

            # Calculate days since last sign-in
            $daysSinceSignIn = if ($lastSignIn) {
                ((Get-Date) - $lastSignIn).Days
            }
            else { $null }

            [PSCustomObject]@{
                # Identity
                Id                          = $user.Id
                UserPrincipalName           = $user.UserPrincipalName
                DisplayName                 = $user.DisplayName
                Mail                        = $user.Mail
                UserType                    = $user.UserType

                # Status
                AccountEnabled              = $user.AccountEnabled
                CreatedDateTime             = $user.CreatedDateTime
                AccountAgeDays              = if ($accountAge) { [int]$accountAge.TotalDays } else { $null }
                LastSignInDateTime          = $lastSignIn
                DaysSinceLastSignIn         = $daysSinceSignIn

                # Hybrid status
                IsHybrid                    = [bool]$user.OnPremisesSyncEnabled
                OnPremisesSamAccountName    = $user.OnPremisesSamAccountName
                OnPremisesDistinguishedName = $user.OnPremisesDistinguishedName

                # Licensing
                HasLicenses                 = ($user.AssignedLicenses.Count -gt 0)
                LicenseCount                = $user.AssignedLicenses.Count

                # Privileges
                IsPrivileged                = $isPrivileged
                IsGlobalAdmin               = $isGlobalAdmin
                DirectoryRoles              = $userRoles

                # MFA Status
                IsMfaRegistered             = if ($userMfa) { $userMfa.IsMfaRegistered } else { $null }
                IsMfaCapable                = if ($userMfa) { $userMfa.IsMfaCapable } else { $null }
                DefaultMfaMethod            = if ($userMfa) { $userMfa.DefaultMfaMethod } else { $null }
                MfaMethodsRegistered        = if ($userMfa) { $userMfa.MethodsRegistered } else { @() }
                IsPasswordlessCapable       = if ($userMfa) { $userMfa.IsPasswordlessCapable } else { $null }

                # Password policies
                PasswordPolicies            = $user.PasswordPolicies
            }
        }

        # Cache results
        Set-ADScoutCache -Key $cacheKey -Value $normalizedUsers

        Write-Verbose "Collected $($normalizedUsers.Count) Entra ID users"

        return $normalizedUsers
    }
    catch {
        Write-Error "Failed to collect Entra ID user data: $_"
        return @()
    }
}

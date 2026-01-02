function Get-ADScoutEntraPolicyData {
    <#
    .SYNOPSIS
        Collects security policy data from Entra ID.

    .DESCRIPTION
        Retrieves Conditional Access policies, authentication methods policies,
        and other security configurations from Entra ID.

        Requires active Microsoft Graph connection via Connect-ADScoutGraph.
    #>
    [CmdletBinding()]
    param()

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected. Skipping Entra ID policy collection."
        return @()
    }

    # Check cache
    $cacheKey = "EntraPolicies"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached Entra ID policy data"
        return $cached
    }

    Write-Verbose "Collecting policy data from Entra ID"

    $policyData = [PSCustomObject]@{
        ConditionalAccessPolicies = @()
        AuthenticationMethods     = $null
        AuthorizationPolicy       = $null
        SecurityDefaults          = $null
        PasswordPolicy            = $null
    }

    try {
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

        # Get Conditional Access policies
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue

            $policyData.ConditionalAccessPolicies = foreach ($policy in $caPolicies) {
                # Analyze policy coverage
                $targetUsers = $policy.Conditions.Users
                $targetApps = $policy.Conditions.Applications
                $grantControls = $policy.GrantControls

                # Check if policy requires MFA
                $requiresMfa = $grantControls.BuiltInControls -contains 'mfa'

                # Check if policy blocks legacy auth
                $blocksLegacyAuth = ($policy.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
                                    $policy.Conditions.ClientAppTypes -contains 'other') -and
                                    $grantControls.BuiltInControls -contains 'block'

                # Check scope
                $appliesToAllUsers = $targetUsers.IncludeUsers -contains 'All'
                $appliesToAllApps = $targetApps.IncludeApplications -contains 'All'

                [PSCustomObject]@{
                    Id                   = $policy.Id
                    DisplayName          = $policy.DisplayName
                    State                = $policy.State
                    CreatedDateTime      = $policy.CreatedDateTime
                    ModifiedDateTime     = $policy.ModifiedDateTime

                    # Scope
                    AppliesToAllUsers    = $appliesToAllUsers
                    AppliesToAllApps     = $appliesToAllApps
                    IncludedUsers        = $targetUsers.IncludeUsers
                    ExcludedUsers        = $targetUsers.ExcludeUsers
                    IncludedGroups       = $targetUsers.IncludeGroups
                    ExcludedGroups       = $targetUsers.ExcludeGroups
                    IncludedApps         = $targetApps.IncludeApplications
                    ExcludedApps         = $targetApps.ExcludeApplications

                    # Controls
                    GrantControls        = $grantControls.BuiltInControls
                    RequiresMfa          = $requiresMfa
                    BlocksLegacyAuth     = $blocksLegacyAuth
                    SessionControls      = $policy.SessionControls

                    # Conditions
                    Platforms            = $policy.Conditions.Platforms
                    Locations            = $policy.Conditions.Locations
                    ClientAppTypes       = $policy.Conditions.ClientAppTypes
                    SignInRiskLevels     = $policy.Conditions.SignInRiskLevels
                    UserRiskLevels       = $policy.Conditions.UserRiskLevels
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve Conditional Access policies: $_"
        }

        # Get authentication methods policy
        try {
            $authMethods = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue

            $policyData.AuthenticationMethods = [PSCustomObject]@{
                Id                     = $authMethods.Id
                Description            = $authMethods.Description
                LastModifiedDateTime   = $authMethods.LastModifiedDateTime
                PolicyVersion          = $authMethods.PolicyVersion
                PolicyMigrationState   = $authMethods.PolicyMigrationState

                # Extract method configurations
                AuthenticationMethodConfigurations = $authMethods.AuthenticationMethodConfigurations | ForEach-Object {
                    [PSCustomObject]@{
                        Id            = $_.Id
                        State         = $_.State
                        MethodType    = $_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethodConfiguration', ''
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve authentication methods policy: $_"
        }

        # Get authorization policy
        try {
            $authzPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue

            if ($authzPolicy) {
                $policyData.AuthorizationPolicy = [PSCustomObject]@{
                    Id                                     = $authzPolicy.Id
                    DisplayName                            = $authzPolicy.DisplayName
                    Description                            = $authzPolicy.Description

                    # Guest settings
                    AllowInvitesFrom                       = $authzPolicy.AllowInvitesFrom
                    GuestUserRoleId                        = $authzPolicy.GuestUserRoleId
                    AllowEmailVerifiedUsersToJoinOrganization = $authzPolicy.AllowEmailVerifiedUsersToJoinOrganization

                    # User settings
                    AllowedToSignUpEmailBasedSubscriptions = $authzPolicy.AllowedToSignUpEmailBasedSubscriptions
                    AllowedToUseSSPR                       = $authzPolicy.AllowedToUseSSPR
                    BlockMsolPowerShell                    = $authzPolicy.BlockMsolPowerShell

                    # Default user permissions
                    DefaultUserRolePermissions             = $authzPolicy.DefaultUserRolePermissions
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve authorization policy: $_"
        }

        # Check if Security Defaults are enabled
        try {
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue

            $policyData.SecurityDefaults = [PSCustomObject]@{
                Id          = $securityDefaults.Id
                DisplayName = $securityDefaults.DisplayName
                Description = $securityDefaults.Description
                IsEnabled   = $securityDefaults.IsEnabled
            }
        }
        catch {
            Write-Verbose "Could not retrieve security defaults: $_"
        }

        # Cache results
        Set-ADScoutCache -Key $cacheKey -Value $policyData

        Write-Verbose "Collected Entra ID policy data"

        return $policyData
    }
    catch {
        Write-Error "Failed to collect Entra ID policy data: $_"
        return $policyData
    }
}

function Get-ADScoutEntraSignInLogs {
    <#
    .SYNOPSIS
        Collects recent sign-in logs from Entra ID.

    .DESCRIPTION
        Retrieves sign-in audit logs for risk detection and analysis.
        Limited to recent entries due to API constraints.

    .PARAMETER Days
        Number of days of logs to retrieve (default: 7, max: 30).

    .PARAMETER RiskyOnly
        Only retrieve risky sign-ins.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [Parameter()]
        [switch]$RiskyOnly
    )

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected."
        return @()
    }

    try {
        Import-Module Microsoft.Graph.Reports -ErrorAction Stop

        $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $filter = "createdDateTime ge $startDate"
        if ($RiskyOnly) {
            $filter += " and (riskLevelDuringSignIn ne 'none' or riskLevelAggregated ne 'none')"
        }

        $signIns = Get-MgAuditLogSignIn -Filter $filter -Top 1000 -ErrorAction Stop

        $normalizedSignIns = foreach ($signIn in $signIns) {
            [PSCustomObject]@{
                Id                     = $signIn.Id
                CreatedDateTime        = $signIn.CreatedDateTime
                UserPrincipalName      = $signIn.UserPrincipalName
                UserDisplayName        = $signIn.UserDisplayName
                UserId                 = $signIn.UserId

                # App info
                AppDisplayName         = $signIn.AppDisplayName
                AppId                  = $signIn.AppId
                ResourceDisplayName    = $signIn.ResourceDisplayName

                # Status
                Status                 = $signIn.Status.ErrorCode
                StatusFailureReason    = $signIn.Status.FailureReason

                # Risk
                RiskLevelDuringSignIn  = $signIn.RiskLevelDuringSignIn
                RiskLevelAggregated    = $signIn.RiskLevelAggregated
                RiskDetail             = $signIn.RiskDetail
                RiskState              = $signIn.RiskState

                # Location
                IPAddress              = $signIn.IPAddress
                City                   = $signIn.Location.City
                State                  = $signIn.Location.State
                CountryOrRegion        = $signIn.Location.CountryOrRegion

                # Device
                DeviceId               = $signIn.DeviceDetail.DeviceId
                DeviceDisplayName      = $signIn.DeviceDetail.DisplayName
                OperatingSystem        = $signIn.DeviceDetail.OperatingSystem
                Browser                = $signIn.DeviceDetail.Browser
                IsCompliant            = $signIn.DeviceDetail.IsCompliant
                IsManaged              = $signIn.DeviceDetail.IsManaged

                # Auth details
                ClientAppUsed          = $signIn.ClientAppUsed
                ConditionalAccessStatus = $signIn.ConditionalAccessStatus
                IsInteractive          = $signIn.IsInteractive
                MfaDetail              = $signIn.MfaDetail
            }
        }

        return $normalizedSignIns
    }
    catch {
        Write-Warning "Could not retrieve sign-in logs: $_"
        return @()
    }
}

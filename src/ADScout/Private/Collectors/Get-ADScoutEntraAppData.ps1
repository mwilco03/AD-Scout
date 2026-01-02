function Get-ADScoutEntraAppData {
    <#
    .SYNOPSIS
        Collects application and service principal data from Entra ID.

    .DESCRIPTION
        Retrieves enterprise applications, app registrations, and service principals
        with security-relevant properties. Includes OAuth permission grants and
        credential expiration information.

        Requires active Microsoft Graph connection via Connect-ADScoutGraph.
    #>
    [CmdletBinding()]
    param()

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected. Skipping Entra ID app collection."
        return @()
    }

    # Check cache
    $cacheKey = "EntraApps"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached Entra ID app data"
        return $cached
    }

    Write-Verbose "Collecting application data from Entra ID"

    try {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop

        # Get all service principals (enterprise apps)
        $servicePrincipals = Get-MgServicePrincipal -All -Property @(
            'Id'
            'AppId'
            'DisplayName'
            'ServicePrincipalType'
            'AccountEnabled'
            'AppRoleAssignmentRequired'
            'CreatedDateTime'
            'KeyCredentials'
            'PasswordCredentials'
            'Oauth2PermissionScopes'
            'AppRoles'
            'Tags'
            'SignInAudience'
        ) -ErrorAction Stop

        # Get app registrations
        $appRegistrations = Get-MgApplication -All -Property @(
            'Id'
            'AppId'
            'DisplayName'
            'CreatedDateTime'
            'KeyCredentials'
            'PasswordCredentials'
            'RequiredResourceAccess'
            'SignInAudience'
            'PublisherDomain'
        ) -ErrorAction Stop

        # Get OAuth2 permission grants (delegated permissions)
        $oauthGrants = @{}
        try {
            $grants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
            foreach ($grant in $grants) {
                if (-not $oauthGrants.ContainsKey($grant.ClientId)) {
                    $oauthGrants[$grant.ClientId] = @()
                }
                $oauthGrants[$grant.ClientId] += [PSCustomObject]@{
                    ResourceId   = $grant.ResourceId
                    Scope        = $grant.Scope
                    ConsentType  = $grant.ConsentType
                    PrincipalId  = $grant.PrincipalId
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve OAuth grants: $_"
        }

        # Build lookup for app registrations by AppId
        $appRegLookup = @{}
        foreach ($app in $appRegistrations) {
            $appRegLookup[$app.AppId] = $app
        }

        # Process service principals
        $normalizedApps = foreach ($sp in $servicePrincipals) {
            $appReg = $appRegLookup[$sp.AppId]
            $grants = $oauthGrants[$sp.Id]

            # Check credential expiration
            $credentials = @()
            $hasExpiredCreds = $false
            $hasExpiringCreds = $false
            $credentialCount = 0

            # Password credentials (client secrets)
            foreach ($cred in $sp.PasswordCredentials) {
                $credentialCount++
                $daysUntilExpiry = if ($cred.EndDateTime) {
                    ($cred.EndDateTime - (Get-Date)).Days
                }
                else { 999999 }

                if ($daysUntilExpiry -lt 0) { $hasExpiredCreds = $true }
                if ($daysUntilExpiry -ge 0 -and $daysUntilExpiry -le 30) { $hasExpiringCreds = $true }

                $credentials += [PSCustomObject]@{
                    Type           = 'ClientSecret'
                    DisplayName    = $cred.DisplayName
                    KeyId          = $cred.KeyId
                    StartDateTime  = $cred.StartDateTime
                    EndDateTime    = $cred.EndDateTime
                    DaysUntilExpiry = $daysUntilExpiry
                    IsExpired      = ($daysUntilExpiry -lt 0)
                }
            }

            # Key credentials (certificates)
            foreach ($cred in $sp.KeyCredentials) {
                $credentialCount++
                $daysUntilExpiry = if ($cred.EndDateTime) {
                    ($cred.EndDateTime - (Get-Date)).Days
                }
                else { 999999 }

                if ($daysUntilExpiry -lt 0) { $hasExpiredCreds = $true }
                if ($daysUntilExpiry -ge 0 -and $daysUntilExpiry -le 30) { $hasExpiringCreds = $true }

                $credentials += [PSCustomObject]@{
                    Type           = 'Certificate'
                    DisplayName    = $cred.DisplayName
                    KeyId          = $cred.KeyId
                    StartDateTime  = $cred.StartDateTime
                    EndDateTime    = $cred.EndDateTime
                    DaysUntilExpiry = $daysUntilExpiry
                    IsExpired      = ($daysUntilExpiry -lt 0)
                }
            }

            # Check for high-privilege permissions
            $hasHighPrivilege = $false
            $highPrivilegeScopes = @(
                'Directory.ReadWrite.All'
                'RoleManagement.ReadWrite.Directory'
                'Application.ReadWrite.All'
                'AppRoleAssignment.ReadWrite.All'
                'Mail.ReadWrite'
                'Files.ReadWrite.All'
                'User.ReadWrite.All'
                'Group.ReadWrite.All'
            )

            if ($grants) {
                foreach ($grant in $grants) {
                    $scopes = $grant.Scope -split ' '
                    if ($scopes | Where-Object { $_ -in $highPrivilegeScopes }) {
                        $hasHighPrivilege = $true
                        break
                    }
                }
            }

            # Determine app type
            $appType = switch ($sp.ServicePrincipalType) {
                'Application' { 'EnterpriseApp' }
                'ManagedIdentity' { 'ManagedIdentity' }
                'Legacy' { 'Legacy' }
                default { $sp.ServicePrincipalType }
            }

            # Check if first-party Microsoft app
            $isFirstParty = $sp.AppId -match '^00000[0-9a-f-]+$' -or
                            $sp.Tags -contains 'WindowsAzureActiveDirectoryIntegratedApp'

            [PSCustomObject]@{
                # Identity
                Id                       = $sp.Id
                AppId                    = $sp.AppId
                DisplayName              = $sp.DisplayName
                ServicePrincipalType     = $appType

                # Status
                Enabled                  = $sp.AccountEnabled
                CreatedDateTime          = $sp.CreatedDateTime

                # Classification
                IsFirstParty             = $isFirstParty
                SignInAudience           = $sp.SignInAudience
                RequiresAssignment       = $sp.AppRoleAssignmentRequired

                # Credentials
                CredentialCount          = $credentialCount
                Credentials              = $credentials
                HasExpiredCredentials    = $hasExpiredCreds
                HasExpiringCredentials   = $hasExpiringCreds

                # Permissions
                OAuthGrants              = $grants
                OAuthGrantCount          = if ($grants) { $grants.Count } else { 0 }
                HasHighPrivilegeGrants   = $hasHighPrivilege

                # App registration details (if exists)
                HasAppRegistration       = ($null -ne $appReg)
                PublisherDomain          = if ($appReg) { $appReg.PublisherDomain } else { $null }
            }
        }

        # Cache results
        Set-ADScoutCache -Key $cacheKey -Value $normalizedApps

        Write-Verbose "Collected $($normalizedApps.Count) Entra ID applications"

        return $normalizedApps
    }
    catch {
        Write-Error "Failed to collect Entra ID app data: $_"
        return @()
    }
}

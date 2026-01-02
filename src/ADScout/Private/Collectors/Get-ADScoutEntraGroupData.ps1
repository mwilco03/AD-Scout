function Get-ADScoutEntraGroupData {
    <#
    .SYNOPSIS
        Collects group data from Entra ID (Azure AD) via Microsoft Graph.

    .DESCRIPTION
        Retrieves security groups and their memberships from Entra ID.
        Requires active Microsoft Graph connection via Connect-ADScoutGraph.

    .PARAMETER IncludeM365Groups
        Include Microsoft 365 groups in addition to security groups.

    .PARAMETER IncludeMembers
        Include group membership details (increases API calls).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeM365Groups,

        [Parameter()]
        [switch]$IncludeMembers
    )

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected. Skipping Entra ID group collection."
        return @()
    }

    # Check cache
    $cacheKey = "EntraGroups:$IncludeM365Groups`:$IncludeMembers"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached Entra ID group data"
        return $cached
    }

    Write-Verbose "Collecting group data from Entra ID"

    try {
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop

        # Build filter for security groups
        $filter = if (-not $IncludeM365Groups) {
            "securityEnabled eq true and mailEnabled eq false"
        }
        else {
            "securityEnabled eq true"
        }

        $groups = Get-MgGroup -All -Filter $filter -Property @(
            'Id'
            'DisplayName'
            'Description'
            'SecurityEnabled'
            'MailEnabled'
            'GroupTypes'
            'CreatedDateTime'
            'OnPremisesSyncEnabled'
            'OnPremisesSecurityIdentifier'
            'IsAssignableToRole'
            'MembershipRule'
            'MembershipRuleProcessingState'
        ) -ErrorAction Stop

        # Get role-assignable groups (privileged)
        $roleAssignableGroups = $groups | Where-Object { $_.IsAssignableToRole -eq $true }

        # Get membership counts and optionally full membership
        $normalizedGroups = foreach ($group in $groups) {
            # Get member count
            $memberCount = 0
            $members = @()

            try {
                if ($IncludeMembers) {
                    $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                    $memberCount = $members.Count
                }
                else {
                    # Just get count via API
                    $memberCount = (Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue).Count
                }
            }
            catch {
                Write-Verbose "Could not get members for group $($group.DisplayName)"
            }

            # Get owners
            $owners = @()
            try {
                $owners = Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty AdditionalProperties |
                    ForEach-Object { $_['userPrincipalName'] }
            }
            catch {
                Write-Verbose "Could not get owners for group $($group.DisplayName)"
            }

            # Determine group type
            $groupType = 'Security'
            if ($group.GroupTypes -contains 'Unified') {
                $groupType = 'Microsoft365'
            }
            elseif ($group.GroupTypes -contains 'DynamicMembership') {
                $groupType = 'DynamicSecurity'
            }

            [PSCustomObject]@{
                Id                          = $group.Id
                DisplayName                 = $group.DisplayName
                Description                 = $group.Description
                GroupType                   = $groupType
                SecurityEnabled             = $group.SecurityEnabled
                MailEnabled                 = $group.MailEnabled

                # Membership
                MemberCount                 = $memberCount
                Members                     = if ($IncludeMembers) { $members } else { @() }
                Owners                      = $owners
                OwnerCount                  = $owners.Count

                # Dynamic membership
                IsDynamic                   = ($group.GroupTypes -contains 'DynamicMembership')
                MembershipRule              = $group.MembershipRule
                MembershipRuleProcessing    = $group.MembershipRuleProcessingState

                # Privilege
                IsRoleAssignable            = $group.IsAssignableToRole
                IsPrivileged                = $group.IsAssignableToRole

                # Hybrid status
                IsHybrid                    = [bool]$group.OnPremisesSyncEnabled
                OnPremisesSid               = $group.OnPremisesSecurityIdentifier

                # Metadata
                CreatedDateTime             = $group.CreatedDateTime
            }
        }

        # Cache results
        Set-ADScoutCache -Key $cacheKey -Value $normalizedGroups

        Write-Verbose "Collected $($normalizedGroups.Count) Entra ID groups"

        return $normalizedGroups
    }
    catch {
        Write-Error "Failed to collect Entra ID group data: $_"
        return @()
    }
}

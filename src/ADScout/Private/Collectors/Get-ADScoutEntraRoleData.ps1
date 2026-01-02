function Get-ADScoutEntraRoleData {
    <#
    .SYNOPSIS
        Collects directory role and PIM data from Entra ID.

    .DESCRIPTION
        Retrieves directory role definitions, role assignments, and PIM
        (Privileged Identity Management) eligibility information.

        Requires active Microsoft Graph connection via Connect-ADScoutGraph.
    #>
    [CmdletBinding()]
    param()

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected. Skipping Entra ID role collection."
        return @()
    }

    # Check cache
    $cacheKey = "EntraRoles"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached Entra ID role data"
        return $cached
    }

    Write-Verbose "Collecting role data from Entra ID"

    try {
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

        # Get role definitions
        $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop

        # Get active role assignments
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop

        # Try to get PIM eligible assignments
        $pimEligible = @()
        try {
            $pimEligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "PIM data not available (may require P2 license): $_"
        }

        # Build role definition lookup
        $roleLookup = @{}
        foreach ($role in $roleDefinitions) {
            $roleLookup[$role.Id] = $role
        }

        # Identify high-privilege roles
        $highPrivilegeRoles = @(
            'Global Administrator'
            'Privileged Role Administrator'
            'Privileged Authentication Administrator'
            'Security Administrator'
            'Exchange Administrator'
            'SharePoint Administrator'
            'Intune Administrator'
            'Azure AD Joined Device Local Administrator'
            'Cloud Application Administrator'
            'Application Administrator'
            'Authentication Administrator'
            'Helpdesk Administrator'
            'User Administrator'
            'Groups Administrator'
        )

        $criticalRoles = @(
            'Global Administrator'
            'Privileged Role Administrator'
            'Privileged Authentication Administrator'
        )

        # Process role assignments
        $assignmentsByRole = @{}
        foreach ($assignment in $roleAssignments) {
            $roleId = $assignment.RoleDefinitionId
            if (-not $assignmentsByRole.ContainsKey($roleId)) {
                $assignmentsByRole[$roleId] = @()
            }
            $assignmentsByRole[$roleId] += $assignment
        }

        # Build normalized role data
        $normalizedRoles = foreach ($role in $roleDefinitions) {
            $assignments = $assignmentsByRole[$role.Id]
            $assignmentCount = if ($assignments) { $assignments.Count } else { 0 }

            # Get eligible (PIM) count
            $eligibleCount = ($pimEligible | Where-Object { $_.RoleDefinitionId -eq $role.Id }).Count

            # Check privilege level
            $isHighPrivilege = $role.DisplayName -in $highPrivilegeRoles
            $isCritical = $role.DisplayName -in $criticalRoles

            # Extract assigned principals
            $assignedPrincipals = @()
            if ($assignments) {
                $assignedPrincipals = foreach ($a in $assignments) {
                    [PSCustomObject]@{
                        PrincipalId   = $a.PrincipalId
                        PrincipalType = if ($a.Principal.AdditionalProperties['@odata.type']) {
                            $a.Principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                        } else { 'Unknown' }
                        DisplayName   = $a.Principal.AdditionalProperties['displayName']
                        AssignmentType = 'Active'
                        DirectoryScopeId = $a.DirectoryScopeId
                    }
                }
            }

            [PSCustomObject]@{
                Id                    = $role.Id
                DisplayName           = $role.DisplayName
                Description           = $role.Description
                IsBuiltIn             = $role.IsBuiltIn
                IsEnabled             = $role.IsEnabled

                # Privilege classification
                IsHighPrivilege       = $isHighPrivilege
                IsCritical            = $isCritical

                # Assignment counts
                ActiveAssignmentCount = $assignmentCount
                EligibleAssignmentCount = $eligibleCount
                TotalAssignmentCount  = $assignmentCount + $eligibleCount

                # Assigned principals
                AssignedPrincipals    = $assignedPrincipals

                # Role permissions (simplified)
                PermissionCount       = if ($role.RolePermissions) { $role.RolePermissions.Count } else { 0 }
            }
        }

        # Cache results
        Set-ADScoutCache -Key $cacheKey -Value $normalizedRoles

        Write-Verbose "Collected $($normalizedRoles.Count) Entra ID role definitions"

        return $normalizedRoles
    }
    catch {
        Write-Error "Failed to collect Entra ID role data: $_"
        return @()
    }
}

function Get-ADScoutEntraRoleAssignments {
    <#
    .SYNOPSIS
        Gets a flattened view of all role assignments for analysis.

    .DESCRIPTION
        Returns a flat list of all active and eligible role assignments,
        useful for finding users with multiple privileged roles.
    #>
    [CmdletBinding()]
    param()

    # Check Graph connection
    if (-not (Test-ADScoutGraphConnection)) {
        Write-Verbose "Microsoft Graph not connected."
        return @()
    }

    try {
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

        $results = @()

        # Get role definitions for lookup
        $roles = Get-MgRoleManagementDirectoryRoleDefinition -All
        $roleLookup = @{}
        foreach ($r in $roles) { $roleLookup[$r.Id] = $r.DisplayName }

        # Active assignments
        $active = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop
        foreach ($a in $active) {
            $results += [PSCustomObject]@{
                PrincipalId    = $a.PrincipalId
                PrincipalName  = $a.Principal.AdditionalProperties['displayName']
                PrincipalType  = ($a.Principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '')
                RoleId         = $a.RoleDefinitionId
                RoleName       = $roleLookup[$a.RoleDefinitionId]
                AssignmentType = 'Active'
                Scope          = $a.DirectoryScopeId
            }
        }

        # Eligible assignments (PIM)
        try {
            $eligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue
            foreach ($e in $eligible) {
                $results += [PSCustomObject]@{
                    PrincipalId    = $e.PrincipalId
                    PrincipalName  = $null  # Need separate lookup
                    PrincipalType  = 'Unknown'
                    RoleId         = $e.RoleDefinitionId
                    RoleName       = $roleLookup[$e.RoleDefinitionId]
                    AssignmentType = 'Eligible'
                    Scope          = $e.DirectoryScopeId
                }
            }
        }
        catch {
            Write-Verbose "PIM eligibility not available"
        }

        return $results
    }
    catch {
        Write-Error "Failed to get role assignments: $_"
        return @()
    }
}

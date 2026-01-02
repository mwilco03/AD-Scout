<#
.SYNOPSIS
    Detects excessive Global Administrator assignments in Entra ID.

.DESCRIPTION
    Global Administrator is the most privileged role in Entra ID. Having too many
    Global Admins increases attack surface and makes it harder to maintain least
    privilege. Microsoft recommends no more than 5 Global Administrators.

.NOTES
    Rule ID    : EID-GlobalAdminCount
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-GlobalAdminCount'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Excessive Global Administrators'
    Description = 'Identifies when there are too many Global Administrator role assignments. Microsoft recommends limiting Global Admins to 5 or fewer.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'EntraRoles'

    References  = @(
        @{ Title = 'Azure AD built-in roles'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference' }
        @{ Title = 'Securing privileged access'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1078.004')          # Cloud Accounts
    }

    Scoring = @{
        Type    = 'TriggerOnThreshold'
        Threshold = 5
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        # Check if Entra ID data is available
        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-GlobalAdminCount."
            return @()
        }

        $findings = @()

        try {
            # Get role data
            $roles = Get-ADScoutEntraRoleData

            # Find Global Administrator role
            $globalAdminRole = $roles | Where-Object { $_.DisplayName -eq 'Global Administrator' }

            if ($globalAdminRole -and $globalAdminRole.ActiveAssignmentCount -gt 5) {
                $findings += [PSCustomObject]@{
                    RoleName          = 'Global Administrator'
                    ActiveCount       = $globalAdminRole.ActiveAssignmentCount
                    EligibleCount     = $globalAdminRole.EligibleAssignmentCount
                    TotalCount        = $globalAdminRole.TotalAssignmentCount
                    RecommendedMax    = 5
                    Excess            = $globalAdminRole.ActiveAssignmentCount - 5
                    AssignedUsers     = ($globalAdminRole.AssignedPrincipals | Where-Object { $_.PrincipalType -eq 'user' }).DisplayName -join '; '
                    AssignedGroups    = ($globalAdminRole.AssignedPrincipals | Where-Object { $_.PrincipalType -eq 'group' }).DisplayName -join '; '
                    RiskLevel         = if ($globalAdminRole.ActiveAssignmentCount -gt 10) { 'Critical' } else { 'High' }
                    Recommendation    = 'Review Global Admin assignments and migrate to least-privilege roles where possible'
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-GlobalAdminCount: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reduce Global Administrator assignments to 5 or fewer by using least-privilege roles.'
        Impact      = 'Medium - Requires role reassignment planning.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Reduce Global Administrator Assignments
#############################################################################
#
# Current Global Admin count: $($Finding.Findings[0].ActiveCount)
# Recommended maximum: 5
#
# Assigned users: $($Finding.Findings[0].AssignedUsers)
#
#############################################################################
# Step 1: Review Current Assignments
#############################################################################

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# List all Global Administrators
`$globalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"
`$assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '`$(`$globalAdminRole.Id)'"

`$assignments | ForEach-Object {
    `$principal = Get-MgDirectoryObject -DirectoryObjectId `$_.PrincipalId
    [PSCustomObject]@{
        Principal = `$principal.AdditionalProperties['displayName']
        Type = (`$principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '')
        AssignedDate = `$_.CreatedDateTime
    }
} | Format-Table

#############################################################################
# Step 2: Identify Least-Privilege Alternatives
#############################################################################

# Common Global Admin tasks and their least-privilege alternatives:
#
# | Task                          | Alternative Role                    |
# |-------------------------------|-------------------------------------|
# | Manage users                  | User Administrator                  |
# | Manage groups                 | Groups Administrator                |
# | Reset passwords               | Password Administrator              |
# | Manage applications           | Application Administrator           |
# | Manage Conditional Access     | Conditional Access Administrator    |
# | Manage Exchange               | Exchange Administrator              |
# | Manage SharePoint             | SharePoint Administrator            |
# | Manage Intune                 | Intune Administrator                |
# | Manage Azure AD settings      | Privileged Role Administrator       |

#############################################################################
# Step 3: Remove Unnecessary Global Admin Assignments
#############################################################################

# Remove specific user from Global Administrator
# `$userToRemove = Get-MgUser -Filter "userPrincipalName eq 'user@domain.com'"
# `$assignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '`$(`$userToRemove.Id)' and roleDefinitionId eq '`$(`$globalAdminRole.Id)'"
# Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId `$assignment.Id

#############################################################################
# Step 4: Consider Using PIM for Just-In-Time Access
#############################################################################

# With Azure AD P2, use Privileged Identity Management:
# - Make Global Admin assignments "eligible" instead of "active"
# - Require justification and approval for activation
# - Set maximum activation duration (e.g., 8 hours)
# - Enable MFA on activation

# Example: Convert active assignment to eligible
# New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -Action "adminAssign" ``
#     -RoleDefinitionId `$globalAdminRole.Id ``
#     -PrincipalId `$userId ``
#     -DirectoryScopeId "/" ``
#     -ScheduleInfo @{ Expiration = @{ Type = "noExpiration" } }

#############################################################################
# Step 5: Maintain Break-Glass Accounts
#############################################################################

# Keep 2 cloud-only break-glass accounts as Global Admin:
# - Use strong, unique passwords stored securely
# - Exclude from Conditional Access policies
# - Monitor sign-in activity
# - Never use for daily operations

Write-Host "Review complete. Plan role migrations before removing Global Admin access." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

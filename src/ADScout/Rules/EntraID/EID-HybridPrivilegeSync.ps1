<#
.SYNOPSIS
    Detects users with privileged access in both on-premises AD and Entra ID.

.DESCRIPTION
    Users synchronized from on-premises AD who also have Entra ID directory
    roles create a bridge between environments. Compromise of either side
    can lead to full compromise. This rule identifies these high-risk
    hybrid privileged accounts.

.NOTES
    Rule ID    : EID-HybridPrivilegeSync
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-HybridPrivilegeSync'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Hybrid Users with Cloud Privileges'
    Description = 'Identifies synced users from on-premises AD who also have privileged Entra ID directory roles, creating a bridge between environments.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'EntraUsers'

    References  = @(
        @{ Title = 'Securing privileged access'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning' }
        @{ Title = 'Protecting Microsoft 365 from on-premises attacks'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/protect-m365-from-on-premises-attacks' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1078.002', 'T1078.004')  # Domain Accounts, Cloud Accounts
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-HybridPrivilegeSync."
            return @()
        }

        $findings = @()

        try {
            $users = Get-ADScoutEntraUserData -IncludeMFAStatus

            # Find synced users with Entra ID roles
            $hybridPrivileged = $users | Where-Object {
                $_.IsHybrid -eq $true -and
                $_.IsPrivileged -eq $true -and
                $_.AccountEnabled -eq $true
            }

            foreach ($user in $hybridPrivileged) {
                $riskLevel = if ($user.IsGlobalAdmin) { 'Critical' }
                             elseif ($user.DirectoryRoles.Count -gt 2) { 'High' }
                             else { 'Medium' }

                # Additional risk if no MFA
                if ($user.IsMfaRegistered -eq $false) {
                    $riskLevel = 'Critical'
                }

                $findings += [PSCustomObject]@{
                    UserPrincipalName         = $user.UserPrincipalName
                    DisplayName               = $user.DisplayName
                    OnPremisesSamAccountName  = $user.OnPremisesSamAccountName
                    OnPremisesDN              = $user.OnPremisesDistinguishedName
                    IsHybrid                  = $user.IsHybrid
                    EntraRoles                = $user.DirectoryRoles -join '; '
                    EntraRoleCount            = $user.DirectoryRoles.Count
                    IsGlobalAdmin             = $user.IsGlobalAdmin
                    IsMfaRegistered           = $user.IsMfaRegistered
                    LastSignInDateTime        = $user.LastSignInDateTime
                    RiskLevel                 = $riskLevel
                    RiskExplanation           = @(
                        if ($user.IsGlobalAdmin) { 'Global Admin from on-prem is highest risk' }
                        if ($user.IsMfaRegistered -eq $false) { 'No MFA registered' }
                        'On-prem compromise could lead to cloud takeover'
                    ) -join '; '
                    Recommendation            = 'Consider using cloud-only accounts for Entra ID admin roles'
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-HybridPrivilegeSync: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Use cloud-only accounts for Entra ID privileged roles, separate from on-premises identities.'
        Impact      = 'Medium - Requires creating new cloud-only admin accounts.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Separate Hybrid and Cloud Privileged Accounts
#############################################################################
#
# Hybrid accounts with cloud privileges:
$($Finding.Findings | ForEach-Object { "# - $($_.UserPrincipalName) ($($_.EntraRoles))" } | Out-String)
#
# RISK: If on-premises AD is compromised, attackers can:
# - Reset passwords of synced admin accounts
# - Use those credentials to access Entra ID
# - Escalate to Global Administrator
#
#############################################################################
# Step 1: Create Cloud-Only Admin Accounts
#############################################################################

Connect-MgGraph -Scopes "User.ReadWrite.All"

# Create a new cloud-only admin account
`$adminPassword = ConvertTo-SecureString -String "$(New-Guid)" -AsPlainText -Force

`$newAdmin = @{
    displayName = "Cloud Admin - John Smith"
    userPrincipalName = "admin-jsmith@domain.onmicrosoft.com"  # Use .onmicrosoft.com
    mailNickname = "admin-jsmith"
    accountEnabled = `$true
    passwordProfile = @{
        password = "ComplexPassword123!"  # Will be reset on first login
        forceChangePasswordNextSignIn = `$true
    }
}

# New-MgUser -BodyParameter `$newAdmin

#############################################################################
# Step 2: Assign Roles to Cloud-Only Accounts
#############################################################################

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get the role to assign
`$role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"

# Assign to cloud-only account
`$assignment = @{
    principalId = "cloud-admin-user-id"
    roleDefinitionId = `$role.Id
    directoryScopeId = "/"
}

# New-MgRoleManagementDirectoryRoleAssignment -BodyParameter `$assignment

#############################################################################
# Step 3: Remove Roles from Synced Accounts
#############################################################################

# After cloud-only admins are operational, remove roles from synced accounts

# Get synced user's current assignments
`$syncedUserId = "synced-user-object-id"
`$assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '`$syncedUserId'"

foreach (`$assignment in `$assignments) {
    Write-Host "Would remove role: `$(Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId `$assignment.RoleDefinitionId | Select -Expand DisplayName)"
    # Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId `$assignment.Id
}

#############################################################################
# Step 4: Implement Privileged Access Strategy
#############################################################################

# Best practices for hybrid environments:

# 1. Cloud-only accounts for Entra ID roles
#    - admin-username@domain.onmicrosoft.com
#    - Never synced from on-premises
#    - Separate from daily user account

# 2. Break-glass accounts (2 minimum)
#    - Cloud-only, excluded from CA policies
#    - Strong passwords in physical safe
#    - Monitored for any usage

# 3. Use PIM for just-in-time access
#    - No standing admin access
#    - Time-limited activations
#    - Require approval for critical roles

# 4. Protect on-premises to protect cloud
#    - If you must use synced admins, protect on-prem AD
#    - Tier 0 security for AAD Connect
#    - Monitor for on-prem compromise indicators

#############################################################################
# Step 5: Block On-Premises Sync for Admin Accounts
#############################################################################

# In Azure AD Connect, exclude admin accounts from sync:
# 1. Open Azure AD Connect wizard
# 2. Select "Customize synchronization options"
# 3. Add filter to exclude admin OUs or accounts

# Or use cloud-only domain (@domain.onmicrosoft.com) for all admins

Write-Host "Create cloud-only accounts before removing roles from synced accounts." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

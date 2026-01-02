<#
.SYNOPSIS
    Detects privileged users without MFA registration in Entra ID.

.DESCRIPTION
    Users with privileged directory roles should always have MFA enabled.
    This rule identifies privileged users who have not registered for
    multi-factor authentication, creating a significant security risk.

.NOTES
    Rule ID    : EID-PrivilegedNoMFA
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-PrivilegedNoMFA'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Privileged Users Without MFA'
    Description = 'Identifies users with privileged Entra ID roles who have not registered for multi-factor authentication.'
    Severity    = 'Critical'
    Weight      = 100
    DataSource  = 'EntraUsers'

    References  = @(
        @{ Title = 'Securing privileged access for hybrid and cloud deployments'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning' }
        @{ Title = 'How to require MFA for admins'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0006')  # Initial Access, Credential Access
        Techniques = @('T1078.004', 'T1110')  # Cloud Accounts, Brute Force
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-PrivilegedNoMFA."
            return @()
        }

        $findings = @()

        try {
            # Get users with MFA status
            $users = Get-ADScoutEntraUserData -IncludeMFAStatus

            # Filter to privileged users without MFA
            $atRiskUsers = $users | Where-Object {
                $_.IsPrivileged -eq $true -and
                $_.AccountEnabled -eq $true -and
                $_.IsMfaRegistered -eq $false
            }

            foreach ($user in $atRiskUsers) {
                $riskLevel = if ($user.IsGlobalAdmin) { 'Critical' } else { 'High' }

                $findings += [PSCustomObject]@{
                    UserPrincipalName    = $user.UserPrincipalName
                    DisplayName          = $user.DisplayName
                    DirectoryRoles       = $user.DirectoryRoles -join '; '
                    IsGlobalAdmin        = $user.IsGlobalAdmin
                    IsMfaRegistered      = $user.IsMfaRegistered
                    IsMfaCapable         = $user.IsMfaCapable
                    DefaultMfaMethod     = $user.DefaultMfaMethod
                    AccountEnabled       = $user.AccountEnabled
                    LastSignInDateTime   = $user.LastSignInDateTime
                    IsHybrid             = $user.IsHybrid
                    RiskLevel            = $riskLevel
                    Recommendation       = 'Require MFA registration immediately'
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-PrivilegedNoMFA: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Ensure all privileged users register for and use MFA.'
        Impact      = 'Low - Users must register for MFA.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Require MFA for Privileged Users
#############################################################################
#
# Found privileged users without MFA:
$($Finding.Findings | ForEach-Object { "# - $($_.UserPrincipalName) ($($_.DirectoryRoles))" } | Out-String)
#
#############################################################################
# Step 1: Create Conditional Access Policy for Admin MFA
#############################################################################

Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Create policy requiring MFA for all admin roles
`$policy = @{
    displayName = "Require MFA for administrators"
    state = "enabledForReportingButNotEnforced"  # Start in report-only mode
    conditions = @{
        users = @{
            includeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
                "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"  # SharePoint Administrator
                "29232cdf-9323-42fd-ade2-1d097af3e4de"  # Exchange Administrator
                "fdd7a751-b60b-444a-984c-02652fe8fa1c"  # Privileged Role Administrator
                # Add other roles as needed
            )
        }
        applications = @{
            includeApplications = @("All")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter `$policy

#############################################################################
# Step 2: Enable Security Defaults (if no Conditional Access)
#############################################################################

# If not using Conditional Access, enable Security Defaults:
# Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
# Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true

#############################################################################
# Step 3: Monitor MFA Registration Status
#############################################################################

# Get MFA registration report
Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object {
    `$_.IsAdmin -eq `$true -and `$_.IsMfaRegistered -eq `$false
} | Select-Object UserPrincipalName, UserDisplayName, IsMfaRegistered, DefaultMfaMethod

#############################################################################
# Step 4: Enforce Registration Deadline
#############################################################################

# Send notification to unregistered users:
# - Set a deadline for MFA registration
# - Block sign-in after deadline via Conditional Access
# - Provide self-service registration instructions

Write-Host "Policy created in report-only mode. Monitor and then enable." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

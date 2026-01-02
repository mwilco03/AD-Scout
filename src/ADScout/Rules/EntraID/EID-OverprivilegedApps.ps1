<#
.SYNOPSIS
    Detects applications with excessive permissions in Entra ID.

.DESCRIPTION
    Applications granted high-privilege API permissions (like Directory.ReadWrite.All)
    can be abused if compromised. This rule identifies apps with dangerous permission
    combinations that should be reviewed.

.NOTES
    Rule ID    : EID-OverprivilegedApps
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-OverprivilegedApps'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Overprivileged Applications'
    Description = 'Identifies applications granted high-privilege Microsoft Graph permissions that could be abused if compromised.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'EntraApps'

    References  = @(
        @{ Title = 'Microsoft Graph permissions reference'; Url = 'https://learn.microsoft.com/en-us/graph/permissions-reference' }
        @{ Title = 'Least privilege for apps'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/secure-least-privileged-access' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1098.001', 'T1078.004')  # Additional Cloud Credentials, Cloud Accounts
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-OverprivilegedApps."
            return @()
        }

        $findings = @()

        # Define high-risk permissions
        $criticalPermissions = @(
            'RoleManagement.ReadWrite.Directory'
            'AppRoleAssignment.ReadWrite.All'
            'Directory.ReadWrite.All'
            'Application.ReadWrite.All'
            'Group.ReadWrite.All'
            'User.ReadWrite.All'
            'Mail.ReadWrite'
            'Mail.Send'
            'Files.ReadWrite.All'
            'Sites.FullControl.All'
        )

        try {
            $apps = Get-ADScoutEntraAppData

            foreach ($app in $apps) {
                # Skip first-party Microsoft apps
                if ($app.IsFirstParty) { continue }

                # Skip disabled apps
                if (-not $app.Enabled) { continue }

                # Check for high-privilege grants
                if ($app.HasHighPrivilegeGrants -or $app.OAuthGrantCount -gt 0) {
                    $grantedScopes = @()
                    $criticalGrants = @()

                    if ($app.OAuthGrants) {
                        foreach ($grant in $app.OAuthGrants) {
                            $scopes = $grant.Scope -split ' '
                            $grantedScopes += $scopes

                            foreach ($scope in $scopes) {
                                if ($scope -in $criticalPermissions) {
                                    $criticalGrants += $scope
                                }
                            }
                        }
                    }

                    if ($criticalGrants.Count -gt 0) {
                        $riskLevel = if ($criticalGrants.Count -ge 3) { 'Critical' }
                                     elseif ($criticalGrants -match 'RoleManagement|AppRoleAssignment') { 'Critical' }
                                     else { 'High' }

                        $findings += [PSCustomObject]@{
                            AppId                  = $app.AppId
                            DisplayName            = $app.DisplayName
                            ServicePrincipalType   = $app.ServicePrincipalType
                            Enabled                = $app.Enabled
                            TotalGrantCount        = $app.OAuthGrantCount
                            CriticalPermissions    = $criticalGrants -join '; '
                            CriticalPermissionCount = $criticalGrants.Count
                            AllScopes              = ($grantedScopes | Select-Object -Unique) -join '; '
                            HasAppRegistration     = $app.HasAppRegistration
                            PublisherDomain        = $app.PublisherDomain
                            CreatedDateTime        = $app.CreatedDateTime
                            RiskLevel              = $riskLevel
                            Recommendation         = 'Review and reduce permissions to least privilege'
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-OverprivilegedApps: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and reduce application permissions to minimum required.'
        Impact      = 'Medium - May break functionality if permissions are needed.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Review and Reduce Overprivileged Applications
#############################################################################
#
# Applications with excessive permissions:
$($Finding.Findings | ForEach-Object { "# - $($_.DisplayName): $($_.CriticalPermissions)" } | Out-String)
#
#############################################################################
# Step 1: Audit Current Permissions
#############################################################################

Connect-MgGraph -Scopes "Application.Read.All"

# List all OAuth2 permission grants
`$grants = Get-MgOauth2PermissionGrant -All

# Build detailed report
`$report = foreach (`$grant in `$grants) {
    `$sp = Get-MgServicePrincipal -ServicePrincipalId `$grant.ClientId -ErrorAction SilentlyContinue
    `$resource = Get-MgServicePrincipal -ServicePrincipalId `$grant.ResourceId -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        AppName = `$sp.DisplayName
        AppId = `$sp.AppId
        Resource = `$resource.DisplayName
        Scopes = `$grant.Scope
        ConsentType = `$grant.ConsentType
        PrincipalId = `$grant.PrincipalId
    }
}

`$report | Where-Object { `$_.Scopes -match 'ReadWrite|FullControl|RoleManagement' } |
    Format-Table -AutoSize

#############################################################################
# Step 2: Identify Least Privilege Alternatives
#############################################################################

# Common permission downgrades:
#
# | Current Permission           | Consider Instead              |
# |------------------------------|-------------------------------|
# | User.ReadWrite.All           | User.Read.All (if read-only)  |
# | Directory.ReadWrite.All      | Specific object permissions   |
# | Mail.ReadWrite               | Mail.Read (if read-only)      |
# | Files.ReadWrite.All          | Files.Read.All                |
# | Group.ReadWrite.All          | GroupMember.Read.All          |

#############################################################################
# Step 3: Remove Excessive Permissions
#############################################################################

Connect-MgGraph -Scopes "DelegatedPermissionGrant.ReadWrite.All"

# Remove specific OAuth2 grant
# `$grantToRemove = Get-MgOauth2PermissionGrant -Filter "clientId eq 'service-principal-id'"
# Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId `$grantToRemove.Id

# Update grant with reduced scopes
`$grantId = "grant-id-here"
`$reducedScopes = "User.Read Group.Read.All"  # Only what's needed
Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId `$grantId -Scope `$reducedScopes

#############################################################################
# Step 4: Implement App Governance (if available)
#############################################################################

# Microsoft Defender for Cloud Apps - App Governance add-on
# - Automated detection of overprivileged apps
# - Policy-based remediation
# - Continuous monitoring

#############################################################################
# Step 5: Ongoing Monitoring
#############################################################################

# Create alert for new high-privilege grants
# Monitor Azure AD audit logs for:
# - "Add OAuth2PermissionGrant"
# - "Consent to application"

# Regular review cadence:
# - Monthly: High-privilege apps
# - Quarterly: All third-party apps
# - Immediately: New admin consent requests

Write-Host "Review each app and reduce to minimum required permissions." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

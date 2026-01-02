<#
.SYNOPSIS
    Detects when Conditional Access policies are missing or insufficient.

.DESCRIPTION
    Conditional Access is the primary security control plane for Entra ID.
    This rule checks for essential policies that should be in place to
    protect the tenant.

.NOTES
    Rule ID    : EID-NoConditionalAccess
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-NoConditionalAccess'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Missing Essential Conditional Access Policies'
    Description = 'Identifies gaps in Conditional Access coverage for critical security controls like MFA, device compliance, and location-based access.'
    Severity    = 'High'
    Weight      = 70
    DataSource  = 'EntraPolicies'

    References  = @(
        @{ Title = 'Conditional Access overview'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview' }
        @{ Title = 'Common CA policies'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0005')  # Initial Access, Defense Evasion
        Techniques = @('T1078.004', 'T1556')  # Cloud Accounts, Modify Authentication Process
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-NoConditionalAccess."
            return @()
        }

        $findings = @()

        try {
            $policyData = Get-ADScoutEntraPolicyData

            # Essential policy checks
            $essentialPolicies = @(
                @{
                    Name = 'MFA for Administrators'
                    Check = { ($policyData.ConditionalAccessPolicies | Where-Object {
                        $_.State -eq 'enabled' -and
                        $_.RequiresMfa -eq $true -and
                        $_.IncludedUsers -contains 'All'
                    }).Count -gt 0 }
                    Recommendation = 'Create policy requiring MFA for all administrator roles'
                }
                @{
                    Name = 'MFA for All Users'
                    Check = { ($policyData.ConditionalAccessPolicies | Where-Object {
                        $_.State -eq 'enabled' -and
                        $_.RequiresMfa -eq $true -and
                        $_.AppliesToAllUsers -eq $true -and
                        $_.AppliesToAllApps -eq $true
                    }).Count -gt 0 }
                    Recommendation = 'Create policy requiring MFA for all users on all apps'
                }
                @{
                    Name = 'Block Legacy Authentication'
                    Check = { ($policyData.ConditionalAccessPolicies | Where-Object {
                        $_.State -eq 'enabled' -and
                        $_.BlocksLegacyAuth -eq $true
                    }).Count -gt 0 }
                    Recommendation = 'Create policy blocking legacy authentication protocols'
                }
                @{
                    Name = 'Require Compliant Device for Sensitive Apps'
                    Check = { ($policyData.ConditionalAccessPolicies | Where-Object {
                        $_.State -eq 'enabled' -and
                        $_.GrantControls -contains 'compliantDevice'
                    }).Count -gt 0 }
                    Recommendation = 'Create policy requiring compliant devices for sensitive applications'
                }
                @{
                    Name = 'Block High-Risk Sign-Ins'
                    Check = { ($policyData.ConditionalAccessPolicies | Where-Object {
                        $_.State -eq 'enabled' -and
                        ($_.SignInRiskLevels -contains 'high' -or $_.UserRiskLevels -contains 'high') -and
                        $_.GrantControls -contains 'block'
                    }).Count -gt 0 }
                    Recommendation = 'Create policy blocking or requiring MFA for high-risk sign-ins (requires P2)'
                }
            )

            # Check if Security Defaults is enabled (provides basic protection)
            $hasSecurityDefaults = $policyData.SecurityDefaults.IsEnabled -eq $true
            $totalEnabledPolicies = ($policyData.ConditionalAccessPolicies | Where-Object { $_.State -eq 'enabled' }).Count

            # If no CA policies and no Security Defaults, that's critical
            if ($totalEnabledPolicies -eq 0 -and -not $hasSecurityDefaults) {
                $findings += [PSCustomObject]@{
                    MissingPolicy         = 'Any Conditional Access'
                    SecurityDefaultsEnabled = $hasSecurityDefaults
                    EnabledPolicyCount    = $totalEnabledPolicies
                    RiskLevel             = 'Critical'
                    Recommendation        = 'Enable Security Defaults or implement Conditional Access policies immediately'
                }
            }
            else {
                # Check each essential policy
                foreach ($policy in $essentialPolicies) {
                    $exists = & $policy.Check

                    if (-not $exists -and -not $hasSecurityDefaults) {
                        $findings += [PSCustomObject]@{
                            MissingPolicy         = $policy.Name
                            SecurityDefaultsEnabled = $hasSecurityDefaults
                            EnabledPolicyCount    = $totalEnabledPolicies
                            RiskLevel             = 'High'
                            Recommendation        = $policy.Recommendation
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-NoConditionalAccess: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Implement essential Conditional Access policies or enable Security Defaults.'
        Impact      = 'Medium - Users may need to satisfy additional authentication requirements.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Implement Essential Conditional Access Policies
#############################################################################
#
# Missing policies:
$($Finding.Findings | ForEach-Object { "# - $($_.MissingPolicy)" } | Out-String)
#
#############################################################################
# Quick Start: Enable Security Defaults (if no CA policies)
#############################################################################

Connect-MgGraph -Scopes "Policy.ReadWrite.SecurityDefaults"

# Security Defaults provides:
# - MFA for all users
# - Block legacy authentication
# - Protect privileged actions

# Enable Security Defaults:
# Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true

# Note: Cannot use Security Defaults with Conditional Access

#############################################################################
# Essential CA Policy 1: MFA for Administrators
#############################################################################

Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

`$adminMfaPolicy = @{
    displayName = "CA001: Require MFA for administrators"
    state = "enabled"
    conditions = @{
        users = @{
            includeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
                "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"  # SharePoint Administrator
                "29232cdf-9323-42fd-ade2-1d097af3e4de"  # Exchange Administrator
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"  # Conditional Access Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Privileged Role Administrator
                "b0f54661-2d74-4c50-afa3-1ec803f12efe"  # Billing Administrator
                "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"  # Application Administrator
                "c4e39bd9-1100-46d3-8c65-fb160da0071f"  # Authentication Administrator
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

New-MgIdentityConditionalAccessPolicy -BodyParameter `$adminMfaPolicy

#############################################################################
# Essential CA Policy 2: Block Legacy Authentication
#############################################################################

`$blockLegacyPolicy = @{
    displayName = "CA002: Block legacy authentication"
    state = "enabled"
    conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("exchangeActiveSync", "other")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter `$blockLegacyPolicy

#############################################################################
# Essential CA Policy 3: MFA for All Users
#############################################################################

`$allUserMfaPolicy = @{
    displayName = "CA003: Require MFA for all users"
    state = "enabledForReportingButNotEnforced"  # Start in report-only
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @()  # Add break-glass accounts
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter `$allUserMfaPolicy

#############################################################################
# Essential CA Policy 4: Require Compliant Device for Office 365
#############################################################################

`$compliantDevicePolicy = @{
    displayName = "CA004: Require compliant device for Office 365"
    state = "enabledForReportingButNotEnforced"
    conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("Office365")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("compliantDevice", "domainJoinedDevice")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter `$compliantDevicePolicy

Write-Host "Policies created. Review report-only policies before enforcing." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

<#
.SYNOPSIS
    Detects if legacy authentication is not blocked in Entra ID.

.DESCRIPTION
    Legacy authentication protocols (POP, IMAP, SMTP AUTH, etc.) don't support
    MFA and are frequently exploited in password spray attacks. Blocking legacy
    auth is a critical security control.

.NOTES
    Rule ID    : EID-LegacyAuthEnabled
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-LegacyAuthEnabled'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Legacy Authentication Not Blocked'
    Description = 'Checks if Conditional Access policies block legacy authentication protocols that cannot support MFA.'
    Severity    = 'High'
    Weight      = 60
    DataSource  = 'EntraPolicies'

    References  = @(
        @{ Title = 'Block legacy authentication'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication' }
        @{ Title = 'What is legacy authentication'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-conditions#legacy-authentication' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0006')  # Initial Access, Credential Access
        Techniques = @('T1110.003', 'T1078.004')  # Password Spraying, Cloud Accounts
    }

    Scoring = @{
        Type    = 'TriggerOnPresence'
        Points  = 60
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-LegacyAuthEnabled."
            return @()
        }

        $findings = @()

        try {
            $policyData = Get-ADScoutEntraPolicyData

            # Check if Security Defaults are enabled (blocks legacy auth)
            $securityDefaultsEnabled = $policyData.SecurityDefaults.IsEnabled -eq $true

            # Check for CA policy that blocks legacy auth
            $legacyAuthBlocked = $false
            $blockingPolicies = @()

            foreach ($policy in $policyData.ConditionalAccessPolicies) {
                if ($policy.State -eq 'enabled' -and $policy.BlocksLegacyAuth -eq $true) {
                    $legacyAuthBlocked = $true
                    $blockingPolicies += $policy.DisplayName
                }
            }

            if (-not $securityDefaultsEnabled -and -not $legacyAuthBlocked) {
                # Check for any sign-ins using legacy auth
                $legacySignIns = @()
                try {
                    $signIns = Get-ADScoutEntraSignInLogs -Days 7
                    $legacySignIns = $signIns | Where-Object {
                        $_.ClientAppUsed -in @(
                            'Exchange ActiveSync'
                            'Other clients'
                            'IMAP'
                            'POP'
                            'SMTP'
                            'MAPI'
                            'Authenticated SMTP'
                        )
                    }
                }
                catch {
                    Write-Verbose "Could not check sign-in logs"
                }

                $findings += [PSCustomObject]@{
                    Issue                    = 'Legacy authentication is not blocked'
                    SecurityDefaultsEnabled  = $securityDefaultsEnabled
                    LegacyAuthBlockedByCA    = $legacyAuthBlocked
                    BlockingPolicies         = $blockingPolicies -join '; '
                    RecentLegacySignIns      = $legacySignIns.Count
                    LegacyProtocolsUsed      = ($legacySignIns | Group-Object ClientAppUsed | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; '
                    RiskLevel                = 'High'
                    Recommendation           = 'Create Conditional Access policy to block legacy authentication'
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-LegacyAuthEnabled: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Block legacy authentication using Conditional Access or Security Defaults.'
        Impact      = 'Medium - May break older apps using legacy protocols.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Block Legacy Authentication
#############################################################################
#
# Legacy auth protocols (POP, IMAP, SMTP) don't support MFA and are
# commonly exploited in password spray attacks.
#
#############################################################################
# Option 1: Enable Security Defaults (simplest)
#############################################################################

Connect-MgGraph -Scopes "Policy.ReadWrite.SecurityDefaults"

# Enable Security Defaults (blocks legacy auth automatically)
Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true

# Note: Security Defaults cannot be used with Conditional Access

#############################################################################
# Option 2: Create Conditional Access Policy (recommended for enterprises)
#############################################################################

Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

`$policy = @{
    displayName = "Block legacy authentication"
    state = "enabledForReportingButNotEnforced"  # Start in report-only
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @()  # Add break-glass accounts if needed
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @(
            "exchangeActiveSync"
            "other"
        )
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter `$policy

#############################################################################
# Step 3: Monitor Legacy Auth Usage Before Blocking
#############################################################################

# Check sign-in logs for legacy auth usage
Get-MgAuditLogSignIn -Filter "clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Other clients'" -Top 100 |
    Select-Object UserPrincipalName, ClientAppUsed, AppDisplayName, CreatedDateTime |
    Group-Object UserPrincipalName |
    Select-Object Name, Count |
    Sort-Object Count -Descending

# Users still using legacy auth need to be migrated to modern auth apps

#############################################################################
# Step 4: Migrate Users to Modern Authentication
#############################################################################

# Common migration paths:
# - Outlook 2013+ with Modern Auth enabled
# - Outlook Mobile app instead of native mail
# - Microsoft 365 Apps instead of Office 2010
# - PowerShell with EXO v2 module (Connect-ExchangeOnline)

# Disable IMAP/POP per mailbox if not needed:
# Set-CASMailbox -Identity user@domain.com -PopEnabled `$false -ImapEnabled `$false

Write-Host "Start with report-only mode, monitor, then enforce." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}

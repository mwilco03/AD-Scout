<#
.SYNOPSIS
    Detects when Fine-Grained Password Policies are not used for privileged accounts.

.DESCRIPTION
    Fine-Grained Password Policies allow stronger password requirements for privileged
    accounts. Without them, all accounts use the same (often weaker) domain policy.

.NOTES
    Rule ID    : AUTH-FGPPNotUsed
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-FGPPNotUsed'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'Fine-Grained Password Policies Not Used'
    Description = 'Identifies when Fine-Grained Password Policies are not configured for privileged accounts, meaning they use potentially weaker default policy.'
    Severity    = 'Medium'
    Weight      = 30
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'Fine-Grained Password Policies'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt' }
        @{ Title = 'FGPP Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy' }
        @{ Title = 'Password Policy Tiering'; Url = 'https://adsecurity.org/?p=4367' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1110')   # Brute Force
    }

    CIS   = @('1.1.1', '1.1.2')
    STIG  = @('V-63337')
    ANSSI = @('R68')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get Fine-Grained Password Policies
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue

            if (-not $fgpps -or $fgpps.Count -eq 0) {
                # No FGPPs configured at all
                $findings += [PSCustomObject]@{
                    Issue               = 'No Fine-Grained Password Policies configured'
                    AffectedAccounts    = 'All privileged accounts use default domain policy'
                    CurrentState        = 'Not configured'
                    DefaultPolicyMinLen = $Data.PasswordPolicy.MinPasswordLength
                    Recommendation      = 'Create FGPP with stricter requirements for privileged accounts'
                    RiskLevel           = 'Medium'
                    Impact              = 'Privileged accounts may have same password requirements as regular users'
                }
                return $findings
            }

            # Check if privileged accounts have FGPP applied
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
            $coveredGroups = @()
            $uncoveredGroups = @()

            foreach ($groupName in $privilegedGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                    if (-not $group) { continue }

                    # Check if any FGPP applies to this group
                    $appliedFGPP = $fgpps | Where-Object {
                        $_.AppliesTo -contains $group.DistinguishedName
                    }

                    if ($appliedFGPP) {
                        $coveredGroups += @{
                            Group = $groupName
                            Policy = $appliedFGPP.Name
                            MinLength = $appliedFGPP.MinPasswordLength
                        }
                    } else {
                        $uncoveredGroups += $groupName
                    }
                } catch {
                    # Can't check this group
                }
            }

            if ($uncoveredGroups.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    Issue               = 'Privileged groups without Fine-Grained Password Policy'
                    AffectedAccounts    = ($uncoveredGroups -join ', ')
                    CurrentState        = 'Using default domain policy'
                    DefaultPolicyMinLen = $Data.PasswordPolicy.MinPasswordLength
                    Recommendation      = 'Create FGPP with stricter requirements for these groups'
                    RiskLevel           = 'Medium'
                    Impact              = 'Privileged accounts have same password requirements as regular users'
                }
            }

            # Check if existing FGPPs are strong enough
            foreach ($fgpp in $fgpps) {
                $issues = @()

                if ($fgpp.MinPasswordLength -lt 15) {
                    $issues += "Minimum length $($fgpp.MinPasswordLength) (should be 15+)"
                }
                if ($fgpp.MaxPasswordAge -gt [TimeSpan]::FromDays(60)) {
                    $issues += "Max age $($fgpp.MaxPasswordAge.Days) days (should be 60 or less)"
                }
                if ($fgpp.PasswordHistoryCount -lt 24) {
                    $issues += "History $($fgpp.PasswordHistoryCount) (should be 24+)"
                }
                if (-not $fgpp.ComplexityEnabled) {
                    $issues += "Complexity not enabled"
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Issue               = "FGPP '$($fgpp.Name)' has weak settings"
                        AffectedAccounts    = ($fgpp.AppliesTo -join ', ')
                        CurrentState        = ($issues -join '; ')
                        DefaultPolicyMinLen = 'N/A'
                        Recommendation      = 'Strengthen FGPP settings for privileged accounts'
                        RiskLevel           = 'Low'
                        Impact              = 'FGPP exists but may not be strong enough'
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                Issue               = 'Unable to check Fine-Grained Password Policies'
                AffectedAccounts    = 'Unknown'
                CurrentState        = 'Error checking policies'
                DefaultPolicyMinLen = 'Unknown'
                Recommendation      = 'Manually verify FGPP configuration'
                RiskLevel           = 'Medium'
                Impact              = 'Policy status unknown'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Create Fine-Grained Password Policies with stronger requirements for privileged accounts.'
        Impact      = 'Low - FGPPs only affect password requirements at next password change.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Fine-Grained Password Policy Configuration
#############################################################################
#
# FGPPs allow different password requirements for different users/groups.
# Best practice: Privileged accounts should have STRICTER password policies.
#
# Recommended Settings for Privileged Accounts:
# - Minimum length: 15+ characters
# - Maximum age: 60 days or less
# - History: 24+ passwords remembered
# - Complexity: Enabled
# - Lockout: 5 attempts, 30+ minutes
#
# Issues Found:
$($Finding.Findings | ForEach-Object { "# - $($_.Issue)" } | Out-String)

#############################################################################
# Step 1: Create FGPP for Privileged Accounts
#############################################################################

# Create strong FGPP for Domain Admins, Enterprise Admins, etc.
New-ADFineGrainedPasswordPolicy -Name 'Privileged Account Password Policy' `
    -DisplayName 'Privileged Account Password Policy' `
    -Description 'Strict password policy for administrative accounts' `
    -Precedence 10 `
    -MinPasswordLength 15 `
    -MaxPasswordAge '60.00:00:00' `
    -MinPasswordAge '1.00:00:00' `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled `$true `
    -ReversibleEncryptionEnabled `$false `
    -LockoutThreshold 5 `
    -LockoutDuration '00:30:00' `
    -LockoutObservationWindow '00:30:00'

Write-Host "FGPP created successfully" -ForegroundColor Green

#############################################################################
# Step 2: Apply FGPP to Privileged Groups
#############################################################################

`$privilegedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Backup Operators'
)

`$fgpp = Get-ADFineGrainedPasswordPolicy -Identity 'Privileged Account Password Policy'

foreach (`$groupName in `$privilegedGroups) {
    `$group = Get-ADGroup -Identity `$groupName -ErrorAction SilentlyContinue
    if (`$group) {
        Add-ADFineGrainedPasswordPolicySubject -Identity `$fgpp -Subjects `$group
        Write-Host "Applied FGPP to `$groupName" -ForegroundColor Green
    }
}

#############################################################################
# Step 3: Create FGPP for Service Accounts
#############################################################################

# Service accounts should have very long passwords that never expire
# (Or better: use Group Managed Service Accounts)

New-ADFineGrainedPasswordPolicy -Name 'Service Account Password Policy' `
    -DisplayName 'Service Account Password Policy' `
    -Description 'Policy for service accounts - long passwords, no expiry' `
    -Precedence 20 `
    -MinPasswordLength 25 `
    -MaxPasswordAge '0.00:00:00' `  # Never expires
    -MinPasswordAge '0.00:00:00' `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled `$true `
    -ReversibleEncryptionEnabled `$false `
    -LockoutThreshold 0  # No lockout for service accounts

# Apply to service account group
# Add-ADFineGrainedPasswordPolicySubject -Identity 'Service Account Password Policy' -Subjects 'Service Accounts'

#############################################################################
# Step 4: Verify FGPP Assignment
#############################################################################

# View all FGPPs
Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name, Precedence, MinPasswordLength, MaxPasswordAge

# Check which policy applies to a specific user
Get-ADUserResultantPasswordPolicy -Identity 'AdminUser'

# View policy subjects
Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
    Write-Host "`n`$(`$_.Name):" -ForegroundColor Cyan
    Get-ADFineGrainedPasswordPolicySubject -Identity `$_ | Select-Object Name, ObjectClass
}

#############################################################################
# Recommended FGPP Tiers
#############################################################################

# Tier 0 (Domain Admins, Enterprise Admins):
# - 20+ character passwords
# - 30-day max age
# - 5 attempt lockout

# Tier 1 (Server Admins):
# - 15+ character passwords
# - 60-day max age
# - 5 attempt lockout

# Tier 2 (Workstation Admins):
# - 14+ character passwords
# - 90-day max age
# - 10 attempt lockout

# Service Accounts:
# - 25+ character passwords
# - No expiration (use gMSAs instead when possible)
# - No lockout

"@
            return $commands
        }
    }
}

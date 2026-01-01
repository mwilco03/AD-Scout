<#
.SYNOPSIS
    Detects privileged accounts with passwords unchanged for extended periods.

.DESCRIPTION
    Identifies enabled privileged accounts (AdminCount=1) where the password
    has not been changed in over 365 days. Stale passwords on privileged
    accounts significantly increase the risk of credential compromise.

.NOTES
    Rule ID    : PA-StalePrivilegedPassword
    Category   : PrivilegedAccounts
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "PA-StalePrivilegedPassword"
    Name        = "Stale Privileged Account Password"
    Category    = "PrivilegedAccounts"
    Model       = "PasswordHygiene"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 5
    MaxPoints   = 50
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")  # Valid Accounts: Domain Accounts
    CIS         = @("5.2.1", "5.2.2")  # Password policies
    STIG        = @()
    ANSSI       = @("R68")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $thresholdDays = 365
        $thresholdDate = (Get-Date).AddDays(-$thresholdDays)

        $ADData.Users | Where-Object {
            $_.Enabled -eq $true -and
            $_.AdminCount -eq 1 -and
            $_.PasswordLastSet -and
            $_.PasswordLastSet -lt $thresholdDate
        } | ForEach-Object {
            $daysSinceChange = [math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays, 0)

            $severity = if ($daysSinceChange -gt 730) {
                'Critical'
            } elseif ($daysSinceChange -gt 545) {
                'High'
            } else {
                'Medium'
            }

            [PSCustomObject]@{
                SamAccountName       = $_.SamAccountName
                DistinguishedName    = $_.DistinguishedName
                DisplayName          = $_.DisplayName
                AdminCount           = $_.AdminCount
                PasswordLastSet      = $_.PasswordLastSet
                DaysSinceChange      = $daysSinceChange
                PasswordNeverExpires = $_.PasswordNeverExpires
                Severity             = $severity
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DaysSinceChange", "PasswordLastSet", "Severity")
    DetailFormat     = "{SamAccountName}: Password unchanged for {DaysSinceChange} days"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Stale password on privileged account: $($Finding.SamAccountName)
# Password last set: $($Finding.PasswordLastSet) ($($Finding.DaysSinceChange) days ago)

# Force password change at next logon:
Set-ADUser -Identity '$($Finding.SamAccountName)' -ChangePasswordAtLogon `$true

# Or reset the password directly:
# Set-ADAccountPassword -Identity '$($Finding.SamAccountName)' -Reset -NewPassword (Read-Host -AsSecureString 'New Password')

# If this is a service account, consider migrating to gMSA:
# New-ADServiceAccount -Name 'gMSA_ServiceName' -DNSHostName 'server.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup'

# Ensure password expiration is enabled:
$(if ($Finding.PasswordNeverExpires) {
"Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false"
} else {
"# PasswordNeverExpires is already disabled (good)"
})

"@
    }

    # === DOCUMENTATION ===
    Description = "Privileged accounts with passwords unchanged for over a year."

    TechnicalExplanation = @"
Privileged account passwords should be rotated regularly because:

1. Extended exposure window
   - Longer a password exists, more chances for compromise
   - Credential theft, keyloggers, phishing all accumulate over time

2. Breach detection gap
   - If credentials were stolen, old passwords may still be in use
   - Regular rotation limits the useful lifetime of stolen creds

3. Compliance requirements
   - Many frameworks require 90-day rotation for privileged accounts
   - 365+ days is well beyond any reasonable policy

4. Defense in depth
   - Even strong passwords can be compromised
   - Rotation provides an additional security layer

This rule flags privileged accounts (AdminCount=1) where:
- Account is enabled
- Password was last set more than 365 days ago

Severity levels:
- Medium: 365-545 days
- High: 545-730 days
- Critical: 730+ days (2+ years)
"@

    References = @(
        "https://attack.mitre.org/techniques/T1078/002/"
        "https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-secure-remote-workers"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

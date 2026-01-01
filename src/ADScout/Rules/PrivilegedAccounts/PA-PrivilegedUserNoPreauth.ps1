<#
.SYNOPSIS
    Detects privileged accounts with Kerberos pre-authentication disabled.

.DESCRIPTION
    Identifies privileged user accounts (AdminCount=1) that have the
    "Do not require Kerberos preauthentication" flag set. This makes
    them vulnerable to AS-REP Roasting attacks.

    For privileged accounts, this is especially dangerous because
    successful cracking grants administrative access.

.NOTES
    Rule ID    : PA-PrivilegedUserNoPreauth
    Category   : PrivilegedAccounts
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "PA-PrivilegedUserNoPreauth"
    Name        = "Privileged User Without Pre-Authentication"
    Category    = "PrivilegedAccounts"
    Model       = "KerberosExposure"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1558.004")  # Steal or Forge Kerberos Tickets: AS-REP Roasting
    CIS         = @()
    STIG        = @()
    ANSSI       = @("R37")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # UserAccountControl flag for DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
        $DONT_REQUIRE_PREAUTH = 0x400000

        $ADData.Users | Where-Object {
            $_.Enabled -eq $true -and
            $_.AdminCount -eq 1 -and
            ($_.UserAccountControl -band $DONT_REQUIRE_PREAUTH)
        } | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName     = $_.SamAccountName
                DistinguishedName  = $_.DistinguishedName
                DisplayName        = $_.DisplayName
                AdminCount         = $_.AdminCount
                UserAccountControl = $_.UserAccountControl
                PasswordLastSet    = $_.PasswordLastSet
                Description        = $_.Description
                Severity           = 'Critical'
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "PasswordLastSet", "Severity")
    DetailFormat     = "{SamAccountName}: AS-REP Roastable privileged account"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# CRITICAL: Privileged account vulnerable to AS-REP Roasting!
# Account: $($Finding.SamAccountName)

# Enable Kerberos pre-authentication:
Set-ADAccountControl -Identity '$($Finding.SamAccountName)' -DoesNotRequirePreAuth `$false

# Verify the change:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, DoesNotRequirePreAuth

# ALSO: Change the password immediately (may already be compromised)
Set-ADAccountPassword -Identity '$($Finding.SamAccountName)' -Reset -NewPassword (Read-Host -AsSecureString 'New Password')

"@
    }

    # === DOCUMENTATION ===
    Description = "Privileged accounts without Kerberos pre-authentication are vulnerable to AS-REP Roasting."

    TechnicalExplanation = @"
AS-REP Roasting exploits accounts with pre-authentication disabled:

1. Normally, Kerberos requires the user to prove identity BEFORE
   receiving an encrypted response (pre-authentication)

2. When pre-auth is disabled, anyone can request an AS-REP for that user

3. The AS-REP contains data encrypted with the user's password hash

4. Attackers crack this offline to obtain the password

For PRIVILEGED accounts, this is catastrophic:
- Any domain user can request the AS-REP
- No authentication required
- Minimal forensic evidence
- Cracked password = admin access

Why pre-auth gets disabled:
- Legacy application compatibility
- Troubleshooting that was never reverted
- Misconfiguration

There is almost NEVER a legitimate reason to disable pre-auth
on a privileged account.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1558/004/"
        "https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

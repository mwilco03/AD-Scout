<#
.SYNOPSIS
    Detects user accounts with passwords set to never expire.

.DESCRIPTION
    Identifies user accounts that have the "Password Never Expires" flag enabled.
    This setting bypasses password policies and increases the risk of credential
    compromise through prolonged exposure to password attacks.

.NOTES
    Rule ID    : S-PwdNeverExpires
    Category   : StaleObjects
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "S-PwdNeverExpires"
    Name        = "Password Never Expires"
    Category    = "StaleObjects"
    Model       = "AccountPolicy"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 1
    MaxPoints   = 100
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")          # Valid Accounts: Domain Accounts
    CIS         = @("5.1.2", "5.2.8")     # Password Policy controls
    STIG        = @("V-63337")            # Password expiration requirement
    ANSSI       = @("R36")                # Password management

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $ADData.Users | Where-Object {
            # Check for enabled accounts with password never expires
            $_.Enabled -eq $true -and
            $_.PasswordNeverExpires -eq $true
        } | Select-Object @(
            'SamAccountName'
            'DistinguishedName'
            'UserPrincipalName'
            'DisplayName'
            'PasswordLastSet'
            'WhenCreated'
            'Description'
            @{Name='DaysSincePasswordSet'; Expression={
                if ($_.PasswordLastSet) {
                    [math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays)
                } else { 'Never' }
            }}
        )
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName", "DaysSincePasswordSet")
    DetailFormat     = "{SamAccountName} (Password age: {DaysSincePasswordSet} days)"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"
# Remediation for: $($Finding.SamAccountName)
# Remove the 'Password Never Expires' flag

# Using Active Directory module:
Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false

# Verify the change:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties PasswordNeverExpires | Select-Object SamAccountName, PasswordNeverExpires

# Note: The user's password will now be subject to domain password policies.
# Consider notifying the user and coordinating a password change if needed.

"@
    }

    # === DOCUMENTATION ===
    Description = "User accounts with passwords configured to never expire bypass security policies."

    TechnicalExplanation = @"
The 'Password Never Expires' flag (DONT_EXPIRE_PASSWORD, UAC 0x10000) exempts
an account from domain password expiration policies. While sometimes used for
service accounts, this setting on regular user accounts poses significant risks:

SECURITY IMPLICATIONS:
- Passwords have unlimited time to be compromised through phishing or brute force
- Old passwords may exist in historical breach databases
- No forced rotation reduces defense against credential stuffing
- Violates security best practices and compliance requirements

COMMON EXPLOITATION:
1. Attackers obtain credentials through phishing or credential dumps
2. The credentials remain valid indefinitely without user awareness
3. Persistent access maintained without triggering password change alerts

EXCEPTIONS TO CONSIDER:
- Managed Service Accounts (MSA/gMSA) - these have automatic rotation
- Service accounts with compensating controls (strong passwords, MFA)
- Break-glass accounts (should have additional monitoring)

RECOMMENDED ACTIONS:
1. Remove flag from all standard user accounts
2. Migrate service accounts to gMSA where possible
3. Implement compensating controls for necessary exceptions
4. Document business justification for any remaining exceptions
"@

    References = @(
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"
        "https://attack.mitre.org/techniques/T1078/002/"
        "https://www.cisecurity.org/controls"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        # Require user data to be available
        $null -ne $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

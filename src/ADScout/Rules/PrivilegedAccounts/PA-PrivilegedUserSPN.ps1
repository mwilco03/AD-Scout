<#
.SYNOPSIS
    Detects privileged user accounts with Service Principal Names (Kerberoastable).

.DESCRIPTION
    Identifies user accounts that have AdminCount=1 (privileged) AND have
    Service Principal Names registered. These accounts are vulnerable to
    Kerberoasting attacks, which can expose their password hashes.

    This is particularly dangerous for admin accounts because:
    - Attackers can request service tickets offline
    - Tickets can be cracked to reveal the password
    - Admin passwords grant domain-wide access

.NOTES
    Rule ID    : PA-PrivilegedUserSPN
    Category   : PrivilegedAccounts
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "PA-PrivilegedUserSPN"
    Name        = "Privileged User with SPN (Kerberoastable Admin)"
    Category    = "PrivilegedAccounts"
    Model       = "KerberosExposure"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1558.003")  # Steal or Forge Kerberos Tickets: Kerberoasting
    CIS         = @()
    STIG        = @()
    ANSSI       = @("R37")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $ADData.Users | Where-Object {
            $_.Enabled -eq $true -and
            $_.AdminCount -eq 1 -and
            $_.ServicePrincipalNames -and
            @($_.ServicePrincipalNames).Count -gt 0
        } | ForEach-Object {
            $spns = @($_.ServicePrincipalNames)

            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                DisplayName       = $_.DisplayName
                AdminCount        = $_.AdminCount
                SPNCount          = $spns.Count
                SPNs              = ($spns | Select-Object -First 3) -join '; '
                PasswordLastSet   = $_.PasswordLastSet
                Severity          = 'Critical'
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "SPNCount", "SPNs", "Severity")
    DetailFormat     = "{SamAccountName}: {SPNCount} SPNs - Kerberoastable admin"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# CRITICAL: Privileged account with SPN - Kerberoastable!
# Account: $($Finding.SamAccountName)
# SPNs: $($Finding.SPNs)

# OPTION 1: Remove unnecessary SPNs (preferred if service not needed)
Set-ADUser -Identity '$($Finding.SamAccountName)' -ServicePrincipalNames @{Remove='SPN_VALUE_HERE'}

# OPTION 2: Use Group Managed Service Account (gMSA) instead
# gMSAs have 120-character auto-rotating passwords, making cracking impractical

# OPTION 3: If SPN is required, implement these mitigations:
# a) Use AES encryption only (disable RC4)
# b) Use 25+ character random password
# c) Rotate password frequently (every 30 days)
# d) Monitor for TGS requests to this SPN

# List all SPNs on this account:
Get-ADUser -Identity '$($Finding.SamAccountName)' -Properties ServicePrincipalNames |
    Select-Object -ExpandProperty ServicePrincipalNames

"@
    }

    # === DOCUMENTATION ===
    Description = "Privileged accounts with SPNs are vulnerable to Kerberoasting attacks."

    TechnicalExplanation = @"
Kerberoasting exploits how Kerberos service tickets work:
1. Any domain user can request a TGS for any SPN
2. The TGS is encrypted with the service account's password hash
3. Attackers take the ticket offline and crack it
4. If successful, they obtain the service account's password

When a PRIVILEGED account (Domain Admin, etc.) has an SPN:
- The account is Kerberoastable
- Cracking the password grants admin access
- No special privileges needed to request the ticket
- Attack leaves minimal forensic evidence

Why this happens:
- Misconfigured service accounts running as Domain Admins
- Legacy applications requiring admin service accounts
- Admins adding SPNs for testing and forgetting to remove

Impact: Complete domain compromise if password is cracked.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1558/003/"
        "https://adsecurity.org/?p=3458"
        "https://www.semperis.com/blog/what-is-kerberoasting/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

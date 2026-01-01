@{
    Id          = 'A-ShadowCredentials'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Shadow Credentials Attack Detection'
    Description = 'Detects accounts with msDS-KeyCredentialLink attribute populated, which may indicate Shadow Credentials attack. Attackers can add their own key credentials to accounts, allowing authentication without knowing the password.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Shadow Credentials Attack'; Url = 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab' }
        @{ Title = 'Whisker Tool'; Url = 'https://github.com/eladshamir/Whisker' }
        @{ Title = 'Key Trust Account Mapping'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004', 'TA0006')  # Persistence, Privilege Escalation, Credential Access
        Techniques = @('T1556', 'T1098')              # Modify Authentication Process, Account Manipulation
    }

    CIS   = @('5.7.1')
    STIG  = @('V-220952')
    ANSSI = @('R50')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check for accounts with msDS-KeyCredentialLink populated
        # This attribute is used for Windows Hello for Business but can be abused

        foreach ($user in $Data.Users) {
            if ($user.'msDS-KeyCredentialLink') {
                $keyCredentials = $user.'msDS-KeyCredentialLink'
                $keyCount = if ($keyCredentials -is [Array]) { $keyCredentials.Count } else { 1 }

                # Check if this is a suspicious addition
                $riskLevel = 'Medium'
                $riskFactors = @()

                # High-value targets are more concerning
                if ($user.AdminCount -eq 1) {
                    $riskLevel = 'Critical'
                    $riskFactors += 'Privileged account with key credentials'
                }

                # Service accounts with key credentials are unusual
                if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                    $riskLevel = 'High'
                    $riskFactors += 'Service account with key credentials'
                }

                # Multiple key credentials may indicate abuse
                if ($keyCount -gt 2) {
                    $riskFactors += "Multiple key credentials ($keyCount)"
                }

                # If Windows Hello is not deployed, any key credential is suspicious
                # This would need additional context from the environment

                $findings += [PSCustomObject]@{
                    SamAccountName          = $user.SamAccountName
                    DisplayName             = $user.DisplayName
                    DistinguishedName       = $user.DistinguishedName
                    KeyCredentialCount      = $keyCount
                    AdminCount              = $user.AdminCount
                    HasSPNs                 = ($user.ServicePrincipalNames.Count -gt 0)
                    Enabled                 = $user.Enabled
                    WhenChanged             = $user.WhenChanged
                    RiskLevel               = $riskLevel
                    RiskFactors             = ($riskFactors -join '; ')
                    AttackDescription       = @(
                        'Attacker adds key credentials to victim account',
                        'Can then request TGT using PKINIT without password',
                        'Persistence mechanism - survives password changes',
                        'Tool: Whisker (add/list/remove key credentials)'
                    ) -join '; '
                }
            }
        }

        # Also check computer accounts
        foreach ($computer in $Data.Computers) {
            if ($computer.'msDS-KeyCredentialLink') {
                $keyCredentials = $computer.'msDS-KeyCredentialLink'
                $keyCount = if ($keyCredentials -is [Array]) { $keyCredentials.Count } else { 1 }

                $findings += [PSCustomObject]@{
                    SamAccountName          = $computer.Name
                    DisplayName             = "Computer: $($computer.Name)"
                    DistinguishedName       = $computer.DistinguishedName
                    KeyCredentialCount      = $keyCount
                    ObjectType              = 'Computer'
                    Enabled                 = $computer.Enabled
                    RiskLevel               = 'High'
                    RiskFactors             = 'Computer account with key credentials'
                }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}
    }

    Remediation = @{
        Description = 'Investigate accounts with key credentials. Remove unauthorized key credentials and monitor for re-addition.'
        Impact      = 'Medium - May break Windows Hello for Business if legitimate'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SHADOW CREDENTIALS DETECTION
# ================================================================
# Shadow Credentials abuse the msDS-KeyCredentialLink attribute
# to add attacker-controlled key credentials to accounts.
#
# This allows attackers to:
# - Authenticate as the account without knowing the password
# - Persist even after password changes
# - Escalate privileges to any account they can write to

# ================================================================
# INVESTIGATE FINDINGS
# ================================================================

# List all accounts with key credentials:
Get-ADObject -Filter { msDS-KeyCredentialLink -like '*' } -Properties msDS-KeyCredentialLink, ObjectClass | ``
    Select-Object Name, ObjectClass, @{N='KeyCount';E={`$_.'msDS-KeyCredentialLink'.Count}}

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Account: $($item.SamAccountName)
# Risk: $($item.RiskLevel)
# Key Credentials: $($item.KeyCredentialCount)
# Risk Factors: $($item.RiskFactors)
# ================================================================

# View key credential details:
Get-ADUser -Identity '$($item.SamAccountName)' -Properties msDS-KeyCredentialLink | ``
    Select-Object -ExpandProperty msDS-KeyCredentialLink

# If Windows Hello is NOT used, remove all key credentials:
Set-ADUser -Identity '$($item.SamAccountName)' -Clear msDS-KeyCredentialLink

# If Windows Hello IS used, investigate each key:
# - Check creation time vs Windows Hello enrollment
# - Verify key thumbprint matches known devices
# - Use Whisker to list/analyze: Whisker.exe list /target:$($item.SamAccountName)

"@
            }

            $commands += @"

# ================================================================
# PREVENTION & DETECTION
# ================================================================

# 1. Restrict who can modify msDS-KeyCredentialLink:
# By default, account owners and admins can modify this
# Consider restricting via ACL on OUs

# 2. Monitor for modifications:
# Event ID 5136 - Directory Service Changes
# Attribute: msDS-KeyCredentialLink

# 3. Use Whisker for investigation:
# Whisker.exe list /target:USERNAME   # List key credentials
# Whisker.exe remove /target:USERNAME /deviceid:GUID  # Remove specific key

# 4. If Windows Hello not used, block the attribute:
# Deny Write on msDS-KeyCredentialLink for Everyone except system

"@
            return $commands
        }
    }
}

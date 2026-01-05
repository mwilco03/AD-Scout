@{
    Id          = 'A-ReversibleEncryption'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Reversible Encryption Enabled for Passwords'
    Description = 'Detects user accounts or password policies with "Store passwords using reversible encryption" enabled. This stores passwords in a way that allows recovery of the plaintext password, significantly weakening security.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Reversible Encryption'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption' }
        @{ Title = 'Password Storage'; Url = 'https://attack.mitre.org/techniques/T1003/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.002', 'T1552.001')
    }

    CIS   = @('1.1.6')
    STIG  = @('V-220906')
    ANSSI = @('R23')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check domain password policy
            $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue

            if ($domainPolicy -and $domainPolicy.ReversibleEncryptionEnabled) {
                $findings += [PSCustomObject]@{
                    CheckType               = 'Domain Password Policy'
                    Setting                 = 'ReversibleEncryptionEnabled'
                    Value                   = $true
                    RiskLevel               = 'Critical'
                    Issue                   = 'Domain policy stores all passwords with reversible encryption'
                    Impact                  = 'ALL domain passwords can be recovered in plaintext'
                }
            }

            # Check Fine-Grained Password Policies
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue

            foreach ($fgpp in $fgpps) {
                if ($fgpp.ReversibleEncryptionEnabled) {
                    $findings += [PSCustomObject]@{
                        CheckType               = 'Fine-Grained Password Policy'
                        PolicyName              = $fgpp.Name
                        Setting                 = 'ReversibleEncryptionEnabled'
                        Value                   = $true
                        Precedence              = $fgpp.Precedence
                        AppliesTo               = ($fgpp.AppliesTo -join ', ')
                        RiskLevel               = 'Critical'
                        Issue                   = 'FGPP stores passwords with reversible encryption'
                    }
                }
            }

            # Check individual users with AllowReversiblePasswordEncryption
            foreach ($user in $Data.Users) {
                if ($user.AllowReversiblePasswordEncryption -eq $true) {
                    $findings += [PSCustomObject]@{
                        CheckType               = 'User Account'
                        SamAccountName          = $user.SamAccountName
                        DisplayName             = $user.DisplayName
                        DistinguishedName       = $user.DistinguishedName
                        Setting                 = 'AllowReversiblePasswordEncryption'
                        Value                   = $true
                        RiskLevel               = if ($user.AdminCount -eq 1) { 'Critical' } else { 'High' }
                        IsPrivileged            = $user.AdminCount -eq 1
                        Issue                   = 'User password stored with reversible encryption'
                    }
                }
            }
        }
        catch {
            # Could not check settings
        }

        return $findings | Sort-Object RiskLevel
    }

    Remediation = @{
        Description = 'Disable reversible encryption in password policies and on individual accounts. Force password changes for affected accounts.'
        Impact      = 'Medium - Some legacy applications may require reversible encryption'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# REVERSIBLE ENCRYPTION
# ================================================================
# Reversible encryption allows recovery of plaintext passwords.
# This is equivalent to storing passwords in cleartext.
#
# Why it exists: CHAP authentication, Digest authentication
# Why it's bad: Attackers with database access get all passwords

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Check Type: $($item.CheckType)
# Affected: $($item.PolicyName ?? $item.SamAccountName)
# Setting: $($item.Setting) = $($item.Value)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# 1. DISABLE IN DOMAIN PASSWORD POLICY
# GPO: Computer Configuration
#      -> Policies
#      -> Windows Settings
#      -> Security Settings
#      -> Account Policies
#      -> Password Policy
#      -> "Store passwords using reversible encryption" = Disabled

# Check current policy:
Get-ADDefaultDomainPasswordPolicy | Select-Object ReversibleEncryptionEnabled

# 2. DISABLE IN FINE-GRAINED PASSWORD POLICIES
Get-ADFineGrainedPasswordPolicy -Filter * |
    Where-Object { `$_.ReversibleEncryptionEnabled } |
    ForEach-Object {
        Write-Host "Disabling reversible encryption on FGPP: `$(`$_.Name)"
        # Set-ADFineGrainedPasswordPolicy -Identity `$_.Name -ReversibleEncryptionEnabled `$false
    }

# 3. DISABLE ON INDIVIDUAL USERS
Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq `$true } -Properties AllowReversiblePasswordEncryption |
    ForEach-Object {
        Write-Host "Disabling reversible encryption for user: `$(`$_.SamAccountName)"
        # Set-ADUser -Identity `$_.SamAccountName -AllowReversiblePasswordEncryption `$false
    }

# ================================================================
# FORCE PASSWORD CHANGE
# ================================================================

# After disabling, affected users must change passwords
# to remove the reversibly encrypted version.

Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq `$true } |
    ForEach-Object {
        Write-Host "Forcing password change for: `$(`$_.SamAccountName)"
        # Set-ADUser -Identity `$_.SamAccountName -ChangePasswordAtLogon `$true
    }

# ================================================================
# LEGACY APPLICATION ALTERNATIVES
# ================================================================

# If an application requires reversible encryption:
# 1. Use a dedicated service account
# 2. Apply FGPP to ONLY that account
# 3. Use extremely long, complex password
# 4. Audit access to that account
# 5. Plan migration away from legacy protocol

# Better alternatives:
# - CHAP: Use PEAP with EAP-TLS instead
# - Digest Auth: Use Kerberos or NTLM instead
# - RADIUS: Use modern EAP methods

"@
            return $commands
        }
    }
}

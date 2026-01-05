@{
    Id          = 'A-WeakPasswordPolicy'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Weak Domain Password Policy'
    Description = 'Detects when the default domain password policy does not meet security best practices. Weak password policies enable brute force attacks, credential stuffing, and make password cracking trivial for attackers.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'NIST SP 800-63B Digital Identity Guidelines'; Url = 'https://pages.nist.gov/800-63-3/sp800-63b.html' }
        @{ Title = 'Microsoft Password Guidance'; Url = 'https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations' }
        @{ Title = 'CIS Password Policy Benchmark'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0001')  # Credential Access, Initial Access
        Techniques = @('T1110', 'T1110.001', 'T1110.003', 'T1110.004')  # Brute Force variants
    }

    CIS   = @('1.1.1', '1.1.2', '1.1.3', '1.1.4', '1.1.5', '1.1.6', '1.1.7')
    STIG  = @('V-220901', 'V-220902', 'V-220903', 'V-220904')
    ANSSI = @('R32', 'R33')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $policy = $Data.NetworkSecurity.PasswordPolicy

        if ($policy -and $policy.WeaknessCount -gt 0) {
            # Calculate overall risk
            $riskLevel = $policy.RiskLevel
            $criticalIssues = @()
            $highIssues = @()
            $mediumIssues = @()

            foreach ($weakness in $policy.Weaknesses) {
                if ($weakness -match 'critically|reversible|never expire|No account lockout') {
                    $criticalIssues += $weakness
                }
                elseif ($weakness -match 'disabled|too high|no minimum') {
                    $highIssues += $weakness
                }
                else {
                    $mediumIssues += $weakness
                }
            }

            # Calculate password crack time estimates
            $crackTimeEstimate = switch ($policy.MinPasswordLength) {
                { $_ -lt 8 }  { 'Minutes to hours with GPU' }
                { $_ -lt 10 } { 'Hours to days with GPU' }
                { $_ -lt 12 } { 'Days to weeks with GPU' }
                { $_ -lt 14 } { 'Weeks to months with GPU' }
                default       { 'Months to years with GPU' }
            }

            $findings += [PSCustomObject]@{
                PolicyDN                    = $policy.DistinguishedName
                MinPasswordLength           = $policy.MinPasswordLength
                PasswordHistoryCount        = $policy.PasswordHistoryCount
                MaxPasswordAgeDays          = $policy.MaxPasswordAge.Days
                MinPasswordAgeDays          = $policy.MinPasswordAge.Days
                ComplexityEnabled           = $policy.ComplexityEnabled
                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
                LockoutThreshold            = $policy.LockoutThreshold
                LockoutDurationMins         = $policy.LockoutDuration.TotalMinutes
                LockoutObservationMins      = $policy.LockoutObservationWindow.TotalMinutes
                CriticalIssues              = ($criticalIssues -join '; ')
                HighIssues                  = ($highIssues -join '; ')
                MediumIssues                = ($mediumIssues -join '; ')
                TotalWeaknesses             = $policy.WeaknessCount
                CrackTimeEstimate           = $crackTimeEstimate
                RiskLevel                   = $riskLevel
                RecommendedSettings         = @{
                    MinPasswordLength    = '14+ characters'
                    PasswordHistory      = '24 passwords'
                    MaxPasswordAge       = '60-90 days (or never with MFA)'
                    MinPasswordAge       = '1 day minimum'
                    Complexity           = 'Enabled (or use passphrase policy)'
                    LockoutThreshold     = '5-10 attempts'
                    LockoutDuration      = '15-30 minutes'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Update the default domain password policy to meet security best practices. Consider implementing fine-grained password policies for privileged accounts.'
        Impact      = 'Medium - Users will need to update passwords on next change'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# WEAK PASSWORD POLICY DETECTED
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"
# Current Policy Issues:
# Critical: $($item.CriticalIssues)
# High: $($item.HighIssues)
# Medium: $($item.MediumIssues)

# Current Settings:
#   Min Length: $($item.MinPasswordLength) (Recommended: 14+)
#   History: $($item.PasswordHistoryCount) (Recommended: 24)
#   Max Age: $($item.MaxPasswordAgeDays) days
#   Lockout: $($item.LockoutThreshold) attempts

# Estimated crack time for current policy: $($item.CrackTimeEstimate)

"@
            }

            $commands += @"

# ================================================================
# UPDATE DEFAULT DOMAIN PASSWORD POLICY
# ================================================================

# Option 1: PowerShell (Recommended)
Set-ADDefaultDomainPasswordPolicy -Identity "$Domain" ``
    -MinPasswordLength 14 ``
    -PasswordHistoryCount 24 ``
    -MaxPasswordAge (New-TimeSpan -Days 90) ``
    -MinPasswordAge (New-TimeSpan -Days 1) ``
    -ComplexityEnabled `$true ``
    -ReversibleEncryptionEnabled `$false ``
    -LockoutThreshold 5 ``
    -LockoutDuration (New-TimeSpan -Minutes 30) ``
    -LockoutObservationWindow (New-TimeSpan -Minutes 30)

# Verify changes:
Get-ADDefaultDomainPasswordPolicy -Identity "$Domain"

# ================================================================
# FINE-GRAINED PASSWORD POLICY FOR ADMINS
# ================================================================

# Create stronger policy for privileged accounts:
New-ADFineGrainedPasswordPolicy -Name "Privileged Account Policy" ``
    -Precedence 10 ``
    -MinPasswordLength 20 ``
    -PasswordHistoryCount 24 ``
    -MaxPasswordAge (New-TimeSpan -Days 60) ``
    -MinPasswordAge (New-TimeSpan -Days 1) ``
    -ComplexityEnabled `$true ``
    -ReversibleEncryptionEnabled `$false ``
    -LockoutThreshold 3 ``
    -LockoutDuration (New-TimeSpan -Minutes 60) ``
    -LockoutObservationWindow (New-TimeSpan -Minutes 60)

# Apply to Domain Admins:
Add-ADFineGrainedPasswordPolicySubject -Identity "Privileged Account Policy" ``
    -Subjects "Domain Admins", "Enterprise Admins", "Schema Admins"

# ================================================================
# ADDITIONAL RECOMMENDATIONS
# ================================================================

# 1. Implement Azure AD Password Protection (blocks common passwords)
# 2. Enable MFA for all accounts (allows relaxing password rotation)
# 3. Use Privileged Access Workstations (PAW) for admin accounts
# 4. Monitor for password spraying attacks
# 5. Regular password audits with tools like DSInternals

# ================================================================
# AUDIT CURRENT WEAK PASSWORDS
# ================================================================

# Install DSInternals module:
# Install-Module DSInternals -Force

# Check for weak passwords:
# `$passwords = Get-ADReplAccount -All -Server DC01 -NamingContext "DC=domain,DC=com"
# Test-PasswordQuality -Account `$passwords -WeakPasswordsFile .\common-passwords.txt

"@
            return $commands
        }
    }
}

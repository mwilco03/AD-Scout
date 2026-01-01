@{
    Id          = 'A-WeakPwdPolicy'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Weak Domain Password Policy'
    Description = 'The domain password policy does not meet security best practices. Weak password requirements allow users to set easily guessable passwords that can be cracked or guessed through brute force and password spraying attacks.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'NIST Password Guidelines'; Url = 'https://pages.nist.gov/800-63-3/sp800-63b.html' }
        @{ Title = 'Password Spraying Attack'; Url = 'https://attack.mitre.org/techniques/T1110/003/' }
        @{ Title = 'CIS Password Policy'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0001')  # Credential Access, Initial Access
        Techniques = @('T1110.001', 'T1110.003')  # Brute Force, Password Spraying
    }

    CIS   = @('1.1.1', '1.1.2', '1.1.3', '1.1.4', '1.1.5')
    STIG  = @('V-63413', 'V-63417', 'V-63421')
    ANSSI = @('vuln1_password_policy')
    NIST  = @('CM-2', 'CM-6', 'IA-5(1)')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $issues = @()

        # Recommended minimum values
        $recommendations = @{
            MinPasswordLength     = 14      # CIS/NIST recommends 14+
            PasswordHistoryCount  = 24      # Remember 24 passwords
            MaxPasswordAge        = 365     # Change at least annually (NIST says no forced rotation, but many orgs require it)
            MinPasswordAge        = 1       # Prevent immediate changes
            LockoutThreshold      = 5       # Lock after 5 bad attempts
            LockoutDuration       = 30      # Lock for 30 minutes
            ComplexityEnabled     = $true   # Require complexity
        }

        try {
            # Get password policy
            $policy = $null
            if ($Domain.MinPasswordLength) {
                $policy = $Domain
            } else {
                try {
                    $policy = Get-ADDefaultDomainPasswordPolicy
                } catch {
                    # Try direct query
                    $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new()
                    $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                    $searcher.Filter = "(objectClass=domainDNS)"
                    $searcher.PropertiesToLoad.AddRange(@('minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'lockoutThreshold', 'lockoutDuration', 'pwdProperties'))
                    $result = $searcher.FindOne()

                    if ($result) {
                        $policy = [PSCustomObject]@{
                            MinPasswordLength     = $result.Properties['minpwdlength'][0]
                            PasswordHistoryCount  = $result.Properties['pwdhistorylength'][0]
                            MaxPasswordAge        = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['maxpwdage'][0]))
                            MinPasswordAge        = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['minpwdage'][0]))
                            LockoutThreshold      = $result.Properties['lockoutthreshold'][0]
                            LockoutDuration       = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['lockoutduration'][0]))
                            ComplexityEnabled     = ($result.Properties['pwdproperties'][0] -band 1) -eq 1
                        }
                    }
                }
            }

            if ($policy) {
                # Check minimum password length
                $minLength = if ($policy.MinPasswordLength) { $policy.MinPasswordLength } else { 0 }
                if ($minLength -lt $recommendations.MinPasswordLength) {
                    $issues += [PSCustomObject]@{
                        Setting       = 'Minimum Password Length'
                        CurrentValue  = $minLength
                        Recommended   = $recommendations.MinPasswordLength
                        Severity      = if ($minLength -lt 8) { 'Critical' } elseif ($minLength -lt 12) { 'High' } else { 'Medium' }
                        Risk          = 'Short passwords are easily cracked'
                    }
                }

                # Check password history
                $historyCount = if ($policy.PasswordHistoryCount) { $policy.PasswordHistoryCount } else { 0 }
                if ($historyCount -lt $recommendations.PasswordHistoryCount) {
                    $issues += [PSCustomObject]@{
                        Setting       = 'Password History Count'
                        CurrentValue  = $historyCount
                        Recommended   = $recommendations.PasswordHistoryCount
                        Severity      = if ($historyCount -lt 5) { 'High' } else { 'Medium' }
                        Risk          = 'Users can quickly cycle back to old passwords'
                    }
                }

                # Check complexity
                $complexity = $policy.ComplexityEnabled
                if (-not $complexity) {
                    $issues += [PSCustomObject]@{
                        Setting       = 'Password Complexity'
                        CurrentValue  = 'Disabled'
                        Recommended   = 'Enabled'
                        Severity      = 'High'
                        Risk          = 'Users can set simple, easily guessable passwords'
                    }
                }

                # Check lockout threshold
                $lockoutThreshold = if ($policy.LockoutThreshold) { $policy.LockoutThreshold } else { 0 }
                if ($lockoutThreshold -eq 0) {
                    $issues += [PSCustomObject]@{
                        Setting       = 'Account Lockout Threshold'
                        CurrentValue  = 'Disabled (0)'
                        Recommended   = $recommendations.LockoutThreshold
                        Severity      = 'High'
                        Risk          = 'Unlimited password attempts enable brute force attacks'
                    }
                } elseif ($lockoutThreshold -gt 10) {
                    $issues += [PSCustomObject]@{
                        Setting       = 'Account Lockout Threshold'
                        CurrentValue  = $lockoutThreshold
                        Recommended   = $recommendations.LockoutThreshold
                        Severity      = 'Medium'
                        Risk          = 'High threshold allows many guessing attempts'
                    }
                }
            }

            if ($issues.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    DomainName            = $Domain.Name
                    PolicyIssues          = $issues
                    IssueCount            = $issues.Count
                    HighestSeverity       = ($issues | Sort-Object { switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } } | Select-Object -First 1).Severity
                    RiskLevel             = 'High'
                    AttackVectors         = 'Password spraying, brute force, credential guessing'
                }
            }
        } catch {
            $findings += [PSCustomObject]@{
                DomainName            = $Domain.Name
                PolicyIssues          = @([PSCustomObject]@{ Setting = 'Error'; CurrentValue = "Unable to read policy: $_"; Recommended = 'Manual review'; Severity = 'Unknown'; Risk = 'Unknown' })
                IssueCount            = 1
                HighestSeverity       = 'Unknown'
                RiskLevel             = 'Unknown'
                AttackVectors         = 'Manual policy review required'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Update the domain password policy to meet security best practices. Consider implementing fine-grained password policies for privileged accounts.'
        Impact      = 'Medium - Users may need to update passwords to meet new requirements.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Update Domain Password Policy
# Current Issues: $($Finding.Findings[0].IssueCount)

# Current Policy Issues:
$($Finding.Findings[0].PolicyIssues | ForEach-Object { "# - $($_.Setting): $($_.CurrentValue) (Recommended: $($_.Recommended)) - $($_.Risk)" } | Out-String)

# Set recommended password policy via PowerShell:
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled `$true `
    -MinPasswordAge 1.00:00:00 `
    -MaxPasswordAge 365.00:00:00 `
    -LockoutThreshold 5 `
    -LockoutDuration 00:30:00 `
    -LockoutObservationWindow 00:30:00

# Alternatively, configure via Group Policy:
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Account Policies > Password Policy

# NIST 800-63B Recommendations:
# - Minimum 8 characters (14+ recommended for privileged)
# - No forced periodic rotation (controversial, many orgs still require it)
# - Check passwords against known breached password lists
# - Allow all printable ASCII and Unicode characters

# For privileged accounts, create a Fine-Grained Password Policy:
New-ADFineGrainedPasswordPolicy -Name "Privileged Account Policy" `
    -Precedence 10 `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled `$true `
    -LockoutThreshold 3 `
    -LockoutDuration "0.00:30:00" `
    -LockoutObservationWindow "0.00:30:00"

# Apply to privileged groups:
Add-ADFineGrainedPasswordPolicySubject -Identity "Privileged Account Policy" -Subjects "Domain Admins", "Enterprise Admins"

# Verify the policy:
Get-ADDefaultDomainPasswordPolicy | Select-Object *

"@
            return $commands
        }
    }
}

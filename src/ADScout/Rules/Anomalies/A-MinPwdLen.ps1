@{
    Id          = 'A-MinPwdLen'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Minimum Password Length Below Recommended'
    Description = 'Detects when the domain password policy minimum length is below recommended standards. Short passwords are easier to crack and guess.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'NIST Password Guidelines'; Url = 'https://pages.nist.gov/800-63-3/sp800-63b.html' }
        @{ Title = 'CIS Password Policy'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
        @{ Title = 'PingCastle Rule A-MinPwdLen'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1110.001', 'T1110.003')  # Password Guessing, Password Spraying
    }

    CIS   = @('1.1.4')  # Password Policy - Minimum password length
    STIG  = @()  # Password length STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('IA-5')  # Authenticator Management

    Scoring = @{
        Type      = 'ThresholdBased'
        Threshold = 14
        Points    = 5
        MaxPoints = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Minimum recommended password length
        $recommendedMinLength = 14  # NIST/CIS recommendation
        $criticalMinLength = 8      # Absolute minimum (STIG)

        try {
            # Get domain password policy
            $minPwdLength = $null

            if ($Domain.MinPasswordLength) {
                $minPwdLength = $Domain.MinPasswordLength
            } elseif ($Data.Domain -and $Data.Domain.MinPasswordLength) {
                $minPwdLength = $Data.Domain.MinPasswordLength
            } else {
                # Try to get it directly
                try {
                    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
                    if ($domainPolicy) {
                        $minPwdLength = $domainPolicy.MinPasswordLength
                    }
                } catch {
                    # Try ADSI
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $domainDN = $rootDSE.defaultNamingContext.ToString()
                        $domain = [ADSI]"LDAP://$domainDN"
                        $minPwdLength = $domain.minPwdLength.Value
                    } catch {
                        Write-Verbose "A-MinPwdLen: Could not read minPwdLength from $domainDN via ADSI: $_"
                    }
                }
            }

            if ($null -eq $minPwdLength) {
                $findings += [PSCustomObject]@{
                    Issue               = 'Unable to determine minimum password length'
                    Severity            = 'Info'
                    Risk                = 'Password policy could not be retrieved'
                    Recommendation      = 'Verify password policy configuration'
                }
                return $findings
            }

            if ($minPwdLength -lt $criticalMinLength) {
                $findings += [PSCustomObject]@{
                    CurrentMinLength    = $minPwdLength
                    RecommendedLength   = $recommendedMinLength
                    CriticalThreshold   = $criticalMinLength
                    Severity            = 'Critical'
                    Risk                = "Minimum password length ($minPwdLength) is critically low"
                    Impact              = 'Passwords can be cracked in minutes'
                    CrackTime           = 'Less than 1 hour for most passwords'
                    Recommendation      = "Increase to at least $recommendedMinLength characters"
                }
            } elseif ($minPwdLength -lt $recommendedMinLength) {
                $findings += [PSCustomObject]@{
                    CurrentMinLength    = $minPwdLength
                    RecommendedLength   = $recommendedMinLength
                    Severity            = 'Medium'
                    Risk                = "Minimum password length ($minPwdLength) below recommended ($recommendedMinLength)"
                    Impact              = 'Passwords more susceptible to offline cracking'
                    CrackTime           = $( switch ($minPwdLength) {
                        8  { 'Hours to days' }
                        10 { 'Days to weeks' }
                        12 { 'Weeks to months' }
                        default { 'Varies based on complexity' }
                    })
                    Recommendation      = "Increase to $recommendedMinLength characters"
                }
            }

            # Also check Fine-Grained Password Policies
            try {
                $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue

                foreach ($fgpp in $fgpps) {
                    if ($fgpp.MinPasswordLength -lt $recommendedMinLength) {
                        $findings += [PSCustomObject]@{
                            PolicyType          = 'Fine-Grained Password Policy'
                            PolicyName          = $fgpp.Name
                            CurrentMinLength    = $fgpp.MinPasswordLength
                            RecommendedLength   = $recommendedMinLength
                            Precedence          = $fgpp.Precedence
                            AppliesToCount      = @($fgpp.AppliesTo).Count
                            Severity            = if ($fgpp.MinPasswordLength -lt $criticalMinLength) { 'High' } else { 'Medium' }
                            Risk                = "FGPP '$($fgpp.Name)' has minimum length of $($fgpp.MinPasswordLength)"
                        }
                    }
                }
            } catch {
                Write-Verbose "A-MinPwdLen: Could not enumerate Fine-Grained Password Policies: $_"
            }

        } catch {
            Write-Verbose "A-MinPwdLen: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Increase the minimum password length to at least 14 characters. Consider implementing a phased rollout with user notification.'
        Impact      = 'Medium - Users will need to create longer passwords. May require help desk support during transition.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Minimum Password Length Remediation
#
# Current Issues:
$($Finding.Findings | ForEach-Object { "# - $($_.PolicyType): Length = $($_.CurrentMinLength), Recommended = $($_.RecommendedLength)" } | Out-String)

# Password length recommendations:
# - NIST SP 800-63B: 8+ characters minimum, encourage longer
# - CIS Benchmark: 14 characters for admin accounts
# - Microsoft: 14+ characters recommended
# - PingCastle: 14 characters minimum

# STEP 1: View current domain password policy
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, MaxPasswordAge, MinPasswordAge,
    PasswordHistoryCount, ComplexityEnabled, ReversibleEncryptionEnabled

# STEP 2: Update the default domain password policy
# CAUTION: This affects all users not covered by FGPP
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity (Get-ADDomain).DNSRoot
Write-Host "Set minimum password length to 14" -ForegroundColor Green

# STEP 3: Update Fine-Grained Password Policies
$($Finding.Findings | Where-Object { $_.PolicyType -eq 'Fine-Grained Password Policy' } | ForEach-Object { @"
# Update FGPP: $($_.PolicyName)
Set-ADFineGrainedPasswordPolicy -Identity "$($_.PolicyName)" -MinPasswordLength 14
Write-Host "Updated FGPP $($_.PolicyName) to 14 characters" -ForegroundColor Green

"@ })

# STEP 4: Verify changes
Write-Host "`nUpdated Password Policies:" -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, MinPasswordLength, Precedence

# STEP 5: Consider password phrasephrase approach
# Instead of complex 14-character passwords, encourage passphrases:
# "CorrectHorseBatteryStaple" is more secure and memorable than "P@ssw0rd123!"

# STEP 6: Communication plan
Write-Host @"

USER COMMUNICATION:
1. Notify users of upcoming password policy change
2. Provide guidance on creating strong passphrases
3. Set a reasonable deadline for password changes
4. Prepare help desk for increased calls

PASSPHRASE GUIDANCE:
- Use 4-5 random words: "purple-elephant-flying-tuesday"
- Include a number or special character if required
- Avoid common phrases or song lyrics
- Consider using a password manager

"@ -ForegroundColor Cyan

# STEP 7: Monitor for weak passwords
# Consider implementing Azure AD Password Protection or
# running periodic password audits with tools like:
# - DSInternals Test-PasswordQuality
# - Hashcat rules against ntds.dit (authorized testing only)

# STEP 8: Implement account lockout to prevent brute force
# Recommended: 5 attempts, 30-minute lockout
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration, LockoutObservationWindow, LockoutThreshold

# Update if needed:
# Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"

"@
            return $commands
        }
    }
}

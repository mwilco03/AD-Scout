@{
    Id          = 'K-GoldenTicketRisk'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Golden Ticket Attack Risk - KRBTGT Password Age'
    Description = 'Detects when the KRBTGT account password has not been changed in an extended period. The KRBTGT password is used to encrypt all Kerberos TGT tickets. If compromised, attackers can forge Golden Tickets for persistent domain access. KRBTGT should be rotated at least every 180 days, and twice in succession if compromise is suspected.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'Golden Ticket Attack'; Url = 'https://attack.mitre.org/techniques/T1558/001/' }
        @{ Title = 'KRBTGT Account Password Reset'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/krbtgt-password-reset' }
        @{ Title = 'Detecting Golden Ticket Attacks'; Url = 'https://adsecurity.org/?p=1640' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0006')  # Persistence, Credential Access
        Techniques = @('T1558.001')          # Steal or Forge Kerberos Tickets: Golden Ticket
    }

    CIS   = @('5.4.3')
    STIG  = @('V-220931')
    ANSSI = @('R40', 'R41')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $kerbSettings = $Data.NetworkSecurity.KerberosSettings

        if ($kerbSettings -and $kerbSettings.KrbtgtPasswordAge) {
            $passwordAge = $kerbSettings.KrbtgtPasswordAge

            # Risk thresholds
            $riskLevel = 'Low'
            $risks = @()

            if ($passwordAge -gt 365) {
                $riskLevel = 'Critical'
                $risks += "KRBTGT password is $passwordAge days old (over 1 year)"
                $risks += 'If previously compromised, Golden Tickets remain valid'
                $risks += 'Attackers have had extended persistence window'
            }
            elseif ($passwordAge -gt 180) {
                $riskLevel = 'High'
                $risks += "KRBTGT password is $passwordAge days old (over 6 months)"
                $risks += 'Password should be rotated at least twice yearly'
            }
            elseif ($passwordAge -gt 90) {
                $riskLevel = 'Medium'
                $risks += "KRBTGT password is $passwordAge days old"
                $risks += 'Consider more frequent rotation for high-security environments'
            }

            # Additional risks
            if ($kerbSettings.RC4Enabled) {
                $risks += 'RC4 encryption enabled (vulnerable to cracking)'
            }
            if (-not $kerbSettings.AESEnabled) {
                $risks += 'AES encryption not enabled'
            }

            if ($riskLevel -ne 'Low' -or $risks.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    Account                 = 'KRBTGT'
                    PasswordLastChanged     = $kerbSettings.KrbtgtLastChanged
                    PasswordAgeDays         = $passwordAge
                    RC4Enabled              = $kerbSettings.RC4Enabled
                    AESEnabled              = $kerbSettings.AESEnabled
                    DESDisabled             = $kerbSettings.DESDisabled
                    RiskLevel               = $riskLevel
                    Risks                   = ($risks -join '; ')
                    GoldenTicketImpact      = @(
                        'Attacker can impersonate ANY user including Domain Admins',
                        'Access persists until KRBTGT rotated TWICE',
                        'Can access any resource in the domain',
                        'Tickets can be created offline without network access',
                        'Very difficult to detect without proper monitoring'
                    ) -join '; '
                    AttackTools             = 'Mimikatz, Rubeus, Impacket (ticketer.py)'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Rotate the KRBTGT password twice to invalidate any potential Golden Tickets. Implement regular rotation schedule.'
        Impact      = 'Medium - May cause temporary Kerberos authentication failures during rotation'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GOLDEN TICKET RISK - KRBTGT PASSWORD ROTATION
# ================================================================
# The KRBTGT account encrypts all TGT tickets in the domain.
# If compromised, attackers can create "Golden Tickets" that:
# - Impersonate ANY user (including Domain Admins)
# - Persist until KRBTGT is changed TWICE
# - Work offline - no need to contact DC

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"
# KRBTGT Password Age: $($item.PasswordAgeDays) days
# Last Changed: $($item.PasswordLastChanged)
# Risk Level: $($item.RiskLevel)
# RC4 Enabled: $($item.RC4Enabled) (should be disabled)
# AES Enabled: $($item.AESEnabled) (should be enabled)

# Identified Risks:
# $($item.Risks -replace '; ', "`n# ")

"@
            }

            $commands += @"

# ================================================================
# KRBTGT PASSWORD ROTATION PROCEDURE
# ================================================================
# IMPORTANT: Must be done TWICE with at least 10-24 hours between
# to ensure all DCs replicate and ticket max lifetime expires.

# Step 1: Check current KRBTGT status
Get-ADUser krbtgt -Properties PasswordLastSet, msDS-KeyVersionNumber | ``
    Select-Object PasswordLastSet, msDS-KeyVersionNumber

# Step 2: Verify AD replication is healthy
repadmin /replsummary

# Step 3: First password reset
# Use Microsoft's official KRBTGT reset script:
# https://github.com/microsoft/New-KrbtgtKeys.ps1

# Or manually:
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)

# Step 4: Verify replication
repadmin /syncall /AdeP
Start-Sleep -Seconds 300  # Wait for replication
repadmin /showrepl

# Step 5: Wait for ticket lifetime (typically 10 hours)
# Maximum ticket lifetime is configured in Default Domain Policy

# Step 6: Second password reset (CRITICAL!)
# This invalidates all Golden Tickets
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)

# Step 7: Verify again
repadmin /syncall /AdeP
Get-ADUser krbtgt -Properties PasswordLastSet, msDS-KeyVersionNumber

# ================================================================
# DISABLE RC4 ENCRYPTION (Optional but recommended)
# ================================================================

# Force AES-only encryption:
Set-ADUser krbtgt -KerberosEncryptionType 'AES128,AES256'

# Note: This may break older systems that don't support AES
# Test in non-production first!

# ================================================================
# MONITORING FOR GOLDEN TICKETS
# ================================================================

# Event ID 4769 (TGS Request) - Look for:
# - Ticket encryption type 0x17 (RC4) when AES is expected
# - Ticket lifetime longer than policy allows
# - Domain field doesn't match

# Event ID 4768 (TGT Request) - Look for:
# - Requests from suspicious sources
# - After-hours activity

# ================================================================
# RECOMMENDED ROTATION SCHEDULE
# ================================================================

# High Security: Every 40 days (before TGT lifetime expires twice)
# Standard: Every 90-180 days
# After Breach: Immediately rotate TWICE

# Create scheduled task for reminders:

`$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
`$action = New-ScheduledTaskAction -Execute "PowerShell.exe" ``
    -Argument "-Command `"Send-MailMessage -To 'security@domain.com' -Subject 'KRBTGT Rotation Reminder' -SmtpServer 'mail.domain.com'`""

"@
            return $commands
        }
    }
}

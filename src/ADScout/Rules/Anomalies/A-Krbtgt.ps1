@{
    Id          = 'A-Krbtgt'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Krbtgt Account Password Age'
    Description = 'The krbtgt account password has not been changed recently, making the domain vulnerable to Golden Ticket attacks. Attackers with access to the krbtgt hash can forge TGTs for any account.'
    Severity    = 'Critical'
    Weight      = 100
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Golden Ticket Attack'; Url = 'https://attack.mitre.org/techniques/T1558/001/' }
        @{ Title = 'Krbtgt Account Password Reset'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password' }
        @{ Title = 'KRBTGT Account Password Reset Script'; Url = 'https://github.com/microsoft/New-KrbtgtKeys.ps1' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0006')  # Persistence, Credential Access
        Techniques = @('T1558.001')          # Steal or Forge Kerberos Tickets: Golden Ticket
    }

    CIS   = @('5.21')
    STIG  = @('V-36451')
    ANSSI = @('vuln1_krbtgt')
    NIST  = @('IA-5', 'SC-12')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $thresholdDays = 180  # 6 months - should be rotated at least twice yearly

        $krbtgt = $Data | Where-Object { $_.SamAccountName -eq 'krbtgt' }

        if ($krbtgt) {
            $passwordAge = if ($krbtgt.PasswordLastSet) {
                ((Get-Date) - $krbtgt.PasswordLastSet).Days
            } else {
                9999  # Never set
            }

            if ($passwordAge -gt $thresholdDays) {
                $findings += [PSCustomObject]@{
                    Account           = 'krbtgt'
                    PasswordAgeDays   = $passwordAge
                    PasswordLastSet   = $krbtgt.PasswordLastSet
                    ThresholdDays     = $thresholdDays
                    RiskLevel         = if ($passwordAge -gt 365) { 'Critical' } elseif ($passwordAge -gt 180) { 'High' } else { 'Medium' }
                    GoldenTicketRisk  = 'High - Attackers with krbtgt hash can create unlimited TGTs'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Rotate the krbtgt password using Microsoft recommended procedures. Must be done twice with replication in between to ensure all DCs have the new key.'
        Impact      = 'Medium - All existing Kerberos tickets will be invalidated, causing temporary service interruptions'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: Krbtgt password is $($Finding.Findings[0].PasswordAgeDays) days old
# Golden Ticket attacks are possible if the hash has been compromised

# IMPORTANT: Follow Microsoft's documented procedure for krbtgt reset
# The password must be changed TWICE with time for replication between changes

# Step 1: Download and review Microsoft's official script
# https://github.com/microsoft/New-KrbtgtKeys.ps1

# Step 2: Run in "Informational" mode first
# .\New-KrbtgtKeys.ps1 -Mode RODCPurge_intendedInfoOnly

# Step 3: First password reset (wait for replication)
# .\New-KrbtgtKeys.ps1 -Mode Reset -PasswordChangeWaitTimeInMinutes 10

# Step 4: Verify replication across all DCs
# repadmin /syncall /AeD

# Step 5: Wait at least the maximum ticket lifetime (default 10 hours)
# before the second reset

# Step 6: Second password reset
# .\New-KrbtgtKeys.ps1 -Mode Reset

# Manual single reset (use script above for production):
# Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "<ComplexPassword>" -Force)

# Verify the change:
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet

"@
            return $commands
        }
    }
}

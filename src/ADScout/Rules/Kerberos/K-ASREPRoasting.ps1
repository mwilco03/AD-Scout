@{
    Id          = 'K-ASREPRoasting'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'AS-REP Roastable Accounts'
    Description = 'Identifies accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). These accounts are vulnerable to AS-REP roasting attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'AS-REP Roasting'; Url = 'https://attack.mitre.org/techniques/T1558/004/' }
        @{ Title = 'Roasting AS-REPs'; Url = 'https://blog.harmj0y.net/activedirectory/roasting-as-reps/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558.004')  # Steal or Forge Kerberos Tickets: AS-REP Roasting
    }

    CIS   = @('5.13')
    STIG  = @('V-36445')
    ANSSI = @('vuln1_asreproasting')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
        $DONT_REQUIRE_PREAUTH = 4194304

        foreach ($user in $Data) {
            if ($user.UserAccountControl -band $DONT_REQUIRE_PREAUTH) {
                $findings += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserAccountControl = $user.UserAccountControl
                    Enabled           = $user.Enabled
                    PasswordLastSet   = $user.PasswordLastSet
                    LastLogon         = $user.LastLogonDate
                    AdminCount        = $user.AdminCount
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable Kerberos pre-authentication for all accounts unless there is a documented business justification. Consider smart card authentication for privileged accounts.'
        Impact      = 'Low - Standard security setting'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable Kerberos pre-authentication for vulnerable accounts
# This is a standard security setting and should not break functionality

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Enable pre-auth for: $($item.SamAccountName)
Set-ADAccountControl -Identity '$($item.SamAccountName)' -DoesNotRequirePreAuth `$false

# Verify the change:
Get-ADUser -Identity '$($item.SamAccountName)' -Properties DoesNotRequirePreAuth | Select-Object Name, DoesNotRequirePreAuth

"@
            }
            return $commands
        }
    }
}

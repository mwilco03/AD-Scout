@{
    Id          = 'K-UnconstrainedDelegation'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Unconstrained Kerberos Delegation'
    Description = 'Identifies computers and users with unconstrained Kerberos delegation enabled. These systems cache user TGTs and can be abused to impersonate any user, including Domain Admins.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Unconstrained Delegation'; Url = 'https://attack.mitre.org/techniques/T1558/001/' }
        @{ Title = 'Exploiting Unconstrained Delegation'; Url = 'https://adsecurity.org/?p=1667' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1558.001')          # Steal or Forge Kerberos Tickets: Golden Ticket
    }

    CIS   = @('5.14')
    STIG  = @('V-36446')
    ANSSI = @('vuln1_unconstrained_delegation')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # TRUSTED_FOR_DELEGATION = 0x80000 (524288)
        $TRUSTED_FOR_DELEGATION = 524288

        foreach ($computer in $Data) {
            # Skip domain controllers (they require unconstrained delegation)
            if ($computer.IsDomainController) { continue }

            if ($computer.UserAccountControl -band $TRUSTED_FOR_DELEGATION) {
                $findings += [PSCustomObject]@{
                    Name               = $computer.Name
                    DNSHostName        = $computer.DNSHostName
                    OperatingSystem    = $computer.OperatingSystem
                    IsDomainController = $computer.IsDomainController
                    Enabled            = $computer.Enabled
                    LastLogon          = $computer.LastLogonDate
                    DistinguishedName  = $computer.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Replace unconstrained delegation with constrained delegation or Resource-Based Constrained Delegation (RBCD). Add sensitive accounts to the Protected Users group.'
        Impact      = 'High - Requires reconfiguration of services using delegation'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Unconstrained delegation detected on non-DC computers
# This is a critical security risk

# For each system:
# 1. Identify services requiring delegation
# 2. Configure constrained delegation to specific SPNs
# 3. Consider Resource-Based Constrained Delegation (RBCD)

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Computer: $($item.Name)
# DNS: $($item.DNSHostName)

# Step 1: Disable unconstrained delegation
Set-ADComputer -Identity '$($item.Name)' -TrustedForDelegation `$false

# Step 2: Configure constrained delegation (example)
# Set-ADComputer -Identity '$($item.Name)' -Add @{'msDS-AllowedToDelegateTo'='HTTP/target.domain.com'}

# Step 3: For RBCD (preferred):
# `$targetComputer = Get-ADComputer -Identity 'TargetServer'
# Set-ADComputer -Identity `$targetComputer -PrincipalsAllowedToDelegateToAccount (Get-ADComputer '$($item.Name)')

"@
            }

            $commands += @"


# Additionally, protect high-value accounts:
# Add to Protected Users group (prevents delegation):
# Add-ADGroupMember -Identity 'Protected Users' -Members 'AdminAccount'

# Mark sensitive accounts as 'Account is sensitive and cannot be delegated':
# Set-ADUser -Identity 'AdminAccount' -AccountNotDelegated `$true
"@
            return $commands
        }
    }
}

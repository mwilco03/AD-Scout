@{
    Id          = 'K-UnconstrainedDelegationComputers'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Computers with Unconstrained Delegation'
    Description = 'Detects computer accounts configured for unconstrained Kerberos delegation. Any user authenticating to these systems will have their TGT cached in memory, allowing attackers to harvest tickets and impersonate users, including Domain Admins.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Unconstrained Delegation Attack'; Url = 'https://attack.mitre.org/techniques/T1558/001/' }
        @{ Title = 'Kerberos Delegation Attacks'; Url = 'https://adsecurity.org/?p=1667' }
        @{ Title = 'Microsoft - Delegation Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1558.001', 'T1134')  # Golden Ticket, Token Impersonation
    }

    CIS   = @('5.4.5')
    STIG  = @('V-220934')
    ANSSI = @('R43', 'vuln1_delegation')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check computers for unconstrained delegation
        foreach ($computer in $Data.Computers) {
            if ($computer.TrustedForDelegation -and -not $computer.IsDomainController) {

                $findings += [PSCustomObject]@{
                    ComputerName            = $computer.Name
                    DNSHostName             = $computer.DNSHostName
                    OperatingSystem         = $computer.OperatingSystem
                    DistinguishedName       = $computer.DistinguishedName
                    TrustedForDelegation    = $computer.TrustedForDelegation
                    Enabled                 = $computer.Enabled
                    LastLogonDate           = $computer.LastLogonDate
                    IsDomainController      = $false
                    RiskLevel               = 'Critical'
                    AttackScenario          = @(
                        '1. Attacker compromises this server',
                        '2. Waits for or coerces privileged user authentication',
                        '3. Extracts TGT from LSASS memory (Mimikatz)',
                        '4. Uses TGT to authenticate as that user anywhere',
                        '5. If Domain Admin authenticates = full domain compromise'
                    ) -join ' -> '
                    AttackTools             = 'Mimikatz sekurlsa::tickets, Rubeus dump, SpoolSample, PrinterBug'
                    CoercionMethods         = @(
                        'Print Spooler bug (MS-RPRN)',
                        'PetitPotam (MS-EFSRPC)',
                        'DFSCoerce (MS-DFSNM)',
                        'Waiting for admin remote management'
                    ) -join '; '
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove unconstrained delegation and replace with constrained delegation or Resource-Based Constrained Delegation (RBCD).'
        Impact      = 'Medium - Applications using delegation may require reconfiguration'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: UNCONSTRAINED DELEGATION ON COMPUTERS
# ================================================================
# Unconstrained delegation caches the TGT of EVERY user who
# authenticates to the system. This is extremely dangerous:
#
# If a Domain Admin RDPs, runs Enter-PSSession, or even clicks
# a link to this server, their TGT is stored in memory.
# Attacker can extract it and become Domain Admin.

# ================================================================
# AFFECTED COMPUTERS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Computer: $($item.ComputerName)
# OS: $($item.OperatingSystem)
# DN: $($item.DistinguishedName)
# Attack: $($item.AttackScenario)

"@
            }

            $commands += @"

# ================================================================
# FIND ALL UNCONSTRAINED DELEGATION COMPUTERS
# ================================================================

Get-ADComputer -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation, OperatingSystem | ``
    Where-Object { `$_.DistinguishedName -notmatch 'Domain Controllers' } | ``
    Select-Object Name, OperatingSystem, DistinguishedName

# ================================================================
# REMOVE UNCONSTRAINED DELEGATION
# ================================================================

# For each affected computer:
"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove delegation from $($item.ComputerName):
Set-ADComputer -Identity '$($item.ComputerName)' -TrustedForDelegation `$false

"@
            }

            $commands += @"

# ================================================================
# MIGRATE TO CONSTRAINED DELEGATION
# ================================================================

# If the service requires delegation, use constrained delegation:

# Option 1: Traditional Constrained Delegation (requires SeEnableDelegation)
Set-ADComputer -Identity 'ServerName' ``
    -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/webserver.domain.com','MSSQLSvc/sqlserver.domain.com:1433')}

# Option 2: Resource-Based Constrained Delegation (RBCD) - Recommended
# Set on the TARGET service, not the source:
`$sourceComputer = Get-ADComputer -Identity 'SourceServer'
Set-ADComputer -Identity 'TargetServer' ``
    -PrincipalsAllowedToDelegateToAccount `$sourceComputer

# ================================================================
# PROTECT PRIVILEGED ACCOUNTS
# ================================================================

# Add high-value accounts to Protected Users group:
# (Prevents credential caching and delegation)
Add-ADGroupMember -Identity "Protected Users" -Members "Admin1", "Admin2"

# Or set on individual accounts:
Set-ADAccountControl -Identity "Admin1" -AccountNotDelegated `$true

# ================================================================
# MONITOR FOR DELEGATION ATTACKS
# ================================================================

# Enable auditing for Kerberos:
# Event ID 4768 - TGT Request
# Event ID 4769 - TGS Request
# Look for: S4U2Self, S4U2Proxy in ticket options

# Monitor for coercion attempts:
# Event ID 5145 - File share access (SpoolSample, PetitPotam)

"@
            return $commands
        }
    }
}

@{
    Id          = 'S-UnrestrictedJoin'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Unrestricted Domain Computer Join'
    Description = 'The ms-DS-MachineAccountQuota attribute allows authenticated users to join computers to the domain without explicit delegation. The default value of 10 enables any user to add up to 10 computer accounts, which can be abused for privilege escalation attacks.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'Machine Account Quota'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/default-workstation-numbers-join-domain' }
        @{ Title = 'RBCD Attack'; Url = 'https://attack.mitre.org/techniques/T1134/001/' }
        @{ Title = 'Computer Account Abuse'; Url = 'https://www.thehacker.recipes/a-d/movement/kerberos/delegations/rbcd' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1136.002', 'T1134.001')  # Create Account: Domain, Token Manipulation
    }

    CIS   = @('2.3.6.6')
    STIG  = @('V-63579')
    ANSSI = @('vuln2_machine_quota')
    NIST  = @('AC-6(1)')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $machineQuota = $null

            # Try to get the ms-DS-MachineAccountQuota value
            if ($Domain.'ms-DS-MachineAccountQuota') {
                $machineQuota = $Domain.'ms-DS-MachineAccountQuota'
            } else {
                # Query directly
                try {
                    $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
                    if ($Domain.DistinguishedName) {
                        $domainDN = $Domain.DistinguishedName
                    }

                    $searcher = [System.DirectoryServices.DirectorySearcher]::new()
                    $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                    $searcher.Filter = "(objectClass=domainDNS)"
                    $searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota") | Out-Null
                    $result = $searcher.FindOne()

                    if ($result -and $result.Properties["ms-ds-machineaccountquota"]) {
                        $machineQuota = $result.Properties["ms-ds-machineaccountquota"][0]
                    }
                } catch {
                    # Try AD cmdlet
                    try {
                        $machineQuota = (Get-ADDomain).DistinguishedName | ForEach-Object {
                            (Get-ADObject -Identity $_ -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
                        }
                    } catch {
                        $machineQuota = $null
                    }
                }
            }

            # Default is 10 if not explicitly set
            if ($null -eq $machineQuota) {
                $machineQuota = 10  # Default value
            }

            if ($machineQuota -gt 0) {
                $riskLevel = switch ($machineQuota) {
                    { $_ -ge 10 } { 'Medium' }
                    { $_ -ge 1 -and $_ -lt 10 } { 'Low' }
                    default { 'Info' }
                }

                $findings += [PSCustomObject]@{
                    DomainName                  = $Domain.Name
                    MachineAccountQuota         = $machineQuota
                    DefaultValue                = 10
                    Status                      = if ($machineQuota -gt 0) { 'Users can join computers to domain' } else { 'Restricted' }
                    RiskLevel                   = $riskLevel
                    AttackVector                = 'Any authenticated user can create machine accounts for RBCD, MAQ, or other attacks'
                    PotentialAbuse              = @(
                        'Resource-Based Constrained Delegation (RBCD) attack'
                        'Machine account password spraying'
                        'Kerberos delegation abuse'
                        'Hiding persistence via rogue computer accounts'
                    ) -join '; '
                }
            }
        } catch {
            $findings += [PSCustomObject]@{
                DomainName                  = $Domain.Name
                MachineAccountQuota         = 'Unable to determine'
                DefaultValue                = 10
                Status                      = 'Requires manual verification'
                RiskLevel                   = 'Unknown'
                AttackVector                = 'Default allows 10 computer accounts per user'
                PotentialAbuse              = 'Manual review required'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Set ms-DS-MachineAccountQuota to 0 and use explicit delegation for computer joining via security groups.'
        Impact      = 'Medium - Users will no longer be able to join computers. Must delegate this privilege to specific groups or accounts.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Restrict Domain Computer Join Privilege
# Current ms-DS-MachineAccountQuota: $($Finding.Findings[0].MachineAccountQuota)

# Step 1: Set MachineAccountQuota to 0
`$domainDN = (Get-ADDomain).DistinguishedName
Set-ADObject -Identity `$domainDN -Replace @{'ms-DS-MachineAccountQuota' = 0}

# Verify the change:
Get-ADObject -Identity `$domainDN -Properties 'ms-DS-MachineAccountQuota' |
    Select-Object DistinguishedName, 'ms-DS-MachineAccountQuota'

# Step 2: Delegate computer join rights to specific security group
# Create a delegation group:
New-ADGroup -Name "Computer Joiners" -GroupScope DomainLocal -Description "Users authorized to join computers to domain"

# Option A: Delegate rights on the entire domain (or specific OU)
`$ou = `$domainDN  # or "OU=Workstations,`$domainDN"
`$group = "Computer Joiners"

# Grant Create Computer Objects permission
dsacls "`$ou" /G "`$group:CC;computer"

# Grant delete and modify permissions for computers they create
dsacls "`$ou" /G "`$group:DC;computer"

# Option B: Use Group Policy to delegate (recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > User Rights Assignment > "Add workstations to domain"
# Add the "Computer Joiners" group

# Step 3: Review and clean up any rogue computer accounts
Get-ADComputer -Filter * -Properties Created, Description |
    Where-Object { `$_.Created -gt (Get-Date).AddDays(-30) -and -not `$_.Description } |
    Select-Object Name, Created, DistinguishedName |
    Format-Table -AutoSize

"@
            return $commands
        }
    }
}

<#
.SYNOPSIS
    Detects endpoints with excessive local administrators.

.DESCRIPTION
    Too many local administrators increases attack surface and makes
    privilege escalation easier for attackers.

.NOTES
    Rule ID    : ES-LocalAdminExcess
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-LocalAdminExcess'
    Name        = 'Excessive Local Administrators'
    Category    = 'EndpointSecurity'
    Model       = 'LocalAccounts'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 5
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1078.003')  # Valid Accounts: Local Accounts
    CIS         = @('5.6.1')
    STIG        = @('V-63859')
    ANSSI       = @('R29')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.LocalAccounts) {
            foreach ($endpoint in $ADData.EndpointData.LocalAccounts) {
                $admins = $endpoint.SecurityGroups.Administrators
                if ($admins -and $admins.MemberCount -gt 3) {
                    $memberNames = ($admins.Members | ForEach-Object { $_.Name }) -join ', '

                    $findings += [PSCustomObject]@{
                        Hostname       = $endpoint.Hostname
                        AdminCount     = $admins.MemberCount
                        Members        = $memberNames
                        Risk           = if ($admins.MemberCount -gt 10) { 'High' } else { 'Medium' }
                        Issue          = 'Excessive local administrators'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'AdminCount', 'Risk')
    DetailFormat     = '{Hostname}: {AdminCount} local administrators'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Review and reduce local administrators

# Current members: $($Finding.Members)

# Remove unnecessary local admins:
Remove-LocalGroupMember -Group 'Administrators' -Member 'DOMAIN\UnnecessaryUser'

# Best practices:
# 1. Use LAPS for local admin password (unique per machine)
# 2. Limit local admins to:
#    - Built-in Administrator (managed by LAPS)
#    - Domain Admins (for emergency access)
#    - Specific service accounts if required
# 3. Use Privileged Access Workstations (PAWs) for admin tasks
# 4. Implement Just-In-Time admin access where possible

# Audit local admin group:
Get-LocalGroupMember -Group 'Administrators'

"@
    }

    Description = 'Too many local administrators increase attack surface and lateral movement risk.'

    TechnicalExplanation = @"
Excessive local administrators create security risks:

1. Expanded Attack Surface
   - More accounts that can be compromised
   - Each admin account is a potential entry point

2. Lateral Movement
   - Attackers with one local admin can move laterally
   - Password reuse across machines enables pivoting

3. Privilege Escalation
   - More targets for credential theft
   - Easier to find vulnerable admin sessions

Recommended maximum: 3 local administrators
- Built-in Administrator (LAPS managed)
- Domain Admins group
- One break-glass account if required

Common excess causes:
- IT staff added individually instead of via groups
- Legacy accounts never removed
- Application installers adding service accounts
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts',
        'https://attack.mitre.org/techniques/T1078/003/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.LocalAccounts
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

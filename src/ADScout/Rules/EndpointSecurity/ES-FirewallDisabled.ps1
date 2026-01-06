<#
.SYNOPSIS
    Detects endpoints with Windows Firewall disabled.

.DESCRIPTION
    Windows Firewall provides essential network-level protection.
    Disabled firewall leaves systems exposed to network attacks.

.NOTES
    Rule ID    : ES-FirewallDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-FirewallDisabled'
    Name        = 'Windows Firewall Disabled'
    Category    = 'EndpointSecurity'
    Model       = 'NetworkSecurity'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 8
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1562.004')  # Impair Defenses: Disable or Modify System Firewall
    CIS         = @('9.1.1', '9.2.1', '9.3.1')
    STIG        = @('V-17415', 'V-17416', 'V-17417')
    ANSSI       = @('R49')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity) {
            foreach ($endpoint in $ADData.EndpointData.NetworkSecurity) {
                $disabledProfiles = @()

                foreach ($profile in $endpoint.Firewall) {
                    if ($profile.Enabled -ne $true) {
                        $disabledProfiles += $profile.Profile
                    }
                }

                if ($disabledProfiles.Count -gt 0) {
                    $risk = switch ($disabledProfiles.Count) {
                        1 { 'Medium' }
                        2 { 'High' }
                        3 { 'Critical' }
                        default { 'High' }
                    }

                    $findings += [PSCustomObject]@{
                        Hostname           = $endpoint.Hostname
                        DisabledProfiles   = $disabledProfiles -join ', '
                        DisabledCount      = $disabledProfiles.Count
                        Risk               = $risk
                        Issue              = 'Windows Firewall disabled on one or more profiles'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'DisabledProfiles', 'Risk')
    DetailFormat     = '{Hostname}: Firewall disabled on {DisabledProfiles}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Enable Windows Firewall

# Disabled profiles: $($Finding.DisabledProfiles)

# Enable all firewall profiles:
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable specific profile:
Set-NetFirewallProfile -Profile Domain -Enabled True
Set-NetFirewallProfile -Profile Private -Enabled True
Set-NetFirewallProfile -Profile Public -Enabled True

# Via GPO:
# Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security
# > Windows Defender Firewall Properties > [Profile] Tab > Firewall state = On

# Verify:
Get-NetFirewallProfile | Select-Object Name, Enabled

# Set default actions (recommended):
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

"@
    }

    Description = 'Windows Firewall is disabled, leaving the system exposed to network attacks.'

    TechnicalExplanation = @"
Windows Firewall provides host-based network filtering:

Firewall Profiles:
1. Domain - Connected to domain network
2. Private - Trusted home/work network
3. Public - Untrusted networks (coffee shop, airport)

Risks of disabled firewall:
- Direct exposure to network attacks
- No protection against lateral movement
- Worms and malware can spread freely
- Port scans reveal all services

Common attack vectors blocked by firewall:
- SMB attacks (EternalBlue, relay)
- RDP brute force
- DCOM/RPC attacks
- NetBIOS/LLMNR poisoning

Attackers disable firewall to:
- Enable reverse shells
- Allow C2 communication
- Facilitate lateral movement
- Expose additional attack surface

Best practice:
- Enable firewall on all profiles
- Block inbound by default
- Allow only required services
- Log blocked connections
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security',
        'https://attack.mitre.org/techniques/T1562/004/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

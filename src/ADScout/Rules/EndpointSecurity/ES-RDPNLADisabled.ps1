<#
.SYNOPSIS
    Detects endpoints with RDP Network Level Authentication disabled.

.DESCRIPTION
    NLA requires authentication before establishing RDP session,
    protecting against credential exposure and DoS attacks.

.NOTES
    Rule ID    : ES-RDPNLADisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-RDPNLADisabled'
    Name        = 'RDP Network Level Authentication Disabled'
    Category    = 'EndpointSecurity'
    Model       = 'NetworkSecurity'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 6
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1021.001')  # Remote Services: RDP
    CIS         = @('18.9.59.3.9.1')
    STIG        = @('V-63621')
    ANSSI       = @('R50')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity) {
            foreach ($endpoint in $ADData.EndpointData.NetworkSecurity) {
                $rdp = $endpoint.RDP

                if ($rdp.Enabled -eq $true -and $rdp.NLARequired -ne $true) {
                    $findings += [PSCustomObject]@{
                        Hostname      = $endpoint.Hostname
                        RDPEnabled    = $rdp.Enabled
                        NLARequired   = $rdp.NLARequired
                        Risk          = 'Medium'
                        Issue         = 'RDP enabled without Network Level Authentication'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'NLARequired', 'Risk')
    DetailFormat     = '{Hostname}: RDP NLA disabled'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Enable Network Level Authentication for RDP

# Via Registry:
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1

# Via System Properties:
# 1. Right-click This PC > Properties
# 2. Remote settings
# 3. Check "Allow connections only from computers running Remote Desktop with Network Level Authentication"

# Via GPO:
# Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services
# > Remote Desktop Session Host > Security
# > Require user authentication for remote connections by using NLA = Enabled

# Verify:
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select-Object UserAuthentication

"@
    }

    Description = 'RDP is enabled without NLA, allowing unauthenticated session initiation.'

    TechnicalExplanation = @"
Network Level Authentication (NLA) for RDP:

Without NLA:
- RDP session starts before authentication
- Server resources consumed before login
- Credentials entered on remote system
- Vulnerable to man-in-the-middle attacks

With NLA:
- Authentication happens before session
- Uses CredSSP/Kerberos
- Protects against:
  - DoS attacks (BlueKeep-style)
  - Credential interception
  - Unauthorized resource consumption

NLA Requirements:
- CredSSP support (Vista+/Server 2008+)
- Kerberos or NTLM credentials
- May break smart card scenarios (configurable)

Related vulnerabilities:
- CVE-2019-0708 (BlueKeep) - Pre-auth RCE, mitigated by NLA
- RDP credential theft via MITM
- DoS via session exhaustion

Best practice:
- Enable NLA on all RDP-enabled systems
- Use RDP Gateway for internet access
- Implement MFA for RDP where possible
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access',
        'https://attack.mitre.org/techniques/T1021/001/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

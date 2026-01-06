<#
.SYNOPSIS
    Detects endpoints with SMBv1 enabled.

.DESCRIPTION
    SMBv1 is vulnerable to EternalBlue and other exploits.
    Should be disabled on all modern systems.

.NOTES
    Rule ID    : ES-SMBv1Enabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-SMBv1Enabled'
    Name        = 'SMBv1 Protocol Enabled'
    Category    = 'EndpointSecurity'
    Model       = 'NetworkSecurity'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1210')  # Exploitation of Remote Services
    CIS         = @('9.1.1')
    STIG        = @('V-70639')
    ANSSI       = @('R48')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity) {
            foreach ($endpoint in $ADData.EndpointData.NetworkSecurity) {
                $smb = $endpoint.SMB

                if ($smb.SMB1Enabled -eq $true) {
                    $findings += [PSCustomObject]@{
                        Hostname                = $endpoint.Hostname
                        SMB1Enabled             = $smb.SMB1Enabled
                        SMBSigningRequired      = $smb.RequireSecuritySignature
                        SMBEncryption           = $smb.EncryptData
                        Risk                    = 'Critical'
                        Issue                   = 'SMBv1 enabled - vulnerable to EternalBlue'
                        Impact                  = 'Remote code execution, WannaCry/NotPetya ransomware'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'SMB1Enabled', 'Risk')
    DetailFormat     = '{Hostname}: SMBv1 enabled - CRITICAL'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Disable SMBv1

# Check current SMB status:
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol

# Disable SMBv1 server:
Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force

# Disable SMBv1 client (Windows 10+):
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# For Windows Server:
Remove-WindowsFeature FS-SMB1

# Via GPO:
# Computer Configuration > Administrative Templates > MS Security Guide
# > Configure SMB v1 server = Disabled
# > Configure SMB v1 client driver = Disabled

# Verify after reboot:
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# IMPORTANT: Test for legacy system dependencies before disabling

"@
    }

    Description = 'SMBv1 is enabled and vulnerable to critical exploits like EternalBlue.'

    TechnicalExplanation = @"
SMBv1 is a legacy protocol with critical security vulnerabilities:

1. EternalBlue (MS17-010)
   - Remote code execution via crafted SMB packets
   - Used by WannaCry, NotPetya, EternalRocks
   - No authentication required

2. Other SMBv1 vulnerabilities:
   - SMBLoris (DoS)
   - SMB relay attacks (easier than v2)
   - No encryption support
   - Weak signing implementation

Attack scenarios:
- WannaCry ransomware spread via SMBv1
- NotPetya caused billions in damages using SMBv1
- APT groups commonly exploit SMBv1 for initial access

Microsoft deprecation:
- SMBv1 disabled by default since Windows 10 1709
- Microsoft recommends disabling everywhere
- No new SMBv1 development or security fixes

Legacy dependencies:
- Some old printers, NAS devices, scanners
- Windows XP/Server 2003 (end of life)
- Some line-of-business applications
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3',
        'https://attack.mitre.org/techniques/T1210/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.NetworkSecurity
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

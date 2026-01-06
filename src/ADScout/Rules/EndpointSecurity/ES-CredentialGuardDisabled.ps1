<#
.SYNOPSIS
    Detects endpoints without Credential Guard enabled.

.DESCRIPTION
    Credential Guard uses virtualization-based security to isolate secrets,
    preventing pass-the-hash and pass-the-ticket attacks.

.NOTES
    Rule ID    : ES-CredentialGuardDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-CredentialGuardDisabled'
    Name        = 'Credential Guard Not Running'
    Category    = 'EndpointSecurity'
    Model       = 'CredentialProtection'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 6
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1003', 'T1550.002')
    CIS         = @('18.9.5.1')
    STIG        = @('V-63323')
    ANSSI       = @('R38')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.CredentialProtection) {
            foreach ($endpoint in $ADData.EndpointData.CredentialProtection) {
                $cg = $endpoint.CredentialGuard
                if ($cg -and $cg.Available -ne $false) {
                    if ($cg.CredentialGuardRunning -ne $true) {
                        $findings += [PSCustomObject]@{
                            Hostname                = $endpoint.Hostname
                            VBSRunning              = $cg.VBSRunning
                            CredentialGuardRunning  = $cg.CredentialGuardRunning
                            HVCIRunning             = $cg.HVCIRunning
                            Risk                    = 'Medium'
                            Issue                   = 'Credential Guard not protecting credentials'
                            Impact                  = 'Pass-the-hash and pass-the-ticket attacks possible'
                        }
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'VBSRunning', 'CredentialGuardRunning')
    DetailFormat     = '{Hostname}: VBS={VBSRunning}, CredGuard={CredentialGuardRunning}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Enable Credential Guard

# Prerequisites:
# - Windows 10 Enterprise/Education or Server 2016+
# - UEFI firmware with Secure Boot
# - Hardware virtualization (VT-x/AMD-V)
# - SLAT (Second Level Address Translation)
# - TPM 2.0 (recommended)

# Via GPO:
# Computer Configuration > Administrative Templates > System > Device Guard
# > Turn On Virtualization Based Security = Enabled
# > Credential Guard Configuration = Enabled with UEFI lock

# Via Registry:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Value 1 -Type DWord

# Verify after reboot:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

"@
    }

    Description = 'Credential Guard uses VBS to isolate credentials from the OS, preventing pass-the-hash attacks.'

    TechnicalExplanation = @"
Credential Guard isolates NTLM hashes, Kerberos tickets, and other secrets in a
separate virtualization container that the OS cannot access directly. This prevents:

- Credential theft even with kernel-level access
- Pass-the-hash attacks using stolen NTLM hashes
- Pass-the-ticket attacks using stolen Kerberos tickets
- Golden ticket attacks (cannot extract krbtgt hash)

VBS Status codes:
- 0: Not enabled
- 1: Enabled but not running
- 2: Running

SecurityServicesRunning:
- 1: Credential Guard
- 2: HVCI (Hypervisor-enforced Code Integrity)

Limitations:
- Does not protect against keyloggers or phishing
- Does not work with certain legacy protocols (NTLMv1, DES Kerberos)
- May have compatibility issues with some applications
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage',
        'https://attack.mitre.org/mitigations/M1017/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.CredentialProtection
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

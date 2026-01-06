<#
.SYNOPSIS
    Detects endpoints without LSA Protection (RunAsPPL) enabled.

.DESCRIPTION
    LSA Protection prevents unauthorized access to LSASS memory by running
    it as a Protected Process Light (PPL), blocking credential dumping tools.

.NOTES
    Rule ID    : ES-LSAProtectionDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-LSAProtectionDisabled'
    Name        = 'LSA Protection Not Enabled'
    Category    = 'EndpointSecurity'
    Model       = 'CredentialProtection'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 8
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1003.001')
    CIS         = @('18.3.5')
    STIG        = @('V-63599')
    ANSSI       = @('R36')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.CredentialProtection) {
            foreach ($endpoint in $ADData.EndpointData.CredentialProtection) {
                if ($endpoint.LSAProtection.Protected -ne $true -and $endpoint.LSAProtection.RunAsPPL -ne 1) {
                    $findings += [PSCustomObject]@{
                        Hostname           = $endpoint.Hostname
                        RunAsPPL           = $endpoint.LSAProtection.RunAsPPL
                        Risk               = 'High'
                        Issue              = 'LSASS not protected - vulnerable to credential dumping'
                        Impact             = 'Mimikatz and similar tools can extract credentials'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'RunAsPPL', 'Risk')
    DetailFormat     = '{Hostname}: LSA Protection disabled (RunAsPPL={RunAsPPL})'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Enable LSA Protection (RunAsPPL)

# Via Registry:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord

# Via GPO (Windows 8.1+):
# Computer Configuration > Administrative Templates > System > Local Security Authority
# > Configure LSASS to run as a protected process = Enabled with UEFI Lock

# IMPORTANT: Test thoroughly before deployment
# Some security products may not be compatible with PPL
# Reboot required for changes to take effect

"@
    }

    Description = 'LSA Protection (RunAsPPL) prevents credential dumping by running LSASS as a protected process.'

    TechnicalExplanation = @"
LSA Protection runs the Local Security Authority Subsystem Service (LSASS) as a
Protected Process Light (PPL). This prevents:

- Memory access from non-protected processes
- DLL injection into LSASS
- Credential dumping tools like Mimikatz

Without LSA Protection, an attacker with local admin can:
1. Open a handle to LSASS with PROCESS_VM_READ
2. Read memory containing NTLM hashes, Kerberos tickets, and potentially plaintext passwords
3. Use these credentials for pass-the-hash, pass-the-ticket attacks

Requirements:
- Windows 8.1 / Server 2012 R2 or later
- UEFI Secure Boot (recommended for UEFI Lock)
- Compatible security software (drivers must be signed)
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection',
        'https://attack.mitre.org/mitigations/M1025/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.CredentialProtection
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

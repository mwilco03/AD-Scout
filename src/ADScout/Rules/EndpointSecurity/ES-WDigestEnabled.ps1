<#
.SYNOPSIS
    Detects endpoints with WDigest credential caching enabled.

.DESCRIPTION
    WDigest UseLogonCredential=1 stores cleartext passwords in memory,
    allowing tools like Mimikatz to extract credentials directly.

.NOTES
    Rule ID    : ES-WDigestEnabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-WDigestEnabled'
    Name        = 'WDigest Credential Caching Enabled'
    Category    = 'EndpointSecurity'
    Model       = 'CredentialProtection'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1003.001')  # OS Credential Dumping: LSASS Memory
    CIS         = @('18.3.6')
    STIG        = @('V-63797')
    ANSSI       = @('R37')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.CredentialProtection) {
            foreach ($endpoint in $ADData.EndpointData.CredentialProtection) {
                if ($endpoint.WDigest.Vulnerable -eq $true -or $endpoint.WDigest.UseLogonCredential -eq 1) {
                    $findings += [PSCustomObject]@{
                        Hostname              = $endpoint.Hostname
                        UseLogonCredential    = $endpoint.WDigest.UseLogonCredential
                        Risk                  = 'Critical'
                        Issue                 = 'Cleartext passwords stored in LSASS memory'
                        Impact                = 'Credential theft via memory extraction (Mimikatz)'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'UseLogonCredential', 'Risk')
    DetailFormat     = '{Hostname}: WDigest UseLogonCredential={UseLogonCredential}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Disable WDigest credential caching

# Via Registry (immediate):
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord

# Via GPO (recommended for enterprise):
# Computer Configuration > Administrative Templates > MS Security Guide
# > WDigest Authentication (disabling may require KB2871997)

# Note: Reboot may be required for changes to take effect
# Verify with: Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

"@
    }

    Description = 'WDigest credential caching stores cleartext passwords in LSASS memory, enabling credential theft.'

    TechnicalExplanation = @"
When UseLogonCredential is set to 1, Windows stores cleartext passwords in LSASS
memory for WDigest authentication. This legacy feature (pre-Windows 8.1) allows
attackers with local admin access to extract passwords using tools like Mimikatz.

Attack scenario:
1. Attacker gains local admin on a workstation
2. Runs Mimikatz: sekurlsa::wdigest
3. Obtains cleartext passwords for all users who logged in
4. Uses credentials for lateral movement

Windows 8.1+ has this disabled by default, but it can be re-enabled by malware
or misconfiguration.
"@

    References = @(
        'https://attack.mitre.org/techniques/T1003/001/',
        'https://docs.microsoft.com/en-us/security-updates/securityadvisories/2016/2871997'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.CredentialProtection
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

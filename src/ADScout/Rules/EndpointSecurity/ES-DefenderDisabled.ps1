<#
.SYNOPSIS
    Detects endpoints with Windows Defender real-time protection disabled.

.DESCRIPTION
    Windows Defender provides essential endpoint protection. Disabled real-time
    protection leaves systems vulnerable to malware and attacker tools.

.NOTES
    Rule ID    : ES-DefenderDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-DefenderDisabled'
    Name        = 'Windows Defender Real-Time Protection Disabled'
    Category    = 'EndpointSecurity'
    Model       = 'AntiMalware'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1562.001')  # Impair Defenses: Disable or Modify Tools
    CIS         = @('8.1')
    STIG        = @('V-68847')
    ANSSI       = @('R45')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.DefenderStatus) {
            foreach ($endpoint in $ADData.EndpointData.DefenderStatus) {
                $status = $endpoint.MpComputerStatus
                $pref = $endpoint.MpPreference

                $issues = @()

                if ($status.RealTimeProtectionEnabled -eq $false -or $pref.DisableRealtimeMonitoring -eq $true) {
                    $issues += 'Real-time protection disabled'
                }
                if ($status.AntivirusEnabled -eq $false) {
                    $issues += 'Antivirus disabled'
                }
                if ($status.BehaviorMonitorEnabled -eq $false -or $pref.DisableBehaviorMonitoring -eq $true) {
                    $issues += 'Behavior monitoring disabled'
                }
                if ($status.IsTamperProtected -eq $false) {
                    $issues += 'Tamper protection disabled'
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Hostname                   = $endpoint.Hostname
                        RealTimeProtection         = $status.RealTimeProtectionEnabled
                        AntivirusEnabled           = $status.AntivirusEnabled
                        BehaviorMonitoring         = $status.BehaviorMonitorEnabled
                        TamperProtected            = $status.IsTamperProtected
                        Issues                     = $issues -join '; '
                        Risk                       = 'Critical'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'Issues', 'Risk')
    DetailFormat     = '{Hostname}: {Issues}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Re-enable Windows Defender protections

# Enable Real-Time Protection:
Set-MpPreference -DisableRealtimeMonitoring `$false

# Enable Behavior Monitoring:
Set-MpPreference -DisableBehaviorMonitoring `$false

# Enable IOAV Protection (download scanning):
Set-MpPreference -DisableIOAVProtection `$false

# Enable Tamper Protection (via Security Center or Intune):
# This cannot be set via PowerShell for security reasons

# Via GPO:
# Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
# > Turn off Microsoft Defender Antivirus = Disabled
# > Real-time Protection > Turn off real-time protection = Disabled

# Verify:
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IsTamperProtected

"@
    }

    Description = 'Windows Defender protection is disabled, leaving endpoints vulnerable to malware.'

    TechnicalExplanation = @"
Windows Defender provides multiple protection layers:

1. Real-Time Protection: Scans files as they are accessed
2. Behavior Monitoring: Detects suspicious process behavior
3. IOAV Protection: Scans downloaded files and attachments
4. Tamper Protection: Prevents malware from disabling Defender

Attackers commonly disable Defender before deploying payloads:
- Cobalt Strike: Uses service-based tampering
- Ransomware: Disables AV before encryption
- APT groups: Use GPO to disable across domain

Without these protections:
- Malware can execute undetected
- Credential dumping tools work freely
- Lateral movement is unimpeded
"@

    References = @(
        'https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus',
        'https://attack.mitre.org/techniques/T1562/001/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.DefenderStatus
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

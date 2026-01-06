<#
.SYNOPSIS
    Detects endpoints without PowerShell logging enabled.

.DESCRIPTION
    PowerShell logging provides visibility into script execution,
    essential for detecting malicious activity.

.NOTES
    Rule ID    : ES-PowerShellLoggingDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-PowerShellLoggingDisabled'
    Name        = 'PowerShell Logging Not Enabled'
    Category    = 'EndpointSecurity'
    Model       = 'AuditLogging'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 6
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1059.001')  # Command and Scripting Interpreter: PowerShell
    CIS         = @('8.8')
    STIG        = @('V-68819')
    ANSSI       = @('R47')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.PowerShellSecurity) {
            foreach ($endpoint in $ADData.EndpointData.PowerShellSecurity) {
                $logging = $endpoint.Logging
                $issues = @()

                if ($logging.ScriptBlockLogging -ne $true) {
                    $issues += 'ScriptBlock logging disabled'
                }
                if ($logging.ModuleLogging -ne $true) {
                    $issues += 'Module logging disabled'
                }
                if ($endpoint.V2Enabled -eq $true) {
                    $issues += 'PowerShell v2 enabled (bypasses logging)'
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Hostname             = $endpoint.Hostname
                        ScriptBlockLogging   = $logging.ScriptBlockLogging
                        ModuleLogging        = $logging.ModuleLogging
                        V2Enabled            = $endpoint.V2Enabled
                        LanguageMode         = $endpoint.LanguageMode
                        Issues               = $issues -join '; '
                        Risk                 = if ($endpoint.V2Enabled) { 'High' } else { 'Medium' }
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
# Enable PowerShell logging

# Enable Script Block Logging (GPO recommended):
# Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
# > Turn on PowerShell Script Block Logging = Enabled

# Via Registry:
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Value 1

# Enable Module Logging:
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1

# Disable PowerShell v2 (if not required):
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Verify:
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

"@
    }

    Description = 'PowerShell logging is not enabled, limiting visibility into script execution.'

    TechnicalExplanation = @"
PowerShell is heavily used by attackers for:
- Fileless malware execution
- Credential dumping
- Lateral movement
- Command and control

Logging types:
1. Script Block Logging (Event ID 4104)
   - Records all PowerShell script content
   - Includes deobfuscated scripts
   - Critical for forensics

2. Module Logging (Event ID 4103)
   - Records pipeline execution details
   - Shows cmdlet/function calls
   - Less verbose than script block

3. Transcription
   - Full text output of sessions
   - Useful but generates large logs

PowerShell v2 Risk:
- Lacks AMSI (Antimalware Scan Interface)
- No script block logging
- Used by attackers to bypass security
- Should be disabled if not required
"@

    References = @(
        'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows',
        'https://attack.mitre.org/techniques/T1059/001/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.PowerShellSecurity
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

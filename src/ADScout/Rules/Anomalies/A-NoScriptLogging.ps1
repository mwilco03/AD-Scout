@{
    Id          = 'A-NoScriptLogging'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'PowerShell Script Block Logging Disabled'
    Description = 'PowerShell Script Block Logging is not enabled on Domain Controllers. This prevents detection of malicious PowerShell activity including obfuscated commands, fileless malware, and post-exploitation frameworks like Empire, PowerSploit, and Cobalt Strike.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'PowerShell Logging'; Url = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging' }
        @{ Title = 'Detecting Malicious PowerShell'; Url = 'https://attack.mitre.org/techniques/T1059/001/' }
        @{ Title = 'PowerShell Security'; Url = 'https://devblogs.microsoft.com/powershell/powershell-the-blue-team/' }
    )

    MITRE = @{
        Tactics    = @('TA0002', 'TA0005')  # Execution, Defense Evasion
        Techniques = @('T1059.001', 'T1562.003')  # PowerShell, Impair Command History Logging
    }

    CIS   = @('18.9.100.1', '18.9.100.2')
    STIG  = @('V-63351', 'V-63353')
    ANSSI = @('vuln1_powershell_logging')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            $scriptBlockLogging = $null
            $moduleLogging = $null
            $transcription = $null

            try {
                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local check
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

                    # Script Block Logging
                    $sblPath = "$regPath\ScriptBlockLogging"
                    $scriptBlockLogging = Get-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue |
                                          Select-Object -ExpandProperty EnableScriptBlockLogging

                    # Module Logging
                    $mlPath = "$regPath\ModuleLogging"
                    $moduleLogging = Get-ItemProperty -Path $mlPath -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue |
                                     Select-Object -ExpandProperty EnableModuleLogging

                    # Transcription
                    $transPath = "$regPath\Transcription"
                    $transcription = Get-ItemProperty -Path $transPath -Name 'EnableTranscripting' -ErrorAction SilentlyContinue |
                                     Select-Object -ExpandProperty EnableTranscripting
                } else {
                    # Remote check
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.Name)

                        $sblKey = $reg.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging')
                        if ($sblKey) {
                            $scriptBlockLogging = $sblKey.GetValue('EnableScriptBlockLogging')
                            $sblKey.Close()
                        }

                        $mlKey = $reg.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging')
                        if ($mlKey) {
                            $moduleLogging = $mlKey.GetValue('EnableModuleLogging')
                            $mlKey.Close()
                        }

                        $transKey = $reg.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription')
                        if ($transKey) {
                            $transcription = $transKey.GetValue('EnableTranscripting')
                            $transKey.Close()
                        }

                        $reg.Close()
                    } catch {
                        # Remote registry access failed
                    }
                }

                $issues = @()

                if ($scriptBlockLogging -ne 1) {
                    $issues += 'Script Block Logging disabled'
                }
                if ($moduleLogging -ne 1) {
                    $issues += 'Module Logging disabled'
                }
                if ($transcription -ne 1) {
                    $issues += 'Transcription disabled'
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        DomainController        = $dc.Name
                        OperatingSystem         = $dc.OperatingSystem
                        ScriptBlockLogging      = if ($scriptBlockLogging -eq 1) { 'Enabled' } else { 'Disabled' }
                        ModuleLogging           = if ($moduleLogging -eq 1) { 'Enabled' } else { 'Disabled' }
                        Transcription           = if ($transcription -eq 1) { 'Enabled' } else { 'Disabled' }
                        Issues                  = $issues -join '; '
                        RiskLevel               = if (-not $scriptBlockLogging) { 'High' } else { 'Medium' }
                        Impact                  = 'Cannot detect malicious PowerShell execution'
                        AttackVector            = 'Empire, PowerSploit, Cobalt Strike, mimikatz, obfuscated scripts'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController        = $dc.Name
                    OperatingSystem         = $dc.OperatingSystem
                    ScriptBlockLogging      = 'Unable to determine'
                    ModuleLogging           = 'Unable to determine'
                    Transcription           = 'Unable to determine'
                    Issues                  = "Query failed: $_"
                    RiskLevel               = 'Unknown'
                    Impact                  = 'Manual verification required'
                    AttackVector            = 'Unknown logging status'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable PowerShell Script Block Logging, Module Logging, and optionally Transcription via Group Policy on all Domain Controllers and sensitive systems.'
        Impact      = 'Low - Logging has minimal performance impact. May generate significant log volume that needs to be stored/forwarded.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable PowerShell Logging on Domain Controllers
# DCs Missing Logging: $($Finding.Findings.Count)

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell

# Turn on Script Block Logging = Enabled
# Turn on Module Logging = Enabled (log all modules: *)
# Turn on PowerShell Transcription = Enabled (optional, creates transcript files)

# Option 2: Configure via Registry:

# Script Block Logging (CRITICAL - enables Event ID 4104)
`$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path `$regPath -Force | Out-Null
Set-ItemProperty -Path `$regPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
Set-ItemProperty -Path `$regPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord

# Module Logging (enables Event ID 4103)
`$mlPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path `$mlPath -Force | Out-Null
Set-ItemProperty -Path `$mlPath -Name 'EnableModuleLogging' -Value 1 -Type DWord

# Log all modules
`$modulePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
New-Item -Path `$modulePath -Force | Out-Null
Set-ItemProperty -Path `$modulePath -Name '*' -Value '*' -Type String

# Transcription (optional - creates files)
`$transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
New-Item -Path `$transPath -Force | Out-Null
Set-ItemProperty -Path `$transPath -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-ItemProperty -Path `$transPath -Name 'EnableInvocationHeader' -Value 1 -Type DWord
# Set-ItemProperty -Path `$transPath -Name 'OutputDirectory' -Value 'C:\PSTranscripts' -Type String

# Verify configuration:
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue

# Important Event IDs to monitor:
# 4103 - Module Logging
# 4104 - Script Block Logging (includes decoded obfuscated scripts!)
# 4105 - Script Block Start
# 4106 - Script Block Stop

# Forward Microsoft-Windows-PowerShell/Operational log to SIEM

"@
            return $commands
        }
    }
}

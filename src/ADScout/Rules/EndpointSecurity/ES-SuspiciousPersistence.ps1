<#
.SYNOPSIS
    Detects suspicious persistence mechanisms on endpoints.

.DESCRIPTION
    Identifies Run keys, scheduled tasks, and WMI subscriptions
    that may indicate malware persistence.

.NOTES
    Rule ID    : ES-SuspiciousPersistence
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-SuspiciousPersistence'
    Name        = 'Suspicious Persistence Mechanisms'
    Category    = 'EndpointSecurity'
    Model       = 'Persistence'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1547.001', 'T1053.005', 'T1546.003')  # Boot/Logon Autostart, Scheduled Task, WMI Event
    CIS         = @()
    STIG        = @()
    ANSSI       = @('R46')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        # Suspicious patterns
        $suspiciousPatterns = @(
            'powershell.*-enc',
            'powershell.*-e\s',
            'powershell.*downloadstring',
            'powershell.*iex',
            'cmd.*/c.*http',
            'mshta.*http',
            'wscript.*http',
            'cscript.*http',
            'certutil.*-urlcache',
            'bitsadmin.*transfer',
            'regsvr32.*/s.*/u',
            '\\AppData\\Local\\Temp\\',
            '\\ProgramData\\[^\\]+\.exe',
            '\\Users\\Public\\',
            'base64'
        )

        if ($ADData.EndpointData -and $ADData.EndpointData.PersistenceMechanisms) {
            foreach ($endpoint in $ADData.EndpointData.PersistenceMechanisms) {
                $suspicious = @()

                # Check Run Keys
                foreach ($key in $endpoint.RunKeys) {
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($key.Value -match $pattern) {
                            $suspicious += [PSCustomObject]@{
                                Type    = 'RunKey'
                                Name    = $key.Name
                                Value   = $key.Value
                                Path    = $key.Path
                            }
                            break
                        }
                    }
                }

                # Check Scheduled Tasks
                foreach ($task in $endpoint.ScheduledTasks) {
                    $actions = $task.Actions -join ' '
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($actions -match $pattern -or $task.TaskName -match '^[a-f0-9]{8,}$') {
                            $suspicious += [PSCustomObject]@{
                                Type     = 'ScheduledTask'
                                Name     = $task.TaskName
                                Value    = $actions
                                Path     = $task.TaskPath
                            }
                            break
                        }
                    }
                }

                # Check WMI Subscriptions
                foreach ($wmi in $endpoint.WMISubscriptions) {
                    if ($wmi.CommandLineTemplate) {
                        $suspicious += [PSCustomObject]@{
                            Type     = 'WMISubscription'
                            Name     = $wmi.Name
                            Value    = $wmi.CommandLineTemplate
                            Path     = 'root\subscription'
                        }
                    }
                }

                if ($suspicious.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Hostname         = $endpoint.Hostname
                        SuspiciousCount  = $suspicious.Count
                        Items            = ($suspicious | ForEach-Object { "$($_.Type): $($_.Name)" }) -join '; '
                        Details          = $suspicious
                        Risk             = if ($suspicious.Count -gt 3) { 'Critical' } else { 'High' }
                        Issue            = 'Suspicious persistence mechanisms detected'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'SuspiciousCount', 'Items', 'Risk')
    DetailFormat     = '{Hostname}: {SuspiciousCount} suspicious items - {Items}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# INVESTIGATE BEFORE REMOVING - may indicate active compromise

# ============================================================
# SUSPICIOUS ITEMS FOUND:
# ============================================================
$($Finding.Items)

# ============================================================
# INVESTIGATION STEPS:
# ============================================================

# 1. Isolate the system if active compromise suspected
# 2. Collect forensic evidence before remediation
# 3. Check for related IOCs across the environment

# ============================================================
# REMOVAL COMMANDS (use with caution):
# ============================================================

# Remove Run Key:
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SuspiciousEntry'

# Remove Scheduled Task:
Unregister-ScheduledTask -TaskName 'SuspiciousTask' -Confirm:`$false

# Remove WMI Subscription:
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Where-Object { `$_.Name -eq 'SuspiciousFilter' } | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Where-Object { `$_.Name -eq 'SuspiciousConsumer' } | Remove-CimInstance

# ============================================================
# POST-REMEDIATION:
# ============================================================
# 1. Monitor for re-creation of persistence
# 2. Hunt for related malware
# 3. Review logs for lateral movement
# 4. Consider full incident response if needed

"@
    }

    Description = 'Suspicious persistence mechanisms that may indicate malware or attacker presence.'

    TechnicalExplanation = @"
Common persistence mechanisms abused by attackers:

1. Registry Run Keys (T1547.001)
   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   - Execute on user logon

2. Scheduled Tasks (T1053.005)
   - Can run as SYSTEM
   - Survive reboots
   - Can be triggered by various events

3. WMI Event Subscriptions (T1546.003)
   - "Fileless" persistence
   - Difficult to detect
   - Can monitor for specific events

Suspicious indicators:
- Encoded PowerShell commands (-enc, -e)
- Download cradles (DownloadString, IEX)
- Living-off-the-land binaries (mshta, certutil, bitsadmin)
- Execution from temp/public directories
- Random/GUID-like names

These patterns are commonly used by:
- Cobalt Strike beacons
- Emotet/Trickbot
- APT groups
- Ransomware pre-encryption
"@

    References = @(
        'https://attack.mitre.org/techniques/T1547/001/',
        'https://attack.mitre.org/techniques/T1053/005/',
        'https://attack.mitre.org/techniques/T1546/003/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.PersistenceMechanisms
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}

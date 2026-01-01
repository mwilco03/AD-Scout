<#
.SYNOPSIS
    Detects privileged scheduled tasks that could be persistence mechanisms.

.DESCRIPTION
    Scheduled tasks running as SYSTEM or privileged accounts on domain controllers
    and sensitive systems can be used for persistence. This rule identifies high-risk
    scheduled tasks.

.NOTES
    Rule ID    : PERS-ScheduledTaskPriv
    Category   : Persistence
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'PERS-ScheduledTaskPriv'
    Version     = '1.0.0'
    Category    = 'Persistence'
    Title       = 'Privileged Scheduled Tasks'
    Description = 'Identifies scheduled tasks running with elevated privileges on sensitive systems that could be used for persistence.'
    Severity    = 'Medium'
    Weight      = 40
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Scheduled Task Persistence'; Url = 'https://attack.mitre.org/techniques/T1053/005/' }
        @{ Title = 'Scheduled Task Security'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events' }
        @{ Title = 'Task Scheduler Hardening'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002')  # Persistence, Execution
        Techniques = @('T1053.005', 'T1078.002')  # Scheduled Task, Domain Accounts
    }

    CIS   = @('18.9.48.1')
    STIG  = @('V-254448')
    ANSSI = @('R43')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Known legitimate Microsoft tasks to exclude
        $excludedTasks = @(
            'Microsoft',
            'Windows',
            'OneDrive',
            'Google',
            'Adobe',
            'MicrosoftEdge'
        )

        # Suspicious indicators
        $suspiciousIndicators = @(
            'powershell',
            'cmd.exe',
            'wscript',
            'cscript',
            'mshta',
            'rundll32',
            'regsvr32',
            'certutil',
            'bitsadmin',
            'temp',
            'tmp',
            'appdata',
            'public'
        )

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $tasks = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        param($excludedTasks, $suspiciousIndicators)

                        $results = @()

                        # Get all scheduled tasks
                        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                            $_.State -ne 'Disabled' -and
                            $_.TaskPath -notmatch ($excludedTasks -join '|')
                        }

                        foreach ($task in $allTasks) {
                            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

                            # Get task principal (run as)
                            $principal = $task.Principal
                            $runAs = $principal.UserId
                            $runLevel = $principal.RunLevel

                            # Get actions
                            $actions = $task.Actions | ForEach-Object {
                                "$($_.Execute) $($_.Arguments)"
                            }
                            $actionString = $actions -join '; '

                            # Check for suspicious characteristics
                            $suspicious = @()

                            # Running as SYSTEM
                            if ($runAs -match 'SYSTEM|LocalSystem') {
                                $suspicious += 'Runs as SYSTEM'
                            }

                            # Running with highest privileges
                            if ($runLevel -eq 'Highest') {
                                $suspicious += 'Highest privileges'
                            }

                            # Suspicious commands in action
                            foreach ($indicator in $suspiciousIndicators) {
                                if ($actionString -match $indicator) {
                                    $suspicious += "Contains: $indicator"
                                    break
                                }
                            }

                            # Task created recently
                            if ($taskInfo.NextRunTime -or $task.Date) {
                                try {
                                    $createDate = if ($task.Date) { [DateTime]$task.Date } else { $null }
                                    if ($createDate -and $createDate -gt (Get-Date).AddDays(-30)) {
                                        $suspicious += 'Created in last 30 days'
                                    }
                                } catch {}
                            }

                            # Hidden task
                            if ($task.Settings.Hidden) {
                                $suspicious += 'Hidden task'
                            }

                            # Task in root path (not in subfolder)
                            if ($task.TaskPath -eq '\') {
                                $suspicious += 'In root task path'
                            }

                            # Running from user-writable location
                            if ($actionString -match 'Users|Temp|AppData|Public|Downloads') {
                                $suspicious += 'Runs from user-writable location'
                            }

                            if ($suspicious.Count -gt 0) {
                                $results += @{
                                    TaskName = $task.TaskName
                                    TaskPath = $task.TaskPath
                                    State = $task.State.ToString()
                                    RunAs = $runAs
                                    RunLevel = $runLevel.ToString()
                                    Actions = $actionString
                                    LastRunTime = if ($taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString() } else { 'Never' }
                                    NextRunTime = if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString() } else { 'Not scheduled' }
                                    Suspicious = $suspicious
                                    Hidden = $task.Settings.Hidden
                                }
                            }
                        }

                        return $results
                    } -ArgumentList $excludedTasks, $suspiciousIndicators -ErrorAction SilentlyContinue

                    foreach ($task in $tasks) {
                        $riskLevel = 'Medium'
                        if ($task.Suspicious -match 'SYSTEM|Highest|Hidden') {
                            $riskLevel = 'High'
                        }
                        if ($task.Suspicious.Count -ge 3) {
                            $riskLevel = 'High'
                        }

                        $findings += [PSCustomObject]@{
                            DomainController = $dcName
                            TaskName         = $task.TaskName
                            TaskPath         = $task.TaskPath
                            State            = $task.State
                            RunAs            = $task.RunAs
                            RunLevel         = $task.RunLevel
                            Actions          = if ($task.Actions.Length -gt 200) { $task.Actions.Substring(0,200) + '...' } else { $task.Actions }
                            LastRunTime      = $task.LastRunTime
                            Hidden           = $task.Hidden
                            SuspiciousFlags  = ($task.Suspicious -join '; ')
                            RiskLevel        = $riskLevel
                            DistinguishedName = $dc.DistinguishedName
                        }
                    }

                } catch {
                    # Report check failure
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and validate all privileged scheduled tasks. Remove unauthorized tasks and implement monitoring.'
        Impact      = 'Low - Review process; removal may affect legitimate automation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Privileged Scheduled Task Review
#############################################################################
#
# Scheduled tasks running with elevated privileges can be persistence mechanisms.
# Attackers create tasks to maintain access after initial compromise.
#
# Suspicious tasks identified:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.TaskName) ($($_.SuspiciousFlags))" } | Out-String)

#############################################################################
# Step 1: Review Suspicious Tasks
#############################################################################

# For each Domain Controller, review tasks:
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Write-Host "`n=== `$(`$dc.HostName) ===" -ForegroundColor Cyan

    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # List non-Microsoft tasks running as SYSTEM
        Get-ScheduledTask | Where-Object {
            `$_.Principal.UserId -match 'SYSTEM' -and
            `$_.TaskPath -notmatch 'Microsoft|Windows'
        } | ForEach-Object {
            `$info = Get-ScheduledTaskInfo -TaskName `$_.TaskName -TaskPath `$_.TaskPath
            [PSCustomObject]@{
                Name = `$_.TaskName
                Path = `$_.TaskPath
                State = `$_.State
                Action = (`$_.Actions | ForEach-Object { `$_.Execute }) -join '; '
                LastRun = `$info.LastRunTime
            }
        } | Format-Table -AutoSize
    }
}

#############################################################################
# Step 2: Investigate Specific Tasks
#############################################################################

# Get detailed information about a suspicious task:
`$taskName = "SuspiciousTaskName"  # Replace with actual task name
`$taskPath = "\"  # Replace with actual path

`$task = Get-ScheduledTask -TaskName `$taskName -TaskPath `$taskPath
`$task | Select-Object *
`$task.Actions | Select-Object *
`$task.Triggers | Select-Object *
`$task.Principal | Select-Object *

#############################################################################
# Step 3: Remove Malicious Tasks
#############################################################################

# Disable task first (reversible):
# Disable-ScheduledTask -TaskName `$taskName -TaskPath `$taskPath

# Unregister task (removes it):
# Unregister-ScheduledTask -TaskName `$taskName -TaskPath `$taskPath -Confirm:`$false

# Export task for forensics before removal:
# Export-ScheduledTask -TaskName `$taskName -TaskPath `$taskPath | Out-File "C:\Forensics\`$taskName.xml"

#############################################################################
# Step 4: Restrict Task Creation
#############################################################################

# Remove ability for non-admins to create scheduled tasks:
# Via GPO: Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> User Rights Assignment
# -> "Log on as a batch job" - Remove non-admin groups

# Restrict task folder permissions:
`$taskFolder = "C:\Windows\System32\Tasks"
`$acl = Get-Acl `$taskFolder
# Remove write access for non-admin users

#############################################################################
# Step 5: Enable Scheduled Task Auditing
#############################################################################

# Enable task scheduler operational log:
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

# Monitor for task creation/modification:
# Event ID 106: Task registered
# Event ID 140: Task updated
# Event ID 141: Task deleted
# Event ID 200: Action started
# Event ID 201: Action completed

Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' `
    -FilterXPath "*[System[(EventID=106 or EventID=140)]]" `
    -MaxEvents 50 | Format-Table TimeCreated, Id, Message -Wrap

#############################################################################
# Step 6: Create Baseline of Legitimate Tasks
#############################################################################

# Export current tasks for baseline:
`$baseline = @()
foreach (`$dc in `$dcs) {
    `$tasks = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Get-ScheduledTask | Where-Object { `$_.State -ne 'Disabled' } |
            Select-Object TaskName, TaskPath, @{N='RunAs';E={`$_.Principal.UserId}},
                @{N='Action';E={(`$_.Actions | ForEach-Object { `$_.Execute }) -join ';'}}
    }
    `$baseline += `$tasks
}
`$baseline | Export-Csv -Path "C:\Baseline\ScheduledTasks_`$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

#############################################################################
# Step 7: Implement Detection Rules
#############################################################################

# Create SIEM rule for suspicious task creation:
# - Task created on Domain Controller
# - Task runs as SYSTEM or privileged account
# - Task action contains suspicious commands
# - Task created by non-admin user

# Example Sigma rule:
# title: Suspicious Scheduled Task on Domain Controller
# logsource:
#   product: windows
#   service: taskscheduler
# detection:
#   selection:
#     EventID: 106
#   filter:
#     TaskName|startswith: '\Microsoft\'
#   condition: selection and not filter

"@
            return $commands
        }
    }
}

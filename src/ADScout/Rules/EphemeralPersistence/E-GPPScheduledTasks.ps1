@{
    Id          = 'E-GPPScheduledTasks'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'Scheduled Tasks Deployed via Group Policy Preferences'
    Description = 'Detects scheduled tasks configured through Group Policy Preferences. GPP can deploy scheduled tasks to domain computers, which is a powerful persistence mechanism. Attackers can abuse this to run malicious code as SYSTEM across multiple machines. This rule enumerates ScheduledTasks.xml files in SYSVOL and analyzes their contents.'
    Severity    = 'High'
    Weight      = 25

    References  = @(
        @{ Title = 'GPP Scheduled Tasks'; Url = 'https://attack.mitre.org/techniques/T1053/005/' }
        @{ Title = 'GPO Persistence'; Url = 'https://adsecurity.org/?p=2716' }
        @{ Title = 'Scheduled Task Abuse'; Url = 'https://pentestlab.blog/2019/10/08/persistence-scheduled-tasks/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002', 'TA0004')  # Persistence, Execution, Privilege Escalation
        Techniques = @('T1053.005', 'T1484.001')  # Scheduled Task, GPO Modification
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_gpp_tasks')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get SYSVOL path
        $domainName = if ($Domain.Name) { $Domain.Name } elseif ($Domain.DNSRoot) { $Domain.DNSRoot } else { $env:USERDNSDOMAIN }
        $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"

        if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                GPOName       = 'N/A'
                GPOId         = 'N/A'
                TaskName      = 'Error'
                TaskAction    = 'Unable to access SYSVOL'
                RiskLevel     = 'Unknown'
                RiskFactors   = "Cannot access: $sysvolPath"
            })
        }

        # Suspicious patterns in task commands
        $suspiciousPatterns = @(
            @{ Pattern = 'powershell.*-enc'; Desc = 'Encoded PowerShell' }
            @{ Pattern = 'powershell.*-e\s'; Desc = 'Encoded PowerShell (short)' }
            @{ Pattern = 'bypass|hidden|noprofile'; Desc = 'PowerShell evasion' }
            @{ Pattern = 'iex|invoke-expression|downloadstring'; Desc = 'Dynamic execution' }
            @{ Pattern = 'cmd.*\/c'; Desc = 'Command prompt execution' }
            @{ Pattern = 'mshta|wscript|cscript'; Desc = 'Script host' }
            @{ Pattern = 'rundll32|regsvr32|certutil'; Desc = 'LOLBin' }
            @{ Pattern = 'http:|https:|ftp:'; Desc = 'URL reference' }
            @{ Pattern = '\\\\[^\\]+\\'; Desc = 'UNC path' }
            @{ Pattern = '\\temp\\|\\tmp\\|%temp%'; Desc = 'Temp directory' }
        )

        try {
            # Find all ScheduledTasks.xml files
            $taskFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter 'ScheduledTasks.xml' -ErrorAction SilentlyContinue

            foreach ($taskFile in $taskFiles) {
                try {
                    # Extract GPO ID from path
                    $gpoId = ($taskFile.FullName -split '\\Policies\\')[1] -split '\\' | Select-Object -First 1

                    # Get GPO name
                    $gpoName = $gpoId
                    try {
                        if (Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue) {
                            Import-Module GroupPolicy -ErrorAction SilentlyContinue
                            $gpo = Get-GPO -Guid $gpoId.Trim('{}') -ErrorAction SilentlyContinue
                            if ($gpo) { $gpoName = $gpo.DisplayName }
                        }
                    }
                    catch { }

                    # Parse XML
                    [xml]$xml = Get-Content $taskFile.FullName -ErrorAction SilentlyContinue

                    # Check for different task types
                    $taskTypes = @('Task', 'ImmediateTask', 'TaskV2', 'ImmediateTaskV2')

                    foreach ($taskType in $taskTypes) {
                        $tasks = $xml.ScheduledTasks.$taskType

                        foreach ($task in $tasks) {
                            if (-not $task) { continue }

                            $taskName = $task.name
                            $action = $task.Properties.appName
                            $arguments = $task.Properties.args
                            $runAs = $task.Properties.runAs
                            $startIn = $task.Properties.startIn

                            # Combine action and arguments
                            $fullCommand = "$action $arguments".Trim()

                            $riskLevel = 'Medium'
                            $riskFactors = @()

                            # Check task type
                            if ($taskType -like 'Immediate*') {
                                $riskLevel = 'High'
                                $riskFactors += 'Immediate task (runs once per GPO application)'
                            }

                            # Check run-as context
                            if ($runAs -match 'SYSTEM|NT AUTHORITY') {
                                $riskLevel = 'High'
                                $riskFactors += 'Runs as SYSTEM'
                            }
                            elseif ($runAs -match 'Administrator') {
                                $riskLevel = 'High'
                                $riskFactors += 'Runs as Administrator'
                            }

                            # Check for suspicious patterns
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($fullCommand -match $pattern.Pattern) {
                                    $riskLevel = 'Critical'
                                    $riskFactors += $pattern.Desc
                                }
                            }

                            # Check modification time
                            $recentThreshold = (Get-Date).AddDays(-30)
                            if ($taskFile.LastWriteTime -gt $recentThreshold) {
                                $riskFactors += "Recently modified: $($taskFile.LastWriteTime)"
                                if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
                            }

                            $findings += [PSCustomObject]@{
                                GPOName          = $gpoName
                                GPOId            = $gpoId
                                TaskType         = $taskType
                                TaskName         = $taskName
                                TaskAction       = $action
                                TaskArguments    = $arguments
                                FullCommand      = $fullCommand
                                RunAs            = $runAs
                                StartIn          = $startIn
                                XMLPath          = $taskFile.FullName
                                LastModified     = $taskFile.LastWriteTime
                                RiskLevel        = $riskLevel
                                RiskFactors      = ($riskFactors -join '; ')
                                AttackPath       = 'Execute scheduled task on domain computers'
                                Impact           = 'Code execution on all computers where GPO applies'
                            }
                        }
                    }
                }
                catch {
                    $findings += [PSCustomObject]@{
                        GPOName       = 'Parse Error'
                        GPOId         = $gpoId
                        TaskName      = 'Error'
                        TaskAction    = $_.Exception.Message
                        XMLPath       = $taskFile.FullName
                        RiskLevel     = 'Unknown'
                        RiskFactors   = "Failed to parse: $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{
                GPOName       = 'Error'
                TaskName      = 'Enumeration failed'
                TaskAction    = $_.Exception.Message
                RiskLevel     = 'Unknown'
                RiskFactors   = "Error: $($_.Exception.Message)"
            }
        }

        # Sort by risk
        $riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Unknown' = 4 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, GPOName

        return $findings
    }

    Remediation = @{
        Description = 'Review all GPP scheduled tasks for legitimacy. Remove unauthorized tasks. Consider using proper scheduled task deployment methods with better auditing. Monitor SYSVOL for changes.'
        Impact      = 'High - Removing scheduled tasks may break legitimate automation. Identify task owners first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# GPP Scheduled Tasks Analysis
# Total tasks found: $($Finding.Findings.Count)
# Critical: $(($Finding.Findings | Where-Object RiskLevel -eq 'Critical').Count)
# High: $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)

# CRITICAL/HIGH RISK tasks (investigate immediately):
$($Finding.Findings | Where-Object { $_.RiskLevel -in @('Critical', 'High') } | ForEach-Object {
"# GPO: $($_.GPOName) [$($_.GPOId)]"
"# Task: $($_.TaskName) ($($_.TaskType))"
"# Command: $($_.FullCommand)"
"# RunAs: $($_.RunAs)"
"# Risk: $($_.RiskFactors)"
"# File: $($_.XMLPath)"
""
} | Out-String)

# INVESTIGATION STEPS:

# 1. Review the XML files:
$($Finding.Findings | Where-Object RiskLevel -eq 'Critical' | Select-Object -First 3 | ForEach-Object {
"Get-Content '$($_.XMLPath)'"
} | Out-String)

# 2. Check GPO links to see affected OUs:
$($Finding.Findings | Select-Object -First 3 | ForEach-Object {
"# Get-GPOReport -Guid '$($_.GPOId.Trim('{}'))' -ReportType Html -Path 'GPO_$($_.GPOId).html'"
} | Out-String)

# 3. To remove a scheduled task from GPP:
# Option A: Edit via GPMC (recommended)
# Option B: Delete the ScheduledTasks.xml file (caution!)

# 4. Check what computers have applied this GPO:
# Get-ADComputer -Filter * -Properties gpLink |
#     Where-Object { `$_.gpLink -match "GPO_GUID" }

# 5. Check for tasks already created on endpoints:
# Invoke-Command -ComputerName "targetPC" -ScriptBlock {
#     Get-ScheduledTask | Where-Object { `$_.TaskName -like "*suspicious*" }
# }

# 6. Monitor for GPP changes:
# Enable auditing on SYSVOL Preferences folders
# Event ID 4663 for file modifications

# IMMEDIATE TASK TYPES EXPLAINED:
# - ImmediateTask: Runs once when GPO is applied (one-time execution)
# - ImmediateTaskV2: Same, newer schema
# - Task: Persistent scheduled task
# - TaskV2: Persistent scheduled task, newer schema

"@
            return $commands
        }
    }
}

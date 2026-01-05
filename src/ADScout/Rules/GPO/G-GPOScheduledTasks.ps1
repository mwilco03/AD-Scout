@{
    Id          = 'G-GPOScheduledTasks'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'GPO Deploying Scheduled Tasks or Scripts'
    Description = 'Detects Group Policy Objects that deploy scheduled tasks, startup scripts, or logon scripts. While these can be legitimate, they are also prime targets for attackers to establish persistence or execute malicious code domain-wide.'
    Severity    = 'Medium'
    Weight      = 30
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'GPO Persistence'; Url = 'https://attack.mitre.org/techniques/T1547/001/' }
        @{ Title = 'Scheduled Task Abuse'; Url = 'https://attack.mitre.org/techniques/T1053/005/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002')  # Persistence, Execution
        Techniques = @('T1053.005', 'T1547.001')
    }

    CIS   = @('5.5.2')
    STIG  = @('V-220942')
    ANSSI = @('R45')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $domainName = (Get-ADDomain).DNSRoot
            $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"

            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                $gpoPath = Join-Path $sysvolPath "{$($gpo.Id)}"

                # Check for Scheduled Tasks (GPP)
                foreach ($type in @('Machine', 'User')) {
                    $scheduledTaskPath = Join-Path $gpoPath "$type\Preferences\ScheduledTasks\ScheduledTasks.xml"

                    if (Test-Path $scheduledTaskPath -ErrorAction SilentlyContinue) {
                        try {
                            [xml]$xml = Get-Content $scheduledTaskPath -ErrorAction SilentlyContinue

                            $tasks = $xml.SelectNodes("//TaskV2|//Task|//ImmediateTaskV2|//ImmediateTask")

                            foreach ($task in $tasks) {
                                $command = $task.Properties.Action.Exec.Command ?? $task.Properties.appName ?? 'Unknown'
                                $arguments = $task.Properties.Action.Exec.Arguments ?? $task.Properties.args ?? ''

                                # Check for suspicious commands
                                $isSuspicious = $command -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec'

                                $findings += [PSCustomObject]@{
                                    GPOName             = $gpo.DisplayName
                                    GPOID               = $gpo.Id
                                    SettingType         = 'Scheduled Task (GPP)'
                                    Scope               = $type
                                    TaskName            = $task.name ?? 'Unknown'
                                    Command             = $command
                                    Arguments           = $arguments
                                    IsSuspicious        = $isSuspicious
                                    RiskLevel           = if ($isSuspicious) { 'High' } else { 'Medium' }
                                    Review              = 'Verify this scheduled task is legitimate'
                                }
                            }
                        }
                        catch { }
                    }

                    # Check for startup/shutdown scripts
                    $scriptsIniPath = Join-Path $gpoPath "$type\Scripts\scripts.ini"

                    if (Test-Path $scriptsIniPath -ErrorAction SilentlyContinue) {
                        try {
                            $content = Get-Content $scriptsIniPath -Raw -ErrorAction SilentlyContinue

                            if ($content -match '\d+CmdLine=(.+)') {
                                $findings += [PSCustomObject]@{
                                    GPOName             = $gpo.DisplayName
                                    GPOID               = $gpo.Id
                                    SettingType         = 'Startup/Shutdown Script'
                                    Scope               = $type
                                    FilePath            = $scriptsIniPath
                                    RiskLevel           = 'Medium'
                                    Review              = 'Verify startup/shutdown scripts are legitimate'
                                }
                            }
                        }
                        catch { }
                    }

                    # Check for logon/logoff scripts
                    $scriptsPath = Join-Path $gpoPath "$type\Scripts"
                    if (Test-Path $scriptsPath -ErrorAction SilentlyContinue) {
                        $scriptFiles = Get-ChildItem -Path $scriptsPath -Include *.ps1,*.bat,*.cmd,*.vbs,*.js -Recurse -ErrorAction SilentlyContinue

                        foreach ($script in $scriptFiles) {
                            $findings += [PSCustomObject]@{
                                GPOName             = $gpo.DisplayName
                                GPOID               = $gpo.Id
                                SettingType         = 'Script File'
                                Scope               = $type
                                ScriptPath          = $script.FullName
                                ScriptName          = $script.Name
                                LastModified        = $script.LastWriteTime
                                RiskLevel           = 'Medium'
                                Review              = 'Review script content for malicious code'
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Could not check GPOs
        }

        return $findings | Sort-Object RiskLevel, GPOName
    }

    Remediation = @{
        Description = 'Review all GPO-deployed scheduled tasks and scripts. Remove any that are not documented or necessary.'
        Impact      = 'High - May affect legitimate automation if removed'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GPO SCHEDULED TASKS AND SCRIPTS
# ================================================================
# GPOs can deploy code that runs on every linked computer.
# This is legitimate for management but abused for persistence.
#
# Review each finding and verify:
# 1. Is this task/script documented?
# 2. Who created it and when?
# 3. Is the code safe?

# ================================================================
# DETECTED TASKS/SCRIPTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName)
# Type: $($item.SettingType)
# Scope: $($item.Scope)
# Task/Script: $($item.TaskName ?? $item.ScriptName ?? 'N/A')
# Command: $($item.Command ?? $item.ScriptPath ?? 'N/A')
# Risk: $($item.RiskLevel)
# Suspicious: $($item.IsSuspicious ?? 'N/A')

"@
            }

            $commands += @"

# ================================================================
# REVIEW PROCESS
# ================================================================

# 1. DOCUMENT LEGITIMATE TASKS
# Create inventory of approved GPO deployments

# 2. REVIEW SCRIPT CONTENT
# Read each script and verify it's safe:

"@
            foreach ($item in $Finding.Findings | Where-Object { $_.ScriptPath }) {
                $commands += @"
# Get-Content "$($item.ScriptPath)"
"@
            }

            $commands += @"

# 3. CHECK GPO HISTORY
# When was this GPO last modified?
Get-GPO -All | Select-Object DisplayName, ModificationTime | Sort-Object ModificationTime -Descending

# 4. COMPARE TO BACKUP
# If you have GPO backups, compare current state to known-good

# ================================================================
# SUSPICIOUS INDICATORS
# ================================================================

# Watch for:
# - PowerShell with encoded commands (-enc, -e)
# - Download cradles (Invoke-WebRequest, IWR, curl)
# - Unusual executables (not from C:\Windows)
# - Obfuscated code
# - Recently modified GPOs

# ================================================================
# MONITORING
# ================================================================

# Enable auditing:
# - GPO changes (Event ID 5136)
# - Scheduled task creation (Event ID 4698)
# - Process creation with command line (Event ID 4688)

# Alert on:
# - New scheduled tasks created by GPO
# - Modifications to existing GPO scripts
# - Unusual commands in GPO-deployed tasks

"@
            return $commands
        }
    }
}

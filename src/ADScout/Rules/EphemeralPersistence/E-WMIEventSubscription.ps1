@{
    Id          = 'E-WMIEventSubscription'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'WMI Event Subscription Persistence'
    Description = 'Detects WMI event subscriptions on domain controllers that can be used for fileless persistence. WMI subscriptions consist of an EventFilter (trigger), EventConsumer (action), and FilterToConsumerBinding. Attackers use these for persistent, stealthy code execution. This rule queries DCs for suspicious WMI subscriptions.'
    Severity    = 'Critical'
    Weight      = 30

    References  = @(
        @{ Title = 'WMI Persistence'; Url = 'https://attack.mitre.org/techniques/T1546/003/' }
        @{ Title = 'WMI Attacks'; Url = 'https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html' }
        @{ Title = 'Detecting WMI Persistence'; Url = 'https://www.sans.org/reading-room/whitepapers/detection/finding-evil-wmi-attacks-37012' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002')  # Persistence, Execution
        Techniques = @('T1546.003')  # Event Triggered Execution: WMI Event Subscription
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_wmi_persistence')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Known legitimate WMI subscriptions to exclude
        $legitimateNames = @(
            'BVTFilter',
            'SCM Event Log Filter',
            'DSCTimer',
            'TSLogonFilter',
            'TSLogonConsumer'
        )

        # Suspicious patterns
        $suspiciousPatterns = @(
            @{ Pattern = 'powershell'; Desc = 'PowerShell execution' }
            @{ Pattern = 'cmd\.exe|cmd\s+\/c'; Desc = 'Command prompt' }
            @{ Pattern = '-enc|-e\s|encodedcommand'; Desc = 'Encoded command' }
            @{ Pattern = 'bypass|hidden|noprofile'; Desc = 'Evasion flags' }
            @{ Pattern = 'iex|invoke-expression'; Desc = 'Dynamic execution' }
            @{ Pattern = 'downloadstring|webclient|net\.webclient'; Desc = 'Download and execute' }
            @{ Pattern = 'wscript|cscript|mshta'; Desc = 'Script host' }
            @{ Pattern = 'rundll32|regsvr32'; Desc = 'Binary proxy execution' }
            @{ Pattern = 'base64|frombase64'; Desc = 'Base64 encoding' }
        )

        # Query each DC
        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { continue }

            try {
                # Get WMI Event Filters
                $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ComputerName $dcName -ErrorAction SilentlyContinue

                # Get Event Consumers (command line and active script)
                $cmdConsumers = Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ComputerName $dcName -ErrorAction SilentlyContinue
                $scriptConsumers = Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ComputerName $dcName -ErrorAction SilentlyContinue

                # Get Bindings
                $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ComputerName $dcName -ErrorAction SilentlyContinue

                # Analyze CommandLine consumers
                foreach ($consumer in $cmdConsumers) {
                    $name = $consumer.Name
                    $commandLine = $consumer.CommandLineTemplate
                    $execPath = $consumer.ExecutablePath

                    # Skip known legitimate
                    if ($name -in $legitimateNames) { continue }

                    $riskLevel = 'High'
                    $riskFactors = @('CommandLineEventConsumer detected')

                    $fullCommand = if ($commandLine) { $commandLine } else { $execPath }

                    # Check for suspicious patterns
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($fullCommand -match $pattern.Pattern) {
                            $riskLevel = 'Critical'
                            $riskFactors += $pattern.Desc
                        }
                    }

                    # Find associated filter
                    $associatedFilter = $bindings | Where-Object { $_.Consumer -match [regex]::Escape($name) }
                    $filterQuery = ''
                    if ($associatedFilter) {
                        $filterName = ($associatedFilter.Filter -split '"')[1]
                        $filter = $filters | Where-Object { $_.Name -eq $filterName }
                        if ($filter) {
                            $filterQuery = $filter.Query
                        }
                    }

                    $findings += [PSCustomObject]@{
                        DomainController = $dcName
                        ConsumerType     = 'CommandLineEventConsumer'
                        ConsumerName     = $name
                        CommandLine      = $commandLine
                        ExecutablePath   = $execPath
                        FilterQuery      = $filterQuery
                        RiskLevel        = $riskLevel
                        RiskFactors      = ($riskFactors -join '; ')
                        AttackPath       = 'Execute commands via WMI event trigger'
                        Impact           = 'Fileless persistence, code execution on DC'
                    }
                }

                # Analyze ActiveScript consumers
                foreach ($consumer in $scriptConsumers) {
                    $name = $consumer.Name
                    $scriptText = $consumer.ScriptText
                    $scriptFile = $consumer.ScriptFileName
                    $scriptEngine = $consumer.ScriptingEngine

                    if ($name -in $legitimateNames) { continue }

                    $riskLevel = 'Critical'  # Script consumers are almost always malicious
                    $riskFactors = @('ActiveScriptEventConsumer detected', "Engine: $scriptEngine")

                    $scriptContent = if ($scriptText) { $scriptText.Substring(0, [Math]::Min(500, $scriptText.Length)) } else { $scriptFile }

                    foreach ($pattern in $suspiciousPatterns) {
                        if ($scriptContent -match $pattern.Pattern) {
                            $riskFactors += $pattern.Desc
                        }
                    }

                    $filterQuery = ''
                    $associatedFilter = $bindings | Where-Object { $_.Consumer -match [regex]::Escape($name) }
                    if ($associatedFilter) {
                        $filterName = ($associatedFilter.Filter -split '"')[1]
                        $filter = $filters | Where-Object { $_.Name -eq $filterName }
                        if ($filter) { $filterQuery = $filter.Query }
                    }

                    $findings += [PSCustomObject]@{
                        DomainController = $dcName
                        ConsumerType     = 'ActiveScriptEventConsumer'
                        ConsumerName     = $name
                        ScriptEngine     = $scriptEngine
                        ScriptContent    = $scriptContent
                        ScriptFile       = $scriptFile
                        FilterQuery      = $filterQuery
                        RiskLevel        = $riskLevel
                        RiskFactors      = ($riskFactors -join '; ')
                        AttackPath       = 'Execute script via WMI event trigger'
                        Impact           = 'Fileless persistence, code execution on DC'
                    }
                }

                # Report orphaned filters (filter without binding - could be remnants)
                foreach ($filter in $filters) {
                    if ($filter.Name -in $legitimateNames) { continue }

                    $hasBinding = $bindings | Where-Object { $_.Filter -match [regex]::Escape($filter.Name) }
                    if (-not $hasBinding) {
                        $findings += [PSCustomObject]@{
                            DomainController = $dcName
                            ConsumerType     = 'OrphanedFilter'
                            ConsumerName     = $filter.Name
                            FilterQuery      = $filter.Query
                            RiskLevel        = 'Medium'
                            RiskFactors      = 'Orphaned event filter (no consumer binding) - possible attack remnant'
                            AttackPath       = 'Incomplete or cleaned-up WMI persistence'
                            Impact           = 'May indicate previous compromise'
                        }
                    }
                }
            }
            catch {
                $findings += [PSCustomObject]@{
                    DomainController = $dcName
                    ConsumerType     = 'Error'
                    ConsumerName     = 'Query Failed'
                    RiskLevel        = 'Unknown'
                    RiskFactors      = "Cannot query WMI: $($_.Exception.Message)"
                }
            }
        }

        # Sort by risk
        $riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Unknown' = 4 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, DomainController

        return $findings
    }

    Remediation = @{
        Description = 'Remove malicious WMI event subscriptions immediately. This is a critical finding indicating active compromise. Investigate the full scope of the attack before and after WMI persistence was established.'
        Impact      = 'Low - Removing WMI subscriptions typically has no impact on legitimate operations, as they are rarely used legitimately.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: WMI Event Subscription Persistence Detected
# This indicates fileless malware or active compromise!

# Findings: $($Finding.Findings.Count)
# Critical: $(($Finding.Findings | Where-Object RiskLevel -eq 'Critical').Count)

# DETECTED SUBSCRIPTIONS:
$($Finding.Findings | Where-Object { $_.RiskLevel -in @('Critical', 'High') } | ForEach-Object {
"# DC: $($_.DomainController)"
"# Type: $($_.ConsumerType)"
"# Name: $($_.ConsumerName)"
"# Command/Script: $(if ($_.CommandLine) { $_.CommandLine } elseif ($_.ScriptContent) { $_.ScriptContent.Substring(0, [Math]::Min(100, $_.ScriptContent.Length)) + '...' } else { 'N/A' })"
"# Filter: $($_.FilterQuery)"
"# Risk: $($_.RiskFactors)"
""
} | Out-String)

# IMMEDIATE REMEDIATION:

# 1. Remove the malicious consumers:
$($Finding.Findings | Where-Object { $_.RiskLevel -in @('Critical', 'High') } | ForEach-Object {
"Invoke-Command -ComputerName '$($_.DomainController)' -ScriptBlock {"
"    Get-CimInstance -Namespace 'root\subscription' -ClassName '$($_.ConsumerType)' |"
"        Where-Object { `$_.Name -eq '$($_.ConsumerName)' } |"
"        Remove-CimInstance -Verbose"
"}"
} | Out-String)

# 2. Remove bindings:
# Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' |
#     Where-Object { `$_.Consumer -match 'ConsumerName' } |
#     Remove-CimInstance

# 3. Remove filters:
# Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' |
#     Where-Object { `$_.Name -eq 'FilterName' } |
#     Remove-CimInstance

# 4. Autoruns-style full cleanup (recommended):
# Invoke-Command -ComputerName "DC01" -ScriptBlock {
#     Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' | Remove-CimInstance
#     Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' | Remove-CimInstance
#     Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' | Remove-CimInstance
#     Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' | Remove-CimInstance
# }

# 5. Monitor for recreation:
# Enable WMI Activity logging (Microsoft-Windows-WMI-Activity/Operational)
# Event ID 5857, 5858, 5859, 5860, 5861

# INCIDENT RESPONSE:
# - WMI persistence is often part of larger attacks
# - Check for lateral movement before/after persistence
# - Review authentication logs on affected DCs
# - Hunt for related IoCs across the environment
# - Consider full DC forensic analysis

"@
            return $commands
        }
    }
}

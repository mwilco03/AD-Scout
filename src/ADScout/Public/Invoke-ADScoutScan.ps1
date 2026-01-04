function Invoke-ADScoutScan {
    <#
    .SYNOPSIS
        Performs a security assessment scan of Active Directory.

    .DESCRIPTION
        Invoke-ADScoutScan executes security rules against Active Directory data
        to identify security weaknesses, misconfigurations, and compliance issues.

        The scan collects data from AD, evaluates rules, and returns findings that
        can be exported to various formats using Export-ADScoutReport.

    .PARAMETER Domain
        The domain to scan. Defaults to the current user's domain.

    .PARAMETER Server
        Specific domain controller to query. If not specified, uses automatic DC selection.

    .PARAMETER Credential
        Credentials to use for AD queries. If not specified, uses current user context.

    .PARAMETER Category
        Filter rules by category. Valid values: Anomalies, StaleObjects, PrivilegedAccounts, Trusts, EntraID, All.
        Defaults to 'All'.

    .PARAMETER IncludeEntraID
        Include Entra ID (Azure AD) data collection and rules. Requires active Microsoft Graph connection
        via Connect-ADScoutGraph. If not connected, Entra ID rules will be skipped gracefully.

    .PARAMETER RuleId
        Specific rule IDs to execute. Accepts an array of rule IDs.

    .PARAMETER ExcludeRuleId
        Rule IDs to exclude from the scan.

    .PARAMETER ThrottleLimit
        Maximum number of parallel operations. Defaults to processor count.

    .PARAMETER SkipCache
        Force fresh data collection, ignoring cached data.

    .EXAMPLE
        Invoke-ADScoutScan
        Runs all rules against the current domain.

    .EXAMPLE
        Invoke-ADScoutScan -Category StaleObjects, PrivilegedAccounts
        Runs only StaleObjects and PrivilegedAccounts category rules.

    .EXAMPLE
        Invoke-ADScoutScan -Domain "contoso.com" -Credential $cred | Export-ADScoutReport -Format HTML
        Scans a specific domain with credentials and exports to HTML.

    .EXAMPLE
        Invoke-ADScoutScan -RuleId "S-PwdNeverExpires", "P-AdminCount"
        Runs only the specified rules.

    .OUTPUTS
        ADScoutResult[]
        Collection of findings from the security scan.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI', 'EntraID', 'All')]
        [string[]]$Category = 'All',

        [Parameter()]
        [switch]$IncludeEntraID,

        [Parameter()]
        [string[]]$RuleId,

        [Parameter()]
        [string[]]$ExcludeRuleId,

        [Parameter()]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,

        [Parameter()]
        [switch]$SkipCache
    )

    begin {
        Write-Verbose "Starting AD-Scout scan"
        $startTime = Get-Date

        # Clear cache if requested
        if ($SkipCache) {
            Write-Verbose "Clearing cache"
            $script:ADScoutCache.Data.Clear()
            $script:ADScoutCache.Timestamps.Clear()
        }

        # Get rules to execute
        $ruleParams = @{}
        if ($Category -and $Category -ne 'All') {
            $ruleParams.Category = $Category
        }
        if ($RuleId) {
            $ruleParams.Id = $RuleId
        }

        $rules = Get-ADScoutRule @ruleParams

        if ($ExcludeRuleId) {
            $rules = $rules | Where-Object { $_.Id -notin $ExcludeRuleId }
        }

        if (-not $rules) {
            Write-Warning "No rules found matching the specified criteria"
            return
        }

        Write-Verbose "Found $($rules.Count) rules to execute"
    }

    process {
        # Collect AD data - use parallel collection when possible
        Write-Verbose "Collecting Active Directory data..."

        $adDataParams = @{}
        if ($Domain) { $adDataParams.Domain = $Domain }
        if ($Server) { $adDataParams.Server = $Server }
        if ($Credential) { $adDataParams.Credential = $Credential }

        # Initialize AD data hashtable with thread-safe collection for parallel writes
        $adData = [hashtable]::Synchronized(@{
            Domain   = $Domain
            Server   = $Server
            ScanTime = $startTime
        })

        # Define collectors to run - each returns a key-value pair
        $collectors = @(
            @{ Key = 'Users';        Collector = { param($p) Get-ADScoutUserData @p } }
            @{ Key = 'Computers';    Collector = { param($p) Get-ADScoutComputerData @p } }
            @{ Key = 'Groups';       Collector = { param($p) Get-ADScoutGroupData @p } }
            @{ Key = 'Trusts';       Collector = { param($p) Get-ADScoutTrustData @p } }
            @{ Key = 'GPOs';         Collector = { param($p) Get-ADScoutGPOData @p } }
            @{ Key = 'Certificates'; Collector = { param($p) Get-ADScoutCertificateData @p } }
        )

        # Check if we can use parallel collection (PS7+ is safest for LDAP connections)
        $useParallelCollection = $PSVersionTable.PSVersion.Major -ge 7 -and $ThrottleLimit -gt 1

        if ($useParallelCollection) {
            Write-Verbose "Using parallel data collection (ThrottleLimit=$ThrottleLimit)"

            # PS7+ parallel collection
            $collectors | ForEach-Object -Parallel {
                $collector = $_
                $params = $using:adDataParams
                $data = $using:adData

                try {
                    $result = & $collector.Collector -p $params
                    $data[$collector.Key] = $result
                }
                catch {
                    Write-Warning "Collector $($collector.Key) failed: $_"
                    $data[$collector.Key] = @()
                }
            } -ThrottleLimit ([Math]::Min($ThrottleLimit, $collectors.Count))
        }
        else {
            Write-Verbose "Using sequential data collection"

            # Sequential collection (PS 5.1 or single-threaded)
            foreach ($collector in $collectors) {
                try {
                    Write-Progress -Activity "Collecting AD Data" -Status $collector.Key -PercentComplete (
                        ($collectors.IndexOf($collector) / $collectors.Count) * 100
                    )
                    $adData[$collector.Key] = & $collector.Collector -p $adDataParams
                }
                catch {
                    Write-Warning "Collector $($collector.Key) failed: $_"
                    $adData[$collector.Key] = @()
                }
            }
            Write-Progress -Activity "Collecting AD Data" -Completed
        }

        Write-Verbose "AD data collection complete: Users=$($adData.Users.Count), Computers=$($adData.Computers.Count), Groups=$($adData.Groups.Count)"

        # Collect Entra ID data if requested or EntraID category is specified
        $entraConnected = Test-ADScoutGraphConnection
        $collectEntra = $IncludeEntraID -or ($Category -contains 'EntraID') -or ($Category -contains 'All')

        if ($collectEntra) {
            if ($entraConnected) {
                Write-Verbose "Collecting Entra ID data..."
                $adData['EntraUsers'] = Get-ADScoutEntraUserData -IncludeMFAStatus -IncludeGuests
                $adData['EntraGroups'] = Get-ADScoutEntraGroupData
                $adData['EntraApps'] = Get-ADScoutEntraAppData
                $adData['EntraRoles'] = Get-ADScoutEntraRoleData
                $adData['EntraPolicies'] = Get-ADScoutEntraPolicyData
                $adData['EntraConnected'] = $true
                Write-Verbose "Entra ID data collection complete"
            }
            else {
                Write-Verbose "Microsoft Graph not connected. Entra ID rules will use their own data collection."
                $adData['EntraConnected'] = $false
            }
        }
        else {
            $adData['EntraConnected'] = $false
        }

        Write-Verbose "Data collection complete"

        # Execute rules - use Invoke-RuleEvaluation for consistent handling
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $totalRules = $rules.Count

        # Define rule execution scriptblock for reuse
        $executeRule = {
            param($rule, $adData, $domainName)

            # Check prerequisites
            if ($rule.Prerequisites) {
                try {
                    $prereqResult = & $rule.Prerequisites -ADData $adData
                    if (-not $prereqResult) {
                        return $null  # Prerequisites not met
                    }
                }
                catch {
                    return $null  # Prerequisite check failed
                }
            }

            # Execute the rule using Invoke-RuleEvaluation for consistent scoring
            try {
                $finding = Invoke-RuleEvaluation -Rule $rule -Data $adData -Domain $domainName
                return $finding
            }
            catch {
                # Return error result
                return [PSCustomObject]@{
                    PSTypeName   = 'ADScoutResult'
                    RuleId       = $rule.Id
                    RuleName     = $rule.Name
                    Category     = $rule.Category
                    Description  = "Error executing rule: $_"
                    FindingCount = 0
                    Score        = 0
                    MaxScore     = $rule.MaxPoints
                    Findings     = @()
                    Error        = $_.Exception.Message
                    ExecutedAt   = Get-Date
                }
            }
        }

        # Check if we should use parallel rule execution
        # Only use parallel for PS7+ with many rules (overhead not worth it for few rules)
        $useParallelRules = $PSVersionTable.PSVersion.Major -ge 7 -and $ThrottleLimit -gt 1 -and $totalRules -gt 10

        if ($useParallelRules) {
            Write-Verbose "Using parallel rule execution for $totalRules rules (ThrottleLimit=$ThrottleLimit)"

            # Thread-safe results collection
            $parallelResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
            $completedCount = [ref]0

            $rules | ForEach-Object -Parallel {
                $rule = $_
                $data = $using:adData
                $domainName = $using:Domain
                $resultsBag = $using:parallelResults
                $completed = $using:completedCount

                # Check prerequisites
                if ($rule.Prerequisites) {
                    try {
                        $prereqResult = & $rule.Prerequisites -ADData $data
                        if (-not $prereqResult) {
                            [System.Threading.Interlocked]::Increment($completed)
                            return
                        }
                    }
                    catch {
                        [System.Threading.Interlocked]::Increment($completed)
                        return
                    }
                }

                # Execute the rule
                try {
                    $findings = & $rule.ScriptBlock -ADData $data

                    if ($findings) {
                        $findingCount = @($findings).Count

                        # Calculate score
                        $score = switch ($rule.Computation) {
                            'TriggerOnPresence' { $rule.Points }
                            'PerDiscover' { [math]::Min($findingCount * $rule.Points, $rule.MaxPoints) }
                            'TriggerOnThreshold' { if ($findingCount -ge $rule.Threshold) { $rule.Points } else { 0 } }
                            'TriggerIfLessThan' { if ($findingCount -lt $rule.Threshold) { $rule.Points } else { 0 } }
                            default { $findingCount * $rule.Points }
                        }

                        $result = [PSCustomObject]@{
                            PSTypeName   = 'ADScoutResult'
                            RuleId       = $rule.Id
                            RuleName     = $rule.Name
                            Category     = $rule.Category
                            Description  = $rule.Description
                            FindingCount = $findingCount
                            Score        = $score
                            MaxScore     = $rule.MaxPoints
                            Findings     = $findings
                            MITRE        = $rule.MITRE
                            CIS          = $rule.CIS
                            STIG         = $rule.STIG
                            Remediation  = $rule.Remediation
                            TechnicalExplanation = $rule.TechnicalExplanation
                            References   = $rule.References
                            ExecutedAt   = Get-Date
                        }

                        $resultsBag.Add($result)
                    }
                }
                catch {
                    # Log but don't fail entire scan
                    Write-Warning "Error executing rule $($rule.Id): $_"
                }

                [System.Threading.Interlocked]::Increment($completed)
            } -ThrottleLimit $ThrottleLimit

            # Convert concurrent bag to list
            foreach ($item in $parallelResults) {
                $results.Add($item)
            }
        }
        else {
            Write-Verbose "Using sequential rule execution for $totalRules rules"

            $ruleCount = 0
            foreach ($rule in $rules) {
                $ruleCount++
                $percentComplete = [math]::Round(($ruleCount / $totalRules) * 100)

                Write-Progress -Activity "Executing security rules" `
                               -Status "Running: $($rule.Name) ($ruleCount/$totalRules)" `
                               -PercentComplete $percentComplete

                Write-Verbose "Executing rule: $($rule.Id) - $($rule.Name)"

                try {
                    # Check prerequisites
                    if ($rule.Prerequisites) {
                        $prereqResult = & $rule.Prerequisites -ADData $adData
                        if (-not $prereqResult) {
                            Write-Verbose "Skipping rule $($rule.Id): Prerequisites not met"
                            continue
                        }
                    }

                    # Execute the rule
                    $findings = & $rule.ScriptBlock -ADData $adData

                    if ($findings) {
                        $findingCount = @($findings).Count

                        # Calculate score based on computation type
                        $score = switch ($rule.Computation) {
                            'TriggerOnPresence' { $rule.Points }
                            'PerDiscover' { [math]::Min($findingCount * $rule.Points, $rule.MaxPoints) }
                            'TriggerOnThreshold' { if ($findingCount -ge $rule.Threshold) { $rule.Points } else { 0 } }
                            'TriggerIfLessThan' { if ($findingCount -lt $rule.Threshold) { $rule.Points } else { 0 } }
                            default { $findingCount * $rule.Points }
                        }

                        $result = [PSCustomObject]@{
                            PSTypeName   = 'ADScoutResult'
                            RuleId       = $rule.Id
                            RuleName     = $rule.Name
                            Category     = $rule.Category
                            Description  = $rule.Description
                            FindingCount = $findingCount
                            Score        = $score
                            MaxScore     = $rule.MaxPoints
                            Findings     = $findings
                            MITRE        = $rule.MITRE
                            CIS          = $rule.CIS
                            STIG         = $rule.STIG
                            Remediation  = $rule.Remediation
                            TechnicalExplanation = $rule.TechnicalExplanation
                            References   = $rule.References
                            ExecutedAt   = Get-Date
                        }

                        $results.Add($result)
                        Write-Verbose "Rule $($rule.Id) found $findingCount issues (Score: $score)"
                    }
                    else {
                        Write-Verbose "Rule $($rule.Id) passed with no findings"
                    }
                }
                catch {
                    Write-Warning "Error executing rule $($rule.Id): $_"
                }
            }

            Write-Progress -Activity "Executing security rules" -Completed
        }
    }

    end {
        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Verbose "Scan completed in $($duration.TotalSeconds) seconds"
        Write-Verbose "Total findings: $($results.Count) rules with issues"

        # Return results as array
        $results.ToArray()
    }
}

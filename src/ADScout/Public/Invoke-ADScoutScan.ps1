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
        Filter rules by category. Valid values: Anomalies, StaleObjects, PrivilegedAccounts, Trusts, All.
        Defaults to 'All'.

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
        [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'All')]
        [string[]]$Category = 'All',

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
        # Collect AD data
        Write-Verbose "Collecting Active Directory data..."

        $adDataParams = @{}
        if ($Domain) { $adDataParams.Domain = $Domain }
        if ($Server) { $adDataParams.Server = $Server }
        if ($Credential) { $adDataParams.Credential = $Credential }

        $adData = @{
            Users        = Get-ADScoutUserData @adDataParams
            Computers    = Get-ADScoutComputerData @adDataParams
            Groups       = Get-ADScoutGroupData @adDataParams
            Trusts       = Get-ADScoutTrustData @adDataParams
            GPOs         = Get-ADScoutGPOData @adDataParams
            Certificates = Get-ADScoutCertificateData @adDataParams
            Domain       = $Domain
            Server       = $Server
            ScanTime     = $startTime
        }

        Write-Verbose "Data collection complete"

        # Execute rules
        $results = @()
        $ruleCount = 0
        $totalRules = $rules.Count

        foreach ($rule in $rules) {
            $ruleCount++
            $percentComplete = [math]::Round(($ruleCount / $totalRules) * 100)

            Write-Progress -Activity "Executing security rules" `
                           -Status "Running: $($rule.Name)" `
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
                        'TriggerOnPresence' {
                            $rule.Points
                        }
                        'PerDiscover' {
                            [math]::Min($findingCount * $rule.Points, $rule.MaxPoints)
                        }
                        'TriggerOnThreshold' {
                            if ($findingCount -ge $rule.Threshold) { $rule.Points } else { 0 }
                        }
                        'TriggerIfLessThan' {
                            if ($findingCount -lt $rule.Threshold) { $rule.Points } else { 0 }
                        }
                        default {
                            $findingCount * $rule.Points
                        }
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

                    $results += $result

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

    end {
        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Verbose "Scan completed in $($duration.TotalSeconds) seconds"
        Write-Verbose "Total findings: $($results.Count) rules with issues"

        # Return results
        $results
    }
}

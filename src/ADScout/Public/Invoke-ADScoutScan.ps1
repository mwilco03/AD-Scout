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

    .PARAMETER Incremental
        Perform an incremental scan, only checking objects that have changed
        since the last scan. Uses USN (Update Sequence Number) or whenChanged
        timestamps to detect modifications. Requires a previous scan watermark.

    .PARAMETER BaselinePath
        Path to a previous scan session to use as baseline for incremental
        scanning. If not specified, uses the most recent session.

    .PARAMETER EngagementId
        Engagement ID for scoped incremental scanning. Uses watermarks stored
        within the engagement's session history.

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

    .EXAMPLE
        Invoke-ADScoutScan -Incremental
        Performs an incremental scan, only evaluating objects changed since
        the last scan.

    .EXAMPLE
        Invoke-ADScoutScan -Incremental -EngagementId 'Q1-2024-Audit'
        Performs an incremental scan within a specific engagement context.

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
        [switch]$SkipCache,

        [Parameter()]
        [Alias('Differential')]
        [switch]$Incremental,

        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string]$EngagementId
    )

    begin {
        Write-Verbose "Starting AD-Scout scan"
        $startTime = Get-Date

        # Initialize session for disk persistence
        $sessionParams = @{}
        if ($EngagementId) { $sessionParams.EngagementId = $EngagementId }
        $script:CurrentSession = Get-ADScoutSessionPath @sessionParams

        # Incremental scan setup
        $script:IncrementalMode = $false
        $script:Watermark = $null
        $script:BaselineResults = @()
        $script:ChangedObjectDNs = @()

        if ($Incremental) {
            Write-Verbose "Checking incremental scan availability..."

            $incrementalCheck = Test-ADScoutIncrementalAvailable -Domain $Domain -EngagementId $EngagementId -SessionPath $BaselinePath

            if ($incrementalCheck.Available) {
                $script:IncrementalMode = $true
                $script:Watermark = $incrementalCheck.Watermark
                Write-Verbose "Incremental mode enabled. Baseline from: $($script:Watermark.ScanTime)"
                Write-Host "Incremental scan: Using baseline from $($script:Watermark.ScanTime)" -ForegroundColor Cyan

                # Load baseline results
                $baselinePath = if ($BaselinePath) { $BaselinePath }
                                elseif ($EngagementId) {
                                    $latestSession = Get-ADScoutLatestSession -EngagementId $EngagementId
                                    if ($latestSession) { $latestSession.Path }
                                }
                                else {
                                    $latestSession = Get-ADScoutLatestSession
                                    if ($latestSession) { $latestSession.Path }
                                }

                if ($baselinePath) {
                    $baselineState = Get-ADScoutSessionState -SessionPath $baselinePath
                    $script:BaselineResults = $baselineState.Results
                    Write-Verbose "Loaded $($script:BaselineResults.Count) baseline results"
                }
            }
            else {
                Write-Warning "Incremental scan not available: $($incrementalCheck.Reason)"
                Write-Warning "Falling back to full scan"
            }
        }

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

        # Get current highest USN for watermark
        $currentUSN = Get-ADScoutHighestUSN -Server $Server -Domain $Domain
        $script:HighestUSN = if ($currentUSN) { $currentUSN.HighestCommittedUSN } else { 0 }

        # Incremental mode: only fetch changed objects
        if ($script:IncrementalMode -and $script:Watermark) {
            Write-Verbose "Incremental mode: Fetching objects changed since USN $($script:Watermark.HighestUSN)"
            Write-Host "Fetching changed objects since last scan..." -ForegroundColor Cyan

            $sinceUSN = [long]$script:Watermark.HighestUSN
            $sinceTime = [datetime]$script:Watermark.ScanTime

            # Get changed objects for each type
            $changedUsers = Get-ADScoutChangedObjects -ObjectType 'User' -SinceUSN $sinceUSN -SinceTime $sinceTime @adDataParams
            $changedComputers = Get-ADScoutChangedObjects -ObjectType 'Computer' -SinceUSN $sinceUSN -SinceTime $sinceTime @adDataParams
            $changedGroups = Get-ADScoutChangedObjects -ObjectType 'Group' -SinceUSN $sinceUSN -SinceTime $sinceTime @adDataParams

            # Track changed DNs for result merging
            $script:ChangedObjectDNs = @(
                $changedUsers.Objects | ForEach-Object { $_.distinguishedname }
                $changedComputers.Objects | ForEach-Object { $_.distinguishedname }
                $changedGroups.Objects | ForEach-Object { $_.distinguishedname }
            ) | Where-Object { $_ }

            $totalChanged = $changedUsers.Count + $changedComputers.Count + $changedGroups.Count
            Write-Host "Found $totalChanged changed objects (Users: $($changedUsers.Count), Computers: $($changedComputers.Count), Groups: $($changedGroups.Count))" -ForegroundColor Cyan

            # For incremental, we still need full data but mark what changed
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
                IncrementalMode = $true
                ChangedDNs   = $script:ChangedObjectDNs
                BaselineUSN  = $sinceUSN
                CurrentUSN   = $script:HighestUSN
            }
        }
        else {
            # Full scan mode
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
                IncrementalMode = $false
            }
        }

        Write-Verbose "AD data collection complete"

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

        # Merge with baseline if incremental mode
        $finalResults = $results
        if ($script:IncrementalMode -and $script:BaselineResults.Count -gt 0) {
            Write-Verbose "Merging incremental results with baseline..."

            $finalResults = Merge-ADScoutIncrementalResults `
                -BaselineResults $script:BaselineResults `
                -IncrementalResults $results `
                -ChangedObjectDNs $script:ChangedObjectDNs

            # Generate incremental summary
            $incrementalSummary = Get-ADScoutIncrementalSummary `
                -BaselineResults $script:BaselineResults `
                -CurrentResults $finalResults `
                -Watermark $script:Watermark

            Write-Host "`nIncremental Scan Summary:" -ForegroundColor Cyan
            Write-Host "  Baseline: $($incrementalSummary.BaselineDate)" -ForegroundColor Gray
            Write-Host "  Score Change: $($incrementalSummary.BaselineTotalScore) -> $($incrementalSummary.CurrentTotalScore) ($($incrementalSummary.ScoreChange))" -ForegroundColor $(if ($incrementalSummary.ScoreChange -lt 0) { 'Green' } elseif ($incrementalSummary.ScoreChange -gt 0) { 'Red' } else { 'Gray' })
            Write-Host "  New Findings: $($incrementalSummary.NewFindingCount)" -ForegroundColor $(if ($incrementalSummary.NewFindingCount -gt 0) { 'Yellow' } else { 'Gray' })
            Write-Host "  Resolved: $($incrementalSummary.ResolvedFindingCount)" -ForegroundColor $(if ($incrementalSummary.ResolvedFindingCount -gt 0) { 'Green' } else { 'Gray' })
            Write-Host "  Changed: $($incrementalSummary.ChangedFindingCount)" -ForegroundColor Gray
        }

        Write-Verbose "Scan completed in $($duration.TotalSeconds) seconds"
        Write-Verbose "Total findings: $($finalResults.Count) rules with issues"

        # Save watermark for future incremental scans
        if ($script:CurrentSession) {
            $domainName = if ($Domain) { $Domain } else {
                try { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name } catch { 'Unknown' }
            }

            Save-ADScoutScanWatermark `
                -SessionPath $script:CurrentSession.Path `
                -Domain $domainName `
                -ScanTime $startTime `
                -HighestUSN $script:HighestUSN `
                -ObjectCount ($adData.Users.Count + $adData.Computers.Count + $adData.Groups.Count) `
                -ScanType $(if ($script:IncrementalMode) { 'Incremental' } else { 'Full' })

            # Save results to session for disk persistence
            Save-ADScoutSessionState `
                -SessionPath $script:CurrentSession.Path `
                -Results $finalResults `
                -Status 'Completed'

            Write-Verbose "Session saved to: $($script:CurrentSession.Path)"
        }

        # Return results
        $finalResults
    }
}

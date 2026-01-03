function Compare-ADScoutBaseline {
    <#
    .SYNOPSIS
        Compares current scan results against a baseline to identify changes.

    .DESCRIPTION
        Performs delta analysis between current scan results and a saved baseline.
        Identifies new findings, resolved findings, and score changes to track
        security posture over time.

    .PARAMETER Current
        The current scan results from Invoke-ADScoutScan.

    .PARAMETER Baseline
        The baseline object from Import-ADScoutBaseline, or path to baseline file.

    .PARAMETER ShowResolved
        Include resolved findings in the output (findings that were in baseline but not current).

    .PARAMETER ShowUnchanged
        Include unchanged findings in the output.

    .EXAMPLE
        $baseline = Import-ADScoutBaseline -Path ./baseline.json
        Invoke-ADScoutScan | Compare-ADScoutBaseline -Baseline $baseline

    .EXAMPLE
        $results | Compare-ADScoutBaseline -Baseline ./baseline.json -ShowResolved
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Current,

        [Parameter(Mandatory)]
        [PSObject]$Baseline,

        [Parameter()]
        [switch]$ShowResolved,

        [Parameter()]
        [switch]$ShowUnchanged
    )

    begin {
        # Load baseline if path provided
        if ($Baseline -is [string]) {
            $Baseline = Import-ADScoutBaseline -Path $Baseline
        }

        # Build baseline lookup
        $baselineRules = @{}
        foreach ($rule in $Baseline.Rules) {
            $baselineRules[$rule.RuleId] = $rule
        }

        $currentResults = @()
        $comparisonResults = @()
    }

    process {
        $currentResults += $Current
    }

    end {
        # Process current results
        $processedRuleIds = @()

        foreach ($result in $currentResults) {
            $ruleId = $result.RuleId
            $processedRuleIds += $ruleId

            $baselineRule = $baselineRules[$ruleId]

            # Generate hashes for current findings using centralized helper
            $currentHashes = @()
            if ($result.Findings) {
                foreach ($finding in $result.Findings) {
                    $hash = Get-ADScoutFingerprint -InputObject $finding
                    if ($hash) {
                        $currentHashes += $hash
                    }
                }
            }

            if ($baselineRule) {
                # Rule exists in baseline - compare
                $baselineHashes = $baselineRule.FindingHashes

                # Find new findings (in current but not in baseline)
                $newHashes = $currentHashes | Where-Object { $_ -notin $baselineHashes }

                # Find resolved findings (in baseline but not in current)
                $resolvedHashes = $baselineHashes | Where-Object { $_ -notin $currentHashes }

                # Calculate changes
                $scoreDelta = $result.Score - $baselineRule.Score
                $countDelta = $result.FindingCount - $baselineRule.FindingCount

                $status = if ($newHashes.Count -gt 0 -and $resolvedHashes.Count -gt 0) {
                    'Changed'
                }
                elseif ($newHashes.Count -gt 0) {
                    'Degraded'
                }
                elseif ($resolvedHashes.Count -gt 0) {
                    'Improved'
                }
                else {
                    'Unchanged'
                }

                $trend = if ($scoreDelta -gt 0) { 'Worsening' }
                         elseif ($scoreDelta -lt 0) { 'Improving' }
                         else { 'Stable' }

                # Skip unchanged if not requested
                if ($status -eq 'Unchanged' -and -not $ShowUnchanged) {
                    continue
                }

                $comparisonResults += [PSCustomObject]@{
                    RuleId            = $ruleId
                    Category          = $result.Category
                    Status            = $status
                    Trend             = $trend

                    # Current state
                    CurrentScore      = $result.Score
                    CurrentCount      = $result.FindingCount

                    # Baseline state
                    BaselineScore     = $baselineRule.Score
                    BaselineCount     = $baselineRule.FindingCount

                    # Deltas
                    ScoreDelta        = $scoreDelta
                    CountDelta        = $countDelta
                    NewFindings       = $newHashes.Count
                    ResolvedFindings  = $resolvedHashes.Count

                    # Details
                    IsNew             = $false
                    IsResolved        = $false
                    Findings          = $result.Findings
                    FirstSeen         = $Baseline.CreatedAt
                }
            }
            else {
                # New rule not in baseline
                $comparisonResults += [PSCustomObject]@{
                    RuleId            = $ruleId
                    Category          = $result.Category
                    Status            = 'New'
                    Trend             = 'New'

                    CurrentScore      = $result.Score
                    CurrentCount      = $result.FindingCount

                    BaselineScore     = 0
                    BaselineCount     = 0

                    ScoreDelta        = $result.Score
                    CountDelta        = $result.FindingCount
                    NewFindings       = $result.FindingCount
                    ResolvedFindings  = 0

                    IsNew             = $true
                    IsResolved        = $false
                    Findings          = $result.Findings
                    FirstSeen         = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
        }

        # Find resolved rules (in baseline but not in current)
        if ($ShowResolved) {
            foreach ($baselineRule in $Baseline.Rules) {
                if ($baselineRule.RuleId -notin $processedRuleIds) {
                    $comparisonResults += [PSCustomObject]@{
                        RuleId            = $baselineRule.RuleId
                        Category          = $baselineRule.Category
                        Status            = 'Resolved'
                        Trend             = 'Improving'

                        CurrentScore      = 0
                        CurrentCount      = 0

                        BaselineScore     = $baselineRule.Score
                        BaselineCount     = $baselineRule.FindingCount

                        ScoreDelta        = -$baselineRule.Score
                        CountDelta        = -$baselineRule.FindingCount
                        NewFindings       = 0
                        ResolvedFindings  = $baselineRule.FindingCount

                        IsNew             = $false
                        IsResolved        = $true
                        Findings          = $baselineRule.SampleFindings
                        FirstSeen         = $Baseline.CreatedAt
                    }
                }
            }
        }

        # Calculate summary
        $summary = [PSCustomObject]@{
            BaselineDate        = $Baseline.CreatedAt
            BaselineDomain      = $Baseline.Domain

            # Totals
            CurrentTotalScore   = ($currentResults | Measure-Object -Property Score -Sum).Sum
            BaselineTotalScore  = $Baseline.Summary.TotalScore
            TotalScoreDelta     = ($currentResults | Measure-Object -Property Score -Sum).Sum - $Baseline.Summary.TotalScore

            CurrentTotalFindings = ($currentResults | Measure-Object -Property FindingCount -Sum).Sum
            BaselineTotalFindings = $Baseline.Summary.TotalFindings

            # Status counts
            NewRules            = ($comparisonResults | Where-Object { $_.Status -eq 'New' }).Count
            ResolvedRules       = ($comparisonResults | Where-Object { $_.Status -eq 'Resolved' }).Count
            DegradedRules       = ($comparisonResults | Where-Object { $_.Status -eq 'Degraded' }).Count
            ImprovedRules       = ($comparisonResults | Where-Object { $_.Status -eq 'Improved' }).Count
            ChangedRules        = ($comparisonResults | Where-Object { $_.Status -eq 'Changed' }).Count
            UnchangedRules      = ($comparisonResults | Where-Object { $_.Status -eq 'Unchanged' }).Count

            # Overall trend
            OverallTrend        = ''
        }

        $summary.OverallTrend = if ($summary.TotalScoreDelta -gt 10) { 'Significantly Worsening' }
                                 elseif ($summary.TotalScoreDelta -gt 0) { 'Worsening' }
                                 elseif ($summary.TotalScoreDelta -lt -10) { 'Significantly Improving' }
                                 elseif ($summary.TotalScoreDelta -lt 0) { 'Improving' }
                                 else { 'Stable' }

        # Output summary
        Write-Host "`n=== Baseline Comparison ===" -ForegroundColor Cyan
        Write-Host "Baseline: $($summary.BaselineDate) | Domain: $($summary.BaselineDomain)"
        Write-Host "Score: $($summary.BaselineTotalScore) -> $($summary.CurrentTotalScore) ($($summary.TotalScoreDelta))" -ForegroundColor $(
            if ($summary.TotalScoreDelta -gt 0) { 'Red' }
            elseif ($summary.TotalScoreDelta -lt 0) { 'Green' }
            else { 'Gray' }
        )
        Write-Host "Trend: $($summary.OverallTrend)" -ForegroundColor $(
            if ($summary.OverallTrend -match 'Worsening') { 'Red' }
            elseif ($summary.OverallTrend -match 'Improving') { 'Green' }
            else { 'Gray' }
        )
        Write-Host "`nChanges: $($summary.NewRules) new, $($summary.ResolvedRules) resolved, $($summary.DegradedRules) degraded, $($summary.ImprovedRules) improved"

        # Return results
        return [PSCustomObject]@{
            Summary = $summary
            Results = $comparisonResults
        }
    }
}

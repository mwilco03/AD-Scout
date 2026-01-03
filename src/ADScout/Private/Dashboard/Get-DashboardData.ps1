function Get-DashboardData {
    <#
    .SYNOPSIS
        Formats scan results for dashboard consumption.

    .DESCRIPTION
        Processes AD-Scout scan results and baseline data to produce
        formatted data structures for the dashboard views (Auditor, Manager, Technician).
        Calculates scores, trends, comparisons, and category breakdowns.

        Uses Export-ADScoutBaseline format for baseline comparisons.

    .PARAMETER Results
        Array of ADScoutResult objects from Invoke-ADScoutScan.

    .PARAMETER BaselinePath
        Path to baseline file for comparison. If not provided,
        attempts to find adscout-baseline.json in current directory.
        Supports JSON, CLIXML, and compressed formats.

    .PARAMETER HistoryPath
        Path to scan history file for trend analysis.

    .OUTPUTS
        PSCustomObject containing formatted dashboard data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string]$HistoryPath,

        [Parameter()]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    # Auto-detect baseline if not specified
    if (-not $BaselinePath) {
        $defaultBaseline = Join-Path $PWD 'adscout-baseline.json'
        if (Test-Path $defaultBaseline) {
            $BaselinePath = $defaultBaseline
        }
    }

    # Auto-detect history if not specified
    if (-not $HistoryPath) {
        $defaultHistory = Join-Path $PWD 'adscout-history.json'
        if (Test-Path $defaultHistory) {
            $HistoryPath = $defaultHistory
        }
    }

    # Calculate totals
    $totalScore = ($Results | Measure-Object -Property Score -Sum).Sum
    if ($null -eq $totalScore) { $totalScore = 0 }

    $totalFindings = ($Results | Measure-Object -Property FindingCount -Sum).Sum
    if ($null -eq $totalFindings) { $totalFindings = 0 }

    $rulesWithFindings = ($Results | Where-Object { $_.FindingCount -gt 0 }).Count

    # Normalize score to 0-100 (lower is better, inverted for display)
    $maxPossibleScore = ($Results | Measure-Object -Property MaxScore -Sum).Sum
    if ($maxPossibleScore -gt 0) {
        $normalizedScore = [math]::Round(100 - (($totalScore / $maxPossibleScore) * 100))
    } else {
        $normalizedScore = 100
    }
    $normalizedScore = [math]::Max(0, [math]::Min(100, $normalizedScore))

    # Determine score grade and color
    $scoreGrade = switch ($normalizedScore) {
        { $_ -ge 90 } { 'A'; break }
        { $_ -ge 80 } { 'B'; break }
        { $_ -ge 70 } { 'C'; break }
        { $_ -ge 60 } { 'D'; break }
        default { 'F' }
    }

    $scoreColor = switch ($normalizedScore) {
        { $_ -ge 61 } { 'green'; break }
        { $_ -ge 31 } { 'yellow'; break }
        default { 'red' }
    }

    # Load baseline for comparison
    $baseline = $null
    $isFirstRun = $true
    $comparison = @{
        IsFirstRun = $true
        Trend = 'Stable'
        TrendArrow = '→'
        ScoreDelta = 0
        NewFindings = 0
        ResolvedFindings = 0
        NewCategories = @()
        BaselineDate = $null
    }

    if ($BaselinePath -and (Test-Path $BaselinePath)) {
        try {
            # Load baseline using Import-ADScoutBaseline if available, otherwise parse JSON
            $baselineContent = $null
            if (Get-Command -Name Import-ADScoutBaseline -ErrorAction SilentlyContinue) {
                $baselineContent = Import-ADScoutBaseline -Path $BaselinePath
            } else {
                $baselineContent = Get-Content $BaselinePath -Raw | ConvertFrom-Json
            }

            $baseline = $baselineContent
            $isFirstRun = $false

            # Export-ADScoutBaseline format: Version, Summary.TotalScore, Rules[]
            $baselineTotalScore = $baselineContent.Summary.TotalScore
            $baselineRules = $baselineContent.Rules
            $baselineDate = $baselineContent.CreatedAt
            $baselineCategories = @($baselineRules | ForEach-Object { $_.Category } | Select-Object -Unique)

            # Calculate normalized score from baseline
            $baselineMaxScore = ($baselineRules | Measure-Object -Property Score -Sum).Sum
            if ($baselineMaxScore -gt 0 -and $maxPossibleScore -gt 0) {
                $baselineNormalized = [math]::Round(100 - (($baselineTotalScore / $maxPossibleScore) * 100))
            } else {
                $baselineNormalized = 100
            }

            $scoreDelta = $normalizedScore - $baselineNormalized

            $comparison = @{
                IsFirstRun = $false
                Trend = if ($scoreDelta -gt 0) { 'Improving' }
                        elseif ($scoreDelta -lt 0) { 'Degrading' }
                        else { 'Stable' }
                TrendArrow = if ($scoreDelta -gt 0) { '↑' }
                             elseif ($scoreDelta -lt 0) { '↓' }
                             else { '→' }
                ScoreDelta = [math]::Abs($scoreDelta)
                NewFindings = 0
                ResolvedFindings = 0
                NewCategories = @()
                BaselineDate = $baselineDate
                BaselineScore = $baselineNormalized
            }

            # Compare findings
            if ($baselineRules) {
                $baselineRuleIds = @($baselineRules | ForEach-Object { $_.RuleId })
                $currentRuleIds = @($Results | ForEach-Object { $_.RuleId })

                $comparison.NewFindings = ($currentRuleIds | Where-Object { $_ -notin $baselineRuleIds }).Count
                $comparison.ResolvedFindings = ($baselineRuleIds | Where-Object { $_ -notin $currentRuleIds }).Count

                # Detect new categories
                $currentCategories = @($Results | ForEach-Object { $_.Category } | Select-Object -Unique)
                $comparison.NewCategories = @($currentCategories | Where-Object { $_ -notin $baselineCategories })
            }
        } catch {
            Write-Verbose "Failed to load baseline: $_"
        }
    }

    # Load history for trends
    $history = @()
    if ($HistoryPath -and (Test-Path $HistoryPath)) {
        try {
            $history = Get-Content $HistoryPath -Raw | ConvertFrom-Json
        } catch {
            Write-Verbose "Failed to load history: $_"
        }
    }

    # Category breakdown
    $categoryBreakdown = $Results | Group-Object Category | ForEach-Object {
        $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
        $catMaxScore = ($_.Group | Measure-Object -Property MaxScore -Sum).Sum
        $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum

        $catNormalized = if ($catMaxScore -gt 0) {
            [math]::Round(100 - (($catScore / $catMaxScore) * 100))
        } else { 100 }

        $isNew = $_.Name -in $comparison.NewCategories

        [PSCustomObject]@{
            Category = $_.Name
            RuleCount = $_.Count
            FindingCount = $catFindings
            Score = $catScore
            MaxScore = $catMaxScore
            NormalizedScore = $catNormalized
            Color = switch ($catNormalized) {
                { $_ -ge 61 } { 'green'; break }
                { $_ -ge 31 } { 'yellow'; break }
                default { 'red' }
            }
            IsNew = $isNew
        }
    } | Sort-Object Score -Descending

    # Framework mapping summary
    $frameworkCounts = @{
        MITRE = @($Results | Where-Object { $_.MITRE } | ForEach-Object { $_.MITRE } | Select-Object -Unique).Count
        CIS = @($Results | Where-Object { $_.CIS } | ForEach-Object { $_.CIS } | Select-Object -Unique).Count
        NIST = @($Results | Where-Object { $_.NIST } | ForEach-Object { $_.NIST } | Select-Object -Unique).Count
        STIG = @($Results | Where-Object { $_.STIG } | ForEach-Object { $_.STIG } | Select-Object -Unique).Count
    }

    # Top findings (critical and high priority)
    $topFindings = $Results |
        Where-Object { $_.Score -gt 0 } |
        Sort-Object Score -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                RuleId = $_.RuleId
                RuleName = $_.RuleName
                Category = $_.Category
                Score = $_.Score
                MaxScore = $_.MaxScore
                FindingCount = $_.FindingCount
                Description = $_.Description
                Severity = switch ($_.Score) {
                    { $_ -ge 50 } { 'Critical'; break }
                    { $_ -ge 20 } { 'High'; break }
                    { $_ -ge 10 } { 'Medium'; break }
                    default { 'Low' }
                }
                SeverityColor = switch ($_.Score) {
                    { $_ -ge 50 } { 'red'; break }
                    { $_ -ge 20 } { 'orange'; break }
                    { $_ -ge 10 } { 'yellow'; break }
                    default { 'green' }
                }
                MITRE = $_.MITRE
                CIS = $_.CIS
                NIST = $_.NIST
                STIG = $_.STIG
            }
        }

    # All findings for technician view
    $allFindings = $Results | ForEach-Object {
        [PSCustomObject]@{
            RuleId = $_.RuleId
            RuleName = $_.RuleName
            Category = $_.Category
            Score = $_.Score
            MaxScore = $_.MaxScore
            FindingCount = $_.FindingCount
            Description = $_.Description
            TechnicalExplanation = $_.TechnicalExplanation
            Severity = switch ($_.Score) {
                { $_ -ge 50 } { 'Critical'; break }
                { $_ -ge 20 } { 'High'; break }
                { $_ -ge 10 } { 'Medium'; break }
                default { 'Low' }
            }
            SeverityColor = switch ($_.Score) {
                { $_ -ge 50 } { 'red'; break }
                { $_ -ge 20 } { 'orange'; break }
                { $_ -ge 10 } { 'yellow'; break }
                default { 'green' }
            }
            MITRE = $_.MITRE -join ', '
            CIS = $_.CIS -join ', '
            NIST = $_.NIST -join ', '
            STIG = $_.STIG -join ', '
            Findings = $_.Findings
            References = $_.References
            HasRemediation = $null -ne $_.Remediation
        }
    } | Sort-Object Score -Descending

    # Risk heatmap (Category x Severity matrix)
    $riskHeatmap = @{}
    $severities = @('Critical', 'High', 'Medium', 'Low')
    foreach ($category in ($Results | Select-Object -ExpandProperty Category -Unique)) {
        $riskHeatmap[$category] = @{}
        foreach ($sev in $severities) {
            $count = ($Results | Where-Object {
                $_.Category -eq $category -and
                (switch ($_.Score) {
                    { $_ -ge 50 } { 'Critical'; break }
                    { $_ -ge 20 } { 'High'; break }
                    { $_ -ge 10 } { 'Medium'; break }
                    default { 'Low' }
                }) -eq $sev
            } | Measure-Object -Property FindingCount -Sum).Sum
            $riskHeatmap[$category][$sev] = if ($count) { $count } else { 0 }
        }
    }

    # Manager view: Top 3 priorities
    $topPriorities = $Results |
        Where-Object { $_.Score -gt 0 } |
        Sort-Object Score -Descending |
        Select-Object -First 3 |
        ForEach-Object {
            [PSCustomObject]@{
                Title = $_.RuleName
                Impact = switch ($_.Score) {
                    { $_ -ge 50 } { 'Critical Impact - Immediate action required'; break }
                    { $_ -ge 20 } { 'High Impact - Address within 1 week'; break }
                    { $_ -ge 10 } { 'Medium Impact - Plan remediation'; break }
                    default { 'Low Impact - Monitor and review' }
                }
                AffectedCount = $_.FindingCount
                Category = $_.Category
            }
        }

    # Entra ID status
    $hasEntraID = ($Results | Where-Object { $_.Category -eq 'EntraID' -or $_.Category -eq 'AzureAD' }).Count -gt 0

    # Build the complete dashboard data object
    $dashboardData = [PSCustomObject]@{
        PSTypeName = 'ADScoutDashboardData'

        # Meta information
        Meta = [PSCustomObject]@{
            Domain = $Domain
            ScanTime = Get-Date
            Version = $script:ADScoutVersion ?? '0.2.0'
            GeneratedAt = (Get-Date).ToString('o')
        }

        # Summary scores
        Summary = [PSCustomObject]@{
            TotalScore = $totalScore
            NormalizedScore = $normalizedScore
            TotalFindings = $totalFindings
            RulesWithFindings = $rulesWithFindings
            TotalRules = $Results.Count
            Grade = $scoreGrade
            Color = $scoreColor
        }

        # State flags
        State = [PSCustomObject]@{
            IsFirstRun = $isFirstRun
            HasBaseline = -not $isFirstRun
            HasHistory = $history.Count -gt 0
            HasEntraID = $hasEntraID
        }

        # Comparison with baseline
        Comparison = [PSCustomObject]$comparison

        # History for trend charts
        History = $history

        # Category breakdown
        Categories = $categoryBreakdown

        # Framework mapping counts
        Frameworks = [PSCustomObject]$frameworkCounts

        # Top findings (for auditor view)
        TopFindings = $topFindings

        # All findings (for technician view)
        AllFindings = $allFindings

        # Risk heatmap (for manager view)
        RiskHeatmap = $riskHeatmap

        # Top priorities (for manager view)
        TopPriorities = $topPriorities

        # Raw results for export/API
        RawResults = $Results

        # Baseline data if available
        Baseline = $baseline
    }

    return $dashboardData
}

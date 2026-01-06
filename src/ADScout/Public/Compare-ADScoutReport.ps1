function Compare-ADScoutReport {
    <#
    .SYNOPSIS
        Compares two AD-Scout scan results to show changes over time.

    .DESCRIPTION
        Generates a before/after comparison of scan results, showing:
        - New findings (appeared since baseline)
        - Resolved findings (fixed since baseline)
        - Changed findings (count or severity changed)
        - Score progression

        Useful for demonstrating remediation progress to customers.

    .PARAMETER Before
        Baseline scan results (path to JSON or result objects).

    .PARAMETER After
        Current scan results (path to JSON or result objects).

    .PARAMETER Format
        Output format: Console, HTML, JSON, Markdown.

    .PARAMETER Path
        Output file path for HTML/JSON/Markdown formats.

    .PARAMETER Title
        Report title.

    .EXAMPLE
        Compare-ADScoutReport -Before ./baseline.json -After $currentResults

    .EXAMPLE
        Compare-ADScoutReport -Before $baseline -After $current -Format HTML -Path ./progress.html

    .EXAMPLE
        $baseline = Invoke-ADScoutScan
        # ... customer remediates ...
        $current = Invoke-ADScoutScan
        Compare-ADScoutReport -Before $baseline -After $current
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Before,

        [Parameter(Mandatory)]
        $After,

        [Parameter()]
        [ValidateSet('Console', 'HTML', 'JSON', 'Markdown')]
        [string]$Format = 'Console',

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Title = "AD-Scout Remediation Progress Report"
    )

    # Load results if paths provided
    $beforeResults = if ($Before -is [string] -and (Test-Path $Before)) {
        $content = Get-Content -Path $Before -Raw | ConvertFrom-Json
        if ($content.Results) { $content.Results } else { $content }
    } else {
        $Before
    }

    $afterResults = if ($After -is [string] -and (Test-Path $After)) {
        $content = Get-Content -Path $After -Raw | ConvertFrom-Json
        if ($content.Results) { $content.Results } else { $content }
    } else {
        $After
    }

    # Build comparison
    $comparison = [ordered]@{
        Title          = $Title
        GeneratedAt    = Get-Date
        BeforeDate     = if ($Before -is [string]) { (Get-Item $Before).LastWriteTime } else { $null }
        AfterDate      = Get-Date
        Summary        = @{}
        NewFindings    = @()
        ResolvedFindings = @()
        ChangedFindings = @()
        UnchangedFindings = @()
    }

    # Create lookup tables
    $beforeByRule = @{}
    foreach ($result in $beforeResults) {
        $ruleId = $result.RuleId
        if (-not $ruleId) { $ruleId = $result.Id }
        $beforeByRule[$ruleId] = $result
    }

    $afterByRule = @{}
    foreach ($result in $afterResults) {
        $ruleId = $result.RuleId
        if (-not $ruleId) { $ruleId = $result.Id }
        $afterByRule[$ruleId] = $result
    }

    # Find new, resolved, changed
    foreach ($ruleId in $afterByRule.Keys) {
        $afterRule = $afterByRule[$ruleId]

        if (-not $beforeByRule.ContainsKey($ruleId)) {
            # New finding
            $comparison.NewFindings += [PSCustomObject]@{
                RuleId       = $ruleId
                RuleName     = $afterRule.RuleName ?? $afterRule.Name
                Category     = $afterRule.Category
                FindingCount = $afterRule.FindingCount ?? $afterRule.Findings.Count
                Score        = $afterRule.Score
                Status       = 'New'
            }
        } else {
            $beforeRule = $beforeByRule[$ruleId]
            $beforeCount = $beforeRule.FindingCount ?? $beforeRule.Findings.Count ?? 0
            $afterCount = $afterRule.FindingCount ?? $afterRule.Findings.Count ?? 0
            $beforeScore = $beforeRule.Score ?? 0
            $afterScore = $afterRule.Score ?? 0

            if ($beforeCount -ne $afterCount -or $beforeScore -ne $afterScore) {
                # Changed
                $comparison.ChangedFindings += [PSCustomObject]@{
                    RuleId           = $ruleId
                    RuleName         = $afterRule.RuleName ?? $afterRule.Name
                    Category         = $afterRule.Category
                    BeforeCount      = $beforeCount
                    AfterCount       = $afterCount
                    CountChange      = $afterCount - $beforeCount
                    BeforeScore      = $beforeScore
                    AfterScore       = $afterScore
                    ScoreChange      = $afterScore - $beforeScore
                    Status           = if ($afterCount -lt $beforeCount) { 'Improved' } elseif ($afterCount -gt $beforeCount) { 'Worsened' } else { 'Changed' }
                }
            } else {
                # Unchanged
                $comparison.UnchangedFindings += [PSCustomObject]@{
                    RuleId       = $ruleId
                    RuleName     = $afterRule.RuleName ?? $afterRule.Name
                    Category     = $afterRule.Category
                    FindingCount = $afterCount
                    Score        = $afterScore
                    Status       = 'Unchanged'
                }
            }
        }
    }

    # Find resolved (in before but not in after)
    foreach ($ruleId in $beforeByRule.Keys) {
        if (-not $afterByRule.ContainsKey($ruleId)) {
            $beforeRule = $beforeByRule[$ruleId]
            $comparison.ResolvedFindings += [PSCustomObject]@{
                RuleId       = $ruleId
                RuleName     = $beforeRule.RuleName ?? $beforeRule.Name
                Category     = $beforeRule.Category
                FindingCount = $beforeRule.FindingCount ?? $beforeRule.Findings.Count
                Score        = $beforeRule.Score
                Status       = 'Resolved'
            }
        }
    }

    # Calculate summary
    $beforeTotalScore = ($beforeResults | Measure-Object -Property Score -Sum).Sum ?? 0
    $afterTotalScore = ($afterResults | Measure-Object -Property Score -Sum).Sum ?? 0
    $beforeTotalFindings = ($beforeResults | Measure-Object -Property FindingCount -Sum).Sum ?? 0
    $afterTotalFindings = ($afterResults | Measure-Object -Property FindingCount -Sum).Sum ?? 0

    $comparison.Summary = [ordered]@{
        BeforeTotalScore    = $beforeTotalScore
        AfterTotalScore     = $afterTotalScore
        ScoreChange         = $afterTotalScore - $beforeTotalScore
        ScoreChangePercent  = if ($beforeTotalScore -gt 0) { [math]::Round((($afterTotalScore - $beforeTotalScore) / $beforeTotalScore) * 100, 1) } else { 0 }
        BeforeTotalFindings = $beforeTotalFindings
        AfterTotalFindings  = $afterTotalFindings
        FindingsChange      = $afterTotalFindings - $beforeTotalFindings
        NewCount            = $comparison.NewFindings.Count
        ResolvedCount       = $comparison.ResolvedFindings.Count
        ImprovedCount       = ($comparison.ChangedFindings | Where-Object { $_.Status -eq 'Improved' }).Count
        WorsenedCount       = ($comparison.ChangedFindings | Where-Object { $_.Status -eq 'Worsened' }).Count
        UnchangedCount      = $comparison.UnchangedFindings.Count
    }

    # Output based on format
    switch ($Format) {
        'Console' {
            Write-Host "`n$Title" -ForegroundColor Cyan
            Write-Host ("=" * 60) -ForegroundColor Cyan

            Write-Host "`nScore Progression:" -ForegroundColor White
            $scoreColor = if ($comparison.Summary.ScoreChange -lt 0) { 'Green' } elseif ($comparison.Summary.ScoreChange -gt 0) { 'Red' } else { 'Gray' }
            $arrow = if ($comparison.Summary.ScoreChange -lt 0) { '↓' } elseif ($comparison.Summary.ScoreChange -gt 0) { '↑' } else { '→' }
            Write-Host "  $($comparison.Summary.BeforeTotalScore) $arrow $($comparison.Summary.AfterTotalScore) ($($comparison.Summary.ScoreChangePercent)%)" -ForegroundColor $scoreColor

            Write-Host "`nFindings Summary:" -ForegroundColor White
            Write-Host "  Resolved: $($comparison.Summary.ResolvedCount)" -ForegroundColor Green
            Write-Host "  Improved: $($comparison.Summary.ImprovedCount)" -ForegroundColor Green
            Write-Host "  Worsened: $($comparison.Summary.WorsenedCount)" -ForegroundColor Red
            Write-Host "  New:      $($comparison.Summary.NewCount)" -ForegroundColor Yellow
            Write-Host "  Unchanged: $($comparison.Summary.UnchangedCount)" -ForegroundColor Gray

            if ($comparison.ResolvedFindings.Count -gt 0) {
                Write-Host "`nResolved Issues:" -ForegroundColor Green
                foreach ($r in $comparison.ResolvedFindings | Sort-Object Score -Descending | Select-Object -First 10) {
                    Write-Host "  [✓] $($r.RuleName) (-$($r.Score) points)" -ForegroundColor Green
                }
            }

            if ($comparison.NewFindings.Count -gt 0) {
                Write-Host "`nNew Issues:" -ForegroundColor Yellow
                foreach ($n in $comparison.NewFindings | Sort-Object Score -Descending | Select-Object -First 10) {
                    Write-Host "  [!] $($n.RuleName) (+$($n.Score) points)" -ForegroundColor Yellow
                }
            }

            $improved = $comparison.ChangedFindings | Where-Object { $_.Status -eq 'Improved' }
            if ($improved.Count -gt 0) {
                Write-Host "`nImproved:" -ForegroundColor Green
                foreach ($i in $improved | Sort-Object ScoreChange | Select-Object -First 10) {
                    Write-Host "  [↓] $($i.RuleName): $($i.BeforeCount) → $($i.AfterCount) ($($i.ScoreChange) points)" -ForegroundColor Green
                }
            }

            $worsened = $comparison.ChangedFindings | Where-Object { $_.Status -eq 'Worsened' }
            if ($worsened.Count -gt 0) {
                Write-Host "`nWorsened:" -ForegroundColor Red
                foreach ($w in $worsened | Sort-Object ScoreChange -Descending | Select-Object -First 10) {
                    Write-Host "  [↑] $($w.RuleName): $($w.BeforeCount) → $($w.AfterCount) (+$($w.ScoreChange) points)" -ForegroundColor Red
                }
            }
        }

        'JSON' {
            if (-not $Path) {
                Write-Error "Path required for JSON format"
                return
            }
            $comparison | ConvertTo-Json -Depth 10 | Out-File -Path $Path -Encoding UTF8
            Write-Host "Comparison saved to: $Path" -ForegroundColor Green
        }

        'Markdown' {
            $md = @"
# $Title

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm')

## Score Progression

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| **Total Score** | $($comparison.Summary.BeforeTotalScore) | $($comparison.Summary.AfterTotalScore) | $($comparison.Summary.ScoreChange) ($($comparison.Summary.ScoreChangePercent)%) |
| **Total Findings** | $($comparison.Summary.BeforeTotalFindings) | $($comparison.Summary.AfterTotalFindings) | $($comparison.Summary.FindingsChange) |

## Summary

| Status | Count |
|--------|-------|
| ✅ Resolved | $($comparison.Summary.ResolvedCount) |
| ⬇️ Improved | $($comparison.Summary.ImprovedCount) |
| ⬆️ Worsened | $($comparison.Summary.WorsenedCount) |
| 🆕 New | $($comparison.Summary.NewCount) |
| ➖ Unchanged | $($comparison.Summary.UnchangedCount) |

"@
            if ($comparison.ResolvedFindings.Count -gt 0) {
                $md += "`n## Resolved Issues`n`n"
                foreach ($r in $comparison.ResolvedFindings | Sort-Object Score -Descending) {
                    $md += "- ✅ **$($r.RuleName)** - $($r.FindingCount) findings resolved (-$($r.Score) points)`n"
                }
            }

            if ($comparison.NewFindings.Count -gt 0) {
                $md += "`n## New Issues`n`n"
                foreach ($n in $comparison.NewFindings | Sort-Object Score -Descending) {
                    $md += "- 🆕 **$($n.RuleName)** - $($n.FindingCount) findings (+$($n.Score) points)`n"
                }
            }

            if (-not $Path) {
                Write-Error "Path required for Markdown format"
                return
            }
            $md | Out-File -Path $Path -Encoding UTF8
            Write-Host "Comparison saved to: $Path" -ForegroundColor Green
        }

        'HTML' {
            # Build HTML report
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .score-box { display: flex; align-items: center; gap: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px; margin: 20px 0; }
        .score { font-size: 48px; font-weight: bold; }
        .score.before { color: #666; }
        .score.after { color: #0066cc; }
        .score.improved { color: #28a745; }
        .score.worsened { color: #dc3545; }
        .arrow { font-size: 32px; color: #999; }
        .change { font-size: 24px; padding: 5px 15px; border-radius: 20px; }
        .change.positive { background: #d4edda; color: #155724; }
        .change.negative { background: #f8d7da; color: #721c24; }
        .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
        .summary-card { text-align: center; padding: 20px; border-radius: 8px; }
        .summary-card.resolved { background: #d4edda; }
        .summary-card.improved { background: #cce5ff; }
        .summary-card.worsened { background: #f8d7da; }
        .summary-card.new { background: #fff3cd; }
        .summary-card.unchanged { background: #e9ecef; }
        .summary-card .count { font-size: 36px; font-weight: bold; }
        .finding-list { list-style: none; padding: 0; }
        .finding-list li { padding: 12px 15px; margin: 5px 0; border-radius: 4px; display: flex; justify-content: space-between; }
        .finding-list li.resolved { background: #d4edda; }
        .finding-list li.new { background: #fff3cd; }
        .finding-list li.improved { background: #cce5ff; }
        .finding-list li.worsened { background: #f8d7da; }
        .points { font-weight: bold; }
        .points.negative { color: #155724; }
        .points.positive { color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$Title</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>

        <h2>Score Progression</h2>
        <div class="score-box">
            <div class="score before">$($comparison.Summary.BeforeTotalScore)</div>
            <div class="arrow">→</div>
            <div class="score after $(if ($comparison.Summary.ScoreChange -lt 0) { 'improved' } elseif ($comparison.Summary.ScoreChange -gt 0) { 'worsened' })">$($comparison.Summary.AfterTotalScore)</div>
            <div class="change $(if ($comparison.Summary.ScoreChange -le 0) { 'positive' } else { 'negative' })">
                $(if ($comparison.Summary.ScoreChange -lt 0) { '' } else { '+' })$($comparison.Summary.ScoreChange) ($($comparison.Summary.ScoreChangePercent)%)
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card resolved"><div class="count">$($comparison.Summary.ResolvedCount)</div><div>Resolved</div></div>
            <div class="summary-card improved"><div class="count">$($comparison.Summary.ImprovedCount)</div><div>Improved</div></div>
            <div class="summary-card worsened"><div class="count">$($comparison.Summary.WorsenedCount)</div><div>Worsened</div></div>
            <div class="summary-card new"><div class="count">$($comparison.Summary.NewCount)</div><div>New</div></div>
            <div class="summary-card unchanged"><div class="count">$($comparison.Summary.UnchangedCount)</div><div>Unchanged</div></div>
        </div>
"@
            if ($comparison.ResolvedFindings.Count -gt 0) {
                $html += "<h2>✅ Resolved Issues</h2><ul class='finding-list'>"
                foreach ($r in $comparison.ResolvedFindings | Sort-Object Score -Descending) {
                    $html += "<li class='resolved'><span>$($r.RuleName)</span><span class='points negative'>-$($r.Score) points</span></li>"
                }
                $html += "</ul>"
            }

            if ($comparison.NewFindings.Count -gt 0) {
                $html += "<h2>🆕 New Issues</h2><ul class='finding-list'>"
                foreach ($n in $comparison.NewFindings | Sort-Object Score -Descending) {
                    $html += "<li class='new'><span>$($n.RuleName)</span><span class='points positive'>+$($n.Score) points</span></li>"
                }
                $html += "</ul>"
            }

            $html += "</div></body></html>"

            if (-not $Path) {
                Write-Error "Path required for HTML format"
                return
            }
            $html | Out-File -Path $Path -Encoding UTF8
            Write-Host "Comparison saved to: $Path" -ForegroundColor Green
        }
    }

    return [PSCustomObject]$comparison
}

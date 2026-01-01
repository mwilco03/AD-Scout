function Export-ADScoutHTMLReport {
    <#
    .SYNOPSIS
        Exports AD-Scout results to an HTML report.

    .DESCRIPTION
        Generates a comprehensive HTML report with charts and detailed findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation
    )

    $totalScore = ($Results | Measure-Object -Property Score -Sum).Sum
    $totalFindings = ($Results | Measure-Object -Property FindingCount -Sum).Sum

    $scoreClass = if ($totalScore -ge 100) { 'critical' }
                  elseif ($totalScore -ge 50) { 'warning' }
                  else { 'good' }

    # Generate category summary
    $categorySummary = $Results | Group-Object Category | ForEach-Object {
        $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
        [PSCustomObject]@{
            Category = $_.Name
            Rules = $_.Count
            Score = $catScore
        }
    }

    # Generate findings HTML
    $findingsHtml = $Results | Sort-Object Score -Descending | ForEach-Object {
        $result = $_
        $severityClass = if ($result.Score -ge 50) { 'critical' }
                        elseif ($result.Score -ge 20) { 'warning' }
                        else { 'info' }

        $mitreHtml = if ($result.MITRE) {
            "<div class='tag mitre'>MITRE: $($result.MITRE -join ', ')</div>"
        } else { '' }

        $cisHtml = if ($result.CIS) {
            "<div class='tag cis'>CIS: $($result.CIS -join ', ')</div>"
        } else { '' }

        $findingsListHtml = if ($result.Findings) {
            $items = $result.Findings | Select-Object -First 10 | ForEach-Object {
                $item = if ($_.SamAccountName) { $_.SamAccountName } else { $_ | ConvertTo-Json -Compress }
                "<li>$([System.Web.HttpUtility]::HtmlEncode($item))</li>"
            }
            $more = if ($result.FindingCount -gt 10) { "<li class='more'>... and $($result.FindingCount - 10) more</li>" } else { '' }
            "<ul class='findings-list'>$($items -join '')$more</ul>"
        } else { '' }

        @"
        <div class="finding $severityClass">
            <div class="finding-header">
                <span class="rule-id">$($result.RuleId)</span>
                <span class="rule-name">$($result.RuleName)</span>
                <span class="score">Score: $($result.Score)/$($result.MaxScore)</span>
            </div>
            <div class="finding-meta">
                <span class="category">$($result.Category)</span>
                <span class="count">$($result.FindingCount) findings</span>
                $mitreHtml
                $cisHtml
            </div>
            <div class="finding-description">$([System.Web.HttpUtility]::HtmlEncode($result.Description))</div>
            $findingsListHtml
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        :root {
            --critical: #e74c3c;
            --warning: #f39c12;
            --good: #27ae60;
            --info: #3498db;
            --bg: #1a1a2e;
            --card: #16213e;
            --text: #eee;
            --text-secondary: #aaa;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: var(--card);
            border-radius: 10px;
        }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .timestamp { color: var(--text-secondary); }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .summary-card {
            background: var(--card);
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
        }
        .summary-card.critical { border-left: 4px solid var(--critical); }
        .summary-card.warning { border-left: 4px solid var(--warning); }
        .summary-card.good { border-left: 4px solid var(--good); }
        .summary-value { font-size: 2.5rem; font-weight: bold; }
        .summary-label { color: var(--text-secondary); }
        .findings { margin-top: 2rem; }
        .finding {
            background: var(--card);
            margin-bottom: 1rem;
            border-radius: 10px;
            overflow: hidden;
        }
        .finding.critical { border-left: 4px solid var(--critical); }
        .finding.warning { border-left: 4px solid var(--warning); }
        .finding.info { border-left: 4px solid var(--info); }
        .finding-header {
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .rule-id {
            background: rgba(255,255,255,0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
        }
        .rule-name { font-weight: bold; flex-grow: 1; margin-left: 1rem; }
        .score { color: var(--text-secondary); }
        .finding-meta {
            padding: 0 1rem 1rem;
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        .category, .count { color: var(--text-secondary); font-size: 0.9rem; }
        .tag {
            font-size: 0.8rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }
        .tag.mitre { background: rgba(155, 89, 182, 0.3); }
        .tag.cis { background: rgba(52, 152, 219, 0.3); }
        .finding-description {
            padding: 0 1rem 1rem;
            color: var(--text-secondary);
        }
        .findings-list {
            padding: 0 1rem 1rem 2rem;
            color: var(--text-secondary);
            font-family: monospace;
            font-size: 0.9rem;
        }
        .findings-list li { margin-bottom: 0.25rem; }
        .findings-list .more { color: var(--warning); font-style: italic; }
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>$Title</h1>
            <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </header>

        <div class="summary">
            <div class="summary-card $scoreClass">
                <div class="summary-value">$totalScore</div>
                <div class="summary-label">Total Score</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">$($Results.Count)</div>
                <div class="summary-label">Rules with Findings</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">$totalFindings</div>
                <div class="summary-label">Total Findings</div>
            </div>
        </div>

        <h2>Findings</h2>
        <div class="findings">
            $($findingsHtml -join "`n")
        </div>

        <footer>
            <p>Generated by AD-Scout - PowerShell Active Directory Security Assessment</p>
            <p><a href="https://github.com/mwilco03/AD-Scout" style="color: var(--info);">https://github.com/mwilco03/AD-Scout</a></p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Verbose "HTML report saved to: $Path"
}

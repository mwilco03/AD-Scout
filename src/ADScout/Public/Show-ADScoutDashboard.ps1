function Show-ADScoutDashboard {
    <#
    .SYNOPSIS
        Displays an interactive dashboard for AD-Scout results.

    .DESCRIPTION
        Shows a formatted console dashboard with scan results including:
        - Overall security score
        - Findings by category
        - Top issues by severity
        - MITRE ATT&CK coverage

        When -Port is specified, launches a live web dashboard with:
        - Real-time scan results
        - Interactive charts and filtering
        - API endpoints for integration
        - WebSocket updates for live monitoring

    .PARAMETER Results
        Scan results to display. If not provided, runs a new scan.

    .PARAMETER Port
        Port number for the web dashboard (1024-65535). When specified,
        launches an HTTP server hosting an interactive web dashboard.

    .PARAMETER NoBrowser
        When using web dashboard mode, prevents automatic browser launch.

    .PARAMETER EngagementId
        Optional engagement ID to associate with this dashboard session.

    .EXAMPLE
        Show-ADScoutDashboard
        Runs a scan and displays results in the console dashboard.

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Show-ADScoutDashboard -Results $results
        Displays existing results in the console dashboard.

    .EXAMPLE
        Show-ADScoutDashboard -Port 8080
        Launches a web dashboard on http://localhost:8080

    .EXAMPLE
        Show-ADScoutDashboard -Port 8080 -NoBrowser
        Launches web dashboard without opening browser automatically.

    .EXAMPLE
        Invoke-ADScoutScan | Show-ADScoutDashboard -Port 9000
        Pipeline results to a web dashboard.

    .OUTPUTS
        ADScoutResult[]
        Returns the results for pipeline usage.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [ValidateRange(1024, 65535)]
        [int]$Port,

        [Parameter()]
        [switch]$NoBrowser,

        [Parameter()]
        [string]$EngagementId
    )

    begin {
        $allResults = @()
    }

    process {
        if ($Results) {
            $allResults += $Results
        }
    }

    end {
        # If no results provided, run a scan
        if (-not $allResults) {
            Write-Host "Running security scan..." -ForegroundColor Yellow
            $allResults = Invoke-ADScoutScan
        }

        # If Port is specified, launch web dashboard
        if ($Port) {
            Start-ADScoutWebDashboard -Results $allResults -Port $Port -NoBrowser:$NoBrowser -EngagementId $EngagementId
            return $allResults
        }

        # Console dashboard mode
        Write-Host "AD-Scout Dashboard" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan

        if (-not $allResults) {
            Write-Host "No findings to display." -ForegroundColor Green
            return
        }

        # Display console dashboard
        Write-Host "`nDashboard Summary" -ForegroundColor Cyan
        Write-Host "-----------------" -ForegroundColor Cyan

        $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
        $totalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum

        # Score gauge
        $scoreColor = if ($totalScore -ge 100) { 'Red' }
                      elseif ($totalScore -ge 50) { 'Yellow' }
                      else { 'Green' }

        Write-Host "`nOverall Security Score: " -NoNewline
        Write-Host $totalScore -ForegroundColor $scoreColor
        Write-Host "Total Findings: $totalFindings"
        Write-Host "Rules with Issues: $($allResults.Count)"

        # Category breakdown
        Write-Host "`nFindings by Category:" -ForegroundColor Cyan
        $allResults | Group-Object Category | ForEach-Object {
            $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
            $catColor = if ($catScore -ge 30) { 'Red' }
                        elseif ($catScore -ge 15) { 'Yellow' }
                        else { 'White' }
            Write-Host "  $($_.Name): " -NoNewline
            Write-Host "$($_.Count) rules, $catScore points" -ForegroundColor $catColor
        }

        # Top issues
        Write-Host "`nTop Issues by Score:" -ForegroundColor Cyan
        $allResults | Sort-Object Score -Descending | Select-Object -First 5 | ForEach-Object {
            $issueColor = if ($_.Score -ge 20) { 'Red' }
                          elseif ($_.Score -ge 10) { 'Yellow' }
                          else { 'White' }
            Write-Host "  [$($_.RuleId)] " -NoNewline -ForegroundColor Gray
            Write-Host "$($_.RuleName)" -NoNewline
            Write-Host " (Score: $($_.Score))" -ForegroundColor $issueColor
        }

        # MITRE coverage
        $allMitre = $allResults | Where-Object { $_.MITRE } | ForEach-Object { $_.MITRE } | Select-Object -Unique
        if ($allMitre) {
            Write-Host "`nMITRE ATT&CK Techniques Detected:" -ForegroundColor Cyan
            Write-Host "  $($allMitre -join ', ')" -ForegroundColor DarkCyan
        }

        Write-Host "`n"
        Write-Host "Use 'Export-ADScoutReport -Format HTML' for a detailed report." -ForegroundColor Gray
        Write-Host "Use 'Show-ADScoutDashboard -Port 8080' for a live web dashboard." -ForegroundColor Gray

        # Return results for pipeline
        $allResults
    }
}

function Start-ADScoutWebDashboard {
    <#
    .SYNOPSIS
        Internal function to start the web dashboard HTTP server.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Results,
        [int]$Port,
        [switch]$NoBrowser,
        [string]$EngagementId
    )

    # Store results in script scope for API access
    $script:DashboardResults = $Results
    $script:DashboardEngagement = $EngagementId
    $script:DashboardStartTime = Get-Date

    $prefix = "http://localhost:$Port/"

    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add($prefix)
        $listener.Start()

        Write-Host "`nAD-Scout Web Dashboard" -ForegroundColor Cyan
        Write-Host "======================" -ForegroundColor Cyan
        Write-Host "Dashboard URL: " -NoNewline
        Write-Host $prefix -ForegroundColor Green
        Write-Host "Press Ctrl+C to stop the server.`n" -ForegroundColor Yellow

        # Open browser unless suppressed
        if (-not $NoBrowser) {
            try {
                if ($IsWindows -or $env:OS -match 'Windows') {
                    Start-Process $prefix
                } elseif ($IsMacOS) {
                    Start-Process "open" -ArgumentList $prefix
                } elseif ($IsLinux) {
                    Start-Process "xdg-open" -ArgumentList $prefix
                }
            } catch {
                Write-Verbose "Could not open browser automatically: $_"
            }
        }

        # Main request loop
        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $request = $context.Request
                $response = $context.Response

                $path = $request.Url.LocalPath
                Write-Verbose "Request: $($request.HttpMethod) $path"

                # Route the request
                switch -Regex ($path) {
                    '^/$' {
                        $content = Get-ADScoutDashboardHTML -Results $script:DashboardResults
                        Send-ADScoutResponse -Response $response -Content $content -ContentType 'text/html'
                    }
                    '^/api/results$' {
                        $content = $script:DashboardResults | ConvertTo-Json -Depth 10 -Compress
                        Send-ADScoutResponse -Response $response -Content $content -ContentType 'application/json'
                    }
                    '^/api/summary$' {
                        $summary = Get-ADScoutDashboardSummary -Results $script:DashboardResults
                        $content = $summary | ConvertTo-Json -Depth 5 -Compress
                        Send-ADScoutResponse -Response $response -Content $content -ContentType 'application/json'
                    }
                    '^/api/scan$' {
                        if ($request.HttpMethod -eq 'POST') {
                            Write-Host "Running new scan..." -ForegroundColor Yellow
                            $script:DashboardResults = Invoke-ADScoutScan
                            $content = @{ status = 'completed'; resultCount = $script:DashboardResults.Count } | ConvertTo-Json
                            Send-ADScoutResponse -Response $response -Content $content -ContentType 'application/json'
                        } else {
                            Send-ADScoutResponse -Response $response -Content '{"error":"Use POST to trigger scan"}' -ContentType 'application/json' -StatusCode 405
                        }
                    }
                    '^/api/categories$' {
                        $categories = $script:DashboardResults | Group-Object Category | ForEach-Object {
                            @{
                                name = $_.Name
                                count = $_.Count
                                score = ($_.Group | Measure-Object -Property Score -Sum).Sum
                                findings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
                            }
                        }
                        $content = $categories | ConvertTo-Json -Depth 3 -Compress
                        Send-ADScoutResponse -Response $response -Content $content -ContentType 'application/json'
                    }
                    '^/api/health$' {
                        $health = @{
                            status = 'healthy'
                            uptime = ((Get-Date) - $script:DashboardStartTime).TotalSeconds
                            engagement = $script:DashboardEngagement
                            resultCount = if ($script:DashboardResults) { $script:DashboardResults.Count } else { 0 }
                        }
                        $content = $health | ConvertTo-Json -Compress
                        Send-ADScoutResponse -Response $response -Content $content -ContentType 'application/json'
                    }
                    default {
                        Send-ADScoutResponse -Response $response -Content '{"error":"Not found"}' -ContentType 'application/json' -StatusCode 404
                    }
                }
            }
            catch [System.Net.HttpListenerException] {
                # Listener was closed (Ctrl+C)
                break
            }
            catch {
                Write-Warning "Request error: $_"
                try {
                    Send-ADScoutResponse -Response $response -Content "{`"error`":`"$($_.Exception.Message)`"}" -ContentType 'application/json' -StatusCode 500
                } catch { }
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied') {
            Write-Error "Port $Port requires administrator privileges or is already in use. Try a different port."
        } else {
            Write-Error "Failed to start web dashboard: $_"
        }
    }
    finally {
        if ($listener) {
            $listener.Stop()
            $listener.Close()
            Write-Host "`nWeb dashboard stopped." -ForegroundColor Yellow
        }
    }
}

function Send-ADScoutResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Content,
        [string]$ContentType = 'text/html',
        [int]$StatusCode = 200
    )

    $Response.StatusCode = $StatusCode
    $Response.ContentType = "$ContentType; charset=utf-8"
    $Response.Headers.Add('Access-Control-Allow-Origin', '*')
    $Response.Headers.Add('X-Content-Type-Options', 'nosniff')

    $buffer = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

function Get-ADScoutDashboardSummary {
    param([PSCustomObject[]]$Results)

    if (-not $Results) {
        return @{
            totalScore = 0
            totalFindings = 0
            ruleCount = 0
            severityCounts = @{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
            categories = @()
        }
    }

    $totalScore = ($Results | Measure-Object -Property Score -Sum).Sum
    $totalFindings = ($Results | Measure-Object -Property FindingCount -Sum).Sum

    @{
        totalScore = $totalScore
        totalFindings = $totalFindings
        ruleCount = $Results.Count
        securityScore = [math]::Max(0, 100 - [math]::Min(100, $totalScore))
        severityCounts = @{
            critical = @($Results | Where-Object { $_.Score -ge 50 }).Count
            high = @($Results | Where-Object { $_.Score -ge 30 -and $_.Score -lt 50 }).Count
            medium = @($Results | Where-Object { $_.Score -ge 15 -and $_.Score -lt 30 }).Count
            low = @($Results | Where-Object { $_.Score -ge 5 -and $_.Score -lt 15 }).Count
            info = @($Results | Where-Object { $_.Score -lt 5 }).Count
        }
        categories = @($Results | Group-Object Category | ForEach-Object {
            @{
                name = $_.Name
                count = $_.Count
                score = ($_.Group | Measure-Object -Property Score -Sum).Sum
            }
        })
        generatedAt = (Get-Date).ToString('o')
    }
}

function Get-ADScoutDashboardHTML {
    param([PSCustomObject[]]$Results)

    $summary = Get-ADScoutDashboardSummary -Results $Results

    $categoryRows = if ($Results) {
        $Results | Group-Object Category | Sort-Object { ($_.Group | Measure-Object -Property Score -Sum).Sum } -Descending | ForEach-Object {
            $score = ($_.Group | Measure-Object -Property Score -Sum).Sum
            $findings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
            $severityClass = if ($score -ge 50) { 'critical' } elseif ($score -ge 25) { 'warning' } else { 'good' }
            "<tr class='category-row $severityClass' onclick='filterCategory(`"$($_.Name)`")'><td>$($_.Name)</td><td>$($_.Count)</td><td>$findings</td><td>$score</td></tr>"
        }
    } else { "<tr><td colspan='4'>No findings</td></tr>" }

    $findingsRows = if ($Results) {
        $Results | Sort-Object Score -Descending | Select-Object -First 50 | ForEach-Object {
            $severity = if ($_.Score -ge 50) { 'critical' }
                       elseif ($_.Score -ge 30) { 'high' }
                       elseif ($_.Score -ge 15) { 'medium' }
                       elseif ($_.Score -ge 5) { 'low' }
                       else { 'info' }
            "<tr class='finding-row' data-category='$($_.Category)' data-severity='$severity'>
                <td><span class='severity-badge $severity'>$severity</span></td>
                <td><code>$($_.RuleId)</code></td>
                <td>$($_.RuleName)</td>
                <td>$($_.Category)</td>
                <td>$($_.FindingCount)</td>
                <td>$($_.Score)</td>
            </tr>"
        }
    } else { "<tr><td colspan='6'>No findings</td></tr>" }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD-Scout Live Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        h1 {
            background: linear-gradient(135deg, var(--accent), #a371f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2rem;
        }
        .controls { display: flex; gap: 1rem; align-items: center; }
        button {
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .status { color: var(--text-secondary); font-size: 0.85rem; }
        .status.live::before { content: '●'; color: var(--low); margin-right: 0.5rem; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
        }
        .card.score-card { text-align: center; }
        .score-value { font-size: 3rem; font-weight: 700; }
        .score-value.good { color: var(--low); }
        .score-value.warning { color: var(--medium); }
        .score-value.critical { color: var(--critical); }
        .score-label { color: var(--text-secondary); margin-top: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 600; }
        .stat-value.critical { color: var(--critical); }
        .stat-value.high { color: var(--high); }
        .stat-value.medium { color: var(--medium); }
        .stat-value.low { color: var(--low); }
        .stat-value.info { color: var(--info); }
        .stat-label { color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.25rem; }

        .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
        @media (max-width: 900px) { .charts-row { grid-template-columns: 1fr; } }
        .chart-card { background: var(--bg-card); border-radius: 12px; padding: 1.5rem; border: 1px solid var(--border-color); }
        .chart-card h3 { margin-bottom: 1rem; font-size: 1rem; color: var(--text-secondary); }
        .chart-wrapper { height: 250px; }

        section { margin-bottom: 2rem; }
        section h2 { margin-bottom: 1rem; font-size: 1.25rem; color: var(--text-secondary); }
        table { width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 12px; overflow: hidden; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { background: var(--bg-secondary); color: var(--text-secondary); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
        tr:hover { background: var(--bg-secondary); }
        tr:last-child td { border-bottom: none; }
        .category-row { cursor: pointer; }
        .category-row.critical td:first-child { border-left: 3px solid var(--critical); }
        .category-row.warning td:first-child { border-left: 3px solid var(--medium); }
        .category-row.good td:first-child { border-left: 3px solid var(--low); }

        .severity-badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-badge.critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); }
        .severity-badge.high { background: rgba(240, 136, 62, 0.2); color: var(--high); }
        .severity-badge.medium { background: rgba(210, 153, 34, 0.2); color: var(--medium); }
        .severity-badge.low { background: rgba(63, 185, 80, 0.2); color: var(--low); }
        .severity-badge.info { background: rgba(88, 166, 255, 0.2); color: var(--info); }

        .filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .filter-btn {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
        }
        .filter-btn:hover, .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
        code { font-family: 'SF Mono', Consolas, monospace; font-size: 0.85rem; color: var(--accent); }
        footer { text-align: center; color: var(--text-secondary); padding: 2rem 0; font-size: 0.85rem; }
        footer a { color: var(--accent); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>AD-Scout Dashboard</h1>
                <span class="status live">Live - Auto-refreshes every 30s</span>
            </div>
            <div class="controls">
                <button onclick="runScan()" id="scanBtn">Run New Scan</button>
                <button onclick="exportReport()">Export HTML</button>
            </div>
        </header>

        <div class="grid">
            <div class="card score-card">
                <div class="score-value $( if ($summary.securityScore -ge 80) { 'good' } elseif ($summary.securityScore -ge 50) { 'warning' } else { 'critical' } )" id="securityScore">$($summary.securityScore)</div>
                <div class="score-label">Security Score</div>
            </div>
            <div class="card">
                <div class="stat-value" id="totalFindings">$($summary.totalFindings)</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="card">
                <div class="stat-value critical" id="criticalCount">$($summary.severityCounts.critical)</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="card">
                <div class="stat-value high" id="highCount">$($summary.severityCounts.high)</div>
                <div class="stat-label">High</div>
            </div>
            <div class="card">
                <div class="stat-value medium" id="mediumCount">$($summary.severityCounts.medium)</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="card">
                <div class="stat-value low" id="lowCount">$($summary.severityCounts.low)</div>
                <div class="stat-label">Low / Info</div>
            </div>
        </div>

        <div class="charts-row">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <div class="chart-wrapper"><canvas id="severityChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Category Scores</h3>
                <div class="chart-wrapper"><canvas id="categoryChart"></canvas></div>
            </div>
        </div>

        <section>
            <h2>Categories</h2>
            <table id="categoryTable">
                <thead><tr><th>Category</th><th>Rules</th><th>Findings</th><th>Score</th></tr></thead>
                <tbody>$($categoryRows -join '')</tbody>
            </table>
        </section>

        <section>
            <h2>Findings</h2>
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterSeverity('all')">All</button>
                <button class="filter-btn" onclick="filterSeverity('critical')">Critical</button>
                <button class="filter-btn" onclick="filterSeverity('high')">High</button>
                <button class="filter-btn" onclick="filterSeverity('medium')">Medium</button>
                <button class="filter-btn" onclick="filterSeverity('low')">Low</button>
            </div>
            <table id="findingsTable">
                <thead><tr><th>Severity</th><th>Rule ID</th><th>Name</th><th>Category</th><th>Affected</th><th>Score</th></tr></thead>
                <tbody>$($findingsRows -join '')</tbody>
            </table>
        </section>

        <footer>
            <p>AD-Scout Live Dashboard | <a href="/api/results" target="_blank">API: /api/results</a> | <a href="/api/summary" target="_blank">/api/summary</a></p>
        </footer>
    </div>

    <script>
        const colors = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#3fb950', info: '#58a6ff' };
        let severityChart, categoryChart;

        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            setInterval(refreshData, 30000);
        });

        function initCharts() {
            const severityCtx = document.getElementById('severityChart');
            severityChart = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{ data: [$($summary.severityCounts.critical), $($summary.severityCounts.high), $($summary.severityCounts.medium), $($summary.severityCounts.low), $($summary.severityCounts.info)], backgroundColor: [colors.critical, colors.high, colors.medium, colors.low, colors.info], borderWidth: 0 }]
                },
                options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } } }
            });

            const catData = $(($summary.categories | ForEach-Object { "@{ name = '$($_.name)'; score = $($_.score) }" }) -join ', ' | ForEach-Object { "[$_]" });
            const categoryCtx = document.getElementById('categoryChart');
            categoryChart = new Chart(categoryCtx, {
                type: 'bar',
                data: {
                    labels: catData.map(c => c.name),
                    datasets: [{ data: catData.map(c => c.score), backgroundColor: catData.map(c => c.score >= 50 ? colors.critical : c.score >= 25 ? colors.medium : colors.low), borderRadius: 4 }]
                },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#30363d' }, ticks: { color: '#8b949e' } }, y: { grid: { display: false }, ticks: { color: '#8b949e' } } } }
            });
        }

        async function refreshData() {
            try {
                const res = await fetch('/api/summary');
                const data = await res.json();
                document.getElementById('securityScore').textContent = data.securityScore;
                document.getElementById('totalFindings').textContent = data.totalFindings;
                document.getElementById('criticalCount').textContent = data.severityCounts.critical;
                document.getElementById('highCount').textContent = data.severityCounts.high;
                document.getElementById('mediumCount').textContent = data.severityCounts.medium;
                document.getElementById('lowCount').textContent = data.severityCounts.low + data.severityCounts.info;
                severityChart.data.datasets[0].data = [data.severityCounts.critical, data.severityCounts.high, data.severityCounts.medium, data.severityCounts.low, data.severityCounts.info];
                severityChart.update();
            } catch (e) { console.error('Refresh failed:', e); }
        }

        async function runScan() {
            const btn = document.getElementById('scanBtn');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            try {
                await fetch('/api/scan', { method: 'POST' });
                location.reload();
            } catch (e) {
                alert('Scan failed: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Run New Scan';
            }
        }

        function exportReport() {
            window.open('/api/results', '_blank');
        }

        function filterSeverity(sev) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('.finding-row').forEach(row => {
                row.style.display = (sev === 'all' || row.dataset.severity === sev) ? '' : 'none';
            });
        }

        function filterCategory(cat) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.finding-row').forEach(row => {
                row.style.display = row.dataset.category === cat ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"@
}

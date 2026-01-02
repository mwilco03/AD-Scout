function Show-ADScoutDashboard {
    <#
    .SYNOPSIS
        Displays an interactive web dashboard for AD-Scout results.

    .DESCRIPTION
        Launches a web server to display AD-Scout scan results in an interactive
        dashboard. Provides three views optimized for different personas:

        - Auditor View: Compliance validation and audit documentation
        - Manager View: Executive summary and trend reporting
        - Technician View: Detailed findings and remediation

        Features include:
        - Real-time score display with trend indicators
        - Baseline comparison with drift visualization
        - Category breakdown with drill-down
        - Framework mapping (MITRE ATT&CK, CIS, NIST, STIG)
        - One-click export to HTML, JSON, CSV, SARIF
        - Auto-refresh capability
        - API endpoints for programmatic access

    .PARAMETER Results
        Scan results to display. If not provided, runs a new scan.

    .PARAMETER Baseline
        Path to baseline JSON file for comparison. If not provided,
        looks for adscout-baseline.json in current directory.

    .PARAMETER Port
        TCP port for the web server (default: 8080).

    .PARAMETER Launch
        Automatically open dashboard in default browser.

    .PARAMETER Background
        Run server in background, returning immediately.

    .PARAMETER AutoRefresh
        Enable automatic page refresh.

    .PARAMETER RefreshInterval
        Auto-refresh interval in seconds (default: 60).

    .PARAMETER ConsoleOnly
        Display console dashboard instead of web dashboard.

    .EXAMPLE
        Show-ADScoutDashboard
        Runs a scan and displays results in the web dashboard.

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Show-ADScoutDashboard -Results $results -Launch
        Opens the dashboard in browser with existing results.

    .EXAMPLE
        Show-ADScoutDashboard -Results $results -Baseline ./baseline.json
        Displays results with baseline comparison.

    .EXAMPLE
        Show-ADScoutDashboard -Results $results -Port 9000 -Background
        Runs dashboard on port 9000 in background.

    .EXAMPLE
        Show-ADScoutDashboard -Results $results -AutoRefresh -RefreshInterval 300
        Dashboard with 5-minute auto-refresh.

    .EXAMPLE
        Invoke-ADScoutScan | Show-ADScoutDashboard -ConsoleOnly
        Pipeline results to console dashboard (original behavior).

    .OUTPUTS
        If -Background: Returns the background job object.
        If -ConsoleOnly: Returns the scan results.
        Otherwise: Blocks until server is stopped.

    .NOTES
        Author: AD-Scout Contributors

    .LINK
        https://github.com/mwilco03/AD-Scout
    #>
    [CmdletBinding(DefaultParameterSetName = 'Web')]
    param(
        [Parameter(ValueFromPipeline, Position = 0)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [Alias('BaselinePath')]
        [string]$Baseline,

        [Parameter(ParameterSetName = 'Web')]
        [ValidateRange(1024, 65535)]
        [int]$Port = 8080,

        [Parameter(ParameterSetName = 'Web')]
        [Alias('Open', 'NoBrowser')]
        [switch]$Launch,

        [Parameter(ParameterSetName = 'Web')]
        [switch]$Background,

        [Parameter(ParameterSetName = 'Web')]
        [switch]$AutoRefresh,

        [Parameter(ParameterSetName = 'Web')]
        [ValidateRange(10, 3600)]
        [int]$RefreshInterval = 60,

        [Parameter(ParameterSetName = 'Console')]
        [switch]$ConsoleOnly
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
        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Host "Running AD-Scout security scan..." -ForegroundColor Yellow
            $allResults = Invoke-ADScoutScan
        }

        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Host "No findings to display." -ForegroundColor Green
            return
        }

        # Console-only mode (original behavior)
        if ($ConsoleOnly) {
            Show-ConsoleDashboard -Results $allResults
            return $allResults
        }

        # Web dashboard mode
        Write-Host "AD-Scout Live Dashboard" -ForegroundColor Cyan
        Write-Host "=======================" -ForegroundColor Cyan

        # Prepare dashboard data
        $dashboardData = Get-DashboardData -Results $allResults -BaselinePath $Baseline

        # Display summary before launching
        $score = $dashboardData.Summary.NormalizedScore
        $scoreColor = switch ($score) {
            { $_ -ge 61 } { 'Green' }
            { $_ -ge 31 } { 'Yellow' }
            default { 'Red' }
        }

        Write-Host ""
        Write-Host "Security Score: " -NoNewline
        Write-Host "$score/100 " -ForegroundColor $scoreColor -NoNewline
        Write-Host "(Grade: $($dashboardData.Summary.Grade))"
        Write-Host "Total Findings: $($dashboardData.Summary.TotalFindings)"
        Write-Host "Rules with Issues: $($dashboardData.Summary.RulesWithFindings)"

        if (-not $dashboardData.State.IsFirstRun) {
            $trend = $dashboardData.Comparison.Trend
            $arrow = $dashboardData.Comparison.TrendArrow
            $delta = $dashboardData.Comparison.ScoreDelta
            $trendColor = switch ($trend) {
                'Improving' { 'Green' }
                'Degrading' { 'Red' }
                default { 'Gray' }
            }
            Write-Host "Trend: " -NoNewline
            Write-Host "$arrow $trend ($delta points)" -ForegroundColor $trendColor
        } else {
            Write-Host "Status: " -NoNewline
            Write-Host "Initial Assessment" -ForegroundColor Cyan
        }

        Write-Host ""

        # Get templates path
        $templatesPath = Join-Path $PSScriptRoot '..\Templates\Dashboard'
        if (-not (Test-Path $templatesPath)) {
            # Fallback for module installation path
            $templatesPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Templates\Dashboard'
        }

        # Verify templates exist
        if (-not (Test-Path $templatesPath)) {
            Write-Error "Dashboard templates not found at: $templatesPath"
            Write-Host "Falling back to console dashboard..." -ForegroundColor Yellow
            Show-ConsoleDashboard -Results $allResults
            return $allResults
        }

        # Build server parameters
        $serverParams = @{
            Port = $Port
            DashboardData = $dashboardData
            Results = $allResults
            BaselinePath = $Baseline
            TemplatesPath = $templatesPath
            AutoRefresh = $AutoRefresh
            RefreshInterval = $RefreshInterval
        }

        if ($Background) {
            $serverParams['Background'] = $true
        }

        # Launch browser if requested
        if ($Launch -and -not $Background) {
            # Launch browser after a short delay
            $launchJob = Start-Job -ScriptBlock {
                param($url)
                Start-Sleep -Milliseconds 1500
                Start-Process $url
            } -ArgumentList "http://localhost:$Port"
        } elseif ($Launch -and $Background) {
            # Launch immediately since server starts in background
            Start-Sleep -Milliseconds 500
            Start-Process "http://localhost:$Port"
        }

        Write-Host "Starting web dashboard..." -ForegroundColor Cyan
        Write-Host "URL: http://localhost:$Port" -ForegroundColor Green
        Write-Host ""
        Write-Host "Views available:" -ForegroundColor Gray
        Write-Host "  Auditor:    http://localhost:$Port/auditor" -ForegroundColor Gray
        Write-Host "  Manager:    http://localhost:$Port/manager" -ForegroundColor Gray
        Write-Host "  Technician: http://localhost:$Port/technician" -ForegroundColor Gray
        Write-Host ""

        if (-not $Background) {
            Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
            Write-Host ""
        }

        # Start the server
        $result = Start-ADScoutDashboardServer @serverParams

        if ($Background) {
            return $result  # Return job object
        }

        # Clean up browser launch job if it exists
        if ($launchJob) {
            Remove-Job -Job $launchJob -Force -ErrorAction SilentlyContinue
        }

        return $allResults
    }
}

function Show-ConsoleDashboard {
    <#
    .SYNOPSIS
        Displays the original console-based dashboard.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results
    )

    Write-Host "AD-Scout Dashboard" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan

    Write-Host "`nDashboard Summary" -ForegroundColor Cyan
    Write-Host "-----------------" -ForegroundColor Cyan

    $totalScore = ($Results | Measure-Object -Property Score -Sum).Sum
    $totalFindings = ($Results | Measure-Object -Property FindingCount -Sum).Sum

    # Score gauge
    $scoreColor = if ($totalScore -ge 100) { 'Red' }
                  elseif ($totalScore -ge 50) { 'Yellow' }
                  else { 'Green' }

    Write-Host "`nOverall Security Score: " -NoNewline
    Write-Host $totalScore -ForegroundColor $scoreColor
    Write-Host "Total Findings: $totalFindings"
    Write-Host "Rules with Issues: $($Results.Count)"

    # Category breakdown
    Write-Host "`nFindings by Category:" -ForegroundColor Cyan
    $Results | Group-Object Category | ForEach-Object {
        $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
        $catColor = if ($catScore -ge 30) { 'Red' }
                    elseif ($catScore -ge 15) { 'Yellow' }
                    else { 'White' }
        Write-Host "  $($_.Name): " -NoNewline
        Write-Host "$($_.Count) rules, $catScore points" -ForegroundColor $catColor
    }

    # Top issues
    Write-Host "`nTop Issues by Score:" -ForegroundColor Cyan
    $Results | Sort-Object Score -Descending | Select-Object -First 5 | ForEach-Object {
        $issueColor = if ($_.Score -ge 20) { 'Red' }
                      elseif ($_.Score -ge 10) { 'Yellow' }
                      else { 'White' }
        Write-Host "  [$($_.RuleId)] " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.RuleName)" -NoNewline
        Write-Host " (Score: $($_.Score))" -ForegroundColor $issueColor
    }

    # MITRE coverage
    $allMitre = $Results | Where-Object { $_.MITRE } | ForEach-Object { $_.MITRE } | Select-Object -Unique
    if ($allMitre) {
        Write-Host "`nMITRE ATT&CK Techniques Detected:" -ForegroundColor Cyan
        Write-Host "  $($allMitre -join ', ')" -ForegroundColor DarkCyan
    }

    Write-Host "`n"
    Write-Host "Tip: Use 'Show-ADScoutDashboard -Launch' for web dashboard." -ForegroundColor Gray
    Write-Host "     Use 'Export-ADScoutReport -Format HTML' for detailed report." -ForegroundColor Gray
}

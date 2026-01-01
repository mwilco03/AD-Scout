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

        For detailed reports, use Export-ADScoutReport with HTML format.

    .PARAMETER Results
        Scan results to display. If not provided, runs a new scan.

    .PARAMETER Port
        Reserved for future web dashboard functionality.

    .PARAMETER NoBrowser
        Reserved for future web dashboard functionality.

    .EXAMPLE
        Show-ADScoutDashboard
        Runs a scan and displays results in the dashboard.

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Show-ADScoutDashboard -Results $results
        Displays existing results in the dashboard.

    .EXAMPLE
        Invoke-ADScoutScan | Show-ADScoutDashboard
        Pipeline results directly to the dashboard.

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
        [int]$Port = 8080,

        [Parameter()]
        [switch]$NoBrowser
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
        Write-Host "AD-Scout Dashboard" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan

        # If no results provided, run a scan
        if (-not $allResults) {
            Write-Host "Running security scan..." -ForegroundColor Yellow
            $allResults = Invoke-ADScoutScan
        }

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

        # Return results for pipeline
        $allResults
    }
}

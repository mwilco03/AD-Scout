<#
.SYNOPSIS
    Example of using AD-Scout in CI/CD pipelines.

.DESCRIPTION
    Demonstrates how to integrate AD-Scout into automated pipelines
    for continuous security assessment.

.NOTES
    This script is designed to run in CI environments like Azure DevOps,
    GitHub Actions, or Jenkins.
#>

#Requires -Version 5.1

param(
    [Parameter()]
    [string]$OutputPath = './adscout-reports',

    [Parameter()]
    [int]$ScoreThreshold = 50,

    [Parameter()]
    [switch]$FailOnThreshold
)

$ErrorActionPreference = 'Stop'

Write-Host "AD-Scout CI Pipeline Scan" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host "Threshold: $ScoreThreshold points" -ForegroundColor Gray
Write-Host "Fail on threshold: $FailOnThreshold" -ForegroundColor Gray

# Install module if not present
if (-not (Get-Module -ListAvailable ADScout)) {
    Write-Host "`nInstalling ADScout module..." -ForegroundColor Yellow
    Install-Module ADScout -Force -Scope CurrentUser -AllowPrerelease
}

Import-Module ADScout -Force

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Run scan
Write-Host "`nRunning security scan..." -ForegroundColor Yellow
$startTime = Get-Date
$results = Invoke-ADScoutScan
$endTime = Get-Date
$duration = $endTime - $startTime

# Calculate summary
$totalScore = ($results | Measure-Object -Property Score -Sum).Sum
$totalFindings = ($results | Measure-Object -Property FindingCount -Sum).Sum
$rulesWithFindings = $results.Count

# Display summary
Write-Host "`nScan Summary" -ForegroundColor Cyan
Write-Host "------------" -ForegroundColor Gray
Write-Host "Duration: $([math]::Round($duration.TotalSeconds, 2)) seconds"
Write-Host "Total Score: $totalScore"
Write-Host "Rules with Findings: $rulesWithFindings"
Write-Host "Total Findings: $totalFindings"

# Generate reports
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Host "`nGenerating reports..." -ForegroundColor Yellow

# HTML Report
$htmlPath = Join-Path $OutputPath "adscout-report-$timestamp.html"
$results | Export-ADScoutReport -Format HTML -Path $htmlPath
Write-Host "  HTML: $htmlPath" -ForegroundColor Gray

# JSON Report
$jsonPath = Join-Path $OutputPath "adscout-results-$timestamp.json"
$results | Export-ADScoutReport -Format JSON -Path $jsonPath
Write-Host "  JSON: $jsonPath" -ForegroundColor Gray

# CSV Report
$csvPath = Join-Path $OutputPath "adscout-findings-$timestamp.csv"
$results | Export-ADScoutReport -Format CSV -Path $csvPath
Write-Host "  CSV: $csvPath" -ForegroundColor Gray

# SARIF Report (for GitHub Code Scanning)
$sarifPath = Join-Path $OutputPath "adscout-$timestamp.sarif"
$results | Export-ADScoutReport -Format SARIF -Path $sarifPath
Write-Host "  SARIF: $sarifPath" -ForegroundColor Gray

# Generate summary for CI systems
$summaryPath = Join-Path $OutputPath "summary.json"
$summary = [ordered]@{
    scanTime     = $startTime.ToString('o')
    duration     = $duration.TotalSeconds
    totalScore   = $totalScore
    threshold    = $ScoreThreshold
    passed       = $totalScore -lt $ScoreThreshold
    rulesRun     = $rulesWithFindings
    findingsCount = $totalFindings
    categories   = @(
        $results | Group-Object Category | ForEach-Object {
            [ordered]@{
                name     = $_.Name
                rules    = $_.Count
                score    = ($_.Group | Measure-Object -Property Score -Sum).Sum
                findings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
            }
        }
    )
}
$summary | ConvertTo-Json -Depth 5 | Out-File $summaryPath -Encoding UTF8
Write-Host "  Summary: $summaryPath" -ForegroundColor Gray

# Output for CI systems
Write-Host "`n##[group]AD-Scout Results" -ForegroundColor Cyan
$results | Format-Table RuleId, RuleName, Category, Score, FindingCount -AutoSize
Write-Host "##[endgroup]" -ForegroundColor Cyan

# Threshold check
if ($totalScore -ge $ScoreThreshold) {
    Write-Host "`n[WARNING] Score $totalScore exceeds threshold $ScoreThreshold" -ForegroundColor Yellow

    # Show top issues
    Write-Host "`nTop Issues:" -ForegroundColor Yellow
    $results | Sort-Object Score -Descending | Select-Object -First 5 |
        Format-Table RuleId, RuleName, Score, FindingCount -AutoSize

    if ($FailOnThreshold) {
        Write-Host "`n[ERROR] Pipeline failed due to security score threshold" -ForegroundColor Red

        # Set exit code for CI systems
        exit 1
    }
}
else {
    Write-Host "`n[PASSED] Score $totalScore is below threshold $ScoreThreshold" -ForegroundColor Green
}

# Azure DevOps specific outputs
if ($env:TF_BUILD) {
    Write-Host "##vso[task.setvariable variable=ADScoutScore]$totalScore"
    Write-Host "##vso[task.setvariable variable=ADScoutPassed]$($totalScore -lt $ScoreThreshold)"

    if ($totalScore -ge $ScoreThreshold -and $FailOnThreshold) {
        Write-Host "##vso[task.complete result=Failed;]Security score exceeded threshold"
    }
}

# GitHub Actions specific outputs
if ($env:GITHUB_ACTIONS) {
    "adscout_score=$totalScore" | Out-File $env:GITHUB_OUTPUT -Append -Encoding UTF8
    "adscout_passed=$($totalScore -lt $ScoreThreshold)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding UTF8

    # Write summary
    if ($env:GITHUB_STEP_SUMMARY) {
        @"
## AD-Scout Security Scan Results

| Metric | Value |
|--------|-------|
| Total Score | **$totalScore** |
| Threshold | $ScoreThreshold |
| Status | $(if ($totalScore -lt $ScoreThreshold) { 'PASSED' } else { 'FAILED' }) |
| Rules with Findings | $rulesWithFindings |
| Total Findings | $totalFindings |

[View Full Report](./adscout-report-$timestamp.html)
"@ | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding UTF8
    }
}

Write-Host "`nPipeline complete." -ForegroundColor Green

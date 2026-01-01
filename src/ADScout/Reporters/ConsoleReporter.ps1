function Export-ADScoutConsoleReport {
    <#
    .SYNOPSIS
        Outputs AD-Scout results to the console.

    .DESCRIPTION
        Formats and displays scan results with color-coded severity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation,

        [Parameter()]
        [switch]$Detailed
    )

    # Header
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""

    if (-not $Results) {
        Write-Host "  No security issues found." -ForegroundColor Green
        Write-Host ""
        return
    }

    # Summary
    $totalScore = ($Results | Measure-Object -Property Score -Sum).Sum
    $totalFindings = ($Results | Measure-Object -Property FindingCount -Sum).Sum

    $scoreColor = if ($totalScore -ge 100) { 'Red' }
                  elseif ($totalScore -ge 50) { 'Yellow' }
                  else { 'Green' }

    Write-Host "  SUMMARY" -ForegroundColor White
    Write-Host "  -------" -ForegroundColor Gray
    Write-Host "  Total Score:        " -NoNewline
    Write-Host "$totalScore" -ForegroundColor $scoreColor
    Write-Host "  Rules with Findings: $($Results.Count)" -ForegroundColor Gray
    Write-Host "  Total Findings:      $totalFindings" -ForegroundColor Gray
    Write-Host ""

    # Category breakdown
    Write-Host "  FINDINGS BY CATEGORY" -ForegroundColor White
    Write-Host "  --------------------" -ForegroundColor Gray

    $Results | Group-Object Category | Sort-Object Name | ForEach-Object {
        $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
        $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
        $catColor = if ($catScore -ge 30) { 'Red' }
                    elseif ($catScore -ge 15) { 'Yellow' }
                    else { 'White' }

        Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($_.Count) rules, $catFindings findings, $catScore points" -ForegroundColor $catColor
    }

    Write-Host ""
    Write-Host "  DETAILED FINDINGS" -ForegroundColor White
    Write-Host "  -----------------" -ForegroundColor Gray
    Write-Host ""

    # Detailed findings
    foreach ($result in $Results | Sort-Object Score -Descending) {
        $ruleColor = if ($result.Score -ge 50) { 'Red' }
                     elseif ($result.Score -ge 20) { 'Yellow' }
                     else { 'White' }

        Write-Host "  [$($result.RuleId)]" -ForegroundColor $ruleColor -NoNewline
        Write-Host " $($result.RuleName)" -ForegroundColor White
        Write-Host "    Category:  $($result.Category)" -ForegroundColor Gray
        Write-Host "    Findings:  $($result.FindingCount)" -ForegroundColor Gray
        Write-Host "    Score:     $($result.Score)/$($result.MaxScore)" -ForegroundColor $ruleColor

        if ($result.MITRE) {
            Write-Host "    MITRE:     $($result.MITRE -join ', ')" -ForegroundColor DarkCyan
        }

        if ($result.CIS) {
            Write-Host "    CIS:       $($result.CIS -join ', ')" -ForegroundColor DarkCyan
        }

        Write-Host "    $($result.Description)" -ForegroundColor DarkGray

        if ($Detailed -and $result.Findings) {
            Write-Host "    Examples:" -ForegroundColor Gray
            $result.Findings | Select-Object -First 5 | ForEach-Object {
                $findingStr = if ($_.SamAccountName) { $_.SamAccountName } else { $_ | ConvertTo-Json -Compress }
                Write-Host "      - $findingStr" -ForegroundColor DarkYellow
            }
            if ($result.FindingCount -gt 5) {
                Write-Host "      ... and $($result.FindingCount - 5) more" -ForegroundColor DarkGray
            }
        }

        if ($IncludeRemediation -and $result.Remediation) {
            Write-Host "    Remediation:" -ForegroundColor Magenta
            $remediationText = "      See Get-ADScoutRemediation -RuleId '$($result.RuleId)'"
            Write-Host $remediationText -ForegroundColor DarkMagenta
        }

        Write-Host ""
    }

    # Footer
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  Use 'Export-ADScoutReport -Format HTML' for a detailed report" -ForegroundColor Gray
    Write-Host "  Use 'Get-ADScoutRemediation' for remediation scripts" -ForegroundColor Gray
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
}

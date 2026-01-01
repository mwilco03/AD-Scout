function Export-ADScoutConsoleReport {
    <#
    .SYNOPSIS
        Outputs AD-Scout results to the console with color-coded severity.

    .DESCRIPTION
        Formats and displays scan results in a clear, readable format with
        color-coded severity levels, category breakdown, and optional detailed output.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER Title
        Custom title for the report.

    .PARAMETER IncludeRemediation
        Show remediation hints for each finding.

    .PARAMETER Detailed
        Show example affected objects for each finding.

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutConsoleReport

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutConsoleReport -Detailed -IncludeRemediation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation,

        [Parameter()]
        [switch]$Detailed
    )

    begin {
        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        # Helper function to get severity info
        function Get-SeverityInfo {
            param([int]$Score)
            if ($Score -ge 50) {
                @{ Label = 'CRITICAL'; Color = 'Red'; Symbol = '!' }
            } elseif ($Score -ge 30) {
                @{ Label = 'HIGH'; Color = 'Red'; Symbol = '!' }
            } elseif ($Score -ge 15) {
                @{ Label = 'MEDIUM'; Color = 'Yellow'; Symbol = '*' }
            } elseif ($Score -ge 5) {
                @{ Label = 'LOW'; Color = 'Cyan'; Symbol = '-' }
            } else {
                @{ Label = 'INFO'; Color = 'Gray'; Symbol = 'i' }
            }
        }

        # Header
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "    $Title" -ForegroundColor Cyan
        Write-Host "    Active Directory Security Assessment Report" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "    Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        Write-Host ""

        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Host "    No security issues found." -ForegroundColor Green
            Write-Host ""
            Write-Host ("=" * 80) -ForegroundColor DarkCyan
            Write-Host ""
            return
        }

        # Calculate summary statistics
        $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
        if ($null -eq $totalScore) { $totalScore = 0 }
        $totalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
        if ($null -eq $totalFindings) { $totalFindings = 0 }
        $maxPossibleScore = ($allResults | Measure-Object -Property MaxScore -Sum).Sum
        if ($null -eq $maxPossibleScore -or $maxPossibleScore -eq 0) { $maxPossibleScore = 100 }

        # Calculate security score (inverse - lower is better)
        $securityScore = [math]::Max(0, [math]::Round(100 - (($totalScore / $maxPossibleScore) * 100)))

        # Categorize findings by severity
        $criticalFindings = @($allResults | Where-Object { $_.Score -ge 50 })
        $highFindings = @($allResults | Where-Object { $_.Score -ge 30 -and $_.Score -lt 50 })
        $mediumFindings = @($allResults | Where-Object { $_.Score -ge 15 -and $_.Score -lt 30 })
        $lowFindings = @($allResults | Where-Object { $_.Score -ge 5 -and $_.Score -lt 15 })
        $infoFindings = @($allResults | Where-Object { $_.Score -lt 5 })

        # Determine score color and grade
        $scoreColor = if ($securityScore -ge 80) { 'Green' }
                      elseif ($securityScore -ge 60) { 'Yellow' }
                      else { 'Red' }

        $scoreGrade = if ($securityScore -ge 90) { 'A' }
                      elseif ($securityScore -ge 80) { 'B' }
                      elseif ($securityScore -ge 70) { 'C' }
                      elseif ($securityScore -ge 60) { 'D' }
                      else { 'F' }

        # Executive Summary
        Write-Host "    EXECUTIVE SUMMARY" -ForegroundColor White
        Write-Host ("    " + "-" * 40) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Security Score: " -NoNewline -ForegroundColor Gray
        Write-Host "$securityScore/100 " -NoNewline -ForegroundColor $scoreColor
        Write-Host "(Grade: $scoreGrade)" -ForegroundColor $scoreColor
        Write-Host ""
        Write-Host "    Total Risk Score:      $totalScore points" -ForegroundColor Gray
        Write-Host "    Rules with Findings:   $($allResults.Count)" -ForegroundColor Gray
        Write-Host "    Total Affected Objects: $totalFindings" -ForegroundColor Gray
        Write-Host ""

        # Severity Breakdown
        Write-Host "    SEVERITY BREAKDOWN" -ForegroundColor White
        Write-Host ("    " + "-" * 40) -ForegroundColor DarkGray
        Write-Host ""

        $severityWidth = 12
        Write-Host "    " -NoNewline
        Write-Host "CRITICAL".PadRight($severityWidth) -NoNewline -ForegroundColor Red
        Write-Host "HIGH".PadRight($severityWidth) -NoNewline -ForegroundColor Red
        Write-Host "MEDIUM".PadRight($severityWidth) -NoNewline -ForegroundColor Yellow
        Write-Host "LOW".PadRight($severityWidth) -NoNewline -ForegroundColor Cyan
        Write-Host "INFO" -ForegroundColor Gray

        Write-Host "    " -NoNewline
        Write-Host "$($criticalFindings.Count)".PadRight($severityWidth) -NoNewline -ForegroundColor Red
        Write-Host "$($highFindings.Count)".PadRight($severityWidth) -NoNewline -ForegroundColor Red
        Write-Host "$($mediumFindings.Count)".PadRight($severityWidth) -NoNewline -ForegroundColor Yellow
        Write-Host "$($lowFindings.Count)".PadRight($severityWidth) -NoNewline -ForegroundColor Cyan
        Write-Host "$($infoFindings.Count)" -ForegroundColor Gray
        Write-Host ""

        # Category breakdown
        Write-Host "    FINDINGS BY CATEGORY" -ForegroundColor White
        Write-Host ("    " + "-" * 40) -ForegroundColor DarkGray
        Write-Host ""

        $allResults | Group-Object Category | Sort-Object { ($_.Group | Measure-Object -Property Score -Sum).Sum } -Descending | ForEach-Object {
            $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
            $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
            $catColor = if ($catScore -ge 50) { 'Red' }
                        elseif ($catScore -ge 25) { 'Yellow' }
                        else { 'Gray' }

            $catName = $_.Name.PadRight(22)
            Write-Host "    $catName" -NoNewline -ForegroundColor White
            Write-Host "$($_.Count) rules, $catFindings objects, " -NoNewline -ForegroundColor DarkGray
            Write-Host "$catScore pts" -ForegroundColor $catColor
        }

        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "    DETAILED FINDINGS" -ForegroundColor White
        Write-Host ("    " + "-" * 40) -ForegroundColor DarkGray
        Write-Host ""

        # Detailed findings
        foreach ($result in $allResults | Sort-Object Score -Descending) {
            $severityInfo = Get-SeverityInfo -Score $result.Score

            # Finding header
            Write-Host "    [$($severityInfo.Symbol)]" -NoNewline -ForegroundColor $severityInfo.Color
            Write-Host " [$($result.RuleId)]" -NoNewline -ForegroundColor DarkGray
            Write-Host " $($result.RuleName)" -ForegroundColor White

            # Severity and score
            Write-Host "        Severity:  " -NoNewline -ForegroundColor Gray
            Write-Host $severityInfo.Label -ForegroundColor $severityInfo.Color
            Write-Host "        Category:  $($result.Category)" -ForegroundColor Gray
            Write-Host "        Affected:  $($result.FindingCount) objects" -ForegroundColor Gray
            Write-Host "        Score:     $($result.Score)/$($result.MaxScore) points" -ForegroundColor $severityInfo.Color

            # Framework mappings
            $mappings = @()
            if ($result.MITRE -and $result.MITRE.Count -gt 0) {
                $mappings += "MITRE: $($result.MITRE -join ', ')"
            }
            if ($result.CIS -and $result.CIS.Count -gt 0) {
                $mappings += "CIS: $($result.CIS -join ', ')"
            }
            if ($result.STIG -and $result.STIG.Count -gt 0) {
                $mappings += "STIG: $($result.STIG -join ', ')"
            }
            if ($result.NIST -and $result.NIST.Count -gt 0) {
                $mappings += "NIST: $($result.NIST -join ', ')"
            }

            if ($mappings.Count -gt 0) {
                Write-Host "        Frameworks: " -NoNewline -ForegroundColor Gray
                Write-Host ($mappings -join ' | ') -ForegroundColor DarkCyan
            }

            # Description
            Write-Host ""
            Write-Host "        $($result.Description)" -ForegroundColor DarkGray

            # Detailed examples if requested
            if ($Detailed -and $result.Findings -and $result.Findings.Count -gt 0) {
                Write-Host ""
                Write-Host "        Affected Objects:" -ForegroundColor Gray
                $result.Findings | Select-Object -First 5 | ForEach-Object {
                    $findingStr = if ($_.SamAccountName) {
                        $_.SamAccountName
                    } elseif ($_.Name) {
                        $_.Name
                    } elseif ($_.DNSHostName) {
                        $_.DNSHostName
                    } else {
                        ($_ | ConvertTo-Json -Compress -Depth 1).Substring(0, [Math]::Min(60, ($_ | ConvertTo-Json -Compress -Depth 1).Length))
                    }
                    Write-Host "          - $findingStr" -ForegroundColor DarkYellow
                }
                if ($result.FindingCount -gt 5) {
                    Write-Host "          ... and $($result.FindingCount - 5) more" -ForegroundColor DarkGray
                }
            }

            # Remediation hint if requested
            if ($IncludeRemediation) {
                Write-Host ""
                Write-Host "        Remediation:" -ForegroundColor Magenta
                if ($result.TechnicalExplanation) {
                    $explanation = $result.TechnicalExplanation
                    if ($explanation.Length -gt 100) {
                        $explanation = $explanation.Substring(0, 97) + "..."
                    }
                    Write-Host "          $explanation" -ForegroundColor DarkMagenta
                }
                Write-Host "          Run: Get-ADScoutRemediation -RuleId '$($result.RuleId)'" -ForegroundColor DarkMagenta
            }

            Write-Host ""
            Write-Host ("    " + "-" * 72) -ForegroundColor DarkGray
            Write-Host ""
        }

        # Priority Recommendations
        if ($criticalFindings.Count -gt 0 -or $highFindings.Count -gt 0) {
            Write-Host "    PRIORITY RECOMMENDATIONS" -ForegroundColor White
            Write-Host ("    " + "-" * 40) -ForegroundColor DarkGray
            Write-Host ""

            $priorityCount = 0
            $topIssues = $allResults | Sort-Object Score -Descending | Select-Object -First 5
            foreach ($issue in $topIssues) {
                $priorityCount++
                $severityInfo = Get-SeverityInfo -Score $issue.Score
                Write-Host "    $priorityCount. " -NoNewline -ForegroundColor White
                Write-Host "[$($severityInfo.Label)] " -NoNewline -ForegroundColor $severityInfo.Color
                Write-Host $issue.RuleName -ForegroundColor White
                Write-Host "       $($issue.FindingCount) affected objects | Score: $($issue.Score)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }

        # Footer
        Write-Host ("=" * 80) -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "    NEXT STEPS" -ForegroundColor White
        Write-Host ""
        Write-Host "    - Export to HTML:  Export-ADScoutReport -Format HTML -Path report.html" -ForegroundColor Gray
        Write-Host "    - Get Remediation: Get-ADScoutRemediation -RuleId '<RuleId>'" -ForegroundColor Gray
        Write-Host "    - NIST Report:     Export-ADScoutReport -Format HTML -Path nist.html" -ForegroundColor Gray
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor DarkCyan
        Write-Host ""
    }
}

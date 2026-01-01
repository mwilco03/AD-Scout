function Export-ADScoutReport {
    <#
    .SYNOPSIS
        Exports AD-Scout scan results to various formats.

    .DESCRIPTION
        Takes scan results from Invoke-ADScoutScan and exports them
        to the specified format. Supports HTML, JSON, CSV, SARIF, and Console output.

    .PARAMETER Results
        The scan results to export. Accepts pipeline input from Invoke-ADScoutScan.

    .PARAMETER Format
        The output format. Valid values: HTML, JSON, CSV, SARIF, Markdown, Console.

    .PARAMETER Path
        The output file path. Required for file-based formats (HTML, JSON, CSV, SARIF, Markdown).

    .PARAMETER Title
        Custom title for the report.

    .PARAMETER IncludeRemediation
        Include remediation scripts in the output.

    .PARAMETER PassThru
        Return the results object in addition to exporting.

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutReport -Format Console
        Outputs results to the console.

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutReport -Format HTML -Path ./report.html
        Exports results to an HTML file.

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Export-ADScoutReport -Results $results -Format JSON -Path ./results.json
        Exports results to a JSON file.

    .OUTPUTS
        None, or PSCustomObject[] if PassThru is specified.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [ValidateSet('HTML', 'JSON', 'CSV', 'SARIF', 'Markdown', 'Console')]
        [string]$Format,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        if (-not $allResults) {
            Write-Warning "No results to export"
            return
        }

        # Validate path for file-based formats
        if ($Format -ne 'Console' -and -not $Path) {
            Write-Error "Path is required for $Format format"
            return
        }

        Write-Verbose "Exporting $($allResults.Count) results to $Format format"

        switch ($Format) {
            'Console' {
                # Load and execute console reporter
                $reporterPath = Join-Path $PSScriptRoot '..\Reporters\ConsoleReporter.ps1'
                if (Test-Path $reporterPath) {
                    . $reporterPath
                    Export-ADScoutConsoleReport -Results $allResults -Title $Title -IncludeRemediation:$IncludeRemediation
                }
                else {
                    # Fallback console output
                    Write-Host "`n$Title" -ForegroundColor Cyan
                    Write-Host ("=" * $Title.Length) -ForegroundColor Cyan
                    Write-Host "`nScan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
                    Write-Host "Total findings: $($allResults.Count) rules with issues`n" -ForegroundColor Gray

                    foreach ($result in $allResults | Sort-Object -Property Score -Descending) {
                        $color = if ($result.Score -ge 50) { 'Red' }
                                 elseif ($result.Score -ge 20) { 'Yellow' }
                                 else { 'White' }

                        Write-Host "[$($result.RuleId)]" -ForegroundColor $color -NoNewline
                        Write-Host " $($result.RuleName)" -ForegroundColor White
                        Write-Host "  Category: $($result.Category)" -ForegroundColor Gray
                        Write-Host "  Findings: $($result.FindingCount)" -ForegroundColor Gray
                        Write-Host "  Score: $($result.Score)/$($result.MaxScore)" -ForegroundColor $color

                        if ($result.MITRE) {
                            Write-Host "  MITRE: $($result.MITRE -join ', ')" -ForegroundColor DarkCyan
                        }

                        Write-Host ""
                    }

                    $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
                    Write-Host "Total Score: $totalScore" -ForegroundColor $(if ($totalScore -ge 100) { 'Red' } elseif ($totalScore -ge 50) { 'Yellow' } else { 'Green' })
                }
            }

            'JSON' {
                $jsonOutput = @{
                    Title      = $Title
                    GeneratedAt = (Get-Date).ToString('o')
                    Summary    = @{
                        TotalRulesWithFindings = $allResults.Count
                        TotalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
                        TotalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
                    }
                    Results    = $allResults | ForEach-Object {
                        $result = $_
                        @{
                            RuleId       = $result.RuleId
                            RuleName     = $result.RuleName
                            Category     = $result.Category
                            Description  = $result.Description
                            FindingCount = $result.FindingCount
                            Score        = $result.Score
                            MaxScore     = $result.MaxScore
                            MITRE        = $result.MITRE
                            CIS          = $result.CIS
                            STIG         = $result.STIG
                            Findings     = $result.Findings
                        }
                    }
                }

                $jsonOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Verbose "JSON report saved to: $Path"
            }

            'CSV' {
                $csvData = $allResults | ForEach-Object {
                    $result = $_
                    foreach ($finding in $result.Findings) {
                        [PSCustomObject]@{
                            RuleId       = $result.RuleId
                            RuleName     = $result.RuleName
                            Category     = $result.Category
                            Score        = $result.Score
                            MITRE        = ($result.MITRE -join ';')
                            CIS          = ($result.CIS -join ';')
                            Finding      = ($finding | ConvertTo-Json -Compress)
                        }
                    }
                }

                $csvData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Verbose "CSV report saved to: $Path"
            }

            'HTML' {
                $reporterPath = Join-Path $PSScriptRoot '..\Reporters\HTMLReporter.ps1'
                if (Test-Path $reporterPath) {
                    . $reporterPath
                    Export-ADScoutHTMLReport -Results $allResults -Path $Path -Title $Title -IncludeRemediation:$IncludeRemediation
                }
                else {
                    Write-Warning "HTML reporter not found. Use JSON or CSV format."
                }
            }

            'SARIF' {
                # SARIF format for DevSecOps integration
                $sarifOutput = @{
                    '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
                    version = '2.1.0'
                    runs = @(
                        @{
                            tool = @{
                                driver = @{
                                    name = 'AD-Scout'
                                    version = (Get-Module ADScout).Version.ToString()
                                    informationUri = 'https://github.com/mwilco03/AD-Scout'
                                    rules = $allResults | ForEach-Object {
                                        @{
                                            id = $_.RuleId
                                            name = $_.RuleName
                                            shortDescription = @{ text = $_.Description }
                                            properties = @{
                                                category = $_.Category
                                                mitre = $_.MITRE
                                            }
                                        }
                                    }
                                }
                            }
                            results = $allResults | ForEach-Object {
                                $result = $_
                                @{
                                    ruleId = $result.RuleId
                                    level = if ($result.Score -ge 50) { 'error' } elseif ($result.Score -ge 20) { 'warning' } else { 'note' }
                                    message = @{ text = "$($result.RuleName): $($result.FindingCount) findings" }
                                    properties = @{
                                        score = $result.Score
                                        findingCount = $result.FindingCount
                                    }
                                }
                            }
                        }
                    )
                }

                $sarifOutput | ConvertTo-Json -Depth 20 | Out-File -FilePath $Path -Encoding UTF8
                Write-Verbose "SARIF report saved to: $Path"
            }

            'Markdown' {
                # Calculate summary statistics
                $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
                if ($null -eq $totalScore) { $totalScore = 0 }
                $totalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
                if ($null -eq $totalFindings) { $totalFindings = 0 }
                $maxPossibleScore = ($allResults | Measure-Object -Property MaxScore -Sum).Sum
                if ($null -eq $maxPossibleScore -or $maxPossibleScore -eq 0) { $maxPossibleScore = 100 }

                # Calculate security score
                $securityScore = [math]::Max(0, [math]::Round(100 - (($totalScore / $maxPossibleScore) * 100)))
                $scoreGrade = if ($securityScore -ge 90) { 'A' }
                              elseif ($securityScore -ge 80) { 'B' }
                              elseif ($securityScore -ge 70) { 'C' }
                              elseif ($securityScore -ge 60) { 'D' }
                              else { 'F' }

                # Categorize findings by severity
                $criticalFindings = @($allResults | Where-Object { $_.Score -ge 50 })
                $highFindings = @($allResults | Where-Object { $_.Score -ge 30 -and $_.Score -lt 50 })
                $mediumFindings = @($allResults | Where-Object { $_.Score -ge 15 -and $_.Score -lt 30 })
                $lowFindings = @($allResults | Where-Object { $_.Score -ge 5 -and $_.Score -lt 15 })
                $infoFindings = @($allResults | Where-Object { $_.Score -lt 5 })

                $mdContent = @"
# $Title

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Security Score** | $securityScore/100 (Grade: $scoreGrade) |
| **Total Risk Score** | $totalScore points |
| **Rules with Findings** | $($allResults.Count) |
| **Total Affected Objects** | $totalFindings |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | $($criticalFindings.Count) |
| High | $($highFindings.Count) |
| Medium | $($mediumFindings.Count) |
| Low | $($lowFindings.Count) |
| Info | $($infoFindings.Count) |

---

## Category Breakdown

| Category | Rules | Findings | Score |
|----------|-------|----------|-------|

"@

                # Category summary
                $allResults | Group-Object Category | Sort-Object { ($_.Group | Measure-Object -Property Score -Sum).Sum } -Descending | ForEach-Object {
                    $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
                    $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
                    $mdContent += "| $($_.Name) | $($_.Count) | $catFindings | $catScore |`n"
                }

                $mdContent += @"

---

## Detailed Findings

"@

                foreach ($result in $allResults | Sort-Object -Property Score -Descending) {
                    # Determine severity
                    $severity = if ($result.Score -ge 50) { 'CRITICAL' }
                               elseif ($result.Score -ge 30) { 'HIGH' }
                               elseif ($result.Score -ge 15) { 'MEDIUM' }
                               elseif ($result.Score -ge 5) { 'LOW' }
                               else { 'INFO' }

                    $mdContent += @"

### [$severity] $($result.RuleId) - $($result.RuleName)

| Property | Value |
|----------|-------|
| **Severity** | $severity |
| **Category** | $($result.Category) |
| **Affected Objects** | $($result.FindingCount) |
| **Score** | $($result.Score)/$($result.MaxScore) |

**Description:** $($result.Description)

"@

                    # Framework mappings
                    $mappings = @()
                    if ($result.MITRE -and $result.MITRE.Count -gt 0) {
                        $mappings += "- **MITRE ATT&CK:** $($result.MITRE -join ', ')"
                    }
                    if ($result.CIS -and $result.CIS.Count -gt 0) {
                        $mappings += "- **CIS Controls:** $($result.CIS -join ', ')"
                    }
                    if ($result.STIG -and $result.STIG.Count -gt 0) {
                        $mappings += "- **DISA STIG:** $($result.STIG -join ', ')"
                    }
                    if ($result.NIST -and $result.NIST.Count -gt 0) {
                        $mappings += "- **NIST 800-53:** $($result.NIST -join ', ')"
                    }

                    if ($mappings.Count -gt 0) {
                        $mdContent += "**Framework Mappings:**`n"
                        $mdContent += ($mappings -join "`n") + "`n"
                    }

                    # Show example findings
                    if ($result.Findings -and $result.Findings.Count -gt 0) {
                        $mdContent += "`n**Affected Objects (first 10):**`n`n"
                        $displayFindings = $result.Findings | Select-Object -First 10
                        foreach ($finding in $displayFindings) {
                            $findingStr = if ($finding.SamAccountName) { $finding.SamAccountName }
                                         elseif ($finding.Name) { $finding.Name }
                                         elseif ($finding.DNSHostName) { $finding.DNSHostName }
                                         else { ($finding | ConvertTo-Json -Compress -Depth 1) }
                            $mdContent += "- ``$findingStr```n"
                        }
                        if ($result.FindingCount -gt 10) {
                            $mdContent += "- *... and $($result.FindingCount - 10) more*`n"
                        }
                    }

                    # Technical explanation if available
                    if ($result.TechnicalExplanation) {
                        $mdContent += "`n**Technical Details:** $($result.TechnicalExplanation)`n"
                    }

                    # References if available
                    if ($result.References -and $result.References.Count -gt 0) {
                        $mdContent += "`n**References:**`n"
                        foreach ($ref in $result.References) {
                            $mdContent += "- $ref`n"
                        }
                    }

                    $mdContent += "`n---`n"
                }

                # Priority Recommendations
                if ($criticalFindings.Count -gt 0 -or $highFindings.Count -gt 0) {
                    $mdContent += @"

## Priority Remediation Steps

"@
                    $priorityCount = 0
                    $topIssues = $allResults | Sort-Object Score -Descending | Select-Object -First 10
                    foreach ($issue in $topIssues) {
                        $priorityCount++
                        $severity = if ($issue.Score -ge 50) { 'CRITICAL' }
                                   elseif ($issue.Score -ge 30) { 'HIGH' }
                                   elseif ($issue.Score -ge 15) { 'MEDIUM' }
                                   else { 'LOW' }
                        $mdContent += "$priorityCount. **[$severity]** $($issue.RuleName) - $($issue.FindingCount) affected objects`n"
                    }
                }

                $mdContent += @"

---

## Appendix

### Scan Information

- **Report Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- **PowerShell Version:** $($PSVersionTable.PSVersion.ToString())
- **AD-Scout Version:** $(try { (Get-Module ADScout).Version.ToString() } catch { '1.0.0' })

### Framework Coverage

This assessment includes mappings to:
- MITRE ATT&CK for Enterprise
- CIS Microsoft Windows Server Benchmarks
- DISA STIGs for Active Directory
- NIST 800-53 Security Controls
- ANSSI Active Directory Guidelines

---

*Report generated by [AD-Scout](https://github.com/mwilco03/AD-Scout) - Open Source Active Directory Security Assessment*
"@

                $mdContent | Out-File -FilePath $Path -Encoding UTF8
                Write-Verbose "Markdown report saved to: $Path"
                Write-Host "Markdown report saved to: $Path" -ForegroundColor Green
            }
        }

        if ($PassThru) {
            $allResults
        }
    }
}

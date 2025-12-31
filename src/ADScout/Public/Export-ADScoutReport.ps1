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
                $mdContent = @"
# $Title

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Summary

| Metric | Value |
|--------|-------|
| Rules with Findings | $($allResults.Count) |
| Total Findings | $(($allResults | Measure-Object -Property FindingCount -Sum).Sum) |
| Total Score | $(($allResults | Measure-Object -Property Score -Sum).Sum) |

## Findings

"@

                foreach ($result in $allResults | Sort-Object -Property Score -Descending) {
                    $mdContent += @"

### $($result.RuleId) - $($result.RuleName)

- **Category:** $($result.Category)
- **Findings:** $($result.FindingCount)
- **Score:** $($result.Score)/$($result.MaxScore)
$(if ($result.MITRE) { "- **MITRE ATT&CK:** $($result.MITRE -join ', ')" })
$(if ($result.CIS) { "- **CIS Controls:** $($result.CIS -join ', ')" })

$($result.Description)

"@
                }

                $mdContent | Out-File -FilePath $Path -Encoding UTF8
                Write-Verbose "Markdown report saved to: $Path"
            }
        }

        if ($PassThru) {
            $allResults
        }
    }
}

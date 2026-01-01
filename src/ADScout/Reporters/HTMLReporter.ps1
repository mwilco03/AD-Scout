function Export-ADScoutHTMLReport {
    <#
    .SYNOPSIS
        Exports AD-Scout results to a beautiful, interactive HTML report.

    .DESCRIPTION
        Generates a comprehensive HTML report with executive summary, category breakdown,
        detailed findings with framework mappings, remediation scripts, and interactive
        filtering capabilities. Uses embedded CSS for self-contained reports.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER Path
        The output file path for the HTML report.

    .PARAMETER Title
        Custom title for the report.

    .PARAMETER IncludeRemediation
        Include PowerShell remediation scripts in the output.

    .PARAMETER Domain
        Domain name to display in the report. Auto-detected if not specified.

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutHTMLReport -Path ./report.html

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Export-ADScoutHTMLReport -Results $results -Path ./report.html -IncludeRemediation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation,

        [Parameter()]
        [string]$Domain
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

        # Auto-detect domain if not specified
        if (-not $Domain) {
            $Domain = try {
                (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot
            } catch {
                $env:USERDNSDOMAIN
            }
            if (-not $Domain) { $Domain = "Active Directory" }
        }

        # Calculate summary statistics
        $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
        if ($null -eq $totalScore) { $totalScore = 0 }
        $totalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
        if ($null -eq $totalFindings) { $totalFindings = 0 }
        $maxPossibleScore = ($allResults | Measure-Object -Property MaxScore -Sum).Sum
        if ($null -eq $maxPossibleScore -or $maxPossibleScore -eq 0) { $maxPossibleScore = 100 }

        # Calculate security score (inverse - lower is better, so we show 100 - percentage)
        $securityScore = [math]::Max(0, [math]::Round(100 - (($totalScore / $maxPossibleScore) * 100)))

        # Categorize findings by severity
        $criticalFindings = @($allResults | Where-Object { $_.Score -ge 50 })
        $highFindings = @($allResults | Where-Object { $_.Score -ge 30 -and $_.Score -lt 50 })
        $mediumFindings = @($allResults | Where-Object { $_.Score -ge 15 -and $_.Score -lt 30 })
        $lowFindings = @($allResults | Where-Object { $_.Score -ge 5 -and $_.Score -lt 15 })
        $infoFindings = @($allResults | Where-Object { $_.Score -lt 5 })

        # Determine overall score class and grade
        $scoreClass = if ($securityScore -ge 80) { 'good' }
                      elseif ($securityScore -ge 60) { 'warning' }
                      else { 'critical' }

        $scoreGrade = if ($securityScore -ge 90) { 'A' }
                      elseif ($securityScore -ge 80) { 'B' }
                      elseif ($securityScore -ge 70) { 'C' }
                      elseif ($securityScore -ge 60) { 'D' }
                      else { 'F' }

        # Generate summary text
        $summaryText = if ($criticalFindings.Count -gt 0) {
            "This assessment identified $($criticalFindings.Count) critical security issue$(if($criticalFindings.Count -ne 1){'s'}) requiring immediate attention. " +
            "A total of $totalFindings finding$(if($totalFindings -ne 1){'s'}) were discovered across $($allResults.Count) security rules. " +
            "Priority should be given to addressing critical and high severity findings to reduce attack surface."
        } elseif ($highFindings.Count -gt 0) {
            "No critical issues were found, but $($highFindings.Count) high severity finding$(if($highFindings.Count -ne 1){'s'}) require attention. " +
            "The environment shows reasonable security posture with room for improvement."
        } else {
            "The Active Directory environment demonstrates good security practices. " +
            "Continue monitoring and addressing the $($mediumFindings.Count + $lowFindings.Count) remaining lower-severity findings."
        }

        # Generate category summary HTML
        $categoryIcons = @{
            'StaleObjects' = '&#128368;'      # Clock
            'PrivilegedAccounts' = '&#128081;' # Crown
            'Kerberos' = '&#128273;'           # Key
            'Authentication' = '&#128274;'     # Lock
            'Trusts' = '&#129309;'             # Handshake
            'GPO' = '&#128196;'                # Document
            'PKI' = '&#128272;'                # Certificate
            'Anomalies' = '&#128200;'          # Chart
            'AttackVectors' = '&#9888;'        # Warning
            'ServiceAccounts' = '&#128101;'    # People
            'DLLRequired' = '&#128268;'        # Plugin
            'Persistence' = '&#128279;'        # Link
            'Logging' = '&#128203;'            # Clipboard
            'Infrastructure' = '&#127959;'     # Building
            'DataProtection' = '&#128737;'     # Shield
            'LateralMovement' = '&#10145;'     # Arrow
        }

        $categorySummary = $allResults | Group-Object Category | ForEach-Object {
            $catScore = ($_.Group | Measure-Object -Property Score -Sum).Sum
            $catMax = ($_.Group | Measure-Object -Property MaxScore -Sum).Sum
            $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
            $percentage = if ($catMax -gt 0) { [math]::Round(($catScore / $catMax) * 100) } else { 0 }
            $categoryClass = if ($percentage -ge 50) { 'critical' } elseif ($percentage -ge 25) { 'warning' } else { 'good' }
            $icon = if ($categoryIcons.ContainsKey($_.Name)) { $categoryIcons[$_.Name] } else { '&#128736;' }

            [PSCustomObject]@{
                Name = $_.Name
                Icon = $icon
                Score = $catScore
                MaxScore = $catMax
                Percentage = $percentage
                FindingCount = $catFindings
                Class = $categoryClass
            }
        } | Sort-Object Score -Descending

        $categoryHtml = $categorySummary | ForEach-Object {
            @"
            <div class="category-card $($_.Class)">
                <div class="category-icon">$($_.Icon)</div>
                <div class="category-info">
                    <h4>$([System.Web.HttpUtility]::HtmlEncode($_.Name))</h4>
                    <div class="category-score-display">
                        <span class="score-value">$($_.Score)</span>
                        <span class="score-max">/$($_.MaxScore)</span>
                    </div>
                    <div class="category-bar">
                        <div class="category-fill" style="width: $($_.Percentage)%;"></div>
                    </div>
                </div>
                <div class="category-stats">
                    <span class="finding-count">$($_.FindingCount) finding$(if($_.FindingCount -ne 1){'s'})</span>
                </div>
            </div>
"@
        }

        # Generate findings HTML
        $findingsHtml = $allResults | Sort-Object Score -Descending | ForEach-Object {
            $result = $_

            # Determine severity
            $severity = if ($result.Score -ge 50) { 'critical' }
                       elseif ($result.Score -ge 30) { 'high' }
                       elseif ($result.Score -ge 15) { 'medium' }
                       elseif ($result.Score -ge 5) { 'low' }
                       else { 'info' }

            $severityLabel = switch ($severity) {
                'critical' { 'Critical' }
                'high' { 'High' }
                'medium' { 'Medium' }
                'low' { 'Low' }
                'info' { 'Info' }
            }

            # Generate framework tags
            $frameworkTags = @()
            if ($result.MITRE -and $result.MITRE.Count -gt 0) {
                $mitreTags = $result.MITRE | ForEach-Object {
                    "<a href=`"https://attack.mitre.org/techniques/$($_ -replace '\.', '/')/`" target=`"_blank`" class=`"tag mitre`">$_</a>"
                }
                $frameworkTags += $mitreTags
            }
            if ($result.CIS -and $result.CIS.Count -gt 0) {
                $cisTags = $result.CIS | ForEach-Object { "<span class=`"tag cis`">CIS $_</span>" }
                $frameworkTags += $cisTags
            }
            if ($result.STIG -and $result.STIG.Count -gt 0) {
                $stigTags = $result.STIG | ForEach-Object { "<span class=`"tag stig`">$_</span>" }
                $frameworkTags += $stigTags
            }
            if ($result.NIST -and $result.NIST.Count -gt 0) {
                $nistTags = $result.NIST | ForEach-Object { "<span class=`"tag nist`">NIST $_</span>" }
                $frameworkTags += $nistTags
            }
            $frameworkHtml = if ($frameworkTags.Count -gt 0) { $frameworkTags -join ' ' } else { '' }

            # Generate affected objects table
            $affectedHtml = ''
            if ($result.Findings -and $result.Findings.Count -gt 0) {
                $displayFindings = $result.Findings | Select-Object -First 15

                # Determine what properties to show
                $sampleFinding = $displayFindings[0]
                $properties = @()
                if ($sampleFinding.PSObject.Properties['SamAccountName']) { $properties += 'SamAccountName' }
                if ($sampleFinding.PSObject.Properties['Name']) { $properties += 'Name' }
                if ($sampleFinding.PSObject.Properties['DistinguishedName']) { $properties += 'DistinguishedName' }
                if ($sampleFinding.PSObject.Properties['DNSHostName']) { $properties += 'DNSHostName' }
                if ($sampleFinding.PSObject.Properties['LastLogonDate']) { $properties += 'LastLogonDate' }
                if ($sampleFinding.PSObject.Properties['PasswordLastSet']) { $properties += 'PasswordLastSet' }
                if ($sampleFinding.PSObject.Properties['Enabled']) { $properties += 'Enabled' }

                if ($properties.Count -eq 0) {
                    # Fallback - show as JSON
                    $affectedItems = $displayFindings | ForEach-Object {
                        $item = if ($_.SamAccountName) { $_.SamAccountName }
                               elseif ($_.Name) { $_.Name }
                               else { $_ | ConvertTo-Json -Compress -Depth 1 }
                        "<li>$([System.Web.HttpUtility]::HtmlEncode($item))</li>"
                    }
                    $moreText = if ($result.FindingCount -gt 15) {
                        "<li class=`"more`">... and $($result.FindingCount - 15) more</li>"
                    } else { '' }
                    $affectedHtml = "<ul class=`"findings-list`">$($affectedItems -join '')$moreText</ul>"
                } else {
                    # Show as table
                    $headers = $properties | ForEach-Object { "<th>$_</th>" }
                    $rows = $displayFindings | ForEach-Object {
                        $finding = $_
                        $cells = $properties | ForEach-Object {
                            $value = $finding.$_
                            if ($value -is [datetime]) {
                                $value = $value.ToString('yyyy-MM-dd HH:mm')
                            }
                            $displayValue = [System.Web.HttpUtility]::HtmlEncode($value)
                            if ($_ -eq 'DistinguishedName' -and $displayValue.Length -gt 60) {
                                $displayValue = $displayValue.Substring(0, 57) + '...'
                            }
                            "<td>$displayValue</td>"
                        }
                        "<tr>$($cells -join '')</tr>"
                    }
                    $moreRow = if ($result.FindingCount -gt 15) {
                        "<tr class=`"more-row`"><td colspan=`"$($properties.Count)`">... and $($result.FindingCount - 15) more affected objects</td></tr>"
                    } else { '' }
                    $affectedHtml = @"
                    <div class="table-container">
                        <table class="affected-table">
                            <thead><tr>$($headers -join '')</tr></thead>
                            <tbody>$($rows -join '')$moreRow</tbody>
                        </table>
                    </div>
"@
                }
            }

            # Generate remediation section
            $remediationHtml = ''
            if ($IncludeRemediation) {
                $remediationDesc = if ($result.TechnicalExplanation) {
                    [System.Web.HttpUtility]::HtmlEncode($result.TechnicalExplanation)
                } else {
                    "Address this finding by reviewing the affected objects and applying appropriate security controls."
                }

                $scriptHtml = ''
                if ($result.Remediation) {
                    $script = try {
                        if ($result.Remediation -is [scriptblock]) {
                            $result.Remediation.ToString()
                        } else {
                            $result.Remediation.ToString()
                        }
                    } catch { '' }

                    if ($script) {
                        $scriptHtml = @"
                        <div class="script-container">
                            <div class="script-warning">Review and test in non-production before execution</div>
                            <pre class="remediation-script"><code>$([System.Web.HttpUtility]::HtmlEncode($script))</code></pre>
                            <button class="copy-btn" onclick="copyScript(this)">Copy Script</button>
                        </div>
"@
                    }
                }

                $remediationHtml = @"
                <div class="remediation-section">
                    <h5>Remediation</h5>
                    <p>$remediationDesc</p>
                    $scriptHtml
                </div>
"@
            }

            # Generate references
            $referencesHtml = ''
            if ($result.References -and $result.References.Count -gt 0) {
                $refItems = $result.References | ForEach-Object {
                    $url = [System.Web.HttpUtility]::HtmlEncode($_)
                    "<li><a href=`"$url`" target=`"_blank`">$url</a></li>"
                }
                $referencesHtml = @"
                <div class="references-section">
                    <h5>References</h5>
                    <ul>$($refItems -join '')</ul>
                </div>
"@
            }

            # Build the complete finding card
            @"
            <div class="finding-card $severity" data-severity="$severity" data-category="$([System.Web.HttpUtility]::HtmlEncode($result.Category))">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <div class="finding-title">
                        <span class="severity-badge $severity">$severityLabel</span>
                        <span class="rule-id">$([System.Web.HttpUtility]::HtmlEncode($result.RuleId))</span>
                        <span class="rule-name">$([System.Web.HttpUtility]::HtmlEncode($result.RuleName))</span>
                    </div>
                    <div class="finding-stats">
                        <span class="category-badge">$([System.Web.HttpUtility]::HtmlEncode($result.Category))</span>
                        <span class="finding-count">$($result.FindingCount) affected</span>
                        <span class="score-badge">$($result.Score)/$($result.MaxScore) pts</span>
                        <span class="expand-icon">&#9660;</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-description">
                        <p>$([System.Web.HttpUtility]::HtmlEncode($result.Description))</p>
                    </div>
                    <div class="framework-tags">
                        $frameworkHtml
                    </div>
                    <div class="affected-objects">
                        <h5>Affected Objects ($($result.FindingCount))</h5>
                        $affectedHtml
                    </div>
                    $remediationHtml
                    $referencesHtml
                </div>
            </div>
"@
        }

        # Generate priority remediation steps
        $topIssues = $allResults | Sort-Object Score -Descending | Select-Object -First 10
        $remediationSteps = $topIssues | ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            $severity = if ($_.Score -ge 50) { 'critical' }
                       elseif ($_.Score -ge 30) { 'high' }
                       elseif ($_.Score -ge 15) { 'medium' }
                       else { 'low' }
            @"
            <li class="priority-item $severity">
                <span class="priority-number">$i</span>
                <div class="priority-content">
                    <strong>$([System.Web.HttpUtility]::HtmlEncode($_.RuleName))</strong>
                    <span class="priority-meta">$($_.FindingCount) affected objects | Score: $($_.Score)</span>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($_.Description))</p>
                </div>
            </li>
"@
        }

        # Get scan metadata
        $scanTime = if ($allResults[0].PSObject.Properties['ExecutedAt']) {
            $allResults[0].ExecutedAt
        } else {
            Get-Date
        }
        $psVersion = $PSVersionTable.PSVersion.ToString()
        $moduleVersion = try { (Get-Module ADScout).Version.ToString() } catch { '1.0.0' }

        # Build the complete HTML document
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$([System.Web.HttpUtility]::HtmlEncode($Title)) - $([System.Web.HttpUtility]::HtmlEncode($Domain))</title>
    <style>
        /* CSS Variables */
        :root {
            --critical: #dc3545;
            --critical-bg: rgba(220, 53, 69, 0.1);
            --high: #e74c3c;
            --high-bg: rgba(231, 76, 60, 0.1);
            --warning: #f39c12;
            --warning-bg: rgba(243, 156, 18, 0.1);
            --medium: #fd7e14;
            --medium-bg: rgba(253, 126, 20, 0.1);
            --low: #17a2b8;
            --low-bg: rgba(23, 162, 184, 0.1);
            --good: #28a745;
            --good-bg: rgba(40, 167, 69, 0.1);
            --info: #3498db;
            --info-bg: rgba(52, 152, 219, 0.1);
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-card: #1c2128;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-color: #30363d;
            --accent: #58a6ff;
            --shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
            --shadow-sm: 0 3px 6px rgba(0, 0, 0, 0.3);
            --radius: 12px;
            --radius-sm: 6px;
            --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            --font-mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
        }

        @media (prefers-color-scheme: light) {
            :root {
                --bg-primary: #ffffff;
                --bg-secondary: #f6f8fa;
                --bg-tertiary: #eaeef2;
                --bg-card: #ffffff;
                --text-primary: #1f2328;
                --text-secondary: #656d76;
                --text-muted: #8c959f;
                --border-color: #d0d7de;
                --shadow: 0 8px 24px rgba(140, 149, 159, 0.2);
                --shadow-sm: 0 3px 6px rgba(140, 149, 159, 0.15);
            }
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--font-family);
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Header */
        .report-header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: var(--radius);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.5rem;
        }

        .logo h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent) 0%, #a371f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .tagline {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }

        .report-meta {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            text-align: right;
        }

        .meta-item {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .meta-item .value {
            color: var(--text-primary);
            font-weight: 500;
        }

        /* Executive Summary */
        .executive-summary {
            margin-bottom: 2rem;
        }

        .executive-summary h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }

        .score-overview {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 2rem;
            margin-bottom: 1.5rem;
        }

        @media (max-width: 768px) {
            .score-overview { grid-template-columns: 1fr; }
        }

        .overall-score {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 2rem;
            text-align: center;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
        }

        .overall-score.good { border-left: 4px solid var(--good); }
        .overall-score.warning { border-left: 4px solid var(--warning); }
        .overall-score.critical { border-left: 4px solid var(--critical); }

        .score-value {
            font-size: 4rem;
            font-weight: 700;
            line-height: 1;
        }

        .overall-score.good .score-value { color: var(--good); }
        .overall-score.warning .score-value { color: var(--warning); }
        .overall-score.critical .score-value { color: var(--critical); }

        .score-label {
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }

        .score-grade {
            display: inline-block;
            margin-top: 1rem;
            padding: 0.5rem 1.5rem;
            border-radius: var(--radius);
            font-size: 1.5rem;
            font-weight: 700;
        }

        .overall-score.good .score-grade { background: var(--good-bg); color: var(--good); }
        .overall-score.warning .score-grade { background: var(--warning-bg); color: var(--warning); }
        .overall-score.critical .score-grade { background: var(--critical-bg); color: var(--critical); }

        .score-breakdown {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
        }

        @media (max-width: 600px) {
            .score-breakdown { grid-template-columns: repeat(3, 1fr); }
        }

        .breakdown-item {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 1.25rem;
            text-align: center;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .breakdown-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }

        .breakdown-item .count {
            font-size: 2rem;
            font-weight: 700;
            display: block;
        }

        .breakdown-item .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .breakdown-item.critical .count { color: var(--critical); }
        .breakdown-item.high .count { color: var(--high); }
        .breakdown-item.medium .count { color: var(--warning); }
        .breakdown-item.low .count { color: var(--low); }
        .breakdown-item.info .count { color: var(--info); }

        .summary-text {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 1.5rem;
            color: var(--text-secondary);
            line-height: 1.8;
            border: 1px solid var(--border-color);
        }

        /* Category Section */
        .category-scores { margin-bottom: 2rem; }

        .category-scores h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }

        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1rem;
        }

        .category-card {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .category-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }

        .category-card.critical { border-left: 4px solid var(--critical); }
        .category-card.warning { border-left: 4px solid var(--warning); }
        .category-card.good { border-left: 4px solid var(--good); }

        .category-icon {
            font-size: 2rem;
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-tertiary);
            border-radius: var(--radius-sm);
        }

        .category-info { flex: 1; }

        .category-info h4 {
            font-size: 0.95rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }

        .category-score-display {
            font-family: var(--font-mono);
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }

        .score-max { color: var(--text-muted); }

        .category-bar {
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
        }

        .category-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s ease;
        }

        .category-card.critical .category-fill { background: var(--critical); }
        .category-card.warning .category-fill { background: var(--warning); }
        .category-card.good .category-fill { background: var(--good); }

        .category-stats {
            text-align: right;
        }

        .finding-count {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        /* Findings Section */
        .findings-section { margin-bottom: 2rem; }

        .findings-section h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }

        .filter-controls {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
            color: var(--text-secondary);
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s;
        }

        .filter-btn:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .filter-btn.active {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        .findings-list { display: flex; flex-direction: column; gap: 1rem; }

        .finding-card {
            background: var(--bg-card);
            border-radius: var(--radius);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            overflow: hidden;
            transition: box-shadow 0.2s;
        }

        .finding-card:hover { box-shadow: var(--shadow); }

        .finding-card.critical { border-left: 4px solid var(--critical); }
        .finding-card.high { border-left: 4px solid var(--high); }
        .finding-card.medium { border-left: 4px solid var(--warning); }
        .finding-card.low { border-left: 4px solid var(--low); }
        .finding-card.info { border-left: 4px solid var(--info); }

        .finding-header {
            padding: 1rem 1.25rem;
            background: var(--bg-tertiary);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .finding-header:hover { background: var(--bg-secondary); }

        .finding-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical { background: var(--critical); color: #fff; }
        .severity-badge.high { background: var(--high); color: #fff; }
        .severity-badge.medium { background: var(--warning); color: #000; }
        .severity-badge.low { background: var(--low); color: #fff; }
        .severity-badge.info { background: var(--info); color: #fff; }

        .rule-id {
            font-family: var(--font-mono);
            font-size: 0.85rem;
            padding: 0.25rem 0.5rem;
            background: rgba(255, 255, 255, 0.1);
            border-radius: var(--radius-sm);
        }

        .rule-name {
            font-weight: 600;
            font-size: 1rem;
        }

        .finding-stats {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        .category-badge {
            padding: 0.2rem 0.6rem;
            background: var(--bg-secondary);
            border-radius: var(--radius-sm);
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .score-badge {
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .expand-icon {
            color: var(--text-muted);
            transition: transform 0.2s;
        }

        .finding-card.expanded .expand-icon { transform: rotate(180deg); }

        .finding-body {
            display: none;
            padding: 1.25rem;
            border-top: 1px solid var(--border-color);
        }

        .finding-card.expanded .finding-body { display: block; }

        .finding-description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.7;
        }

        .framework-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .tag {
            padding: 0.25rem 0.6rem;
            border-radius: var(--radius-sm);
            font-size: 0.8rem;
            font-family: var(--font-mono);
            text-decoration: none;
            transition: opacity 0.2s;
        }

        .tag:hover { opacity: 0.8; }

        .tag.mitre { background: rgba(155, 89, 182, 0.25); color: #b39ddb; }
        .tag.cis { background: rgba(52, 152, 219, 0.25); color: #64b5f6; }
        .tag.stig { background: rgba(46, 204, 113, 0.25); color: #81c784; }
        .tag.nist { background: rgba(241, 196, 15, 0.25); color: #ffd54f; }

        .affected-objects { margin-bottom: 1rem; }

        .affected-objects h5 {
            font-size: 0.9rem;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
        }

        .table-container {
            overflow-x: auto;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-color);
        }

        .affected-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        .affected-table th, .affected-table td {
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .affected-table th {
            background: var(--bg-tertiary);
            font-weight: 600;
            white-space: nowrap;
        }

        .affected-table tr:last-child td { border-bottom: none; }
        .affected-table tr:hover { background: var(--bg-tertiary); }

        .more-row td {
            color: var(--warning);
            font-style: italic;
            text-align: center;
        }

        .findings-list ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .findings-list ul li {
            padding: 0.4rem 0;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .findings-list ul li:last-child { border-bottom: none; }
        .findings-list ul li.more { color: var(--warning); font-style: italic; }

        .remediation-section, .references-section {
            margin-top: 1.25rem;
            padding-top: 1.25rem;
            border-top: 1px solid var(--border-color);
        }

        .remediation-section h5, .references-section h5 {
            font-size: 0.95rem;
            margin-bottom: 0.75rem;
        }

        .remediation-section p {
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .script-container {
            background: var(--bg-tertiary);
            border-radius: var(--radius-sm);
            padding: 1rem;
            margin-top: 1rem;
        }

        .script-warning {
            background: var(--warning-bg);
            color: var(--warning);
            padding: 0.5rem 0.75rem;
            border-radius: var(--radius-sm);
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }

        .remediation-script {
            background: var(--bg-primary);
            border-radius: var(--radius-sm);
            padding: 1rem;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            line-height: 1.5;
            margin-bottom: 0.75rem;
        }

        .copy-btn {
            padding: 0.4rem 0.75rem;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 0.85rem;
            transition: opacity 0.2s;
        }

        .copy-btn:hover { opacity: 0.9; }

        .references-section ul {
            list-style: none;
            padding: 0;
        }

        .references-section li {
            padding: 0.3rem 0;
        }

        .references-section a {
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }

        .references-section a:hover { text-decoration: underline; }

        /* Priority Remediation */
        .priority-section { margin-bottom: 2rem; }

        .priority-section h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }

        .priority-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .priority-item {
            display: flex;
            gap: 1rem;
            padding: 1.25rem;
            background: var(--bg-card);
            border-radius: var(--radius);
            margin-bottom: 1rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
        }

        .priority-item.critical { border-left: 4px solid var(--critical); }
        .priority-item.high { border-left: 4px solid var(--high); }
        .priority-item.medium { border-left: 4px solid var(--warning); }
        .priority-item.low { border-left: 4px solid var(--low); }

        .priority-number {
            width: 36px;
            height: 36px;
            background: var(--bg-tertiary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            flex-shrink: 0;
        }

        .priority-content { flex: 1; }

        .priority-content strong {
            display: block;
            margin-bottom: 0.25rem;
        }

        .priority-meta {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .priority-content p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        /* Appendix */
        .appendix {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
        }

        .appendix h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }

        .appendix-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }

        .appendix h3 {
            font-size: 1rem;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
        }

        .config-table {
            width: 100%;
            font-size: 0.9rem;
        }

        .config-table td {
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .config-table td:first-child { color: var(--text-secondary); }
        .config-table td:last-child { text-align: right; font-weight: 500; }

        .framework-list {
            list-style: none;
            padding: 0;
        }

        .framework-list li {
            padding: 0.4rem 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .framework-list li::before {
            content: "✓";
            margin-right: 0.5rem;
            color: var(--good);
        }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .report-footer a {
            color: var(--accent);
            text-decoration: none;
        }

        .report-footer a:hover { text-decoration: underline; }

        .disclaimer {
            margin-top: 0.75rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        /* Print Styles */
        @media print {
            body { background: #fff; color: #000; font-size: 12px; }
            .container { max-width: none; padding: 1rem; }
            .report-header, .finding-card, .priority-item, .appendix, .category-card, .overall-score, .breakdown-item {
                box-shadow: none;
                border: 1px solid #ddd;
            }
            .filter-controls { display: none; }
            .finding-body { display: block !important; }
            .finding-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <div class="header-content">
                <div class="logo">
                    <h1>AD-Scout</h1>
                    <span class="tagline">Active Directory Security Assessment</span>
                </div>
                <div class="report-meta">
                    <div class="meta-item">
                        <span class="label">Domain: </span>
                        <span class="value">$([System.Web.HttpUtility]::HtmlEncode($Domain))</span>
                    </div>
                    <div class="meta-item">
                        <span class="label">Scan Date: </span>
                        <span class="value">$($scanTime.ToString('yyyy-MM-dd HH:mm:ss'))</span>
                    </div>
                    <div class="meta-item">
                        <span class="label">Report Generated: </span>
                        <span class="value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                    </div>
                </div>
            </div>
        </header>

        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="score-overview">
                <div class="overall-score $scoreClass">
                    <div class="score-value">$securityScore</div>
                    <div class="score-label">Security Score</div>
                    <div class="score-grade">Grade: $scoreGrade</div>
                </div>
                <div class="score-breakdown">
                    <div class="breakdown-item critical">
                        <span class="count">$($criticalFindings.Count)</span>
                        <span class="label">Critical</span>
                    </div>
                    <div class="breakdown-item high">
                        <span class="count">$($highFindings.Count)</span>
                        <span class="label">High</span>
                    </div>
                    <div class="breakdown-item medium">
                        <span class="count">$($mediumFindings.Count)</span>
                        <span class="label">Medium</span>
                    </div>
                    <div class="breakdown-item low">
                        <span class="count">$($lowFindings.Count)</span>
                        <span class="label">Low</span>
                    </div>
                    <div class="breakdown-item info">
                        <span class="count">$($infoFindings.Count)</span>
                        <span class="label">Info</span>
                    </div>
                </div>
            </div>
            <div class="summary-text">
                <p>$summaryText</p>
            </div>
        </section>

        <section class="category-scores">
            <h2>Category Breakdown</h2>
            <div class="category-grid">
                $($categoryHtml -join "`n")
            </div>
        </section>

        <section class="findings-section">
            <h2>Detailed Findings</h2>
            <div class="filter-controls">
                <button class="filter-btn active" data-severity="all">All ($($allResults.Count))</button>
                <button class="filter-btn" data-severity="critical">Critical ($($criticalFindings.Count))</button>
                <button class="filter-btn" data-severity="high">High ($($highFindings.Count))</button>
                <button class="filter-btn" data-severity="medium">Medium ($($mediumFindings.Count))</button>
                <button class="filter-btn" data-severity="low">Low ($($lowFindings.Count))</button>
                <button class="filter-btn" data-severity="info">Info ($($infoFindings.Count))</button>
            </div>
            <div class="findings-list">
                $($findingsHtml -join "`n")
            </div>
        </section>

        <section class="priority-section">
            <h2>Priority Remediation Steps</h2>
            <ol class="priority-list">
                $($remediationSteps -join "`n")
            </ol>
        </section>

        <section class="appendix">
            <h2>Appendix</h2>
            <div class="appendix-grid">
                <div class="scan-details">
                    <h3>Scan Configuration</h3>
                    <table class="config-table">
                        <tr><td>Rules Evaluated</td><td>$($allResults.Count)</td></tr>
                        <tr><td>Total Findings</td><td>$totalFindings</td></tr>
                        <tr><td>Total Score</td><td>$totalScore</td></tr>
                        <tr><td>AD-Scout Version</td><td>$moduleVersion</td></tr>
                        <tr><td>PowerShell Version</td><td>$psVersion</td></tr>
                    </table>
                </div>
                <div class="framework-mappings">
                    <h3>Framework Coverage</h3>
                    <ul class="framework-list">
                        <li>MITRE ATT&CK for Enterprise</li>
                        <li>CIS Microsoft Windows Server Benchmarks</li>
                        <li>DISA STIGs for Active Directory</li>
                        <li>NIST 800-53 Security Controls</li>
                        <li>ANSSI Active Directory Guidelines</li>
                    </ul>
                </div>
            </div>
        </section>

        <footer class="report-footer">
            <p>Generated by <a href="https://github.com/mwilco03/AD-Scout">AD-Scout</a> - Open Source Active Directory Security Assessment</p>
            <p class="disclaimer">This report is provided for informational purposes. Always validate findings before making changes to production environments.</p>
        </footer>
    </div>

    <script>
        // Filter functionality
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const severity = this.dataset.severity;
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');

                document.querySelectorAll('.finding-card').forEach(card => {
                    if (severity === 'all' || card.dataset.severity === severity) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });

        // Toggle finding expansion
        function toggleFinding(header) {
            const card = header.closest('.finding-card');
            card.classList.toggle('expanded');
        }

        // Copy script to clipboard
        function copyScript(btn) {
            const code = btn.previousElementSibling.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = originalText; }, 2000);
            }).catch(() => {
                btn.textContent = 'Copy failed';
                setTimeout(() => { btn.textContent = 'Copy Script'; }, 2000);
            });
        }

        // Expand all findings on print
        window.addEventListener('beforeprint', () => {
            document.querySelectorAll('.finding-card').forEach(card => {
                card.classList.add('expanded');
                card.style.display = 'block';
            });
        });
    </script>
</body>
</html>
"@

        # Write the HTML file
        $html | Out-File -FilePath $Path -Encoding UTF8
        Write-Verbose "HTML report saved to: $Path"
        Write-Host "Report generated: $Path" -ForegroundColor Green
    }
}

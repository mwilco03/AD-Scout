function Export-ADScoutNISTReport {
    <#
    .SYNOPSIS
        Exports AD-Scout results as a NIST 800-53 compliance report.

    .DESCRIPTION
        Generates a compliance report organized by NIST 800-53 Rev 5 control families.
        This format is suitable for compliance assessments and regulatory reporting.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER Path
        Output file path. Supports .json, .html, or .md extensions.

    .PARAMETER Format
        Output format: JSON, HTML, or Markdown.

    .PARAMETER Title
        Report title.

    .PARAMETER IncludePassingControls
        Include controls with no findings (compliant).

    .EXAMPLE
        Export-ADScoutNISTReport -Results $results -Path ".\NIST_Compliance.html" -Format HTML
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('JSON', 'HTML', 'Markdown')]
        [string]$Format = 'HTML',

        [Parameter()]
        [string]$Title = "NIST 800-53 Rev 5 Compliance Assessment",

        [Parameter()]
        [switch]$IncludePassingControls
    )

    # NIST 800-53 Control Family definitions
    $nistFamilies = @{
        'AC' = @{ Name = 'Access Control'; Description = 'Policies and procedures for controlling access to information systems' }
        'AU' = @{ Name = 'Audit and Accountability'; Description = 'Policies for creating, protecting, and retaining audit records' }
        'CM' = @{ Name = 'Configuration Management'; Description = 'Baseline configurations and change control' }
        'IA' = @{ Name = 'Identification and Authentication'; Description = 'Policies for identifying and authenticating users and devices' }
        'SC' = @{ Name = 'System and Communications Protection'; Description = 'Protecting information in transit and at rest' }
        'SI' = @{ Name = 'System and Information Integrity'; Description = 'Flaw remediation, malicious code protection, and monitoring' }
    }

    # Build NIST control mapping from results
    $controlFindings = @{}
    $allControls = @{}

    foreach ($result in $Results) {
        if ($result.NIST) {
            foreach ($control in $result.NIST) {
                # Get control family (first 2 chars)
                $family = $control.Substring(0, 2).ToUpper()

                if (-not $controlFindings.ContainsKey($control)) {
                    $controlFindings[$control] = @{
                        Control      = $control
                        Family       = $family
                        FamilyName   = if ($nistFamilies[$family]) { $nistFamilies[$family].Name } else { $family }
                        Rules        = @()
                        TotalFindings = 0
                        TotalScore   = 0
                        Status       = 'Compliant'
                    }
                }

                $controlFindings[$control].Rules += [PSCustomObject]@{
                    RuleId       = $result.RuleId
                    RuleName     = $result.RuleName
                    Category     = $result.Category
                    FindingCount = $result.FindingCount
                    Score        = $result.Score
                    Severity     = $result.Severity
                }

                $controlFindings[$control].TotalFindings += $result.FindingCount
                $controlFindings[$control].TotalScore += $result.Score

                if ($result.FindingCount -gt 0) {
                    $controlFindings[$control].Status = 'Non-Compliant'
                }

                $allControls[$control] = $true
            }
        }
    }

    # Group by family
    $familyGroups = @{}
    foreach ($control in $controlFindings.Keys | Sort-Object) {
        $family = $controlFindings[$control].Family
        if (-not $familyGroups.ContainsKey($family)) {
            $familyGroups[$family] = @{
                Family       = $family
                FamilyName   = if ($nistFamilies[$family]) { $nistFamilies[$family].Name } else { $family }
                Description  = if ($nistFamilies[$family]) { $nistFamilies[$family].Description } else { '' }
                Controls     = @()
                TotalFindings = 0
                CompliantCount = 0
                NonCompliantCount = 0
            }
        }
        $familyGroups[$family].Controls += $controlFindings[$control]
        $familyGroups[$family].TotalFindings += $controlFindings[$control].TotalFindings

        if ($controlFindings[$control].Status -eq 'Compliant') {
            $familyGroups[$family].CompliantCount++
        } else {
            $familyGroups[$family].NonCompliantCount++
        }
    }

    # Calculate overall compliance
    $totalControls = $controlFindings.Count
    $compliantControls = ($controlFindings.Values | Where-Object { $_.Status -eq 'Compliant' }).Count
    $compliancePercentage = if ($totalControls -gt 0) { [math]::Round(($compliantControls / $totalControls) * 100, 1) } else { 100 }

    # Build report based on format
    switch ($Format) {
        'JSON' {
            $report = [ordered]@{
                meta = [ordered]@{
                    title           = $Title
                    framework       = 'NIST SP 800-53 Rev 5'
                    generatedAt     = (Get-Date).ToString('o')
                    generator       = 'AD-Scout NIST Reporter'
                }
                summary = [ordered]@{
                    overallCompliance     = "$compliancePercentage%"
                    totalControlsAssessed = $totalControls
                    compliantControls     = $compliantControls
                    nonCompliantControls  = $totalControls - $compliantControls
                    totalFindings         = ($Results | Measure-Object -Property FindingCount -Sum).Sum
                }
                controlFamilies = @(
                    $familyGroups.Keys | Sort-Object | ForEach-Object {
                        $fg = $familyGroups[$_]
                        [ordered]@{
                            family            = $fg.Family
                            familyName        = $fg.FamilyName
                            description       = $fg.Description
                            compliantControls = $fg.CompliantCount
                            nonCompliantControls = $fg.NonCompliantCount
                            totalFindings     = $fg.TotalFindings
                            controls          = @($fg.Controls | ForEach-Object {
                                [ordered]@{
                                    control       = $_.Control
                                    status        = $_.Status
                                    findingCount  = $_.TotalFindings
                                    score         = $_.TotalScore
                                    rules         = $_.Rules
                                }
                            })
                        }
                    }
                )
            }
            $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }

        'HTML' {
            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #0f4c75;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
            --border: #333;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2, h3 { margin-bottom: 1rem; }
        h1 { color: #fff; border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .summary-card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
        }
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        .summary-card .label { color: var(--text-secondary); }
        .compliance-meter {
            height: 20px;
            background: var(--bg-secondary);
            border-radius: 10px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .compliance-fill {
            height: 100%;
            transition: width 0.5s ease;
        }
        .family-section {
            background: var(--bg-secondary);
            border-radius: 8px;
            margin: 1.5rem 0;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        .family-header {
            background: var(--accent);
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .family-header:hover { background: #1a5a8a; }
        .family-content { padding: 1rem 1.5rem; display: none; }
        .family-content.active { display: block; }
        .control-item {
            background: var(--bg-primary);
            border-radius: 4px;
            padding: 1rem;
            margin: 0.5rem 0;
            border-left: 4px solid var(--border);
        }
        .control-item.compliant { border-left-color: var(--success); }
        .control-item.non-compliant { border-left-color: var(--danger); }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .badge-success { background: var(--success); color: #fff; }
        .badge-danger { background: var(--danger); color: #fff; }
        .badge-warning { background: var(--warning); color: #000; }
        .rules-list { margin-top: 0.5rem; padding-left: 1rem; }
        .rules-list li { color: var(--text-secondary); margin: 0.25rem 0; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: var(--bg-primary); color: var(--accent); }
        .footer {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>$Title</h1>
        <p style="color: var(--text-secondary);">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Framework: NIST SP 800-53 Rev 5</p>

        <div class="summary">
            <div class="summary-card">
                <div class="value" style="color: $(if ($compliancePercentage -ge 80) { 'var(--success)' } elseif ($compliancePercentage -ge 60) { 'var(--warning)' } else { 'var(--danger)' })">$compliancePercentage%</div>
                <div class="label">Overall Compliance</div>
            </div>
            <div class="summary-card">
                <div class="value">$totalControls</div>
                <div class="label">Controls Assessed</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--success)">$compliantControls</div>
                <div class="label">Compliant</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--danger)">$($totalControls - $compliantControls)</div>
                <div class="label">Non-Compliant</div>
            </div>
        </div>

        <div class="compliance-meter">
            <div class="compliance-fill" style="width: $compliancePercentage%; background: $(if ($compliancePercentage -ge 80) { 'var(--success)' } elseif ($compliancePercentage -ge 60) { 'var(--warning)' } else { 'var(--danger)' })"></div>
        </div>

        <h2>Control Family Assessment</h2>
"@

            foreach ($familyKey in $familyGroups.Keys | Sort-Object) {
                $family = $familyGroups[$familyKey]
                $familyCompliance = if (($family.CompliantCount + $family.NonCompliantCount) -gt 0) {
                    [math]::Round(($family.CompliantCount / ($family.CompliantCount + $family.NonCompliantCount)) * 100, 0)
                } else { 100 }

                $html += @"

        <div class="family-section">
            <div class="family-header" onclick="this.nextElementSibling.classList.toggle('active')">
                <div>
                    <strong>$($family.Family) - $($family.FamilyName)</strong>
                    <br><small style="color: rgba(255,255,255,0.7)">$($family.Description)</small>
                </div>
                <div>
                    <span class="badge badge-success">$($family.CompliantCount) Compliant</span>
                    $(if ($family.NonCompliantCount -gt 0) { "<span class='badge badge-danger'>$($family.NonCompliantCount) Non-Compliant</span>" })
                </div>
            </div>
            <div class="family-content">
"@

                foreach ($control in $family.Controls | Sort-Object Control) {
                    $statusClass = if ($control.Status -eq 'Compliant') { 'compliant' } else { 'non-compliant' }
                    $badgeClass = if ($control.Status -eq 'Compliant') { 'badge-success' } else { 'badge-danger' }

                    $html += @"
                <div class="control-item $statusClass">
                    <strong>$($control.Control)</strong>
                    <span class="badge $badgeClass">$($control.Status)</span>
                    $(if ($control.TotalFindings -gt 0) { "<span class='badge badge-warning'>$($control.TotalFindings) Findings</span>" })
                    <ul class="rules-list">
"@
                    foreach ($rule in $control.Rules) {
                        $html += "                        <li>$($rule.RuleId): $($rule.RuleName) ($($rule.FindingCount) findings)</li>`n"
                    }

                    $html += @"
                    </ul>
                </div>
"@
                }

                $html += @"
            </div>
        </div>
"@
            }

            $html += @"

        <div class="footer">
            <p>Generated by AD-Scout NIST Reporter | NIST SP 800-53 Rev 5 Compliance Assessment</p>
        </div>
    </div>
</body>
</html>
"@
            $html | Out-File -FilePath $Path -Encoding UTF8
        }

        'Markdown' {
            $md = @"
# $Title

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Framework:** NIST SP 800-53 Rev 5

## Executive Summary

| Metric | Value |
|--------|-------|
| Overall Compliance | $compliancePercentage% |
| Controls Assessed | $totalControls |
| Compliant Controls | $compliantControls |
| Non-Compliant Controls | $($totalControls - $compliantControls) |
| Total Findings | $(($Results | Measure-Object -Property FindingCount -Sum).Sum) |

---

## Control Family Assessment

"@

            foreach ($familyKey in $familyGroups.Keys | Sort-Object) {
                $family = $familyGroups[$familyKey]

                $md += @"

### $($family.Family) - $($family.FamilyName)

$($family.Description)

| Control | Status | Findings | Related Rules |
|---------|--------|----------|---------------|
"@
                foreach ($control in $family.Controls | Sort-Object Control) {
                    $ruleList = ($control.Rules | ForEach-Object { $_.RuleId }) -join ', '
                    $md += "| $($control.Control) | $($control.Status) | $($control.TotalFindings) | $ruleList |`n"
                }
            }

            $md += @"

---

*Generated by AD-Scout NIST Reporter*
"@
            $md | Out-File -FilePath $Path -Encoding UTF8
        }
    }

    Write-Verbose "NIST compliance report saved to: $Path"
    Write-Host "NIST 800-53 compliance report generated: $Path" -ForegroundColor Green
    Write-Host "  Overall Compliance: $compliancePercentage% ($compliantControls of $totalControls controls)" -ForegroundColor $(if ($compliancePercentage -ge 80) { 'Green' } elseif ($compliancePercentage -ge 60) { 'Yellow' } else { 'Red' })
}

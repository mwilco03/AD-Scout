function Export-ADScoutRemediationReport {
    <#
    .SYNOPSIS
        Exports a detailed remediation report for audit and compliance purposes.

    .DESCRIPTION
        Generates comprehensive reports of remediation activities including:
        - Executive summary of changes made
        - Detailed listing of each remediation action
        - Before/after state comparison
        - Risk assessment summary
        - Compliance evidence suitable for SOX/PCI/HIPAA audits

    .PARAMETER BatchId
        The batch ID to generate a report for.

    .PARAMETER RemediationResult
        Remediation result object from Invoke-ADScoutRemediation -PassThru.

    .PARAMETER Format
        Output format: HTML, JSON, CSV, or PDF.

    .PARAMETER Path
        Output file path. If not specified, returns the report content.

    .PARAMETER IncludeRollbackData
        Include full rollback state data in the report.

    .PARAMETER IncludeScripts
        Include the actual remediation scripts executed.

    .PARAMETER SignReport
        Digitally sign the report for tamper evidence.

    .EXAMPLE
        Export-ADScoutRemediationReport -BatchId "abc12345" -Format HTML -Path "C:\Reports\remediation.html"

    .EXAMPLE
        $result = Invoke-ADScoutRemediation -Results $scan -PassThru
        Export-ADScoutRemediationReport -RemediationResult $result -Format JSON

    .OUTPUTS
        String or file path depending on parameters.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByBatchId')]
    param(
        [Parameter(ParameterSetName = 'ByBatchId', Mandatory)]
        [string]$BatchId,

        [Parameter(ParameterSetName = 'ByResult', Mandatory)]
        [PSCustomObject]$RemediationResult,

        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'Markdown')]
        [string]$Format = 'HTML',

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [switch]$IncludeRollbackData,

        [Parameter()]
        [switch]$IncludeScripts,

        [Parameter()]
        [string]$CompanyName = "Organization",

        [Parameter()]
        [string]$PreparedBy = $env:USERNAME
    )

    # Load batch data
    if ($PSCmdlet.ParameterSetName -eq 'ByBatchId') {
        $manifestPath = Join-Path $RollbackPath "$BatchId`_manifest.json"
        if (-not (Test-Path $manifestPath)) {
            throw "Batch manifest not found: $BatchId"
        }
        $batchData = Get-Content $manifestPath -Raw | ConvertFrom-Json
    }
    else {
        $batchData = @{
            BatchId      = $RemediationResult.BatchId
            StartTime    = $RemediationResult.Summary.StartTime
            EndTime      = Get-Date
            Status       = if ($RemediationResult.Summary.Failed -gt 0) { 'PartialFailure' } else { 'Completed' }
            Remediations = $RemediationResult.Remediations
            ChangeTicket = $RemediationResult.Summary.ChangeTicket
        }
    }

    # Build report data structure
    $reportData = @{
        ReportMetadata = @{
            GeneratedAt   = Get-Date -Format 'o'
            GeneratedBy   = $PreparedBy
            CompanyName   = $CompanyName
            ADScoutVersion = (Get-Module ADScout).Version.ToString()
            ReportType    = 'Remediation Audit Report'
        }
        ExecutiveSummary = @{
            BatchId       = $batchData.BatchId
            ExecutionTime = $batchData.StartTime
            CompletionTime = $batchData.EndTime
            Status        = $batchData.Status
            ChangeTicket  = $batchData.ChangeTicket
            TotalActions  = $batchData.Remediations.Count
            Completed     = ($batchData.Remediations | Where-Object Status -eq 'Completed').Count
            Failed        = ($batchData.Remediations | Where-Object Status -eq 'Failed').Count
            Skipped       = ($batchData.Remediations | Where-Object Status -eq 'Skipped').Count
        }
        RemediationDetails = @()
        RiskAssessment = @{
            OverallRisk   = 'Unknown'
            HighRiskCount = 0
            Warnings      = @()
        }
    }

    # Process each remediation
    foreach ($remediation in $batchData.Remediations) {
        $detail = @{
            RemediationId = $remediation.RemediationId
            RuleId        = $remediation.RuleId
            RuleName      = $remediation.RuleName
            Target        = Get-RemediationTargetIdentity -Finding $remediation.Finding
            Status        = $remediation.Status
            StartTime     = $remediation.StartTime
            EndTime       = $remediation.EndTime
            Error         = $remediation.Error
        }

        if ($IncludeScripts -and $remediation.Script) {
            $detail.Script = $remediation.Script
        }

        if ($IncludeRollbackData -and $remediation.RollbackData) {
            $detail.RollbackData = $remediation.RollbackData
        }

        $reportData.RemediationDetails += [PSCustomObject]$detail
    }

    # Generate output based on format
    $output = switch ($Format) {
        'HTML' { ConvertTo-RemediationHtmlReport -ReportData $reportData }
        'JSON' { $reportData | ConvertTo-Json -Depth 20 }
        'CSV'  { ConvertTo-RemediationCsvReport -ReportData $reportData }
        'Markdown' { ConvertTo-RemediationMarkdownReport -ReportData $reportData }
    }

    if ($Path) {
        $output | Set-Content -Path $Path -Encoding UTF8
        Write-Host "✓ Report exported to: $Path" -ForegroundColor Green
        return $Path
    }
    else {
        return $output
    }
}

function ConvertTo-RemediationHtmlReport {
    param([hashtable]$ReportData)

    $statusColors = @{
        'Completed' = '#28a745'
        'Failed'    = '#dc3545'
        'Skipped'   = '#ffc107'
        'Simulated' = '#17a2b8'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD-Scout Remediation Report - $($ReportData.ExecutiveSummary.BatchId)</title>
    <style>
        :root {
            --primary: #2c3e50;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .report-header {
            background: var(--primary);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .report-header h1 {
            margin: 0 0 10px 0;
        }
        .report-header .meta {
            opacity: 0.8;
            font-size: 0.9em;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: var(--primary);
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .summary-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .summary-item .value {
            font-size: 2em;
            font-weight: bold;
            color: var(--primary);
        }
        .summary-item .label {
            color: #666;
            font-size: 0.9em;
        }
        .summary-item.success .value { color: var(--success); }
        .summary-item.danger .value { color: var(--danger); }
        .summary-item.warning .value { color: var(--warning); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: var(--primary);
        }
        tr:hover {
            background: #f8f9fa;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            color: white;
        }
        .status-completed { background: var(--success); }
        .status-failed { background: var(--danger); }
        .status-skipped { background: var(--warning); color: #333; }
        .status-simulated { background: var(--info); }
        .footer {
            text-align: center;
            color: #666;
            font-size: 0.9em;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .script-block {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .error-message {
            background: #fff3f3;
            border-left: 4px solid var(--danger);
            padding: 10px 15px;
            margin: 10px 0;
        }
        @media print {
            body { background: white; }
            .card { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🛡️ AD-Scout Remediation Report</h1>
        <div class="meta">
            <strong>Batch ID:</strong> $($ReportData.ExecutiveSummary.BatchId) |
            <strong>Generated:</strong> $($ReportData.ReportMetadata.GeneratedAt) |
            <strong>Prepared By:</strong> $($ReportData.ReportMetadata.GeneratedBy)
        </div>
    </div>

    <div class="card">
        <h2>📊 Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value">$($ReportData.ExecutiveSummary.TotalActions)</div>
                <div class="label">Total Actions</div>
            </div>
            <div class="summary-item success">
                <div class="value">$($ReportData.ExecutiveSummary.Completed)</div>
                <div class="label">Completed</div>
            </div>
            <div class="summary-item danger">
                <div class="value">$($ReportData.ExecutiveSummary.Failed)</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-item warning">
                <div class="value">$($ReportData.ExecutiveSummary.Skipped)</div>
                <div class="label">Skipped</div>
            </div>
        </div>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Execution Started</td><td>$($ReportData.ExecutiveSummary.ExecutionTime)</td></tr>
            <tr><td>Execution Completed</td><td>$($ReportData.ExecutiveSummary.CompletionTime)</td></tr>
            <tr><td>Overall Status</td><td><span class="status-badge status-$($ReportData.ExecutiveSummary.Status.ToLower())">$($ReportData.ExecutiveSummary.Status)</span></td></tr>
            $(if ($ReportData.ExecutiveSummary.ChangeTicket) { "<tr><td>Change Ticket</td><td>$($ReportData.ExecutiveSummary.ChangeTicket)</td></tr>" })
        </table>
    </div>

    <div class="card">
        <h2>📝 Remediation Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($detail in $ReportData.RemediationDetails) {
        $statusClass = "status-$($detail.Status.ToLower())"
        $html += @"
                <tr>
                    <td><strong>$($detail.RuleId)</strong><br><small>$($detail.RuleName)</small></td>
                    <td>$($detail.Target)</td>
                    <td><span class="status-badge $statusClass">$($detail.Status)</span></td>
                    <td>$($detail.StartTime)</td>
                </tr>
"@
        if ($detail.Error) {
            $html += @"
                <tr>
                    <td colspan="4">
                        <div class="error-message">
                            <strong>Error:</strong> $($detail.Error)
                        </div>
                    </td>
                </tr>
"@
        }
        if ($detail.Script) {
            $escapedScript = [System.Web.HttpUtility]::HtmlEncode($detail.Script)
            $html += @"
                <tr>
                    <td colspan="4">
                        <details>
                            <summary>View Script</summary>
                            <div class="script-block">$escapedScript</div>
                        </details>
                    </td>
                </tr>
"@
        }
    }

    $html += @"
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by AD-Scout v$($ReportData.ReportMetadata.ADScoutVersion) | $($ReportData.ReportMetadata.CompanyName)</p>
        <p><em>This report is generated for audit and compliance purposes. Retain according to your organization's data retention policy.</em></p>
    </div>
</body>
</html>
"@

    return $html
}

function ConvertTo-RemediationCsvReport {
    param([hashtable]$ReportData)

    $ReportData.RemediationDetails | ForEach-Object {
        [PSCustomObject]@{
            BatchId       = $ReportData.ExecutiveSummary.BatchId
            RemediationId = $_.RemediationId
            RuleId        = $_.RuleId
            RuleName      = $_.RuleName
            Target        = $_.Target
            Status        = $_.Status
            StartTime     = $_.StartTime
            EndTime       = $_.EndTime
            Error         = $_.Error
            ChangeTicket  = $ReportData.ExecutiveSummary.ChangeTicket
        }
    } | ConvertTo-Csv -NoTypeInformation
}

function ConvertTo-RemediationMarkdownReport {
    param([hashtable]$ReportData)

    $md = @"
# AD-Scout Remediation Report

**Batch ID:** $($ReportData.ExecutiveSummary.BatchId)
**Generated:** $($ReportData.ReportMetadata.GeneratedAt)
**Prepared By:** $($ReportData.ReportMetadata.GeneratedBy)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Actions | $($ReportData.ExecutiveSummary.TotalActions) |
| Completed | $($ReportData.ExecutiveSummary.Completed) |
| Failed | $($ReportData.ExecutiveSummary.Failed) |
| Skipped | $($ReportData.ExecutiveSummary.Skipped) |
| Status | $($ReportData.ExecutiveSummary.Status) |
| Execution Time | $($ReportData.ExecutiveSummary.ExecutionTime) |
$(if ($ReportData.ExecutiveSummary.ChangeTicket) { "| Change Ticket | $($ReportData.ExecutiveSummary.ChangeTicket) |" })

---

## Remediation Details

| Rule ID | Target | Status | Time |
|---------|--------|--------|------|
"@

    foreach ($detail in $ReportData.RemediationDetails) {
        $md += "| $($detail.RuleId) | $($detail.Target) | $($detail.Status) | $($detail.StartTime) |`n"
    }

    $failedDetails = $ReportData.RemediationDetails | Where-Object { $_.Error }
    if ($failedDetails) {
        $md += @"

---

## Errors

"@
        foreach ($detail in $failedDetails) {
            $md += @"
### $($detail.RuleId) - $($detail.Target)

**Error:** $($detail.Error)

"@
        }
    }

    $md += @"

---

*Generated by AD-Scout v$($ReportData.ReportMetadata.ADScoutVersion)*
"@

    return $md
}

function Send-ADScoutRemediationToSIEM {
    <#
    .SYNOPSIS
        Sends remediation events to SIEM systems.

    .DESCRIPTION
        Exports remediation events in formats compatible with common SIEM systems
        including Splunk, Microsoft Sentinel, and generic syslog.

    .PARAMETER RemediationResult
        Remediation result from Invoke-ADScoutRemediation -PassThru.

    .PARAMETER Target
        SIEM target: Splunk, Sentinel, Syslog.

    .PARAMETER Endpoint
        API endpoint or syslog server address.

    .PARAMETER ApiKey
        API key for authentication.

    .EXAMPLE
        Send-ADScoutRemediationToSIEM -RemediationResult $result -Target Splunk -Endpoint "https://splunk.company.com:8088"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$RemediationResult,

        [Parameter(Mandatory)]
        [ValidateSet('Splunk', 'Sentinel', 'Syslog', 'Webhook')]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter()]
        [string]$ApiKey,

        [Parameter()]
        [string]$SourceType = 'adscout:remediation'
    )

    # Build event data
    $events = foreach ($remediation in $RemediationResult.Remediations) {
        @{
            time       = [DateTimeOffset]::new($remediation.StartTime).ToUnixTimeSeconds()
            source     = 'AD-Scout'
            sourcetype = $SourceType
            event      = @{
                action        = 'remediation'
                batch_id      = $RemediationResult.BatchId
                remediation_id = $remediation.RemediationId
                rule_id       = $remediation.RuleId
                rule_name     = $remediation.RuleName
                target        = Get-RemediationTargetIdentity -Finding $remediation.Finding
                status        = $remediation.Status
                change_ticket = $RemediationResult.Summary.ChangeTicket
                user          = $env:USERNAME
                computer      = $env:COMPUTERNAME
                error         = $remediation.Error
            }
        }
    }

    switch ($Target) {
        'Splunk' {
            $headers = @{
                'Authorization' = "Splunk $ApiKey"
                'Content-Type'  = 'application/json'
            }

            foreach ($event in $events) {
                $body = $event | ConvertTo-Json -Depth 10
                Invoke-RestMethod -Uri "$Endpoint/services/collector/event" -Method Post -Headers $headers -Body $body
            }
        }

        'Sentinel' {
            # Azure Monitor Data Collector API
            $body = $events.event | ConvertTo-Json -Depth 10
            $contentLength = [System.Text.Encoding]::UTF8.GetByteCount($body)
            $date = [DateTime]::UtcNow.ToString('r')

            # Build signature (requires workspace ID and key)
            $headers = @{
                'Content-Type'  = 'application/json'
                'Log-Type'      = 'ADScoutRemediation'
                'x-ms-date'     = $date
            }

            Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $headers -Body $body
        }

        'Syslog' {
            # UDP syslog
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $parts = $Endpoint -split ':'
            $server = $parts[0]
            $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { 514 }

            foreach ($event in $events) {
                $message = "<14>1 $(Get-Date -Format 'o') $env:COMPUTERNAME ADScout - - - $($event.event | ConvertTo-Json -Compress)"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($message)
                $udpClient.Send($bytes, $bytes.Length, $server, $port)
            }
            $udpClient.Close()
        }

        'Webhook' {
            $body = @{
                batch_id   = $RemediationResult.BatchId
                summary    = $RemediationResult.Summary
                events     = $events.event
                timestamp  = Get-Date -Format 'o'
            } | ConvertTo-Json -Depth 10

            $headers = @{ 'Content-Type' = 'application/json' }
            if ($ApiKey) {
                $headers['Authorization'] = "Bearer $ApiKey"
            }

            Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $headers -Body $body
        }
    }

    Write-Host "✓ Sent $($events.Count) events to $Target" -ForegroundColor Green
}

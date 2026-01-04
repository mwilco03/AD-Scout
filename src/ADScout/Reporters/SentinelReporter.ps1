function Export-ADScoutSentinel {
    <#
    .SYNOPSIS
        Exports AD-Scout results to Microsoft Sentinel via Log Analytics Data Collector API.

    .DESCRIPTION
        Sends AD-Scout scan results to Microsoft Sentinel (Azure Log Analytics) using
        the HTTP Data Collector API. Results appear in the custom log table specified.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER WorkspaceId
        Log Analytics workspace ID (GUID).

    .PARAMETER SharedKey
        Primary or secondary key for the Log Analytics workspace.

    .PARAMETER LogType
        Custom log table name. "_CL" suffix is added automatically.
        Default: ADScoutFindings

    .PARAMETER TimeGeneratedField
        Field name to use as TimeGenerated. Default: ExecutedAt

    .PARAMETER EngagementId
        Optional engagement ID to tag all records.

    .PARAMETER AzureCloud
        Azure cloud environment. Default: AzureCloud (public).
        Options: AzureCloud, AzureUSGovernment, AzureChinaCloud

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutSentinel -WorkspaceId $wsId -SharedKey $key

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Export-ADScoutSentinel -Results $results -WorkspaceId $wsId -SharedKey $key -LogType "ADSecurityAudit"

    .NOTES
        Author: AD-Scout Contributors

        The Log Analytics Data Collector API has a 30MB limit per request.
        Large result sets are automatically batched.

        Results appear in Sentinel under:
        - Table: ADScoutFindings_CL (or your custom LogType)
        - Category: Custom Logs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [string]$SharedKey,

        [Parameter()]
        [string]$LogType = 'ADScoutFindings',

        [Parameter()]
        [string]$TimeGeneratedField = 'ExecutedAt',

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud')]
        [string]$AzureCloud = 'AzureCloud'
    )

    begin {
        $allResults = @()

        # Determine API endpoint based on cloud
        $endpoint = switch ($AzureCloud) {
            'AzureCloud' { "https://$WorkspaceId.ods.opinsights.azure.com" }
            'AzureUSGovernment' { "https://$WorkspaceId.ods.opinsights.azure.us" }
            'AzureChinaCloud' { "https://$WorkspaceId.ods.opinsights.azure.cn" }
        }
    }

    process {
        $allResults += $Results
    }

    end {
        if (-not $allResults) {
            Write-Warning "No results to export"
            return
        }

        Write-Host "Exporting $($allResults.Count) results to Microsoft Sentinel..." -ForegroundColor Cyan

        $successCount = 0
        $errorCount = 0

        # Convert results to Sentinel-compatible format
        $records = $allResults | ForEach-Object {
            $severity = if ($_.Score -ge 50) { 'Critical' }
                       elseif ($_.Score -ge 30) { 'High' }
                       elseif ($_.Score -ge 15) { 'Medium' }
                       elseif ($_.Score -ge 5) { 'Low' }
                       else { 'Informational' }

            @{
                TimeGenerated = (Get-Date).ToUniversalTime().ToString('o')
                RuleId = $_.RuleId
                RuleName = $_.RuleName
                Category = $_.Category
                Description = $_.Description
                Score = $_.Score
                MaxScore = $_.MaxScore
                FindingCount = $_.FindingCount
                Severity = $severity
                SeverityNumber = switch ($severity) {
                    'Critical' { 4 }
                    'High' { 3 }
                    'Medium' { 2 }
                    'Low' { 1 }
                    'Informational' { 0 }
                }
                MitreTechniques = if ($_.MITRE) { $_.MITRE -join ';' } else { '' }
                CISControls = if ($_.CIS) { $_.CIS -join ';' } else { '' }
                NISTControls = if ($_.NIST) { $_.NIST -join ';' } else { '' }
                EngagementId = $EngagementId
                Computer = $env:COMPUTERNAME
                # Flatten top findings for easier querying
                TopFindings = if ($_.Findings) {
                    ($_.Findings | Select-Object -First 10 | ForEach-Object {
                        if ($_.SamAccountName) { $_.SamAccountName }
                        elseif ($_.Name) { $_.Name }
                        elseif ($_.DistinguishedName) { $_.DistinguishedName }
                        else { $_ | ConvertTo-Json -Compress -Depth 1 }
                    }) -join ';'
                } else { '' }
            }
        }

        # Batch records (Log Analytics API has ~30MB limit)
        $batchSize = 500
        for ($i = 0; $i -lt $records.Count; $i += $batchSize) {
            $batch = $records | Select-Object -Skip $i -First $batchSize
            $body = $batch | ConvertTo-Json -Depth 5

            # Build authorization header
            $rfc1123date = [DateTime]::UtcNow.ToString('r')
            $contentLength = [System.Text.Encoding]::UTF8.GetBytes($body).Length
            $signature = Build-SentinelSignature -WorkspaceId $WorkspaceId -SharedKey $SharedKey -Date $rfc1123date -ContentLength $contentLength -Method 'POST' -ContentType 'application/json' -Resource '/api/logs'

            $headers = @{
                'Authorization' = $signature
                'Log-Type' = $LogType
                'x-ms-date' = $rfc1123date
                'time-generated-field' = $TimeGeneratedField
                'Content-Type' = 'application/json'
            }

            $uri = "$endpoint/api/logs?api-version=2016-04-01"

            try {
                $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing

                if ($response.StatusCode -eq 200) {
                    $successCount += $batch.Count
                    Write-Verbose "Batch of $($batch.Count) records sent successfully"
                }
                else {
                    Write-Warning "Unexpected status code: $($response.StatusCode)"
                    $errorCount += $batch.Count
                }
            }
            catch {
                Write-Error "Failed to send batch: $_"
                $errorCount += $batch.Count
            }
        }

        Write-Host "Export complete: $successCount records sent, $errorCount errors" -ForegroundColor $(if ($errorCount -gt 0) { 'Yellow' } else { 'Green' })

        # Return summary
        [PSCustomObject]@{
            WorkspaceId = $WorkspaceId
            LogType = "${LogType}_CL"
            TotalRecords = $allResults.Count
            Sent = $successCount
            Errors = $errorCount
            Timestamp = (Get-Date).ToString('o')
        }
    }
}

function Build-SentinelSignature {
    <#
    .SYNOPSIS
        Builds the authorization signature for Log Analytics Data Collector API.
    #>
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$Date,
        [int]$ContentLength,
        [string]$Method,
        [string]$ContentType,
        [string]$Resource
    )

    $xHeaders = "x-ms-date:$Date"
    $stringToHash = "$Method`n$ContentLength`n$ContentType`n$xHeaders`n$Resource"

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)

    "SharedKey ${WorkspaceId}:${encodedHash}"
}

function New-ADScoutSentinelAnalyticsRule {
    <#
    .SYNOPSIS
        Creates a Microsoft Sentinel Analytics Rule for AD-Scout findings.

    .DESCRIPTION
        Generates a KQL query and optionally creates an analytics rule in Sentinel
        to alert on high-severity AD-Scout findings.

    .PARAMETER Severity
        Minimum severity to alert on. Default: High

    .PARAMETER OutputKQL
        Output the KQL query only without creating the rule.

    .EXAMPLE
        New-ADScoutSentinelAnalyticsRule -OutputKQL
        Outputs the KQL query for manual rule creation.

    .EXAMPLE
        New-ADScoutSentinelAnalyticsRule -Severity Critical
        Creates an analytics rule for critical findings only.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity = 'High',

        [Parameter()]
        [switch]$OutputKQL
    )

    $severityNumber = switch ($Severity) {
        'Critical' { 4 }
        'High' { 3 }
        'Medium' { 2 }
        'Low' { 1 }
        'Informational' { 0 }
    }

    $kql = @"
// AD-Scout Security Findings Alert
// Alerts when new findings at $Severity severity or above are detected

ADScoutFindings_CL
| where TimeGenerated > ago(1h)
| where SeverityNumber_d >= $severityNumber
| summarize
    FindingCount = count(),
    TotalScore = sum(Score_d),
    UniqueRules = dcount(RuleId_s),
    Categories = make_set(Category_s),
    TopRules = make_list(RuleName_s, 5)
    by Computer_s, EngagementId_s
| where FindingCount > 0
| extend
    AlertTitle = strcat("AD-Scout: ", FindingCount, " ", "$Severity", "+ findings detected"),
    AlertDescription = strcat("AD-Scout detected ", FindingCount, " security findings (Score: ", TotalScore, ") across ", UniqueRules, " unique rules. Categories: ", Categories)
"@

    if ($OutputKQL) {
        Write-Host "KQL Query for Sentinel Analytics Rule:" -ForegroundColor Cyan
        Write-Host $kql
        return $kql
    }

    # If not just outputting KQL, provide instructions
    Write-Host @"

Microsoft Sentinel Analytics Rule Setup
========================================

1. Navigate to Microsoft Sentinel > Analytics > Create > Scheduled query rule

2. General tab:
   - Name: AD-Scout Security Findings Alert
   - Description: Alerts when AD-Scout detects security findings
   - Severity: $Severity
   - Status: Enabled

3. Rule logic tab:
   - Rule query: (copy the KQL below)
   - Query scheduling: Run every 1 hour, lookup last 1 hour
   - Alert threshold: Greater than 0

4. Incident settings:
   - Create incidents: Enabled
   - Grouping: Group related alerts into a single incident

KQL Query:
----------
$kql

"@ -ForegroundColor Cyan

    return $kql
}

function Test-ADScoutSentinelConnection {
    <#
    .SYNOPSIS
        Tests connectivity to Log Analytics workspace.

    .PARAMETER WorkspaceId
        Log Analytics workspace ID.

    .PARAMETER SharedKey
        Primary or secondary key for the workspace.

    .EXAMPLE
        Test-ADScoutSentinelConnection -WorkspaceId $wsId -SharedKey $key
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [string]$SharedKey,

        [Parameter()]
        [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud')]
        [string]$AzureCloud = 'AzureCloud'
    )

    $endpoint = switch ($AzureCloud) {
        'AzureCloud' { "https://$WorkspaceId.ods.opinsights.azure.com" }
        'AzureUSGovernment' { "https://$WorkspaceId.ods.opinsights.azure.us" }
        'AzureChinaCloud' { "https://$WorkspaceId.ods.opinsights.azure.cn" }
    }

    $testRecord = @(
        @{
            TimeGenerated = (Get-Date).ToUniversalTime().ToString('o')
            Message = 'AD-Scout connection test'
            Test = $true
        }
    )

    $body = $testRecord | ConvertTo-Json -Depth 3

    $rfc1123date = [DateTime]::UtcNow.ToString('r')
    $contentLength = [System.Text.Encoding]::UTF8.GetBytes($body).Length
    $signature = Build-SentinelSignature -WorkspaceId $WorkspaceId -SharedKey $SharedKey -Date $rfc1123date -ContentLength $contentLength -Method 'POST' -ContentType 'application/json' -Resource '/api/logs'

    $headers = @{
        'Authorization' = $signature
        'Log-Type' = 'ADScoutTest'
        'x-ms-date' = $rfc1123date
        'Content-Type' = 'application/json'
    }

    $uri = "$endpoint/api/logs?api-version=2016-04-01"

    try {
        $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing

        if ($response.StatusCode -eq 200) {
            Write-Host "Connection successful!" -ForegroundColor Green
            Write-Host "Test record sent to ADScoutTest_CL table" -ForegroundColor Cyan
            [PSCustomObject]@{
                Status = 'Success'
                WorkspaceId = $WorkspaceId
                Endpoint = $endpoint
                Message = 'Connection verified. Check ADScoutTest_CL table in Log Analytics.'
            }
        }
        else {
            Write-Warning "Unexpected status code: $($response.StatusCode)"
            [PSCustomObject]@{
                Status = 'Warning'
                StatusCode = $response.StatusCode
            }
        }
    }
    catch {
        Write-Error "Connection failed: $_"
        [PSCustomObject]@{
            Status = 'Failed'
            Error = $_.Exception.Message
        }
    }
}

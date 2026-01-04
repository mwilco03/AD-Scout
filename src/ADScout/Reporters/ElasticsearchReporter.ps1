function Export-ADScoutElasticsearch {
    <#
    .SYNOPSIS
        Exports AD-Scout results to Elasticsearch.

    .DESCRIPTION
        Sends AD-Scout scan results to an Elasticsearch cluster using the bulk API.
        Supports ECS (Elastic Common Schema) field mapping for better integration
        with Elastic Security and Kibana dashboards.

        Documents are indexed with the pattern: adscout-findings-{yyyy.MM.dd}

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER ElasticsearchUrl
        Base URL of the Elasticsearch cluster (e.g., https://localhost:9200).

    .PARAMETER Index
        Index name pattern. Supports date formatting with {date:format}.
        Default: adscout-findings-{date:yyyy.MM.dd}

    .PARAMETER ApiKey
        Elasticsearch API key for authentication.

    .PARAMETER Username
        Username for basic authentication (use with Password).

    .PARAMETER Password
        Password for basic authentication (use with Username).

    .PARAMETER UseECS
        Map fields to Elastic Common Schema format.

    .PARAMETER Pipeline
        Ingest pipeline name to process documents.

    .PARAMETER BatchSize
        Number of documents to send per bulk request. Default: 500.

    .PARAMETER EngagementId
        Optional engagement ID to tag all documents.

    .PARAMETER SkipCertificateCheck
        Skip TLS certificate validation (use only for testing).

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutElasticsearch -ElasticsearchUrl "https://elastic:9200" -ApiKey "abc123"

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Export-ADScoutElasticsearch -Results $results -ElasticsearchUrl "https://elastic:9200" -Username "elastic" -Password $securePass

    .EXAMPLE
        # With ECS mapping and custom index
        Export-ADScoutElasticsearch -Results $results -ElasticsearchUrl "https://elastic:9200" -ApiKey $key -UseECS -Index "security-adscout"

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$ElasticsearchUrl,

        [Parameter()]
        [string]$Index = "adscout-findings-{date:yyyy.MM.dd}",

        [Parameter()]
        [string]$ApiKey,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [SecureString]$Password,

        [Parameter()]
        [switch]$UseECS,

        [Parameter()]
        [string]$Pipeline,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$BatchSize = 500,

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    begin {
        $allResults = @()
        $ElasticsearchUrl = $ElasticsearchUrl.TrimEnd('/')

        # Resolve index name with date
        $indexName = $Index -replace '\{date:([^}]+)\}', { (Get-Date).ToString($matches[1]) }

        # Build headers
        $headers = @{
            'Content-Type' = 'application/x-ndjson'
        }

        if ($ApiKey) {
            $headers['Authorization'] = "ApiKey $ApiKey"
        }
        elseif ($Username -and $Password) {
            $cred = New-Object PSCredential($Username, $Password)
            $plainPass = $cred.GetNetworkCredential().Password
            $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${Username}:${plainPass}"))
            $headers['Authorization'] = "Basic $base64"
        }

        # Web request parameters
        $webParams = @{
            Headers = $headers
            Method = 'POST'
            ContentType = 'application/x-ndjson'
        }

        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $webParams['SkipCertificateCheck'] = $true
            }
            else {
                # PowerShell 5.1 workaround
                Add-Type @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
                    }
"@ -ErrorAction SilentlyContinue
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
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

        Write-Host "Exporting $($allResults.Count) results to Elasticsearch..." -ForegroundColor Cyan

        $timestamp = (Get-Date).ToUniversalTime().ToString('o')
        $successCount = 0
        $errorCount = 0

        # Process in batches
        for ($i = 0; $i -lt $allResults.Count; $i += $BatchSize) {
            $batch = $allResults | Select-Object -Skip $i -First $BatchSize
            $ndjsonLines = @()

            foreach ($result in $batch) {
                # Build the document
                if ($UseECS) {
                    $doc = ConvertTo-ECSDocument -Result $result -EngagementId $EngagementId -Timestamp $timestamp
                }
                else {
                    $doc = @{
                        '@timestamp' = $timestamp
                        'adscout' = @{
                            'rule' = @{
                                'id' = $result.RuleId
                                'name' = $result.RuleName
                                'category' = $result.Category
                                'description' = $result.Description
                            }
                            'score' = $result.Score
                            'max_score' = $result.MaxScore
                            'finding_count' = $result.FindingCount
                            'findings' = $result.Findings
                            'mitre' = $result.MITRE
                            'cis' = $result.CIS
                            'nist' = $result.NIST
                            'remediation' = if ($result.Remediation) { $result.Remediation.ToString() } else { $null }
                        }
                        'engagement_id' = $EngagementId
                        'host' = @{
                            'name' = $env:COMPUTERNAME
                        }
                    }
                }

                # Index action
                $action = @{ 'index' = @{ '_index' = $indexName } }
                if ($Pipeline) {
                    $action.index['pipeline'] = $Pipeline
                }

                $ndjsonLines += ($action | ConvertTo-Json -Compress -Depth 1)
                $ndjsonLines += ($doc | ConvertTo-Json -Compress -Depth 10)
            }

            # Build bulk request body
            $body = ($ndjsonLines -join "`n") + "`n"

            # Send bulk request
            $bulkUrl = "$ElasticsearchUrl/_bulk"
            try {
                $response = Invoke-RestMethod -Uri $bulkUrl @webParams -Body $body

                if ($response.errors) {
                    foreach ($item in $response.items) {
                        if ($item.index.error) {
                            $errorCount++
                            Write-Warning "Index error: $($item.index.error.reason)"
                        }
                        else {
                            $successCount++
                        }
                    }
                }
                else {
                    $successCount += $batch.Count
                }

                Write-Verbose "Batch complete: $successCount indexed, $errorCount errors"
            }
            catch {
                Write-Error "Bulk request failed: $_"
                $errorCount += $batch.Count
            }
        }

        Write-Host "Export complete: $successCount documents indexed, $errorCount errors" -ForegroundColor $(if ($errorCount -gt 0) { 'Yellow' } else { 'Green' })

        # Return summary
        [PSCustomObject]@{
            Index = $indexName
            TotalDocuments = $allResults.Count
            Indexed = $successCount
            Errors = $errorCount
            Timestamp = $timestamp
        }
    }
}

function ConvertTo-ECSDocument {
    <#
    .SYNOPSIS
        Converts an AD-Scout result to ECS format.
    #>
    param(
        [PSCustomObject]$Result,
        [string]$EngagementId,
        [string]$Timestamp
    )

    # Map severity to ECS severity levels
    $severity = if ($Result.Score -ge 50) { 'critical' }
               elseif ($Result.Score -ge 30) { 'high' }
               elseif ($Result.Score -ge 15) { 'medium' }
               elseif ($Result.Score -ge 5) { 'low' }
               else { 'informational' }

    $severityNumber = switch ($severity) {
        'critical' { 1 }
        'high' { 2 }
        'medium' { 3 }
        'low' { 4 }
        'informational' { 5 }
    }

    @{
        '@timestamp' = $Timestamp
        'ecs' = @{ 'version' = '8.0.0' }
        'event' = @{
            'kind' = 'alert'
            'category' = @('configuration')
            'type' = @('info')
            'severity' = $severityNumber
            'risk_score' = $Result.Score
            'risk_score_norm' = [math]::Min(100, ($Result.Score / [math]::Max(1, $Result.MaxScore)) * 100)
            'module' = 'adscout'
            'dataset' = 'adscout.findings'
        }
        'rule' = @{
            'id' = $Result.RuleId
            'name' = $Result.RuleName
            'category' = $Result.Category
            'description' = $Result.Description
            'reference' = $Result.References
        }
        'threat' = @{
            'framework' = 'MITRE ATT&CK'
            'technique' = if ($Result.MITRE) {
                $Result.MITRE | ForEach-Object {
                    @{ 'id' = $_; 'name' = $_ }
                }
            } else { @() }
        }
        'vulnerability' = @{
            'severity' = $severity
            'score' = @{
                'base' = $Result.Score
            }
        }
        'adscout' = @{
            'finding_count' = $Result.FindingCount
            'max_score' = $Result.MaxScore
            'category' = $Result.Category
            'cis_controls' = $Result.CIS
            'nist_controls' = $Result.NIST
            'findings' = $Result.Findings | Select-Object -First 100
            'engagement_id' = $EngagementId
        }
        'host' = @{
            'name' = $env:COMPUTERNAME
            'hostname' = $env:COMPUTERNAME
        }
        'observer' = @{
            'product' = 'AD-Scout'
            'vendor' = 'Community'
            'type' = 'security-scanner'
        }
        'labels' = @{
            'engagement_id' = $EngagementId
        }
    }
}

function New-ADScoutElasticsearchIndex {
    <#
    .SYNOPSIS
        Creates an Elasticsearch index with appropriate mappings for AD-Scout data.

    .DESCRIPTION
        Creates an index template with optimized mappings for AD-Scout findings,
        including proper field types, analyzers, and ECS compatibility.

    .PARAMETER ElasticsearchUrl
        Base URL of the Elasticsearch cluster.

    .PARAMETER ApiKey
        Elasticsearch API key for authentication.

    .PARAMETER TemplateName
        Name for the index template. Default: adscout-findings.

    .PARAMETER IndexPattern
        Index pattern to match. Default: adscout-findings-*

    .EXAMPLE
        New-ADScoutElasticsearchIndex -ElasticsearchUrl "https://elastic:9200" -ApiKey "abc123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ElasticsearchUrl,

        [Parameter()]
        [string]$ApiKey,

        [Parameter()]
        [string]$TemplateName = 'adscout-findings',

        [Parameter()]
        [string]$IndexPattern = 'adscout-findings-*'
    )

    $ElasticsearchUrl = $ElasticsearchUrl.TrimEnd('/')

    $headers = @{
        'Content-Type' = 'application/json'
    }

    if ($ApiKey) {
        $headers['Authorization'] = "ApiKey $ApiKey"
    }

    $template = @{
        'index_patterns' = @($IndexPattern)
        'template' = @{
            'settings' = @{
                'number_of_shards' = 1
                'number_of_replicas' = 1
                'index.lifecycle.name' = 'adscout-policy'
            }
            'mappings' = @{
                'dynamic' = 'true'
                'properties' = @{
                    '@timestamp' = @{ 'type' = 'date' }
                    'event' = @{
                        'properties' = @{
                            'kind' = @{ 'type' = 'keyword' }
                            'category' = @{ 'type' = 'keyword' }
                            'severity' = @{ 'type' = 'integer' }
                            'risk_score' = @{ 'type' = 'float' }
                            'risk_score_norm' = @{ 'type' = 'float' }
                        }
                    }
                    'rule' = @{
                        'properties' = @{
                            'id' = @{ 'type' = 'keyword' }
                            'name' = @{ 'type' = 'text'; 'fields' = @{ 'keyword' = @{ 'type' = 'keyword' } } }
                            'category' = @{ 'type' = 'keyword' }
                            'description' = @{ 'type' = 'text' }
                        }
                    }
                    'adscout' = @{
                        'properties' = @{
                            'finding_count' = @{ 'type' = 'integer' }
                            'score' = @{ 'type' = 'float' }
                            'max_score' = @{ 'type' = 'float' }
                            'category' = @{ 'type' = 'keyword' }
                            'engagement_id' = @{ 'type' = 'keyword' }
                            'cis_controls' = @{ 'type' = 'keyword' }
                            'nist_controls' = @{ 'type' = 'keyword' }
                        }
                    }
                    'threat' = @{
                        'properties' = @{
                            'framework' = @{ 'type' = 'keyword' }
                            'technique' = @{
                                'properties' = @{
                                    'id' = @{ 'type' = 'keyword' }
                                    'name' = @{ 'type' = 'keyword' }
                                }
                            }
                        }
                    }
                    'host' = @{
                        'properties' = @{
                            'name' = @{ 'type' = 'keyword' }
                            'hostname' = @{ 'type' = 'keyword' }
                        }
                    }
                }
            }
        }
        'priority' = 200
    }

    $body = $template | ConvertTo-Json -Depth 20

    try {
        $response = Invoke-RestMethod -Uri "$ElasticsearchUrl/_index_template/$TemplateName" -Method PUT -Headers $headers -Body $body
        Write-Host "Index template '$TemplateName' created successfully" -ForegroundColor Green
        $response
    }
    catch {
        Write-Error "Failed to create index template: $_"
    }
}

<#
.SYNOPSIS
    Example of integrating AD-Scout with Elasticsearch/Elastic SIEM.

.DESCRIPTION
    Demonstrates how to send AD-Scout findings to Elasticsearch
    for SIEM integration and dashboarding.

.NOTES
    Requires Elasticsearch endpoint and appropriate credentials.
#>

#Requires -Version 5.1

Import-Module ADScout -Force

Write-Host "AD-Scout Elastic Integration Example" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Configuration - Update these for your environment
$elasticConfig = @{
    Endpoint = 'https://elasticsearch.example.com:9200'
    Index    = 'adscout-findings'
    Username = 'elastic'
    # Use secure method in production:
    # $password = Get-Content ./elastic-password.txt | ConvertTo-SecureString
    Password = 'changeme'
}

# Function to send documents to Elasticsearch
function Send-ToElastic {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Documents,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter(Mandatory)]
        [string]$Index,

        [string]$Username,
        [string]$Password
    )

    $headers = @{
        'Content-Type' = 'application/json'
    }

    # Create credential if provided
    if ($Username -and $Password) {
        $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
        $headers['Authorization'] = "Basic $base64Auth"
    }

    $bulkPayload = ""

    foreach ($doc in $Documents) {
        # Index action
        $action = @{ index = @{ _index = $Index } } | ConvertTo-Json -Compress
        $document = $doc | ConvertTo-Json -Compress -Depth 10

        $bulkPayload += "$action`n$document`n"
    }

    try {
        $response = Invoke-RestMethod -Uri "$Endpoint/_bulk" `
                                       -Method Post `
                                       -Headers $headers `
                                       -Body $bulkPayload

        if ($response.errors) {
            Write-Warning "Some documents failed to index"
            $response.items | Where-Object { $_.index.error } | ForEach-Object {
                Write-Warning "Error: $($_.index.error.reason)"
            }
        }

        return $response
    }
    catch {
        Write-Error "Failed to send to Elasticsearch: $_"
        throw
    }
}

# Run AD-Scout scan
Write-Host "`nRunning AD-Scout scan..." -ForegroundColor Yellow
$results = Invoke-ADScoutScan

if (-not $results) {
    Write-Host "No findings to send." -ForegroundColor Green
    return
}

# Transform results to Elastic Common Schema (ECS) format
Write-Host "`nTransforming $($results.Count) findings to ECS format..." -ForegroundColor Yellow

$elasticDocs = $results | ForEach-Object {
    $result = $_

    # Base document
    $doc = [ordered]@{
        '@timestamp'     = (Get-Date).ToString('o')
        'event.kind'     = 'alert'
        'event.category' = @('configuration')
        'event.type'     = @('info')
        'event.module'   = 'adscout'
        'event.dataset'  = 'adscout.finding'

        'rule.id'          = $result.RuleId
        'rule.name'        = $result.RuleName
        'rule.category'    = $result.Category
        'rule.description' = $result.Description

        'adscout.score'      = $result.Score
        'adscout.max_score'  = $result.MaxScore
        'adscout.finding_count' = $result.FindingCount

        'threat.framework' = 'MITRE ATT&CK'
        'threat.technique.id' = $result.MITRE

        'host.domain' = $env:USERDNSDOMAIN
        'host.name'   = $env:COMPUTERNAME
    }

    # Add individual findings as nested documents
    if ($result.Findings) {
        $doc['adscout.findings'] = $result.Findings | ForEach-Object {
            [ordered]@{
                sam_account_name    = $_.SamAccountName
                distinguished_name  = $_.DistinguishedName
            }
        }
    }

    [PSCustomObject]$doc
}

# Send to Elasticsearch
Write-Host "`nSending to Elasticsearch..." -ForegroundColor Yellow
Write-Host "Endpoint: $($elasticConfig.Endpoint)" -ForegroundColor Gray
Write-Host "Index: $($elasticConfig.Index)" -ForegroundColor Gray

try {
    # Uncomment to actually send:
    # $response = Send-ToElastic -Documents $elasticDocs @elasticConfig

    # For demo, just show what would be sent
    Write-Host "`nSample document that would be sent:" -ForegroundColor Yellow
    $elasticDocs | Select-Object -First 1 | ConvertTo-Json -Depth 5

    Write-Host "`n[Demo mode - Uncomment Send-ToElastic to actually send]" -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to send to Elasticsearch: $_"
}

# Also save locally as JSON for bulk import
$outputPath = './adscout-elastic-export.ndjson'
Write-Host "`nSaving NDJSON export to: $outputPath" -ForegroundColor Yellow

$elasticDocs | ForEach-Object {
    $_ | ConvertTo-Json -Compress -Depth 10
} | Out-File $outputPath -Encoding UTF8

Write-Host "`nElastic integration complete!" -ForegroundColor Green
Write-Host "Documents can be imported with: curl -X POST '$($elasticConfig.Endpoint)/_bulk' --data-binary '@$outputPath'" -ForegroundColor Gray

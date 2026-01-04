function Export-ADScoutSplunk {
    <#
    .SYNOPSIS
        Exports AD-Scout results to Splunk via HTTP Event Collector (HEC).

    .DESCRIPTION
        Sends AD-Scout scan results to Splunk using the HTTP Event Collector API.
        Supports batching, custom indexes, source types, and CIM-compliant field mapping.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER HECUrl
        Splunk HEC endpoint URL (e.g., https://splunk:8088/services/collector/event).

    .PARAMETER Token
        HEC token for authentication.

    .PARAMETER Index
        Target Splunk index. If not specified, uses HEC token's default index.

    .PARAMETER SourceType
        Source type for events. Default: adscout:findings

    .PARAMETER Source
        Source identifier. Default: AD-Scout

    .PARAMETER Host
        Host value for events. Default: local computer name.

    .PARAMETER UseCIM
        Map fields to Splunk Common Information Model (Alerts data model).

    .PARAMETER BatchSize
        Number of events to send per request. Default: 100.

    .PARAMETER EngagementId
        Optional engagement ID to tag all events.

    .PARAMETER SkipCertificateCheck
        Skip TLS certificate validation (use only for testing).

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutSplunk -HECUrl "https://splunk:8088/services/collector/event" -Token "abc-123"

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Export-ADScoutSplunk -Results $results -HECUrl $hecUrl -Token $token -Index "security" -UseCIM

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$HECUrl,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter()]
        [string]$Index,

        [Parameter()]
        [string]$SourceType = 'adscout:findings',

        [Parameter()]
        [string]$Source = 'AD-Scout',

        [Parameter()]
        [string]$Host,

        [Parameter()]
        [switch]$UseCIM,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$BatchSize = 100,

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    begin {
        $allResults = @()

        if (-not $Host) {
            $Host = $env:COMPUTERNAME
        }

        # Build headers
        $headers = @{
            'Authorization' = "Splunk $Token"
            'Content-Type' = 'application/json'
        }

        # Web request parameters
        $webParams = @{
            Headers = $headers
            Method = 'POST'
            ContentType = 'application/json'
        }

        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $webParams['SkipCertificateCheck'] = $true
            }
            else {
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

        Write-Host "Exporting $($allResults.Count) results to Splunk HEC..." -ForegroundColor Cyan

        $timestamp = [int][double]::Parse((Get-Date -UFormat %s))
        $successCount = 0
        $errorCount = 0

        # Process in batches
        for ($i = 0; $i -lt $allResults.Count; $i += $BatchSize) {
            $batch = $allResults | Select-Object -Skip $i -First $BatchSize
            $events = @()

            foreach ($result in $batch) {
                # Build event data
                if ($UseCIM) {
                    $eventData = ConvertTo-SplunkCIMEvent -Result $result -EngagementId $EngagementId
                }
                else {
                    $eventData = @{
                        rule_id = $result.RuleId
                        rule_name = $result.RuleName
                        category = $result.Category
                        description = $result.Description
                        score = $result.Score
                        max_score = $result.MaxScore
                        finding_count = $result.FindingCount
                        severity = Get-SeverityLevel -Score $result.Score
                        mitre_techniques = $result.MITRE
                        cis_controls = $result.CIS
                        nist_controls = $result.NIST
                        engagement_id = $EngagementId
                        findings = $result.Findings | Select-Object -First 50
                    }
                }

                # Build HEC event wrapper
                $event = @{
                    time = $timestamp
                    host = $Host
                    source = $Source
                    sourcetype = $SourceType
                    event = $eventData
                }

                if ($Index) {
                    $event['index'] = $Index
                }

                $events += $event
            }

            # Send batch (Splunk accepts multiple JSON objects without array wrapper)
            $body = ($events | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 }) -join ''

            try {
                $response = Invoke-RestMethod -Uri $HECUrl @webParams -Body $body

                if ($response.text -eq 'Success') {
                    $successCount += $batch.Count
                }
                else {
                    Write-Warning "HEC response: $($response | ConvertTo-Json -Compress)"
                    $errorCount += $batch.Count
                }

                Write-Verbose "Batch complete: $successCount sent, $errorCount errors"
            }
            catch {
                Write-Error "HEC request failed: $_"
                $errorCount += $batch.Count
            }
        }

        Write-Host "Export complete: $successCount events sent, $errorCount errors" -ForegroundColor $(if ($errorCount -gt 0) { 'Yellow' } else { 'Green' })

        # Return summary
        [PSCustomObject]@{
            Index = $Index
            TotalEvents = $allResults.Count
            Sent = $successCount
            Errors = $errorCount
            Timestamp = (Get-Date).ToString('o')
        }
    }
}

function Get-SeverityLevel {
    param([int]$Score)

    if ($Score -ge 50) { 'critical' }
    elseif ($Score -ge 30) { 'high' }
    elseif ($Score -ge 15) { 'medium' }
    elseif ($Score -ge 5) { 'low' }
    else { 'informational' }
}

function ConvertTo-SplunkCIMEvent {
    <#
    .SYNOPSIS
        Converts an AD-Scout result to Splunk CIM Alerts data model format.
    #>
    param(
        [PSCustomObject]$Result,
        [string]$EngagementId
    )

    $severity = Get-SeverityLevel -Score $Result.Score

    # Map to CIM Alerts data model
    @{
        # Alert fields (CIM)
        app = 'AD-Scout'
        type = 'security'
        severity = $severity
        severity_id = switch ($severity) {
            'critical' { 5 }
            'high' { 4 }
            'medium' { 3 }
            'low' { 2 }
            'informational' { 1 }
        }
        signature = $Result.RuleId
        signature_id = $Result.RuleId
        description = $Result.Description
        category = $Result.Category

        # Risk scoring
        risk_score = $Result.Score
        risk_level = $severity

        # Additional context
        mitre_attack_id = if ($Result.MITRE) { $Result.MITRE -join ',' } else { $null }
        mitre_attack_technique = $Result.MITRE

        # Finding details
        objects_affected = $Result.FindingCount
        findings = $Result.Findings | Select-Object -First 50

        # Compliance mappings
        cis_control = $Result.CIS
        nist_control = $Result.NIST

        # Engagement tracking
        engagement_id = $EngagementId

        # Rule metadata
        rule = @{
            id = $Result.RuleId
            name = $Result.RuleName
            category = $Result.Category
            max_score = $Result.MaxScore
        }

        # Vendor info
        vendor_product = 'AD-Scout'
        action = 'detected'
    }
}

function Test-ADScoutSplunkConnection {
    <#
    .SYNOPSIS
        Tests connectivity to Splunk HEC endpoint.

    .PARAMETER HECUrl
        Splunk HEC endpoint URL.

    .PARAMETER Token
        HEC token for authentication.

    .EXAMPLE
        Test-ADScoutSplunkConnection -HECUrl "https://splunk:8088/services/collector/event" -Token "abc-123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HECUrl,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $headers = @{
        'Authorization' = "Splunk $Token"
        'Content-Type' = 'application/json'
    }

    $testEvent = @{
        event = @{
            message = 'AD-Scout connection test'
            test = $true
        }
    } | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Uri $HECUrl -Method POST -Headers $headers -Body $testEvent -TimeoutSec 10

        if ($response.text -eq 'Success') {
            Write-Host "Connection successful!" -ForegroundColor Green
            [PSCustomObject]@{
                Status = 'Success'
                Code = $response.code
                Message = 'HEC endpoint is reachable and token is valid'
            }
        }
        else {
            Write-Warning "Unexpected response: $($response | ConvertTo-Json)"
            [PSCustomObject]@{
                Status = 'Warning'
                Response = $response
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

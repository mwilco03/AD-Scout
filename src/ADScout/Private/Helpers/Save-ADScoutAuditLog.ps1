function Save-ADScoutAuditLog {
    <#
    .SYNOPSIS
        Saves execution audit log for compliance and tracking.

    .DESCRIPTION
        Creates an immutable audit trail of AD-Scout scan execution including:
        - Execution metadata (who, when, where)
        - Scan parameters and profile
        - Summary of findings
        - Integrity checksum

        Audit logs are stored alongside session data and can be forwarded to SIEM.

    .PARAMETER AuditLog
        The audit log hashtable containing execution details.

    .PARAMETER SessionPath
        Path to the session directory.

    .EXAMPLE
        Save-ADScoutAuditLog -AuditLog $auditData -SessionPath $sessionPath
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditLog,

        [Parameter()]
        [string]$SessionPath
    )

    try {
        # Determine log directory
        $logDir = if ($SessionPath) {
            Join-Path $SessionPath 'Logs'
        } else {
            $defaultPath = Join-Path $env:LOCALAPPDATA 'ADScout\Logs'
            $defaultPath
        }

        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        # Create timestamp for filenames
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        # Build manifest object
        $manifest = [ordered]@{
            SchemaVersion  = '1.0'
            ExecutionId    = $AuditLog.ExecutionId
            StartTime      = $AuditLog.StartTime.ToString('o')
            EndTime        = $AuditLog.EndTime.ToString('o')
            DurationSeconds = [math]::Round($AuditLog.Duration, 2)
            Operator       = $AuditLog.Operator
            HostName       = $env:COMPUTERNAME
            TargetDomain   = $AuditLog.TargetDomain
            ScanProfile    = $AuditLog.ScanProfile
            AlertProfile   = $AuditLog.AlertProfile
            ToolVersion    = (Get-Module ADScout -ErrorAction SilentlyContinue).Version.ToString()
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Parameters     = $AuditLog.Parameters
            Results        = @{
                RulesEvaluated = $AuditLog.RulesEvaluated
                FindingsCount  = $AuditLog.FindingsCount
                TotalScore     = $AuditLog.TotalScore
            }
            Events         = $AuditLog.Events
        }

        # Convert to JSON
        $manifestJson = $manifest | ConvertTo-Json -Depth 10

        # Calculate integrity checksum
        $hash = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($manifestJson)
        $hashBytes = $hash.ComputeHash($bytes)
        $hashString = [BitConverter]::ToString($hashBytes) -replace '-', ''

        # Add checksum to manifest
        $manifest.Checksum = "SHA256:$hashString"

        # Save manifest
        $manifestPath = Join-Path $logDir "ADScout-$timestamp-Manifest.json"
        $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding UTF8 -Force

        # Save detailed execution log
        $logPath = Join-Path $logDir "ADScout-$timestamp-Scan.log"
        $logContent = @"
================================================================================
AD-Scout Execution Log
================================================================================
Execution ID: $($manifest.ExecutionId)
Start Time:   $($manifest.StartTime)
End Time:     $($manifest.EndTime)
Duration:     $($manifest.DurationSeconds) seconds

OPERATOR
--------
User:     $($manifest.Operator)
Host:     $($manifest.HostName)
Domain:   $($manifest.TargetDomain)

CONFIGURATION
-------------
Scan Profile:  $($manifest.ScanProfile ?? 'Default')
Alert Profile: $($manifest.AlertProfile -join ', ' ?? 'All')
Categories:    $($manifest.Parameters.Category -join ', ')

RESULTS
-------
Rules Evaluated: $($manifest.Results.RulesEvaluated)
Findings:        $($manifest.Results.FindingsCount)
Total Score:     $($manifest.Results.TotalScore)

TOOL INFO
---------
Version:    $($manifest.ToolVersion)
PowerShell: $($manifest.PowerShellVersion)

INTEGRITY
---------
$($manifest.Checksum)
================================================================================
"@
        $logContent | Out-File -FilePath $logPath -Encoding UTF8 -Force

        Write-Verbose "Audit log saved to: $logDir"

        # Return manifest for SIEM forwarding
        return $manifest
    }
    catch {
        Write-Warning "Failed to save audit log: $_"
    }
}

function Send-ADScoutAuditToSIEM {
    <#
    .SYNOPSIS
        Forwards audit log to SIEM endpoint.

    .PARAMETER AuditLog
        The audit manifest to send.

    .PARAMETER Destination
        SIEM type: 'Splunk', 'Elasticsearch', 'Sentinel', 'Syslog'

    .PARAMETER Endpoint
        SIEM endpoint URL or host.

    .PARAMETER Token
        Authentication token (for Splunk HEC, etc.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditLog,

        [Parameter(Mandatory)]
        [ValidateSet('Splunk', 'Elasticsearch', 'Sentinel', 'Syslog')]
        [string]$Destination,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter()]
        [string]$Token
    )

    try {
        switch ($Destination) {
            'Splunk' {
                $headers = @{
                    'Authorization' = "Splunk $Token"
                    'Content-Type'  = 'application/json'
                }
                $body = @{
                    event      = $AuditLog
                    sourcetype = 'adscout:audit'
                    source     = 'ADScout'
                    index      = 'security'
                } | ConvertTo-Json -Depth 10

                Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $headers -Body $body
                Write-Verbose "Audit log forwarded to Splunk"
            }

            'Elasticsearch' {
                $headers = @{ 'Content-Type' = 'application/json' }
                if ($Token) {
                    $headers['Authorization'] = "ApiKey $Token"
                }
                $body = $AuditLog | ConvertTo-Json -Depth 10

                $indexUrl = "$Endpoint/adscout-audit-$(Get-Date -Format 'yyyy.MM.dd')/_doc"
                Invoke-RestMethod -Uri $indexUrl -Method Post -Headers $headers -Body $body
                Write-Verbose "Audit log forwarded to Elasticsearch"
            }

            'Sentinel' {
                # Azure Sentinel/Log Analytics
                $body = $AuditLog | ConvertTo-Json -Depth 10
                # Sentinel ingestion requires workspace ID and key
                Write-Warning "Sentinel integration requires additional configuration"
            }

            'Syslog' {
                # Basic syslog via UDP
                $message = "ADScout Audit: ExecutionId=$($AuditLog.ExecutionId) Operator=$($AuditLog.Operator) Findings=$($AuditLog.Results.FindingsCount)"
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $bytes = [System.Text.Encoding]::ASCII.GetBytes("<14>$message")
                $parts = $Endpoint -split ':'
                $udpClient.Send($bytes, $bytes.Length, $parts[0], [int]$parts[1])
                $udpClient.Close()
                Write-Verbose "Audit log forwarded to Syslog"
            }
        }
    }
    catch {
        Write-Warning "Failed to forward audit log to $Destination`: $_"
    }
}

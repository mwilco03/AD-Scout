function Get-ADScoutAuditLog {
    <#
    .SYNOPSIS
        Retrieves AD-Scout execution audit logs.

    .DESCRIPTION
        Searches and returns audit logs from AD-Scout scan executions.
        Logs include execution metadata, parameters, and results summary.

    .PARAMETER Last
        Return the N most recent audit logs.

    .PARAMETER ExecutionId
        Return a specific audit log by execution ID.

    .PARAMETER Since
        Return logs since a specific date/time.

    .PARAMETER Domain
        Filter logs by target domain.

    .PARAMETER Operator
        Filter logs by operator (username).

    .PARAMETER Path
        Custom path to search for logs. Defaults to %LOCALAPPDATA%\ADScout\Logs.

    .EXAMPLE
        Get-ADScoutAuditLog -Last 5

    .EXAMPLE
        Get-ADScoutAuditLog -ExecutionId "abc123-def456"

    .EXAMPLE
        Get-ADScoutAuditLog -Since (Get-Date).AddDays(-7) -Domain "customer.local"
    #>
    [CmdletBinding(DefaultParameterSetName = 'Last')]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(ParameterSetName = 'Last')]
        [int]$Last = 10,

        [Parameter(Mandatory, ParameterSetName = 'ExecutionId')]
        [string]$ExecutionId,

        [Parameter(ParameterSetName = 'Since')]
        [datetime]$Since,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Operator,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [switch]$IncludeDetails
    )

    # Determine log directory
    $logDirs = @()

    if ($Path) {
        $logDirs += $Path
    } else {
        # Default locations
        $logDirs += Join-Path $env:LOCALAPPDATA 'ADScout\Logs'

        # Also check session directories for embedded logs
        $sessionBase = Join-Path $env:LOCALAPPDATA 'ADScout\Sessions'
        if (Test-Path $sessionBase) {
            $logDirs += Get-ChildItem -Path $sessionBase -Directory -Recurse |
                        Where-Object { Test-Path (Join-Path $_.FullName 'Logs') } |
                        ForEach-Object { Join-Path $_.FullName 'Logs' }
        }
    }

    $allLogs = @()

    foreach ($logDir in $logDirs) {
        if (-not (Test-Path $logDir)) {
            continue
        }

        # Find manifest files
        $manifests = Get-ChildItem -Path $logDir -Filter '*-Manifest.json' -ErrorAction SilentlyContinue

        foreach ($manifest in $manifests) {
            try {
                $logData = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json

                # Convert to consistent object
                $logEntry = [PSCustomObject]@{
                    ExecutionId     = $logData.ExecutionId
                    StartTime       = [datetime]$logData.StartTime
                    EndTime         = if ($logData.EndTime) { [datetime]$logData.EndTime } else { $null }
                    Duration        = if ($logData.DurationSeconds) { [TimeSpan]::FromSeconds($logData.DurationSeconds) } else { $null }
                    Operator        = $logData.Operator
                    HostName        = $logData.HostName
                    TargetDomain    = $logData.TargetDomain
                    ScanProfile     = $logData.ScanProfile
                    AlertProfile    = $logData.AlertProfile
                    RulesEvaluated  = $logData.Results.RulesEvaluated
                    FindingsCount   = $logData.Results.FindingsCount
                    TotalScore      = $logData.Results.TotalScore
                    ToolVersion     = $logData.ToolVersion
                    Checksum        = $logData.Checksum
                    ManifestPath    = $manifest.FullName
                    Parameters      = $logData.Parameters
                }

                $allLogs += $logEntry
            }
            catch {
                Write-Verbose "Failed to parse manifest: $($manifest.FullName) - $_"
            }
        }
    }

    # Apply filters
    $filteredLogs = $allLogs

    if ($PSCmdlet.ParameterSetName -eq 'ExecutionId') {
        $filteredLogs = $filteredLogs | Where-Object { $_.ExecutionId -eq $ExecutionId -or $_.ExecutionId -like "$ExecutionId*" }
    }

    if ($Since) {
        $filteredLogs = $filteredLogs | Where-Object { $_.StartTime -ge $Since }
    }

    if ($Domain) {
        $filteredLogs = $filteredLogs | Where-Object { $_.TargetDomain -like "*$Domain*" }
    }

    if ($Operator) {
        $filteredLogs = $filteredLogs | Where-Object { $_.Operator -like "*$Operator*" }
    }

    # Sort by start time descending
    $filteredLogs = $filteredLogs | Sort-Object StartTime -Descending

    # Apply Last limit
    if ($PSCmdlet.ParameterSetName -eq 'Last' -and $Last -gt 0) {
        $filteredLogs = $filteredLogs | Select-Object -First $Last
    }

    # Format output
    if (-not $IncludeDetails) {
        $filteredLogs = $filteredLogs | Select-Object ExecutionId, StartTime, Operator, TargetDomain, ScanProfile, RulesEvaluated, FindingsCount, TotalScore, Duration
    }

    return $filteredLogs
}

function Show-ADScoutAuditLog {
    <#
    .SYNOPSIS
        Displays formatted audit log information.

    .PARAMETER ExecutionId
        The execution ID to display.

    .EXAMPLE
        Show-ADScoutAuditLog -ExecutionId "abc123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ExecutionId
    )

    $log = Get-ADScoutAuditLog -ExecutionId $ExecutionId -IncludeDetails

    if (-not $log) {
        Write-Warning "Audit log not found: $ExecutionId"
        return
    }

    Write-Host "`nAD-Scout Execution Audit" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Cyan

    Write-Host "`nExecution Details:" -ForegroundColor White
    Write-Host "  ID:        $($log.ExecutionId)" -ForegroundColor Gray
    Write-Host "  Started:   $($log.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host "  Duration:  $($log.Duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    Write-Host "  Operator:  $($log.Operator)" -ForegroundColor Gray
    Write-Host "  Host:      $($log.HostName)" -ForegroundColor Gray

    Write-Host "`nTarget:" -ForegroundColor White
    Write-Host "  Domain:    $($log.TargetDomain)" -ForegroundColor Gray
    Write-Host "  Profile:   $($log.ScanProfile)" -ForegroundColor Gray

    Write-Host "`nResults:" -ForegroundColor White
    Write-Host "  Rules:     $($log.RulesEvaluated)" -ForegroundColor Gray
    Write-Host "  Findings:  $($log.FindingsCount)" -ForegroundColor $(if ($log.FindingsCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Score:     $($log.TotalScore)" -ForegroundColor $(if ($log.TotalScore -ge 100) { 'Red' } elseif ($log.TotalScore -ge 50) { 'Yellow' } else { 'Green' })

    if ($log.Parameters) {
        Write-Host "`nParameters:" -ForegroundColor White
        $log.Parameters.PSObject.Properties | ForEach-Object {
            if ($_.Value) {
                Write-Host "  $($_.Name): $($_.Value -join ', ')" -ForegroundColor Gray
            }
        }
    }

    Write-Host "`nIntegrity:" -ForegroundColor White
    Write-Host "  $($log.Checksum)" -ForegroundColor DarkGray

    Write-Host "`nManifest: $($log.ManifestPath)" -ForegroundColor DarkGray
}

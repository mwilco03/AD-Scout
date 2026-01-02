function Stop-ADScoutDashboardServer {
    <#
    .SYNOPSIS
        Stops the AD-Scout web dashboard server.

    .DESCRIPTION
        Stops a running AD-Scout dashboard server that was started with
        Start-ADScoutDashboardServer -Background.

    .PARAMETER Job
        The background job object returned by Start-ADScoutDashboardServer.
        If not provided, attempts to find and stop the most recent dashboard job.

    .PARAMETER Force
        Force stop without confirmation.

    .EXAMPLE
        Stop-ADScoutDashboardServer
        Stops the running dashboard server.

    .EXAMPLE
        $job = Show-ADScoutDashboard -Results $results -Background
        Stop-ADScoutDashboardServer -Job $job
        Stops a specific dashboard server job.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [System.Management.Automation.Job]$Job,

        [Parameter()]
        [switch]$Force
    )

    # Find the job if not specified
    if (-not $Job) {
        if ($script:ADScoutDashboard -and $script:ADScoutDashboard.Job) {
            $Job = $script:ADScoutDashboard.Job
        } else {
            # Look for running AD-Scout dashboard jobs
            $Job = Get-Job | Where-Object {
                $_.State -eq 'Running' -and
                $_.Command -like '*ADScoutDashboard*'
            } | Select-Object -First 1
        }
    }

    if (-not $Job) {
        Write-Warning "No running AD-Scout dashboard server found."
        return
    }

    if ($Force -or $PSCmdlet.ShouldProcess("Dashboard server (Job $($Job.Id))", "Stop")) {
        # Stop the job
        Stop-Job -Job $Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue

        # Clear script state
        if ($script:ADScoutDashboard) {
            $script:ADScoutDashboard.Job = $null
        }

        Write-Host "AD-Scout Dashboard server stopped." -ForegroundColor Yellow
    }
}

function Get-ADScoutDashboardStatus {
    <#
    .SYNOPSIS
        Gets the status of the AD-Scout dashboard server.

    .DESCRIPTION
        Returns information about the running dashboard server including
        URL, uptime, and scan data summary.

    .OUTPUTS
        PSCustomObject with dashboard status information.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:ADScoutDashboard) {
        return [PSCustomObject]@{
            Running = $false
            Message = 'No dashboard server has been started in this session.'
        }
    }

    $job = $script:ADScoutDashboard.Job
    $isRunning = $job -and $job.State -eq 'Running'

    [PSCustomObject]@{
        Running = $isRunning
        Port = $script:ADScoutDashboard.Port
        URL = "http://localhost:$($script:ADScoutDashboard.Port)"
        StartTime = $script:ADScoutDashboard.StartTime
        Uptime = if ($isRunning) {
            (Get-Date) - $script:ADScoutDashboard.StartTime
        } else { $null }
        AutoRefresh = $script:ADScoutDashboard.AutoRefresh
        RefreshInterval = $script:ADScoutDashboard.RefreshInterval
        JobId = if ($job) { $job.Id } else { $null }
        JobState = if ($job) { $job.State } else { 'NotStarted' }
        Score = $script:ADScoutDashboard.Data.Summary.NormalizedScore
        TotalFindings = $script:ADScoutDashboard.Data.Summary.TotalFindings
        IsFirstRun = $script:ADScoutDashboard.Data.State.IsFirstRun
    }
}

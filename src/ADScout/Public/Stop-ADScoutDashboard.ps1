function Stop-ADScoutDashboard {
    <#
    .SYNOPSIS
        Stops a running AD-Scout dashboard server.

    .DESCRIPTION
        Stops the AD-Scout web dashboard server that was started with
        Show-ADScoutDashboard -Background.

    .PARAMETER Job
        The background job object returned by Show-ADScoutDashboard.
        If not provided, attempts to find and stop the most recent dashboard job.

    .PARAMETER Force
        Force stop without confirmation.

    .EXAMPLE
        Stop-ADScoutDashboard
        Stops the running dashboard server.

    .EXAMPLE
        $job = Show-ADScoutDashboard -Results $results -Background
        Stop-ADScoutDashboard -Job $job
        Stops a specific dashboard server job.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [System.Management.Automation.Job]$Job,

        [Parameter()]
        [switch]$Force
    )

    Stop-ADScoutDashboardServer -Job $Job -Force:$Force
}

function Get-ADScoutDashboard {
    <#
    .SYNOPSIS
        Gets the status of the AD-Scout dashboard server.

    .DESCRIPTION
        Returns information about the running dashboard server including
        URL, uptime, and scan data summary.

    .EXAMPLE
        Get-ADScoutDashboard
        Returns status information about the dashboard server.

    .OUTPUTS
        PSCustomObject with dashboard status information.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param()

    Get-ADScoutDashboardStatus
}

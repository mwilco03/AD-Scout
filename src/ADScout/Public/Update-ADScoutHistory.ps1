function Update-ADScoutHistory {
    <#
    .SYNOPSIS
        Updates scan history for trend tracking.

    .DESCRIPTION
        Appends the current scan to a history file for trend analysis
        in the dashboard.

    .PARAMETER Results
        Array of ADScoutResult objects from Invoke-ADScoutScan.

    .PARAMETER Path
        Path to history JSON file.
        Defaults to 'adscout-history.json' in the current directory.

    .PARAMETER MaxEntries
        Maximum number of history entries to keep (default: 50).

    .EXAMPLE
        Invoke-ADScoutScan | Update-ADScoutHistory
        Adds current scan to history.

    .OUTPUTS
        String path to the updated history file.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$Path = (Join-Path $PWD 'adscout-history.json'),

        [Parameter()]
        [ValidateRange(5, 1000)]
        [int]$MaxEntries = 50
    )

    begin {
        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Error "No scan results to add to history."
            return
        }

        # Get dashboard data
        $dashboardData = Get-DashboardData -Results $allResults

        # Load existing history
        $history = @()
        if (Test-Path $Path) {
            try {
                $existingContent = Get-Content $Path -Raw
                if ($existingContent) {
                    $parsed = $existingContent | ConvertFrom-Json
                    if ($parsed -is [array]) {
                        $history = @($parsed)
                    } else {
                        $history = @($parsed)
                    }
                }
            } catch {
                Write-Warning "Could not parse existing history file. Starting fresh."
                $history = @()
            }
        }

        # Add new entry
        $entry = [PSCustomObject]@{
            timestamp = (Get-Date).ToString('o')
            score = $dashboardData.Summary.NormalizedScore
            totalFindings = $dashboardData.Summary.TotalFindings
            rulesWithFindings = $dashboardData.Summary.RulesWithFindings
            grade = $dashboardData.Summary.Grade
        }

        $history = @($history) + @($entry)

        # Trim to max entries
        if ($history.Count -gt $MaxEntries) {
            $history = $history | Select-Object -Last $MaxEntries
        }

        # Ensure directory exists
        $directory = Split-Path $Path -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        # Save history
        $history | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8

        Write-Verbose "History updated: $Path ($($history.Count) entries)"

        return $Path
    }
}

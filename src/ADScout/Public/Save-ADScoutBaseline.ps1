function Save-ADScoutBaseline {
    <#
    .SYNOPSIS
        Saves current scan results as a baseline for future comparisons.

    .DESCRIPTION
        DEPRECATED: This function is a wrapper for Export-ADScoutBaseline.
        Please use Export-ADScoutBaseline directly for more options including
        multiple formats (JSON, CSV, CLIXML, XML) and compression.

        Creates a baseline file from the current scan results. This baseline
        can be used with Show-ADScoutDashboard to track security posture
        changes over time.

    .PARAMETER Results
        Array of ADScoutResult objects from Invoke-ADScoutScan.
        If not provided via parameter or pipeline, runs a new scan.

    .PARAMETER Path
        Output path for the baseline JSON file.
        Defaults to 'adscout-baseline.json' in the current directory.

    .PARAMETER Force
        Overwrite existing baseline file without prompting.

    .EXAMPLE
        Invoke-ADScoutScan | Save-ADScoutBaseline
        Runs a scan and saves results as the baseline.

    .EXAMPLE
        # Preferred: Use Export-ADScoutBaseline directly
        Invoke-ADScoutScan | Export-ADScoutBaseline -Path ./baseline.json

    .OUTPUTS
        String path to the saved baseline file.

    .NOTES
        Author: AD-Scout Contributors
        This function is deprecated. Use Export-ADScoutBaseline instead.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$Path = (Join-Path $PWD 'adscout-baseline.json'),

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Warning "Save-ADScoutBaseline is deprecated. Use Export-ADScoutBaseline for more options (formats, compression)."
        $allResults = @()
    }

    process {
        if ($Results) {
            $allResults += $Results
        }
    }

    end {
        # Run scan if no results provided
        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Host "Running AD-Scout security scan..." -ForegroundColor Yellow
            $allResults = Invoke-ADScoutScan
        }

        if (-not $allResults -or $allResults.Count -eq 0) {
            Write-Error "No scan results to save as baseline."
            return
        }

        # Delegate to Export-ADScoutBaseline
        $exportParams = @{
            Results = $allResults
            Path    = $Path
            Format  = 'json'
        }

        if ($Force) {
            $exportParams['Force'] = $true
        }

        try {
            Export-ADScoutBaseline @exportParams
            return $Path
        }
        catch {
            Write-Error "Failed to save baseline: $_"
        }
    }
}

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

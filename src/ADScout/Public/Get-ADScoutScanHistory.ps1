function Get-ADScoutScanHistory {
    <#
    .SYNOPSIS
        Retrieves scan history for trend visualization.

    .DESCRIPTION
        Reads scan history from a JSON file created by Save-ADScoutScanHistory.
        Returns data formatted for use with Export-ADScoutReport -TrendHistory.

    .PARAMETER Path
        Path to the history JSON file.

    .PARAMETER Last
        Return only the last N entries. Default returns all.

    .PARAMETER Since
        Return entries since this date (inclusive).

    .PARAMETER AsChartData
        Return simplified objects with just Date and Score properties,
        optimized for chart rendering.

    .EXAMPLE
        Get-ADScoutScanHistory -Path ./scan-history.json
        Returns all history entries.

    .EXAMPLE
        Get-ADScoutScanHistory -Path ./history.json -Last 10
        Returns the 10 most recent entries.

    .EXAMPLE
        Get-ADScoutScanHistory -Path ./history.json -Since "2024-01-01"
        Returns entries from 2024 onwards.

    .EXAMPLE
        # Use with HTML report
        $history = Get-ADScoutScanHistory -Path ./history.json -Last 12 -AsChartData
        Export-ADScoutReport -Format HTML -Path ./report.html -TrendHistory $history

    .OUTPUTS
        PSCustomObject[] - Array of history entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path,

        [Parameter()]
        [int]$Last,

        [Parameter()]
        [datetime]$Since,

        [Parameter()]
        [switch]$AsChartData
    )

    # Load history file
    try {
        $content = Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse history file: $_"
        return
    }

    # Extract entries
    $entries = if ($content.Entries) {
        @($content.Entries)
    } elseif ($content -is [array]) {
        @($content)
    } else {
        Write-Warning "No history entries found in file"
        return @()
    }

    # Filter by date if specified
    if ($Since) {
        $entries = $entries | Where-Object {
            $entryDate = if ($_.Date) { [datetime]::Parse($_.Date) } elseif ($_.Timestamp) { [datetime]::Parse($_.Timestamp) } else { $null }
            $entryDate -and $entryDate -ge $Since
        }
    }

    # Limit to last N entries
    if ($Last -and $Last -gt 0) {
        $entries = $entries | Select-Object -Last $Last
    }

    # Return simplified format for charts if requested
    if ($AsChartData) {
        return $entries | ForEach-Object {
            [PSCustomObject]@{
                Date  = $_.Date
                Score = $_.Score
            }
        }
    }

    return $entries
}

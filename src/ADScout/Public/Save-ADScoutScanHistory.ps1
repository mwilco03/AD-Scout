function Save-ADScoutScanHistory {
    <#
    .SYNOPSIS
        Saves scan results to a history file for trend tracking over time.

    .DESCRIPTION
        Appends scan summary data (date, score, finding counts) to a JSON history file.
        This history can be used with Export-ADScoutReport -TrendHistory to visualize
        security posture changes over time.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan.

    .PARAMETER Path
        Path to the history JSON file. Creates if it doesn't exist.

    .PARAMETER MaxEntries
        Maximum number of history entries to retain. Oldest entries are removed
        when this limit is exceeded. Default is 100.

    .PARAMETER Label
        Optional label for this scan entry (e.g., "Post-remediation", "Weekly scan").

    .EXAMPLE
        Invoke-ADScoutScan | Save-ADScoutScanHistory -Path ./scan-history.json
        Saves current scan summary to history file.

    .EXAMPLE
        $results = Invoke-ADScoutScan
        Save-ADScoutScanHistory -Results $results -Path ./history.json -Label "Monthly scan"
        Saves with a custom label.

    .EXAMPLE
        # Full workflow: scan, save history, export with trend
        $results = Invoke-ADScoutScan
        $results | Save-ADScoutScanHistory -Path ./history.json
        $history = Get-ADScoutScanHistory -Path ./history.json
        $results | Export-ADScoutReport -Format HTML -Path ./report.html -TrendHistory $history

    .OUTPUTS
        PSCustomObject representing the saved history entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [int]$MaxEntries = 100,

        [Parameter()]
        [string]$Label
    )

    begin {
        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        if (-not $allResults) {
            Write-Warning "No results to save"
            return
        }

        # Calculate summary statistics
        $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
        if ($null -eq $totalScore) { $totalScore = 0 }
        $totalFindings = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
        if ($null -eq $totalFindings) { $totalFindings = 0 }

        # Count by severity
        $criticalCount = @($allResults | Where-Object { $_.Score -ge 50 }).Count
        $highCount = @($allResults | Where-Object { $_.Score -ge 30 -and $_.Score -lt 50 }).Count
        $mediumCount = @($allResults | Where-Object { $_.Score -ge 15 -and $_.Score -lt 30 }).Count
        $lowCount = @($allResults | Where-Object { $_.Score -ge 5 -and $_.Score -lt 15 }).Count
        $infoCount = @($allResults | Where-Object { $_.Score -lt 5 }).Count

        # Create history entry
        $entry = [PSCustomObject]@{
            Date           = (Get-Date).ToString('yyyy-MM-dd')
            Timestamp      = (Get-Date).ToUniversalTime().ToString('o')
            Score          = $totalScore
            FindingCount   = $totalFindings
            RuleCount      = $allResults.Count
            Critical       = $criticalCount
            High           = $highCount
            Medium         = $mediumCount
            Low            = $lowCount
            Info           = $infoCount
            Label          = $Label
            Domain         = try { (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot } catch { $env:USERDNSDOMAIN }
        }

        # Load existing history or create new
        $history = @()
        if (Test-Path $Path) {
            try {
                $existing = Get-Content -Path $Path -Raw | ConvertFrom-Json
                if ($existing -is [array]) {
                    $history = @($existing)
                } elseif ($existing.Entries) {
                    $history = @($existing.Entries)
                }
            } catch {
                Write-Warning "Could not parse existing history file. Starting fresh."
            }
        }

        # Add new entry
        $history += $entry

        # Trim to max entries (keep most recent)
        if ($history.Count -gt $MaxEntries) {
            $history = $history | Select-Object -Last $MaxEntries
        }

        # Save history file
        $historyFile = [PSCustomObject]@{
            Version     = '1.0'
            LastUpdated = (Get-Date).ToUniversalTime().ToString('o')
            EntryCount  = $history.Count
            Entries     = $history
        }

        $historyFile | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8

        Write-Verbose "Saved scan history to: $Path (Total entries: $($history.Count))"
        Write-Host "Scan history saved: $Path" -ForegroundColor Green

        return $entry
    }
}

function Get-ScanProgress {
    <#
    .SYNOPSIS
        Tracks and reports scan progress.

    .DESCRIPTION
        Maintains state for scan progress and provides formatted progress updates.
        Used by Invoke-ADScoutScan to display progress to users.

    .PARAMETER Action
        The action to perform: Start, Update, Complete, Get.

    .PARAMETER TotalRules
        Total number of rules being evaluated.

    .PARAMETER CurrentRule
        Current rule being processed.

    .PARAMETER Category
        Current category being scanned.

    .OUTPUTS
        Progress information hashtable when Action is 'Get'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Start', 'Update', 'Complete', 'Get')]
        [string]$Action,

        [Parameter()]
        [int]$TotalRules,

        [Parameter()]
        [int]$CurrentRule,

        [Parameter()]
        [string]$Category,

        [Parameter()]
        [string]$RuleId
    )

    # Script-scoped progress state
    if (-not $script:ScanProgress) {
        $script:ScanProgress = @{
            StartTime     = $null
            TotalRules    = 0
            ProcessedRules = 0
            CurrentCategory = ''
            CurrentRule   = ''
            FindingsCount = 0
            Errors        = 0
        }
    }

    switch ($Action) {
        'Start' {
            $script:ScanProgress = @{
                StartTime      = [datetime]::UtcNow
                TotalRules     = $TotalRules
                ProcessedRules = 0
                CurrentCategory = ''
                CurrentRule    = ''
                FindingsCount  = 0
                Errors         = 0
            }

            Write-Progress -Activity "AD-Scout Security Scan" -Status "Initializing..." -PercentComplete 0
        }

        'Update' {
            $script:ScanProgress.ProcessedRules = $CurrentRule
            $script:ScanProgress.CurrentCategory = $Category
            $script:ScanProgress.CurrentRule = $RuleId

            $percentComplete = if ($script:ScanProgress.TotalRules -gt 0) {
                [Math]::Round(($CurrentRule / $script:ScanProgress.TotalRules) * 100)
            } else { 0 }

            $elapsed = [datetime]::UtcNow - $script:ScanProgress.StartTime
            $status = "[$Category] $RuleId ($CurrentRule of $($script:ScanProgress.TotalRules))"

            Write-Progress -Activity "AD-Scout Security Scan" `
                          -Status $status `
                          -PercentComplete $percentComplete `
                          -SecondsRemaining (Get-EstimatedTimeRemaining -Elapsed $elapsed -PercentComplete $percentComplete)
        }

        'Complete' {
            $script:ScanProgress.EndTime = [datetime]::UtcNow
            $elapsed = $script:ScanProgress.EndTime - $script:ScanProgress.StartTime

            Write-Progress -Activity "AD-Scout Security Scan" -Completed

            Write-ADScoutLog -Message "Scan complete. Processed $($script:ScanProgress.ProcessedRules) rules in $($elapsed.TotalSeconds.ToString('F1'))s" -Level Info
        }

        'Get' {
            return $script:ScanProgress.Clone()
        }
    }
}

function Get-EstimatedTimeRemaining {
    param(
        [TimeSpan]$Elapsed,
        [int]$PercentComplete
    )

    if ($PercentComplete -le 0) { return -1 }

    $totalEstimated = $Elapsed.TotalSeconds * (100 / $PercentComplete)
    $remaining = $totalEstimated - $Elapsed.TotalSeconds

    return [Math]::Max(0, [int]$remaining)
}

function Resume-ADScoutRemediation {
    <#
    .SYNOPSIS
        Resumes a failed or partially completed remediation batch.

    .DESCRIPTION
        Continues remediation from where a previous batch stopped, allowing
        you to retry failed items or continue after an interruption.
        Maintains the original batch ID for audit continuity.

    .PARAMETER BatchId
        The batch ID to resume.

    .PARAMETER RetryFailed
        Retry only the failed remediations.

    .PARAMETER RetrySkipped
        Retry skipped remediations (those declined during confirmation).

    .PARAMETER RollbackPath
        Path where rollback data is stored.

    .PARAMETER Force
        Skip confirmation prompts.

    .EXAMPLE
        Resume-ADScoutRemediation -BatchId "abc12345" -RetryFailed
        Retries all failed remediations from the batch.

    .EXAMPLE
        Resume-ADScoutRemediation -BatchId "abc12345"
        Continues from where the batch stopped.

    .OUTPUTS
        ADScoutRemediationBatchResult
        Updated batch result with resumed remediations.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$BatchId,

        [Parameter()]
        [switch]$RetryFailed,

        [Parameter()]
        [switch]$RetrySkipped,

        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$EnableRollback = $true,

        [Parameter()]
        [switch]$PassThru
    )

    # Load original batch manifest
    $manifestPath = Join-Path $RollbackPath "$BatchId`_manifest.json"
    if (-not (Test-Path $manifestPath)) {
        throw "Batch manifest not found: $BatchId. Cannot resume."
    }

    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json -AsHashtable

    Write-Host "`n=== Resuming Remediation Batch: $BatchId ===" -ForegroundColor Cyan
    Write-Host "Original execution: $($manifest.StartTime)"
    Write-Host "Original status: $($manifest.Status)"

    # Determine which remediations to retry
    $toRetry = @()

    if ($RetryFailed) {
        $toRetry = $manifest.Remediations | Where-Object { $_.Status -eq 'Failed' }
        Write-Host "Failed remediations to retry: $($toRetry.Count)" -ForegroundColor Yellow
    }
    elseif ($RetrySkipped) {
        $toRetry = $manifest.Remediations | Where-Object { $_.Status -eq 'Skipped' }
        Write-Host "Skipped remediations to retry: $($toRetry.Count)" -ForegroundColor Yellow
    }
    else {
        # Continue from pending (not started) items
        $toRetry = $manifest.Remediations | Where-Object { $_.Status -eq 'Pending' }
        if ($toRetry.Count -eq 0) {
            # If no pending, offer to retry failed
            $toRetry = $manifest.Remediations | Where-Object { $_.Status -eq 'Failed' }
        }
        Write-Host "Remediations to process: $($toRetry.Count)"
    }

    if ($toRetry.Count -eq 0) {
        Write-Host "`nNo remediations to retry." -ForegroundColor Green
        return
    }

    # Show what will be retried
    Write-Host "`nRemediations to retry:" -ForegroundColor Cyan
    foreach ($item in $toRetry) {
        $target = if ($item.Finding) { Get-RemediationTargetIdentity -Finding ([PSCustomObject]$item.Finding) } else { 'Unknown' }
        $statusColor = switch ($item.Status) {
            'Failed' { 'Red' }
            'Skipped' { 'Yellow' }
            default { 'Gray' }
        }
        Write-Host "  • $($item.RuleId): $target [$($item.Status)]" -ForegroundColor $statusColor
    }

    if (-not $Force -and -not $PSCmdlet.ShouldProcess("$($toRetry.Count) remediations", "Resume batch $BatchId")) {
        return
    }

    # Process retries
    $resumeResults = @()
    $resumeStartTime = Get-Date

    foreach ($item in $toRetry) {
        $rule = Get-ADScoutRule -Id $item.RuleId

        if (-not $rule -or -not $rule.Remediation) {
            Write-Warning "No remediation available for rule: $($item.RuleId)"
            continue
        }

        $finding = [PSCustomObject]$item.Finding
        $remediationId = $item.RemediationId
        $targetIdentity = Get-RemediationTargetIdentity -Finding $finding

        $result = @{
            RemediationId = $remediationId
            RuleId        = $item.RuleId
            RuleName      = $item.RuleName
            Finding       = $finding
            StartTime     = Get-Date
            Status        = 'Pending'
            PreviousStatus = $item.Status
            PreviousError = $item.Error
            RetryAttempt  = ($item.RetryCount ?? 0) + 1
        }

        try {
            # Generate remediation script
            $remediationScript = & $rule.Remediation -Finding $finding
            $result.Script = $remediationScript

            if ($PSCmdlet.ShouldProcess($targetIdentity, "Retry remediation for $($item.RuleName)")) {
                # Capture new rollback state if enabled
                if ($EnableRollback) {
                    $rollbackData = Get-RemediationRollbackState -Finding $finding -Rule $rule
                    $result.RollbackData = $rollbackData

                    $rollbackFile = Join-Path $RollbackPath "$BatchId`_$remediationId`_retry.json"
                    $rollbackData | ConvertTo-Json -Depth 10 | Set-Content -Path $rollbackFile -Encoding UTF8
                }

                # Execute
                $output = Invoke-RemediationScript -Script $remediationScript -Finding $finding
                $result.Status = 'Completed'
                $result.Output = $output
                $result.EndTime = Get-Date

                Write-Host "  ✓ $targetIdentity" -ForegroundColor Green
            }
            else {
                $result.Status = 'Skipped'
            }
        }
        catch {
            $result.Status = 'Failed'
            $result.Error = $_.Exception.Message
            $result.EndTime = Get-Date

            Write-Host "  ✗ $targetIdentity - $_" -ForegroundColor Red
        }

        $resumeResults += [PSCustomObject]$result
    }

    # Update manifest with retry results
    foreach ($result in $resumeResults) {
        $originalIdx = [Array]::FindIndex($manifest.Remediations, [Predicate[object]]{ param($r) $r.RemediationId -eq $result.RemediationId })
        if ($originalIdx -ge 0) {
            $manifest.Remediations[$originalIdx].Status = $result.Status
            $manifest.Remediations[$originalIdx].Error = $result.Error
            $manifest.Remediations[$originalIdx].RetryCount = $result.RetryAttempt
            $manifest.Remediations[$originalIdx].LastRetryTime = $result.StartTime
        }
    }

    # Update overall batch status
    $allStatuses = $manifest.Remediations | ForEach-Object { $_.Status }
    $manifest.Status = if ($allStatuses -contains 'Failed') {
        'PartialFailure'
    }
    elseif ($allStatuses -contains 'Pending') {
        'InProgress'
    }
    else {
        'Completed'
    }

    $manifest.LastResumed = Get-Date -Format 'o'

    # Save updated manifest
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8

    # Summary
    $summary = @{
        BatchId       = $BatchId
        Retried       = $resumeResults.Count
        Completed     = ($resumeResults | Where-Object Status -eq 'Completed').Count
        Failed        = ($resumeResults | Where-Object Status -eq 'Failed').Count
        Skipped       = ($resumeResults | Where-Object Status -eq 'Skipped').Count
        Duration      = (Get-Date) - $resumeStartTime
        OverallStatus = $manifest.Status
    }

    Write-Host "`n=== Resume Summary ===" -ForegroundColor Cyan
    Write-Host "Retried:    $($summary.Retried)"
    Write-Host "Completed:  $($summary.Completed)" -ForegroundColor Green
    Write-Host "Failed:     $($summary.Failed)" -ForegroundColor $(if ($summary.Failed -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Duration:   $($summary.Duration.ToString('mm\:ss'))"
    Write-Host "Batch Status: $($summary.OverallStatus)"

    if ($PassThru) {
        [PSCustomObject]@{
            PSTypeName   = 'ADScoutRemediationResumeResult'
            BatchId      = $BatchId
            Summary      = [PSCustomObject]$summary
            Retried      = $resumeResults
            OriginalManifest = $manifest
        }
    }
}

function Get-ADScoutRemediationQueue {
    <#
    .SYNOPSIS
        Gets pending remediations that need attention.

    .DESCRIPTION
        Lists all batches with failed or pending remediations,
        helping identify what needs to be resumed or investigated.

    .PARAMETER RollbackPath
        Path where rollback data is stored.

    .PARAMETER Status
        Filter by remediation status.

    .EXAMPLE
        Get-ADScoutRemediationQueue -Status Failed
        Shows all batches with failed remediations.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [ValidateSet('Failed', 'Pending', 'Skipped', 'All')]
        [string]$Status = 'All'
    )

    if (-not (Test-Path $RollbackPath)) {
        Write-Warning "No rollback data found."
        return
    }

    $manifests = Get-ChildItem -Path $RollbackPath -Filter "*_manifest.json"

    foreach ($file in $manifests) {
        $manifest = Get-Content $file.FullName -Raw | ConvertFrom-Json

        $statusFilter = switch ($Status) {
            'All' { @('Failed', 'Pending', 'Skipped') }
            default { @($Status) }
        }

        $matchingRemediations = $manifest.Remediations | Where-Object { $_.Status -in $statusFilter }

        if ($matchingRemediations.Count -gt 0) {
            [PSCustomObject]@{
                PSTypeName    = 'ADScoutRemediationQueueItem'
                BatchId       = $manifest.BatchId
                ExecutedAt    = $manifest.StartTime
                BatchStatus   = $manifest.Status
                ChangeTicket  = $manifest.ChangeTicket
                TotalCount    = $manifest.Remediations.Count
                FailedCount   = ($manifest.Remediations | Where-Object Status -eq 'Failed').Count
                PendingCount  = ($manifest.Remediations | Where-Object Status -eq 'Pending').Count
                SkippedCount  = ($manifest.Remediations | Where-Object Status -eq 'Skipped').Count
                NeedsAttention = $matchingRemediations.Count
            }
        }
    }
}

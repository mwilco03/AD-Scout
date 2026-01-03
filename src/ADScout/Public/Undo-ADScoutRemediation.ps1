function Undo-ADScoutRemediation {
    <#
    .SYNOPSIS
        Rolls back remediation changes using captured state data.

    .DESCRIPTION
        Reverts Active Directory objects to their pre-remediation state using
        the rollback data captured during Invoke-ADScoutRemediation execution.
        Supports rolling back individual remediations or entire batches.

    .PARAMETER BatchId
        The batch ID to rollback. Rolls back all remediations in the batch.

    .PARAMETER RemediationId
        A specific remediation ID to rollback.

    .PARAMETER RollbackPath
        Path where rollback data is stored. Defaults to $env:TEMP\ADScout\Rollback.

    .PARAMETER Force
        Skip confirmation prompts and force rollback.

    .EXAMPLE
        Undo-ADScoutRemediation -BatchId "abc12345"
        Rolls back all remediations in the specified batch.

    .EXAMPLE
        Undo-ADScoutRemediation -RemediationId "xyz98765" -Force
        Forces rollback of a specific remediation without confirmation.

    .EXAMPLE
        Get-ADScoutRemediationHistory | Where-Object Status -eq 'Completed' | Undo-ADScoutRemediation
        Interactively rollback completed remediations.

    .OUTPUTS
        ADScoutRollbackResult
        Details of the rollback operation.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(ParameterSetName = 'ByBatch', Mandatory)]
        [string]$BatchId,

        [Parameter(ParameterSetName = 'ByRemediation', Mandatory)]
        [string]$RemediationId,

        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [switch]$Force
    )

    begin {
        if (-not (Test-Path $RollbackPath)) {
            throw "Rollback path not found: $RollbackPath. No rollback data available."
        }

        $rollbackResults = @()
    }

    process {
        $rollbackFiles = @()

        switch ($PSCmdlet.ParameterSetName) {
            'ByBatch' {
                # Load batch manifest
                $manifestFile = Join-Path $RollbackPath "$BatchId`_manifest.json"
                if (-not (Test-Path $manifestFile)) {
                    throw "Batch manifest not found: $BatchId"
                }

                $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json

                Write-Host "`n=== Rollback Batch: $BatchId ===" -ForegroundColor Yellow
                Write-Host "Original execution: $($manifest.StartTime)"
                Write-Host "Remediations to rollback: $($manifest.Remediations.Count)"
                if ($manifest.ChangeTicket) {
                    Write-Host "Change Ticket: $($manifest.ChangeTicket)"
                }
                Write-Host ""

                # Get all rollback files for this batch
                $rollbackFiles = Get-ChildItem -Path $RollbackPath -Filter "$BatchId`_*.json" |
                    Where-Object { $_.Name -ne "$BatchId`_manifest.json" }
            }
            'ByRemediation' {
                # Find the specific remediation file
                $rollbackFiles = Get-ChildItem -Path $RollbackPath -Filter "*_$RemediationId.json"
                if ($rollbackFiles.Count -eq 0) {
                    throw "Remediation rollback data not found: $RemediationId"
                }
            }
        }

        foreach ($file in $rollbackFiles) {
            $rollbackData = Get-Content $file.FullName -Raw | ConvertFrom-Json

            $result = @{
                RemediationId = $file.BaseName -replace '^[^_]+_', ''
                RuleId        = $rollbackData.RuleId
                Identity      = $rollbackData.Identity
                Status        = 'Pending'
                Message       = $null
            }

            $targetDescription = if ($rollbackData.Identity) { $rollbackData.Identity } else { "Object from $($rollbackData.RuleId)" }

            if ($Force -or $PSCmdlet.ShouldProcess($targetDescription, "Rollback to pre-remediation state")) {
                try {
                    $rollbackResult = Invoke-ObjectRollback -RollbackData $rollbackData
                    $result.Status = 'Completed'
                    $result.Message = "Successfully rolled back to state from $($rollbackData.CapturedAt)"

                    Write-Host "✓ Rolled back: $targetDescription" -ForegroundColor Green
                }
                catch {
                    $result.Status = 'Failed'
                    $result.Message = $_.Exception.Message

                    Write-Host "✗ Failed to rollback: $targetDescription - $_" -ForegroundColor Red
                }
            }
            else {
                $result.Status = 'Skipped'
                $result.Message = 'User declined rollback'
            }

            $rollbackResults += [PSCustomObject]$result
        }
    }

    end {
        # Summary
        Write-Host "`n=== Rollback Summary ===" -ForegroundColor Cyan
        Write-Host "Total:     $($rollbackResults.Count)"
        Write-Host "Completed: $(($rollbackResults | Where-Object Status -eq 'Completed').Count)" -ForegroundColor Green
        Write-Host "Skipped:   $(($rollbackResults | Where-Object Status -eq 'Skipped').Count)" -ForegroundColor Yellow
        Write-Host "Failed:    $(($rollbackResults | Where-Object Status -eq 'Failed').Count)" -ForegroundColor Red

        # Return results
        [PSCustomObject]@{
            PSTypeName = 'ADScoutRollbackResult'
            BatchId    = $BatchId
            Results    = $rollbackResults
            Timestamp  = Get-Date
        }
    }
}

function Invoke-ObjectRollback {
    <#
    .SYNOPSIS
        Performs the actual rollback of an AD object to its captured state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$RollbackData
    )

    if (-not $RollbackData.State) {
        throw "No state data available for rollback"
    }

    $state = $RollbackData.State

    switch ($RollbackData.ObjectType) {
        'user' {
            $setParams = @{
                Identity = $RollbackData.Identity
            }

            # Restore user properties
            if ($null -ne $state.Enabled) {
                if ($state.Enabled) {
                    Enable-ADAccount -Identity $RollbackData.Identity
                }
                else {
                    Disable-ADAccount -Identity $RollbackData.Identity
                }
            }

            if ($null -ne $state.PasswordNeverExpires) {
                $setParams['PasswordNeverExpires'] = $state.PasswordNeverExpires
            }

            if ($null -ne $state.PasswordNotRequired) {
                $setParams['PasswordNotRequired'] = $state.PasswordNotRequired
            }

            if ($null -ne $state.CannotChangePassword) {
                $setParams['CannotChangePassword'] = $state.CannotChangePassword
            }

            if ($null -ne $state.AccountExpirationDate) {
                $setParams['AccountExpirationDate'] = $state.AccountExpirationDate
            }

            if ($null -ne $state.Description) {
                $setParams['Description'] = $state.Description
            }

            if ($setParams.Count -gt 1) {
                Set-ADUser @setParams
            }

            # Restore group memberships
            if ($state.MemberOf) {
                $currentMemberships = (Get-ADUser -Identity $RollbackData.Identity -Properties MemberOf).MemberOf
                $originalMemberships = $state.MemberOf

                # Add back removed memberships
                foreach ($group in $originalMemberships) {
                    if ($group -notin $currentMemberships) {
                        Add-ADGroupMember -Identity $group -Members $RollbackData.Identity
                    }
                }

                # Note: We don't remove new memberships as that could be dangerous
            }
        }

        'computer' {
            $setParams = @{
                Identity = $RollbackData.Identity
            }

            if ($null -ne $state.Enabled) {
                if ($state.Enabled) {
                    Enable-ADAccount -Identity $RollbackData.Identity
                }
                else {
                    Disable-ADAccount -Identity $RollbackData.Identity
                }
            }

            if ($null -ne $state.Description) {
                $setParams['Description'] = $state.Description
            }

            if ($setParams.Count -gt 1) {
                Set-ADComputer @setParams
            }
        }

        'group' {
            if ($state.Members) {
                $currentMembers = Get-ADGroupMember -Identity $RollbackData.Identity |
                    Select-Object -ExpandProperty DistinguishedName
                $originalMembers = $state.Members

                # Restore removed members
                foreach ($member in $originalMembers) {
                    if ($member -notin $currentMembers) {
                        Add-ADGroupMember -Identity $RollbackData.Identity -Members $member
                    }
                }
            }

            if ($null -ne $state.Description) {
                Set-ADGroup -Identity $RollbackData.Identity -Description $state.Description
            }
        }

        default {
            throw "Unsupported object type for rollback: $($RollbackData.ObjectType)"
        }
    }

    return @{
        Success     = $true
        RestoredTo  = $RollbackData.CapturedAt
        ObjectType  = $RollbackData.ObjectType
        Identity    = $RollbackData.Identity
    }
}

function Get-ADScoutRemediationHistory {
    <#
    .SYNOPSIS
        Retrieves remediation history from stored batch manifests.

    .DESCRIPTION
        Lists all remediation batches that have been executed with rollback enabled,
        allowing review of past remediations and their status.

    .PARAMETER RollbackPath
        Path where rollback data is stored.

    .PARAMETER BatchId
        Filter to a specific batch ID.

    .PARAMETER Last
        Return only the last N batches.

    .EXAMPLE
        Get-ADScoutRemediationHistory
        Lists all remediation batches.

    .EXAMPLE
        Get-ADScoutRemediationHistory -Last 5
        Gets the 5 most recent remediation batches.

    .OUTPUTS
        ADScoutRemediationBatch
        Remediation batch history objects.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [string]$BatchId,

        [Parameter()]
        [int]$Last
    )

    if (-not (Test-Path $RollbackPath)) {
        Write-Warning "No rollback data found at: $RollbackPath"
        return
    }

    $manifests = Get-ChildItem -Path $RollbackPath -Filter "*_manifest.json" |
        Sort-Object LastWriteTime -Descending

    if ($BatchId) {
        $manifests = $manifests | Where-Object { $_.Name -like "$BatchId*" }
    }

    if ($Last) {
        $manifests = $manifests | Select-Object -First $Last
    }

    foreach ($manifestFile in $manifests) {
        $manifest = Get-Content $manifestFile.FullName -Raw | ConvertFrom-Json

        [PSCustomObject]@{
            PSTypeName       = 'ADScoutRemediationBatch'
            BatchId          = $manifest.BatchId
            StartTime        = [datetime]$manifest.StartTime
            EndTime          = if ($manifest.EndTime) { [datetime]$manifest.EndTime } else { $null }
            Status           = $manifest.Status
            ChangeTicket     = $manifest.ChangeTicket
            RemediationCount = $manifest.Remediations.Count
            WasSimulation    = $manifest.WhatIf
            ManifestPath     = $manifestFile.FullName
        }
    }
}

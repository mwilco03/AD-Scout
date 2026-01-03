function Get-ADScoutRollbackPolicy {
    <#
    .SYNOPSIS
        Gets the current rollback data retention policy.
    #>
    [CmdletBinding()]
    param()

    $configPath = Join-Path $env:USERPROFILE '.adscout\rollback-policy.json'

    if (Test-Path $configPath) {
        Get-Content $configPath -Raw | ConvertFrom-Json
    }
    else {
        # Default policy
        [PSCustomObject]@{
            RetentionDays       = 30
            MaxBatches          = 100
            MaxSizeMB           = 500
            ArchivePath         = $null
            EncryptArchive      = $false
            AutoCleanup         = $true
            CleanupSchedule     = 'Daily'
        }
    }
}

function Set-ADScoutRollbackPolicy {
    <#
    .SYNOPSIS
        Sets the rollback data retention policy.

    .DESCRIPTION
        Configures how long rollback data is retained, maximum storage limits,
        and archive settings for compliance.

    .PARAMETER RetentionDays
        Number of days to retain rollback data. Default is 30.

    .PARAMETER MaxBatches
        Maximum number of batch manifests to keep. Default is 100.

    .PARAMETER MaxSizeMB
        Maximum total size of rollback data in MB. Default is 500.

    .PARAMETER ArchivePath
        Network path to archive old rollback data for compliance.

    .PARAMETER EncryptArchive
        Encrypt archived rollback data.

    .PARAMETER AutoCleanup
        Enable automatic cleanup based on policy. Default is true.

    .EXAMPLE
        Set-ADScoutRollbackPolicy -RetentionDays 90 -ArchivePath "\\server\compliance\adscout"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$RetentionDays = 30,

        [Parameter()]
        [ValidateRange(10, 1000)]
        [int]$MaxBatches = 100,

        [Parameter()]
        [ValidateRange(100, 10000)]
        [int]$MaxSizeMB = 500,

        [Parameter()]
        [string]$ArchivePath,

        [Parameter()]
        [switch]$EncryptArchive,

        [Parameter()]
        [switch]$AutoCleanup = $true
    )

    $configDir = Join-Path $env:USERPROFILE '.adscout'
    if (-not (Test-Path $configDir)) {
        $null = New-Item -ItemType Directory -Path $configDir -Force
    }

    $policy = [PSCustomObject]@{
        RetentionDays   = $RetentionDays
        MaxBatches      = $MaxBatches
        MaxSizeMB       = $MaxSizeMB
        ArchivePath     = $ArchivePath
        EncryptArchive  = [bool]$EncryptArchive
        AutoCleanup     = [bool]$AutoCleanup
        LastUpdated     = Get-Date -Format 'o'
    }

    $configPath = Join-Path $configDir 'rollback-policy.json'
    $policy | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

    Write-Host "✓ Rollback policy updated" -ForegroundColor Green
    $policy
}

function Invoke-ADScoutRollbackCleanup {
    <#
    .SYNOPSIS
        Cleans up old rollback data based on retention policy.

    .DESCRIPTION
        Removes rollback data older than the retention period,
        enforces batch count limits, and optionally archives data.

    .PARAMETER RollbackPath
        Path to the rollback data directory.

    .PARAMETER Force
        Skip confirmation prompts.

    .PARAMETER ArchiveOnly
        Only archive, don't delete.

    .PARAMETER WhatIf
        Show what would be cleaned up without making changes.

    .EXAMPLE
        Invoke-ADScoutRollbackCleanup -WhatIf
        Shows what would be cleaned up.

    .EXAMPLE
        Invoke-ADScoutRollbackCleanup -Force
        Cleans up data without prompts.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$RollbackPath = (Join-Path $env:TEMP 'ADScout\Rollback'),

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$ArchiveOnly
    )

    if (-not (Test-Path $RollbackPath)) {
        Write-Host "No rollback data found at: $RollbackPath" -ForegroundColor Yellow
        return
    }

    $policy = Get-ADScoutRollbackPolicy
    $cutoffDate = (Get-Date).AddDays(-$policy.RetentionDays)

    # Get all manifest files
    $manifests = Get-ChildItem -Path $RollbackPath -Filter "*_manifest.json" |
        Sort-Object LastWriteTime -Descending

    $toArchive = @()
    $toDelete = @()

    # Identify files to archive/delete
    foreach ($manifest in $manifests) {
        $batchId = $manifest.BaseName -replace '_manifest$', ''

        if ($manifest.LastWriteTime -lt $cutoffDate) {
            $batchFiles = Get-ChildItem -Path $RollbackPath -Filter "$batchId*"
            $toDelete += $batchFiles

            if ($policy.ArchivePath) {
                $toArchive += $batchFiles
            }
        }
    }

    # Enforce max batch count
    if ($manifests.Count -gt $policy.MaxBatches) {
        $excessCount = $manifests.Count - $policy.MaxBatches
        $excessManifests = $manifests | Select-Object -Last $excessCount

        foreach ($manifest in $excessManifests) {
            $batchId = $manifest.BaseName -replace '_manifest$', ''
            $batchFiles = Get-ChildItem -Path $RollbackPath -Filter "$batchId*"

            foreach ($file in $batchFiles) {
                if ($file.FullName -notin $toDelete.FullName) {
                    $toDelete += $file
                    if ($policy.ArchivePath) {
                        $toArchive += $file
                    }
                }
            }
        }
    }

    # Enforce size limit
    $currentSize = (Get-ChildItem -Path $RollbackPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    if ($currentSize -gt $policy.MaxSizeMB) {
        Write-Host "Rollback storage ($([math]::Round($currentSize, 2)) MB) exceeds limit ($($policy.MaxSizeMB) MB)" -ForegroundColor Yellow
    }

    # Summary
    Write-Host "`n=== Rollback Cleanup Summary ===" -ForegroundColor Cyan
    Write-Host "Policy: Retain $($policy.RetentionDays) days, max $($policy.MaxBatches) batches"
    Write-Host "Current batches: $($manifests.Count)"
    Write-Host "Files to process: $($toDelete.Count)"

    if ($toArchive.Count -gt 0 -and $policy.ArchivePath) {
        Write-Host "Archive destination: $($policy.ArchivePath)"
    }

    if ($toDelete.Count -eq 0) {
        Write-Host "`nNo cleanup needed." -ForegroundColor Green
        return
    }

    # Archive if configured
    if ($toArchive.Count -gt 0 -and $policy.ArchivePath) {
        $archiveDate = Get-Date -Format 'yyyyMMdd-HHmmss'
        $archiveDir = Join-Path $policy.ArchivePath "ADScout-Rollback-$archiveDate"

        if ($PSCmdlet.ShouldProcess($archiveDir, "Archive $($toArchive.Count) files")) {
            if (-not (Test-Path $archiveDir)) {
                $null = New-Item -ItemType Directory -Path $archiveDir -Force
            }

            foreach ($file in $toArchive) {
                $destPath = Join-Path $archiveDir $file.Name

                if ($policy.EncryptArchive) {
                    # Encrypt using DPAPI
                    $content = Get-Content $file.FullName -Raw
                    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
                        [System.Text.Encoding]::UTF8.GetBytes($content),
                        $null,
                        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                    )
                    [System.IO.File]::WriteAllBytes("$destPath.encrypted", $encrypted)
                }
                else {
                    Copy-Item -Path $file.FullName -Destination $destPath
                }
            }

            Write-Host "✓ Archived $($toArchive.Count) files to $archiveDir" -ForegroundColor Green
        }
    }

    # Delete if not archive-only
    if (-not $ArchiveOnly) {
        if ($Force -or $PSCmdlet.ShouldProcess("$($toDelete.Count) files", "Delete old rollback data")) {
            foreach ($file in $toDelete) {
                Remove-Item -Path $file.FullName -Force
            }

            Write-Host "✓ Deleted $($toDelete.Count) old rollback files" -ForegroundColor Green
        }
    }

    # Return summary
    [PSCustomObject]@{
        ProcessedFiles = $toDelete.Count
        ArchivedFiles  = $toArchive.Count
        ArchivePath    = if ($policy.ArchivePath) { $archiveDir } else { $null }
        SpaceFreedMB   = [math]::Round(($toDelete | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    }
}

function Protect-RollbackData {
    <#
    .SYNOPSIS
        Encrypts sensitive rollback data at rest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [switch]$Decrypt
    )

    Add-Type -AssemblyName System.Security

    if ($Decrypt) {
        $encrypted = [System.IO.File]::ReadAllBytes($FilePath)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    else {
        $content = Get-Content $FilePath -Raw
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::UTF8.GetBytes($content),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $encryptedPath = "$FilePath.encrypted"
        [System.IO.File]::WriteAllBytes($encryptedPath, $encrypted)
        Remove-Item $FilePath -Force
        return $encryptedPath
    }
}

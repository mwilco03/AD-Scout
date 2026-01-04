function New-ADScoutException {
    <#
    .SYNOPSIS
        Creates an exception to suppress a specific AD-Scout finding.

    .DESCRIPTION
        Creates an exception rule that suppresses findings matching specific criteria.
        Exceptions include audit trails, expiration dates, and approval workflows.

        Exception types:
        - RuleException: Suppress all findings for a specific rule
        - ObjectException: Suppress findings for specific AD objects
        - CategoryException: Suppress all findings in a category
        - GlobalException: Suppress based on custom criteria

    .PARAMETER RuleId
        Rule ID to create exception for.

    .PARAMETER ObjectIdentity
        AD object(s) to exempt (SamAccountName, DN, or GUID).

    .PARAMETER Category
        Category to exempt.

    .PARAMETER Justification
        Required explanation for the exception.

    .PARAMETER ApprovedBy
        Name/email of approver.

    .PARAMETER ExpirationDate
        When the exception expires. Defaults to 1 year from now.

    .PARAMETER Scope
        Exception scope: Global, Engagement, or Session.

    .PARAMETER EngagementId
        Engagement ID if scope is Engagement.

    .PARAMETER TicketReference
        Reference to change ticket, risk acceptance, etc.

    .PARAMETER StoragePath
        Path to store exception. Defaults to ~/.adscout/exceptions/

    .EXAMPLE
        New-ADScoutException -RuleId "S-PwdNeverExpires" -ObjectIdentity "svc_backup" -Justification "Service account - managed by CyberArk"

    .EXAMPLE
        New-ADScoutException -RuleId "A-StaleComputers" -Justification "Legacy systems under decommission plan" -ExpirationDate (Get-Date).AddMonths(6) -TicketReference "CHG0012345"

    .EXAMPLE
        New-ADScoutException -Category "DLLRequired" -Justification "Third-party DLLs not available in this environment" -Scope "Global"

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Rule')]
        [string]$RuleId,

        [Parameter()]
        [string[]]$ObjectIdentity,

        [Parameter(ParameterSetName = 'Category')]
        [string]$Category,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Justification,

        [Parameter()]
        [string]$ApprovedBy,

        [Parameter()]
        [datetime]$ExpirationDate,

        [Parameter()]
        [ValidateSet('Global', 'Engagement', 'Session')]
        [string]$Scope = 'Global',

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [string]$TicketReference,

        [Parameter()]
        [string]$StoragePath
    )

    # Validate parameters
    if (-not $RuleId -and -not $Category) {
        throw "Either -RuleId or -Category must be specified"
    }

    if ($Scope -eq 'Engagement' -and -not $EngagementId) {
        throw "-EngagementId is required when Scope is 'Engagement'"
    }

    # Set default expiration (1 year)
    if (-not $ExpirationDate) {
        $ExpirationDate = (Get-Date).AddYears(1)
    }

    # Generate exception ID
    $exceptionId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    # Determine exception type
    $exceptionType = if ($Category) { 'Category' }
                     elseif ($ObjectIdentity) { 'Object' }
                     else { 'Rule' }

    # Build exception object
    $exception = [PSCustomObject]@{
        PSTypeName = 'ADScoutException'
        Id = $exceptionId
        Type = $exceptionType
        RuleId = $RuleId
        Category = $Category
        ObjectIdentity = $ObjectIdentity
        Justification = $Justification
        ApprovedBy = $ApprovedBy
        CreatedAt = (Get-Date)
        CreatedBy = "$env:USERNAME@$env:COMPUTERNAME"
        ExpirationDate = $ExpirationDate
        Scope = $Scope
        EngagementId = $EngagementId
        TicketReference = $TicketReference
        Status = 'Active'
        AuditLog = @(
            @{
                Action = 'Created'
                Timestamp = (Get-Date)
                User = "$env:USERNAME@$env:COMPUTERNAME"
                Details = "Exception created with justification: $Justification"
            }
        )
    }

    # Determine storage path
    if (-not $StoragePath) {
        if ($Scope -eq 'Engagement' -and $EngagementId) {
            $engagement = Get-ADScoutEngagement -Id $EngagementId
            if ($engagement) {
                $StoragePath = Join-Path $engagement.StoragePath 'exceptions'
            }
        }
        if (-not $StoragePath) {
            $StoragePath = Join-Path $HOME '.adscout' 'exceptions'
        }
    }

    # Create directory if needed
    if (-not (Test-Path $StoragePath)) {
        New-Item -Path $StoragePath -ItemType Directory -Force | Out-Null
    }

    # Save exception
    $exceptionPath = Join-Path $StoragePath "$exceptionId.json"
    $exception | ConvertTo-Json -Depth 10 | Out-File -FilePath $exceptionPath -Encoding UTF8

    Write-Host "Exception created: $exceptionId" -ForegroundColor Green
    if ($RuleId) {
        Write-Host "  Rule: $RuleId" -ForegroundColor Cyan
    }
    if ($Category) {
        Write-Host "  Category: $Category" -ForegroundColor Cyan
    }
    if ($ObjectIdentity) {
        Write-Host "  Objects: $($ObjectIdentity -join ', ')" -ForegroundColor Cyan
    }
    Write-Host "  Expires: $($ExpirationDate.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

    return $exception
}

function Get-ADScoutException {
    <#
    .SYNOPSIS
        Retrieves AD-Scout exceptions.

    .PARAMETER Id
        Exception ID to retrieve.

    .PARAMETER RuleId
        Filter by rule ID.

    .PARAMETER Category
        Filter by category.

    .PARAMETER Scope
        Filter by scope.

    .PARAMETER EngagementId
        Filter by engagement ID.

    .PARAMETER IncludeExpired
        Include expired exceptions.

    .PARAMETER StoragePath
        Path to search for exceptions.

    .EXAMPLE
        Get-ADScoutException
        Lists all active global exceptions.

    .EXAMPLE
        Get-ADScoutException -RuleId "S-PwdNeverExpires"

    .EXAMPLE
        Get-ADScoutException -EngagementId "abc123"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Id,

        [Parameter()]
        [string]$RuleId,

        [Parameter()]
        [string]$Category,

        [Parameter()]
        [ValidateSet('Global', 'Engagement', 'Session')]
        [string]$Scope,

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [switch]$IncludeExpired,

        [Parameter()]
        [string]$StoragePath
    )

    $exceptions = @()
    $searchPaths = @()

    # Build search paths
    if ($StoragePath) {
        $searchPaths += $StoragePath
    }
    else {
        # Global exceptions
        $globalPath = Join-Path $HOME '.adscout' 'exceptions'
        if (Test-Path $globalPath) {
            $searchPaths += $globalPath
        }

        # Engagement-specific exceptions
        if ($EngagementId) {
            $engagement = Get-ADScoutEngagement -Id $EngagementId
            if ($engagement) {
                $engPath = Join-Path $engagement.StoragePath 'exceptions'
                if (Test-Path $engPath) {
                    $searchPaths += $engPath
                }
            }
        }
    }

    # Load exceptions from all paths
    foreach ($path in $searchPaths) {
        Get-ChildItem -Path $path -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $exc = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
                $exc.PSObject.TypeNames.Insert(0, 'ADScoutException')
                $exceptions += $exc
            }
            catch {
                Write-Warning "Failed to load exception from $($_.FullName): $_"
            }
        }
    }

    # Apply filters
    if ($Id) {
        $exceptions = $exceptions | Where-Object { $_.Id -eq $Id }
    }
    if ($RuleId) {
        $exceptions = $exceptions | Where-Object { $_.RuleId -eq $RuleId }
    }
    if ($Category) {
        $exceptions = $exceptions | Where-Object { $_.Category -eq $Category }
    }
    if ($Scope) {
        $exceptions = $exceptions | Where-Object { $_.Scope -eq $Scope }
    }
    if ($EngagementId) {
        $exceptions = $exceptions | Where-Object { $_.EngagementId -eq $EngagementId -or $_.Scope -eq 'Global' }
    }

    # Filter expired unless requested
    if (-not $IncludeExpired) {
        $now = Get-Date
        $exceptions = $exceptions | Where-Object {
            $_.Status -eq 'Active' -and ([datetime]$_.ExpirationDate) -gt $now
        }
    }

    return $exceptions
}

function Set-ADScoutException {
    <#
    .SYNOPSIS
        Updates an existing AD-Scout exception.

    .PARAMETER Id
        Exception ID to update.

    .PARAMETER Status
        New status (Active, Revoked, Expired).

    .PARAMETER ExpirationDate
        New expiration date.

    .PARAMETER Justification
        Updated justification.

    .PARAMETER ApprovedBy
        Update approver.

    .PARAMETER TicketReference
        Update ticket reference.

    .PARAMETER Comment
        Comment to add to audit log.

    .EXAMPLE
        Set-ADScoutException -Id "abc123" -Status "Revoked" -Comment "Risk accepted no longer valid"

    .EXAMPLE
        Set-ADScoutException -Id "abc123" -ExpirationDate (Get-Date).AddMonths(6) -Comment "Extended per CHG0054321"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [Parameter()]
        [ValidateSet('Active', 'Revoked', 'Expired')]
        [string]$Status,

        [Parameter()]
        [datetime]$ExpirationDate,

        [Parameter()]
        [string]$Justification,

        [Parameter()]
        [string]$ApprovedBy,

        [Parameter()]
        [string]$TicketReference,

        [Parameter()]
        [string]$Comment
    )

    process {
        # Find the exception
        $exception = Get-ADScoutException -Id $Id -IncludeExpired

        if (-not $exception) {
            Write-Error "Exception not found: $Id"
            return
        }

        $changes = @()

        if ($Status -and $Status -ne $exception.Status) {
            $changes += "Status: $($exception.Status) -> $Status"
            $exception.Status = $Status
        }
        if ($ExpirationDate) {
            $changes += "ExpirationDate: $($exception.ExpirationDate) -> $ExpirationDate"
            $exception.ExpirationDate = $ExpirationDate
        }
        if ($Justification) {
            $changes += "Justification updated"
            $exception.Justification = $Justification
        }
        if ($ApprovedBy) {
            $changes += "ApprovedBy: $($exception.ApprovedBy) -> $ApprovedBy"
            $exception.ApprovedBy = $ApprovedBy
        }
        if ($TicketReference) {
            $changes += "TicketReference: $TicketReference"
            $exception.TicketReference = $TicketReference
        }

        if ($changes.Count -gt 0 -or $Comment) {
            # Add audit log entry
            $auditEntry = @{
                Action = 'Modified'
                Timestamp = (Get-Date)
                User = "$env:USERNAME@$env:COMPUTERNAME"
                Changes = $changes
                Comment = $Comment
            }

            if (-not $exception.AuditLog) {
                $exception | Add-Member -NotePropertyName 'AuditLog' -NotePropertyValue @() -Force
            }
            $exception.AuditLog += $auditEntry

            # Determine storage path and save
            $storagePath = if ($exception.EngagementId) {
                $engagement = Get-ADScoutEngagement -Id $exception.EngagementId
                if ($engagement) {
                    Join-Path $engagement.StoragePath 'exceptions'
                }
            }
            if (-not $storagePath) {
                $storagePath = Join-Path $HOME '.adscout' 'exceptions'
            }

            $exceptionPath = Join-Path $storagePath "$($exception.Id).json"
            $exception | ConvertTo-Json -Depth 10 | Out-File -FilePath $exceptionPath -Encoding UTF8

            Write-Host "Exception updated: $Id" -ForegroundColor Green
            $changes | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
        }

        return $exception
    }
}

function Remove-ADScoutException {
    <#
    .SYNOPSIS
        Removes an AD-Scout exception.

    .PARAMETER Id
        Exception ID to remove.

    .PARAMETER Force
        Skip confirmation.

    .PARAMETER Revoke
        Mark as revoked instead of deleting (preserves audit trail).

    .EXAMPLE
        Remove-ADScoutException -Id "abc123" -Revoke

    .EXAMPLE
        Get-ADScoutException -RuleId "S-Test" | Remove-ADScoutException -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Revoke
    )

    process {
        $exception = Get-ADScoutException -Id $Id -IncludeExpired

        if (-not $exception) {
            Write-Error "Exception not found: $Id"
            return
        }

        if ($Revoke) {
            Set-ADScoutException -Id $Id -Status 'Revoked' -Comment 'Exception revoked'
            Write-Host "Exception revoked: $Id" -ForegroundColor Yellow
            return
        }

        if ($Force -or $PSCmdlet.ShouldProcess($Id, 'Remove exception')) {
            # Find and delete the file
            $storagePath = if ($exception.EngagementId) {
                $engagement = Get-ADScoutEngagement -Id $exception.EngagementId
                if ($engagement) {
                    Join-Path $engagement.StoragePath 'exceptions'
                }
            }
            if (-not $storagePath) {
                $storagePath = Join-Path $HOME '.adscout' 'exceptions'
            }

            $exceptionPath = Join-Path $storagePath "$Id.json"
            if (Test-Path $exceptionPath) {
                Remove-Item -Path $exceptionPath -Force
                Write-Host "Exception removed: $Id" -ForegroundColor Yellow
            }
        }
    }
}

function Test-ADScoutException {
    <#
    .SYNOPSIS
        Tests if a finding matches any active exception.

    .DESCRIPTION
        Checks if a specific finding should be suppressed based on active exceptions.
        Used internally by the scanning engine and can be called manually.

    .PARAMETER Finding
        The finding object to test.

    .PARAMETER RuleId
        Rule ID to test.

    .PARAMETER Category
        Category to test.

    .PARAMETER ObjectIdentity
        Object identity to test.

    .PARAMETER EngagementId
        Engagement context for exception lookup.

    .EXAMPLE
        Test-ADScoutException -RuleId "S-PwdNeverExpires" -ObjectIdentity "svc_backup"

    .OUTPUTS
        $true if an exception matches, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Finding')]
        [PSCustomObject]$Finding,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$RuleId,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$Category,

        [Parameter()]
        [string]$ObjectIdentity,

        [Parameter()]
        [string]$EngagementId
    )

    # Get rule/category from finding if provided
    if ($Finding) {
        $RuleId = $Finding.RuleId
        $Category = $Finding.Category
    }

    # Get all applicable exceptions
    $exceptions = Get-ADScoutException -EngagementId $EngagementId

    foreach ($exc in $exceptions) {
        # Check rule match
        if ($exc.RuleId -and $exc.RuleId -eq $RuleId) {
            # If object-specific, check object match
            if ($exc.ObjectIdentity) {
                if ($ObjectIdentity -and $ObjectIdentity -in $exc.ObjectIdentity) {
                    return $true
                }
            }
            else {
                # Rule-wide exception
                return $true
            }
        }

        # Check category match
        if ($exc.Category -and $exc.Category -eq $Category) {
            return $true
        }
    }

    return $false
}

function Invoke-ADScoutExceptionCleanup {
    <#
    .SYNOPSIS
        Cleans up expired exceptions.

    .DESCRIPTION
        Marks expired exceptions as 'Expired' status and optionally archives them.

    .PARAMETER Archive
        Move expired exceptions to archive folder.

    .PARAMETER Force
        Don't prompt for confirmation.

    .EXAMPLE
        Invoke-ADScoutExceptionCleanup

    .EXAMPLE
        Invoke-ADScoutExceptionCleanup -Archive -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [switch]$Archive,

        [Parameter()]
        [switch]$Force
    )

    $now = Get-Date
    $expired = Get-ADScoutException -IncludeExpired | Where-Object {
        $_.Status -eq 'Active' -and ([datetime]$_.ExpirationDate) -lt $now
    }

    if (-not $expired) {
        Write-Host "No expired exceptions found." -ForegroundColor Green
        return
    }

    Write-Host "Found $($expired.Count) expired exception(s):" -ForegroundColor Yellow
    $expired | ForEach-Object {
        Write-Host "  [$($_.Id)] $($_.RuleId ?? $_.Category) - Expired: $($_.ExpirationDate)" -ForegroundColor Gray
    }

    if ($Force -or $PSCmdlet.ShouldProcess("$($expired.Count) exceptions", 'Mark as expired')) {
        foreach ($exc in $expired) {
            Set-ADScoutException -Id $exc.Id -Status 'Expired' -Comment 'Automatically expired by cleanup'
        }
        Write-Host "Marked $($expired.Count) exception(s) as expired." -ForegroundColor Green
    }
}

function Get-ADScoutExceptionReport {
    <#
    .SYNOPSIS
        Generates a report of all exceptions.

    .PARAMETER EngagementId
        Filter by engagement.

    .PARAMETER Format
        Output format: Table, JSON, HTML.

    .PARAMETER Path
        Output file path for JSON/HTML formats.

    .EXAMPLE
        Get-ADScoutExceptionReport

    .EXAMPLE
        Get-ADScoutExceptionReport -EngagementId "abc123" -Format HTML -Path "./exceptions.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [ValidateSet('Table', 'JSON', 'HTML')]
        [string]$Format = 'Table',

        [Parameter()]
        [string]$Path
    )

    $exceptions = Get-ADScoutException -EngagementId $EngagementId -IncludeExpired

    if (-not $exceptions) {
        Write-Host "No exceptions found." -ForegroundColor Yellow
        return
    }

    switch ($Format) {
        'Table' {
            $exceptions | Format-Table Id, Type, RuleId, Category, Status, ExpirationDate, Justification -AutoSize
        }
        'JSON' {
            $json = $exceptions | ConvertTo-Json -Depth 10
            if ($Path) {
                $json | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "Report saved to: $Path" -ForegroundColor Green
            }
            else {
                $json
            }
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD-Scout Exception Report</title>
    <style>
        body { font-family: -apple-system, sans-serif; padding: 2rem; background: #0d1117; color: #f0f6fc; }
        h1 { color: #58a6ff; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #161b22; }
        .active { color: #3fb950; }
        .expired { color: #f85149; }
        .revoked { color: #f0883e; }
    </style>
</head>
<body>
    <h1>AD-Scout Exception Report</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>Total Exceptions: $($exceptions.Count) | Active: $(@($exceptions | Where-Object Status -eq 'Active').Count)</p>
    <table>
        <thead>
            <tr><th>ID</th><th>Type</th><th>Rule/Category</th><th>Status</th><th>Expires</th><th>Justification</th><th>Approved By</th></tr>
        </thead>
        <tbody>
$($exceptions | ForEach-Object {
    $target = if ($_.RuleId) { $_.RuleId } else { $_.Category }
    $statusClass = $_.Status.ToLower()
    "            <tr><td>$($_.Id)</td><td>$($_.Type)</td><td>$target</td><td class='$statusClass'>$($_.Status)</td><td>$($_.ExpirationDate.ToString('yyyy-MM-dd'))</td><td>$($_.Justification)</td><td>$($_.ApprovedBy)</td></tr>"
})
        </tbody>
    </table>
</body>
</html>
"@
            if ($Path) {
                $html | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "Report saved to: $Path" -ForegroundColor Green
            }
            else {
                $html
            }
        }
    }
}

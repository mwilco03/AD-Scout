function New-ADScoutEngagement {
    <#
    .SYNOPSIS
        Creates a new AD-Scout engagement for tracking security assessments.

    .DESCRIPTION
        Creates a named engagement context for organizing multiple scans,
        baselines, and exceptions. Engagements provide:
        - Unique identifier for assessment tracking
        - Persistent baseline storage
        - Exception management scope
        - Scan history aggregation
        - Report generation context

    .PARAMETER Name
        Display name for the engagement.

    .PARAMETER Description
        Optional description of the engagement scope and objectives.

    .PARAMETER Client
        Client or organization name.

    .PARAMETER Domain
        Target domain(s) for the assessment.

    .PARAMETER StartDate
        Engagement start date. Defaults to current date.

    .PARAMETER EndDate
        Expected engagement end date.

    .PARAMETER StoragePath
        Path to store engagement data. Defaults to ~/.adscout/engagements/

    .PARAMETER Tags
        Optional tags for categorization.

    .EXAMPLE
        New-ADScoutEngagement -Name "Q1-2024-Assessment" -Client "Contoso" -Domain "contoso.com"

    .EXAMPLE
        $engagement = New-ADScoutEngagement -Name "Annual Audit" -Description "Annual AD security audit" -EndDate (Get-Date).AddDays(30)

    .OUTPUTS
        ADScoutEngagement object with Id, metadata, and methods.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [string]$Client,

        [Parameter()]
        [string[]]$Domain,

        [Parameter()]
        [datetime]$StartDate = (Get-Date),

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [string]$StoragePath,

        [Parameter()]
        [string[]]$Tags
    )

    # Generate unique ID
    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)

    # Determine storage path
    if (-not $StoragePath) {
        $StoragePath = Join-Path $HOME '.adscout' 'engagements'
    }

    $engagementPath = Join-Path $StoragePath $id

    # Create directory structure
    if (-not (Test-Path $engagementPath)) {
        New-Item -Path $engagementPath -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $engagementPath 'scans') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $engagementPath 'baselines') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $engagementPath 'exceptions') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $engagementPath 'reports') -ItemType Directory -Force | Out-Null
    }

    # Create engagement metadata
    $engagement = [PSCustomObject]@{
        PSTypeName = 'ADScoutEngagement'
        Id = $id
        Name = $Name
        Description = $Description
        Client = $Client
        Domain = $Domain
        StartDate = $StartDate
        EndDate = $EndDate
        CreatedAt = (Get-Date)
        CreatedBy = "$env:USERNAME@$env:COMPUTERNAME"
        Status = 'Active'
        StoragePath = $engagementPath
        Tags = $Tags
        ScanCount = 0
        LastScanDate = $null
        BaselineId = $null
    }

    # Save metadata
    $metadataPath = Join-Path $engagementPath 'engagement.json'
    $engagement | ConvertTo-Json -Depth 5 | Out-File -FilePath $metadataPath -Encoding UTF8

    Write-Host "Engagement created: $Name" -ForegroundColor Green
    Write-Host "  ID: $id" -ForegroundColor Cyan
    Write-Host "  Path: $engagementPath" -ForegroundColor Gray

    # Add methods to object
    Add-EngagementMethods -Engagement $engagement

    return $engagement
}

function Get-ADScoutEngagement {
    <#
    .SYNOPSIS
        Retrieves existing AD-Scout engagements.

    .DESCRIPTION
        Gets one or more engagements by ID, name, or lists all engagements.

    .PARAMETER Id
        Engagement ID to retrieve.

    .PARAMETER Name
        Engagement name to search for (supports wildcards).

    .PARAMETER StoragePath
        Path to search for engagements. Defaults to ~/.adscout/engagements/

    .PARAMETER Status
        Filter by engagement status (Active, Completed, Archived).

    .PARAMETER IncludeArchived
        Include archived engagements in results.

    .EXAMPLE
        Get-ADScoutEngagement
        Lists all active engagements.

    .EXAMPLE
        Get-ADScoutEngagement -Id "abc123def456"

    .EXAMPLE
        Get-ADScoutEngagement -Name "*Q1*"
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(ParameterSetName = 'ById')]
        [string]$Id,

        [Parameter(ParameterSetName = 'ByName')]
        [string]$Name,

        [Parameter()]
        [string]$StoragePath,

        [Parameter()]
        [ValidateSet('Active', 'Completed', 'Archived')]
        [string]$Status,

        [Parameter()]
        [switch]$IncludeArchived
    )

    if (-not $StoragePath) {
        $StoragePath = Join-Path $HOME '.adscout' 'engagements'
    }

    if (-not (Test-Path $StoragePath)) {
        Write-Verbose "No engagements found at $StoragePath"
        return @()
    }

    $engagements = @()

    # Get all engagement directories
    Get-ChildItem -Path $StoragePath -Directory | ForEach-Object {
        $metadataPath = Join-Path $_.FullName 'engagement.json'
        if (Test-Path $metadataPath) {
            try {
                $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
                $metadata.PSObject.TypeNames.Insert(0, 'ADScoutEngagement')
                Add-EngagementMethods -Engagement $metadata
                $engagements += $metadata
            }
            catch {
                Write-Warning "Failed to load engagement from $_: $($_.Exception.Message)"
            }
        }
    }

    # Filter by ID
    if ($Id) {
        $engagements = $engagements | Where-Object { $_.Id -eq $Id }
    }

    # Filter by Name
    if ($Name) {
        $engagements = $engagements | Where-Object { $_.Name -like $Name }
    }

    # Filter by Status
    if ($Status) {
        $engagements = $engagements | Where-Object { $_.Status -eq $Status }
    }
    elseif (-not $IncludeArchived) {
        $engagements = $engagements | Where-Object { $_.Status -ne 'Archived' }
    }

    return $engagements
}

function Set-ADScoutEngagement {
    <#
    .SYNOPSIS
        Updates an existing AD-Scout engagement.

    .PARAMETER Id
        Engagement ID to update.

    .PARAMETER Name
        New display name.

    .PARAMETER Description
        New description.

    .PARAMETER Status
        New status (Active, Completed, Archived).

    .PARAMETER EndDate
        New end date.

    .PARAMETER Tags
        Updated tags.

    .EXAMPLE
        Set-ADScoutEngagement -Id "abc123" -Status "Completed"

    .EXAMPLE
        Get-ADScoutEngagement -Name "Q1*" | Set-ADScoutEngagement -Status "Archived"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [ValidateSet('Active', 'Completed', 'Archived')]
        [string]$Status,

        [Parameter()]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$Tags
    )

    process {
        $engagement = Get-ADScoutEngagement -Id $Id
        if (-not $engagement) {
            Write-Error "Engagement not found: $Id"
            return
        }

        $updated = $false

        if ($Name) { $engagement.Name = $Name; $updated = $true }
        if ($Description) { $engagement.Description = $Description; $updated = $true }
        if ($Status) { $engagement.Status = $Status; $updated = $true }
        if ($EndDate) { $engagement.EndDate = $EndDate; $updated = $true }
        if ($Tags) { $engagement.Tags = $Tags; $updated = $true }

        if ($updated) {
            $engagement | Add-Member -NotePropertyName 'ModifiedAt' -NotePropertyValue (Get-Date) -Force
            $engagement | Add-Member -NotePropertyName 'ModifiedBy' -NotePropertyValue "$env:USERNAME@$env:COMPUTERNAME" -Force

            $metadataPath = Join-Path $engagement.StoragePath 'engagement.json'
            $engagement | ConvertTo-Json -Depth 5 | Out-File -FilePath $metadataPath -Encoding UTF8

            Write-Host "Engagement updated: $($engagement.Name)" -ForegroundColor Green
        }

        return $engagement
    }
}

function Remove-ADScoutEngagement {
    <#
    .SYNOPSIS
        Removes an AD-Scout engagement.

    .PARAMETER Id
        Engagement ID to remove.

    .PARAMETER Force
        Skip confirmation prompt.

    .PARAMETER Archive
        Archive instead of delete (sets status to Archived).

    .EXAMPLE
        Remove-ADScoutEngagement -Id "abc123" -Force

    .EXAMPLE
        Get-ADScoutEngagement -Name "Test*" | Remove-ADScoutEngagement -Archive
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Archive
    )

    process {
        $engagement = Get-ADScoutEngagement -Id $Id -IncludeArchived
        if (-not $engagement) {
            Write-Error "Engagement not found: $Id"
            return
        }

        if ($Archive) {
            Set-ADScoutEngagement -Id $Id -Status 'Archived'
            Write-Host "Engagement archived: $($engagement.Name)" -ForegroundColor Yellow
            return
        }

        $message = "Remove engagement '$($engagement.Name)' and all associated data?"
        if ($Force -or $PSCmdlet.ShouldProcess($engagement.Name, 'Remove')) {
            Remove-Item -Path $engagement.StoragePath -Recurse -Force
            Write-Host "Engagement removed: $($engagement.Name)" -ForegroundColor Yellow
        }
    }
}

function Invoke-ADScoutEngagementScan {
    <#
    .SYNOPSIS
        Runs a scan within an engagement context.

    .DESCRIPTION
        Executes an AD-Scout scan and associates the results with an engagement.
        Automatically saves results to the engagement's scan history.

    .PARAMETER EngagementId
        ID of the engagement to scan within.

    .PARAMETER Category
        Rule categories to include.

    .PARAMETER Exclude
        Rule IDs to exclude.

    .PARAMETER SetAsBaseline
        Set this scan as the engagement's baseline.

    .PARAMETER CompareToBaseline
        Compare results to the engagement's baseline.

    .EXAMPLE
        Invoke-ADScoutEngagementScan -EngagementId "abc123"

    .EXAMPLE
        $results = Invoke-ADScoutEngagementScan -EngagementId "abc123" -SetAsBaseline
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId,

        [Parameter()]
        [string[]]$Category,

        [Parameter()]
        [string[]]$Exclude,

        [Parameter()]
        [switch]$SetAsBaseline,

        [Parameter()]
        [switch]$CompareToBaseline
    )

    $engagement = Get-ADScoutEngagement -Id $EngagementId
    if (-not $engagement) {
        Write-Error "Engagement not found: $EngagementId"
        return
    }

    Write-Host "Running scan for engagement: $($engagement.Name)" -ForegroundColor Cyan

    # Build scan parameters
    $scanParams = @{}
    if ($Category) { $scanParams['Category'] = $Category }
    if ($Exclude) { $scanParams['Exclude'] = $Exclude }

    # Run scan
    $results = Invoke-ADScoutScan @scanParams

    # Save scan to engagement
    $scanId = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $scanPath = Join-Path $engagement.StoragePath 'scans' "$scanId.json"

    $scanRecord = @{
        ScanId = $scanId
        EngagementId = $EngagementId
        ExecutedAt = (Get-Date)
        ExecutedBy = "$env:USERNAME@$env:COMPUTERNAME"
        ResultCount = $results.Count
        TotalScore = ($results | Measure-Object -Property Score -Sum).Sum
        TotalFindings = ($results | Measure-Object -Property FindingCount -Sum).Sum
        Categories = ($results | Group-Object Category | ForEach-Object { $_.Name })
        Results = $results
    }

    $scanRecord | ConvertTo-Json -Depth 10 | Out-File -FilePath $scanPath -Encoding UTF8

    # Update engagement metadata
    $engagement.ScanCount++
    $engagement.LastScanDate = Get-Date
    Set-ADScoutEngagement -Id $EngagementId -Status $engagement.Status | Out-Null

    Write-Host "Scan saved: $scanId" -ForegroundColor Green

    # Set as baseline if requested
    if ($SetAsBaseline) {
        $baselinePath = Join-Path $engagement.StoragePath 'baselines' 'current.json'
        Export-ADScoutBaseline -Results $results -Path $baselinePath
        $engagement.BaselineId = $scanId
        Write-Host "Baseline set from scan: $scanId" -ForegroundColor Cyan
    }

    # Compare to baseline if requested
    if ($CompareToBaseline -and $engagement.BaselineId) {
        $baselinePath = Join-Path $engagement.StoragePath 'baselines' 'current.json'
        if (Test-Path $baselinePath) {
            $baseline = Import-ADScoutBaseline -Path $baselinePath
            $comparison = Compare-ADScoutBaseline -Results $results -Baseline $baseline -ShowResolved
            Write-Host "`nBaseline Comparison:" -ForegroundColor Cyan
            Write-Host "  New issues: $($comparison.Summary.NewRules)" -ForegroundColor $(if ($comparison.Summary.NewRules -gt 0) { 'Red' } else { 'Green' })
            Write-Host "  Resolved: $($comparison.Summary.ResolvedRules)" -ForegroundColor Green
            Write-Host "  Degraded: $($comparison.Summary.DegradedRules)" -ForegroundColor Yellow
            Write-Host "  Improved: $($comparison.Summary.ImprovedRules)" -ForegroundColor Cyan
        }
    }

    return $results
}

function Get-ADScoutEngagementScans {
    <#
    .SYNOPSIS
        Retrieves scans from an engagement.

    .PARAMETER EngagementId
        Engagement ID.

    .PARAMETER Last
        Get only the last N scans.

    .PARAMETER IncludeResults
        Include full scan results (larger output).

    .EXAMPLE
        Get-ADScoutEngagementScans -EngagementId "abc123" -Last 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId,

        [Parameter()]
        [int]$Last,

        [Parameter()]
        [switch]$IncludeResults
    )

    $engagement = Get-ADScoutEngagement -Id $EngagementId
    if (-not $engagement) {
        Write-Error "Engagement not found: $EngagementId"
        return
    }

    $scansPath = Join-Path $engagement.StoragePath 'scans'
    if (-not (Test-Path $scansPath)) {
        return @()
    }

    $scans = Get-ChildItem -Path $scansPath -Filter '*.json' | Sort-Object Name -Descending | ForEach-Object {
        $scan = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
        if (-not $IncludeResults) {
            $scan.PSObject.Properties.Remove('Results')
        }
        $scan
    }

    if ($Last) {
        $scans = $scans | Select-Object -First $Last
    }

    return $scans
}

function Add-EngagementMethods {
    <#
    .SYNOPSIS
        Adds convenience methods to engagement objects.
    #>
    param([PSCustomObject]$Engagement)

    # Add script methods for convenience
    $Engagement | Add-Member -MemberType ScriptMethod -Name 'Scan' -Value {
        Invoke-ADScoutEngagementScan -EngagementId $this.Id
    } -Force

    $Engagement | Add-Member -MemberType ScriptMethod -Name 'GetScans' -Value {
        param([int]$Last = 10)
        Get-ADScoutEngagementScans -EngagementId $this.Id -Last $Last
    } -Force

    $Engagement | Add-Member -MemberType ScriptMethod -Name 'Complete' -Value {
        Set-ADScoutEngagement -Id $this.Id -Status 'Completed'
    } -Force

    $Engagement | Add-Member -MemberType ScriptMethod -Name 'Archive' -Value {
        Set-ADScoutEngagement -Id $this.Id -Status 'Archived'
    } -Force
}

# Format data for engagements
Update-FormatData -PrependPath (Join-Path $PSScriptRoot '..' 'Formats' 'ADScoutEngagement.format.ps1xml') -ErrorAction SilentlyContinue

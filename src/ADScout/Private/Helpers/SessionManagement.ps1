function Get-ADScoutSessionPath {
    <#
    .SYNOPSIS
        Gets or creates the session storage path for dashboard persistence.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SessionId,

        [Parameter()]
        [string]$EngagementId
    )

    # Determine base path
    $basePath = if ($EngagementId) {
        $engagement = Get-ADScoutEngagement -Id $EngagementId -ErrorAction SilentlyContinue
        if ($engagement) {
            Join-Path $engagement.StoragePath 'sessions'
        }
    }

    if (-not $basePath) {
        $basePath = Join-Path $HOME '.adscout' 'sessions'
    }

    # Create session ID if not provided
    if (-not $SessionId) {
        $SessionId = (Get-Date).ToString('yyyyMMdd-HHmmss')
    }

    $sessionPath = Join-Path $basePath $SessionId

    # Create directory structure
    if (-not (Test-Path $sessionPath)) {
        New-Item -Path $sessionPath -ItemType Directory -Force | Out-Null
    }

    [PSCustomObject]@{
        SessionId = $SessionId
        Path = $sessionPath
        ResultsFile = Join-Path $sessionPath 'results.json'
        StateFile = Join-Path $sessionPath 'state.json'
        ProgressFile = Join-Path $sessionPath 'progress.json'
    }
}

function Save-ADScoutSessionState {
    <#
    .SYNOPSIS
        Saves current scan state to disk for resume capability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath,

        [Parameter()]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [hashtable]$Progress,

        [Parameter()]
        [string]$Status = 'InProgress'
    )

    $session = Get-ADScoutSessionPath -SessionId (Split-Path $SessionPath -Leaf)

    # Save results incrementally (append mode for large scans)
    if ($Results) {
        $Results | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $session.ResultsFile -Encoding UTF8
    }

    # Save state
    $state = @{
        Status = $Status
        LastUpdated = (Get-Date).ToString('o')
        ResultCount = if ($Results) { $Results.Count } else { 0 }
        TotalScore = if ($Results) { ($Results | Measure-Object -Property Score -Sum).Sum } else { 0 }
    }
    $state | ConvertTo-Json | Out-File -FilePath $session.StateFile -Encoding UTF8

    # Save progress for resume
    if ($Progress) {
        $Progress | ConvertTo-Json -Depth 5 | Out-File -FilePath $session.ProgressFile -Encoding UTF8
    }
}

function Get-ADScoutSessionState {
    <#
    .SYNOPSIS
        Loads scan state from disk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath
    )

    $session = Get-ADScoutSessionPath -SessionId (Split-Path $SessionPath -Leaf)

    $state = @{
        Results = @()
        Progress = @{}
        Status = 'NotFound'
    }

    if (Test-Path $session.ResultsFile) {
        try {
            $state.Results = Get-Content -Path $session.ResultsFile -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Failed to load results: $_"
        }
    }

    if (Test-Path $session.StateFile) {
        try {
            $stateData = Get-Content -Path $session.StateFile -Raw | ConvertFrom-Json
            $state.Status = $stateData.Status
            $state.LastUpdated = $stateData.LastUpdated
        }
        catch {
            Write-Warning "Failed to load state: $_"
        }
    }

    if (Test-Path $session.ProgressFile) {
        try {
            $state.Progress = Get-Content -Path $session.ProgressFile -Raw | ConvertFrom-Json -AsHashtable
        }
        catch {
            Write-Warning "Failed to load progress: $_"
        }
    }

    [PSCustomObject]$state
}

function Get-ADScoutLatestSession {
    <#
    .SYNOPSIS
        Gets the most recent session for resume.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [switch]$IncompleteOnly
    )

    $basePath = if ($EngagementId) {
        $engagement = Get-ADScoutEngagement -Id $EngagementId -ErrorAction SilentlyContinue
        if ($engagement) {
            Join-Path $engagement.StoragePath 'sessions'
        }
    }

    if (-not $basePath) {
        $basePath = Join-Path $HOME '.adscout' 'sessions'
    }

    if (-not (Test-Path $basePath)) {
        return $null
    }

    $sessions = Get-ChildItem -Path $basePath -Directory | Sort-Object Name -Descending

    foreach ($sessionDir in $sessions) {
        $stateFile = Join-Path $sessionDir.FullName 'state.json'
        if (Test-Path $stateFile) {
            $state = Get-Content -Path $stateFile -Raw | ConvertFrom-Json

            if ($IncompleteOnly -and $state.Status -eq 'Completed') {
                continue
            }

            return [PSCustomObject]@{
                SessionId = $sessionDir.Name
                Path = $sessionDir.FullName
                Status = $state.Status
                LastUpdated = $state.LastUpdated
                ResultCount = $state.ResultCount
            }
        }
    }

    return $null
}

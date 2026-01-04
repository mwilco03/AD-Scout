function Get-ADScoutScanWatermark {
    <#
    .SYNOPSIS
        Gets or creates a watermark for incremental scanning.

    .DESCRIPTION
        Retrieves the last scan timestamp and highest USN (Update Sequence Number)
        from a previous scan. This watermark is used to identify objects that
        have changed since the last scan.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SessionPath,

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [string]$Domain
    )

    # Try to get from session
    if ($SessionPath) {
        $watermarkFile = Join-Path $SessionPath 'watermark.json'
        if (Test-Path $watermarkFile) {
            return Get-Content -Path $watermarkFile -Raw | ConvertFrom-Json
        }
    }

    # Try to get from latest engagement session
    if ($EngagementId) {
        $latestSession = Get-ADScoutLatestSession -EngagementId $EngagementId
        if ($latestSession) {
            $watermarkFile = Join-Path $latestSession.Path 'watermark.json'
            if (Test-Path $watermarkFile) {
                return Get-Content -Path $watermarkFile -Raw | ConvertFrom-Json
            }
        }
    }

    # Try default location
    $defaultPath = Join-Path $HOME '.adscout' 'sessions'
    if (Test-Path $defaultPath) {
        $latestSession = Get-ChildItem -Path $defaultPath -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1

        if ($latestSession) {
            $watermarkFile = Join-Path $latestSession.FullName 'watermark.json'
            if (Test-Path $watermarkFile) {
                $watermark = Get-Content -Path $watermarkFile -Raw | ConvertFrom-Json
                # Ensure domain matches if specified
                if (-not $Domain -or $watermark.Domain -eq $Domain) {
                    return $watermark
                }
            }
        }
    }

    return $null
}

function Save-ADScoutScanWatermark {
    <#
    .SYNOPSIS
        Saves the scan watermark for future incremental scans.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [datetime]$ScanTime,

        [Parameter()]
        [long]$HighestUSN,

        [Parameter()]
        [int]$ObjectCount,

        [Parameter()]
        [string]$ScanType = 'Full'
    )

    $watermark = @{
        Domain = $Domain
        ScanTime = $ScanTime.ToString('o')
        HighestUSN = $HighestUSN
        ObjectCount = $ObjectCount
        ScanType = $ScanType
        Version = '1.0'
    }

    $watermarkFile = Join-Path $SessionPath 'watermark.json'
    $watermark | ConvertTo-Json | Out-File -FilePath $watermarkFile -Encoding UTF8

    Write-Verbose "Saved scan watermark: USN=$HighestUSN, Time=$($ScanTime.ToString('o'))"
}

function Get-ADScoutHighestUSN {
    <#
    .SYNOPSIS
        Gets the highest committed USN from the domain controller.

    .DESCRIPTION
        Queries the RootDSE for highestCommittedUSN which is used as a
        watermark for incremental/differential scans.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$Domain
    )

    try {
        $rootDSE = if ($Server) {
            [ADSI]"LDAP://$Server/RootDSE"
        } else {
            [ADSI]"LDAP://RootDSE"
        }

        $highestUSN = [long]$rootDSE.highestCommittedUSN[0]
        $serverName = $rootDSE.dnsHostName[0]

        return [PSCustomObject]@{
            HighestCommittedUSN = $highestUSN
            Server = $serverName
            QueryTime = Get-Date
        }
    }
    catch {
        Write-Warning "Failed to get highest USN: $_"
        return $null
    }
}

function Get-ADScoutChangedObjects {
    <#
    .SYNOPSIS
        Gets AD objects changed since a given watermark.

    .DESCRIPTION
        Performs an incremental query against Active Directory to find
        objects that have changed since the last scan. Uses either USN
        or whenChanged timestamp depending on what's available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectType,

        [Parameter()]
        [datetime]$SinceTime,

        [Parameter()]
        [long]$SinceUSN,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string[]]$Properties
    )

    # Build the LDAP filter based on object type
    $typeFilter = switch ($ObjectType) {
        'User'     { '(objectCategory=person)(objectClass=user)' }
        'Computer' { '(objectCategory=computer)' }
        'Group'    { '(objectCategory=group)' }
        default    { '(objectClass=*)' }
    }

    # Build change detection filter
    $changeFilter = if ($SinceUSN -and $SinceUSN -gt 0) {
        # USN-based incremental (most reliable)
        "(uSNChanged>=$SinceUSN)"
    }
    elseif ($SinceTime) {
        # Time-based incremental (fallback)
        $ldapTime = $SinceTime.ToUniversalTime().ToString('yyyyMMddHHmmss.0Z')
        "(whenChanged>=$ldapTime)"
    }
    else {
        # No filter - full scan
        ''
    }

    # Combine filters
    $filter = if ($changeFilter) {
        "(&$typeFilter$changeFilter)"
    }
    else {
        "(&$typeFilter)"
    }

    Write-Verbose "Incremental query filter: $filter"

    # Build searcher
    $searchRoot = if ($Server -and $Domain) {
        [ADSI]"LDAP://$Server/DC=$($Domain.Replace('.', ',DC='))"
    }
    elseif ($Server) {
        [ADSI]"LDAP://$Server"
    }
    elseif ($Domain) {
        [ADSI]"LDAP://DC=$($Domain.Replace('.', ',DC='))"
    }
    else {
        [ADSI]''
    }

    $searcher = [adsisearcher]$searchRoot
    $searcher.Filter = $filter
    $searcher.PageSize = 1000

    # Add properties to retrieve
    $defaultProps = @('distinguishedName', 'objectGUID', 'uSNChanged', 'whenChanged')
    $allProps = $defaultProps + @($Properties | Where-Object { $_ -notin $defaultProps })

    foreach ($prop in $allProps) {
        $searcher.PropertiesToLoad.Add($prop) | Out-Null
    }

    # Execute search
    try {
        $results = $searcher.FindAll()
        $objects = @()
        $highestUSN = 0

        foreach ($result in $results) {
            $props = @{}
            foreach ($propName in $result.Properties.PropertyNames) {
                $props[$propName] = $result.Properties[$propName][0]
            }

            # Track highest USN
            $usn = [long]$props['usnchanged']
            if ($usn -gt $highestUSN) {
                $highestUSN = $usn
            }

            $objects += [PSCustomObject]$props
        }

        return [PSCustomObject]@{
            Objects = $objects
            Count = $objects.Count
            HighestUSN = $highestUSN
            ObjectType = $ObjectType
        }
    }
    catch {
        Write-Warning "Failed to query changed $ObjectType objects: $_"
        return [PSCustomObject]@{
            Objects = @()
            Count = 0
            HighestUSN = 0
            ObjectType = $ObjectType
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($results) { $results.Dispose() }
    }
}

function Merge-ADScoutIncrementalResults {
    <#
    .SYNOPSIS
        Merges incremental scan results with previous baseline.

    .DESCRIPTION
        Combines findings from an incremental scan with a previous full
        scan baseline. Updates existing findings for changed objects and
        adds new findings while preserving unchanged ones.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$BaselineResults,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$IncrementalResults,

        [Parameter()]
        [string[]]$ChangedObjectDNs
    )

    $merged = @{}

    # Index baseline results by RuleId
    foreach ($result in $BaselineResults) {
        $merged[$result.RuleId] = $result.PSObject.Copy()
    }

    # Process incremental results
    foreach ($incResult in $IncrementalResults) {
        $ruleId = $incResult.RuleId

        if ($merged.ContainsKey($ruleId)) {
            # Rule exists in baseline - need to merge findings
            $baseResult = $merged[$ruleId]

            # Get affected objects from baseline that weren't re-scanned
            $baseFindings = @($baseResult.Findings)
            $incFindings = @($incResult.Findings)

            # Filter baseline findings to exclude objects that were re-evaluated
            if ($ChangedObjectDNs -and $baseFindings.Count -gt 0) {
                $unchangedFindings = $baseFindings | Where-Object {
                    $dn = if ($_.DistinguishedName) { $_.DistinguishedName }
                          elseif ($_.DN) { $_.DN }
                          elseif ($_.distinguishedname) { $_.distinguishedname }
                          else { $null }

                    -not $dn -or ($dn -notin $ChangedObjectDNs)
                }
            }
            else {
                $unchangedFindings = @()
            }

            # Combine unchanged baseline findings with new incremental findings
            $combinedFindings = @($unchangedFindings) + @($incFindings)

            # Update the result
            $merged[$ruleId] = [PSCustomObject]@{
                PSTypeName   = 'ADScoutResult'
                RuleId       = $ruleId
                RuleName     = $baseResult.RuleName
                Category     = $baseResult.Category
                Description  = $baseResult.Description
                FindingCount = $combinedFindings.Count
                Score        = $incResult.Score  # Use incremental score calculation
                MaxScore     = $baseResult.MaxScore
                Findings     = $combinedFindings
                MITRE        = $baseResult.MITRE
                CIS          = $baseResult.CIS
                STIG         = $baseResult.STIG
                Remediation  = $baseResult.Remediation
                TechnicalExplanation = $baseResult.TechnicalExplanation
                References   = $baseResult.References
                ExecutedAt   = $incResult.ExecutedAt
                IncrementalUpdate = $true
            }
        }
        else {
            # New rule finding not in baseline
            $merged[$ruleId] = $incResult
        }
    }

    return $merged.Values | Sort-Object Category, RuleId
}

function Get-ADScoutIncrementalSummary {
    <#
    .SYNOPSIS
        Generates a summary of incremental scan changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject[]]$BaselineResults,

        [Parameter()]
        [PSCustomObject[]]$CurrentResults,

        [Parameter()]
        [PSCustomObject]$Watermark
    )

    $summary = @{
        ScanType = 'Incremental'
        BaselineDate = if ($Watermark) { $Watermark.ScanTime } else { 'Unknown' }
        CurrentDate = (Get-Date).ToString('o')
        BaselineUSN = if ($Watermark) { $Watermark.HighestUSN } else { 0 }

        BaselineTotalScore = ($BaselineResults | Measure-Object -Property Score -Sum).Sum
        CurrentTotalScore = ($CurrentResults | Measure-Object -Property Score -Sum).Sum

        BaselineRuleCount = ($BaselineResults | Measure-Object).Count
        CurrentRuleCount = ($CurrentResults | Measure-Object).Count

        NewFindings = @()
        ResolvedFindings = @()
        ChangedFindings = @()
    }

    # Index baseline by RuleId
    $baselineIndex = @{}
    foreach ($r in $BaselineResults) {
        $baselineIndex[$r.RuleId] = $r
    }

    # Index current by RuleId
    $currentIndex = @{}
    foreach ($r in $CurrentResults) {
        $currentIndex[$r.RuleId] = $r
    }

    # Find new findings (in current but not baseline)
    foreach ($ruleId in $currentIndex.Keys) {
        if (-not $baselineIndex.ContainsKey($ruleId)) {
            $summary.NewFindings += $currentIndex[$ruleId]
        }
        elseif ($currentIndex[$ruleId].FindingCount -ne $baselineIndex[$ruleId].FindingCount) {
            $summary.ChangedFindings += [PSCustomObject]@{
                RuleId = $ruleId
                BaselineCount = $baselineIndex[$ruleId].FindingCount
                CurrentCount = $currentIndex[$ruleId].FindingCount
                BaselineScore = $baselineIndex[$ruleId].Score
                CurrentScore = $currentIndex[$ruleId].Score
            }
        }
    }

    # Find resolved findings (in baseline but not current)
    foreach ($ruleId in $baselineIndex.Keys) {
        if (-not $currentIndex.ContainsKey($ruleId)) {
            $summary.ResolvedFindings += $baselineIndex[$ruleId]
        }
    }

    $summary.ScoreChange = $summary.CurrentTotalScore - $summary.BaselineTotalScore
    $summary.NewFindingCount = $summary.NewFindings.Count
    $summary.ResolvedFindingCount = $summary.ResolvedFindings.Count
    $summary.ChangedFindingCount = $summary.ChangedFindings.Count

    return [PSCustomObject]$summary
}

function Test-ADScoutIncrementalAvailable {
    <#
    .SYNOPSIS
        Checks if incremental scanning is available.

    .DESCRIPTION
        Verifies that a previous scan watermark exists and is valid
        for the specified domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$EngagementId,

        [Parameter()]
        [string]$SessionPath
    )

    $watermark = Get-ADScoutScanWatermark -Domain $Domain -EngagementId $EngagementId -SessionPath $SessionPath

    if (-not $watermark) {
        return [PSCustomObject]@{
            Available = $false
            Reason = 'No previous scan watermark found'
        }
    }

    # Check if watermark is too old (> 7 days by default)
    $watermarkAge = (Get-Date) - [datetime]$watermark.ScanTime
    if ($watermarkAge.TotalDays -gt 7) {
        return [PSCustomObject]@{
            Available = $false
            Reason = "Previous scan is $([math]::Round($watermarkAge.TotalDays, 1)) days old. Recommend full scan."
            Watermark = $watermark
        }
    }

    return [PSCustomObject]@{
        Available = $true
        Watermark = $watermark
        Age = $watermarkAge
    }
}

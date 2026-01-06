function Set-ADScoutEngagementConfig {
    <#
    .SYNOPSIS
        Sets persistent configuration for an engagement.

    .DESCRIPTION
        Saves engagement-specific settings that persist across scan invocations:
        - Excluded rules (false positives, accepted risks)
        - Default categories to scan
        - Target domain/servers
        - Scan profile preferences
        - Custom notes

        Configuration is saved to engagement directory and auto-loaded on subsequent scans.

    .PARAMETER EngagementId
        The engagement identifier (e.g., "ACME-Q1-2024").

    .PARAMETER ExcludeRules
        Rule IDs to always exclude for this engagement.

    .PARAMETER IncludeRules
        Rule IDs to always include (overrides category filtering).

    .PARAMETER DefaultCategories
        Default categories to scan if not specified.

    .PARAMETER DefaultDomain
        Default target domain.

    .PARAMETER DefaultScanProfile
        Default scan profile.

    .PARAMETER Notes
        Free-form notes about the engagement.

    .PARAMETER AcceptedRisks
        Documented accepted risks with justification.

    .EXAMPLE
        Set-ADScoutEngagementConfig -EngagementId "ACME-2024" -ExcludeRules 'S-ObsoleteOS','A-NoEmail'

    .EXAMPLE
        Set-ADScoutEngagementConfig -EngagementId "ACME-2024" -DefaultDomain "acme.local" -DefaultScanProfile Stealth
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId,

        [Parameter()]
        [string[]]$ExcludeRules,

        [Parameter()]
        [string[]]$IncludeRules,

        [Parameter()]
        [string[]]$DefaultCategories,

        [Parameter()]
        [string]$DefaultDomain,

        [Parameter()]
        [ValidateSet('Stealth', 'Standard', 'Comprehensive', 'DCOnly', 'EndpointAudit')]
        [string]$DefaultScanProfile,

        [Parameter()]
        [string]$Notes,

        [Parameter()]
        [hashtable[]]$AcceptedRisks,

        [Parameter()]
        [switch]$Append
    )

    # Get engagement config path
    $engagementPath = Join-Path $env:LOCALAPPDATA "ADScout\Engagements\$EngagementId"
    $configPath = Join-Path $engagementPath "config.json"

    # Create directory if needed
    if (-not (Test-Path $engagementPath)) {
        New-Item -Path $engagementPath -ItemType Directory -Force | Out-Null
    }

    # Load existing config if appending
    $config = if ($Append -and (Test-Path $configPath)) {
        Get-Content -Path $configPath -Raw | ConvertFrom-Json -AsHashtable
    } else {
        @{
            EngagementId      = $EngagementId
            CreatedAt         = (Get-Date).ToString('o')
            UpdatedAt         = (Get-Date).ToString('o')
            ExcludeRules      = @()
            IncludeRules      = @()
            DefaultCategories = @()
            DefaultDomain     = $null
            DefaultScanProfile = $null
            Notes             = $null
            AcceptedRisks     = @()
        }
    }

    # Update config with new values
    $config.UpdatedAt = (Get-Date).ToString('o')

    if ($ExcludeRules) {
        if ($Append) {
            $config.ExcludeRules = @($config.ExcludeRules) + @($ExcludeRules) | Select-Object -Unique
        } else {
            $config.ExcludeRules = $ExcludeRules
        }
    }

    if ($IncludeRules) {
        if ($Append) {
            $config.IncludeRules = @($config.IncludeRules) + @($IncludeRules) | Select-Object -Unique
        } else {
            $config.IncludeRules = $IncludeRules
        }
    }

    if ($DefaultCategories) { $config.DefaultCategories = $DefaultCategories }
    if ($DefaultDomain) { $config.DefaultDomain = $DefaultDomain }
    if ($DefaultScanProfile) { $config.DefaultScanProfile = $DefaultScanProfile }
    if ($Notes) { $config.Notes = $Notes }

    if ($AcceptedRisks) {
        if ($Append) {
            $config.AcceptedRisks = @($config.AcceptedRisks) + @($AcceptedRisks)
        } else {
            $config.AcceptedRisks = $AcceptedRisks
        }
    }

    # Save config
    $config | ConvertTo-Json -Depth 10 | Out-File -Path $configPath -Encoding UTF8 -Force

    Write-Host "Engagement config saved: $configPath" -ForegroundColor Green

    return [PSCustomObject]$config
}

function Get-ADScoutEngagementConfig {
    <#
    .SYNOPSIS
        Retrieves engagement configuration.

    .PARAMETER EngagementId
        The engagement to get config for.

    .EXAMPLE
        Get-ADScoutEngagementConfig -EngagementId "ACME-2024"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId
    )

    $configPath = Join-Path $env:LOCALAPPDATA "ADScout\Engagements\$EngagementId\config.json"

    if (-not (Test-Path $configPath)) {
        Write-Warning "No configuration found for engagement: $EngagementId"
        return $null
    }

    $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json

    return $config
}

function Get-ADScoutEngagements {
    <#
    .SYNOPSIS
        Lists all configured engagements.

    .EXAMPLE
        Get-ADScoutEngagements
    #>
    [CmdletBinding()]
    param()

    $engagementsPath = Join-Path $env:LOCALAPPDATA "ADScout\Engagements"

    if (-not (Test-Path $engagementsPath)) {
        Write-Host "No engagements configured" -ForegroundColor Gray
        return @()
    }

    $engagements = Get-ChildItem -Path $engagementsPath -Directory | ForEach-Object {
        $configPath = Join-Path $_.FullName "config.json"
        if (Test-Path $configPath) {
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            [PSCustomObject]@{
                EngagementId     = $_.Name
                Domain           = $config.DefaultDomain
                ScanProfile      = $config.DefaultScanProfile
                ExcludedRules    = $config.ExcludeRules.Count
                AcceptedRisks    = $config.AcceptedRisks.Count
                LastUpdated      = $config.UpdatedAt
                Path             = $_.FullName
            }
        }
    }

    return $engagements
}

function Add-ADScoutAcceptedRisk {
    <#
    .SYNOPSIS
        Documents an accepted risk for an engagement.

    .PARAMETER EngagementId
        The engagement identifier.

    .PARAMETER RuleId
        The rule being accepted.

    .PARAMETER Justification
        Business justification for accepting the risk.

    .PARAMETER ApprovedBy
        Who approved the risk acceptance.

    .PARAMETER ExpiresAt
        When the acceptance expires (optional).

    .EXAMPLE
        Add-ADScoutAcceptedRisk -EngagementId "ACME-2024" -RuleId "S-ObsoleteOS" `
            -Justification "Legacy system required for manufacturing, isolated network" `
            -ApprovedBy "CISO"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId,

        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [string]$Justification,

        [Parameter()]
        [string]$ApprovedBy,

        [Parameter()]
        [datetime]$ExpiresAt
    )

    $acceptedRisk = @{
        RuleId        = $RuleId
        Justification = $Justification
        ApprovedBy    = $ApprovedBy ?? "$env:USERDOMAIN\$env:USERNAME"
        AcceptedAt    = (Get-Date).ToString('o')
        ExpiresAt     = if ($ExpiresAt) { $ExpiresAt.ToString('o') } else { $null }
    }

    Set-ADScoutEngagementConfig -EngagementId $EngagementId -AcceptedRisks @($acceptedRisk) -Append

    # Also add to exclusions
    Set-ADScoutEngagementConfig -EngagementId $EngagementId -ExcludeRules @($RuleId) -Append

    Write-Host "Accepted risk documented and rule excluded: $RuleId" -ForegroundColor Green
}

function Remove-ADScoutExcludedRule {
    <#
    .SYNOPSIS
        Removes a rule from the exclusion list.

    .PARAMETER EngagementId
        The engagement identifier.

    .PARAMETER RuleId
        The rule to remove from exclusions.

    .EXAMPLE
        Remove-ADScoutExcludedRule -EngagementId "ACME-2024" -RuleId "S-ObsoleteOS"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EngagementId,

        [Parameter(Mandatory)]
        [string]$RuleId
    )

    $config = Get-ADScoutEngagementConfig -EngagementId $EngagementId

    if (-not $config) {
        return
    }

    $config.ExcludeRules = @($config.ExcludeRules | Where-Object { $_ -ne $RuleId })
    $config.UpdatedAt = (Get-Date).ToString('o')

    $configPath = Join-Path $env:LOCALAPPDATA "ADScout\Engagements\$EngagementId\config.json"
    $config | ConvertTo-Json -Depth 10 | Out-File -Path $configPath -Encoding UTF8 -Force

    Write-Host "Rule removed from exclusions: $RuleId" -ForegroundColor Green
}

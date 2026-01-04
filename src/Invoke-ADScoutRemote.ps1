#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstrap loader for AD-Scout remote execution via IWR pipeline.

.DESCRIPTION
    This script enables fileless execution of AD-Scout directly from a URL.
    Download and execute with: iwr https://raw.githubusercontent.com/<org>/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex

    The script:
    1. Downloads the bundled AD-Scout module
    2. Loads it into memory (no disk writes)
    3. Executes the security assessment
    4. Outputs results to console or specified format

.PARAMETER BaseUrl
    Base URL where AD-Scout bundle is hosted. Defaults to GitHub raw content.

.PARAMETER Category
    Security rule categories to run. Default: All
    Valid: Anomalies, StaleObjects, PrivilegedAccounts, Trusts, Kerberos, GPO, PKI, All

.PARAMETER Format
    Output format for results. Default: Console
    Valid: Console, JSON, CSV, HTML

.PARAMETER OutFile
    Path to save the report. If not specified, outputs to console/stdout.

.PARAMETER Domain
    Target domain to scan. Defaults to current user's domain.

.PARAMETER Server
    Specific domain controller to query.

.PARAMETER Credential
    PSCredential object for alternate authentication.

.PARAMETER QuickScan
    Run only critical/high severity rules for faster assessment.

.PARAMETER PassThru
    Return raw result objects instead of formatted output.

.EXAMPLE
    iwr https://raw.githubusercontent.com/org/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex
    Downloads and runs a full AD security assessment with console output.

.EXAMPLE
    $script = iwr https://raw.githubusercontent.com/org/AD-Scout/main/src/Invoke-ADScoutRemote.ps1
    & ([scriptblock]::Create($script.Content)) -Category PrivilegedAccounts -Format JSON
    Runs privileged accounts assessment and outputs JSON.

.EXAMPLE
    iex "& { $(iwr -Uri 'https://raw.githubusercontent.com/org/AD-Scout/main/src/Invoke-ADScoutRemote.ps1') } -QuickScan"
    Runs a quick scan of critical rules only.

.NOTES
    Author: AD-Scout Contributors
    License: MIT

    SECURITY NOTE: This script is designed for authorized security assessments.
    Always ensure you have proper authorization before running security scans.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BaseUrl = 'https://raw.githubusercontent.com/mwilco03/AD-Scout/main',

    [Parameter()]
    [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI', 'All')]
    [string[]]$Category = 'All',

    [Parameter()]
    [ValidateSet('Console', 'JSON', 'CSV', 'HTML', 'SARIF')]
    [string]$Format = 'Console',

    [Parameter()]
    [string]$OutFile,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [switch]$QuickScan,

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [switch]$SkipBanner
)

$ErrorActionPreference = 'Stop'

#region Banner
if (-not $SkipBanner) {
    $banner = @"

    ___    ____        _____                  __
   /   |  / __ \      / ___/__________  __  __/ /_
  / /| | / / / /_____\__ \/ ___/ __ \/ / / / __/
 / ___ |/ /_/ /_____/__/ / /__/ /_/ / /_/ / /_
/_/  |_/_____/     /____/\___/\____/\__,_/\__/

        Active Directory Security Scout
              Remote Execution Mode

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "Starting AD-Scout remote assessment..." -ForegroundColor Yellow
    Write-Host "Target: $(if ($Domain) { $Domain } else { $env:USERDNSDOMAIN })" -ForegroundColor Gray
    Write-Host ""
}
#endregion

#region Helper Functions
function Get-RemoteScript {
    param(
        [string]$Url,
        [int]$MaxRetries = 3
    )

    $retryCount = 0
    $lastError = $null

    while ($retryCount -lt $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
            return $response.Content
        }
        catch {
            $lastError = $_
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $delay = [math]::Pow(2, $retryCount)
                Write-Verbose "Download failed, retrying in $delay seconds... (Attempt $retryCount of $MaxRetries)"
                Start-Sleep -Seconds $delay
            }
        }
    }

    throw "Failed to download from $Url after $MaxRetries attempts: $lastError"
}

function Write-ProgressStatus {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete = -1
    )

    if ($PercentComplete -ge 0) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
    else {
        Write-Progress -Activity $Activity -Status $Status
    }
}
#endregion

#region Module Loading
Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Downloading module bundle..."

try {
    # Try to load the bundled single-file version first
    $bundleUrl = "$BaseUrl/dist/ADScout.bundle.ps1"

    try {
        $bundleContent = Get-RemoteScript -Url $bundleUrl
        Write-Verbose "Loaded bundled module from $bundleUrl"
    }
    catch {
        Write-Verbose "Bundle not found at $bundleUrl, attempting individual component loading..."
        Write-Host "Bundle not available. Loading module components individually..." -ForegroundColor Yellow

        # Load core components in order
        $components = @(
            # Private - Helpers first
            'src/ADScout/Private/Helpers/Write-ADScoutLog.ps1'
            'src/ADScout/Private/Helpers/Get-ADScoutCache.ps1'
            'src/ADScout/Private/Helpers/Convert-SidToName.ps1'
            'src/ADScout/Private/Helpers/Get-ADScoutRulePaths.ps1'
            'src/ADScout/Private/Helpers/Test-ADScoutADConnectivity.ps1'

            # Private - Compatibility
            'src/ADScout/Private/Compatibility/Test-PSVersion.ps1'
            'src/ADScout/Private/Compatibility/Invoke-ADScoutParallel.ps1'
            'src/ADScout/Private/Compatibility/Get-CimOrWmi.ps1'

            # Private - Statistics
            'src/ADScout/Private/Statistics/Get-ADScoutStatistics.ps1'
            'src/ADScout/Private/Statistics/Get-ADScoutZScore.ps1'
            'src/ADScout/Private/Statistics/Get-ADScoutIQROutliers.ps1'
            'src/ADScout/Private/Statistics/Get-ADScoutPeerBaseline.ps1'

            # Private - Collectors
            'src/ADScout/Private/Collectors/Get-ADScoutUserData.ps1'
            'src/ADScout/Private/Collectors/Get-ADScoutComputerData.ps1'
            'src/ADScout/Private/Collectors/Get-ADScoutGroupData.ps1'
            'src/ADScout/Private/Collectors/Get-ADScoutTrustData.ps1'
            'src/ADScout/Private/Collectors/Get-ADScoutGPOData.ps1'
            'src/ADScout/Private/Collectors/Get-ADScoutCertificateData.ps1'

            # Private - Scanners
            'src/ADScout/Private/Scanners/Invoke-RuleEvaluation.ps1'

            # Public functions
            'src/ADScout/Public/Get-ADScoutConfig.ps1'
            'src/ADScout/Public/Set-ADScoutConfig.ps1'
            'src/ADScout/Public/Get-ADScoutRule.ps1'
            'src/ADScout/Public/Invoke-ADScoutScan.ps1'
            'src/ADScout/Public/Export-ADScoutReport.ps1'
            'src/ADScout/Public/Get-ADScoutRemediation.ps1'
            'src/ADScout/Public/Connect-ADScoutGraph.ps1'

            # Reporters
            'src/ADScout/Reporters/ConsoleReporter.ps1'
            'src/ADScout/Reporters/JSONReporter.ps1'
        )

        # Initialize module-level variables
        $script:ADScoutConfig = @{
            ParallelThrottleLimit = [Environment]::ProcessorCount
            DefaultReporter       = 'Console'
            RulePaths             = @()
            CacheTTL              = 300
            LogLevel              = 'Warning'
        }

        $script:ADScoutCache = @{
            Data       = @{}
            Timestamps = @{}
        }

        $loadedComponents = 0
        $totalComponents = $components.Count

        foreach ($component in $components) {
            try {
                $componentUrl = "$BaseUrl/$component"
                Write-Verbose "Loading: $component"
                $componentContent = Get-RemoteScript -Url $componentUrl

                # Execute the component
                $componentBlock = [scriptblock]::Create($componentContent)
                . $componentBlock

                $loadedComponents++
                $percent = [math]::Round(($loadedComponents / $totalComponents) * 30)
                Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Loading: $($component.Split('/')[-1])" -PercentComplete $percent
            }
            catch {
                Write-Warning "Failed to load component $component`: $_"
            }
        }

        if ($loadedComponents -lt 10) {
            throw "Failed to load minimum required components ($loadedComponents of $totalComponents). Check network connectivity to $BaseUrl"
        }

        Write-Host "Loaded $loadedComponents of $totalComponents components" -ForegroundColor Green

        # Note: Rules are loaded dynamically by Get-ADScoutRule from the BaseUrl
        # Set the rule base URL for remote loading
        $script:ADScoutRemoteRuleBase = "$BaseUrl/src/ADScout/Rules"

        $bundleContent = $null  # Mark that we used individual loading
    }

    Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Loading module into memory..." -PercentComplete 30

    # Execute the bundle in a new scope to load all functions (if bundle was loaded)
    if ($bundleContent) {
        $moduleScope = [scriptblock]::Create($bundleContent)
        . $moduleScope
    }
    # If bundleContent is null, we already loaded individual components above

    Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Module loaded successfully" -PercentComplete 50
}
catch {
    Write-Error "Failed to load AD-Scout module: $_"
    return
}
#endregion

#region Execute Scan
Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Running security assessment..." -PercentComplete 60

$scanParams = @{}

if ($Domain) { $scanParams.Domain = $Domain }
if ($Server) { $scanParams.Server = $Server }
if ($Credential) { $scanParams.Credential = $Credential }
if ($Category -and $Category -ne 'All') { $scanParams.Category = $Category }

# Quick scan uses only Critical and High severity rules
if ($QuickScan) {
    Write-Host "Running quick scan (Critical and High severity rules only)..." -ForegroundColor Yellow
    $scanParams.RuleId = (Get-ADScoutRule | Where-Object { $_.Severity -in @('Critical', 'High') }).Id
}

try {
    $results = Invoke-ADScoutScan @scanParams

    Write-ProgressStatus -Activity "AD-Scout Remote Execution" -Status "Assessment complete" -PercentComplete 90
}
catch {
    Write-Error "Scan failed: $_"
    return
}
finally {
    Write-Progress -Activity "AD-Scout Remote Execution" -Completed
}
#endregion

#region Output Results
if ($PassThru) {
    # Return raw objects for pipeline processing
    return $results
}

$reportParams = @{
    Format = $Format
}

if ($OutFile) {
    $reportParams.Path = $OutFile
}

if ($results) {
    $results | Export-ADScoutReport @reportParams

    # Summary
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host "Assessment Summary" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor DarkGray

    $totalScore = ($results | Measure-Object -Property Score -Sum).Sum
    $totalFindings = ($results | Measure-Object -Property FindingCount -Sum).Sum
    $rulesTriggered = $results.Count

    Write-Host "Rules Triggered : $rulesTriggered" -ForegroundColor White
    Write-Host "Total Findings  : $totalFindings" -ForegroundColor $(if ($totalFindings -gt 50) { 'Red' } elseif ($totalFindings -gt 20) { 'Yellow' } else { 'Green' })
    Write-Host "Risk Score      : $totalScore" -ForegroundColor $(if ($totalScore -gt 100) { 'Red' } elseif ($totalScore -gt 50) { 'Yellow' } else { 'Green' })

    if ($OutFile) {
        Write-Host ""
        Write-Host "Report saved to: $OutFile" -ForegroundColor Green
    }

    # Category breakdown
    Write-Host ""
    Write-Host "Findings by Category:" -ForegroundColor Cyan
    $results | Group-Object Category | ForEach-Object {
        $catFindings = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
        Write-Host "  $($_.Name): $catFindings findings" -ForegroundColor Gray
    }
}
else {
    Write-Host "No security findings detected. Your AD configuration looks good!" -ForegroundColor Green
}
#endregion

#region Cleanup Banner
if (-not $SkipBanner) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host "AD-Scout assessment complete." -ForegroundColor Green
    Write-Host "For detailed remediation guidance, use: Get-ADScoutRemediation" -ForegroundColor Gray
    Write-Host "=" * 60 -ForegroundColor DarkGray
}
#endregion

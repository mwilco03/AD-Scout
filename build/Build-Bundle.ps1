#Requires -Version 5.1
<#
.SYNOPSIS
    Builds AD-Scout into a single bundled PowerShell script for IWR execution.

.DESCRIPTION
    Creates a self-contained PowerShell script that includes all module components.
    This bundle can be hosted and executed via: iwr <url> | iex

    The bundle includes:
    - All private helper functions
    - All public cmdlets
    - All security rules
    - All reporters
    - Module configuration

.PARAMETER OutputPath
    Directory to output the bundle. Defaults to ./dist

.PARAMETER FileName
    Name of the output bundle file. Defaults to ADScout.bundle.ps1

.PARAMETER Minify
    Remove comments and extra whitespace to reduce file size.

.PARAMETER IncludeRules
    Which rule categories to include. Defaults to all.
    Use this to create smaller focused bundles.

.EXAMPLE
    ./Build-Bundle.ps1
    Creates ./dist/ADScout.bundle.ps1 with all components.

.EXAMPLE
    ./Build-Bundle.ps1 -Minify -OutputPath ./release
    Creates a minified bundle in the release directory.

.EXAMPLE
    ./Build-Bundle.ps1 -IncludeRules Anomalies, PrivilegedAccounts
    Creates a bundle with only specific rule categories.

.NOTES
    Author: AD-Scout Contributors
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '../dist'),

    [Parameter()]
    [string]$FileName = 'ADScout.bundle.ps1',

    [Parameter()]
    [switch]$Minify,

    [Parameter()]
    [string[]]$IncludeRules
)

$ErrorActionPreference = 'Stop'

Write-Host "Building AD-Scout Bundle" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

# Paths
$srcPath = Join-Path $PSScriptRoot '../src/ADScout'
$bundlePath = Join-Path $OutputPath $FileName

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Read manifest for version info
$manifestPath = Join-Path $srcPath 'ADScout.psd1'
$manifest = Import-PowerShellDataFile $manifestPath
$version = $manifest.ModuleVersion

Write-Host "Version: $version" -ForegroundColor White
Write-Host "Output: $bundlePath" -ForegroundColor White
Write-Host ""

# Initialize bundle content
$bundleContent = [System.Text.StringBuilder]::new()

# Add bundle header
$header = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Scout Security Assessment Bundle v$version

.DESCRIPTION
    Self-contained AD-Scout module for fileless execution.
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUtc)

    Usage:
        iwr https://raw.githubusercontent.com/<org>/AD-Scout/main/dist/ADScout.bundle.ps1 | iex
        Invoke-ADScoutScan | Export-ADScoutReport -Format Console

.NOTES
    This is an auto-generated bundle. Do not edit directly.
    Source: https://github.com/mwilco03/AD-Scout
    License: MIT
#>

# Suppress progress bars during load
`$ProgressPreference = 'SilentlyContinue'

"@

[void]$bundleContent.Append($header)

# Function to read and optionally minify a script file
function Get-ScriptContent {
    param(
        [string]$Path,
        [switch]$Minify
    )

    $content = Get-Content $Path -Raw

    if ($Minify) {
        # Remove block comments
        $content = $content -replace '<#[\s\S]*?#>', ''
        # Remove line comments (but not inside strings)
        $content = $content -replace '(?m)^\s*#(?!Requires).*$', ''
        # Remove empty lines
        $content = $content -replace '(?m)^\s*$\n', ''
        # Trim whitespace
        $content = $content.Trim()
    }

    return $content
}

# Track loaded scripts to avoid duplicates
$loadedScripts = @{}

# Helper to add a script section
function Add-ScriptSection {
    param(
        [string]$Name,
        [string]$Content
    )

    [void]$bundleContent.AppendLine("#region $Name")
    [void]$bundleContent.AppendLine($Content)
    [void]$bundleContent.AppendLine("#endregion $Name")
    [void]$bundleContent.AppendLine("")
}

Write-Host "Loading module components..." -ForegroundColor Yellow

# 1. Load Private functions first (dependencies)
Write-Host "  Loading private functions..." -ForegroundColor Gray
$privateFiles = Get-ChildItem -Path "$srcPath/Private" -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
$privateContent = [System.Text.StringBuilder]::new()

foreach ($file in ($privateFiles | Sort-Object FullName)) {
    if ($loadedScripts.ContainsKey($file.FullName)) { continue }
    $loadedScripts[$file.FullName] = $true

    Write-Verbose "  Adding: $($file.Name)"
    $scriptContent = Get-ScriptContent -Path $file.FullName -Minify:$Minify
    [void]$privateContent.AppendLine("# Source: $($file.Name)")
    [void]$privateContent.AppendLine($scriptContent)
    [void]$privateContent.AppendLine("")
}

Add-ScriptSection -Name "Private Functions" -Content $privateContent.ToString()

# 2. Load Public functions
Write-Host "  Loading public functions..." -ForegroundColor Gray
$publicFiles = Get-ChildItem -Path "$srcPath/Public" -Filter '*.ps1' -ErrorAction SilentlyContinue
$publicContent = [System.Text.StringBuilder]::new()
$exportedFunctions = @()

foreach ($file in ($publicFiles | Sort-Object Name)) {
    if ($loadedScripts.ContainsKey($file.FullName)) { continue }
    $loadedScripts[$file.FullName] = $true

    Write-Verbose "  Adding: $($file.Name)"
    $scriptContent = Get-ScriptContent -Path $file.FullName -Minify:$Minify
    [void]$publicContent.AppendLine("# Source: $($file.Name)")
    [void]$publicContent.AppendLine($scriptContent)
    [void]$publicContent.AppendLine("")

    $exportedFunctions += $file.BaseName
}

Add-ScriptSection -Name "Public Functions" -Content $publicContent.ToString()

# 3. Load Rules
Write-Host "  Loading security rules..." -ForegroundColor Gray
$rulesPath = "$srcPath/Rules"
$rulesContent = [System.Text.StringBuilder]::new()

# Initialize rules collection
[void]$rulesContent.AppendLine('$script:ADScoutBundledRules = @()')
[void]$rulesContent.AppendLine('')

# Get rule categories to include
$ruleCategories = if ($IncludeRules) {
    $IncludeRules
}
else {
    Get-ChildItem -Path $rulesPath -Directory | Select-Object -ExpandProperty Name
}

$ruleCount = 0
foreach ($category in $ruleCategories) {
    $categoryPath = Join-Path $rulesPath $category
    if (-not (Test-Path $categoryPath)) {
        Write-Warning "Category not found: $category"
        continue
    }

    $ruleFiles = Get-ChildItem -Path $categoryPath -Filter '*.ps1' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -ne '_RuleTemplate.ps1' }

    foreach ($file in $ruleFiles) {
        Write-Verbose "  Adding rule: $($file.Name)"
        $scriptContent = Get-ScriptContent -Path $file.FullName -Minify:$Minify

        [void]$rulesContent.AppendLine("# Rule: $($file.BaseName) (Category: $category)")
        [void]$rulesContent.AppendLine('$script:ADScoutBundledRules += $(')
        [void]$rulesContent.AppendLine($scriptContent)
        [void]$rulesContent.AppendLine(')')
        [void]$rulesContent.AppendLine('')

        $ruleCount++
    }
}

Write-Host "  Loaded $ruleCount rules" -ForegroundColor Gray

Add-ScriptSection -Name "Security Rules" -Content $rulesContent.ToString()

# 4. Load Reporters
Write-Host "  Loading reporters..." -ForegroundColor Gray
$reportersPath = "$srcPath/Reporters"
$reporterFiles = Get-ChildItem -Path $reportersPath -Filter '*.ps1' -ErrorAction SilentlyContinue
$reportersContent = [System.Text.StringBuilder]::new()

foreach ($file in $reporterFiles) {
    Write-Verbose "  Adding: $($file.Name)"
    $scriptContent = Get-ScriptContent -Path $file.FullName -Minify:$Minify
    [void]$reportersContent.AppendLine("# Reporter: $($file.BaseName)")
    [void]$reportersContent.AppendLine($scriptContent)
    [void]$reportersContent.AppendLine('')
}

Add-ScriptSection -Name "Reporters" -Content $reportersContent.ToString()

# 5. Load Templates (embed as here-strings)
Write-Host "  Loading templates..." -ForegroundColor Gray
$templatesPath = "$srcPath/Templates"
$templatesContent = [System.Text.StringBuilder]::new()

[void]$templatesContent.AppendLine('$script:ADScoutTemplates = @{}')
[void]$templatesContent.AppendLine('')

if (Test-Path $templatesPath) {
    $templateFiles = Get-ChildItem -Path $templatesPath -File -ErrorAction SilentlyContinue

    foreach ($file in $templateFiles) {
        Write-Verbose "  Embedding: $($file.Name)"
        $templateContent = Get-Content $file.FullName -Raw

        # Escape for here-string embedding
        $escapedContent = $templateContent -replace "'", "''"

        [void]$templatesContent.AppendLine("`$script:ADScoutTemplates['$($file.Name)'] = @'")
        [void]$templatesContent.AppendLine($templateContent)
        [void]$templatesContent.AppendLine("'@")
        [void]$templatesContent.AppendLine('')
    }
}

Add-ScriptSection -Name "Templates" -Content $templatesContent.ToString()

# 6. Add module configuration and initialization
Write-Host "  Adding module initialization..." -ForegroundColor Gray
$initContent = @"
# Module Configuration
`$script:ADScoutConfig = @{
    ParallelThrottleLimit = [Environment]::ProcessorCount
    DefaultReporter       = 'Console'
    RulePaths             = @()
    CacheTTL              = 300
    LogLevel              = 'Warning'
    IsBundled             = `$true
    BundleVersion         = '$version'
}

# Module Cache
`$script:ADScoutCache = @{
    Data       = @{}
    Timestamps = @{}
}

# Override Get-ADScoutRule for bundled mode
if (-not (Get-Command Get-ADScoutRule -ErrorAction SilentlyContinue)) {
    function Get-ADScoutRule {
        [CmdletBinding()]
        param(
            [string[]]`$Category,
            [string[]]`$Id,
            [string[]]`$Severity
        )

        `$rules = `$script:ADScoutBundledRules

        if (`$Category) {
            `$rules = `$rules | Where-Object { `$_.Category -in `$Category }
        }
        if (`$Id) {
            `$rules = `$rules | Where-Object { `$_.Id -in `$Id }
        }
        if (`$Severity) {
            `$rules = `$rules | Where-Object { `$_.Severity -in `$Severity }
        }

        return `$rules
    }
}

# Restore progress preference
`$ProgressPreference = 'Continue'

Write-Verbose "AD-Scout bundle v$version loaded successfully. $ruleCount rules available."
"@

Add-ScriptSection -Name "Initialization" -Content $initContent

# Write bundle to file
Write-Host ""
Write-Host "Writing bundle..." -ForegroundColor Yellow
$bundleContent.ToString() | Set-Content -Path $bundlePath -Encoding UTF8 -Force

# Calculate stats
$bundleSize = (Get-Item $bundlePath).Length
$bundleSizeKB = [math]::Round($bundleSize / 1KB, 2)
$bundleSizeMB = [math]::Round($bundleSize / 1MB, 2)

Write-Host ""
Write-Host "Bundle created successfully!" -ForegroundColor Green
Write-Host "  Path: $bundlePath" -ForegroundColor White
Write-Host "  Size: $bundleSizeKB KB ($bundleSizeMB MB)" -ForegroundColor White
Write-Host "  Rules: $ruleCount" -ForegroundColor White
Write-Host "  Functions: $($exportedFunctions.Count)" -ForegroundColor White

# Validation
Write-Host ""
Write-Host "Validating bundle..." -ForegroundColor Yellow

try {
    $null = [scriptblock]::Create((Get-Content $bundlePath -Raw))
    Write-Host "  Syntax validation: PASSED" -ForegroundColor Green
}
catch {
    Write-Host "  Syntax validation: FAILED" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

# Output usage instructions
Write-Host ""
Write-Host "Usage Instructions:" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Host the bundle on a web server or use raw GitHub URL" -ForegroundColor White
Write-Host ""
Write-Host "2. Execute remotely with:" -ForegroundColor White
Write-Host '   iwr https://raw.githubusercontent.com/<org>/AD-Scout/main/dist/ADScout.bundle.ps1 | iex' -ForegroundColor Yellow
Write-Host '   Invoke-ADScoutScan | Export-ADScoutReport' -ForegroundColor Yellow
Write-Host ""
Write-Host "3. Or use the launcher script:" -ForegroundColor White
Write-Host '   iwr https://raw.githubusercontent.com/<org>/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex' -ForegroundColor Yellow
Write-Host ""

# Return bundle info
[PSCustomObject]@{
    Path          = $bundlePath
    Size          = $bundleSize
    SizeKB        = $bundleSizeKB
    RuleCount     = $ruleCount
    FunctionCount = $exportedFunctions.Count
    Version       = $version
}

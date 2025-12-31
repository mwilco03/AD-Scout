#Requires -Version 5.1
<#
.SYNOPSIS
    Publishes AD-Scout to the PowerShell Gallery.

.DESCRIPTION
    Builds the module and publishes it to PSGallery.
    Requires PSGALLERY_API_KEY environment variable or -ApiKey parameter.

.PARAMETER ApiKey
    NuGet API key for PowerShell Gallery.

.PARAMETER WhatIf
    Show what would be published without actually publishing.

.EXAMPLE
    ./Publish-Module.ps1 -ApiKey $env:PSGALLERY_API_KEY
    Publishes to PSGallery
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ApiKey = $env:PSGALLERY_API_KEY,

    [Parameter()]
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

Write-Host "Publishing AD-Scout to PowerShell Gallery" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Validate API key
if (-not $ApiKey) {
    throw "API key is required. Set PSGALLERY_API_KEY environment variable or use -ApiKey parameter."
}

# Run tests first
if (-not $SkipTests) {
    Write-Host "`nRunning tests..." -ForegroundColor Yellow

    if (-not (Get-Module -ListAvailable Pester)) {
        Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
    }

    $testResults = Invoke-Pester -Path (Join-Path $PSScriptRoot '../tests') -PassThru -Output Minimal

    if ($testResults.FailedCount -gt 0) {
        throw "Tests failed! $($testResults.FailedCount) test(s) failed."
    }

    Write-Host "All tests passed." -ForegroundColor Green
}

# Build module
Write-Host "`nBuilding module..." -ForegroundColor Yellow
$buildResult = & (Join-Path $PSScriptRoot 'Build-Module.ps1')

# Get module info
$manifestPath = Join-Path $buildResult.Path 'ADScout.psd1'
$manifest = Import-PowerShellDataFile $manifestPath

Write-Host "`nModule: $($manifest.ModuleVersion)" -ForegroundColor White
Write-Host "Path: $($buildResult.Path)" -ForegroundColor White

# Check if version already exists
Write-Host "`nChecking PSGallery for existing version..." -ForegroundColor Yellow
$existingModule = Find-Module -Name ADScout -ErrorAction SilentlyContinue

if ($existingModule -and $existingModule.Version -ge [version]$manifest.ModuleVersion) {
    throw "Version $($manifest.ModuleVersion) already exists in PSGallery. Update ModuleVersion in manifest."
}

# Publish
if ($PSCmdlet.ShouldProcess("ADScout $($manifest.ModuleVersion)", "Publish to PSGallery")) {
    Write-Host "`nPublishing to PSGallery..." -ForegroundColor Yellow

    Publish-Module -Path $buildResult.Path -NuGetApiKey $ApiKey -Repository PSGallery -Verbose

    Write-Host "`nPublished successfully!" -ForegroundColor Green
    Write-Host "View at: https://www.powershellgallery.com/packages/ADScout/$($manifest.ModuleVersion)" -ForegroundColor Cyan
}

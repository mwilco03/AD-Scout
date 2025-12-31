#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the AD-Scout module for distribution.

.DESCRIPTION
    Prepares the module for publishing by copying files to an output directory,
    updating version information, and creating a ZIP archive.

.PARAMETER OutputPath
    The directory where the built module will be placed.

.PARAMETER Version
    Override the version number. If not specified, uses the manifest version.

.PARAMETER CreateZip
    Create a ZIP archive of the module.

.EXAMPLE
    ./Build-Module.ps1
    Builds the module to ./output/ADScout

.EXAMPLE
    ./Build-Module.ps1 -OutputPath ./dist -CreateZip
    Builds and creates a ZIP archive
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '../output'),

    [Parameter()]
    [version]$Version,

    [Parameter()]
    [switch]$CreateZip
)

$ErrorActionPreference = 'Stop'

Write-Host "Building AD-Scout Module" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

# Paths
$srcPath = Join-Path $PSScriptRoot '../src/ADScout'
$modulePath = Join-Path $OutputPath 'ADScout'

# Clean output directory
if (Test-Path $modulePath) {
    Write-Host "Cleaning output directory..." -ForegroundColor Yellow
    Remove-Item $modulePath -Recurse -Force
}

New-Item -Path $modulePath -ItemType Directory -Force | Out-Null

# Read manifest
$manifestPath = Join-Path $srcPath 'ADScout.psd1'
$manifest = Import-PowerShellDataFile $manifestPath

$currentVersion = if ($Version) { $Version } else { [version]$manifest.ModuleVersion }

Write-Host "Version: $currentVersion" -ForegroundColor White
Write-Host "Output: $modulePath" -ForegroundColor White

# Copy module files
Write-Host "`nCopying files..." -ForegroundColor Yellow

$filesToCopy = @(
    'ADScout.psd1'
    'ADScout.psm1'
    'Public'
    'Private'
    'Rules'
    'Reporters'
    'Schemas'
    'Templates'
    'en-US'
)

foreach ($item in $filesToCopy) {
    $source = Join-Path $srcPath $item
    if (Test-Path $source) {
        $dest = Join-Path $modulePath $item
        if ((Get-Item $source).PSIsContainer) {
            Copy-Item $source $dest -Recurse -Force
        }
        else {
            Copy-Item $source $dest -Force
        }
        Write-Host "  Copied: $item" -ForegroundColor Gray
    }
}

# Update version in manifest if specified
if ($Version) {
    Write-Host "`nUpdating version to $Version..." -ForegroundColor Yellow
    $manifestContent = Get-Content (Join-Path $modulePath 'ADScout.psd1') -Raw
    $manifestContent = $manifestContent -replace "ModuleVersion\s*=\s*'[\d\.]+'", "ModuleVersion = '$Version'"
    $manifestContent | Set-Content (Join-Path $modulePath 'ADScout.psd1') -Encoding UTF8
}

# Validate module
Write-Host "`nValidating module..." -ForegroundColor Yellow
$testManifest = Test-ModuleManifest -Path (Join-Path $modulePath 'ADScout.psd1') -ErrorAction Stop
Write-Host "  Module: $($testManifest.Name)" -ForegroundColor Gray
Write-Host "  Version: $($testManifest.Version)" -ForegroundColor Gray
Write-Host "  Exported commands: $($testManifest.ExportedFunctions.Count)" -ForegroundColor Gray

# Create ZIP if requested
if ($CreateZip) {
    Write-Host "`nCreating ZIP archive..." -ForegroundColor Yellow
    $zipPath = Join-Path $OutputPath "ADScout-$currentVersion.zip"
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path $modulePath -DestinationPath $zipPath -Force
    Write-Host "  Created: $zipPath" -ForegroundColor Gray
}

Write-Host "`nBuild complete!" -ForegroundColor Green
Write-Host "Module path: $modulePath" -ForegroundColor White

# Return module info
[PSCustomObject]@{
    Name    = 'ADScout'
    Version = $currentVersion
    Path    = $modulePath
    ZipPath = if ($CreateZip) { $zipPath } else { $null }
}

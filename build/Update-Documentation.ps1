#Requires -Version 5.1
<#
.SYNOPSIS
    Generates documentation from module source.

.DESCRIPTION
    Uses PlatyPS to generate markdown documentation from the module's
    comment-based help.

.PARAMETER OutputPath
    Directory for generated documentation.

.EXAMPLE
    ./Update-Documentation.ps1
    Generates docs in ./docs
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '../docs')
)

$ErrorActionPreference = 'Stop'

Write-Host "Generating AD-Scout Documentation" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Check for PlatyPS
if (-not (Get-Module -ListAvailable PlatyPS)) {
    Write-Host "Installing PlatyPS..." -ForegroundColor Yellow
    Install-Module PlatyPS -Force -Scope CurrentUser
}

Import-Module PlatyPS -Force

# Import module
$modulePath = Join-Path $PSScriptRoot '../src/ADScout/ADScout.psd1'
Write-Host "Importing module from: $modulePath" -ForegroundColor Yellow
Import-Module $modulePath -Force

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Generate markdown help
Write-Host "`nGenerating command documentation..." -ForegroundColor Yellow
New-MarkdownHelp -Module ADScout -OutputFolder $OutputPath -Force -NoMetadata

# List generated files
$generatedFiles = Get-ChildItem $OutputPath -Filter '*.md'
Write-Host "`nGenerated files:" -ForegroundColor Green
$generatedFiles | ForEach-Object {
    Write-Host "  $($_.Name)" -ForegroundColor Gray
}

# Generate index
Write-Host "`nGenerating index..." -ForegroundColor Yellow
$commands = Get-Command -Module ADScout | Sort-Object Name
$indexContent = @"
# AD-Scout Documentation

Auto-generated documentation for AD-Scout cmdlets.

## Commands

| Command | Description |
|---------|-------------|
"@

foreach ($cmd in $commands) {
    $help = Get-Help $cmd.Name -ErrorAction SilentlyContinue
    $description = if ($help.Synopsis) { $help.Synopsis } else { 'No description' }
    $indexContent += "`n| [$($cmd.Name)]($($cmd.Name).md) | $description |"
}

$indexContent += @"


## Getting Started

See the main [README](../README.md) for installation and quick start.

## Rule Categories

- **Anomalies** - Unusual configurations that may indicate compromise
- **StaleObjects** - Dormant accounts, unused computers, orphaned objects
- **PrivilegedAccounts** - Excessive privileges, dangerous delegations
- **Trusts** - Insecure trust relationships

## Contributing

See [CONTRIBUTING](../CONTRIBUTING.md) for how to add new rules and features.
"@

$indexContent | Out-File (Join-Path $OutputPath 'README.md') -Encoding UTF8

Write-Host "`nDocumentation complete!" -ForegroundColor Green
Write-Host "Output: $OutputPath" -ForegroundColor White

#Requires -Version 5.1

<#
.SYNOPSIS
    AD-Scout module loader.

.DESCRIPTION
    Loads all public and private functions for the AD-Scout module.
    Initializes module-level configuration and registers argument completers.

.NOTES
    Author: AD-Scout Contributors
    License: MIT
#>

# Get public, private, and reporter function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/**/*.ps1" -Recurse -ErrorAction SilentlyContinue)
$Reporters = @(Get-ChildItem -Path "$PSScriptRoot/Reporters/*.ps1" -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($file in @($Private + $Public + $Reporters)) {
    try {
        Write-Verbose "Importing $($file.FullName)"
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import $($file.FullName): $_"
    }
}

# Export public functions and reporters
$ExportedFunctions = @($Public.BaseName) + @($Reporters.BaseName)
Export-ModuleMember -Function $ExportedFunctions

# Module-level configuration with defaults
$script:ADScoutConfig = @{
    ParallelThrottleLimit = [Environment]::ProcessorCount
    DefaultReporter       = 'Console'
    RulePaths            = @()
    CacheTTL             = 300  # seconds
    LogLevel             = 'Warning'
    DefaultDomain        = $null
    DefaultServer        = $null
    ExcludedRules        = @()
    ReportOutputPath     = $null
}

# Load persisted configuration on module import
$script:ADScoutConfigPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.adscout/config.json'
if (Test-Path $script:ADScoutConfigPath) {
    try {
        $persistedConfig = Get-Content $script:ADScoutConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
        # Merge persisted settings into defaults (persisted values override defaults)
        foreach ($prop in $persistedConfig.PSObject.Properties) {
            if ($script:ADScoutConfig.ContainsKey($prop.Name)) {
                $script:ADScoutConfig[$prop.Name] = $prop.Value
            }
        }
        Write-Verbose "Loaded persisted configuration from $script:ADScoutConfigPath"
    }
    catch {
        Write-Warning "Failed to load persisted configuration: $_"
    }
}

# Module-level cache
$script:ADScoutCache = @{
    Data       = @{}
    Timestamps = @{}
}

# Load module constants from configuration file
$script:ADScoutConstants = $null
$constantsPath = Join-Path $PSScriptRoot 'Config/ADScoutConstants.psd1'
if (Test-Path $constantsPath) {
    try {
        $script:ADScoutConstants = Import-PowerShellDataFile $constantsPath
        Write-Verbose "Loaded module constants from $constantsPath"
    }
    catch {
        Write-Warning "Failed to load module constants: $_"
    }
}

# Load well-known SIDs data
$script:ADScoutSidData = $null
$sidDataPath = Join-Path $PSScriptRoot 'Data/WellKnownSids.json'
if (Test-Path $sidDataPath) {
    try {
        $script:ADScoutSidData = Get-Content $sidDataPath -Raw | ConvertFrom-Json -ErrorAction Stop
        Write-Verbose "Loaded well-known SID data from $sidDataPath"
    }
    catch {
        Write-Warning "Failed to load well-known SID data: $_"
    }
}

# Get categories from constants or use fallback
$script:ADScoutCategories = if ($script:ADScoutConstants -and $script:ADScoutConstants.Categories) {
    $script:ADScoutConstants.Categories
}
else {
    @('Anomalies', 'AttackVectors', 'Authentication', 'DataProtection', 'EntraID',
      'EphemeralPersistence', 'GPO', 'Infrastructure', 'Kerberos', 'LateralMovement',
      'Logging', 'PKI', 'Persistence', 'PrivilegedAccess', 'ServiceAccounts',
      'StaleObjects', 'Trusts')
}

# Register argument completers using centralized categories
Register-ArgumentCompleter -CommandName Invoke-ADScoutScan -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    (@($script:ADScoutCategories) + @('All')) |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Export-ADScoutReport -ParameterName Format -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('HTML', 'JSON', 'CSV', 'SARIF', 'Markdown', 'Console', 'BloodHound') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Get-ADScoutRule -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $script:ADScoutCategories |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Get-ADScoutRule -ParameterName Id -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    # Get all rule IDs from loaded rules
    $rulePaths = Get-ADScoutRulePaths -ErrorAction SilentlyContinue
    if ($rulePaths) {
        Get-ChildItem -Path $rulePaths -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne '_RuleTemplate.ps1' } |
            ForEach-Object {
                try {
                    $rule = . $_.FullName
                    if ($rule.Id -like "$wordToComplete*") {
                        # Handle both Name and Title schemas
                        $ruleName = if ($rule.Name) { $rule.Name } else { $rule.Title }
                        [System.Management.Automation.CompletionResult]::new($rule.Id, $rule.Id, 'ParameterValue', $ruleName)
                    }
                }
                catch { }
            }
    }
}

# Initialize verbose message
Write-Verbose "AD-Scout module loaded. Use 'Get-ADScoutRule' to see available rules."

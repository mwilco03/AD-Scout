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

# Get public and private function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/**/*.ps1" -Recurse -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($file in @($Private + $Public)) {
    try {
        Write-Verbose "Importing $($file.FullName)"
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import $($file.FullName): $_"
    }
}

# Build list of functions to export
# Include all functions from Public/*.ps1 files (by parsing their content)
$ExportFunctions = [System.Collections.Generic.List[string]]::new()

foreach ($file in $Public) {
    try {
        $content = Get-Content -Path $file.FullName -Raw
        # Find all function definitions in the file
        $matches = [regex]::Matches($content, '^\s*function\s+([A-Za-z][\w-]+)', 'Multiline')
        foreach ($match in $matches) {
            $funcName = $match.Groups[1].Value
            if ($funcName -and -not $ExportFunctions.Contains($funcName)) {
                $ExportFunctions.Add($funcName)
            }
        }
    }
    catch {
        Write-Verbose "Could not parse $($file.Name) for functions: $_"
        # Fallback to basename
        if (-not $ExportFunctions.Contains($file.BaseName)) {
            $ExportFunctions.Add($file.BaseName)
        }
    }
}

# Add EDR functions defined in Private that should be public
$EDRPublicFunctions = @(
    'Get-ADScoutEDRProvider',
    'Get-ADScoutEDRTemplate',
    'Register-ADScoutEDRProvider',
    'Test-ADScoutEDRMultiSessionMode'
)
foreach ($func in $EDRPublicFunctions) {
    if (-not $ExportFunctions.Contains($func)) {
        $ExportFunctions.Add($func)
    }
}

# Export all collected functions
Export-ModuleMember -Function $ExportFunctions

# Module-level configuration
$script:ADScoutConfig = @{
    ParallelThrottleLimit = [Environment]::ProcessorCount
    DefaultReporter       = 'Console'
    RulePaths            = @()
    CacheTTL             = 300  # seconds
    LogLevel             = 'Warning'
}

# Module-level cache
$script:ADScoutCache = @{
    Data       = @{}
    Timestamps = @{}
}

# Register argument completers
Register-ArgumentCompleter -CommandName Invoke-ADScoutScan -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI', 'EntraID', 'EndpointSecurity', 'All') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Export-ADScoutReport -ParameterName Format -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('HTML', 'JSON', 'CSV', 'SARIF', 'Markdown', 'Console') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

Register-ArgumentCompleter -CommandName Get-ADScoutRule -ParameterName Category -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI', 'EntraID', 'EndpointSecurity') |
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

# EDR Template argument completer
Register-ArgumentCompleter -CommandName Invoke-ADScoutEDRCommand -ParameterName Template -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    if ($script:EDRTemplates) {
        $script:EDRTemplates.Values |
            Where-Object { $_.Id -like "$wordToComplete*" -or $_.Name -like "$wordToComplete*" } |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Id, $_.Id, 'ParameterValue', $_.Description)
            }
    }
}

Register-ArgumentCompleter -CommandName Invoke-ADScoutEDRCollection -ParameterName Template -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    if ($script:EDRTemplates) {
        $script:EDRTemplates.Values |
            Where-Object { $_.Id -like "$wordToComplete*" -or $_.Name -like "$wordToComplete*" } |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Id, $_.Id, 'ParameterValue', $_.Description)
            }
    }
}

# EDR Provider argument completer
Register-ArgumentCompleter -CommandName Connect-ADScoutEDR -ParameterName Provider -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('PSFalcon', 'DefenderATP', 'MDE', 'CarbonBlack') |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

# Initialize verbose message
Write-Verbose "AD-Scout module loaded. Use 'Get-ADScoutRule' to see available rules."

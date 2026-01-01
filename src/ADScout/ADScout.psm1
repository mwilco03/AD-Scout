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

# Export public functions
Export-ModuleMember -Function $Public.BaseName

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
    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'All') |
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
    @('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts') |
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
                        [System.Management.Automation.CompletionResult]::new($rule.Id, $rule.Id, 'ParameterValue', $rule.Name)
                    }
                }
                catch { }
            }
    }
}

# Initialize verbose message
Write-Verbose "AD-Scout module loaded. Use 'Get-ADScoutRule' to see available rules."

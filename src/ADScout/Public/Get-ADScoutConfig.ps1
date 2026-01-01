function Get-ADScoutConfig {
    <#
    .SYNOPSIS
        Gets current AD-Scout configuration.

    .DESCRIPTION
        Retrieves the current AD-Scout configuration settings.
        Shows both runtime settings and persisted configuration.

    .PARAMETER Name
        Specific setting name to retrieve. If not specified, returns all settings.

    .PARAMETER IncludePersisted
        Also show settings from the persisted configuration file.

    .EXAMPLE
        Get-ADScoutConfig
        Returns all current configuration settings.

    .EXAMPLE
        Get-ADScoutConfig -Name ParallelThrottleLimit
        Returns the specific setting value.

    .EXAMPLE
        Get-ADScoutConfig -IncludePersisted
        Returns current settings and shows persisted values.

    .OUTPUTS
        PSCustomObject
        Configuration settings.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateSet('ParallelThrottleLimit', 'DefaultReporter', 'RulePaths', 'CacheTTL', 'LogLevel')]
        [string]$Name,

        [Parameter()]
        [switch]$IncludePersisted
    )

    process {
        $config = [PSCustomObject]@{
            PSTypeName            = 'ADScoutConfig'
            ParallelThrottleLimit = $script:ADScoutConfig.ParallelThrottleLimit
            DefaultReporter       = $script:ADScoutConfig.DefaultReporter
            RulePaths            = $script:ADScoutConfig.RulePaths
            CacheTTL             = $script:ADScoutConfig.CacheTTL
            LogLevel             = $script:ADScoutConfig.LogLevel
        }

        if ($IncludePersisted) {
            $configPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.adscout/config.json'

            if (Test-Path $configPath) {
                try {
                    $persistedConfig = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
                    $config | Add-Member -NotePropertyName 'PersistedConfig' -NotePropertyValue $persistedConfig
                    $config | Add-Member -NotePropertyName 'ConfigPath' -NotePropertyValue $configPath
                }
                catch {
                    Write-Warning "Failed to read persisted config: $_"
                }
            }
            else {
                $config | Add-Member -NotePropertyName 'PersistedConfig' -NotePropertyValue $null
                $config | Add-Member -NotePropertyName 'ConfigPath' -NotePropertyValue $configPath
            }
        }

        if ($Name) {
            $config.$Name
        }
        else {
            $config
        }
    }
}

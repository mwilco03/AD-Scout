function Get-ADScoutRulePaths {
    <#
    .SYNOPSIS
        Gets the list of paths to search for rules.

    .DESCRIPTION
        Returns all configured rule paths in priority order.
        Later paths take precedence over earlier paths for duplicate rule IDs.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $paths = @()

    # 1. Built-in rules (lowest priority)
    $modulePath = Split-Path -Parent $PSScriptRoot
    $builtInPath = Join-Path $modulePath 'Rules'
    if (Test-Path $builtInPath) {
        $paths += $builtInPath
    }

    # 2. Environment variable paths
    $envPaths = $env:ADSCOUT_RULE_PATHS
    if ($envPaths) {
        $envPaths.Split([IO.Path]::PathSeparator) | ForEach-Object {
            if (Test-Path $_) {
                $paths += $_
            }
        }
    }

    # 3. Configuration file paths
    $configPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.adscout/config.json'
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
            if ($config.RulePaths) {
                $config.RulePaths | ForEach-Object {
                    if (Test-Path $_) {
                        $paths += $_
                    }
                }
            }
        }
        catch {
            Write-Verbose "Failed to read config file: $_"
        }
    }

    # 4. Session-registered paths (highest priority)
    if ($script:ADScoutConfig.RulePaths) {
        $paths += $script:ADScoutConfig.RulePaths
    }

    Write-Verbose "Rule search paths: $($paths -join ', ')"

    return $paths
}

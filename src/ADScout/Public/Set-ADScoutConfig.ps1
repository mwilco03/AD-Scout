function Set-ADScoutConfig {
    <#
    .SYNOPSIS
        Sets AD-Scout configuration options.

    .DESCRIPTION
        Configures AD-Scout module settings. Settings can be persisted
        to disk for use across sessions.

    .PARAMETER ParallelThrottleLimit
        Maximum number of parallel operations.

    .PARAMETER DefaultReporter
        Default output format for reports.

    .PARAMETER CacheTTL
        Cache time-to-live in seconds.

    .PARAMETER LogLevel
        Logging verbosity level.

    .PARAMETER Persist
        Save settings to configuration file.

    .EXAMPLE
        Set-ADScoutConfig -ParallelThrottleLimit 8
        Sets the parallel throttle limit for the current session.

    .EXAMPLE
        Set-ADScoutConfig -DefaultReporter HTML -Persist
        Sets the default reporter and persists the setting.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ParallelThrottleLimit,

        [Parameter()]
        [ValidateSet('Console', 'HTML', 'JSON', 'CSV', 'SARIF', 'Markdown')]
        [string]$DefaultReporter,

        [Parameter()]
        [ValidateRange(0, 86400)]
        [int]$CacheTTL,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')]
        [string]$LogLevel,

        [Parameter()]
        [switch]$Persist
    )

    process {
        $changes = @{}

        if ($PSBoundParameters.ContainsKey('ParallelThrottleLimit')) {
            if ($PSCmdlet.ShouldProcess('ParallelThrottleLimit', "Set to $ParallelThrottleLimit")) {
                $script:ADScoutConfig.ParallelThrottleLimit = $ParallelThrottleLimit
                $changes.ParallelThrottleLimit = $ParallelThrottleLimit
                Write-Verbose "Set ParallelThrottleLimit to $ParallelThrottleLimit"
            }
        }

        if ($PSBoundParameters.ContainsKey('DefaultReporter')) {
            if ($PSCmdlet.ShouldProcess('DefaultReporter', "Set to $DefaultReporter")) {
                $script:ADScoutConfig.DefaultReporter = $DefaultReporter
                $changes.DefaultReporter = $DefaultReporter
                Write-Verbose "Set DefaultReporter to $DefaultReporter"
            }
        }

        if ($PSBoundParameters.ContainsKey('CacheTTL')) {
            if ($PSCmdlet.ShouldProcess('CacheTTL', "Set to $CacheTTL")) {
                $script:ADScoutConfig.CacheTTL = $CacheTTL
                $changes.CacheTTL = $CacheTTL
                Write-Verbose "Set CacheTTL to $CacheTTL"
            }
        }

        if ($PSBoundParameters.ContainsKey('LogLevel')) {
            if ($PSCmdlet.ShouldProcess('LogLevel', "Set to $LogLevel")) {
                $script:ADScoutConfig.LogLevel = $LogLevel
                $changes.LogLevel = $LogLevel
                Write-Verbose "Set LogLevel to $LogLevel"
            }
        }

        if ($Persist -and $changes.Count -gt 0) {
            $configPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.adscout/config.json'
            $configDir = Split-Path $configPath -Parent

            if (-not (Test-Path $configDir)) {
                New-Item -Path $configDir -ItemType Directory -Force | Out-Null
            }

            if (Test-Path $configPath) {
                $existingConfig = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
            }
            else {
                $existingConfig = @{}
            }

            foreach ($key in $changes.Keys) {
                $existingConfig[$key] = $changes[$key]
            }

            $existingConfig | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8

            Write-Verbose "Configuration saved to: $configPath"
        }
    }
}

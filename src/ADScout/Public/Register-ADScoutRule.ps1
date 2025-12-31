function Register-ADScoutRule {
    <#
    .SYNOPSIS
        Registers a custom rule path for AD-Scout.

    .DESCRIPTION
        Adds a custom directory path to the list of paths that AD-Scout
        searches for rule files. This allows using custom rules without
        modifying the module installation.

    .PARAMETER Path
        The directory path containing custom rules.

    .PARAMETER Persist
        Save the path to configuration so it persists across sessions.

    .PARAMETER Remove
        Remove the path from the registered paths instead of adding it.

    .EXAMPLE
        Register-ADScoutRule -Path "C:\MyRules"
        Adds a custom rule path for the current session.

    .EXAMPLE
        Register-ADScoutRule -Path "C:\MyRules" -Persist
        Adds a custom rule path and saves it to configuration.

    .EXAMPLE
        Register-ADScoutRule -Path "C:\MyRules" -Remove
        Removes a previously registered rule path.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$Path,

        [Parameter()]
        [switch]$Persist,

        [Parameter()]
        [switch]$Remove
    )

    process {
        $resolvedPath = Resolve-Path $Path | Select-Object -ExpandProperty Path

        if ($Remove) {
            if ($PSCmdlet.ShouldProcess($resolvedPath, "Remove from rule paths")) {
                $script:ADScoutConfig.RulePaths = @($script:ADScoutConfig.RulePaths | Where-Object { $_ -ne $resolvedPath })
                Write-Verbose "Removed rule path: $resolvedPath"
            }
        }
        else {
            if ($resolvedPath -notin $script:ADScoutConfig.RulePaths) {
                if ($PSCmdlet.ShouldProcess($resolvedPath, "Add to rule paths")) {
                    $script:ADScoutConfig.RulePaths += $resolvedPath
                    Write-Verbose "Added rule path: $resolvedPath"
                }
            }
            else {
                Write-Verbose "Rule path already registered: $resolvedPath"
            }
        }

        if ($Persist) {
            # Save to configuration file
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

            $existingConfig.RulePaths = $script:ADScoutConfig.RulePaths

            $existingConfig | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8

            Write-Verbose "Saved rule paths to: $configPath"
        }
    }
}

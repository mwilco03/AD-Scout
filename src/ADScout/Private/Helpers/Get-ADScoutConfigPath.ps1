function Get-ADScoutConfigPath {
    <#
    .SYNOPSIS
        Returns the path to the AD-Scout configuration file.

    .DESCRIPTION
        Returns the standardized path to the AD-Scout configuration file.
        The configuration is stored in the user's home directory under
        .adscout/config.json.

    .PARAMETER CreateDirectory
        If specified, creates the parent directory if it doesn't exist.

    .EXAMPLE
        $configPath = Get-ADScoutConfigPath

    .EXAMPLE
        $configPath = Get-ADScoutConfigPath -CreateDirectory
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [switch]$CreateDirectory
    )

    # Use module-level cached path if available
    if ($script:ADScoutConfigPath) {
        $configPath = $script:ADScoutConfigPath
    }
    else {
        $configPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.adscout/config.json'
    }

    if ($CreateDirectory) {
        $parentDir = Split-Path $configPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
    }

    return $configPath
}

function Test-PSVersion {
    <#
    .SYNOPSIS
        Tests if the current PowerShell version meets a minimum requirement.

    .DESCRIPTION
        Compares the current PowerShell version against a specified minimum
        and returns true if the requirement is met.

    .PARAMETER MinimumVersion
        The minimum required version.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [version]$MinimumVersion
    )

    $currentVersion = $PSVersionTable.PSVersion

    Write-Verbose "Current PowerShell version: $currentVersion, Required: $MinimumVersion"

    return $currentVersion -ge $MinimumVersion
}

function Get-PSEdition {
    <#
    .SYNOPSIS
        Gets the current PowerShell edition.

    .DESCRIPTION
        Returns 'Core' for PowerShell 7+ or 'Desktop' for Windows PowerShell.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($PSVersionTable.PSEdition) {
        return $PSVersionTable.PSEdition
    }

    # Fallback for older versions
    return 'Desktop'
}

function Test-IsWindows {
    <#
    .SYNOPSIS
        Tests if running on Windows.

    .DESCRIPTION
        Returns true if running on Windows, supporting both PS 5.1 and PS 7+.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return $IsWindows
    }

    # PS 5.1 is always Windows
    return $true
}

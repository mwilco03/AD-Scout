function Write-ADScoutLog {
    <#
    .SYNOPSIS
        Writes a log message with appropriate stream.

    .DESCRIPTION
        Internal logging function that routes messages to the appropriate
        PowerShell stream based on log level.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        The log level.

    .PARAMETER Context
        Additional context object for the log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')]
        [string]$Level = 'Info',

        [Parameter()]
        [object]$Context
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formatted = "[$timestamp] [$Level] $Message"

    if ($Context) {
        $formatted += " | Context: $($Context | ConvertTo-Json -Compress -Depth 2)"
    }

    switch ($Level) {
        'Error' {
            Write-Error $formatted
        }
        'Warning' {
            Write-Warning $formatted
        }
        'Info' {
            Write-Information $formatted -InformationAction Continue
        }
        'Verbose' {
            Write-Verbose $formatted
        }
        'Debug' {
            Write-Debug $formatted
        }
    }
}

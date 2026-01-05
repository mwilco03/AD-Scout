#Requires -Version 5.1

<#
.SYNOPSIS
    Base class and interface definition for EDR provider wrappers.

.DESCRIPTION
    Defines the abstract interface that all EDR providers must implement.
    This enables security professionals without admin accounts to query
    domain controllers and endpoint configurations through EDR platforms
    like CrowdStrike Falcon, Carbon Black, Microsoft Defender, etc.

    SECURITY: EDR execution is READ-ONLY by design. Only pre-approved
    reconnaissance templates can be executed. Arbitrary script execution
    and remediation actions are blocked to prevent unintended changes.

.NOTES
    Author: AD-Scout Contributors
    License: MIT
#>

# EDR Provider interface using PowerShell class
class EDRProviderBase {
    # Provider identification
    [string]$Name
    [string]$Version
    [string]$Description

    # Connection state
    [bool]$IsConnected = $false
    [hashtable]$ConnectionContext = @{}

    # SECURITY: Read-only mode is ALWAYS enforced for EDR operations
    # This cannot be disabled - reconnaissance only, no changes
    [bool]$ReadOnlyMode = $true

    # Rate limiting and throttling
    [int]$MaxConcurrentCommands = 10
    [int]$CommandTimeoutSeconds = 300
    [int]$RetryCount = 3
    [int]$RetryDelaySeconds = 5

    # Constructor
    EDRProviderBase() {
        $this.Name = 'Base'
        $this.Version = '1.0.0'
        $this.Description = 'Abstract EDR Provider Base Class'
        $this.ReadOnlyMode = $true  # Always read-only
    }

    # Connect to the EDR platform
    # Must be overridden by implementations
    [bool] Connect([hashtable]$Parameters) {
        throw "Connect() must be implemented by derived class"
    }

    # Disconnect from the EDR platform
    [void] Disconnect() {
        throw "Disconnect() must be implemented by derived class"
    }

    # Test if connection is valid
    [bool] TestConnection() {
        throw "TestConnection() must be implemented by derived class"
    }

    # Execute a command on target host(s)
    # INTERNAL USE ONLY - called by ExecuteTemplate after validation
    # Returns: Hashtable with results per host
    [hashtable] ExecuteCommand([string]$Command, [string[]]$TargetHosts, [hashtable]$Options) {
        throw "ExecuteCommand() must be implemented by derived class"
    }

    # Execute a pre-canned command template (PUBLIC API)
    # Only allows execution of approved read-only templates
    [hashtable] ExecuteTemplate([string]$TemplateName, [string[]]$TargetHosts, [hashtable]$Parameters) {
        $template = Get-ADScoutEDRTemplate -Name $TemplateName
        if (-not $template) {
            throw "Template '$TemplateName' not found"
        }

        # SECURITY: Verify template is marked as read-only
        if ($template.IsWriteOperation -eq $true) {
            throw "SECURITY: Template '$TemplateName' is marked as a write operation and cannot be executed. EDR operations are read-only."
        }

        # Expand template with parameters
        $expandedCommand = $template.ScriptBlock
        foreach ($key in $Parameters.Keys) {
            $expandedCommand = $expandedCommand -replace "\`$\{$key\}", $Parameters[$key]
            $expandedCommand = $expandedCommand -replace "\`$$key", $Parameters[$key]
        }

        return $this.ExecuteCommand($expandedCommand, $TargetHosts, @{
            Timeout = if ($template.Timeout) { $template.Timeout } else { $this.CommandTimeoutSeconds }
            RequiresElevation = $template.RequiresElevation
        })
    }

    # Get available hosts/endpoints
    [object[]] GetAvailableHosts([hashtable]$Filter) {
        throw "GetAvailableHosts() must be implemented by derived class"
    }

    # Get command execution status
    [hashtable] GetCommandStatus([string]$CommandId) {
        throw "GetCommandStatus() must be implemented by derived class"
    }

    # Wait for command completion with optional timeout
    [hashtable] WaitForCommand([string]$CommandId, [int]$TimeoutSeconds) {
        $elapsed = 0
        $pollInterval = 5

        while ($elapsed -lt $TimeoutSeconds) {
            $status = $this.GetCommandStatus($CommandId)
            if ($status.IsComplete) {
                return $status
            }
            Start-Sleep -Seconds $pollInterval
            $elapsed += $pollInterval
        }

        return @{
            IsComplete = $false
            Error = "Command timed out after $TimeoutSeconds seconds"
            CommandId = $CommandId
        }
    }

    # Get supported capabilities of this provider
    [hashtable] GetCapabilities() {
        return @{
            SupportsParallelExecution = $false
            SupportsScriptExecution = $false
            SupportsFileUpload = $false
            SupportsFileDownload = $false
            MaxScriptLength = 0
            SupportedOSPlatforms = @()
            ReadOnlyMode = $true  # Always true
        }
    }
}

# Registry for EDR providers
$script:EDRProviders = @{}
$script:ActiveEDRProvider = $null

# SECURITY: Global read-only enforcement
$script:ADScoutEDRReadOnlyMode = $true

function Register-ADScoutEDRProvider {
    <#
    .SYNOPSIS
        Registers an EDR provider implementation.

    .PARAMETER Name
        Unique name for the provider.

    .PARAMETER Provider
        The provider class instance or factory scriptblock.

    .PARAMETER Force
        Overwrite existing provider registration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Provider,

        [switch]$Force
    )

    if ($script:EDRProviders.ContainsKey($Name) -and -not $Force) {
        Write-Warning "EDR Provider '$Name' is already registered. Use -Force to overwrite."
        return
    }

    $script:EDRProviders[$Name] = $Provider
    Write-Verbose "Registered EDR Provider: $Name"
}

function Get-ADScoutEDRProvider {
    <#
    .SYNOPSIS
        Gets registered EDR providers or the active provider.

    .PARAMETER Name
        Specific provider name to retrieve.

    .PARAMETER Active
        Return only the currently active provider.

    .PARAMETER ListAvailable
        List all registered providers.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0)]
        [string]$Name,

        [Parameter(ParameterSetName = 'Active')]
        [switch]$Active,

        [Parameter(ParameterSetName = 'List')]
        [switch]$ListAvailable
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Active' {
            return $script:ActiveEDRProvider
        }
        'List' {
            return $script:EDRProviders.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Key
                    Provider = $_.Value
                    IsActive = ($script:ActiveEDRProvider -and $script:ActiveEDRProvider.Name -eq $_.Key)
                }
            }
        }
        default {
            if ($Name) {
                return $script:EDRProviders[$Name]
            }
            return $script:EDRProviders
        }
    }
}

function Set-ADScoutEDRProvider {
    <#
    .SYNOPSIS
        Sets the active EDR provider for command execution.

    .PARAMETER Name
        Name of the registered provider to activate.

    .PARAMETER Provider
        Provider instance to set as active.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Direct')]
        [object]$Provider
    )

    if ($Name) {
        if (-not $script:EDRProviders.ContainsKey($Name)) {
            throw "EDR Provider '$Name' is not registered. Use Get-ADScoutEDRProvider -ListAvailable to see options."
        }
        $script:ActiveEDRProvider = $script:EDRProviders[$Name]
    }
    else {
        $script:ActiveEDRProvider = $Provider
    }

    Write-Verbose "Active EDR Provider set to: $($script:ActiveEDRProvider.Name)"
}

function Test-ADScoutEDRCommandSafety {
    <#
    .SYNOPSIS
        Validates that a command/template is safe for read-only execution.

    .DESCRIPTION
        SECURITY FUNCTION: Checks commands for potentially dangerous patterns
        that could modify systems. This is a defense-in-depth measure.

    .PARAMETER Command
        The command string to validate.

    .PARAMETER TemplateName
        The template name to validate.

    .OUTPUTS
        Returns $true if safe, throws if unsafe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Command')]
        [string]$Command,

        [Parameter(ParameterSetName = 'Template')]
        [string]$TemplateName
    )

    # Dangerous patterns that indicate write operations
    $dangerousPatterns = @(
        # PowerShell write cmdlets
        'Set-AD',
        'New-AD',
        'Remove-AD',
        'Add-AD',
        'Enable-AD',
        'Disable-AD',
        'Unlock-AD',
        'Reset-AD',
        'Move-AD',
        'Rename-AD',
        'Set-Item',
        'New-Item',
        'Remove-Item',
        'Set-Content',
        'Add-Content',
        'Clear-Content',
        'Out-File',
        'Set-Acl',
        'Set-Service',
        'Stop-Service',
        'Start-Service',
        'Restart-Service',
        'Stop-Process',
        'Start-Process',
        'Invoke-Expression',
        'Invoke-Command.*-ScriptBlock',  # Remote execution with scriptblock
        'Start-Job',
        'Register-ScheduledTask',
        'Set-ScheduledTask',
        'Unregister-ScheduledTask',
        'New-LocalUser',
        'Set-LocalUser',
        'Remove-LocalUser',
        'Add-LocalGroupMember',
        'Remove-LocalGroupMember',
        # Net commands
        'net\s+user',
        'net\s+localgroup.*\/add',
        'net\s+localgroup.*\/delete',
        # Registry modifications
        'Set-ItemProperty',
        'New-ItemProperty',
        'Remove-ItemProperty',
        'reg\s+add',
        'reg\s+delete',
        # Dangerous operations
        'Format-',
        'Clear-EventLog',
        'Remove-EventLog',
        'wevtutil\s+cl',
        # File operations
        'Copy-Item.*-Force',
        'Move-Item',
        'Rename-Item',
        'del\s+',
        'rm\s+',
        'rmdir',
        'erase\s+'
    )

    if ($TemplateName) {
        $template = Get-ADScoutEDRTemplate -Name $TemplateName
        if (-not $template) {
            throw "Template '$TemplateName' not found"
        }

        # Check if template is explicitly marked as write operation
        if ($template.IsWriteOperation -eq $true) {
            throw "SECURITY: Template '$TemplateName' is marked as a write operation and cannot be executed via EDR."
        }

        $Command = $template.ScriptBlock
    }

    if (-not $Command) {
        return $true
    }

    # Check for dangerous patterns
    foreach ($pattern in $dangerousPatterns) {
        if ($Command -match $pattern) {
            throw "SECURITY: Command contains potentially dangerous pattern '$pattern'. EDR execution is read-only. Command blocked."
        }
    }

    return $true
}

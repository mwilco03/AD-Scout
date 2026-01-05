#Requires -Version 5.1

<#
.SYNOPSIS
    Base class and interface definition for EDR provider wrappers.

.DESCRIPTION
    Defines the abstract interface that all EDR providers must implement.
    This enables security professionals without admin accounts to query
    domain controllers and endpoint configurations through EDR platforms
    like CrowdStrike Falcon, Carbon Black, Microsoft Defender, etc.

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
    # Returns: Hashtable with results per host
    [hashtable] ExecuteCommand([string]$Command, [string[]]$TargetHosts, [hashtable]$Options) {
        throw "ExecuteCommand() must be implemented by derived class"
    }

    # Execute a pre-canned command template
    [hashtable] ExecuteTemplate([string]$TemplateName, [string[]]$TargetHosts, [hashtable]$Parameters) {
        $template = Get-ADScoutEDRTemplate -Name $TemplateName
        if (-not $template) {
            throw "Template '$TemplateName' not found"
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
        }
    }
}

# Registry for EDR providers
$script:EDRProviders = @{}
$script:ActiveEDRProvider = $null

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

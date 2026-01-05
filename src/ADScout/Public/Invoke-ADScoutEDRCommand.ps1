function Invoke-ADScoutEDRCommand {
    <#
    .SYNOPSIS
        Executes read-only reconnaissance templates on remote endpoints through the connected EDR platform.

    .DESCRIPTION
        SECURITY: This function is READ-ONLY by design. Only pre-approved AD-Scout
        templates can be executed. Arbitrary script execution is not supported to
        prevent unintended changes to production systems.

        Enables execution of pre-canned AD-Scout reconnaissance templates on remote
        endpoints via EDR platforms like CrowdStrike Falcon or Microsoft Defender
        for Endpoint. This is designed for security professionals who need to gather
        Active Directory and endpoint security data without direct administrative
        access to target systems.

        Use Get-ADScoutEDRTemplate to see all available read-only templates.

    .PARAMETER Template
        Name of a pre-canned AD-Scout template to execute. Use Get-ADScoutEDRTemplate
        to see available templates. Templates are predefined scripts for common
        security reconnaissance tasks. This is the ONLY way to execute commands -
        arbitrary script execution is not supported for security reasons.

    .PARAMETER TargetHost
        Target hostname(s) or device ID(s) to execute the command on.
        Accepts pipeline input.

    .PARAMETER Filter
        Hashtable filter for selecting target hosts dynamically.
        Keys: Platform, Online, Hostname, OU, Tags

    .PARAMETER TemplateParameters
        Hashtable of parameters to pass to the template (e.g., @{DaysInactive = 90}).

    .PARAMETER Timeout
        Timeout in seconds for command execution. Default is provider-specific.

    .PARAMETER QueueOffline
        Queue the command for hosts that are currently offline (PSFalcon only).

    .PARAMETER AsJob
        Return immediately with a job object for async execution.

    .PARAMETER Raw
        Return raw JSON output without parsing.

    .PARAMETER Session
        Named session to use for MSSP multi-tenant environments. If not specified,
        uses the active session.

    .EXAMPLE
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01.contoso.com'

        Executes the domain info template on a domain controller.

    .EXAMPLE
        Invoke-ADScoutEDRCommand -Template 'AD-PrivilegedGroups' -TargetHost 'DC01', 'DC02'

        Gets privileged group membership from multiple domain controllers.

    .EXAMPLE
        Invoke-ADScoutEDRCommand -Template 'AD-SPNAccounts' -Filter @{Platform = 'Windows'; OU = '*Domain Controllers*'}

        Finds Kerberoastable accounts via domain controllers selected by OU.

    .EXAMPLE
        $results = Invoke-ADScoutEDRCommand -Template 'AD-StaleComputers' -TargetHost 'DC01' -TemplateParameters @{DaysInactive = 180}

        Finds computers inactive for 180 days.

    .EXAMPLE
        Get-ADScoutEDRHost -Filter @{Platform = 'Windows'; Online = $true} |
            Select-Object -First 5 |
            Invoke-ADScoutEDRCommand -Template 'EP-LocalAdmins'

        Gets local administrators from the first 5 online Windows hosts.

    .EXAMPLE
        # Multi-tenant MSSP usage
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01' -Session 'ClientA'

        Executes against a specific MSSP tenant session.

    .OUTPUTS
        PSCustomObject with results per host, or raw JSON if -Raw specified.

    .NOTES
        SECURITY: Arbitrary script execution is NOT supported. Only pre-approved
        templates can be executed to prevent unintended system modifications.

        Requires an active EDR connection. Use Connect-ADScoutEDR first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Template,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Hostname', 'DeviceId', 'MachineId', 'ComputerName')]
        [string[]]$TargetHost,

        [Parameter()]
        [hashtable]$Filter,

        [Parameter()]
        [hashtable]$TemplateParameters = @{},

        [Parameter()]
        [int]$Timeout,

        [Parameter()]
        [switch]$QueueOffline,

        [Parameter()]
        [switch]$AsJob,

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [string]$Session
    )

    begin {
        # Verify EDR connection
        $targetSession = if ($Session) { $Session } else { $script:ADScoutEDRActiveSession }

        if (-not (Test-ADScoutEDRConnection -Name $targetSession)) {
            throw "Not connected to an EDR platform. Use Connect-ADScoutEDR first."
        }

        $provider = $script:ADScoutEDRSessions[$targetSession].Provider
        $allTargets = [System.Collections.Generic.List[string]]::new()

        # Get and validate template
        $templateDef = Get-ADScoutEDRTemplate -Name $Template
        if (-not $templateDef) {
            throw "Template '$Template' not found. Use Get-ADScoutEDRTemplate to see available templates."
        }

        # SECURITY: Validate template is read-only before execution
        # This is defense-in-depth - templates should already be safe, but we verify
        try {
            $null = Test-ADScoutEDRCommandSafety -TemplateName $Template
        }
        catch {
            Write-Error "SECURITY: Template validation failed - $_"
            throw
        }

        Write-Verbose "Template '$Template' passed safety validation"
    }

    process {
        # Collect targets from pipeline
        if ($TargetHost) {
            foreach ($target in $TargetHost) {
                $allTargets.Add($target)
            }
        }
    }

    end {
        # If no explicit targets, try filter
        if ($allTargets.Count -eq 0 -and $Filter) {
            Write-Verbose "No explicit targets, using filter to find hosts..."
            $filteredHosts = $provider.GetAvailableHosts($Filter)
            if ($filteredHosts) {
                foreach ($host in $filteredHosts) {
                    $hostId = if ($host.DeviceId) { $host.DeviceId }
                              elseif ($host.MachineId) { $host.MachineId }
                              else { $host.Hostname }
                    $allTargets.Add($hostId)
                }
            }
        }

        if ($allTargets.Count -eq 0) {
            Write-Warning "No target hosts specified or found via filter."
            return
        }

        Write-Verbose "Executing template '$Template' on $($allTargets.Count) target(s)..."

        # Build command from template only (SECURITY: no arbitrary script execution)
        $expandedCommand = $templateDef.ScriptBlock
        foreach ($key in $TemplateParameters.Keys) {
            $expandedCommand = $expandedCommand -replace "\`$\{$key\}", $TemplateParameters[$key]
            $expandedCommand = $expandedCommand -replace "\`$$key", $TemplateParameters[$key]
        }
        $commandToExecute = $expandedCommand

        # SECURITY: Final validation of expanded command
        # Ensure parameter substitution didn't introduce dangerous patterns
        try {
            $null = Test-ADScoutEDRCommandSafety -Command $commandToExecute
        }
        catch {
            Write-Error "SECURITY: Expanded command validation failed - $_"
            throw
        }

        # Build options from template
        $options = @{
            RequiresElevation = $templateDef.RequiresElevation
            QueueOffline      = $QueueOffline.IsPresent
            TemplateName      = $Template
            ReadOnly          = $true  # SECURITY: Always read-only
        }

        if ($Timeout) {
            $options.Timeout = $Timeout
        }
        elseif ($templateDef.Timeout) {
            $options.Timeout = $templateDef.Timeout
        }

        # Execute
        if ($AsJob) {
            # Return job for async execution
            $scriptParams = @{
                Provider = $provider
                Command  = $commandToExecute
                Targets  = $allTargets.ToArray()
                Options  = $options
            }

            $job = Start-Job -ScriptBlock {
                param($p)
                $p.Provider.ExecuteCommand($p.Command, $p.Targets, $p.Options)
            } -ArgumentList $scriptParams

            return $job
        }

        try {
            $result = $provider.ExecuteCommand($commandToExecute, $allTargets.ToArray(), $options)

            if ($Raw) {
                return $result
            }

            # Parse and return results
            $output = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($hostResult in $result.Results.GetEnumerator()) {
                $parsedOutput = $null
                if ($hostResult.Value.Output) {
                    try {
                        $parsedOutput = $hostResult.Value.Output | ConvertFrom-Json -ErrorAction SilentlyContinue
                    }
                    catch {
                        $parsedOutput = $hostResult.Value.Output
                    }
                }

                $output.Add([PSCustomObject]@{
                    HostId    = $hostResult.Key
                    Success   = $hostResult.Value.Success
                    Output    = $parsedOutput
                    RawOutput = $hostResult.Value.Output
                    Error     = $hostResult.Value.Error
                })
            }

            # Add summary
            $summary = [PSCustomObject]@{
                PSTypeName   = 'ADScout.EDR.ExecutionResult'
                TotalHosts   = $result.HostsQueried
                Successful   = $result.HostsSuccess
                Failed       = $result.HostsFailed
                StartTime    = $result.StartTime
                EndTime      = $result.EndTime
                Duration     = if ($result.EndTime -and $result.StartTime) {
                                   ($result.EndTime - $result.StartTime).TotalSeconds
                               } else { $null }
                Template     = $Template
                Results      = $output
                Errors       = $result.Errors
            }

            return $summary
        }
        catch {
            Write-Error "Command execution failed: $_"
            throw
        }
    }
}

function Get-ADScoutEDRHost {
    <#
    .SYNOPSIS
        Gets available hosts from the connected EDR platform.

    .DESCRIPTION
        Queries the EDR platform for managed endpoints. Useful for discovering
        domain controllers and other targets for AD reconnaissance.

    .PARAMETER Filter
        Hashtable with filter criteria:
        - Platform: 'Windows', 'Linux', 'macOS'
        - Online: $true for online/active hosts only
        - Hostname: Hostname pattern to match
        - OU: Organizational Unit pattern

    .PARAMETER DomainControllers
        Shortcut filter to find domain controllers only.

    .PARAMETER Detailed
        Return full host details (slower).

    .PARAMETER Session
        Named session to use. If not specified, uses the active session.

    .EXAMPLE
        Get-ADScoutEDRHost -Filter @{Platform = 'Windows'; Online = $true}

        Gets all online Windows hosts.

    .EXAMPLE
        Get-ADScoutEDRHost -DomainControllers

        Gets hosts that appear to be domain controllers.

    .EXAMPLE
        Get-ADScoutEDRHost -Filter @{Hostname = 'DC*'} -Session 'MSSP-ClientA'

        Gets hosts with hostnames starting with 'DC' from a specific session.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Filter = @{},

        [Parameter()]
        [switch]$DomainControllers,

        [Parameter()]
        [switch]$Detailed,

        [Parameter()]
        [string]$Session
    )

    $targetSession = if ($Session) { $Session } else { $script:ADScoutEDRActiveSession }

    if (-not (Test-ADScoutEDRConnection -Name $targetSession)) {
        throw "Not connected to an EDR platform. Use Connect-ADScoutEDR first."
    }

    $provider = $script:ADScoutEDRSessions[$targetSession].Provider

    if ($DomainControllers) {
        # Use provider-specific method if available
        if ($provider | Get-Member -Name 'GetDomainControllers' -MemberType Method) {
            return $provider.GetDomainControllers()
        }

        # Generic approach: filter by OU or hostname patterns
        $Filter.Platform = 'Windows'
        $dcHosts = $provider.GetAvailableHosts($Filter) | Where-Object {
            $_.OU -match 'Domain Controllers' -or
            $_.Hostname -match '^DC\d*\.' -or
            $_.Hostname -match 'DC\d*$'
        }
        return $dcHosts
    }

    return $provider.GetAvailableHosts($Filter)
}

function Get-ADScoutEDRCapabilities {
    <#
    .SYNOPSIS
        Gets the capabilities of the active EDR provider.

    .DESCRIPTION
        Returns information about what the connected EDR platform supports,
        such as parallel execution, script length limits, and supported platforms.

    .PARAMETER Session
        Named session to query. If not specified, uses the active session.

    .EXAMPLE
        Get-ADScoutEDRCapabilities

        Returns capability information for the active EDR provider.

    .EXAMPLE
        Get-ADScoutEDRCapabilities -Session 'MSSP-ClientA'

        Returns capabilities for a specific session.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Session
    )

    $targetSession = if ($Session) { $Session } else { $script:ADScoutEDRActiveSession }

    if (-not $targetSession -or -not $script:ADScoutEDRSessions -or -not $script:ADScoutEDRSessions.ContainsKey($targetSession)) {
        Write-Warning "No active EDR session. Use Connect-ADScoutEDR first."
        return $null
    }

    $provider = $script:ADScoutEDRSessions[$targetSession].Provider

    if (-not $provider) {
        Write-Warning "No active EDR provider. Use Connect-ADScoutEDR first."
        return $null
    }

    $capabilities = $provider.GetCapabilities()

    [PSCustomObject]@{
        PSTypeName                 = 'ADScout.EDR.Capabilities'
        SessionName                = $targetSession
        ProviderName               = $provider.Name
        ProviderVersion            = $provider.Version
        SupportsParallelExecution  = $capabilities.SupportsParallelExecution
        SupportsScriptExecution    = $capabilities.SupportsScriptExecution
        SupportsFileUpload         = $capabilities.SupportsFileUpload
        SupportsFileDownload       = $capabilities.SupportsFileDownload
        MaxScriptLength            = $capabilities.MaxScriptLength
        SupportedOSPlatforms       = $capabilities.SupportedOSPlatforms
        RequiresAgentOnline        = $capabilities.RequiresAgentOnline
        MaxBatchSize               = $capabilities.MaxBatchSize
        AdditionalCapabilities     = $capabilities
    }
}

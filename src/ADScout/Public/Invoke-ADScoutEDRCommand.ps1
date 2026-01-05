function Invoke-ADScoutEDRCommand {
    <#
    .SYNOPSIS
        Executes commands or templates on remote endpoints through the connected EDR platform.

    .DESCRIPTION
        Enables execution of PowerShell commands or pre-canned AD-Scout templates on remote
        endpoints via EDR platforms like CrowdStrike Falcon or Microsoft Defender
        for Endpoint. This is designed for security professionals who need to gather
        Active Directory and endpoint security data without direct administrative
        access to target systems.

        SECURITY NOTE - Multi-Session Mode:
        When multiple EDR sessions are active (MSSP multi-tenant scenarios), this
        function is LOCKED DOWN to template-only, read-only operations to prevent
        accidental changes to client environments. In single-session mode (your own
        environment), full functionality is available.

        Single session  = Full access (ScriptBlock, Command, Template)
        Multi-session   = Template-only, read-only (safety for MSSP)

    .PARAMETER Template
        Name of a pre-canned AD-Scout template to execute. Use Get-ADScoutEDRTemplate
        to see available templates. Templates are predefined scripts for common
        security reconnaissance tasks.

    .PARAMETER ScriptBlock
        Custom PowerShell scriptblock to execute on target hosts.
        NOT AVAILABLE in multi-session mode (MSSP safety).

    .PARAMETER Command
        PowerShell command string to execute on target hosts.
        NOT AVAILABLE in multi-session mode (MSSP safety).

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
        Invoke-ADScoutEDRCommand -ScriptBlock { Get-ADUser -Filter * } -TargetHost 'DC01'

        Executes a custom scriptblock (single-session mode only).

    .EXAMPLE
        Invoke-ADScoutEDRCommand -Command 'Get-Service | Where-Object Status -eq Running' -TargetHost 'Server01'

        Executes a command string (single-session mode only).

    .EXAMPLE
        # Multi-tenant MSSP usage (template-only enforced)
        Connect-ADScoutEDR -Provider PSFalcon -Name 'ClientA' -ClientId $idA -ClientSecret $secretA
        Connect-ADScoutEDR -Provider PSFalcon -Name 'ClientB' -ClientId $idB -ClientSecret $secretB
        # Now in multi-session mode - only templates allowed
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01' -Session 'ClientA'

    .OUTPUTS
        PSCustomObject with results per host, or raw JSON if -Raw specified.

    .NOTES
        Requires an active EDR connection. Use Connect-ADScoutEDR first.

        SECURITY: When multiple sessions are connected, only pre-approved templates
        can be executed to prevent unintended changes to client environments.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Template')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Template', Position = 0)]
        [string]$Template,

        [Parameter(Mandatory, ParameterSetName = 'ScriptBlock')]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory, ParameterSetName = 'Command')]
        [string]$Command,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Hostname', 'DeviceId', 'MachineId', 'ComputerName')]
        [string[]]$TargetHost,

        [Parameter()]
        [hashtable]$Filter,

        [Parameter(ParameterSetName = 'Template')]
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

        # Check if we're in multi-session mode (MSSP safety)
        $isMultiSession = Test-ADScoutEDRMultiSessionMode

        # SECURITY: In multi-session mode, only templates are allowed
        if ($isMultiSession -and $PSCmdlet.ParameterSetName -ne 'Template') {
            throw "SECURITY: Multiple EDR sessions are active (MSSP mode). Only -Template execution is allowed to protect client environments. Disconnect other sessions to use -ScriptBlock or -Command."
        }

        # Get template if using template mode
        $templateDef = $null
        if ($PSCmdlet.ParameterSetName -eq 'Template') {
            $templateDef = Get-ADScoutEDRTemplate -Name $Template
            if (-not $templateDef) {
                throw "Template '$Template' not found. Use Get-ADScoutEDRTemplate to see available templates."
            }

            # In multi-session mode, validate template is read-only
            if ($isMultiSession) {
                try {
                    $null = Test-ADScoutEDRCommandSafety -TemplateName $Template
                }
                catch {
                    Write-Error "SECURITY: Template validation failed - $_"
                    throw
                }
                Write-Verbose "Template '$Template' passed safety validation (multi-session mode)"
            }
        }
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

        Write-Verbose "Executing on $($allTargets.Count) target(s)..."

        # Build command based on parameter set
        $commandToExecute = switch ($PSCmdlet.ParameterSetName) {
            'Template' {
                $expandedCommand = $templateDef.ScriptBlock
                foreach ($key in $TemplateParameters.Keys) {
                    $expandedCommand = $expandedCommand -replace "\`$\{$key\}", $TemplateParameters[$key]
                    $expandedCommand = $expandedCommand -replace "\`$$key", $TemplateParameters[$key]
                }

                # In multi-session mode, validate expanded command for safety
                if ($isMultiSession) {
                    try {
                        $null = Test-ADScoutEDRCommandSafety -Command $expandedCommand
                    }
                    catch {
                        Write-Error "SECURITY: Expanded command validation failed - $_"
                        throw
                    }
                }

                $expandedCommand
            }
            'ScriptBlock' {
                # Single-session mode only (checked in begin block)
                $ScriptBlock.ToString()
            }
            'Command' {
                # Single-session mode only (checked in begin block)
                $Command
            }
        }

        # Build options
        $options = @{
            RequiresElevation = if ($templateDef) { $templateDef.RequiresElevation } else { $false }
            QueueOffline      = $QueueOffline.IsPresent
            TemplateName      = if ($Template) { $Template } else { $null }
            ReadOnly          = $isMultiSession  # Read-only only in multi-session mode
        }

        if ($Timeout) {
            $options.Timeout = $Timeout
        }
        elseif ($templateDef -and $templateDef.Timeout) {
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

function Invoke-ADScoutEDRCollection {
    <#
    .SYNOPSIS
        Runs comprehensive AD/endpoint collection across multiple hosts with automatic batching.

    .DESCRIPTION
        "Just run it" - Automatically handles API rate limits and concurrent session
        limits for each EDR provider. Batches hosts, manages queuing, tracks progress,
        and consolidates results. No brain power required.

        Provider Limits (handled automatically):
        - CrowdStrike Falcon: 500 concurrent sessions, batches of 500
        - Microsoft Defender: 25 concurrent sessions, batches of 25

        The function will:
        1. Query available hosts (or use provided list)
        2. Auto-batch based on provider limits
        3. Execute with progress tracking
        4. Wait for completion with status updates
        5. Consolidate and return all results

    .PARAMETER Template
        Collection template to run. Defaults to 'AD-FullRecon'.
        Options: AD-FullRecon, EP-FullRecon, or any registered template.

    .PARAMETER TargetHost
        Specific hosts to target. If not provided, uses -Filter or all available hosts.

    .PARAMETER Filter
        Hashtable filter for host selection (Platform, Online, Hostname, OU).

    .PARAMETER DomainControllersOnly
        Only target domain controllers.

    .PARAMETER MaxHosts
        Maximum number of hosts to collect from. Default: 100.

    .PARAMETER BatchSize
        Override automatic batch size (use with caution).

    .PARAMETER ThrottleDelaySeconds
        Delay between batches. Default: auto-calculated based on provider.

    .PARAMETER Session
        Named EDR session to use.

    .PARAMETER OutputPath
        Export results to JSON file at this path.

    .EXAMPLE
        Invoke-ADScoutEDRCollection

        Runs AD-FullRecon on all domain controllers (up to 100), auto-batched.

    .EXAMPLE
        Invoke-ADScoutEDRCollection -Template 'EP-FullRecon' -MaxHosts 500

        Collects endpoint security baselines from up to 500 hosts.

    .EXAMPLE
        Invoke-ADScoutEDRCollection -DomainControllersOnly -OutputPath 'C:\Results\ad-recon.json'

        Collects AD data from all DCs and exports to JSON.

    .EXAMPLE
        $results = Invoke-ADScoutEDRCollection -Filter @{Platform='Windows'; Online=$true} -MaxHosts 1000
        $results.Results | Where-Object { $_.Output.SPNAccounts.Count -gt 0 }

        Collect from online Windows hosts and filter results.

    .OUTPUTS
        PSCustomObject with consolidated results, timing, and any errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Template = 'AD-FullRecon',

        [Parameter()]
        [string[]]$TargetHost,

        [Parameter()]
        [hashtable]$Filter,

        [Parameter()]
        [switch]$DomainControllersOnly,

        [Parameter()]
        [int]$MaxHosts = 100,

        [Parameter()]
        [int]$BatchSize,

        [Parameter()]
        [int]$ThrottleDelaySeconds,

        [Parameter()]
        [string]$Session,

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        $startTime = Get-Date
        $targetSession = if ($Session) { $Session } else { $script:ADScoutEDRActiveSession }

        if (-not (Test-ADScoutEDRConnection -Name $targetSession)) {
            throw "Not connected to an EDR platform. Use Connect-ADScoutEDR first."
        }

        $sessionInfo = $script:ADScoutEDRSessions[$targetSession]
        $provider = $sessionInfo.Provider
        $providerName = $sessionInfo.ProviderName

        # Determine batch size based on provider limits
        $providerLimits = @{
            'PSFalcon'    = @{ MaxConcurrent = 500; DefaultDelay = 2; BatchSize = 500 }
            'DefenderATP' = @{ MaxConcurrent = 25;  DefaultDelay = 5; BatchSize = 20 }  # Conservative for MDE
        }

        $limits = $providerLimits[$providerName]
        if (-not $limits) {
            $limits = @{ MaxConcurrent = 50; DefaultDelay = 3; BatchSize = 50 }  # Safe defaults
        }

        $effectiveBatchSize = if ($BatchSize) { $BatchSize } else { $limits.BatchSize }
        $effectiveDelay = if ($ThrottleDelaySeconds) { $ThrottleDelaySeconds } else { $limits.DefaultDelay }

        Write-Host "`n[ADScout EDR Collection]" -ForegroundColor Cyan
        Write-Host "Provider: $providerName (Max concurrent: $($limits.MaxConcurrent))" -ForegroundColor Gray
        Write-Host "Template: $Template" -ForegroundColor Gray
        Write-Host "Batch size: $effectiveBatchSize | Throttle delay: ${effectiveDelay}s" -ForegroundColor Gray
    }

    process {
        # Build target list
        $allTargets = @()

        if ($TargetHost) {
            $allTargets = $TargetHost
            Write-Host "Using provided host list: $($allTargets.Count) hosts" -ForegroundColor Gray
        }
        elseif ($DomainControllersOnly) {
            Write-Host "Discovering domain controllers..." -ForegroundColor Yellow
            $dcHosts = Get-ADScoutEDRHost -DomainControllers -Session $targetSession
            $allTargets = @($dcHosts | ForEach-Object {
                if ($_.DeviceId) { $_.DeviceId } elseif ($_.MachineId) { $_.MachineId } else { $_.Hostname }
            })
            Write-Host "Found $($allTargets.Count) domain controllers" -ForegroundColor Green
        }
        elseif ($Filter) {
            Write-Host "Querying hosts with filter..." -ForegroundColor Yellow
            $filteredHosts = $provider.GetAvailableHosts($Filter)
            $allTargets = @($filteredHosts | ForEach-Object {
                if ($_.DeviceId) { $_.DeviceId } elseif ($_.MachineId) { $_.MachineId } else { $_.Hostname }
            })
            Write-Host "Found $($allTargets.Count) matching hosts" -ForegroundColor Green
        }
        else {
            Write-Host "Querying all available hosts..." -ForegroundColor Yellow
            $allHosts = $provider.GetAvailableHosts(@{ Platform = 'Windows'; Online = $true })
            $allTargets = @($allHosts | ForEach-Object {
                if ($_.DeviceId) { $_.DeviceId } elseif ($_.MachineId) { $_.MachineId } else { $_.Hostname }
            })
            Write-Host "Found $($allTargets.Count) online Windows hosts" -ForegroundColor Green
        }

        # Apply MaxHosts limit
        if ($allTargets.Count -gt $MaxHosts) {
            Write-Host "Limiting to first $MaxHosts hosts (use -MaxHosts to change)" -ForegroundColor Yellow
            $allTargets = $allTargets | Select-Object -First $MaxHosts
        }

        if ($allTargets.Count -eq 0) {
            Write-Warning "No target hosts found. Check your filter or connection."
            return $null
        }

        # Calculate batches
        $batches = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $allTargets.Count; $i += $effectiveBatchSize) {
            $batch = $allTargets[$i..([Math]::Min($i + $effectiveBatchSize - 1, $allTargets.Count - 1))]
            $batches.Add($batch)
        }

        Write-Host "`nCollection Plan:" -ForegroundColor Cyan
        Write-Host "  Total hosts: $($allTargets.Count)" -ForegroundColor White
        Write-Host "  Batches: $($batches.Count)" -ForegroundColor White
        Write-Host "  Est. time: ~$([Math]::Ceiling($batches.Count * ($effectiveDelay + 30))) seconds" -ForegroundColor White
        Write-Host ""

        # Execute batches with progress
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $totalSuccess = 0
        $totalFailed = 0
        $batchNum = 0

        foreach ($batch in $batches) {
            $batchNum++
            $percentComplete = [Math]::Round(($batchNum / $batches.Count) * 100)

            Write-Progress -Activity "ADScout EDR Collection" `
                -Status "Batch $batchNum of $($batches.Count) ($($batch.Count) hosts)" `
                -PercentComplete $percentComplete

            Write-Host "[$batchNum/$($batches.Count)] Executing on $($batch.Count) hosts..." -ForegroundColor Cyan -NoNewline

            try {
                $batchResult = Invoke-ADScoutEDRCommand -Template $Template `
                    -TargetHost $batch `
                    -Session $targetSession `
                    -ErrorAction Stop

                if ($batchResult -and $batchResult.Results) {
                    foreach ($result in $batchResult.Results) {
                        $allResults.Add($result)
                        if ($result.Success) { $totalSuccess++ } else { $totalFailed++ }
                    }
                    Write-Host " Done ($($batchResult.Successful) ok, $($batchResult.Failed) failed)" -ForegroundColor Green
                }
                else {
                    Write-Host " No results" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host " ERROR: $_" -ForegroundColor Red
                $totalFailed += $batch.Count
            }

            # Throttle between batches (except last)
            if ($batchNum -lt $batches.Count) {
                Write-Host "  Throttling ${effectiveDelay}s..." -ForegroundColor DarkGray
                Start-Sleep -Seconds $effectiveDelay
            }
        }

        Write-Progress -Activity "ADScout EDR Collection" -Completed
    }

    end {
        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Build consolidated result
        $consolidatedResult = [PSCustomObject]@{
            PSTypeName      = 'ADScout.EDR.CollectionResult'
            CollectionType  = $Template
            Provider        = $providerName
            Session         = $targetSession
            StartTime       = $startTime
            EndTime         = $endTime
            DurationSeconds = [Math]::Round($duration.TotalSeconds, 2)
            TotalHosts      = $allTargets.Count
            Successful      = $totalSuccess
            Failed          = $totalFailed
            BatchCount      = $batches.Count
            BatchSize       = $effectiveBatchSize
            Results         = $allResults
        }

        # Summary
        Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
        Write-Host "Collection Complete" -ForegroundColor Green
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host "  Duration: $([Math]::Round($duration.TotalSeconds, 1)) seconds"
        Write-Host "  Hosts: $totalSuccess successful, $totalFailed failed"
        Write-Host "  Batches: $($batches.Count) @ $effectiveBatchSize hosts/batch"

        # Export if requested
        if ($OutputPath) {
            try {
                $consolidatedResult | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8
                Write-Host "  Exported: $OutputPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to export: $_"
            }
        }

        Write-Host ""

        return $consolidatedResult
    }
}

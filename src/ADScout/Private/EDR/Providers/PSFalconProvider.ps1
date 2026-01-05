#Requires -Version 5.1

<#
.SYNOPSIS
    CrowdStrike Falcon EDR provider using PSFalcon module.

.DESCRIPTION
    Implements the EDR provider interface for CrowdStrike Falcon using the
    PSFalcon PowerShell module. Enables remote command execution on endpoints
    through the Falcon Real Time Response (RTR) API.

.NOTES
    Author: AD-Scout Contributors
    License: MIT

    Prerequisites:
    - PSFalcon module (Install-Module PSFalcon)
    - CrowdStrike Falcon API credentials with RTR permissions
    - Appropriate scopes: Real Time Response (Read, Write, Admin)

.LINK
    https://github.com/CrowdStrike/psfalcon
#>

class PSFalconProvider : EDRProviderBase {
    # PSFalcon-specific properties
    [string]$ClientId
    [string]$Cloud = 'us-1'
    [string]$MemberCid
    [bool]$UseExistingToken = $false

    # RTR session tracking
    hidden [hashtable]$ActiveSessions = @{}
    hidden [int]$SessionTimeoutMinutes = 10

    PSFalconProvider() {
        $this.Name = 'PSFalcon'
        $this.Version = '1.0.0'
        $this.Description = 'CrowdStrike Falcon EDR provider using PSFalcon module'
        $this.MaxConcurrentCommands = 100
        $this.CommandTimeoutSeconds = 600
    }

    [bool] Connect([hashtable]$Parameters) {
        <#
        .SYNOPSIS
            Connects to CrowdStrike Falcon API.

        .PARAMETER Parameters
            Hashtable containing:
            - ClientId: API Client ID
            - ClientSecret: API Client Secret
            - Cloud: Falcon cloud (us-1, us-2, eu-1, us-gov-1)
            - MemberCid: Child CID for MSSP scenarios
            - UseExistingToken: Skip auth if already connected
        #>

        # Check if PSFalcon is installed
        if (-not (Get-Module -ListAvailable PSFalcon)) {
            Write-Warning @"
PSFalcon module is not installed. CrowdStrike Falcon integration requires this module.

To install, run:
    Install-Module PSFalcon -Scope CurrentUser

For more information: https://github.com/CrowdStrike/psfalcon
"@
            return $false
        }

        try {
            Import-Module PSFalcon -ErrorAction Stop

            # Check for existing valid token
            if ($Parameters.UseExistingToken) {
                $token = Test-FalconToken -ErrorAction SilentlyContinue
                if ($token -and $token.Token) {
                    Write-Verbose "Using existing Falcon API token"
                    $this.IsConnected = $true
                    $this.ConnectionContext = @{
                        Cloud = $token.Cloud
                        Hostname = $token.Hostname
                        TokenExpires = $token.Expiration
                    }
                    return $true
                }
            }

            # Validate required parameters
            if (-not $Parameters.ClientId -or -not $Parameters.ClientSecret) {
                throw "ClientId and ClientSecret are required for Falcon API authentication"
            }

            $this.ClientId = $Parameters.ClientId
            if ($Parameters.Cloud) { $this.Cloud = $Parameters.Cloud }
            if ($Parameters.MemberCid) { $this.MemberCid = $Parameters.MemberCid }

            # Build auth parameters
            $authParams = @{
                ClientId     = $Parameters.ClientId
                ClientSecret = $Parameters.ClientSecret
                Cloud        = $this.Cloud
            }

            if ($this.MemberCid) {
                $authParams.MemberCid = $this.MemberCid
            }

            # Authenticate
            Write-Verbose "Connecting to CrowdStrike Falcon ($($this.Cloud))..."
            Request-FalconToken @authParams -ErrorAction Stop

            # Verify connection
            $token = Test-FalconToken
            if ($token -and $token.Token) {
                $this.IsConnected = $true
                $this.ConnectionContext = @{
                    Cloud         = $token.Cloud
                    Hostname      = $token.Hostname
                    TokenExpires  = $token.Expiration
                    MemberCid     = $this.MemberCid
                }

                Write-Verbose "Connected to CrowdStrike Falcon"
                Write-Verbose "  Cloud: $($token.Cloud)"
                Write-Verbose "  Host: $($token.Hostname)"
                Write-Verbose "  Token expires: $($token.Expiration)"

                return $true
            }
            else {
                throw "Failed to obtain valid Falcon API token"
            }
        }
        catch {
            Write-Error "Failed to connect to CrowdStrike Falcon: $_"
            $this.IsConnected = $false
            return $false
        }
    }

    [void] Disconnect() {
        try {
            # Close any active RTR sessions
            foreach ($sessionId in $this.ActiveSessions.Keys) {
                try {
                    Remove-FalconSession -Id $sessionId -ErrorAction SilentlyContinue
                }
                catch { }
            }
            $this.ActiveSessions.Clear()

            # Revoke token
            if (Get-Module PSFalcon) {
                Revoke-FalconToken -ErrorAction SilentlyContinue
            }

            $this.IsConnected = $false
            $this.ConnectionContext = @{}

            Write-Verbose "Disconnected from CrowdStrike Falcon"
        }
        catch {
            Write-Warning "Error during Falcon disconnect: $_"
        }
    }

    [bool] TestConnection() {
        if (-not $this.IsConnected) { return $false }

        try {
            $token = Test-FalconToken -ErrorAction Stop
            if ($token -and $token.Token) {
                # Check if token is still valid (not expired)
                if ($token.Expiration -gt (Get-Date)) {
                    return $true
                }
            }
        }
        catch { }

        $this.IsConnected = $false
        return $false
    }

    [hashtable] ExecuteCommand([string]$Command, [string[]]$TargetHosts, [hashtable]$Options) {
        <#
        .SYNOPSIS
            Executes a PowerShell command on target hosts via Falcon RTR.

        .PARAMETER Command
            The PowerShell script/command to execute.

        .PARAMETER TargetHosts
            Array of host identifiers (device IDs, hostnames, or AIDs).

        .PARAMETER Options
            Hashtable with:
            - Timeout: Seconds to wait for completion
            - RequiresElevation: Run as admin (uses runscript)
            - QueueOffline: Queue for offline hosts
            - HostIdType: 'device_id', 'hostname', or 'aid'
        #>

        if (-not $this.TestConnection()) {
            throw "Not connected to CrowdStrike Falcon. Use Connect() first."
        }

        $result = @{
            Success       = $false
            StartTime     = Get-Date
            EndTime       = $null
            Results       = @{}
            Errors        = @()
            HostsQueried  = $TargetHosts.Count
            HostsSuccess  = 0
            HostsFailed   = 0
        }

        try {
            # Resolve host IDs if needed
            $deviceIds = $this.ResolveHostIds($TargetHosts, $Options.HostIdType)

            if (-not $deviceIds -or $deviceIds.Count -eq 0) {
                throw "No valid device IDs found for specified hosts"
            }

            Write-Verbose "Executing command on $($deviceIds.Count) host(s)..."

            # Determine if we need admin RTR session
            $useAdmin = $Options.RequiresElevation -or $Command.Length -gt 4096

            # Start RTR batch session
            $sessionParams = @{
                HostId = $deviceIds
            }

            if ($Options.QueueOffline) {
                $sessionParams.QueueOffline = $true
            }

            $session = Start-FalconSession @sessionParams -ErrorAction Stop

            if (-not $session) {
                throw "Failed to create RTR session"
            }

            # Track session for cleanup
            $this.ActiveSessions[$session.batch_id] = @{
                Created  = Get-Date
                HostIds  = $deviceIds
            }

            try {
                # Execute command
                $cmdParams = @{
                    BatchId        = $session.batch_id
                    Command        = 'runscript'
                    Argument       = "-Raw=``````$Command``````"
                    OptionalHostId = $deviceIds
                }

                if ($Options.Timeout) {
                    $cmdParams.Timeout = $Options.Timeout
                }

                $response = Invoke-FalconAdminCommand @cmdParams -ErrorAction Stop

                # Wait for completion and gather results
                $timeout = if ($Options.Timeout) { $Options.Timeout } else { $this.CommandTimeoutSeconds }
                $cmdResult = $this.WaitForBatchCommand($session.batch_id, $response.combined.resources, $timeout)

                foreach ($hostResult in $cmdResult.GetEnumerator()) {
                    $result.Results[$hostResult.Key] = $hostResult.Value

                    if ($hostResult.Value.Success) {
                        $result.HostsSuccess++
                    }
                    else {
                        $result.HostsFailed++
                        $result.Errors += "Host $($hostResult.Key): $($hostResult.Value.Error)"
                    }
                }

                $result.Success = $result.HostsFailed -eq 0
            }
            finally {
                # Clean up session
                Remove-FalconSession -Id $session.batch_id -ErrorAction SilentlyContinue
                $this.ActiveSessions.Remove($session.batch_id)
            }
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
        }

        $result.EndTime = Get-Date
        return $result
    }

    hidden [string[]] ResolveHostIds([string[]]$Hosts, [string]$IdType) {
        $deviceIds = @()

        foreach ($host in $Hosts) {
            try {
                switch ($IdType) {
                    'device_id' {
                        # Already a device ID
                        $deviceIds += $host
                    }
                    'hostname' {
                        $device = Get-FalconHost -Filter "hostname:'$host'" -ErrorAction Stop
                        if ($device) {
                            $deviceIds += $device.device_id
                        }
                        else {
                            Write-Warning "Host not found: $host"
                        }
                    }
                    'aid' {
                        $device = Get-FalconHost -Filter "agent_local_time:'$host'" -ErrorAction Stop
                        if ($device) {
                            $deviceIds += $device.device_id
                        }
                    }
                    default {
                        # Try to auto-detect
                        if ($host -match '^[a-f0-9]{32}$') {
                            # Looks like a device ID
                            $deviceIds += $host
                        }
                        else {
                            # Assume hostname
                            $device = Get-FalconHost -Filter "hostname:'$host'" -ErrorAction Stop
                            if ($device) {
                                $deviceIds += $device.device_id
                            }
                            else {
                                Write-Warning "Host not found: $host"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error resolving host '$host': $_"
            }
        }

        return $deviceIds
    }

    hidden [hashtable] WaitForBatchCommand([string]$BatchId, [object[]]$Resources, [int]$TimeoutSeconds) {
        $results = @{}
        $startTime = Get-Date
        $pendingHosts = @{}

        # Initialize tracking
        foreach ($resource in $Resources) {
            $pendingHosts[$resource.aid] = $resource.cloud_request_id
        }

        while ($pendingHosts.Count -gt 0) {
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            if ($elapsed -ge $TimeoutSeconds) {
                # Timeout - mark remaining as failed
                foreach ($aid in $pendingHosts.Keys) {
                    $results[$aid] = @{
                        Success = $false
                        Error   = "Command timed out after $TimeoutSeconds seconds"
                        Output  = $null
                    }
                }
                break
            }

            Start-Sleep -Seconds 3

            # Check status
            foreach ($aid in @($pendingHosts.Keys)) {
                try {
                    $status = Confirm-FalconAdminCommand -CloudRequestId $pendingHosts[$aid] -ErrorAction Stop

                    if ($status.complete) {
                        $pendingHosts.Remove($aid)

                        if ($status.stdout) {
                            $results[$aid] = @{
                                Success = $true
                                Output  = $status.stdout
                                Error   = $null
                            }
                        }
                        elseif ($status.stderr) {
                            $results[$aid] = @{
                                Success = $false
                                Output  = $null
                                Error   = $status.stderr
                            }
                        }
                        else {
                            $results[$aid] = @{
                                Success = $true
                                Output  = ""
                                Error   = $null
                            }
                        }
                    }
                }
                catch {
                    # Keep waiting unless it's a fatal error
                    if ($_.Exception.Message -match 'not found|expired') {
                        $pendingHosts.Remove($aid)
                        $results[$aid] = @{
                            Success = $false
                            Error   = $_.Exception.Message
                            Output  = $null
                        }
                    }
                }
            }
        }

        return $results
    }

    [object[]] GetAvailableHosts([hashtable]$Filter) {
        <#
        .SYNOPSIS
            Gets available Falcon-managed hosts.

        .PARAMETER Filter
            Hashtable with filter criteria:
            - Platform: 'Windows', 'Mac', 'Linux'
            - Online: $true for online only
            - Hostname: Hostname pattern
            - OU: Organizational Unit pattern
        #>

        if (-not $this.TestConnection()) {
            throw "Not connected to CrowdStrike Falcon"
        }

        $filterParts = @()

        if ($Filter.Platform) {
            $filterParts += "platform_name:'$($Filter.Platform)'"
        }

        if ($Filter.Online) {
            $filterParts += "status:'online'"
        }

        if ($Filter.Hostname) {
            $filterParts += "hostname:'$($Filter.Hostname)'"
        }

        if ($Filter.OU) {
            $filterParts += "ou:'$($Filter.OU)'"
        }

        $filterString = $filterParts -join '+'

        try {
            $hosts = if ($filterString) {
                Get-FalconHost -Filter $filterString -Detailed -ErrorAction Stop
            }
            else {
                Get-FalconHost -Detailed -ErrorAction Stop
            }

            return $hosts | ForEach-Object {
                [PSCustomObject]@{
                    DeviceId          = $_.device_id
                    Hostname          = $_.hostname
                    LocalIP           = $_.local_ip
                    ExternalIP        = $_.external_ip
                    Platform          = $_.platform_name
                    OSVersion         = $_.os_version
                    Status            = $_.status
                    LastSeen          = $_.last_seen
                    MachineDomain     = $_.machine_domain
                    OU                = $_.ou
                    SiteName          = $_.site_name
                    AgentVersion      = $_.agent_version
                    SystemProductName = $_.system_product_name
                }
            }
        }
        catch {
            Write-Error "Failed to get Falcon hosts: $_"
            return @()
        }
    }

    [hashtable] GetCommandStatus([string]$CommandId) {
        try {
            $status = Confirm-FalconAdminCommand -CloudRequestId $CommandId -ErrorAction Stop
            return @{
                IsComplete = $status.complete
                Output     = $status.stdout
                Error      = $status.stderr
                CommandId  = $CommandId
            }
        }
        catch {
            return @{
                IsComplete = $false
                Error      = $_.Exception.Message
                CommandId  = $CommandId
            }
        }
    }

    [hashtable] GetCapabilities() {
        return @{
            SupportsParallelExecution = $true
            SupportsScriptExecution   = $true
            SupportsFileUpload        = $true
            SupportsFileDownload      = $true
            MaxScriptLength           = 1048576  # 1MB via put-and-run
            MaxBatchSize              = 10000
            SupportedOSPlatforms      = @('Windows', 'Mac', 'Linux')
            RequiresAgentOnline       = $false  # Supports queue offline
            SupportsAdminCommands     = $true
            SupportsResponderCommands = $true
        }
    }

    # Additional PSFalcon-specific methods

    [object[]] GetDomainControllers() {
        <#
        .SYNOPSIS
            Gets Falcon-managed hosts that are domain controllers.
        #>
        return $this.GetAvailableHosts(@{
            Platform = 'Windows'
        }) | Where-Object {
            $_.Hostname -match 'DC' -or
            $_.OU -match 'Domain Controllers'
        }
    }

    [hashtable] ExecuteADScoutTemplate([string]$TemplateName, [string[]]$TargetHosts, [hashtable]$Parameters) {
        <#
        .SYNOPSIS
            Executes an AD-Scout pre-canned template via Falcon RTR.

        .PARAMETER TemplateName
            Name/ID of the template from Get-ADScoutEDRTemplate.

        .PARAMETER TargetHosts
            Target hostnames or device IDs.

        .PARAMETER Parameters
            Template-specific parameters.
        #>

        $template = Get-ADScoutEDRTemplate -Name $TemplateName
        if (-not $template) {
            throw "Template '$TemplateName' not found. Use Get-ADScoutEDRTemplate to see available templates."
        }

        # Expand template with parameters
        $expandedCommand = $template.ScriptBlock
        foreach ($key in $Parameters.Keys) {
            $expandedCommand = $expandedCommand -replace "\`$\{$key\}", $Parameters[$key]
        }

        # Execute via RTR
        return $this.ExecuteCommand($expandedCommand, $TargetHosts, @{
            Timeout           = $template.Timeout
            RequiresElevation = $template.RequiresElevation
        })
    }
}

# Register the provider
$psfalconProvider = [PSFalconProvider]::new()
Register-ADScoutEDRProvider -Name 'PSFalcon' -Provider $psfalconProvider -Force

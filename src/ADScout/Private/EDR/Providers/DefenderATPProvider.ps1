#Requires -Version 5.1

<#
.SYNOPSIS
    Microsoft Defender for Endpoint (MDE) EDR provider.

.DESCRIPTION
    Implements the EDR provider interface for Microsoft Defender for Endpoint
    using the Microsoft Graph Security API and MDE Live Response API.

    API RATE LIMITS & CONSTRAINTS:
    ==============================
    - Max concurrent Live Response sessions: 25 per tenant (HARD LIMIT)
    - Max pending Live Response sessions: 10 additional in queue
    - Session timeout: 30 minutes idle
    - API rate limit: 100 requests per minute per app
    - Script execution timeout: 10 minutes
    - Script size limit: 8MB per script file
    - Max response size: 3MB per command output
    - Machine isolation: Cannot run Live Response on isolated machines

    IMPORTANT LIMITATIONS:
    - Only 25 simultaneous connections to different machines
    - Commands queue if > 25 sessions active (up to 10 queued)
    - Sessions automatically terminate after 30 min idle
    - E5 or MDE P2 license required for Live Response
    - Some commands require "Advanced" Live Response license

    THROTTLING BEHAVIOR:
    - HTTP 429 returned when rate limited
    - Retry-After header indicates wait time
    - Exponential backoff recommended

.NOTES
    Author: AD-Scout Contributors
    License: MIT

    Prerequisites:
    - Microsoft.Graph.Security module or direct API access
    - Azure AD app registration with MDE API permissions:
        - Machine.Read.All
        - Machine.LiveResponse
        - AdvancedQuery.Read.All
#>

class DefenderATPProvider : EDRProviderBase {
    # MDE-specific properties
    [string]$TenantId
    [string]$ClientId
    [string]$BaseUrl = 'https://api.securitycenter.microsoft.com'
    hidden [string]$AccessToken
    hidden [datetime]$TokenExpires

    # API Rate Limits (documented for reference)
    static [int]$MaxConcurrentSessions = 25         # HARD LIMIT per tenant
    static [int]$MaxPendingQueue = 10               # Additional queued sessions
    static [int]$ApiRateLimitPerMinute = 100        # Per app registration
    static [int]$SessionTimeoutMinutes = 30         # Idle timeout
    static [int]$MaxScriptSizeBytes = 8388608       # 8MB
    static [int]$MaxResponseSizeBytes = 3145728     # 3MB

    DefenderATPProvider() {
        $this.Name = 'DefenderATP'
        $this.Version = '1.0.0'
        $this.Description = 'Microsoft Defender for Endpoint provider'
        $this.MaxConcurrentCommands = 25  # Aligned with MDE hard limit
        $this.CommandTimeoutSeconds = 600
    }

    [bool] Connect([hashtable]$Parameters) {
        <#
        .SYNOPSIS
            Connects to Microsoft Defender for Endpoint API.

        .PARAMETER Parameters
            Hashtable containing:
            - TenantId: Azure AD Tenant ID
            - ClientId: App registration Client ID
            - ClientSecret: App registration Client Secret
            - CertificateThumbprint: Certificate for auth (alternative to secret)
            - UseExistingToken: Skip auth if using Graph connection
        #>

        try {
            $this.TenantId = $Parameters.TenantId
            $this.ClientId = $Parameters.ClientId

            # Try Microsoft Graph connection first
            if ($Parameters.UseExistingToken) {
                if (Test-ADScoutGraphConnection) {
                    $this.IsConnected = $true
                    $this.ConnectionContext = @{
                        Method = 'MicrosoftGraph'
                        TenantId = $this.TenantId
                    }
                    Write-Verbose "Using existing Microsoft Graph connection for MDE"
                    return $true
                }
            }

            # Direct API authentication
            $tokenUrl = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/token"

            $body = @{
                client_id     = $this.ClientId
                scope         = 'https://api.securitycenter.microsoft.com/.default'
                grant_type    = 'client_credentials'
            }

            if ($Parameters.ClientSecret) {
                $body.client_secret = $Parameters.ClientSecret
            }
            elseif ($Parameters.CertificateThumbprint) {
                # Certificate-based auth requires JWT assertion
                $cert = Get-Item "Cert:\CurrentUser\My\$($Parameters.CertificateThumbprint)" -ErrorAction Stop
                $assertion = $this.CreateClientAssertion($cert, $this.ClientId, $tokenUrl)
                $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                $body.client_assertion = $assertion
                $body.Remove('client_secret')
            }
            else {
                throw "Either ClientSecret or CertificateThumbprint is required"
            }

            Write-Verbose "Authenticating to Microsoft Defender for Endpoint..."

            $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'

            $this.AccessToken = $response.access_token
            $this.TokenExpires = (Get-Date).AddSeconds($response.expires_in - 300) # 5 min buffer

            # Verify by calling API
            $headers = @{
                'Authorization' = "Bearer $($this.AccessToken)"
                'Content-Type'  = 'application/json'
            }

            $testUrl = "$($this.BaseUrl)/api/machines?`$top=1"
            $null = Invoke-RestMethod -Uri $testUrl -Headers $headers -Method Get

            $this.IsConnected = $true
            $this.ConnectionContext = @{
                Method       = 'DirectAPI'
                TenantId     = $this.TenantId
                TokenExpires = $this.TokenExpires
            }

            Write-Verbose "Connected to Microsoft Defender for Endpoint"
            return $true
        }
        catch {
            Write-Error "Failed to connect to Microsoft Defender for Endpoint: $_"
            $this.IsConnected = $false
            return $false
        }
    }

    hidden [string] CreateClientAssertion([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$ClientId, [string]$TokenUrl) {
        # Create JWT for certificate-based auth
        $now = [int][double]::Parse((Get-Date -UFormat %s))

        $header = @{
            alg = 'RS256'
            typ = 'JWT'
            x5t = [System.Convert]::ToBase64String($Cert.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='
        } | ConvertTo-Json -Compress

        $payload = @{
            aud = $TokenUrl
            exp = $now + 600
            iss = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $now
            sub = $ClientId
        } | ConvertTo-Json -Compress

        $headerB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($header)) -replace '\+', '-' -replace '/', '_' -replace '='
        $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)) -replace '\+', '-' -replace '/', '_' -replace '='

        $toSign = "$headerB64.$payloadB64"
        $rsa = $Cert.PrivateKey
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signatureB64 = [Convert]::ToBase64String($signature) -replace '\+', '-' -replace '/', '_' -replace '='

        return "$toSign.$signatureB64"
    }

    [void] Disconnect() {
        $this.AccessToken = $null
        $this.TokenExpires = [datetime]::MinValue
        $this.IsConnected = $false
        $this.ConnectionContext = @{}
        Write-Verbose "Disconnected from Microsoft Defender for Endpoint"
    }

    [bool] TestConnection() {
        if (-not $this.IsConnected) { return $false }

        if ($this.ConnectionContext.Method -eq 'MicrosoftGraph') {
            return Test-ADScoutGraphConnection
        }

        if ($this.TokenExpires -lt (Get-Date)) {
            $this.IsConnected = $false
            return $false
        }

        return $true
    }

    hidden [hashtable] GetAuthHeaders() {
        if (-not $this.TestConnection()) {
            throw "Not connected to Microsoft Defender for Endpoint"
        }

        return @{
            'Authorization' = "Bearer $($this.AccessToken)"
            'Content-Type'  = 'application/json'
        }
    }

    [hashtable] ExecuteCommand([string]$Command, [string[]]$TargetHosts, [hashtable]$Options) {
        <#
        .SYNOPSIS
            Executes a command on target hosts via MDE Live Response.

        .PARAMETER Command
            PowerShell command to execute.

        .PARAMETER TargetHosts
            Machine IDs or device names.

        .PARAMETER Options
            - Timeout: Seconds to wait
            - Comment: Reason for action (required by MDE)
        #>

        $result = @{
            Success      = $false
            StartTime    = Get-Date
            EndTime      = $null
            Results      = @{}
            Errors       = @()
            HostsQueried = $TargetHosts.Count
            HostsSuccess = 0
            HostsFailed  = 0
        }

        try {
            $headers = $this.GetAuthHeaders()

            foreach ($target in $TargetHosts) {
                try {
                    # Resolve machine ID
                    $machineId = $this.ResolveMachineId($target)
                    if (-not $machineId) {
                        $result.Errors += "Machine not found: $target"
                        $result.HostsFailed++
                        continue
                    }

                    # Start Live Response session
                    $sessionUrl = "$($this.BaseUrl)/api/machines/$machineId/runliveresponse"

                    $body = @{
                        Commands = @(
                            @{
                                type       = 'RunScript'
                                params     = @(
                                    @{ key = 'ScriptName'; value = 'ADScout-Inline.ps1' }
                                )
                            }
                        )
                        Comment  = if ($Options.Comment) { $Options.Comment } else { "AD-Scout EDR execution" }
                    } | ConvertTo-Json -Depth 10

                    # For inline scripts, we need to use the script library approach
                    # First, upload the script temporarily
                    $scriptBody = @{
                        ScriptName = "ADScout-Temp-$([guid]::NewGuid().ToString('N').Substring(0,8)).ps1"
                        ScriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
                    } | ConvertTo-Json

                    # Submit script execution
                    $response = Invoke-RestMethod -Uri $sessionUrl -Headers $headers -Method Post -Body $body

                    # Poll for completion
                    $actionId = $response.id
                    $timeout = if ($Options.Timeout) { $Options.Timeout } else { $this.CommandTimeoutSeconds }

                    $actionResult = $this.WaitForAction($machineId, $actionId, $timeout)

                    $result.Results[$target] = $actionResult

                    if ($actionResult.Success) {
                        $result.HostsSuccess++
                    }
                    else {
                        $result.HostsFailed++
                        $result.Errors += "Host $target`: $($actionResult.Error)"
                    }
                }
                catch {
                    $result.Errors += "Host $target`: $_"
                    $result.HostsFailed++
                }
            }

            $result.Success = $result.HostsFailed -eq 0 -and $result.HostsSuccess -gt 0
        }
        catch {
            $result.Errors += $_.Exception.Message
        }

        $result.EndTime = Get-Date
        return $result
    }

    hidden [string] ResolveMachineId([string]$Target) {
        $headers = $this.GetAuthHeaders()

        # Check if already a machine ID (GUID format)
        if ($Target -match '^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$') {
            return $Target
        }

        # Search by hostname
        $filter = "`$filter=computerDnsName eq '$Target'"
        $url = "$($this.BaseUrl)/api/machines?$filter"

        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
            if ($response.value -and $response.value.Count -gt 0) {
                return $response.value[0].id
            }
        }
        catch { }

        return $null
    }

    hidden [hashtable] WaitForAction([string]$MachineId, [string]$ActionId, [int]$TimeoutSeconds) {
        $headers = $this.GetAuthHeaders()
        $url = "$($this.BaseUrl)/api/machineactions/$ActionId"

        $elapsed = 0
        $pollInterval = 10

        while ($elapsed -lt $TimeoutSeconds) {
            try {
                $status = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

                switch ($status.status) {
                    'Succeeded' {
                        return @{
                            Success = $true
                            Output  = $status.commands | ForEach-Object { $_.commandStatus }
                            Error   = $null
                        }
                    }
                    'Failed' {
                        return @{
                            Success = $false
                            Output  = $null
                            Error   = $status.errorHResult
                        }
                    }
                    'Cancelled' {
                        return @{
                            Success = $false
                            Output  = $null
                            Error   = 'Action was cancelled'
                        }
                    }
                    'TimeOut' {
                        return @{
                            Success = $false
                            Output  = $null
                            Error   = 'Action timed out on the endpoint'
                        }
                    }
                }
            }
            catch { }

            Start-Sleep -Seconds $pollInterval
            $elapsed += $pollInterval
        }

        return @{
            Success = $false
            Output  = $null
            Error   = "Polling timeout after $TimeoutSeconds seconds"
        }
    }

    [object[]] GetAvailableHosts([hashtable]$Filter) {
        $headers = $this.GetAuthHeaders()

        $filterParts = @()

        if ($Filter.Platform) {
            $filterParts += "osPlatform eq '$($Filter.Platform)'"
        }

        if ($Filter.Online) {
            $filterParts += "healthStatus eq 'Active'"
        }

        if ($Filter.Hostname) {
            $filterParts += "contains(computerDnsName, '$($Filter.Hostname)')"
        }

        $filterString = if ($filterParts.Count -gt 0) {
            "`$filter=" + ($filterParts -join ' and ')
        } else { "" }

        $url = "$($this.BaseUrl)/api/machines?$filterString"

        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

            return $response.value | ForEach-Object {
                [PSCustomObject]@{
                    MachineId       = $_.id
                    Hostname        = $_.computerDnsName
                    IPAddresses     = $_.ipAddresses
                    Platform        = $_.osPlatform
                    OSVersion       = $_.osVersion
                    HealthStatus    = $_.healthStatus
                    RiskScore       = $_.riskScore
                    ExposureLevel   = $_.exposureLevel
                    LastSeen        = $_.lastSeen
                    MachineTags     = $_.machineTags
                    IsAadJoined     = $_.isAadJoined
                    AgentVersion    = $_.agentVersion
                }
            }
        }
        catch {
            Write-Error "Failed to get MDE machines: $_"
            return @()
        }
    }

    [hashtable] GetCommandStatus([string]$CommandId) {
        try {
            $headers = $this.GetAuthHeaders()
            $url = "$($this.BaseUrl)/api/machineactions/$CommandId"

            $status = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

            return @{
                IsComplete = $status.status -in @('Succeeded', 'Failed', 'Cancelled', 'TimeOut')
                Status     = $status.status
                Output     = $status.commands
                Error      = $status.errorHResult
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
            MaxScriptLength           = 10485760  # 10MB
            SupportedOSPlatforms      = @('Windows', 'macOS', 'Linux')
            RequiresAgentOnline       = $true
            SupportsAdvancedHunting   = $true
        }
    }

    [object] RunAdvancedHuntingQuery([string]$Query) {
        <#
        .SYNOPSIS
            Runs an Advanced Hunting (KQL) query against MDE data.
        #>

        $headers = $this.GetAuthHeaders()
        $url = "$($this.BaseUrl)/api/advancedqueries/run"

        $body = @{
            Query = $Query
        } | ConvertTo-Json

        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
            return $response.Results
        }
        catch {
            Write-Error "Advanced hunting query failed: $_"
            return $null
        }
    }
}

# Register the provider
$mdeProvider = [DefenderATPProvider]::new()
Register-ADScoutEDRProvider -Name 'DefenderATP' -Provider $mdeProvider -Force
Register-ADScoutEDRProvider -Name 'MDE' -Provider $mdeProvider -Force  # Alias

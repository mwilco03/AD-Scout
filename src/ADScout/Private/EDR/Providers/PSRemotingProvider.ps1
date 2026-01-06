#Requires -Version 5.1

<#
.SYNOPSIS
    Native PowerShell Remoting (WinRM) provider for direct endpoint access.

.DESCRIPTION
    Implements the EDR provider interface using native PowerShell Remoting.
    This is a Tier 0 provider - the most direct approach when you have:
    - Network access to target hosts
    - Valid credentials with remote access
    - WinRM enabled on targets (default on modern Windows Server)

    No EDR agent required - uses built-in Windows remoting.

    CONSTRAINTS & LIMITS:
    =====================
    - Default WinRM max connections: 25 per host (configurable)
    - Max shells per user: 5 (configurable via WinRM)
    - Max memory per shell: 150MB (default)
    - Idle timeout: 7200000ms (2 hours, configurable)
    - Operation timeout: 60 seconds (default)
    - PowerShell 5.1+: Built-in support
    - PowerShell 7+: Cross-platform with SSH alternative

    AUTHENTICATION OPTIONS:
    - Kerberos: Default for domain environments (most secure)
    - NTLM: Fallback authentication
    - CredSSP: For double-hop scenarios (requires setup)
    - Basic: Over HTTPS only (not recommended)
    - Certificate: Client certificate authentication

    FIREWALL REQUIREMENTS:
    - TCP 5985 (HTTP) or TCP 5986 (HTTPS)
    - Windows Remote Management (WinRM) service running

.NOTES
    Author: AD-Scout Contributors
    License: MIT

    Prerequisites:
    - WinRM enabled on target hosts (Enable-PSRemoting)
    - Appropriate credentials with remote access
    - Network connectivity to targets (port 5985/5986)
    - For non-domain: TrustedHosts configuration may be needed

.LINK
    https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands
#>

class PSRemotingProvider : EDRProviderBase {
    # PSRemoting-specific properties
    [PSCredential]$Credential
    [string]$Authentication = 'Default'  # Default, Kerberos, Negotiate, NTLM, CredSSP, Basic
    [bool]$UseSSL = $false
    [int]$Port = 5985
    [string]$ConfigurationName = 'Microsoft.PowerShell'
    [string]$DomainController
    [string]$Domain

    # Session management
    hidden [hashtable]$ActiveSessions = @{}
    hidden [hashtable]$SessionOptions = @{}

    # Command tracking
    hidden [hashtable]$PendingCommands = @{}
    hidden [int]$CommandIdCounter = 0

    # Rate Limits (configurable WinRM defaults)
    static [int]$MaxConnectionsPerHost = 25
    static [int]$MaxShellsPerUser = 5
    static [int]$DefaultTimeoutSeconds = 300
    static [int]$MaxConcurrentOperations = 50

    PSRemotingProvider() {
        $this.Name = 'PSRemoting'
        $this.Version = '1.0.0'
        $this.Description = 'Native PowerShell Remoting (WinRM) provider - no agent required'
        $this.MaxConcurrentCommands = 50
        $this.CommandTimeoutSeconds = 300
    }

    [bool] Connect([hashtable]$Parameters) {
        <#
        .SYNOPSIS
            Initializes PSRemoting provider with credentials and options.

        .PARAMETER Parameters
            Hashtable containing:
            - Credential: PSCredential for authentication
            - Authentication: Kerberos, NTLM, CredSSP, Negotiate, Default
            - UseSSL: Use HTTPS (port 5986)
            - Port: Custom port (default 5985/5986)
            - ConfigurationName: PS session configuration
            - Domain: Target domain for AD queries
            - DomainController: Specific DC for AD queries
            - SessionOptions: Additional New-PSSessionOption parameters
        #>

        try {
            # Store configuration
            if ($Parameters.Credential) {
                $this.Credential = $Parameters.Credential
            }
            else {
                # Use current user context
                Write-Verbose "No credential provided - using current user context"
            }

            if ($Parameters.Authentication) {
                $validAuth = @('Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential',
                               'Credssp', 'Kerberos', 'Ntlm')
                if ($Parameters.Authentication -notin $validAuth) {
                    throw "Invalid authentication type. Valid options: $($validAuth -join ', ')"
                }
                $this.Authentication = $Parameters.Authentication
            }

            if ($Parameters.UseSSL) {
                $this.UseSSL = $true
                $this.Port = if ($Parameters.Port) { $Parameters.Port } else { 5986 }
            }
            elseif ($Parameters.Port) {
                $this.Port = $Parameters.Port
            }

            if ($Parameters.ConfigurationName) {
                $this.ConfigurationName = $Parameters.ConfigurationName
            }

            if ($Parameters.Domain) {
                $this.Domain = $Parameters.Domain
            }

            if ($Parameters.DomainController) {
                $this.DomainController = $Parameters.DomainController
            }

            # Build session options
            $sessionOptParams = @{
                OpenTimeout      = 30000
                OperationTimeout = ($this.CommandTimeoutSeconds * 1000)
                IdleTimeout      = 3600000  # 1 hour
            }

            if ($Parameters.SessionOptions) {
                foreach ($key in $Parameters.SessionOptions.Keys) {
                    $sessionOptParams[$key] = $Parameters.SessionOptions[$key]
                }
            }

            $this.SessionOptions = $sessionOptParams

            # Test connectivity if a DC is specified
            if ($this.DomainController) {
                Write-Verbose "Testing connectivity to $($this.DomainController)..."
                $testResult = $this.TestHostConnectivity($this.DomainController)
                if (-not $testResult) {
                    Write-Warning "Could not verify connectivity to $($this.DomainController)"
                }
            }

            $this.IsConnected = $true
            $this.ConnectionContext = @{
                Authentication    = $this.Authentication
                UseSSL           = $this.UseSSL
                Port             = $this.Port
                Domain           = $this.Domain
                DomainController = $this.DomainController
                HasCredential    = ($null -ne $this.Credential)
            }

            Write-Verbose "PSRemoting provider initialized"
            Write-Verbose "  Authentication: $($this.Authentication)"
            Write-Verbose "  Port: $($this.Port)"
            Write-Verbose "  SSL: $($this.UseSSL)"
            if ($this.Domain) { Write-Verbose "  Domain: $($this.Domain)" }

            return $true
        }
        catch {
            Write-Error "Failed to initialize PSRemoting provider: $_"
            $this.IsConnected = $false
            return $false
        }
    }

    [void] Disconnect() {
        try {
            # Close all active sessions
            foreach ($sessionEntry in $this.ActiveSessions.GetEnumerator()) {
                try {
                    $session = $sessionEntry.Value.Session
                    if ($session -and $session.State -eq 'Opened') {
                        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    }
                }
                catch { }
            }
            $this.ActiveSessions.Clear()
            $this.PendingCommands.Clear()

            $this.IsConnected = $false
            $this.ConnectionContext = @{}

            Write-Verbose "PSRemoting provider disconnected"
        }
        catch {
            Write-Warning "Error during PSRemoting disconnect: $_"
        }
    }

    [bool] TestConnection() {
        return $this.IsConnected
    }

    hidden [bool] TestHostConnectivity([string]$ComputerName) {
        try {
            $params = @{
                ComputerName = $ComputerName
                Count        = 1
                Quiet        = $true
                ErrorAction  = 'SilentlyContinue'
            }

            if (Test-Connection @params) {
                # Also try WinRM port
                $tcpTest = Test-NetConnection -ComputerName $ComputerName -Port $this.Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                return $tcpTest.TcpTestSucceeded
            }
            return $false
        }
        catch {
            return $false
        }
    }

    hidden [System.Management.Automation.Runspaces.PSSession] GetOrCreateSession([string]$ComputerName) {
        # Check for existing valid session
        if ($this.ActiveSessions.ContainsKey($ComputerName)) {
            $entry = $this.ActiveSessions[$ComputerName]
            if ($entry.Session.State -eq 'Opened') {
                $entry.LastUsed = Get-Date
                return $entry.Session
            }
            else {
                # Session is broken, remove it
                try { Remove-PSSession -Session $entry.Session -ErrorAction SilentlyContinue } catch { }
                $this.ActiveSessions.Remove($ComputerName)
            }
        }

        # Create new session
        $sessionParams = @{
            ComputerName      = $ComputerName
            ConfigurationName = $this.ConfigurationName
            ErrorAction       = 'Stop'
        }

        if ($this.Credential) {
            $sessionParams.Credential = $this.Credential
        }

        if ($this.Authentication -ne 'Default') {
            $sessionParams.Authentication = $this.Authentication
        }

        if ($this.UseSSL) {
            $sessionParams.UseSSL = $true
            $sessionParams.Port = $this.Port
        }
        elseif ($this.Port -ne 5985) {
            $sessionParams.Port = $this.Port
        }

        # Create session options
        $sessionOpt = New-PSSessionOption @($this.SessionOptions)
        $sessionParams.SessionOption = $sessionOpt

        Write-Verbose "Creating PSSession to $ComputerName..."
        $session = New-PSSession @sessionParams

        # Store session
        $this.ActiveSessions[$ComputerName] = @{
            Session   = $session
            Created   = Get-Date
            LastUsed  = Get-Date
        }

        return $session
    }

    [hashtable] ExecuteCommand([string]$Command, [string[]]$TargetHosts, [hashtable]$Options) {
        <#
        .SYNOPSIS
            Executes a PowerShell command on target hosts via PSRemoting.

        .PARAMETER Command
            The PowerShell script/command to execute.

        .PARAMETER TargetHosts
            Array of computer names.

        .PARAMETER Options
            Hashtable with:
            - Timeout: Seconds to wait for completion
            - ThrottleLimit: Max concurrent executions
            - AsJob: Run asynchronously
            - UseSession: Reuse existing sessions (default $true)
        #>

        if (-not $this.IsConnected) {
            throw "PSRemoting provider not initialized. Use Connect() first."
        }

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
            $timeout = if ($Options.Timeout) { $Options.Timeout } else { $this.CommandTimeoutSeconds }
            $throttleLimit = if ($Options.ThrottleLimit) { $Options.ThrottleLimit } else { 32 }
            $useSession = if ($null -ne $Options.UseSession) { $Options.UseSession } else { $true }

            Write-Verbose "Executing command on $($TargetHosts.Count) host(s)..."

            # Build script block
            $scriptBlock = [ScriptBlock]::Create($Command)

            if ($useSession -and $TargetHosts.Count -le 10) {
                # Use persistent sessions for small batches
                foreach ($hostName in $TargetHosts) {
                    try {
                        $session = $this.GetOrCreateSession($hostName)
                        $output = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ErrorAction Stop

                        $result.Results[$hostName] = @{
                            Success = $true
                            Output  = $output
                            Error   = $null
                        }
                        $result.HostsSuccess++
                    }
                    catch {
                        $result.Results[$hostName] = @{
                            Success = $false
                            Output  = $null
                            Error   = $_.Exception.Message
                        }
                        $result.HostsFailed++
                        $result.Errors += "Host $hostName`: $($_.Exception.Message)"
                    }
                }
            }
            else {
                # Use direct Invoke-Command for larger batches (more efficient)
                $invokeParams = @{
                    ComputerName  = $TargetHosts
                    ScriptBlock   = $scriptBlock
                    ErrorAction   = 'SilentlyContinue'
                    ErrorVariable = 'invokeErrors'
                    ThrottleLimit = $throttleLimit
                }

                if ($this.Credential) {
                    $invokeParams.Credential = $this.Credential
                }

                if ($this.Authentication -ne 'Default') {
                    $invokeParams.Authentication = $this.Authentication
                }

                if ($this.UseSSL) {
                    $invokeParams.UseSSL = $true
                    $invokeParams.Port = $this.Port
                }
                elseif ($this.Port -ne 5985) {
                    $invokeParams.Port = $this.Port
                }

                # Create session options for timeout
                $sessionOpt = New-PSSessionOption -OperationTimeout ($timeout * 1000) -OpenTimeout 30000
                $invokeParams.SessionOption = $sessionOpt

                # Execute
                $outputs = Invoke-Command @invokeParams

                # Process results
                $outputsByHost = @{}
                foreach ($output in $outputs) {
                    $hostName = $output.PSComputerName
                    if (-not $outputsByHost.ContainsKey($hostName)) {
                        $outputsByHost[$hostName] = @()
                    }
                    $outputsByHost[$hostName] += $output
                }

                # Build result set
                foreach ($hostName in $TargetHosts) {
                    if ($outputsByHost.ContainsKey($hostName)) {
                        $result.Results[$hostName] = @{
                            Success = $true
                            Output  = $outputsByHost[$hostName]
                            Error   = $null
                        }
                        $result.HostsSuccess++
                    }
                    else {
                        # Check if there was an error for this host
                        $hostError = $invokeErrors | Where-Object { $_.TargetObject -eq $hostName }
                        $result.Results[$hostName] = @{
                            Success = $false
                            Output  = $null
                            Error   = if ($hostError) { $hostError.Exception.Message } else { "No response from host" }
                        }
                        $result.HostsFailed++
                        $result.Errors += "Host $hostName`: $($result.Results[$hostName].Error)"
                    }
                }
            }

            $result.Success = $result.HostsFailed -eq 0
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
        }

        $result.EndTime = Get-Date
        return $result
    }

    [object[]] GetAvailableHosts([hashtable]$Filter) {
        <#
        .SYNOPSIS
            Gets available hosts from Active Directory.

        .PARAMETER Filter
            Hashtable with filter criteria:
            - OperatingSystem: OS pattern (e.g., '*Server*')
            - Enabled: $true for enabled only
            - Hostname: Hostname pattern
            - SearchBase: OU to search
            - DomainController: Specific DC to query
        #>

        if (-not $this.IsConnected) {
            throw "PSRemoting provider not initialized"
        }

        $hosts = @()

        try {
            # Build AD query
            $adParams = @{
                Filter     = '*'
                Properties = @('OperatingSystem', 'OperatingSystemVersion', 'IPv4Address',
                              'LastLogonDate', 'Enabled', 'DNSHostName', 'Description')
            }

            if ($Filter.SearchBase) {
                $adParams.SearchBase = $Filter.SearchBase
            }

            $dc = if ($Filter.DomainController) { $Filter.DomainController } else { $this.DomainController }
            if ($dc) {
                $adParams.Server = $dc
            }

            if ($this.Credential) {
                $adParams.Credential = $this.Credential
            }

            # Build LDAP filter
            $ldapFilters = @('(objectClass=computer)')

            if ($Filter.OperatingSystem) {
                $ldapFilters += "(operatingSystem=$($Filter.OperatingSystem))"
            }

            if ($Filter.Enabled -eq $true) {
                $ldapFilters += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            }

            if ($Filter.Hostname) {
                $ldapFilters += "(name=$($Filter.Hostname))"
            }

            if ($ldapFilters.Count -gt 1) {
                $adParams.LDAPFilter = "(&$($ldapFilters -join ''))"
            }
            else {
                $adParams.LDAPFilter = $ldapFilters[0]
            }

            # Execute query
            if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                $adParams.Remove('LDAPFilter')
                $filterParts = @()

                if ($Filter.OperatingSystem) {
                    $filterParts += "OperatingSystem -like '$($Filter.OperatingSystem)'"
                }
                if ($Filter.Enabled -eq $true) {
                    $filterParts += 'Enabled -eq $true'
                }
                if ($Filter.Hostname) {
                    $filterParts += "Name -like '$($Filter.Hostname)'"
                }

                $adParams.Filter = if ($filterParts.Count -gt 0) {
                    $filterParts -join ' -and '
                } else { '*' }

                $computers = Get-ADComputer @adParams
            }
            else {
                # Fallback to DirectorySearcher
                $computers = $this.GetComputersViaDirectorySearcher($Filter)
            }

            $hosts = $computers | ForEach-Object {
                [PSCustomObject]@{
                    ComputerName      = $_.Name
                    DNSHostName       = $_.DNSHostName
                    IPv4Address       = $_.IPv4Address
                    OperatingSystem   = $_.OperatingSystem
                    OSVersion         = $_.OperatingSystemVersion
                    Enabled           = $_.Enabled
                    LastLogonDate     = $_.LastLogonDate
                    Description       = $_.Description
                    DistinguishedName = $_.DistinguishedName
                }
            }
        }
        catch {
            Write-Error "Failed to get hosts: $_"
        }

        return $hosts
    }

    hidden [object[]] GetComputersViaDirectorySearcher([hashtable]$Filter) {
        $searcher = [ADSISearcher]::new()

        $ldapFilters = @('(objectClass=computer)')
        if ($Filter.OperatingSystem) {
            $ldapFilters += "(operatingSystem=$($Filter.OperatingSystem))"
        }
        if ($Filter.Enabled -eq $true) {
            $ldapFilters += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        }
        if ($Filter.Hostname) {
            $ldapFilters += "(name=$($Filter.Hostname))"
        }

        $searcher.Filter = "(&$($ldapFilters -join ''))"
        $searcher.PropertiesToLoad.AddRange(@('name', 'dnshostname', 'operatingSystem',
            'operatingSystemVersion', 'lastLogonTimestamp', 'description', 'distinguishedName', 'userAccountControl'))

        return $searcher.FindAll() | ForEach-Object {
            $props = $_.Properties
            [PSCustomObject]@{
                Name              = $props['name'][0]
                DNSHostName       = $props['dnshostname'][0]
                OperatingSystem   = $props['operatingsystem'][0]
                OperatingSystemVersion = $props['operatingsystemversion'][0]
                Enabled           = -not (($props['useraccountcontrol'][0] -band 2) -eq 2)
                Description       = $props['description'][0]
                DistinguishedName = $props['distinguishedname'][0]
            }
        }
    }

    [hashtable] GetCommandStatus([string]$CommandId) {
        if ($this.PendingCommands.ContainsKey($CommandId)) {
            $cmd = $this.PendingCommands[$CommandId]
            if ($cmd.Job) {
                $state = $cmd.Job.State
                return @{
                    IsComplete = $state -eq 'Completed' -or $state -eq 'Failed'
                    Output     = if ($state -eq 'Completed') { Receive-Job -Job $cmd.Job } else { $null }
                    Error      = if ($state -eq 'Failed') { $cmd.Job.ChildJobs[0].JobStateInfo.Reason.Message } else { $null }
                    CommandId  = $CommandId
                    State      = $state
                }
            }
        }

        return @{
            IsComplete = $true
            Error      = "Command '$CommandId' not found"
            CommandId  = $CommandId
        }
    }

    [hashtable] GetCapabilities() {
        return @{
            SupportsParallelExecution = $true
            SupportsScriptExecution   = $true
            SupportsFileUpload        = $true   # Via Copy-Item -ToSession
            SupportsFileDownload      = $true   # Via Copy-Item -FromSession
            MaxScriptLength           = [int]::MaxValue
            MaxBatchSize              = 1000
            SupportedOSPlatforms      = @('Windows')
            RequiresAgent             = $false
            SupportsKerberos          = $true
            SupportsNTLM              = $true
            SupportsCredSSP           = $true
            RequiresNetworkAccess     = $true
            DefaultPort               = 5985
            SSLPort                   = 5986
        }
    }

    # Additional PSRemoting-specific methods

    [object[]] GetDomainControllers() {
        <#
        .SYNOPSIS
            Gets domain controllers from Active Directory.
        #>
        return $this.GetAvailableHosts(@{
            OperatingSystem = '*Server*'
        }) | Where-Object {
            $_.DistinguishedName -match 'OU=Domain Controllers' -or
            $_.Description -match 'Domain Controller'
        }
    }

    [bool] TestWinRM([string]$ComputerName) {
        <#
        .SYNOPSIS
            Tests if WinRM is accessible on a target host.
        #>
        try {
            $params = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
            }

            if ($this.Credential) {
                $params.Credential = $this.Credential
            }

            if ($this.Authentication -ne 'Default') {
                $params.Authentication = $this.Authentication
            }

            if ($this.UseSSL) {
                $params.UseSSL = $true
                $params.Port = $this.Port
            }

            Test-WSMan @params | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }

    [void] CleanupStaleSessions([int]$MaxAgeMinutes = 30) {
        <#
        .SYNOPSIS
            Removes sessions that haven't been used recently.
        #>
        $cutoff = (Get-Date).AddMinutes(-$MaxAgeMinutes)

        $staleSessions = $this.ActiveSessions.GetEnumerator() | Where-Object {
            $_.Value.LastUsed -lt $cutoff
        }

        foreach ($entry in $staleSessions) {
            try {
                Remove-PSSession -Session $entry.Value.Session -ErrorAction SilentlyContinue
            }
            catch { }
            $this.ActiveSessions.Remove($entry.Key)
            Write-Verbose "Removed stale session to $($entry.Key)"
        }
    }
}

# Register the provider
$psRemotingProvider = [PSRemotingProvider]::new()
Register-ADScoutEDRProvider -Name 'PSRemoting' -Provider $psRemotingProvider -Force

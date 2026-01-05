function Connect-ADScoutEDR {
    <#
    .SYNOPSIS
        Connects to an EDR platform for remote command execution.

    .DESCRIPTION
        Establishes a connection to an Endpoint Detection and Response (EDR) platform
        such as CrowdStrike Falcon, Microsoft Defender for Endpoint, or Carbon Black.
        This enables security professionals to query Active Directory and endpoint
        configurations through the EDR's remote execution capabilities, without
        requiring direct administrative access to target systems.

        Supports multiple simultaneous connections via the -Name parameter for
        scenarios with separate MSSP tenants or multiple EDR platforms.

    .PARAMETER Provider
        The EDR provider to connect to. Supported values:
        - PSFalcon: CrowdStrike Falcon (requires PSFalcon module)
        - DefenderATP/MDE: Microsoft Defender for Endpoint
        - CarbonBlack: VMware Carbon Black (requires Carbon Black module)

    .PARAMETER Name
        Optional name for this connection session. Use this to maintain multiple
        simultaneous connections to different MSSP tenants or EDR platforms.
        If not specified, defaults to the provider name.

    .PARAMETER ClientId
        The API client ID for authentication. For PSFalcon, this is the Falcon API
        Client ID. For MDE, this is the Azure AD application Client ID.

    .PARAMETER ClientSecret
        The API client secret for authentication.

    .PARAMETER TenantId
        Azure AD Tenant ID (required for DefenderATP/MDE).

    .PARAMETER Cloud
        For PSFalcon: The Falcon cloud region (us-1, us-2, eu-1, us-gov-1).
        Default is us-1.

    .PARAMETER MemberCid
        For PSFalcon MSSP: The child CID to impersonate within a parent tenant.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for certificate-based authentication.

    .PARAMETER Credential
        PSCredential object containing ClientId as username and ClientSecret as password.

    .PARAMETER UseExistingToken
        Attempt to use an existing authenticated session (if available).

    .PARAMETER SetActive
        Set this connection as the active/default connection. Default is $true.

    .EXAMPLE
        Connect-ADScoutEDR -Provider PSFalcon -ClientId $clientId -ClientSecret $secret -Cloud us-1

        Connects to CrowdStrike Falcon using API credentials.

    .EXAMPLE
        # Multiple MSSP tenant connections
        Connect-ADScoutEDR -Provider PSFalcon -Name 'MSSP-ClientA' -ClientId $clientIdA -ClientSecret $secretA -Cloud us-1
        Connect-ADScoutEDR -Provider PSFalcon -Name 'MSSP-ClientB' -ClientId $clientIdB -ClientSecret $secretB -Cloud us-2

        # Switch between them
        Switch-ADScoutEDRConnection -Name 'MSSP-ClientA'
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01'

        Switch-ADScoutEDRConnection -Name 'MSSP-ClientB'
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC02'

        # Disconnect specific session
        Disconnect-ADScoutEDR -Name 'MSSP-ClientA'

    .EXAMPLE
        Connect-ADScoutEDR -Provider DefenderATP -TenantId $tenantId -ClientId $appId -ClientSecret $secret

        Connects to Microsoft Defender for Endpoint.

    .EXAMPLE
        $cred = Get-Credential
        Connect-ADScoutEDR -Provider PSFalcon -Credential $cred

        Connects using a credential object (username = ClientId, password = ClientSecret).

    .OUTPUTS
        Boolean. Returns $true if connection successful, $false otherwise.

    .NOTES
        Prerequisites vary by provider:
        - PSFalcon: Install-Module PSFalcon
        - DefenderATP: Azure AD app with MDE API permissions
        - Both require appropriate API scopes for remote execution

    .LINK
        https://github.com/CrowdStrike/psfalcon
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
    #>
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PSFalcon', 'DefenderATP', 'MDE', 'CarbonBlack')]
        [string]$Provider,

        [Parameter()]
        [string]$Name,

        [Parameter(ParameterSetName = 'Explicit')]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Explicit')]
        [securestring]$ClientSecret,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [ValidateSet('us-1', 'us-2', 'eu-1', 'us-gov-1')]
        [string]$Cloud = 'us-1',

        [Parameter()]
        [string]$MemberCid,

        [Parameter()]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$UseExistingToken,

        [Parameter()]
        [bool]$SetActive = $true
    )

    # Initialize session registry if needed
    if (-not $script:ADScoutEDRSessions) {
        $script:ADScoutEDRSessions = @{}
    }

    # Normalize provider name
    if ($Provider -eq 'MDE') { $Provider = 'DefenderATP' }

    # Default session name to provider if not specified
    if (-not $Name) {
        $Name = $Provider
    }

    # Check if session name already exists
    if ($script:ADScoutEDRSessions.ContainsKey($Name)) {
        Write-Warning "Session '$Name' already exists. Use Disconnect-ADScoutEDR -Name '$Name' first, or choose a different name."
        return $false
    }

    # Get the provider template and create new instance for this session
    $providerTemplate = Get-ADScoutEDRProvider -Name $Provider

    if (-not $providerTemplate) {
        Write-Error "EDR Provider '$Provider' is not registered. Ensure the provider module is loaded."
        return $false
    }

    # Create a new provider instance for this session
    $providerInstance = switch ($Provider) {
        'PSFalcon' { [PSFalconProvider]::new() }
        'DefenderATP' { [DefenderATPProvider]::new() }
        default { $providerTemplate }
    }

    # Build connection parameters
    $connectionParams = @{
        UseExistingToken = $UseExistingToken.IsPresent
    }

    # Handle credential input
    if ($Credential) {
        $connectionParams.ClientId = $Credential.UserName
        $connectionParams.ClientSecret = $Credential.GetNetworkCredential().Password
    }
    elseif ($ClientId) {
        $connectionParams.ClientId = $ClientId
        if ($ClientSecret) {
            $connectionParams.ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            )
        }
    }

    # Add provider-specific parameters
    switch ($Provider) {
        'PSFalcon' {
            $connectionParams.Cloud = $Cloud
            if ($MemberCid) { $connectionParams.MemberCid = $MemberCid }
        }
        'DefenderATP' {
            if (-not $TenantId -and -not $UseExistingToken) {
                Write-Error "TenantId is required for Microsoft Defender for Endpoint"
                return $false
            }
            $connectionParams.TenantId = $TenantId
            if ($CertificateThumbprint) {
                $connectionParams.CertificateThumbprint = $CertificateThumbprint
            }
        }
    }

    try {
        Write-Verbose "Connecting to EDR provider: $Provider (Session: $Name)"
        $result = $providerInstance.Connect($connectionParams)

        if ($result) {
            # Store session
            $script:ADScoutEDRSessions[$Name] = @{
                Provider     = $providerInstance
                ProviderName = $Provider
                Cloud        = $Cloud
                MemberCid    = $MemberCid
                TenantId     = $TenantId
                ConnectedAt  = Get-Date
            }

            Write-Verbose "Successfully connected to $Provider (Session: $Name)"

            # Set as active if requested
            if ($SetActive) {
                $script:ADScoutEDRActiveSession = $Name
                $script:ADScoutEDRConnected = $true
                $script:ADScoutEDRProvider = $Provider
            }

            return $true
        }
        else {
            Write-Warning "Connection to $Provider returned false"
            return $false
        }
    }
    catch {
        Write-Error "Failed to connect to $Provider`: $_"
        return $false
    }
}

function Disconnect-ADScoutEDR {
    <#
    .SYNOPSIS
        Disconnects from an EDR platform.

    .DESCRIPTION
        Terminates the EDR session and clears cached connection state.
        Can disconnect a specific named session or all sessions.

    .PARAMETER Name
        Name of the session to disconnect. If not specified, disconnects
        the currently active session.

    .PARAMETER All
        Disconnect all active EDR sessions.

    .EXAMPLE
        Disconnect-ADScoutEDR

        Disconnects the currently active session.

    .EXAMPLE
        Disconnect-ADScoutEDR -Name 'MSSP-ClientA'

        Disconnects a specific named session.

    .EXAMPLE
        Disconnect-ADScoutEDR -All

        Disconnects all EDR sessions.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(ParameterSetName = 'Single')]
        [string]$Name,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )

    if (-not $script:ADScoutEDRSessions) {
        $script:ADScoutEDRSessions = @{}
    }

    if ($All) {
        # Disconnect all sessions
        foreach ($sessionName in @($script:ADScoutEDRSessions.Keys)) {
            $session = $script:ADScoutEDRSessions[$sessionName]
            if ($session -and $session.Provider) {
                try {
                    Write-Verbose "Disconnecting session: $sessionName"
                    $session.Provider.Disconnect()
                }
                catch {
                    Write-Warning "Error disconnecting '$sessionName': $_"
                }
            }
            $script:ADScoutEDRSessions.Remove($sessionName)
        }

        $script:ADScoutEDRActiveSession = $null
        $script:ADScoutEDRConnected = $false
        $script:ADScoutEDRProvider = $null

        Write-Verbose "All EDR sessions disconnected"
    }
    else {
        # Disconnect specific session
        $targetSession = if ($Name) { $Name } else { $script:ADScoutEDRActiveSession }

        if (-not $targetSession) {
            Write-Warning "No active EDR session to disconnect"
            return
        }

        if ($script:ADScoutEDRSessions.ContainsKey($targetSession)) {
            $session = $script:ADScoutEDRSessions[$targetSession]
            if ($session -and $session.Provider) {
                try {
                    $session.Provider.Disconnect()
                    Write-Verbose "Disconnected from EDR session: $targetSession"
                }
                catch {
                    Write-Warning "Error during disconnect: $_"
                }
            }
            $script:ADScoutEDRSessions.Remove($targetSession)

            # If we disconnected the active session, clear active state or switch
            if ($targetSession -eq $script:ADScoutEDRActiveSession) {
                $remainingSessions = @($script:ADScoutEDRSessions.Keys)
                if ($remainingSessions.Count -gt 0) {
                    # Switch to another available session
                    $script:ADScoutEDRActiveSession = $remainingSessions[0]
                    $script:ADScoutEDRProvider = $script:ADScoutEDRSessions[$remainingSessions[0]].ProviderName
                    Write-Verbose "Switched active session to: $($remainingSessions[0])"
                }
                else {
                    $script:ADScoutEDRActiveSession = $null
                    $script:ADScoutEDRConnected = $false
                    $script:ADScoutEDRProvider = $null
                }
            }
        }
        else {
            Write-Warning "Session '$targetSession' not found"
        }
    }
}

function Switch-ADScoutEDRConnection {
    <#
    .SYNOPSIS
        Switches the active EDR connection to a different named session.

    .DESCRIPTION
        When multiple EDR sessions are connected (e.g., multiple MSSP tenants),
        use this to switch which session is used by default for commands.

    .PARAMETER Name
        Name of the session to make active.

    .EXAMPLE
        # Connect to multiple MSSP tenants
        Connect-ADScoutEDR -Provider PSFalcon -Name 'ClientA' -ClientId $idA -ClientSecret $secretA
        Connect-ADScoutEDR -Provider PSFalcon -Name 'ClientB' -ClientId $idB -ClientSecret $secretB -SetActive $false

        # Work with Client A (default active)
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC-A'

        # Switch to Client B
        Switch-ADScoutEDRConnection -Name 'ClientB'
        Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC-B'

    .EXAMPLE
        Get-ADScoutEDRConnection | Format-Table Name, Provider, ConnectedAt
        Switch-ADScoutEDRConnection -Name 'MSSP-TenantX'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name
    )

    if (-not $script:ADScoutEDRSessions) {
        $script:ADScoutEDRSessions = @{}
    }

    if (-not $script:ADScoutEDRSessions.ContainsKey($Name)) {
        $available = $script:ADScoutEDRSessions.Keys -join ', '
        if ($available) {
            Write-Error "Session '$Name' not found. Available sessions: $available"
        }
        else {
            Write-Error "No EDR sessions connected. Use Connect-ADScoutEDR first."
        }
        return
    }

    $session = $script:ADScoutEDRSessions[$Name]

    # Verify session is still valid
    if (-not $session.Provider.TestConnection()) {
        Write-Warning "Session '$Name' connection is no longer valid. Reconnect required."
        return
    }

    $script:ADScoutEDRActiveSession = $Name
    $script:ADScoutEDRConnected = $true
    $script:ADScoutEDRProvider = $session.ProviderName

    Write-Verbose "Switched active EDR session to: $Name ($($session.ProviderName))"
}

function Get-ADScoutEDRConnection {
    <#
    .SYNOPSIS
        Gets information about current EDR connections.

    .DESCRIPTION
        Lists all active EDR sessions with their connection details.

    .PARAMETER Name
        Get a specific named session. If not specified, returns all sessions.

    .PARAMETER Active
        Return only the currently active session.

    .EXAMPLE
        Get-ADScoutEDRConnection

        Lists all connected EDR sessions.

    .EXAMPLE
        Get-ADScoutEDRConnection -Active

        Gets the currently active session.

    .EXAMPLE
        Get-ADScoutEDRConnection | Format-Table Name, Provider, Cloud, IsActive, ConnectedAt
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name,

        [Parameter()]
        [switch]$Active
    )

    if (-not $script:ADScoutEDRSessions) {
        $script:ADScoutEDRSessions = @{}
    }

    if ($Active) {
        if ($script:ADScoutEDRActiveSession -and $script:ADScoutEDRSessions.ContainsKey($script:ADScoutEDRActiveSession)) {
            $session = $script:ADScoutEDRSessions[$script:ADScoutEDRActiveSession]
            return [PSCustomObject]@{
                PSTypeName   = 'ADScout.EDR.Connection'
                Name         = $script:ADScoutEDRActiveSession
                Provider     = $session.ProviderName
                Cloud        = $session.Cloud
                MemberCid    = $session.MemberCid
                TenantId     = $session.TenantId
                IsActive     = $true
                IsConnected  = $session.Provider.TestConnection()
                ConnectedAt  = $session.ConnectedAt
            }
        }
        return $null
    }

    if ($Name) {
        if ($script:ADScoutEDRSessions.ContainsKey($Name)) {
            $session = $script:ADScoutEDRSessions[$Name]
            return [PSCustomObject]@{
                PSTypeName   = 'ADScout.EDR.Connection'
                Name         = $Name
                Provider     = $session.ProviderName
                Cloud        = $session.Cloud
                MemberCid    = $session.MemberCid
                TenantId     = $session.TenantId
                IsActive     = ($Name -eq $script:ADScoutEDRActiveSession)
                IsConnected  = $session.Provider.TestConnection()
                ConnectedAt  = $session.ConnectedAt
            }
        }
        return $null
    }

    # Return all sessions
    foreach ($sessionName in $script:ADScoutEDRSessions.Keys) {
        $session = $script:ADScoutEDRSessions[$sessionName]
        [PSCustomObject]@{
            PSTypeName   = 'ADScout.EDR.Connection'
            Name         = $sessionName
            Provider     = $session.ProviderName
            Cloud        = $session.Cloud
            MemberCid    = $session.MemberCid
            TenantId     = $session.TenantId
            IsActive     = ($sessionName -eq $script:ADScoutEDRActiveSession)
            IsConnected  = $session.Provider.TestConnection()
            ConnectedAt  = $session.ConnectedAt
        }
    }
}

function Test-ADScoutEDRConnection {
    <#
    .SYNOPSIS
        Tests if EDR connection is available.

    .DESCRIPTION
        Returns $true if connected to an EDR platform with a valid session.

    .PARAMETER Name
        Test a specific named session. If not specified, tests the active session.

    .EXAMPLE
        if (Test-ADScoutEDRConnection) {
            Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01'
        }

    .EXAMPLE
        Test-ADScoutEDRConnection -Name 'MSSP-ClientA'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string]$Name
    )

    if (-not $script:ADScoutEDRSessions) {
        return $false
    }

    $targetSession = if ($Name) { $Name } else { $script:ADScoutEDRActiveSession }

    if (-not $targetSession) {
        return $false
    }

    if (-not $script:ADScoutEDRSessions.ContainsKey($targetSession)) {
        return $false
    }

    $session = $script:ADScoutEDRSessions[$targetSession]
    if (-not $session -or -not $session.Provider) {
        return $false
    }

    return $session.Provider.TestConnection()
}

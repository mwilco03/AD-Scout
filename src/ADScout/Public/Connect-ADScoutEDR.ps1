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

    .PARAMETER Provider
        The EDR provider to connect to. Supported values:
        - PSFalcon: CrowdStrike Falcon (requires PSFalcon module)
        - DefenderATP/MDE: Microsoft Defender for Endpoint
        - CarbonBlack: VMware Carbon Black (requires Carbon Black module)

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
        For PSFalcon MSSP: The child CID to impersonate.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for certificate-based authentication.

    .PARAMETER Credential
        PSCredential object containing ClientId as username and ClientSecret as password.

    .PARAMETER UseExistingToken
        Attempt to use an existing authenticated session (if available).

    .EXAMPLE
        Connect-ADScoutEDR -Provider PSFalcon -ClientId $clientId -ClientSecret $secret -Cloud us-1

        Connects to CrowdStrike Falcon using API credentials.

    .EXAMPLE
        Connect-ADScoutEDR -Provider DefenderATP -TenantId $tenantId -ClientId $appId -ClientSecret $secret

        Connects to Microsoft Defender for Endpoint.

    .EXAMPLE
        $cred = Get-Credential
        Connect-ADScoutEDR -Provider PSFalcon -Credential $cred

        Connects using a credential object (username = ClientId, password = ClientSecret).

    .EXAMPLE
        Connect-ADScoutEDR -Provider PSFalcon -UseExistingToken

        Uses an existing PSFalcon session if available.

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
        [switch]$UseExistingToken
    )

    # Normalize provider name
    if ($Provider -eq 'MDE') { $Provider = 'DefenderATP' }

    # Get the provider instance
    $providerInstance = Get-ADScoutEDRProvider -Name $Provider

    if (-not $providerInstance) {
        Write-Error "EDR Provider '$Provider' is not registered. Ensure the provider module is loaded."
        return $false
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
        Write-Verbose "Connecting to EDR provider: $Provider"
        $result = $providerInstance.Connect($connectionParams)

        if ($result) {
            # Set as active provider
            Set-ADScoutEDRProvider -Provider $providerInstance
            Write-Verbose "Successfully connected to $Provider"

            # Store connection state in module scope
            $script:ADScoutEDRConnected = $true
            $script:ADScoutEDRProvider = $Provider

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
        Disconnects from the current EDR platform.

    .DESCRIPTION
        Terminates the EDR session and clears cached connection state.

    .EXAMPLE
        Disconnect-ADScoutEDR
    #>
    [CmdletBinding()]
    param()

    $provider = Get-ADScoutEDRProvider -Active

    if ($provider) {
        try {
            $provider.Disconnect()
            Write-Verbose "Disconnected from EDR provider: $($provider.Name)"
        }
        catch {
            Write-Warning "Error during disconnect: $_"
        }
    }

    $script:ADScoutEDRConnected = $false
    $script:ADScoutEDRProvider = $null
}

function Test-ADScoutEDRConnection {
    <#
    .SYNOPSIS
        Tests if EDR connection is available.

    .DESCRIPTION
        Returns $true if connected to an EDR platform with a valid session.

    .EXAMPLE
        if (Test-ADScoutEDRConnection) {
            Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost 'DC01'
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $provider = Get-ADScoutEDRProvider -Active

    if (-not $provider) {
        return $false
    }

    return $provider.TestConnection()
}

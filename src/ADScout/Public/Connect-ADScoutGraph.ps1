function Connect-ADScoutGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph for Entra ID security scanning.

    .DESCRIPTION
        Establishes a connection to Microsoft Graph API for querying Entra ID
        (Azure AD) security configurations. Supports interactive, service principal,
        and managed identity authentication methods.

        This is an OPTIONAL feature. Microsoft.Graph module must be installed.

    .PARAMETER Interactive
        Use interactive browser-based authentication.

    .PARAMETER TenantId
        The Azure AD tenant ID for service principal authentication.

    .PARAMETER ClientId
        The application (client) ID for service principal authentication.

    .PARAMETER ClientSecret
        The client secret for service principal authentication.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for service principal authentication.

    .PARAMETER ManagedIdentity
        Use Azure Managed Identity authentication (for Azure VMs/Functions).

    .PARAMETER Scopes
        Additional Graph API scopes to request beyond defaults.

    .EXAMPLE
        Connect-ADScoutGraph -Interactive
        Connects using interactive browser authentication.

    .EXAMPLE
        Connect-ADScoutGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $thumbprint
        Connects using certificate-based service principal authentication.

    .EXAMPLE
        Connect-ADScoutGraph -ManagedIdentity
        Connects using Azure Managed Identity.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(ParameterSetName = 'ServicePrincipalSecret', Mandatory)]
        [Parameter(ParameterSetName = 'ServicePrincipalCert', Mandatory)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'ServicePrincipalSecret', Mandatory)]
        [Parameter(ParameterSetName = 'ServicePrincipalCert', Mandatory)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'ServicePrincipalSecret', Mandatory)]
        [securestring]$ClientSecret,

        [Parameter(ParameterSetName = 'ServicePrincipalCert', Mandatory)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [switch]$ManagedIdentity,

        [Parameter()]
        [string[]]$Scopes
    )

    # Check if Microsoft.Graph module is available
    $graphModule = Get-Module -ListAvailable Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
    if (-not $graphModule) {
        Write-Warning @"
Microsoft.Graph module is not installed. Entra ID scanning requires this module.

To install, run:
    Install-Module Microsoft.Graph -Scope CurrentUser

Or install only required submodules:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Install-Module Microsoft.Graph.Users -Scope CurrentUser
    Install-Module Microsoft.Graph.Groups -Scope CurrentUser
    Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
    Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser
    Install-Module Microsoft.Graph.Reports -Scope CurrentUser

Entra ID rules will be skipped during scans.
"@
        return $false
    }

    # Default scopes for security scanning
    $defaultScopes = @(
        'User.Read.All'
        'Group.Read.All'
        'Application.Read.All'
        'Directory.Read.All'
        'RoleManagement.Read.Directory'
        'Policy.Read.All'
        'AuditLog.Read.All'
        'IdentityRiskyUser.Read.All'
        'UserAuthenticationMethod.Read.All'
    )

    if ($Scopes) {
        $allScopes = $defaultScopes + $Scopes | Select-Object -Unique
    }
    else {
        $allScopes = $defaultScopes
    }

    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Verbose "Already connected to Microsoft Graph as $($context.Account)"

            # Check if we have the required scopes
            $missingScopes = $defaultScopes | Where-Object { $context.Scopes -notcontains $_ }
            if ($missingScopes) {
                Write-Warning "Current connection is missing scopes: $($missingScopes -join ', ')"
                Write-Warning "Some Entra ID rules may not work. Reconnect with full permissions."
            }

            # Store connection state in module scope
            $script:ADScoutGraphConnected = $true
            $script:ADScoutGraphContext = $context

            return $true
        }

        Write-Verbose "Connecting to Microsoft Graph..."

        switch ($PSCmdlet.ParameterSetName) {
            'Interactive' {
                Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            }
            'ServicePrincipalSecret' {
                $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
            }
            'ServicePrincipalCert' {
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            }
            'ManagedIdentity' {
                Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
            }
        }

        $context = Get-MgContext
        if ($context) {
            Write-Verbose "Connected to Microsoft Graph"
            Write-Verbose "  Tenant: $($context.TenantId)"
            Write-Verbose "  Account: $($context.Account)"
            Write-Verbose "  Scopes: $($context.Scopes -join ', ')"

            # Store connection state
            $script:ADScoutGraphConnected = $true
            $script:ADScoutGraphContext = $context

            return $true
        }
        else {
            Write-Error "Failed to establish Microsoft Graph connection"
            return $false
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        $script:ADScoutGraphConnected = $false
        return $false
    }
}

function Disconnect-ADScoutGraph {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph.

    .DESCRIPTION
        Terminates the Microsoft Graph session and clears cached Entra ID data.

    .EXAMPLE
        Disconnect-ADScoutGraph
    #>
    [CmdletBinding()]
    param()

    try {
        if (Get-Module Microsoft.Graph.Authentication) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }

        $script:ADScoutGraphConnected = $false
        $script:ADScoutGraphContext = $null

        # Clear Entra ID cache
        $cacheKeys = @(
            'EntraUsers', 'EntraGroups', 'EntraApps',
            'EntraRoles', 'EntraPolicies', 'EntraSignIns'
        )
        foreach ($key in $cacheKeys) {
            Set-ADScoutCache -Key $key -Value $null
        }

        Write-Verbose "Disconnected from Microsoft Graph"
    }
    catch {
        Write-Warning "Error during disconnect: $_"
    }
}

function Test-ADScoutGraphConnection {
    <#
    .SYNOPSIS
        Tests if Microsoft Graph connection is available for Entra ID scanning.

    .DESCRIPTION
        Returns $true if connected to Microsoft Graph with appropriate permissions,
        $false otherwise. Used internally by Entra ID rules to skip gracefully.

    .EXAMPLE
        if (Test-ADScoutGraphConnection) { # Run Entra ID checks }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Quick check of module variable
    if ($script:ADScoutGraphConnected) {
        # Verify connection is still valid
        try {
            $context = Get-MgContext -ErrorAction Stop
            if ($context) {
                return $true
            }
        }
        catch {
            $script:ADScoutGraphConnected = $false
        }
    }

    # Check if module is available
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication -ErrorAction SilentlyContinue)) {
        return $false
    }

    # Check for active connection
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $script:ADScoutGraphConnected = $true
            $script:ADScoutGraphContext = $context
            return $true
        }
    }
    catch {
        # Not connected
    }

    return $false
}

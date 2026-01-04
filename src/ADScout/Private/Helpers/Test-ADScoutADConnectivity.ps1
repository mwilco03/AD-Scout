function Test-ADScoutADConnectivity {
    <#
    .SYNOPSIS
        Tests Active Directory connectivity and module availability.

    .DESCRIPTION
        Performs a comprehensive check of AD connectivity including:
        1. RSAT/AD PowerShell module availability
        2. Module can be loaded (not just installed)
        3. Domain controller reachability
        4. Basic LDAP query capability

        Returns a status object with details on what works and what doesn't.

    .PARAMETER Domain
        Target domain to test. Defaults to current user's domain.

    .PARAMETER Server
        Specific domain controller to test.

    .PARAMETER Credential
        Credentials to use for the connectivity test.

    .PARAMETER Quick
        Skip the LDAP test for faster results.

    .EXAMPLE
        $status = Test-ADScoutADConnectivity
        if ($status.CanQuery) { ... }

    .OUTPUTS
        PSCustomObject with connectivity status details.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$Quick
    )

    $result = [PSCustomObject]@{
        ADModuleInstalled     = $false
        ADModuleLoadable      = $false
        GroupPolicyInstalled  = $false
        DCReachable           = $false
        CanQuery              = $false
        PreferredMethod       = 'DirectorySearcher'  # Default fallback
        Domain                = $Domain
        Server                = $Server
        TestedAt              = Get-Date
        Error                 = $null
        Details               = @{}
    }

    # Step 1: Check if AD module is installed
    $adModule = Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue
    $result.ADModuleInstalled = $null -ne $adModule

    if ($result.ADModuleInstalled) {
        $result.Details['ADModuleVersion'] = $adModule.Version.ToString()

        # Step 2: Try to load the module
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $result.ADModuleLoadable = $true
            $result.PreferredMethod = 'ADModule'
        }
        catch {
            $result.Details['ADModuleLoadError'] = $_.Exception.Message
            # Common issue: RSAT installed but AD Web Services not accessible
        }
    }

    # Check GroupPolicy module
    $gpModule = Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue
    $result.GroupPolicyInstalled = $null -ne $gpModule

    # Step 3: Test DC reachability
    $dcToTest = $Server
    if (-not $dcToTest) {
        # Try to find a DC
        try {
            if ($Domain) {
                # Use DNS to find DC
                $dnsResult = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -ErrorAction Stop
                $dcToTest = $dnsResult[0].NameTarget
            }
            else {
                # Use current domain
                $dcToTest = $env:LOGONSERVER -replace '\\\\', ''
                if (-not $dcToTest) {
                    # Try environment variable
                    $dcToTest = $env:USERDNSDOMAIN
                }
            }
        }
        catch {
            $result.Details['DCLookupError'] = $_.Exception.Message
        }
    }

    if ($dcToTest) {
        $result.Details['TestedDC'] = $dcToTest

        # Quick TCP test to LDAP port
        try {
            $tcpTest = Test-NetConnection -ComputerName $dcToTest -Port 389 -WarningAction SilentlyContinue -InformationLevel Quiet
            $result.DCReachable = $tcpTest
        }
        catch {
            # Test-NetConnection not available (PS 5.1 without networking module)
            try {
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.Connect($dcToTest, 389)
                $result.DCReachable = $socket.Connected
                $socket.Close()
            }
            catch {
                $result.DCReachable = $false
                $result.Details['TCPTestError'] = $_.Exception.Message
            }
        }
    }

    # Step 4: Try an actual LDAP query (unless Quick mode)
    if (-not $Quick -and $result.DCReachable) {
        try {
            # Try DirectorySearcher as the universal fallback
            $ldapPath = if ($Server) {
                "LDAP://$Server/RootDSE"
            }
            else {
                "LDAP://RootDSE"
            }

            $directoryEntry = if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry(
                    $ldapPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
            }
            else {
                New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
            }

            # Try to read a property to confirm access
            $defaultNC = $directoryEntry.Properties["defaultNamingContext"][0]
            if ($defaultNC) {
                $result.CanQuery = $true
                $result.Details['DefaultNamingContext'] = $defaultNC
                $result.Domain = ($defaultNC -replace 'DC=', '' -replace ',', '.')
            }
        }
        catch {
            $result.Details['LDAPQueryError'] = $_.Exception.Message
            $result.Error = $_.Exception.Message
        }
    }
    elseif ($Quick -and $result.DCReachable) {
        # Assume we can query if DC is reachable
        $result.CanQuery = $true
    }

    # Set preferred method based on results
    if ($result.ADModuleLoadable -and $result.CanQuery) {
        $result.PreferredMethod = 'ADModule'
    }
    elseif ($result.CanQuery) {
        $result.PreferredMethod = 'DirectorySearcher'
    }
    else {
        $result.PreferredMethod = 'None'
    }

    return $result
}

function Get-ADScoutCollectorMethod {
    <#
    .SYNOPSIS
        Determines the best method for AD data collection.

    .DESCRIPTION
        Returns 'ADModule' if the ActiveDirectory module is available and working,
        otherwise returns 'DirectorySearcher' for the .NET fallback.

    .PARAMETER Force
        Force a fresh check instead of using cached result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [switch]$Force
    )

    # Use cached result if available and not forced
    if (-not $Force -and $script:ADScoutCollectorMethod) {
        return $script:ADScoutCollectorMethod
    }

    # Quick check - just verify module loads
    $adModule = Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue

    if ($adModule) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $script:ADScoutCollectorMethod = 'ADModule'
            return 'ADModule'
        }
        catch {
            Write-Verbose "AD module installed but failed to load: $_"
        }
    }

    $script:ADScoutCollectorMethod = 'DirectorySearcher'
    return 'DirectorySearcher'
}

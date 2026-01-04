function Get-ADScoutComputerData {
    <#
    .SYNOPSIS
        Collects computer account data from Active Directory.

    .DESCRIPTION
        Retrieves computer accounts with security-relevant properties.

    .PARAMETER Domain
        Target domain name.

    .PARAMETER Server
        Specific domain controller to query.

    .PARAMETER Credential
        Credentials for AD queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential
    )

    $cacheKey = "Computers:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached computer data"
        return $cached
    }

    Write-Verbose "Collecting computer data from Active Directory"

    $properties = @(
        'Name'
        'SamAccountName'
        'DistinguishedName'
        'DNSHostName'
        'Enabled'
        'OperatingSystem'
        'OperatingSystemVersion'
        'OperatingSystemServicePack'
        'LastLogonDate'
        'PasswordLastSet'
        'WhenCreated'
        'WhenChanged'
        'ServicePrincipalNames'
        'TrustedForDelegation'
        'TrustedToAuthForDelegation'
        'msDS-AllowedToDelegateTo'
        'UserAccountControl'
        'Description'
        'MemberOf'
    )

    $computers = @()

    if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $params = @{
                Filter     = '*'
                Properties = $properties
            }

            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }

            $computers = Get-ADComputer @params
        }
        catch {
            Write-Warning "AD module failed for computers: $_. Falling back to DirectorySearcher."
            $computers = Get-ADScoutComputerDataFallback -Domain $Domain -Server $Server -Credential $Credential
        }
    }
    else {
        Write-Verbose "AD module not available, using DirectorySearcher"
        $computers = Get-ADScoutComputerDataFallback -Domain $Domain -Server $Server -Credential $Credential
    }

    $normalizedComputers = $computers | ForEach-Object {
        [PSCustomObject]@{
            Name                       = $_.Name
            SamAccountName             = $_.SamAccountName
            DistinguishedName          = $_.DistinguishedName
            DNSHostName                = $_.DNSHostName
            Enabled                    = $_.Enabled
            OperatingSystem            = $_.OperatingSystem
            OperatingSystemVersion     = $_.OperatingSystemVersion
            LastLogonDate              = $_.LastLogonDate
            PasswordLastSet            = $_.PasswordLastSet
            WhenCreated                = $_.WhenCreated
            ServicePrincipalNames      = $_.ServicePrincipalNames
            TrustedForDelegation       = $_.TrustedForDelegation
            TrustedToAuthForDelegation = $_.TrustedToAuthForDelegation
            AllowedToDelegateTo        = $_.'msDS-AllowedToDelegateTo'
            Description                = $_.Description
            MemberOf                   = $_.MemberOf
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedComputers

    Write-Verbose "Collected $($normalizedComputers.Count) computer accounts"

    return $normalizedComputers
}

function Get-ADScoutComputerDataFallback {
    <#
    .SYNOPSIS
        Fallback computer data collector using DirectorySearcher.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    Write-Verbose "Using DirectorySearcher fallback for computer data"

    $computers = @()

    try {
        # Use centralized DirectorySearcher helper
        $propertiesToLoad = @(
            'name', 'samaccountname', 'distinguishedname', 'dnshostname',
            'operatingsystem', 'operatingsystemversion', 'lastlogontimestamp',
            'pwdlastset', 'whencreated', 'whenchanged', 'serviceprincipalname',
            'useraccountcontrol', 'description', 'memberof',
            'msds-allowedtodelegateto'
        )

        $searcher = New-ADScoutDirectorySearcher -Domain $Domain -Server $Server -Credential $Credential `
            -Filter '(objectClass=computer)' `
            -Properties $propertiesToLoad

        $results = $searcher.FindAll()

        foreach ($result in $results) {
            $props = $result.Properties

            # Decode UserAccountControl using centralized helper
            $uac = if ($props['useraccountcontrol']) { $props['useraccountcontrol'][0] } else { 0 }
            $uacInfo = ConvertFrom-ADScoutUAC -UAC $uac

            # Convert timestamps
            $lastLogon = if ($props['lastlogontimestamp']) {
                try { [datetime]::FromFileTime($props['lastlogontimestamp'][0]) } catch { $null }
            } else { $null }

            $pwdLastSet = if ($props['pwdlastset']) {
                try { [datetime]::FromFileTime($props['pwdlastset'][0]) } catch { $null }
            } else { $null }

            $computers += [PSCustomObject]@{
                Name                       = if ($props['name']) { $props['name'][0] } else { $null }
                SamAccountName             = if ($props['samaccountname']) { $props['samaccountname'][0] } else { $null }
                DistinguishedName          = if ($props['distinguishedname']) { $props['distinguishedname'][0] } else { $null }
                DNSHostName                = if ($props['dnshostname']) { $props['dnshostname'][0] } else { $null }
                Enabled                    = $uacInfo.Enabled
                OperatingSystem            = if ($props['operatingsystem']) { $props['operatingsystem'][0] } else { $null }
                OperatingSystemVersion     = if ($props['operatingsystemversion']) { $props['operatingsystemversion'][0] } else { $null }
                LastLogonDate              = $lastLogon
                PasswordLastSet            = $pwdLastSet
                WhenCreated                = if ($props['whencreated']) { $props['whencreated'][0] } else { $null }
                ServicePrincipalNames      = @($props['serviceprincipalname'])
                TrustedForDelegation       = $uacInfo.TrustedForDelegation
                TrustedToAuthForDelegation = $uacInfo.TrustedToAuthForDelegation
                AllowedToDelegateTo        = @($props['msds-allowedtodelegateto'])
                Description                = if ($props['description']) { $props['description'][0] } else { $null }
                MemberOf                   = @($props['memberof'])
            }
        }

        $results.Dispose()
        $searcher.Dispose()
    }
    catch {
        Write-Warning "DirectorySearcher failed for computers: $_"
    }

    return $computers
}

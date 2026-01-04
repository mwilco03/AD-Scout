function Get-ADScoutUserData {
    <#
    .SYNOPSIS
        Collects user account data from Active Directory.

    .DESCRIPTION
        Retrieves user accounts with security-relevant properties.
        Uses AD module when available, falls back to DirectorySearcher.

    .PARAMETER Domain
        Target domain name.

    .PARAMETER Server
        Specific domain controller to query.

    .PARAMETER Credential
        Credentials for AD queries.

    .PARAMETER SearchBase
        LDAP path to start the search.

    .PARAMETER Properties
        Specific properties to retrieve.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$Properties
    )

    # Check cache first
    $cacheKey = "Users:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached user data"
        return $cached
    }

    Write-Verbose "Collecting user data from Active Directory"

    # Default properties for security analysis
    $defaultProperties = @(
        'SamAccountName'
        'DistinguishedName'
        'UserPrincipalName'
        'DisplayName'
        'Enabled'
        'PasswordNeverExpires'
        'PasswordNotRequired'
        'PasswordLastSet'
        'LastLogonDate'
        'LastLogonTimestamp'
        'LogonCount'
        'WhenCreated'
        'WhenChanged'
        'MemberOf'
        'AdminCount'
        'UserAccountControl'
        'ServicePrincipalNames'
        'msDS-AllowedToDelegateTo'
        'TrustedForDelegation'
        'TrustedToAuthForDelegation'
        'Description'
        'SIDHistory'
        'PrimaryGroupID'
        'ObjectSID'
        # Ephemeral persistence attributes
        'ScriptPath'
        'ProfilePath'
        'HomeDirectory'
        'HomeDrive'
        'msTSInitialProgram'
        'msTSWorkDirectory'
        'msTSHomeDirectory'
        'msTSHomeDrive'
        'msDS-KeyCredentialLink'
    )

    if (-not $Properties) {
        $Properties = $defaultProperties
    }

    $users = @()

    # Try AD module first
    if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Write-Verbose "Using ActiveDirectory module"

            $params = @{
                Filter     = '*'
                Properties = $Properties
            }

            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }
            if ($SearchBase) { $params.SearchBase = $SearchBase }

            Import-Module ActiveDirectory -ErrorAction Stop
            $users = Get-ADUser @params
        }
        catch {
            Write-Warning "AD module failed: $_. Falling back to DirectorySearcher."
            $users = Get-ADScoutUserDataFallback @PSBoundParameters
        }
    }
    else {
        Write-Verbose "AD module not available, using DirectorySearcher"
        $users = Get-ADScoutUserDataFallback @PSBoundParameters
    }

    # Normalize to PSCustomObject for consistency
    $normalizedUsers = $users | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName           = $_.SamAccountName
            DistinguishedName        = $_.DistinguishedName
            UserPrincipalName        = $_.UserPrincipalName
            DisplayName              = $_.DisplayName
            Enabled                  = $_.Enabled
            PasswordNeverExpires     = $_.PasswordNeverExpires
            PasswordNotRequired      = $_.PasswordNotRequired
            PasswordLastSet          = $_.PasswordLastSet
            LastLogonDate            = $_.LastLogonDate
            LogonCount               = $_.LogonCount
            WhenCreated              = $_.WhenCreated
            WhenChanged              = $_.WhenChanged
            MemberOf                 = $_.MemberOf
            AdminCount               = $_.AdminCount
            UserAccountControl       = $_.UserAccountControl
            ServicePrincipalNames    = $_.ServicePrincipalNames
            AllowedToDelegateTo      = $_.'msDS-AllowedToDelegateTo'
            TrustedForDelegation     = $_.TrustedForDelegation
            TrustedToAuthForDelegation = $_.TrustedToAuthForDelegation
            Description              = $_.Description
            SIDHistory               = $_.SIDHistory
            PrimaryGroupID           = $_.PrimaryGroupID
            ObjectSID                = $_.ObjectSID
            # Ephemeral persistence attributes
            ScriptPath               = $_.ScriptPath
            ProfilePath              = $_.ProfilePath
            HomeDirectory            = $_.HomeDirectory
            HomeDrive                = $_.HomeDrive
            TSInitialProgram         = $_.msTSInitialProgram
            TSWorkDirectory          = $_.msTSWorkDirectory
            TSHomeDirectory          = $_.msTSHomeDirectory
            TSHomeDrive              = $_.msTSHomeDrive
            KeyCredentialLink        = $_.'msDS-KeyCredentialLink'
        }
    }

    # Cache the results
    Set-ADScoutCache -Key $cacheKey -Value $normalizedUsers

    Write-Verbose "Collected $($normalizedUsers.Count) user accounts"

    return $normalizedUsers
}

function Get-ADScoutUserDataFallback {
    <#
    .SYNOPSIS
        Fallback method using DirectorySearcher for user data.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase,
        [string[]]$Properties
    )

    Write-Verbose "Using DirectorySearcher fallback"

    try {
        # Use centralized DirectorySearcher helper
        $ldapProperties = @(
            'samaccountname', 'distinguishedname', 'userprincipalname',
            'displayname', 'useraccountcontrol', 'pwdlastset',
            'lastlogon', 'lastlogontimestamp', 'logoncount', 'whencreated', 'whenchanged',
            'memberof', 'admincount', 'serviceprincipalname',
            'msds-allowedtodelegateto', 'description', 'sidhistory',
            'primarygroupid', 'objectsid',
            # Ephemeral persistence attributes
            'scriptpath', 'profilepath', 'homedirectory', 'homedrive',
            'mstsinitialprogram', 'mstsworkdirectory', 'mstshomedirectory', 'mstshomedrive',
            'msds-keycredentiallink'
        )

        $searcher = New-ADScoutDirectorySearcher -Domain $Domain -Server $Server -Credential $Credential `
            -SearchBase $SearchBase `
            -Filter '(&(objectCategory=person)(objectClass=user))' `
            -Properties $ldapProperties

        $results = $searcher.FindAll()

        $users = foreach ($result in $results) {
            $props = $result.Properties

            # Decode UserAccountControl flags using centralized helper
            $uac = [int]$props['useraccountcontrol'][0]
            $uacInfo = ConvertFrom-ADScoutUAC -UAC $uac

            [PSCustomObject]@{
                SamAccountName           = [string]$props['samaccountname'][0]
                DistinguishedName        = [string]$props['distinguishedname'][0]
                UserPrincipalName        = [string]$props['userprincipalname'][0]
                DisplayName              = [string]$props['displayname'][0]
                Enabled                  = $uacInfo.Enabled
                PasswordNeverExpires     = $uacInfo.PasswordNeverExpires
                PasswordNotRequired      = $uacInfo.PasswordNotRequired
                PasswordLastSet          = if ($props['pwdlastset'][0]) {
                    [DateTime]::FromFileTime([Int64]$props['pwdlastset'][0])
                } else { $null }
                LastLogonDate            = if ($props['lastlogontimestamp'][0]) {
                    [DateTime]::FromFileTime([Int64]$props['lastlogontimestamp'][0])
                } else { $null }
                LogonCount               = $props['logoncount'][0]
                WhenCreated              = $props['whencreated'][0]
                WhenChanged              = $props['whenchanged'][0]
                MemberOf                 = @($props['memberof'])
                AdminCount               = $props['admincount'][0]
                UserAccountControl       = $uac
                ServicePrincipalNames    = @($props['serviceprincipalname'])
                AllowedToDelegateTo      = @($props['msds-allowedtodelegateto'])
                TrustedForDelegation     = $uacInfo.TrustedForDelegation
                TrustedToAuthForDelegation = $uacInfo.TrustedToAuthForDelegation
                Description              = [string]$props['description'][0]
                SIDHistory               = @($props['sidhistory'])
                PrimaryGroupID           = $props['primarygroupid'][0]
                ObjectSID                = (New-Object Security.Principal.SecurityIdentifier($props['objectsid'][0], 0)).Value
                # Ephemeral persistence attributes
                ScriptPath               = [string]$props['scriptpath'][0]
                ProfilePath              = [string]$props['profilepath'][0]
                HomeDirectory            = [string]$props['homedirectory'][0]
                HomeDrive                = [string]$props['homedrive'][0]
                TSInitialProgram         = [string]$props['mstsinitialprogram'][0]
                TSWorkDirectory          = [string]$props['mstsworkdirectory'][0]
                TSHomeDirectory          = [string]$props['mstshomedirectory'][0]
                TSHomeDrive              = [string]$props['mstshomedrive'][0]
                KeyCredentialLink        = @($props['msds-keycredentiallink'])
            }
        }

        return $users
    }
    catch {
        Write-Error "DirectorySearcher failed: $_"
        return @()
    }
    finally {
        if ($searcher) { $searcher.Dispose() }
        if ($results) { $results.Dispose() }
    }
}

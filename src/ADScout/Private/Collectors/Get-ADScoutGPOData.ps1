function Get-ADScoutGPOData {
    <#
    .SYNOPSIS
        Collects Group Policy Object data from Active Directory.

    .DESCRIPTION
        Retrieves GPOs with security-relevant settings.
        Uses GroupPolicy module when available, falls back to DirectorySearcher.

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

    $cacheKey = "GPOs:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached GPO data"
        return $cached
    }

    Write-Verbose "Collecting GPO data from Active Directory"

    $gpos = @()

    # Check for GroupPolicy module (separate from AD module)
    $gpModuleAvailable = Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue

    if ($gpModuleAvailable) {
        try {
            Write-Verbose "Using GroupPolicy module"
            Import-Module GroupPolicy -ErrorAction Stop

            $params = @{
                All = $true
            }

            if ($Domain) { $params.Domain = $Domain }
            if ($Server) { $params.Server = $Server }

            $gpos = Get-GPO @params
        }
        catch {
            Write-Warning "GroupPolicy module failed: $_. Falling back to DirectorySearcher."
            $gpos = Get-ADScoutGPODataFallback -Domain $Domain -Server $Server -Credential $Credential
        }
    }
    else {
        Write-Verbose "GroupPolicy module not available, using DirectorySearcher"
        $gpos = Get-ADScoutGPODataFallback -Domain $Domain -Server $Server -Credential $Credential
    }

    $normalizedGPOs = $gpos | ForEach-Object {
        [PSCustomObject]@{
            DisplayName      = $_.DisplayName
            Id               = $_.Id
            DomainName       = $_.DomainName
            Owner            = $_.Owner
            GpoStatus        = $_.GpoStatus
            CreationTime     = $_.CreationTime
            ModificationTime = $_.ModificationTime
            WmiFilter        = $_.WmiFilter
            Description      = $_.Description
            UserVersion      = $_.UserVersion
            ComputerVersion  = $_.ComputerVersion
            FilePath         = $_.FilePath
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedGPOs

    Write-Verbose "Collected $($normalizedGPOs.Count) GPOs"

    return $normalizedGPOs
}

function Get-ADScoutGPODataFallback {
    <#
    .SYNOPSIS
        Fallback GPO data collector using DirectorySearcher.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    Write-Verbose "Using DirectorySearcher fallback for GPO data"

    $gpos = @()

    try {
        # Build LDAP path
        $ldapPath = if ($Server) {
            "LDAP://$Server"
        } elseif ($Domain) {
            $domainDN = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
            "LDAP://$domainDN"
        } else {
            "LDAP://RootDSE"
        }

        $directoryEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        # Get the domain DN for GPO container
        if ($ldapPath -eq "LDAP://RootDSE") {
            $defaultNC = $directoryEntry.Properties["defaultNamingContext"][0]
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Policies,CN=System,$defaultNC")
            $domainDN = $defaultNC
        } else {
            $rootDse = [ADSI]"LDAP://RootDSE"
            $defaultNC = $rootDse.Properties["defaultNamingContext"][0]
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Policies,CN=System,$defaultNC")
            $domainDN = $defaultNC
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = "(objectClass=groupPolicyContainer)"
        $searcher.PageSize = 100

        $propertiesToLoad = @(
            'displayname', 'name', 'cn', 'gpcfilesyspath',
            'versionnumber', 'flags', 'whencreated', 'whenchanged',
            'ntsecuritydescriptor'
        )

        foreach ($prop in $propertiesToLoad) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }

        $results = $searcher.FindAll()

        # Extract domain name from DN
        $domainName = ($domainDN -replace 'DC=', '' -replace ',', '.')

        foreach ($result in $results) {
            $props = $result.Properties

            # Extract GUID from CN
            $gpoGuid = if ($props['cn']) { $props['cn'][0] } else { $null }

            # Decode version number - high 16 bits = user version, low 16 bits = computer version
            $versionNumber = if ($props['versionnumber']) { $props['versionnumber'][0] } else { 0 }
            $userVersion = [math]::Floor($versionNumber / 65536)
            $computerVersion = $versionNumber % 65536

            # Decode flags for GPO status
            $flags = if ($props['flags']) { $props['flags'][0] } else { 0 }
            $gpoStatus = switch ($flags) {
                0 { 'AllSettingsEnabled' }
                1 { 'UserSettingsDisabled' }
                2 { 'ComputerSettingsDisabled' }
                3 { 'AllSettingsDisabled' }
                default { 'Unknown' }
            }

            # Get owner from security descriptor if available
            $owner = $null
            if ($props['ntsecuritydescriptor']) {
                try {
                    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sd.SetSecurityDescriptorBinaryForm($props['ntsecuritydescriptor'][0])
                    $owner = $sd.Owner
                }
                catch {
                    # Ignore SD parsing errors
                }
            }

            $gpos += [PSCustomObject]@{
                DisplayName      = if ($props['displayname']) { $props['displayname'][0] } else { $null }
                Id               = $gpoGuid
                DomainName       = $domainName
                Owner            = $owner
                GpoStatus        = $gpoStatus
                CreationTime     = if ($props['whencreated']) { $props['whencreated'][0] } else { $null }
                ModificationTime = if ($props['whenchanged']) { $props['whenchanged'][0] } else { $null }
                WmiFilter        = $null  # Would need separate query
                Description      = $null  # Not stored in AD directly
                UserVersion      = $userVersion
                ComputerVersion  = $computerVersion
                FilePath         = if ($props['gpcfilesyspath']) { $props['gpcfilesyspath'][0] } else { $null }
            }
        }

        $results.Dispose()
        $searcher.Dispose()
    }
    catch {
        Write-Warning "DirectorySearcher failed for GPOs: $_"
    }

    return $gpos
}

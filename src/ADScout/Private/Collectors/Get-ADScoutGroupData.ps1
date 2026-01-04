function Get-ADScoutGroupData {
    <#
    .SYNOPSIS
        Collects group data from Active Directory.

    .DESCRIPTION
        Retrieves security groups with membership information.

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

    $cacheKey = "Groups:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached group data"
        return $cached
    }

    Write-Verbose "Collecting group data from Active Directory"

    $properties = @(
        'Name'
        'SamAccountName'
        'DistinguishedName'
        'GroupCategory'
        'GroupScope'
        'Members'
        'MemberOf'
        'WhenCreated'
        'WhenChanged'
        'Description'
        'AdminCount'
        'ObjectSID'
    )

    $groups = @()

    if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $params = @{
                Filter     = '*'
                Properties = $properties
            }

            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }

            $groups = Get-ADGroup @params
        }
        catch {
            Write-Warning "AD module failed for groups: $_. Falling back to DirectorySearcher."
            $groups = Get-ADScoutGroupDataFallback -Domain $Domain -Server $Server -Credential $Credential
        }
    }
    else {
        Write-Verbose "AD module not available, using DirectorySearcher"
        $groups = Get-ADScoutGroupDataFallback -Domain $Domain -Server $Server -Credential $Credential
    }

    $normalizedGroups = $groups | ForEach-Object {
        [PSCustomObject]@{
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            DistinguishedName = $_.DistinguishedName
            GroupCategory     = $_.GroupCategory
            GroupScope        = $_.GroupScope
            Members           = $_.Members
            MemberOf          = $_.MemberOf
            WhenCreated       = $_.WhenCreated
            WhenChanged       = $_.WhenChanged
            Description       = $_.Description
            AdminCount        = $_.AdminCount
            ObjectSID         = $_.ObjectSID
            MemberCount       = @($_.Members).Count
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedGroups

    Write-Verbose "Collected $($normalizedGroups.Count) groups"

    return $normalizedGroups
}

function Get-ADScoutGroupDataFallback {
    <#
    .SYNOPSIS
        Fallback group data collector using DirectorySearcher.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    Write-Verbose "Using DirectorySearcher fallback for group data"

    $groups = @()

    try {
        # Use centralized DirectorySearcher helper
        $propertiesToLoad = @(
            'name', 'samaccountname', 'distinguishedname', 'grouptype',
            'member', 'memberof', 'whencreated', 'whenchanged',
            'description', 'admincount', 'objectsid'
        )

        $searcher = New-ADScoutDirectorySearcher -Domain $Domain -Server $Server -Credential $Credential `
            -Filter '(objectClass=group)' `
            -Properties $propertiesToLoad

        $results = $searcher.FindAll()

        foreach ($result in $results) {
            $props = $result.Properties

            # Decode group type
            $groupType = if ($props['grouptype']) { $props['grouptype'][0] } else { 0 }
            $groupCategory = if ($groupType -band 0x80000000) { 'Security' } else { 'Distribution' }
            $groupScope = switch ($groupType -band 0xE) {
                2 { 'Global' }
                4 { 'DomainLocal' }
                8 { 'Universal' }
                default { 'Unknown' }
            }

            # Convert SID
            $objectSid = if ($props['objectsid']) {
                try {
                    (New-Object System.Security.Principal.SecurityIdentifier($props['objectsid'][0], 0)).Value
                } catch { $null }
            } else { $null }

            $groups += [PSCustomObject]@{
                Name              = if ($props['name']) { $props['name'][0] } else { $null }
                SamAccountName    = if ($props['samaccountname']) { $props['samaccountname'][0] } else { $null }
                DistinguishedName = if ($props['distinguishedname']) { $props['distinguishedname'][0] } else { $null }
                GroupCategory     = $groupCategory
                GroupScope        = $groupScope
                Members           = @($props['member'])
                MemberOf          = @($props['memberof'])
                WhenCreated       = if ($props['whencreated']) { $props['whencreated'][0] } else { $null }
                WhenChanged       = if ($props['whenchanged']) { $props['whenchanged'][0] } else { $null }
                Description       = if ($props['description']) { $props['description'][0] } else { $null }
                AdminCount        = if ($props['admincount']) { $props['admincount'][0] } else { $null }
                ObjectSID         = $objectSid
            }
        }

        $results.Dispose()
        $searcher.Dispose()
    }
    catch {
        Write-Warning "DirectorySearcher failed for groups: $_"
    }

    return $groups
}

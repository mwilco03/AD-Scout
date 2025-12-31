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
            Write-Warning "AD module failed for groups: $_"
            $groups = @()
        }
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

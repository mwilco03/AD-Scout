function Get-ADScoutTrustData {
    <#
    .SYNOPSIS
        Collects domain trust data from Active Directory.

    .DESCRIPTION
        Retrieves trust relationships with security properties.

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

    $cacheKey = "Trusts:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached trust data"
        return $cached
    }

    Write-Verbose "Collecting trust data from Active Directory"

    $trusts = @()

    if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $params = @{
                Filter = '*'
            }

            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }

            $trusts = Get-ADTrust @params
        }
        catch {
            Write-Warning "AD module failed for trusts: $_"
            $trusts = @()
        }
    }

    $normalizedTrusts = $trusts | ForEach-Object {
        [PSCustomObject]@{
            Name                  = $_.Name
            Source                = $_.Source
            Target                = $_.Target
            Direction             = $_.Direction
            TrustType             = $_.TrustType
            DisallowTransivity    = $_.DisallowTransivity
            SelectiveAuthentication = $_.SelectiveAuthentication
            SIDFilteringForestAware = $_.SIDFilteringForestAware
            SIDFilteringQuarantined = $_.SIDFilteringQuarantined
            TGTDelegation         = $_.TGTDelegation
            IntraForest           = $_.IntraForest
            IsTreeParent          = $_.IsTreeParent
            IsTreeRoot            = $_.IsTreeRoot
            WhenCreated           = $_.WhenCreated
            WhenChanged           = $_.WhenChanged
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedTrusts

    Write-Verbose "Collected $($normalizedTrusts.Count) trusts"

    return $normalizedTrusts
}

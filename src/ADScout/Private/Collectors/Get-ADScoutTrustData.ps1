function Get-ADScoutTrustData {
    <#
    .SYNOPSIS
        Collects domain trust data from Active Directory.

    .DESCRIPTION
        Retrieves trust relationships with security properties.
        Uses AD module when available, falls back to DirectorySearcher.

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

    # Use centralized method detection (cached)
    $collectorMethod = Get-ADScoutCollectorMethod

    if ($collectorMethod -eq 'ADModule') {
        try {
            Write-Verbose "Using ActiveDirectory module"

            $params = @{
                Filter = '*'
            }

            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }

            $trusts = Get-ADTrust @params
        }
        catch {
            Write-Warning "AD module failed for trusts: $_. Falling back to DirectorySearcher."
            $trusts = Get-ADScoutTrustDataFallback -Domain $Domain -Server $Server -Credential $Credential
        }
    }
    else {
        Write-Verbose "Using DirectorySearcher method"
        $trusts = Get-ADScoutTrustDataFallback -Domain $Domain -Server $Server -Credential $Credential
    }

    $normalizedTrusts = $trusts | ForEach-Object {
        [PSCustomObject]@{
            Name                    = $_.Name
            Source                  = $_.Source
            Target                  = $_.Target
            Direction               = $_.Direction
            TrustType               = $_.TrustType
            DisallowTransivity      = $_.DisallowTransivity
            SelectiveAuthentication = $_.SelectiveAuthentication
            SIDFilteringForestAware = $_.SIDFilteringForestAware
            SIDFilteringQuarantined = $_.SIDFilteringQuarantined
            TGTDelegation           = $_.TGTDelegation
            IntraForest             = $_.IntraForest
            IsTreeParent            = $_.IsTreeParent
            IsTreeRoot              = $_.IsTreeRoot
            WhenCreated             = $_.WhenCreated
            WhenChanged             = $_.WhenChanged
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedTrusts

    Write-Verbose "Collected $($normalizedTrusts.Count) trusts"

    return $normalizedTrusts
}

function Get-ADScoutTrustDataFallback {
    <#
    .SYNOPSIS
        Fallback trust data collector using DirectorySearcher.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    Write-Verbose "Using DirectorySearcher fallback for trust data"

    $trusts = @()

    try {
        # Build LDAP path to System container where trustedDomain objects live
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

        if ($ldapPath -eq "LDAP://RootDSE") {
            $defaultNC = $directoryEntry.Properties["defaultNamingContext"][0]
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=System,$defaultNC")
        } else {
            # Navigate to System container
            $rootDse = [ADSI]"LDAP://RootDSE"
            $defaultNC = $rootDse.Properties["defaultNamingContext"][0]
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=System,$defaultNC")
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.PageSize = 100

        $propertiesToLoad = @(
            'name', 'trustpartner', 'trustdirection', 'trusttype',
            'trustattributes', 'whencreated', 'whenchanged', 'securityidentifier'
        )

        foreach ($prop in $propertiesToLoad) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }

        $results = $searcher.FindAll()

        foreach ($result in $results) {
            $props = $result.Properties

            # Decode trust direction
            $trustDir = if ($props['trustdirection']) { $props['trustdirection'][0] } else { 0 }
            $direction = switch ($trustDir) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
                default { 'Unknown' }
            }

            # Decode trust type
            $trustTypeVal = if ($props['trusttype']) { $props['trusttype'][0] } else { 0 }
            $trustType = switch ($trustTypeVal) {
                1 { 'Downlevel' }
                2 { 'Uplevel' }
                3 { 'MIT' }
                4 { 'DCE' }
                default { 'Unknown' }
            }

            # Decode trust attributes
            $trustAttr = if ($props['trustattributes']) { $props['trustattributes'][0] } else { 0 }
            $sidFiltering = [bool]($trustAttr -band 0x4)  # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
            $forestTransitive = [bool]($trustAttr -band 0x8)  # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
            $selectiveAuth = [bool]($trustAttr -band 0x10)  # TRUST_ATTRIBUTE_CROSS_ORGANIZATION
            $intraForest = [bool]($trustAttr -band 0x20)  # TRUST_ATTRIBUTE_WITHIN_FOREST

            $trusts += [PSCustomObject]@{
                Name                    = if ($props['name']) { $props['name'][0] } else { $null }
                Source                  = $Domain
                Target                  = if ($props['trustpartner']) { $props['trustpartner'][0] } else { $null }
                Direction               = $direction
                TrustType               = $trustType
                DisallowTransivity      = -not $forestTransitive
                SelectiveAuthentication = $selectiveAuth
                SIDFilteringForestAware = $false  # Not easily detectable via LDAP
                SIDFilteringQuarantined = $sidFiltering
                TGTDelegation           = $false  # Would need additional query
                IntraForest             = $intraForest
                IsTreeParent            = $false
                IsTreeRoot              = $false
                WhenCreated             = if ($props['whencreated']) { $props['whencreated'][0] } else { $null }
                WhenChanged             = if ($props['whenchanged']) { $props['whenchanged'][0] } else { $null }
            }
        }

        $results.Dispose()
        $searcher.Dispose()
    }
    catch {
        Write-Warning "DirectorySearcher failed for trusts: $_"
    }

    return $trusts
}

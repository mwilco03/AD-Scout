function Get-ADScoutCache {
    <#
    .SYNOPSIS
        Gets a cached value if it exists and is not expired.

    .DESCRIPTION
        Retrieves data from the module-level cache if it exists
        and hasn't exceeded the TTL.

    .PARAMETER Key
        The cache key to retrieve.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    $timestamp = $script:ADScoutCache.Timestamps[$Key]

    if ($timestamp) {
        $age = (Get-Date) - $timestamp
        if ($age.TotalSeconds -lt $script:ADScoutConfig.CacheTTL) {
            Write-Verbose "Cache hit for key: $Key (age: $([math]::Round($age.TotalSeconds))s)"
            return $script:ADScoutCache.Data[$Key]
        }
        else {
            Write-Verbose "Cache expired for key: $Key (age: $([math]::Round($age.TotalSeconds))s)"
            # Clean up expired entry
            $script:ADScoutCache.Data.Remove($Key)
            $script:ADScoutCache.Timestamps.Remove($Key)
        }
    }

    Write-Verbose "Cache miss for key: $Key"
    return $null
}

function Set-ADScoutCache {
    <#
    .SYNOPSIS
        Sets a value in the cache.

    .DESCRIPTION
        Stores data in the module-level cache with a timestamp.

    .PARAMETER Key
        The cache key.

    .PARAMETER Value
        The value to cache.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [object]$Value
    )

    $script:ADScoutCache.Data[$Key] = $Value
    $script:ADScoutCache.Timestamps[$Key] = Get-Date

    Write-Verbose "Cached data for key: $Key"
}

function Clear-ADScoutCache {
    <#
    .SYNOPSIS
        Clears the AD-Scout cache.

    .DESCRIPTION
        Removes all cached data or a specific key.

    .PARAMETER Key
        Specific key to clear. If not specified, clears all.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Key
    )

    if ($Key) {
        $script:ADScoutCache.Data.Remove($Key)
        $script:ADScoutCache.Timestamps.Remove($Key)
        Write-Verbose "Cleared cache for key: $Key"
    }
    else {
        $script:ADScoutCache.Data.Clear()
        $script:ADScoutCache.Timestamps.Clear()
        Write-Verbose "Cleared all cache entries"
    }
}

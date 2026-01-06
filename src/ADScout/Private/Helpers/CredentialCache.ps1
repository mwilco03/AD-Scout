# AD-Scout Session Credential Cache
# Provides session-scoped credential caching to avoid repeated prompts

# Module-scoped credential storage
$script:CredentialCache = @{}
$script:CredentialCacheExpiry = @{}
$script:DefaultCacheDurationMinutes = 60

function Set-ADScoutCredential {
    <#
    .SYNOPSIS
        Caches credentials for the current session.

    .DESCRIPTION
        Stores credentials in memory for reuse across multiple AD-Scout commands.
        Credentials are scoped to the PowerShell session and optionally expire
        after a specified duration.

    .PARAMETER Credential
        The PSCredential to cache.

    .PARAMETER Domain
        The domain to associate with these credentials.

    .PARAMETER DurationMinutes
        How long to cache the credentials. Default: 60 minutes.

    .PARAMETER NoExpiry
        Cache credentials until session ends (no timeout).

    .EXAMPLE
        Set-ADScoutCredential -Credential (Get-Credential) -Domain "customer.local"

    .EXAMPLE
        $cred | Set-ADScoutCredential -Domain "customer.local" -DurationMinutes 120
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$Domain = '*',

        [Parameter()]
        [int]$DurationMinutes = $script:DefaultCacheDurationMinutes,

        [Parameter()]
        [switch]$NoExpiry
    )

    $key = $Domain.ToLower()
    $script:CredentialCache[$key] = $Credential

    if ($NoExpiry) {
        $script:CredentialCacheExpiry[$key] = [datetime]::MaxValue
    } else {
        $script:CredentialCacheExpiry[$key] = (Get-Date).AddMinutes($DurationMinutes)
    }

    Write-Verbose "Cached credentials for '$key' (expires: $(if ($NoExpiry) { 'never' } else { $script:CredentialCacheExpiry[$key].ToString('HH:mm') }))"

    return [PSCustomObject]@{
        Domain    = $key
        Username  = $Credential.UserName
        ExpiresAt = $script:CredentialCacheExpiry[$key]
    }
}

function Get-ADScoutCredential {
    <#
    .SYNOPSIS
        Retrieves cached credentials for a domain.

    .DESCRIPTION
        Returns cached credentials if available and not expired.
        Falls back to wildcard (*) credentials if domain-specific not found.

    .PARAMETER Domain
        The domain to get credentials for.

    .PARAMETER Prompt
        If credentials not cached, prompt the user.

    .PARAMETER PromptMessage
        Custom message for the credential prompt.

    .EXAMPLE
        $cred = Get-ADScoutCredential -Domain "customer.local"

    .EXAMPLE
        $cred = Get-ADScoutCredential -Domain "customer.local" -Prompt
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter()]
        [string]$Domain = '*',

        [Parameter()]
        [switch]$Prompt,

        [Parameter()]
        [string]$PromptMessage = "Enter credentials for AD-Scout"
    )

    $key = $Domain.ToLower()

    # Check domain-specific first
    if ($script:CredentialCache.ContainsKey($key)) {
        $expiry = $script:CredentialCacheExpiry[$key]

        if ((Get-Date) -lt $expiry) {
            Write-Verbose "Using cached credentials for '$key'"
            return $script:CredentialCache[$key]
        } else {
            # Expired - remove
            $script:CredentialCache.Remove($key)
            $script:CredentialCacheExpiry.Remove($key)
            Write-Verbose "Cached credentials for '$key' expired"
        }
    }

    # Fall back to wildcard
    if ($key -ne '*' -and $script:CredentialCache.ContainsKey('*')) {
        $expiry = $script:CredentialCacheExpiry['*']

        if ((Get-Date) -lt $expiry) {
            Write-Verbose "Using wildcard cached credentials for '$key'"
            return $script:CredentialCache['*']
        }
    }

    # No cached credentials - prompt if requested
    if ($Prompt) {
        $cred = Get-Credential -Message "$PromptMessage ($Domain)"
        if ($cred) {
            Set-ADScoutCredential -Credential $cred -Domain $Domain
            return $cred
        }
    }

    return $null
}

function Remove-ADScoutCredential {
    <#
    .SYNOPSIS
        Removes cached credentials.

    .PARAMETER Domain
        The domain to clear credentials for. Use '*' or omit to clear all.

    .PARAMETER All
        Clear all cached credentials.

    .EXAMPLE
        Remove-ADScoutCredential -Domain "customer.local"

    .EXAMPLE
        Remove-ADScoutCredential -All
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [switch]$All
    )

    if ($All) {
        $script:CredentialCache.Clear()
        $script:CredentialCacheExpiry.Clear()
        Write-Verbose "Cleared all cached credentials"
    }
    elseif ($Domain) {
        $key = $Domain.ToLower()
        if ($script:CredentialCache.ContainsKey($key)) {
            $script:CredentialCache.Remove($key)
            $script:CredentialCacheExpiry.Remove($key)
            Write-Verbose "Cleared cached credentials for '$key'"
        }
    }
}

function Get-ADScoutCredentialStatus {
    <#
    .SYNOPSIS
        Shows current credential cache status.

    .EXAMPLE
        Get-ADScoutCredentialStatus
    #>
    [CmdletBinding()]
    param()

    $results = @()

    foreach ($key in $script:CredentialCache.Keys) {
        $cred = $script:CredentialCache[$key]
        $expiry = $script:CredentialCacheExpiry[$key]
        $expired = (Get-Date) -ge $expiry
        $remaining = if ($expired) { [TimeSpan]::Zero } else { $expiry - (Get-Date) }

        $results += [PSCustomObject]@{
            Domain      = $key
            Username    = $cred.UserName
            ExpiresAt   = if ($expiry -eq [datetime]::MaxValue) { 'Never' } else { $expiry.ToString('yyyy-MM-dd HH:mm') }
            Expired     = $expired
            Remaining   = if ($expiry -eq [datetime]::MaxValue) { 'N/A' } else { $remaining.ToString('hh\:mm\:ss') }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "No cached credentials" -ForegroundColor Gray
    }

    return $results
}

# Auto-inject cached credentials into scan parameters
function Get-ADScoutEffectiveCredential {
    <#
    .SYNOPSIS
        Returns the effective credential to use for an operation.

    .DESCRIPTION
        Checks if explicit credential provided, falls back to cache,
        then to current user context.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCredential]$ExplicitCredential,

        [Parameter()]
        [string]$Domain
    )

    if ($ExplicitCredential) {
        Write-Verbose "Using explicitly provided credential"
        return $ExplicitCredential
    }

    $cached = Get-ADScoutCredential -Domain $Domain
    if ($cached) {
        Write-Verbose "Using cached credential for '$Domain'"
        return $cached
    }

    Write-Verbose "Using current user context"
    return $null
}

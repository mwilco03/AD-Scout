function New-ADScoutDirectorySearcher {
    <#
    .SYNOPSIS
        Creates a configured DirectorySearcher for AD queries.

    .DESCRIPTION
        Centralized function for creating DirectorySearcher objects with proper
        LDAP path resolution, credential handling, and performance settings.
        Eliminates duplication across collector fallback functions.

    .PARAMETER Domain
        Target domain name (e.g., 'contoso.com').

    .PARAMETER Server
        Specific domain controller FQDN to query.

    .PARAMETER Credential
        PSCredential for authenticated queries.

    .PARAMETER SearchBase
        LDAP path to start the search (e.g., 'OU=Users,DC=contoso,DC=com').

    .PARAMETER Filter
        LDAP filter for the search. Default: '(objectClass=*)'.

    .PARAMETER Properties
        Array of LDAP properties to load. Empty loads all properties.

    .PARAMETER PageSize
        Number of results per page. Default: 1000.

    .PARAMETER SearchScope
        Search scope: Base, OneLevel, or Subtree. Default: Subtree.

    .EXAMPLE
        $searcher = New-ADScoutDirectorySearcher -Domain 'contoso.com' -Filter '(objectClass=user)'
        $results = $searcher.FindAll()

    .EXAMPLE
        $searcher = New-ADScoutDirectorySearcher -Server 'dc01.contoso.com' `
            -Filter '(objectClass=group)' `
            -Properties @('name', 'member', 'distinguishedname')

    .OUTPUTS
        System.DirectoryServices.DirectorySearcher
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectorySearcher])]
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
        [string]$Filter = '(objectClass=*)',

        [Parameter()]
        [string[]]$Properties,

        [Parameter()]
        [ValidateRange(100, 10000)]
        [int]$PageSize = 1000,

        [Parameter()]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope = 'Subtree'
    )

    # Build LDAP path
    $ldapPath = $null

    if ($SearchBase) {
        $ldapPath = if ($Server) {
            "LDAP://$Server/$SearchBase"
        }
        else {
            "LDAP://$SearchBase"
        }
    }
    elseif ($Server) {
        $ldapPath = "LDAP://$Server"
    }
    elseif ($Domain) {
        # Convert domain name to DN format
        $domainDN = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
        $ldapPath = "LDAP://$domainDN"
    }
    else {
        # Use RootDSE to find default naming context
        $ldapPath = "LDAP://RootDSE"
    }

    Write-Verbose "Building DirectorySearcher for path: $ldapPath"

    try {
        # Create DirectoryEntry with optional credentials
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

        # Handle RootDSE case - need to resolve to actual naming context
        if ($ldapPath -eq "LDAP://RootDSE") {
            $defaultNC = $directoryEntry.Properties["defaultNamingContext"][0]

            if ($Credential) {
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    "LDAP://$defaultNC",
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
            }
            else {
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            }
        }

        # Create and configure DirectorySearcher
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = $Filter
        $searcher.PageSize = $PageSize
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$SearchScope

        # Add specific properties if requested
        if ($Properties -and $Properties.Count -gt 0) {
            foreach ($prop in $Properties) {
                [void]$searcher.PropertiesToLoad.Add($prop.ToLower())
            }
        }

        return $searcher
    }
    catch {
        Write-Error "Failed to create DirectorySearcher: $_"
        throw
    }
}

function Get-ADScoutLdapPath {
    <#
    .SYNOPSIS
        Builds an LDAP path from domain/server/searchbase parameters.

    .DESCRIPTION
        Centralized LDAP path construction logic for consistent AD connectivity.

    .PARAMETER Domain
        Target domain name.

    .PARAMETER Server
        Specific domain controller.

    .PARAMETER SearchBase
        LDAP search base DN.

    .EXAMPLE
        $path = Get-ADScoutLdapPath -Domain 'contoso.com'
        # Returns: LDAP://DC=contoso,DC=com

    .OUTPUTS
        String - The constructed LDAP path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    if ($SearchBase) {
        if ($Server) {
            return "LDAP://$Server/$SearchBase"
        }
        return "LDAP://$SearchBase"
    }

    if ($Server) {
        return "LDAP://$Server"
    }

    if ($Domain) {
        $domainDN = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
        return "LDAP://$domainDN"
    }

    # Fallback: resolve from RootDSE
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        return "LDAP://$($rootDse.defaultNamingContext)"
    }
    catch {
        Write-Error "Could not determine LDAP path: $_"
        throw
    }
}

function ConvertTo-ADScoutPropertyHash {
    <#
    .SYNOPSIS
        Converts DirectorySearcher result properties to a hashtable.

    .DESCRIPTION
        Helper function to normalize SearchResult properties into a consistent
        hashtable format for easier processing.

    .PARAMETER SearchResult
        A System.DirectoryServices.SearchResult object.

    .EXAMPLE
        $results = $searcher.FindAll()
        foreach ($result in $results) {
            $props = ConvertTo-ADScoutPropertyHash -SearchResult $result
            Write-Host $props['samaccountname']
        }

    .OUTPUTS
        Hashtable with property names as keys.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.SearchResult]$SearchResult
    )

    process {
        $hash = @{}

        foreach ($propName in $SearchResult.Properties.PropertyNames) {
            $values = $SearchResult.Properties[$propName]

            if ($values.Count -eq 1) {
                $hash[$propName] = $values[0]
            }
            elseif ($values.Count -gt 1) {
                $hash[$propName] = @($values)
            }
            else {
                $hash[$propName] = $null
            }
        }

        return $hash
    }
}

function ConvertFrom-ADScoutUAC {
    <#
    .SYNOPSIS
        Decodes UserAccountControl flags to a structured object.

    .DESCRIPTION
        Converts the UserAccountControl integer value to meaningful boolean properties.
        Centralizes UAC flag interpretation across collectors.

    .PARAMETER UAC
        The UserAccountControl integer value.

    .EXAMPLE
        $uacInfo = ConvertFrom-ADScoutUAC -UAC 512
        $uacInfo.Enabled  # True (normal account)

    .OUTPUTS
        PSCustomObject with decoded UAC properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]$UAC
    )

    process {
        # Get flag values from constants if available
        $flags = if ($script:ADScoutSidData -and $script:ADScoutSidData.uacFlags) {
            $script:ADScoutSidData.uacFlags
        }
        else {
            # Fallback to hardcoded values
            @{
                ACCOUNTDISABLE            = 0x2
                LOCKOUT                   = 0x10
                PASSWD_NOTREQD            = 0x20
                PASSWD_CANT_CHANGE        = 0x40
                ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
                NORMAL_ACCOUNT            = 0x200
                DONT_EXPIRE_PASSWORD      = 0x10000
                SMARTCARD_REQUIRED        = 0x40000
                TRUSTED_FOR_DELEGATION    = 0x80000
                NOT_DELEGATED             = 0x100000
                USE_DES_KEY_ONLY          = 0x200000
                DONT_REQ_PREAUTH          = 0x400000
                PASSWORD_EXPIRED          = 0x800000
                TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
            }
        }

        return [PSCustomObject]@{
            Enabled                    = -not [bool]($UAC -band $flags.ACCOUNTDISABLE)
            Locked                     = [bool]($UAC -band $flags.LOCKOUT)
            PasswordNotRequired        = [bool]($UAC -band $flags.PASSWD_NOTREQD)
            PasswordCantChange         = [bool]($UAC -band $flags.PASSWD_CANT_CHANGE)
            PasswordNeverExpires       = [bool]($UAC -band $flags.DONT_EXPIRE_PASSWORD)
            SmartcardRequired          = [bool]($UAC -band $flags.SMARTCARD_REQUIRED)
            TrustedForDelegation       = [bool]($UAC -band $flags.TRUSTED_FOR_DELEGATION)
            NotDelegated               = [bool]($UAC -band $flags.NOT_DELEGATED)
            UseDESKeyOnly              = [bool]($UAC -band $flags.USE_DES_KEY_ONLY)
            DontRequirePreauth         = [bool]($UAC -band $flags.DONT_REQ_PREAUTH)
            PasswordExpired            = [bool]($UAC -band $flags.PASSWORD_EXPIRED)
            TrustedToAuthForDelegation = [bool]($UAC -band $flags.TRUSTED_TO_AUTH_FOR_DELEGATION)
            RawValue                   = $UAC
        }
    }
}

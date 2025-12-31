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
            Write-Warning "AD module failed for computers: $_"
            $computers = @()
        }
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

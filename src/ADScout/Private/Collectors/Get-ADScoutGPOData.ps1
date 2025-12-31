function Get-ADScoutGPOData {
    <#
    .SYNOPSIS
        Collects Group Policy Object data from Active Directory.

    .DESCRIPTION
        Retrieves GPOs with security-relevant settings.

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

    if (Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop

            $params = @{
                All = $true
            }

            if ($Domain) { $params.Domain = $Domain }
            if ($Server) { $params.Server = $Server }

            $gpos = Get-GPO @params
        }
        catch {
            Write-Warning "GroupPolicy module failed: $_"
            $gpos = @()
        }
    }
    else {
        Write-Verbose "GroupPolicy module not available"
    }

    $normalizedGPOs = $gpos | ForEach-Object {
        [PSCustomObject]@{
            DisplayName       = $_.DisplayName
            Id                = $_.Id
            DomainName        = $_.DomainName
            Owner             = $_.Owner
            GpoStatus         = $_.GpoStatus
            CreationTime      = $_.CreationTime
            ModificationTime  = $_.ModificationTime
            WmiFilter         = $_.WmiFilter
            Description       = $_.Description
            UserVersion       = $_.User.DSVersion
            ComputerVersion   = $_.Computer.DSVersion
        }
    }

    Set-ADScoutCache -Key $cacheKey -Value $normalizedGPOs

    Write-Verbose "Collected $($normalizedGPOs.Count) GPOs"

    return $normalizedGPOs
}

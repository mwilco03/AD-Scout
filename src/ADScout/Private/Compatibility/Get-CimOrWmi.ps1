function Get-CimOrWmi {
    <#
    .SYNOPSIS
        Gets WMI/CIM data using the best available method.

    .DESCRIPTION
        Abstracts the difference between Get-CimInstance and Get-WmiObject
        for cross-version compatibility.

    .PARAMETER ClassName
        The WMI/CIM class name.

    .PARAMETER ComputerName
        Target computer. Defaults to local.

    .PARAMETER Credential
        Credentials for remote access.

    .PARAMETER Namespace
        WMI namespace. Defaults to root/cimv2.

    .PARAMETER Filter
        WQL filter string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClassName,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$Namespace = 'root/cimv2',

        [Parameter()]
        [string]$Filter
    )

    $params = @{
        ClassName = $ClassName
        Namespace = $Namespace
    }

    if ($ComputerName) {
        $params.ComputerName = $ComputerName
    }

    if ($Credential) {
        $params.Credential = $Credential
    }

    if ($Filter) {
        $params.Filter = $Filter
    }

    # Try CIM first (available in PS 3+ and is the modern approach)
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            Write-Verbose "Using Get-CimInstance for $ClassName"
            return Get-CimInstance @params
        }
        catch {
            Write-Verbose "CIM failed, falling back to WMI: $_"
        }
    }

    # Fallback to WMI (deprecated but works on older systems)
    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        Write-Verbose "Using Get-WmiObject for $ClassName"

        # WMI uses different parameter names
        $wmiParams = @{
            Class = $ClassName
            Namespace = $Namespace
        }

        if ($ComputerName) {
            $wmiParams.ComputerName = $ComputerName
        }

        if ($Credential) {
            $wmiParams.Credential = $Credential
        }

        if ($Filter) {
            $wmiParams.Filter = $Filter
        }

        return Get-WmiObject @wmiParams
    }

    throw "Neither Get-CimInstance nor Get-WmiObject are available"
}

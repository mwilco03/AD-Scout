<#
.SYNOPSIS
    Initializes the SMBLibrary and RPCForSMBLibrary external DLLs for protocol-level scanning.

.DESCRIPTION
    This function loads the optional SMBLibrary.dll and RPCForSMBLibrary.dll files
    that enable protocol-level SMB and RPC security scanning. The libraries are
    loaded on-demand (not at module import) to allow AD-Scout to function without them.

    If the libraries are not available, DLL-dependent rules will gracefully skip
    with a warning message instead of failing.

.NOTES
    Author     : AD-Scout Contributors
    Libraries  : SMBLibrary (LGPL-3.0), RPCForSMBLibrary (LGPL-3.0)
    Source     : https://github.com/TalAloni/SMBLibrary
                 https://github.com/vletoux/RPCForSMBLibrary

.OUTPUTS
    [bool] True if libraries are loaded successfully, False otherwise.

.EXAMPLE
    if (Initialize-ADScoutSMBLibrary) {
        # Perform SMB scanning
    }
#>

function Initialize-ADScoutSMBLibrary {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [switch]$Force
    )

    # Check if already loaded (unless Force is specified)
    if ($script:SMBLibraryLoaded -and -not $Force) {
        Write-Verbose "SMBLibrary already loaded"
        return $true
    }

    # Determine DLL path (relative to this script's location)
    $dllPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) "Libraries"

    $smbLibPath = Join-Path $dllPath "SMBLibrary.dll"
    $rpcLibPath = Join-Path $dllPath "RPCForSMBLibrary.dll"

    # Check if SMBLibrary exists
    if (-not (Test-Path $smbLibPath)) {
        Write-Warning "SMBLibrary.dll not found at: $dllPath"
        Write-Warning "DLL-dependent scanners will be unavailable."
        Write-Warning "Download from: https://github.com/TalAloni/SMBLibrary/releases"
        Write-Verbose "Expected path: $smbLibPath"
        $script:SMBLibraryLoaded = $false
        return $false
    }

    try {
        # Load SMBLibrary
        Write-Verbose "Loading SMBLibrary from: $smbLibPath"
        Add-Type -Path $smbLibPath -ErrorAction Stop
        Write-Verbose "SMBLibrary loaded successfully"

        # Load RPCForSMBLibrary if available (optional extension)
        if (Test-Path $rpcLibPath) {
            Write-Verbose "Loading RPCForSMBLibrary from: $rpcLibPath"
            Add-Type -Path $rpcLibPath -ErrorAction SilentlyContinue
            Write-Verbose "RPCForSMBLibrary loaded successfully"
            $script:RPCLibraryLoaded = $true
        } else {
            Write-Verbose "RPCForSMBLibrary not found - RPC-specific scanners will be limited"
            $script:RPCLibraryLoaded = $false
        }

        $script:SMBLibraryLoaded = $true
        return $true
    }
    catch {
        Write-Warning "Failed to load SMBLibrary: $($_.Exception.Message)"
        Write-Warning "DLL-dependent scanners will be unavailable."
        $script:SMBLibraryLoaded = $false
        return $false
    }
}

function Test-ADScoutSMBLibrary {
    <#
    .SYNOPSIS
        Tests if SMBLibrary is available and returns status information.

    .DESCRIPTION
        Returns detailed status about the DLL libraries including version information.

    .OUTPUTS
        PSCustomObject with library status information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $dllPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) "Libraries"
    $smbLibPath = Join-Path $dllPath "SMBLibrary.dll"
    $rpcLibPath = Join-Path $dllPath "RPCForSMBLibrary.dll"

    $result = [PSCustomObject]@{
        SMBLibraryPath      = $smbLibPath
        SMBLibraryExists    = (Test-Path $smbLibPath)
        SMBLibraryLoaded    = $script:SMBLibraryLoaded -eq $true
        SMBLibraryVersion   = $null
        RPCLibraryPath      = $rpcLibPath
        RPCLibraryExists    = (Test-Path $rpcLibPath)
        RPCLibraryLoaded    = $script:RPCLibraryLoaded -eq $true
        RPCLibraryVersion   = $null
        FullCapability      = $false
    }

    # Get version info if files exist
    if ($result.SMBLibraryExists) {
        try {
            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($smbLibPath)
            $result.SMBLibraryVersion = $fileInfo.FileVersion
        } catch {
            $result.SMBLibraryVersion = "Unknown"
        }
    }

    if ($result.RPCLibraryExists) {
        try {
            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($rpcLibPath)
            $result.RPCLibraryVersion = $fileInfo.FileVersion
        } catch {
            $result.RPCLibraryVersion = "Unknown"
        }
    }

    $result.FullCapability = $result.SMBLibraryLoaded -and $result.RPCLibraryLoaded

    return $result
}

function Get-ADScoutDLLCapabilities {
    <#
    .SYNOPSIS
        Returns a list of capabilities available based on loaded DLLs.

    .DESCRIPTION
        Provides detailed information about which scanning capabilities are available
        based on the currently loaded DLL libraries.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $capabilities = @(
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBDialectScan"
            Description      = "SMB protocol version detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBSigningScan"
            Description      = "SMB signing configuration detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBEncryptionScan"
            Description      = "SMB 3.x encryption capability detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBCompressionScan"
            Description      = "SMB 3.1.1 compression detection (CVE-2020-0796)"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBShareScan"
            Description      = "SMB share enumeration"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBNullSessionScan"
            Description      = "Null session access testing"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SAMRScan"
            Description      = "SAMR anonymous enumeration testing"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-LSAScan"
            Description      = "LSA anonymous query testing"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-NetlogonScan"
            Description      = "Netlogon service security testing"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SpoolerScan"
            Description      = "Print Spooler accessibility (PrinterBug)"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-EFSRPCScan"
            Description      = "EFSRPC accessibility (PetitPotam)"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-DFSCoerceScan"
            Description      = "DFSNM accessibility (DFSCoerce)"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-CoercionScan"
            Description      = "Comprehensive coercion attack testing"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-ZerologonScan"
            Description      = "CVE-2020-1472 (Zerologon) safe detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-EternalBlueScan"
            Description      = "MS17-010 (EternalBlue) detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-SMBGhostScan"
            Description      = "CVE-2020-0796 (SMBGhost) detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $false
            Available        = $script:SMBLibraryLoaded -eq $true
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-LDAPSigningScan"
            Description      = "LDAP signing requirement detection"
            RequiresSMBLib   = $true
            RequiresRPCLib   = $true
            Available        = ($script:SMBLibraryLoaded -eq $true) -and ($script:RPCLibraryLoaded -eq $true)
        }
        [PSCustomObject]@{
            Scanner          = "Invoke-LDAPSScan"
            Description      = "LDAPS configuration and certificate analysis"
            RequiresSMBLib   = $false
            RequiresRPCLib   = $false
            Available        = $true  # Uses native .NET
        }
    )

    return $capabilities
}

# Module-level variables for tracking library status
$script:SMBLibraryLoaded = $false
$script:RPCLibraryLoaded = $false

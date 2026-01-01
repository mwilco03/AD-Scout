<#
.SYNOPSIS
    Tests for DFSNM (DFS Namespace Management) accessibility (DFSCoerce detection).

.DESCRIPTION
    Uses SMBLibrary to test if DFSNM RPC is accessible for DFSCoerce attacks.
    DFSCoerce is similar to PetitPotam but uses the DFS Namespace Management
    protocol (MS-DFSNM) for coercion.

    This scanner checks for accessibility only and does NOT trigger any coercion.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-DFSCoerceScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
    Related    : DFSCoerce attack

.OUTPUTS
    PSCustomObject with DFSNM accessibility results.

.EXAMPLE
    Invoke-DFSCoerceScan -ComputerName "dc01.contoso.com"
#>

function Invoke-DFSCoerceScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("DNSHostName", "Name", "HostName", "IPAddress")]
        [string]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 445,

        [Parameter()]
        [ValidateRange(1000, 60000)]
        [int]$TimeoutMs = 5000
    )

    begin {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "SMBLibrary not available. Cannot perform DFS coercion testing."
            $script:DFSCoerceScanSkipped = $true
        } else {
            $script:DFSCoerceScanSkipped = $false
        }
    }

    process {
        if ($script:DFSCoerceScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing DFS coercion potential on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            DFSPipeAccessible       = $false
            NetDFSAccessible        = $false
            AnonymousAccess         = $false
            DFSCoerceVulnerable     = $false
            AccessiblePipe          = $null
            Vulnerable              = $false
            VulnerabilityDetails    = @()
            Error                   = $null
            Timestamp               = [datetime]::UtcNow
        }

        try {
            # Resolve hostname
            $targetIP = $null
            try {
                $dnsResult = [System.Net.Dns]::GetHostAddresses($ComputerName) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1
                $targetIP = $dnsResult.IPAddressToString
            } catch {
                $result.Status = "DNSError"
                $result.Error = "Failed to resolve hostname: $ComputerName"
                return $result
            }

            $smb2Client = New-Object SMBLibrary.Client.SMB2Client

            $connected = $smb2Client.Connect(
                [System.Net.IPAddress]::Parse($targetIP),
                [SMBLibrary.SMBTransportType]::DirectTCPTransport
            )

            if (-not $connected) {
                $result.Status = "ConnectionFailed"
                $result.Error = "Could not establish SMB connection"
                return $result
            }

            # Negotiate
            $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311) | Out-Null

            # Try anonymous login
            $loginStatus = $smb2Client.Login("", "", "")

            if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.AnonymousAccess = $true

                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # DFSCoerce uses the netdfs pipe
                    $dfsPipes = @(
                        @{ Pipe = "\PIPE\netdfs"; Name = "NETDFS" }
                    )

                    foreach ($pipeInfo in $dfsPipes) {
                        $fileHandle = $null
                        $openStatus = $smb2Client.CreateFile(
                            $pipeInfo.Pipe,
                            [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                            [SMBLibrary.FileAttributes]::Normal,
                            [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                            [SMBLibrary.CreateDisposition]::FILE_OPEN,
                            [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                            [ref]$fileHandle
                        )

                        if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $result.NetDFSAccessible = $true
                            $result.DFSPipeAccessible = $true
                            $result.DFSCoerceVulnerable = $true
                            $result.AccessiblePipe = $pipeInfo.Name
                            $result.VulnerabilityDetails += "DFS pipe accessible - DFSCoerce attack possible"
                            Write-Verbose "  DFS pipe: Accessible via $($pipeInfo.Pipe)"

                            $smb2Client.CloseFile($fileHandle) | Out-Null
                            break
                        } else {
                            Write-Verbose "  DFS pipe ($($pipeInfo.Pipe)): Not accessible"
                        }
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            }

            $smb2Client.Disconnect()

            # Determine vulnerability
            $result.Vulnerable = $result.DFSCoerceVulnerable
            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

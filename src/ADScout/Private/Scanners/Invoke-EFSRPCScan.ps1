<#
.SYNOPSIS
    Tests for EFSRPC accessibility (PetitPotam vulnerability detection).

.DESCRIPTION
    Uses SMBLibrary to test if EFSRPC (Encrypting File System RPC) is accessible.
    EFSRPC accessibility enables PetitPotam (CVE-2021-36942) coercion attacks.

    This scanner checks for accessibility only and does NOT trigger any coercion.

    PetitPotam allows an attacker to:
    1. Coerce a DC to authenticate to an attacker-controlled server
    2. Relay the authentication to ADCS
    3. Obtain a certificate as the DC
    4. Authenticate as the DC and perform DCSync

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-EFSRPCScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
    Related    : CVE-2021-36942 (PetitPotam)

.OUTPUTS
    PSCustomObject with EFSRPC accessibility results.

.EXAMPLE
    Invoke-EFSRPCScan -ComputerName "dc01.contoso.com"
#>

function Invoke-EFSRPCScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform EFSRPC testing."
            $script:EFSRPCScanSkipped = $true
        } else {
            $script:EFSRPCScanSkipped = $false
        }
    }

    process {
        if ($script:EFSRPCScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing EFSRPC accessibility on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            EFSRPCPipeAccessible    = $false
            LSARPCAccessible        = $false
            AnonymousAccess         = $false
            PetitPotamVulnerable    = $false
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
                    # PetitPotam can use multiple named pipes:
                    # 1. \PIPE\efsrpc - Primary EFSRPC pipe
                    # 2. \PIPE\lsarpc - Can also be used for EFS operations
                    # 3. \PIPE\samr - Alternative path
                    # 4. \PIPE\netlogon - Alternative path

                    $efsrpcPipes = @(
                        @{ Pipe = "\PIPE\efsrpc";    Name = "EFSRPC";    Primary = $true }
                        @{ Pipe = "\PIPE\lsarpc";    Name = "LSARPC";    Primary = $false }
                    )

                    foreach ($pipeInfo in $efsrpcPipes) {
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
                            if ($pipeInfo.Primary) {
                                $result.EFSRPCPipeAccessible = $true
                                $result.PetitPotamVulnerable = $true
                                $result.AccessiblePipe = $pipeInfo.Name
                                $result.VulnerabilityDetails += "EFSRPC pipe accessible - PetitPotam coercion possible"
                                Write-Verbose "  EFSRPC: Accessible via $($pipeInfo.Pipe)"
                            } else {
                                $result.LSARPCAccessible = $true
                                if (-not $result.EFSRPCPipeAccessible) {
                                    $result.AccessiblePipe = $pipeInfo.Name
                                }
                                $result.VulnerabilityDetails += "$($pipeInfo.Name) accessible - potential PetitPotam path"
                                Write-Verbose "  $($pipeInfo.Name): Accessible via $($pipeInfo.Pipe)"
                            }

                            $smb2Client.CloseFile($fileHandle) | Out-Null

                            # If primary EFSRPC is accessible, that's the main concern
                            if ($pipeInfo.Primary) {
                                break
                            }
                        } else {
                            Write-Verbose "  $($pipeInfo.Name): Not accessible"
                        }
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            }

            $smb2Client.Disconnect()

            # Determine vulnerability
            $result.Vulnerable = $result.EFSRPCPipeAccessible -or $result.PetitPotamVulnerable
            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

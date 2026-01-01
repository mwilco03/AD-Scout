<#
.SYNOPSIS
    Tests for anonymous LSA (Local Security Authority) access.

.DESCRIPTION
    Uses SMBLibrary and RPCForSMBLibrary to test if anonymous access to
    the LSA RPC interface is allowed. LSA access enables:
    - Domain information retrieval
    - Trust relationship enumeration
    - SID-to-name resolution
    - Security policy access

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-LSAScan
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with LSA access test results.

.EXAMPLE
    Invoke-LSAScan -ComputerName "dc01.contoso.com"
#>

function Invoke-LSAScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform LSA testing."
            $script:LSAScanSkipped = $true
        } else {
            $script:LSAScanSkipped = $false
        }
    }

    process {
        if ($script:LSAScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing LSA access on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            LSAPipeAccessible       = $false
            AnonymousAccess         = $false
            DomainInfoAccess        = $false
            TrustEnumeration        = $false
            SIDResolution           = $false
            PolicyAccess            = $false
            DomainInfo              = $null
            Trusts                  = @()
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
                Write-Verbose "  Anonymous login: Successful"

                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # Try to open LSARPC pipe
                    $fileHandle = $null
                    $openStatus = $smb2Client.CreateFile(
                        "\PIPE\lsarpc",
                        [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                        [SMBLibrary.FileAttributes]::Normal,
                        [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                        [SMBLibrary.CreateDisposition]::FILE_OPEN,
                        [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                        [ref]$fileHandle
                    )

                    if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        $result.LSAPipeAccessible = $true
                        $result.VulnerabilityDetails += "LSARPC named pipe accessible anonymously"
                        Write-Verbose "  LSARPC pipe: Accessible"

                        # Use RPCForSMBLibrary for detailed enumeration
                        if ($script:RPCLibraryLoaded) {
                            try {
                                $rpcTransport = New-Object SMBLibrary.RPC.RPCTransportOverSMB2 -ArgumentList @($smb2Client, $fileHandle)
                                $lsaClient = New-Object RPCForSMBLibrary.LSA.LSAClient -ArgumentList @($rpcTransport)

                                # Open LSA policy
                                $policyHandle = $null
                                $openPolicyStatus = $lsaClient.LsaOpenPolicy2($ComputerName, 0x00020801, [ref]$policyHandle)

                                if ($openPolicyStatus -eq 0) {
                                    $result.PolicyAccess = $true
                                    Write-Verbose "  LSA policy: Opened"

                                    # Query domain information
                                    $domainInfo = $null
                                    $queryStatus = $lsaClient.LsaQueryInformationPolicy($policyHandle, 5, [ref]$domainInfo)  # PolicyAccountDomainInformation

                                    if ($queryStatus -eq 0 -and $domainInfo) {
                                        $result.DomainInfoAccess = $true
                                        $result.DomainInfo = $domainInfo
                                        $result.VulnerabilityDetails += "Domain information accessible"
                                        Write-Verbose "  Domain info: Accessible"
                                    }

                                    # Enumerate trusted domains
                                    $trusts = $null
                                    $enumTrustStatus = $lsaClient.LsaEnumerateTrustedDomainsEx($policyHandle, [ref]$trusts)

                                    if ($enumTrustStatus -eq 0 -and $trusts) {
                                        $result.TrustEnumeration = $true
                                        $result.Trusts = $trusts
                                        $result.VulnerabilityDetails += "Trust enumeration possible ($($trusts.Count) trusts)"
                                        Write-Verbose "  Trust enumeration: Found $($trusts.Count) trusts"
                                    }

                                    $lsaClient.LsaClose($policyHandle) | Out-Null
                                }
                            } catch {
                                Write-Verbose "  LSA RPC error: $($_.Exception.Message)"
                            }
                        }

                        $smb2Client.CloseFile($fileHandle) | Out-Null
                    } else {
                        Write-Verbose "  LSARPC pipe: Access denied"
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            }

            $smb2Client.Disconnect()

            # Determine vulnerability
            $result.Vulnerable = $result.LSAPipeAccessible -or
                                $result.DomainInfoAccess -or
                                $result.TrustEnumeration

            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

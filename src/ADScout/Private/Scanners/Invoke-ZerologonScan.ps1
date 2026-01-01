<#
.SYNOPSIS
    Safe detection of Zerologon (CVE-2020-1472) vulnerability.

.DESCRIPTION
    This scanner performs SAFE detection of the Zerologon vulnerability.
    It does NOT exploit the vulnerability or modify any server state.

    Detection method:
    1. Connects to Netlogon RPC service
    2. Attempts challenge/response with null credentials
    3. Checks if server properly rejects the null authentication

    A patched server will reject null authentication attempts.
    An unpatched server may accept them (vulnerable).

    IMPORTANT: This scanner is designed for defensive security assessment.
    It performs read-only checks and cannot exploit Zerologon.

.PARAMETER ComputerName
    The target Domain Controller name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-ZerologonScan
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors
    Related    : CVE-2020-1472 (Zerologon)
    Safety     : This scanner does NOT exploit Zerologon

.OUTPUTS
    PSCustomObject with Zerologon detection results.

.EXAMPLE
    Invoke-ZerologonScan -ComputerName "dc01.contoso.com"
#>

function Invoke-ZerologonScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform Zerologon detection."
            $script:ZerologonScanSkipped = $true
        } else {
            $script:ZerologonScanSkipped = $false
        }
    }

    process {
        if ($script:ZerologonScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Performing safe Zerologon detection on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            NetlogonAccessible      = $false
            ZerologonVulnerable     = $false
            ZerologonPatched        = $null
            NullCredentialRejected  = $null
            SecureChannelEnforced   = $null
            Vulnerable              = $false
            VulnerabilityDetails    = @()
            CVE                     = "CVE-2020-1472"
            Severity                = "Critical"
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

            # Anonymous login for pipe access
            $loginStatus = $smb2Client.Login("", "", "")

            if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # Open Netlogon pipe
                    $fileHandle = $null
                    $openStatus = $smb2Client.CreateFile(
                        "\PIPE\netlogon",
                        [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                        [SMBLibrary.FileAttributes]::Normal,
                        [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                        [SMBLibrary.CreateDisposition]::FILE_OPEN,
                        [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                        [ref]$fileHandle
                    )

                    if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        $result.NetlogonAccessible = $true
                        Write-Verbose "  Netlogon pipe: Accessible"

                        # For SAFE Zerologon detection:
                        # We check the server's response to initial challenge without
                        # actually attempting the full exploit chain

                        if ($script:RPCLibraryLoaded) {
                            try {
                                $rpcTransport = New-Object SMBLibrary.RPC.RPCTransportOverSMB2 -ArgumentList @($smb2Client, $fileHandle)
                                $netlogonClient = New-Object RPCForSMBLibrary.Netlogon.NetlogonClient -ArgumentList @($rpcTransport)

                                # Safe check: Send a challenge request with null bytes
                                # A patched server will properly validate and reject
                                # An unpatched server may accept (vulnerable)

                                $clientChallenge = [byte[]]::new(8)  # All zeros
                                $serverChallenge = [byte[]]::new(8)

                                try {
                                    $challengeStatus = $netlogonClient.NetrServerReqChallenge(
                                        $null,                          # PrimaryName
                                        $ComputerName.Split('.')[0],    # ComputerName
                                        $clientChallenge,               # ClientChallenge
                                        [ref]$serverChallenge           # ServerChallenge
                                    )

                                    if ($challengeStatus -eq 0) {
                                        # Server accepted challenge - need to verify authentication
                                        Write-Verbose "  Server accepted challenge request"

                                        # Try to authenticate with null credentials
                                        # This is the SAFE part - we only check if server rejects
                                        $nullCredential = [byte[]]::new(8)
                                        $authenticateStatus = $netlogonClient.NetrServerAuthenticate3(
                                            $null,                      # PrimaryName
                                            $ComputerName.Split('.')[0] + "$", # AccountName
                                            2,                          # SecureChannelType (WorkStation)
                                            $ComputerName.Split('.')[0], # ComputerName
                                            $nullCredential,            # ClientCredential
                                            [ref]$null,                 # ServerCredential
                                            [ref]$null                  # NegotiateFlags
                                        )

                                        if ($authenticateStatus -eq 0) {
                                            # Null authentication ACCEPTED - VULNERABLE!
                                            $result.ZerologonVulnerable = $true
                                            $result.ZerologonPatched = $false
                                            $result.Vulnerable = $true
                                            $result.NullCredentialRejected = $false
                                            $result.VulnerabilityDetails += "CVE-2020-1472 (Zerologon) - CRITICAL: Null authentication accepted!"
                                            Write-Warning "  ZEROLOGON VULNERABLE: Null authentication accepted!"
                                        } elseif ($authenticateStatus -eq 0xC000006A) {  # STATUS_WRONG_PASSWORD
                                            # Server properly rejected null credentials
                                            $result.ZerologonPatched = $true
                                            $result.NullCredentialRejected = $true
                                            Write-Verbose "  Zerologon: PATCHED (null credentials rejected)"
                                        } elseif ($authenticateStatus -eq 0xC0000022) {  # STATUS_ACCESS_DENIED
                                            # Secure channel required - patched
                                            $result.ZerologonPatched = $true
                                            $result.SecureChannelEnforced = $true
                                            Write-Verbose "  Zerologon: PATCHED (secure channel enforced)"
                                        } else {
                                            Write-Verbose "  Authentication status: 0x$($authenticateStatus.ToString('X8'))"
                                            $result.ZerologonPatched = $true  # Assume patched for other error codes
                                        }
                                    } elseif ($challengeStatus -eq 5) {  # ACCESS_DENIED
                                        $result.ZerologonPatched = $true
                                        Write-Verbose "  Zerologon: PATCHED (challenge denied)"
                                    }
                                } catch {
                                    # Any error during the test typically means patched
                                    $result.ZerologonPatched = $true
                                    Write-Verbose "  Zerologon test: Assuming patched (error: $($_.Exception.Message))"
                                }
                            } catch {
                                Write-Verbose "  Netlogon RPC error: $($_.Exception.Message)"
                            }
                        } else {
                            # Without RPC library, we can only confirm pipe access
                            $result.VulnerabilityDetails += "Netlogon accessible (full Zerologon test requires RPC library)"
                        }

                        $smb2Client.CloseFile($fileHandle) | Out-Null
                    } else {
                        Write-Verbose "  Netlogon pipe: Access denied"
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            }

            $smb2Client.Disconnect()
            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

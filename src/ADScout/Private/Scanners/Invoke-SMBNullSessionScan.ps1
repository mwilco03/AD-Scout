<#
.SYNOPSIS
    Tests for SMB null session vulnerabilities.

.DESCRIPTION
    Uses SMBLibrary to test for null session access which allows:
    - Anonymous IPC$ access
    - Anonymous user enumeration
    - Anonymous group enumeration
    - Anonymous share listing

    Null sessions were more common in older Windows versions but can
    still be enabled via misconfiguration.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-SMBNullSessionScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with null session test results.

.EXAMPLE
    Invoke-SMBNullSessionScan -ComputerName "dc01.contoso.com"
#>

function Invoke-SMBNullSessionScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform null session testing."
            $script:NullSessionScanSkipped = $true
        } else {
            $script:NullSessionScanSkipped = $false
        }
    }

    process {
        if ($script:NullSessionScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing null session access on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName          = $ComputerName
            Port                  = $Port
            Status                = "Unknown"
            NullSessionAllowed    = $false
            AnonymousLogin        = $false
            IPCAccess             = $false
            ShareEnumeration      = $false
            UserEnumeration       = $false
            GroupEnumeration      = $false
            PasswordPolicy        = $false
            DomainSID             = $false
            EnumeratedShares      = @()
            Vulnerable            = $false
            VulnerabilityDetails  = @()
            Error                 = $null
            Timestamp             = [datetime]::UtcNow
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

            # Connect
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
            $negotiateStatus = $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311)
            if ($negotiateStatus -ne [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB210) | Out-Null
            }

            # Try null session login (empty username and password)
            $loginStatus = $smb2Client.Login("", "", "")

            if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.AnonymousLogin = $true
                $result.NullSessionAllowed = $true
                $result.VulnerabilityDetails += "Anonymous SMB login accepted"
                Write-Verbose "  Anonymous login: ALLOWED"

                # Test IPC$ access
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    $result.IPCAccess = $true
                    $result.VulnerabilityDetails += "Anonymous IPC$ access allowed"
                    Write-Verbose "  IPC$ access: ALLOWED"

                    # Test share enumeration
                    $shareList = $null
                    $shareStatus = $smb2Client.ListShares([ref]$shareList)

                    if ($shareStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS -and $shareList) {
                        $result.ShareEnumeration = $true
                        $result.EnumeratedShares = $shareList
                        $result.VulnerabilityDetails += "Anonymous share enumeration possible"
                        Write-Verbose "  Share enumeration: ALLOWED (found $($shareList.Count) shares)"
                    }

                    # Test SAMR access for user enumeration (requires RPC library)
                    if ($script:RPCLibraryLoaded) {
                        try {
                            # Open SAMR pipe
                            $fileHandle = $null
                            $openStatus = $smb2Client.CreateFile(
                                "\PIPE\samr",
                                [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                                [SMBLibrary.FileAttributes]::Normal,
                                [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                                [SMBLibrary.CreateDisposition]::FILE_OPEN,
                                [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                                [ref]$fileHandle
                            )

                            if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                                $result.UserEnumeration = $true
                                $result.VulnerabilityDetails += "SAMR pipe accessible - user enumeration possible"
                                Write-Verbose "  User enumeration: LIKELY (SAMR accessible)"
                                $smb2Client.CloseFile($fileHandle) | Out-Null
                            }
                        } catch {
                            Write-Verbose "  User enumeration test: $($_.Exception.Message)"
                        }

                        # Test LSA access for domain info
                        try {
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
                                $result.DomainSID = $true
                                $result.VulnerabilityDetails += "LSARPC pipe accessible - domain SID enumeration possible"
                                Write-Verbose "  Domain SID enumeration: LIKELY (LSARPC accessible)"
                                $smb2Client.CloseFile($fileHandle) | Out-Null
                            }
                        } catch {
                            Write-Verbose "  Domain SID enumeration test: $($_.Exception.Message)"
                        }
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                } else {
                    Write-Verbose "  IPC$ access: DENIED"
                }

                $smb2Client.Logoff() | Out-Null
            } else {
                Write-Verbose "  Anonymous login: DENIED ($loginStatus)"
            }

            $smb2Client.Disconnect()

            # Determine overall vulnerability
            $result.Vulnerable = $result.NullSessionAllowed -or
                                $result.IPCAccess -or
                                $result.ShareEnumeration -or
                                $result.UserEnumeration

            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

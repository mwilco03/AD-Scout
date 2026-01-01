<#
.SYNOPSIS
    Tests for anonymous SAMR (Security Account Manager Remote) access.

.DESCRIPTION
    Uses SMBLibrary and RPCForSMBLibrary to test if anonymous access to
    the SAMR RPC interface is allowed. SAMR access enables:
    - User account enumeration
    - Group membership enumeration
    - Password policy retrieval
    - Domain SID enumeration

    This is a common reconnaissance vector used in Active Directory attacks.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.PARAMETER Credential
    Optional credentials for authenticated access testing.

.NOTES
    Scanner    : Invoke-SAMRScan
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with SAMR access test results.

.EXAMPLE
    Invoke-SAMRScan -ComputerName "dc01.contoso.com"
#>

function Invoke-SAMRScan {
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
        [int]$TimeoutMs = 5000,

        [Parameter()]
        [PSCredential]$Credential
    )

    begin {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "SMBLibrary not available. Cannot perform SAMR testing."
            $script:SAMRScanSkipped = $true
        } else {
            $script:SAMRScanSkipped = $false
        }
    }

    process {
        if ($script:SAMRScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing SAMR access on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            SAMRPipeAccessible      = $false
            AnonymousAccess         = $false
            UserEnumeration         = $false
            GroupEnumeration        = $false
            PasswordPolicyAccess    = $false
            DomainSIDAccess         = $false
            RIDCyclingPossible      = $false
            EnumeratedUsers         = @()
            EnumeratedGroups        = @()
            DomainInfo              = $null
            PasswordPolicy          = $null
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

            # Try anonymous login first
            $loginStatus = $smb2Client.Login("", "", "")

            if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.AnonymousAccess = $true
                Write-Verbose "  Anonymous login: Successful"

                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # Try to open SAMR pipe
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
                        $result.SAMRPipeAccessible = $true
                        $result.VulnerabilityDetails += "SAMR named pipe accessible anonymously"
                        Write-Verbose "  SAMR pipe: Accessible"

                        # If RPCForSMBLibrary is loaded, use it for detailed enumeration
                        if ($script:RPCLibraryLoaded) {
                            try {
                                # Create SAMR RPC client
                                $rpcTransport = New-Object SMBLibrary.RPC.RPCTransportOverSMB2 -ArgumentList @($smb2Client, $fileHandle)
                                $samrClient = New-Object RPCForSMBLibrary.SAMR.SAMRClient -ArgumentList @($rpcTransport)

                                # Try to connect to SAMR
                                $samrHandle = $null
                                $connectStatus = $samrClient.SamrConnect5($ComputerName, [ref]$samrHandle)

                                if ($connectStatus -eq 0) {  # STATUS_SUCCESS
                                    Write-Verbose "  SAMR RPC: Connected"

                                    # Try to enumerate domains
                                    $domains = $null
                                    $enumDomainStatus = $samrClient.SamrEnumerateDomainsInSamServer($samrHandle, [ref]$domains)

                                    if ($enumDomainStatus -eq 0 -and $domains) {
                                        $result.DomainSIDAccess = $true
                                        $result.DomainInfo = $domains
                                        $result.VulnerabilityDetails += "Domain enumeration possible"
                                        Write-Verbose "  Domain enumeration: Successful"
                                    }

                                    # Try to get domain SID and open domain
                                    foreach ($domain in $domains) {
                                        $domainSid = $null
                                        $lookupStatus = $samrClient.SamrLookupDomainInSamServer($samrHandle, $domain.Name, [ref]$domainSid)

                                        if ($lookupStatus -eq 0 -and $domainSid) {
                                            $domainHandle = $null
                                            $openDomainStatus = $samrClient.SamrOpenDomain($samrHandle, 0x0000010F, $domainSid, [ref]$domainHandle)

                                            if ($openDomainStatus -eq 0) {
                                                # Try user enumeration
                                                $users = $null
                                                $enumUserStatus = $samrClient.SamrEnumerateUsersInDomain($domainHandle, [ref]$users)

                                                if ($enumUserStatus -eq 0 -and $users) {
                                                    $result.UserEnumeration = $true
                                                    $result.EnumeratedUsers = $users | Select-Object -First 20
                                                    $result.RIDCyclingPossible = $true
                                                    $result.VulnerabilityDetails += "User enumeration possible ($($users.Count) users)"
                                                    Write-Verbose "  User enumeration: Found $($users.Count) users"
                                                }

                                                # Try group enumeration
                                                $groups = $null
                                                $enumGroupStatus = $samrClient.SamrEnumerateGroupsInDomain($domainHandle, [ref]$groups)

                                                if ($enumGroupStatus -eq 0 -and $groups) {
                                                    $result.GroupEnumeration = $true
                                                    $result.EnumeratedGroups = $groups | Select-Object -First 20
                                                    $result.VulnerabilityDetails += "Group enumeration possible ($($groups.Count) groups)"
                                                    Write-Verbose "  Group enumeration: Found $($groups.Count) groups"
                                                }

                                                # Try password policy
                                                $passwordInfo = $null
                                                $policyStatus = $samrClient.SamrQueryInformationDomain($domainHandle, 1, [ref]$passwordInfo)

                                                if ($policyStatus -eq 0 -and $passwordInfo) {
                                                    $result.PasswordPolicyAccess = $true
                                                    $result.PasswordPolicy = $passwordInfo
                                                    $result.VulnerabilityDetails += "Password policy accessible"
                                                    Write-Verbose "  Password policy: Accessible"
                                                }

                                                $samrClient.SamrCloseHandle($domainHandle) | Out-Null
                                            }
                                        }
                                    }

                                    $samrClient.SamrCloseHandle($samrHandle) | Out-Null
                                }
                            } catch {
                                Write-Verbose "  RPC enumeration error: $($_.Exception.Message)"
                            }
                        }

                        $smb2Client.CloseFile($fileHandle) | Out-Null
                    } else {
                        Write-Verbose "  SAMR pipe: Access denied ($openStatus)"
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            } else {
                Write-Verbose "  Anonymous login: Denied"
            }

            $smb2Client.Disconnect()

            # Determine vulnerability
            $result.Vulnerable = $result.SAMRPipeAccessible -or
                                $result.UserEnumeration -or
                                $result.GroupEnumeration -or
                                $result.PasswordPolicyAccess

            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

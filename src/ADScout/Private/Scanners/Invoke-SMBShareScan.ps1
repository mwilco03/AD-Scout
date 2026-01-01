<#
.SYNOPSIS
    Enumerates SMB shares on target systems.

.DESCRIPTION
    Uses SMBLibrary to enumerate accessible SMB shares including detection of:
    - Administrative shares (C$, ADMIN$, IPC$)
    - SYSVOL and NETLOGON shares
    - Custom shares with security-relevant permissions

    Can test both authenticated and anonymous/null session access.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.PARAMETER Credential
    Optional credentials for authenticated access.

.PARAMETER TestAnonymous
    Test for anonymous share enumeration. Default is $true.

.NOTES
    Scanner    : Invoke-SMBShareScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with share enumeration results.

.EXAMPLE
    Invoke-SMBShareScan -ComputerName "dc01.contoso.com"

.EXAMPLE
    Invoke-SMBShareScan -ComputerName "dc01" -Credential $cred
#>

function Invoke-SMBShareScan {
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
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$TestAnonymous = $true
    )

    begin {
        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "SMBLibrary not available. Cannot perform share enumeration."
            $script:ShareScanSkipped = $true
        } else {
            $script:ShareScanSkipped = $false
        }
    }

    process {
        if ($script:ShareScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Enumerating SMB shares on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName          = $ComputerName
            Port                  = $Port
            Status                = "Unknown"
            AnonymousAccess       = $false
            NullSessionShares     = $false
            AuthenticatedAccess   = $false
            Shares                = @()
            AdminSharesAccessible = $false
            SensitiveShares       = @()
            TotalShares           = 0
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

            $shares = @()
            $sensitiveShares = @('C$', 'ADMIN$', 'IPC$', 'SYSVOL', 'NETLOGON', 'D$', 'E$')

            # Test anonymous/null session access first
            if ($TestAnonymous) {
                try {
                    $smb2Client = New-Object SMBLibrary.Client.SMB2Client

                    $connected = $smb2Client.Connect(
                        [System.Net.IPAddress]::Parse($targetIP),
                        [SMBLibrary.SMBTransportType]::DirectTCPTransport
                    )

                    if ($connected) {
                        # Try to negotiate
                        $negotiateStatus = $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311)
                        if ($negotiateStatus -ne [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB210) | Out-Null
                        }

                        # Try anonymous login
                        $loginStatus = $smb2Client.Login("", "", "")

                        if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $result.AnonymousAccess = $true
                            Write-Verbose "  Anonymous login successful"

                            # Try to enumerate shares
                            $shareList = $null
                            $enumStatus = $smb2Client.ListShares([ref]$shareList)

                            if ($enumStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS -and $shareList) {
                                $result.NullSessionShares = $true
                                foreach ($share in $shareList) {
                                    $shareInfo = [PSCustomObject]@{
                                        Name           = $share
                                        AccessMethod   = "Anonymous"
                                        IsSensitive    = $sensitiveShares -contains $share
                                        CanConnect     = $false
                                        CanRead        = $false
                                        CanWrite       = $false
                                    }

                                    # Try to connect to each share
                                    $treeId = $null
                                    $treeStatus = $smb2Client.TreeConnect("\\$ComputerName\$share", [ref]$treeId)
                                    if ($treeStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                                        $shareInfo.CanConnect = $true
                                        if ($sensitiveShares -contains $share) {
                                            $result.SensitiveShares += $share
                                        }
                                        $smb2Client.TreeDisconnect($treeId) | Out-Null
                                    }

                                    $shares += $shareInfo
                                }
                            }

                            $smb2Client.Logoff() | Out-Null
                        } else {
                            Write-Verbose "  Anonymous login failed: $loginStatus"
                        }

                        $smb2Client.Disconnect()
                    }
                } catch {
                    Write-Verbose "  Anonymous access test error: $($_.Exception.Message)"
                }
            }

            # Test authenticated access if credentials provided
            if ($Credential) {
                try {
                    $smb2Client = New-Object SMBLibrary.Client.SMB2Client

                    $connected = $smb2Client.Connect(
                        [System.Net.IPAddress]::Parse($targetIP),
                        [SMBLibrary.SMBTransportType]::DirectTCPTransport
                    )

                    if ($connected) {
                        $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311) | Out-Null

                        $domain = ""
                        $username = $Credential.UserName
                        if ($username -match '(.+)\\(.+)') {
                            $domain = $Matches[1]
                            $username = $Matches[2]
                        }

                        $password = $Credential.GetNetworkCredential().Password
                        $loginStatus = $smb2Client.Login($domain, $username, $password)

                        if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $result.AuthenticatedAccess = $true

                            $shareList = $null
                            $enumStatus = $smb2Client.ListShares([ref]$shareList)

                            if ($enumStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS -and $shareList) {
                                foreach ($share in $shareList) {
                                    $existingShare = $shares | Where-Object { $_.Name -eq $share }
                                    if (-not $existingShare) {
                                        $shareInfo = [PSCustomObject]@{
                                            Name           = $share
                                            AccessMethod   = "Authenticated"
                                            IsSensitive    = $sensitiveShares -contains $share
                                            CanConnect     = $false
                                            CanRead        = $false
                                            CanWrite       = $false
                                        }
                                        $shares += $shareInfo
                                    }
                                }
                            }

                            # Check admin share access
                            $treeId = $null
                            $treeStatus = $smb2Client.TreeConnect("\\$ComputerName\ADMIN$", [ref]$treeId)
                            if ($treeStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                                $result.AdminSharesAccessible = $true
                                $smb2Client.TreeDisconnect($treeId) | Out-Null
                            }

                            $smb2Client.Logoff() | Out-Null
                        }

                        $smb2Client.Disconnect()
                    }
                } catch {
                    Write-Verbose "  Authenticated access test error: $($_.Exception.Message)"
                }
            }

            $result.Shares = $shares
            $result.TotalShares = $shares.Count
            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

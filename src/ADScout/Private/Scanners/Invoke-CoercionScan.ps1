<#
.SYNOPSIS
    Comprehensive coercion attack detection scanner.

.DESCRIPTION
    Uses SMBLibrary to test for multiple coercion attack vectors:
    - PrinterBug (MS-RPRN) - Print Spooler coercion
    - PetitPotam (MS-EFSRPC) - EFS coercion
    - DFSCoerce (MS-DFSNM) - DFS namespace coercion
    - ShadowCoerce (MS-FSRVP) - File Server VSS Agent coercion
    - CheeseOunce (MS-EVEN) - Event log coercion (if applicable)

    This scanner checks for accessibility only and does NOT trigger any coercion.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.PARAMETER Credential
    Optional credentials for authenticated scanning.

.NOTES
    Scanner    : Invoke-CoercionScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
    Safety     : This scanner does NOT trigger any coercion attacks

.OUTPUTS
    PSCustomObject with comprehensive coercion test results.

.EXAMPLE
    Invoke-CoercionScan -ComputerName "dc01.contoso.com"

.EXAMPLE
    $ADData.DomainControllers | Invoke-CoercionScan | Where-Object { $_.VulnerableVectors.Count -gt 0 }
#>

function Invoke-CoercionScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform coercion testing."
            $script:CoercionScanSkipped = $true
        } else {
            $script:CoercionScanSkipped = $false
        }
    }

    process {
        if ($script:CoercionScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Comprehensive coercion scan on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            AnonymousAccess         = $false
            IPCAccess               = $false

            # Individual attack vectors
            PrinterBug              = [PSCustomObject]@{
                Vulnerable   = $false
                PipeAccess   = $false
                Protocol     = "MS-RPRN"
                Pipe         = "\PIPE\spoolss"
            }
            PetitPotam              = [PSCustomObject]@{
                Vulnerable   = $false
                PipeAccess   = $false
                Protocol     = "MS-EFSRPC"
                Pipe         = "\PIPE\efsrpc"
            }
            DFSCoerce               = [PSCustomObject]@{
                Vulnerable   = $false
                PipeAccess   = $false
                Protocol     = "MS-DFSNM"
                Pipe         = "\PIPE\netdfs"
            }
            ShadowCoerce            = [PSCustomObject]@{
                Vulnerable   = $false
                PipeAccess   = $false
                Protocol     = "MS-FSRVP"
                Pipe         = "\PIPE\FssagentRpc"
            }
            CheeseOunce             = [PSCustomObject]@{
                Vulnerable   = $false
                PipeAccess   = $false
                Protocol     = "MS-EVEN"
                Pipe         = "\PIPE\eventlog"
            }

            # Summary
            VulnerableVectors       = @()
            TotalVectors            = 0
            VulnerableCount         = 0
            RiskLevel               = "None"
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

            # Login (anonymous or with credentials)
            $loginStatus = $null
            if ($Credential) {
                $domain = ""
                $username = $Credential.UserName
                if ($username -match '(.+)\\(.+)') {
                    $domain = $Matches[1]
                    $username = $Matches[2]
                }
                $password = $Credential.GetNetworkCredential().Password
                $loginStatus = $smb2Client.Login($domain, $username, $password)
            } else {
                $loginStatus = $smb2Client.Login("", "", "")
            }

            if ($loginStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.AnonymousAccess = -not $Credential
                Write-Verbose "  Login: Successful"

                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    $result.IPCAccess = $true
                    Write-Verbose "  IPC$ access: Granted"

                    # Test each coercion vector
                    $vectors = @(
                        @{ Property = "PrinterBug";   Pipes = @("\PIPE\spoolss", "\PIPE\SPOOLSS") }
                        @{ Property = "PetitPotam";   Pipes = @("\PIPE\efsrpc", "\PIPE\lsarpc") }
                        @{ Property = "DFSCoerce";    Pipes = @("\PIPE\netdfs") }
                        @{ Property = "ShadowCoerce"; Pipes = @("\PIPE\FssagentRpc") }
                        @{ Property = "CheeseOunce";  Pipes = @("\PIPE\eventlog") }
                    )

                    foreach ($vector in $vectors) {
                        $vectorResult = $result.($vector.Property)
                        $accessible = $false

                        foreach ($pipe in $vector.Pipes) {
                            try {
                                $fileHandle = $null
                                $openStatus = $smb2Client.CreateFile(
                                    $pipe,
                                    [SMBLibrary.AccessMask]::GENERIC_READ -bor [SMBLibrary.AccessMask]::GENERIC_WRITE,
                                    [SMBLibrary.FileAttributes]::Normal,
                                    [SMBLibrary.ShareAccess]::Read -bor [SMBLibrary.ShareAccess]::Write,
                                    [SMBLibrary.CreateDisposition]::FILE_OPEN,
                                    [SMBLibrary.CreateOptions]::FILE_NON_DIRECTORY_FILE,
                                    [ref]$fileHandle
                                )

                                if ($openStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                                    $vectorResult.PipeAccess = $true
                                    $vectorResult.Vulnerable = $true
                                    $vectorResult.Pipe = $pipe
                                    $accessible = $true
                                    Write-Verbose "    $($vector.Property): VULNERABLE (pipe: $pipe)"

                                    $smb2Client.CloseFile($fileHandle) | Out-Null
                                    break
                                }
                            } catch {
                                Write-Verbose "    $($vector.Property) test error: $($_.Exception.Message)"
                            }
                        }

                        if ($accessible) {
                            $result.VulnerableVectors += $vector.Property
                            $result.VulnerabilityDetails += "$($vector.Property) ($($vectorResult.Protocol)) - Coercion possible via $($vectorResult.Pipe)"
                        } else {
                            Write-Verbose "    $($vector.Property): Not vulnerable"
                        }
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            } else {
                Write-Verbose "  Login failed: $loginStatus"
            }

            $smb2Client.Disconnect()

            # Calculate summary
            $result.TotalVectors = 5
            $result.VulnerableCount = $result.VulnerableVectors.Count
            $result.Vulnerable = $result.VulnerableCount -gt 0

            # Determine risk level
            $result.RiskLevel = switch ($result.VulnerableCount) {
                0 { "None" }
                1 { "Medium" }
                2 { "High" }
                default { "Critical" }
            }

            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

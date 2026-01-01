<#
.SYNOPSIS
    Tests for Print Spooler service accessibility (PrinterBug/PrintNightmare prerequisite).

.DESCRIPTION
    Uses SMBLibrary to test if the Print Spooler service is accessible over RPC.
    The Print Spooler being accessible on Domain Controllers is a security concern
    because it enables:
    - PrinterBug (MS-RPRN) coercion attacks
    - PrintNightmare (CVE-2021-1675/CVE-2021-34527) exploitation

    This scanner checks for accessibility only and does NOT exploit any vulnerability.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-SpoolerScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
    Related    : PrinterBug, PrintNightmare (CVE-2021-1675, CVE-2021-34527)

.OUTPUTS
    PSCustomObject with Print Spooler accessibility results.

.EXAMPLE
    Invoke-SpoolerScan -ComputerName "dc01.contoso.com"

.EXAMPLE
    $ADData.DomainControllers | Invoke-SpoolerScan | Where-Object SpoolerAccessible
#>

function Invoke-SpoolerScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform Spooler testing."
            $script:SpoolerScanSkipped = $true
        } else {
            $script:SpoolerScanSkipped = $false
        }
    }

    process {
        if ($script:SpoolerScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Testing Print Spooler accessibility on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            SpoolerPipeAccessible   = $false
            SpoolssPipeAccessible   = $false
            SpoolerAccessible       = $false
            AnonymousAccess         = $false
            PrinterBugExploitable   = $false
            PrintNightmareRisk      = $false
            RPRNAccessible          = $false
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

                # Connect to IPC$
                $treeId = $null
                $ipcStatus = $smb2Client.TreeConnect("\\$ComputerName\IPC$", [ref]$treeId)

                if ($ipcStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    # Try to open spoolss pipe (primary spooler pipe)
                    $spoolssPipes = @("\PIPE\spoolss", "\PIPE\SPOOLSS")

                    foreach ($pipe in $spoolssPipes) {
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
                            $result.SpoolssPipeAccessible = $true
                            $result.SpoolerAccessible = $true
                            $result.RPRNAccessible = $true  # MS-RPRN uses spoolss pipe
                            $result.PrinterBugExploitable = $true
                            $result.PrintNightmareRisk = $true
                            $result.VulnerabilityDetails += "Print Spooler ($pipe) accessible - PrinterBug/PrintNightmare risk"
                            Write-Verbose "  Spooler pipe ($pipe): Accessible"

                            $smb2Client.CloseFile($fileHandle) | Out-Null
                            break
                        }
                    }

                    if (-not $result.SpoolssPipeAccessible) {
                        Write-Verbose "  Spooler pipe: Not accessible (Spooler may be disabled)"
                    }

                    $smb2Client.TreeDisconnect($treeId) | Out-Null
                }

                $smb2Client.Logoff() | Out-Null
            } else {
                # Try with guest/authenticated access if anonymous fails
                Write-Verbose "  Anonymous login failed, spooler may require authentication"
            }

            $smb2Client.Disconnect()

            # Determine vulnerability
            $result.Vulnerable = $result.SpoolerAccessible
            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

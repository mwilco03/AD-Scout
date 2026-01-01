<#
.SYNOPSIS
    Scans for supported SMB protocol versions on target systems.

.DESCRIPTION
    Uses SMBLibrary to perform actual SMB protocol negotiation and detect
    which SMB dialects are supported by the target system. This provides
    protocol-level detection rather than registry-based checks.

    Supported dialects:
    - SMB 1.0 (NT LM 0.12) - Legacy, insecure
    - SMB 2.0.2 - Windows Vista/Server 2008
    - SMB 2.1 - Windows 7/Server 2008 R2
    - SMB 3.0 - Windows 8/Server 2012
    - SMB 3.0.2 - Windows 8.1/Server 2012 R2
    - SMB 3.1.1 - Windows 10/Server 2016+

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445 (Direct TCP).

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.PARAMETER TestSMB1
    Also test for SMB1 support. Default is $true.

.NOTES
    Scanner    : Invoke-SMBDialectScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with dialect detection results.

.EXAMPLE
    Invoke-SMBDialectScan -ComputerName "dc01.contoso.com"

.EXAMPLE
    $ADData.DomainControllers | Invoke-SMBDialectScan
#>

function Invoke-SMBDialectScan {
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
        [switch]$TestSMB1 = $true
    )

    begin {
        # Verify DLL availability
        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "SMBLibrary not available. Cannot perform protocol-level dialect detection."
            $script:DialectScanSkipped = $true
        } else {
            $script:DialectScanSkipped = $false
        }
    }

    process {
        # Return skipped result if DLLs not available
        if ($script:DialectScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Scanning SMB dialects on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName      = $ComputerName
            Port              = $Port
            Status            = "Unknown"
            SMB1Supported     = $false
            SMB2Supported     = $false
            SMB21Supported    = $false
            SMB30Supported    = $false
            SMB302Supported   = $false
            SMB311Supported   = $false
            HighestDialect    = $null
            LowestDialect     = $null
            AllDialects       = @()
            SMB1Only          = $false
            ModernOnly        = $false
            Error             = $null
            Timestamp         = [datetime]::UtcNow
        }

        try {
            # Resolve hostname to IP
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

            # Test SMB2/3 dialects using SMB2Client
            $dialects = @()
            $smb2Client = $null

            try {
                $smb2Client = New-Object SMBLibrary.Client.SMB2Client

                # Connect to target
                $connected = $smb2Client.Connect(
                    [System.Net.IPAddress]::Parse($targetIP),
                    [SMBLibrary.SMBTransportType]::DirectTCPTransport
                )

                if (-not $connected) {
                    $result.Status = "ConnectionFailed"
                    $result.Error = "Could not establish SMB connection to $ComputerName`:$Port"
                    return $result
                }

                # Test each SMB2/3 dialect
                $dialectTests = @(
                    @{ Enum = [SMBLibrary.SMB2Dialect]::SMB202;  Name = "SMB 2.0.2"; Property = "SMB2Supported" }
                    @{ Enum = [SMBLibrary.SMB2Dialect]::SMB210;  Name = "SMB 2.1";   Property = "SMB21Supported" }
                    @{ Enum = [SMBLibrary.SMB2Dialect]::SMB300;  Name = "SMB 3.0";   Property = "SMB30Supported" }
                    @{ Enum = [SMBLibrary.SMB2Dialect]::SMB302;  Name = "SMB 3.0.2"; Property = "SMB302Supported" }
                    @{ Enum = [SMBLibrary.SMB2Dialect]::SMB311;  Name = "SMB 3.1.1"; Property = "SMB311Supported" }
                )

                foreach ($test in $dialectTests) {
                    try {
                        # Reconnect for each test
                        if (-not $smb2Client.IsConnected) {
                            $smb2Client.Connect(
                                [System.Net.IPAddress]::Parse($targetIP),
                                [SMBLibrary.SMBTransportType]::DirectTCPTransport
                            ) | Out-Null
                        }

                        # Attempt negotiation with specific dialect
                        $negotiateStatus = $smb2Client.Negotiate($test.Enum)

                        if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $result.($test.Property) = $true
                            $dialects += $test.Name
                            Write-Verbose "  $($test.Name): Supported"
                        } else {
                            Write-Verbose "  $($test.Name): Not supported (Status: $negotiateStatus)"
                        }

                        # Disconnect after each test
                        if ($smb2Client.IsConnected) {
                            $smb2Client.Disconnect()
                        }
                    } catch {
                        Write-Verbose "  $($test.Name): Error - $($_.Exception.Message)"
                    }
                }
            } finally {
                if ($smb2Client -and $smb2Client.IsConnected) {
                    $smb2Client.Disconnect()
                }
            }

            # Test SMB1 if requested
            if ($TestSMB1) {
                try {
                    $smb1Client = New-Object SMBLibrary.Client.SMB1Client

                    $connected = $smb1Client.Connect(
                        [System.Net.IPAddress]::Parse($targetIP),
                        [SMBLibrary.SMBTransportType]::DirectTCPTransport
                    )

                    if ($connected) {
                        $negotiateStatus = $smb1Client.Negotiate()
                        if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                            $result.SMB1Supported = $true
                            $dialects = @("SMB 1.0") + $dialects
                            Write-Verbose "  SMB 1.0: Supported (INSECURE!)"
                        }
                        $smb1Client.Disconnect()
                    }
                } catch {
                    Write-Verbose "  SMB 1.0: Error - $($_.Exception.Message)"
                }
            }

            # Populate result
            $result.AllDialects = $dialects
            $result.Status = "Success"

            if ($dialects.Count -gt 0) {
                $result.HighestDialect = $dialects[-1]
                $result.LowestDialect = $dialects[0]
                $result.SMB1Only = ($dialects.Count -eq 1) -and ($dialects[0] -eq "SMB 1.0")
                $result.ModernOnly = -not $result.SMB1Supported -and $result.SMB311Supported
            }

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

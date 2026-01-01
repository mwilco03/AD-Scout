<#
.SYNOPSIS
    Safe detection of CVE-2020-0796 (SMBGhost) vulnerability.

.DESCRIPTION
    This scanner performs SAFE detection of the SMBGhost vulnerability.
    It does NOT exploit the vulnerability or modify any server state.

    Detection method:
    1. Connects using SMB 3.1.1
    2. Checks if compression is advertised
    3. Systems with compression enabled may be vulnerable

    IMPORTANT: This scanner is designed for defensive security assessment.
    It performs read-only checks and cannot exploit SMBGhost.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-SMBGhostScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
    Related    : CVE-2020-0796 (SMBGhost, CoronaBlue)
    Safety     : This scanner does NOT exploit SMBGhost

.OUTPUTS
    PSCustomObject with SMBGhost detection results.

.EXAMPLE
    Invoke-SMBGhostScan -ComputerName "server01.contoso.com"
#>

function Invoke-SMBGhostScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform SMBGhost detection."
            $script:SMBGhostScanSkipped = $true
        } else {
            $script:SMBGhostScanSkipped = $false
        }
    }

    process {
        if ($script:SMBGhostScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Performing safe SMBGhost detection on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName            = $ComputerName
            Port                    = $Port
            Status                  = "Unknown"
            SMB311Supported         = $false
            CompressionSupported    = $false
            CompressionAlgorithms   = @()
            SMBGhostVulnerable      = $false
            PatchVerified           = $false
            Vulnerable              = $false
            VulnerabilityDetails    = @()
            CVE                     = "CVE-2020-0796"
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

            # Try to negotiate SMB 3.1.1 (required for compression)
            $negotiateStatus = $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311)

            if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.SMB311Supported = $true
                Write-Verbose "  SMB 3.1.1: Supported"

                # Check for compression capability
                # SMBGhost affects the compression decompression in SMB 3.1.1
                # We check if compression is advertised in the negotiate response

                # SMB 3.1.1 negotiate response includes compression capabilities
                # in the negotiate context list

                # Check capabilities flag for compression (0x00000100)
                $capabilities = $smb2Client.Capabilities
                $compressionCapable = ($capabilities -band 0x100) -ne 0

                if ($compressionCapable) {
                    $result.CompressionSupported = $true
                    $result.CompressionAlgorithms = @("LZNT1", "LZ77", "LZ77+Huffman")

                    # Systems with SMB 3.1.1 compression enabled may be vulnerable
                    # unless patched (KB4551762)
                    $result.SMBGhostVulnerable = $true  # Potential
                    $result.Vulnerable = $true
                    $result.VulnerabilityDetails += "CVE-2020-0796 (SMBGhost) - SMB compression enabled, verify patch KB4551762"

                    Write-Verbose "  SMB Compression: Enabled (potential SMBGhost vulnerability)"
                } else {
                    Write-Verbose "  SMB Compression: Not advertised (SMBGhost less likely)"

                    # Even without compression flag, SMB 3.1.1 systems from the
                    # vulnerable Windows versions may still need patching
                    $result.VulnerabilityDetails += "SMB 3.1.1 supported - verify patch status for CVE-2020-0796"
                }

                # Note: Full detection would require:
                # 1. Sending a malformed compression transform header
                # 2. Checking if server crashes or returns error
                # This is NOT safe and we don't do it

            } else {
                Write-Verbose "  SMB 3.1.1: Not supported (SMBGhost not applicable)"
                $result.VulnerabilityDetails += "SMB 3.1.1 not supported - CVE-2020-0796 not applicable"
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

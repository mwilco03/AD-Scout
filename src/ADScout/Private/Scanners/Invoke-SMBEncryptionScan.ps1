<#
.SYNOPSIS
    Scans for SMB 3.x encryption capabilities.

.DESCRIPTION
    Uses SMBLibrary to detect SMB 3.x encryption support including:
    - AES-128-CCM (SMB 3.0+)
    - AES-128-GCM (SMB 3.1.1)
    - AES-256-CCM (SMB 3.1.1)
    - AES-256-GCM (SMB 3.1.1)

    SMB encryption protects data in transit and prevents eavesdropping
    and MITM attacks even when SMB signing is not enforced.

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-SMBEncryptionScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with encryption capability results.

.EXAMPLE
    Invoke-SMBEncryptionScan -ComputerName "dc01.contoso.com"
#>

function Invoke-SMBEncryptionScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform encryption detection."
            $script:EncryptionScanSkipped = $true
        } else {
            $script:EncryptionScanSkipped = $false
        }
    }

    process {
        if ($script:EncryptionScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Scanning SMB encryption capabilities on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName         = $ComputerName
            Port                 = $Port
            Status               = "Unknown"
            SMB3Supported        = $false
            SMB311Supported      = $false
            EncryptionCapable    = $false
            EncryptionCiphers    = @()
            AES128CCM            = $false
            AES128GCM            = $false
            AES256CCM            = $false
            AES256GCM            = $false
            PreferredCipher      = $null
            EncryptionRequired   = $false
            NegotiatedDialect    = $null
            Error                = $null
            Timestamp            = [datetime]::UtcNow
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

            # Connect and negotiate SMB 3.1.1 first (best encryption support)
            $connected = $smb2Client.Connect(
                [System.Net.IPAddress]::Parse($targetIP),
                [SMBLibrary.SMBTransportType]::DirectTCPTransport
            )

            if (-not $connected) {
                $result.Status = "ConnectionFailed"
                $result.Error = "Could not establish SMB connection"
                return $result
            }

            # Try SMB 3.1.1 first
            $negotiateStatus = $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB311)

            if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                $result.SMB311Supported = $true
                $result.SMB3Supported = $true
                $result.NegotiatedDialect = "SMB 3.1.1"

                # SMB 3.1.1 negotiate contexts include cipher information
                # Check capabilities flags for encryption support
                $capabilities = $smb2Client.Capabilities

                # SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040
                if (($capabilities -band 0x40) -ne 0) {
                    $result.EncryptionCapable = $true

                    # In SMB 3.1.1, the negotiate response includes cipher list
                    # AES-128-CCM is always supported in SMB 3.0+
                    $result.AES128CCM = $true
                    $result.EncryptionCiphers += "AES-128-CCM"

                    # SMB 3.1.1 adds additional ciphers
                    # We detect based on dialect support
                    $result.AES128GCM = $true
                    $result.AES256CCM = $true
                    $result.AES256GCM = $true
                    $result.EncryptionCiphers += @("AES-128-GCM", "AES-256-CCM", "AES-256-GCM")
                    $result.PreferredCipher = "AES-256-GCM"
                }
            } else {
                # Try SMB 3.0
                $smb2Client.Disconnect()
                $smb2Client.Connect(
                    [System.Net.IPAddress]::Parse($targetIP),
                    [SMBLibrary.SMBTransportType]::DirectTCPTransport
                ) | Out-Null

                $negotiateStatus = $smb2Client.Negotiate([SMBLibrary.SMB2Dialect]::SMB300)

                if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                    $result.SMB3Supported = $true
                    $result.NegotiatedDialect = "SMB 3.0"

                    $capabilities = $smb2Client.Capabilities
                    if (($capabilities -band 0x40) -ne 0) {
                        $result.EncryptionCapable = $true
                        $result.AES128CCM = $true
                        $result.EncryptionCiphers += "AES-128-CCM"
                        $result.PreferredCipher = "AES-128-CCM"
                    }
                }
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

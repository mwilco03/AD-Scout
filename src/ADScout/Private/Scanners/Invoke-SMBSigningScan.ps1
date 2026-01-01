<#
.SYNOPSIS
    Scans for SMB signing configuration at the protocol level.

.DESCRIPTION
    Uses SMBLibrary to perform actual SMB protocol negotiation and detect
    the signing configuration. This provides protocol-level verification
    of signing status rather than registry-based checks which can be bypassed.

    Checks:
    - SigningEnabled: Server advertises signing capability
    - SigningRequired: Server requires signing (cannot be bypassed)

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The SMB port to connect to. Default is 445.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-SMBSigningScan
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with signing detection results.

.EXAMPLE
    Invoke-SMBSigningScan -ComputerName "dc01.contoso.com"

.EXAMPLE
    $ADData.DomainControllers | Invoke-SMBSigningScan | Where-Object { -not $_.SigningRequired }
#>

function Invoke-SMBSigningScan {
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
            Write-Warning "SMBLibrary not available. Cannot perform protocol-level signing detection."
            $script:SigningScanSkipped = $true
        } else {
            $script:SigningScanSkipped = $false
        }
    }

    process {
        if ($script:SigningScanSkipped) {
            return [PSCustomObject]@{
                ComputerName     = $ComputerName
                Status           = "Skipped"
                Reason           = "SMBLibrary not available"
                Timestamp        = [datetime]::UtcNow
            }
        }

        Write-Verbose "Scanning SMB signing configuration on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName       = $ComputerName
            Port               = $Port
            Status             = "Unknown"
            NegotiatedDialect  = $null
            SigningEnabled     = $false
            SigningRequired    = $false
            SecurityMode       = $null
            Vulnerable         = $false
            VulnerabilityType  = $null
            DialectResults     = @()
            Error              = $null
            Timestamp          = [datetime]::UtcNow
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

            # Test signing for each SMB2/3 dialect
            $dialectTests = @(
                @{ Enum = [SMBLibrary.SMB2Dialect]::SMB311;  Name = "SMB 3.1.1" }
                @{ Enum = [SMBLibrary.SMB2Dialect]::SMB302;  Name = "SMB 3.0.2" }
                @{ Enum = [SMBLibrary.SMB2Dialect]::SMB300;  Name = "SMB 3.0" }
                @{ Enum = [SMBLibrary.SMB2Dialect]::SMB210;  Name = "SMB 2.1" }
                @{ Enum = [SMBLibrary.SMB2Dialect]::SMB202;  Name = "SMB 2.0.2" }
            )

            $dialectResults = @()
            $bestDialect = $null

            foreach ($test in $dialectTests) {
                try {
                    # Reconnect for each test
                    if (-not $smb2Client.IsConnected) {
                        $smb2Client.Connect(
                            [System.Net.IPAddress]::Parse($targetIP),
                            [SMBLibrary.SMBTransportType]::DirectTCPTransport
                        ) | Out-Null
                    }

                    $negotiateStatus = $smb2Client.Negotiate($test.Enum)

                    if ($negotiateStatus -eq [SMBLibrary.NTStatus]::STATUS_SUCCESS) {
                        # Get security mode from the negotiated response
                        $securityMode = $smb2Client.SecurityMode

                        # Check signing flags
                        # SMB2 Security Mode flags:
                        # 0x01 = SMB2_NEGOTIATE_SIGNING_ENABLED
                        # 0x02 = SMB2_NEGOTIATE_SIGNING_REQUIRED
                        $signingEnabled = ($securityMode -band 0x01) -ne 0
                        $signingRequired = ($securityMode -band 0x02) -ne 0

                        $dialectResult = [PSCustomObject]@{
                            Dialect         = $test.Name
                            Supported       = $true
                            SecurityMode    = $securityMode
                            SigningEnabled  = $signingEnabled
                            SigningRequired = $signingRequired
                        }
                        $dialectResults += $dialectResult

                        Write-Verbose "  $($test.Name): Enabled=$signingEnabled, Required=$signingRequired (Mode: $securityMode)"

                        # Track the best (highest) dialect
                        if ($null -eq $bestDialect) {
                            $bestDialect = $dialectResult
                        }
                    }

                    # Disconnect after each test
                    if ($smb2Client.IsConnected) {
                        $smb2Client.Disconnect()
                    }
                } catch {
                    Write-Verbose "  $($test.Name): Error - $($_.Exception.Message)"
                }
            }

            $smb2Client.Disconnect()

            # Populate result from best dialect
            if ($bestDialect) {
                $result.NegotiatedDialect = $bestDialect.Dialect
                $result.SigningEnabled = $bestDialect.SigningEnabled
                $result.SigningRequired = $bestDialect.SigningRequired
                $result.SecurityMode = $bestDialect.SecurityMode
                $result.Status = "Success"

                # Determine vulnerability status
                if (-not $bestDialect.SigningRequired) {
                    $result.Vulnerable = $true
                    if (-not $bestDialect.SigningEnabled) {
                        $result.VulnerabilityType = "SigningDisabled"
                    } else {
                        $result.VulnerabilityType = "SigningNotRequired"
                    }
                }
            } else {
                $result.Status = "NoDialectNegotiated"
                $result.Error = "Could not negotiate any SMB2/3 dialect"
            }

            $result.DialectResults = $dialectResults

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

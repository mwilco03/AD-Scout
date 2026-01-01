<#
.SYNOPSIS
    Tests LDAPS (LDAP over SSL/TLS) configuration and security.

.DESCRIPTION
    Uses .NET SSL libraries to test LDAPS security including:
    - LDAPS availability (port 636)
    - Certificate validity
    - TLS version support
    - Cipher suite strength

.PARAMETER ComputerName
    The target computer name or IP address.

.PARAMETER Port
    The LDAPS port to connect to. Default is 636.

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default is 5000.

.NOTES
    Scanner    : Invoke-LDAPSScan
    Requires   : Native .NET (no external DLLs required)
    Author     : AD-Scout Contributors

.OUTPUTS
    PSCustomObject with LDAPS security test results.

.EXAMPLE
    Invoke-LDAPSScan -ComputerName "dc01.contoso.com"
#>

function Invoke-LDAPSScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("DNSHostName", "Name", "HostName", "IPAddress")]
        [string]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 636,

        [Parameter()]
        [ValidateRange(1000, 60000)]
        [int]$TimeoutMs = 10000
    )

    process {
        Write-Verbose "Testing LDAPS security on $ComputerName`:$Port"

        $result = [PSCustomObject]@{
            ComputerName          = $ComputerName
            Port                  = $Port
            Status                = "Unknown"
            LDAPSAvailable        = $false
            CertificateValid      = $false
            CertificateExpired    = $false
            CertificateExpiresSoon = $false
            CertificateDaysRemaining = $null
            CertificateSubject    = $null
            CertificateIssuer     = $null
            CertificateThumbprint = $null
            CertificateNotBefore  = $null
            CertificateNotAfter   = $null
            TLSVersion            = $null
            TLS10Supported        = $false
            TLS11Supported        = $false
            TLS12Supported        = $false
            TLS13Supported        = $false
            CipherSuite           = $null
            WeakCiphers           = $false
            SelfSigned            = $false
            Vulnerable            = $false
            VulnerabilityDetails  = @()
            Error                 = $null
            Timestamp             = [datetime]::UtcNow
        }

        try {
            # Test LDAPS connectivity and get certificate
            $tcpClient = $null
            $sslStream = $null

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
                $connected = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

                if (-not $connected) {
                    $result.Status = "ConnectionTimeout"
                    $result.Error = "Connection timed out"
                    return $result
                }

                $tcpClient.EndConnect($asyncResult)
                $result.LDAPSAvailable = $true
                Write-Verbose "  LDAPS port open: Yes"

                # Get SSL stream and certificate
                $sslStream = New-Object System.Net.Security.SslStream(
                    $tcpClient.GetStream(),
                    $false,
                    { param($sender, $certificate, $chain, $sslPolicyErrors)
                        # Accept all certificates for testing purposes
                        # We'll validate them ourselves
                        return $true
                    }
                )

                # Test different TLS versions
                $tlsVersions = @(
                    @{ Version = [System.Security.Authentication.SslProtocols]::Tls13; Name = "TLS 1.3"; Property = "TLS13Supported" }
                    @{ Version = [System.Security.Authentication.SslProtocols]::Tls12; Name = "TLS 1.2"; Property = "TLS12Supported" }
                    @{ Version = [System.Security.Authentication.SslProtocols]::Tls11; Name = "TLS 1.1"; Property = "TLS11Supported" }
                    @{ Version = [System.Security.Authentication.SslProtocols]::Tls;   Name = "TLS 1.0"; Property = "TLS10Supported" }
                )

                $authenticated = $false
                foreach ($tlsTest in $tlsVersions) {
                    try {
                        if (-not $authenticated) {
                            $sslStream.AuthenticateAsClient($ComputerName, $null, $tlsTest.Version, $false)
                            $result.($tlsTest.Property) = $true
                            $result.TLSVersion = $tlsTest.Name
                            $authenticated = $true
                            Write-Verbose "    $($tlsTest.Name): Supported (negotiated)"
                        }
                    } catch {
                        Write-Verbose "    $($tlsTest.Name): $($_.Exception.Message)"
                    }
                }

                if (-not $authenticated) {
                    # Try with system default
                    try {
                        $sslStream = New-Object System.Net.Security.SslStream(
                            $tcpClient.GetStream(),
                            $false,
                            { param($sender, $certificate, $chain, $sslPolicyErrors) return $true }
                        )
                        $sslStream.AuthenticateAsClient($ComputerName)
                        $authenticated = $true
                    } catch {
                        $result.Status = "TLSFailed"
                        $result.Error = $_.Exception.Message
                        return $result
                    }
                }

                # Get certificate details
                if ($authenticated -and $sslStream.RemoteCertificate) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)

                    $result.CertificateSubject = $cert.Subject
                    $result.CertificateIssuer = $cert.Issuer
                    $result.CertificateThumbprint = $cert.Thumbprint
                    $result.CertificateNotBefore = $cert.NotBefore
                    $result.CertificateNotAfter = $cert.NotAfter

                    # Check validity
                    $now = Get-Date
                    $result.CertificateDaysRemaining = [math]::Floor(($cert.NotAfter - $now).TotalDays)

                    if ($cert.NotAfter -lt $now) {
                        $result.CertificateExpired = $true
                        $result.Vulnerable = $true
                        $result.VulnerabilityDetails += "LDAPS certificate expired on $($cert.NotAfter)"
                        Write-Verbose "  Certificate: EXPIRED"
                    } elseif ($cert.NotAfter -lt $now.AddDays(30)) {
                        $result.CertificateExpiresSoon = $true
                        $result.VulnerabilityDetails += "LDAPS certificate expires in $($result.CertificateDaysRemaining) days"
                        Write-Verbose "  Certificate: Expires soon ($($result.CertificateDaysRemaining) days)"
                    } else {
                        $result.CertificateValid = $true
                        Write-Verbose "  Certificate: Valid ($($result.CertificateDaysRemaining) days remaining)"
                    }

                    # Check if self-signed
                    if ($cert.Subject -eq $cert.Issuer) {
                        $result.SelfSigned = $true
                        $result.VulnerabilityDetails += "LDAPS uses self-signed certificate"
                        Write-Verbose "  Certificate: Self-signed"
                    }

                    # Get cipher suite info
                    $result.CipherSuite = $sslStream.CipherAlgorithm.ToString()

                    # Check for weak ciphers
                    $weakCiphers = @("Rc4", "Des", "TripleDes", "Null", "None")
                    if ($weakCiphers -contains $sslStream.CipherAlgorithm.ToString()) {
                        $result.WeakCiphers = $true
                        $result.Vulnerable = $true
                        $result.VulnerabilityDetails += "Weak cipher suite: $($sslStream.CipherAlgorithm)"
                    }
                }

                # Check for weak TLS versions
                if ($result.TLS10Supported) {
                    $result.Vulnerable = $true
                    $result.VulnerabilityDetails += "TLS 1.0 supported (deprecated)"
                }
                if ($result.TLS11Supported) {
                    $result.VulnerabilityDetails += "TLS 1.1 supported (deprecated)"
                }

            } finally {
                if ($sslStream) { $sslStream.Dispose() }
                if ($tcpClient) { $tcpClient.Close() }
            }

            $result.Status = "Success"

        } catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }

        return $result
    }
}

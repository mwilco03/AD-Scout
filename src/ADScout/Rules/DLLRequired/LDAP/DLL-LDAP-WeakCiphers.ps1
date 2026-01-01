<#
.SYNOPSIS
    Detects weak TLS cipher suites on LDAPS connections.

.DESCRIPTION
    Uses native .NET TLS testing to detect weak or deprecated cipher
    suites on LDAPS (port 636) connections to Domain Controllers.

.NOTES
    Rule ID    : DLL-LDAP-WeakCiphers
    Category   : DLLRequired
    Requires   : Native .NET
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-LDAP-WeakCiphers'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAPS Weak Cipher Suites Detected'
    Description = 'LDAPS connections accept weak or deprecated TLS cipher suites, potentially allowing cryptographic attacks.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'DomainControllers'

    RequiresDLL     = $false
    FallbackBehavior = 'Continue'

    References  = @(
        @{ Title = 'TLS Cipher Suites'; Url = 'https://docs.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel' }
        @{ Title = 'NIST TLS Guidelines'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final' }
    )

    MITRE = @{
        Tactics    = @('TA0009')  # Collection
        Techniques = @('T1040', 'T1557')  # Network Sniffing, MITM
    }

    CIS   = @('9.3.2')
    NIST  = @('SC-8', 'SC-12', 'SC-13')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
        Maximum = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $weakCiphers = @('Rc4', 'Des', 'TripleDes', 'Null', 'None', 'Rc2')
        $deprecatedTLS = @('Tls', 'Tls11')  # TLS 1.0 and 1.1

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-LDAPSScan -ComputerName $dcName -TimeoutMs 10000

                if ($scanResult.Status -eq 'Success' -and $scanResult.LDAPSAvailable) {
                    $issues = @()

                    # Check for weak ciphers
                    if ($scanResult.CipherSuite -and $weakCiphers -contains $scanResult.CipherSuite) {
                        $issues += "Weak cipher: $($scanResult.CipherSuite)"
                    }

                    # Check for deprecated TLS versions
                    if ($scanResult.TLS10Supported) {
                        $issues += "TLS 1.0 supported (deprecated)"
                    }
                    if ($scanResult.TLS11Supported) {
                        $issues += "TLS 1.1 supported (deprecated)"
                    }

                    if ($issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            DomainController      = $dcName
                            OperatingSystem       = $dc.OperatingSystem
                            TLSVersion            = $scanResult.TLSVersion
                            CipherSuite           = $scanResult.CipherSuite
                            TLS10Supported        = $scanResult.TLS10Supported
                            TLS11Supported        = $scanResult.TLS11Supported
                            TLS12Supported        = $scanResult.TLS12Supported
                            TLS13Supported        = $scanResult.TLS13Supported
                            Issues                = ($issues -join '; ')
                            RiskLevel             = 'Medium'
                            Impact                = 'Potential cryptographic weakness'
                            DistinguishedName     = $dc.DistinguishedName
                        }
                    }
                }
            } catch {
                Write-Verbose "DLL-LDAP-WeakCiphers: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable weak TLS versions and cipher suites via registry or Group Policy.'
        Impact      = 'Medium - May affect legacy clients using deprecated protocols.'
        Script      = {
            param($Finding, $Domain)

            @"
# Disable Weak TLS Versions and Cipher Suites

# Step 1: Disable TLS 1.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' `
    -Name 'Enabled' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' `
    -Name 'DisabledByDefault' -Value 1 -Type DWord

# Step 2: Disable TLS 1.1
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' `
    -Name 'Enabled' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' `
    -Name 'DisabledByDefault' -Value 1 -Type DWord

# Step 3: Disable weak ciphers (RC4, DES, 3DES)
`$weakCiphers = @('RC4 128/128', 'RC4 40/128', 'RC4 56/128', 'DES 56/56', 'Triple DES 168')
foreach (`$cipher in `$weakCiphers) {
    `$path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\`$cipher"
    New-Item -Path `$path -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path `$path -Name 'Enabled' -Value 0 -Type DWord
}

# Step 4: Enable only strong TLS versions
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' `
    -Name 'Enabled' -Value 1 -Type DWord

New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' `
    -Name 'Enabled' -Value 1 -Type DWord

# Reboot required for changes to take effect
Write-Host "Reboot required to apply TLS changes"

# Verify using:
# [Net.ServicePointManager]::SecurityProtocol
"@
        }
    }
}

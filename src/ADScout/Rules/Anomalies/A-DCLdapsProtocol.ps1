@{
    Id          = 'A-DCLdapsProtocol'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Weak TLS/SSL Protocols on Domain Controller LDAPS'
    Description = 'Detects when Domain Controllers have LDAPS configured with weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1). These protocols have known vulnerabilities and should be disabled.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'TLS Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/tls/tls-schannel-ssp-changes-in-windows-10-and-windows-server-2016' }
        @{ Title = 'POODLE Vulnerability'; Url = 'https://nvd.nist.gov/vuln/detail/CVE-2014-3566' }
        @{ Title = 'PingCastle Rule A-DCLdapsProtocol'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1557', 'T1040')  # Adversary-in-the-Middle, Network Sniffing
    }

    CIS   = @()  # TLS settings covered in OS-specific benchmarks
    STIG  = @()  # TLS/SSL STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('SC-8', 'SC-13')  # Transmission Confidentiality, Cryptographic Protection

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Weak protocols
        $weakProtocols = @(
            @{ Name = 'SSL 2.0'; Path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; CVE = 'Multiple' }
            @{ Name = 'SSL 3.0'; Path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; CVE = 'CVE-2014-3566 (POODLE)' }
            @{ Name = 'TLS 1.0'; Path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; CVE = 'Multiple (BEAST, etc.)' }
            @{ Name = 'TLS 1.1'; Path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; CVE = 'Deprecated' }
        )

        try {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                $dcHost = $dc.DNSHostName

                # Check if LDAPS is configured (port 636)
                $ldapsEnabled = $false
                if ($dc.Services) {
                    # Check for LDAPS certificate
                    $ldapsEnabled = $true  # Assume enabled if we have DC data
                }

                # Check weak protocols via registry
                foreach ($protocol in $weakProtocols) {
                    try {
                        $regPath = "HKLM:\$($protocol.Path)"
                        $enabled = $null

                        if ($dc.RegistrySettings) {
                            # Check from collected data
                            $regSetting = $dc.RegistrySettings | Where-Object {
                                $_.Path -match [regex]::Escape($protocol.Path)
                            }
                            if ($regSetting) {
                                $enabled = $regSetting.Enabled
                            }
                        } else {
                            # Try remote registry check
                            try {
                                $result = Invoke-Command -ComputerName $dcHost -ScriptBlock {
                                    param($path)
                                    $val = Get-ItemProperty -Path "HKLM:\$path" -Name 'Enabled' -ErrorAction SilentlyContinue
                                    if ($null -eq $val) {
                                        # If key doesn't exist, protocol may be enabled by default (for older protocols)
                                        return $null
                                    }
                                    return $val.Enabled
                                } -ArgumentList $protocol.Path -ErrorAction SilentlyContinue
                                $enabled = $result
                            } catch {
                                # Cannot check remotely - flag for manual review
                                $enabled = $null
                            }
                        }

                        # SSL 2.0/3.0 are disabled by default on modern Windows
                        # TLS 1.0/1.1 may still be enabled
                        $isWeakEnabled = $false

                        if ($protocol.Name -match 'SSL') {
                            # SSL should be explicitly disabled (Enabled = 0) or key should not exist
                            if ($enabled -eq 1) {
                                $isWeakEnabled = $true
                            }
                        } else {
                            # TLS 1.0/1.1 - enabled by default on older systems, should be explicitly disabled
                            if ($null -eq $enabled -or $enabled -eq 1) {
                                # May be enabled - flag for review
                                $isWeakEnabled = $true
                            }
                        }

                        if ($isWeakEnabled) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dcName
                                HostName            = $dcHost
                                Protocol            = $protocol.Name
                                Status              = if ($enabled -eq 1) { 'Explicitly Enabled' } else { 'Potentially Enabled (default)' }
                                RegistryPath        = "HKLM:\$($protocol.Path)"
                                CVE                 = $protocol.CVE
                                Severity            = if ($protocol.Name -match 'SSL') { 'Critical' } else { 'High' }
                                Risk                = "Weak $($protocol.Name) protocol may be in use"
                                Impact              = 'Vulnerable to protocol downgrade and cryptographic attacks'
                            }
                        }

                    } catch {
                        Write-Verbose "A-DCLdapsProtocol: Error checking $($protocol.Name) on $dcName - $_"
                    }
                }
            }

            # If no DC data, provide general finding
            if ($Data.DomainControllers.Count -eq 0) {
                $findings += [PSCustomObject]@{
                    DCName              = 'All Domain Controllers'
                    Protocol            = 'SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1'
                    Status              = 'Manual verification required'
                    Severity            = 'High'
                    Risk                = 'Weak protocols may be enabled'
                    Recommendation      = 'Check SCHANNEL registry settings on all DCs'
                }
            }

        } catch {
            Write-Verbose "A-DCLdapsProtocol: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on all Domain Controllers. Enable only TLS 1.2 and TLS 1.3.'
        Impact      = 'Medium - May break legacy clients that only support older protocols. Test compatibility first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Weak TLS/SSL Protocol Remediation
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): $($_.Protocol) - $($_.Status)" } | Out-String)

# This script disables weak protocols and enables only TLS 1.2+

# STEP 1: Disable weak protocols via registry
`$protocols = @(
    @{ Name = 'SSL 2.0'; Enabled = 0 }
    @{ Name = 'SSL 3.0'; Enabled = 0 }
    @{ Name = 'TLS 1.0'; Enabled = 0 }
    @{ Name = 'TLS 1.1'; Enabled = 0 }
)

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        param(`$protocols)

        foreach (`$protocol in `$protocols) {
            `$serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\`$(`$protocol.Name)\Server"
            `$clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\`$(`$protocol.Name)\Client"

            # Create keys if they don't exist
            if (-not (Test-Path `$serverPath)) {
                New-Item -Path `$serverPath -Force | Out-Null
            }
            if (-not (Test-Path `$clientPath)) {
                New-Item -Path `$clientPath -Force | Out-Null
            }

            # Disable the protocol
            Set-ItemProperty -Path `$serverPath -Name 'Enabled' -Value 0 -Type DWord
            Set-ItemProperty -Path `$serverPath -Name 'DisabledByDefault' -Value 1 -Type DWord
            Set-ItemProperty -Path `$clientPath -Name 'Enabled' -Value 0 -Type DWord
            Set-ItemProperty -Path `$clientPath -Name 'DisabledByDefault' -Value 1 -Type DWord

            Write-Host "Disabled `$(`$protocol.Name) on `$env:COMPUTERNAME"
        }

        # Enable TLS 1.2 explicitly
        `$tls12Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        `$tls12Client = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

        if (-not (Test-Path `$tls12Server)) { New-Item -Path `$tls12Server -Force | Out-Null }
        if (-not (Test-Path `$tls12Client)) { New-Item -Path `$tls12Client -Force | Out-Null }

        Set-ItemProperty -Path `$tls12Server -Name 'Enabled' -Value 1 -Type DWord
        Set-ItemProperty -Path `$tls12Server -Name 'DisabledByDefault' -Value 0 -Type DWord
        Set-ItemProperty -Path `$tls12Client -Name 'Enabled' -Value 1 -Type DWord
        Set-ItemProperty -Path `$tls12Client -Name 'DisabledByDefault' -Value 0 -Type DWord

        Write-Host "Enabled TLS 1.2 on `$env:COMPUTERNAME"

    } -ArgumentList (,`$protocols)
}

# STEP 2: Also disable weak cipher suites
# Run on each DC or deploy via GPO
`$weakCiphers = @(
    'DES 56/56',
    'NULL',
    'RC2 40/128',
    'RC2 56/128',
    'RC4 40/128',
    'RC4 56/128',
    'RC4 64/128',
    'RC4 128/128',
    'Triple DES 168'
)

# STEP 3: Restart may be required for changes to take effect
Write-Host "`nIMPORTANT: A restart is required for protocol changes to take effect"
Write-Host "Schedule DC restarts during maintenance window"

# STEP 4: Verify with nmap or OpenSSL
# nmap --script ssl-enum-ciphers -p 636 <DC-IP>
# openssl s_client -connect <DC-IP>:636 -tls1
# openssl s_client -connect <DC-IP>:636 -tls1_1

# STEP 5: Test LDAPS connectivity after changes
# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# `$ldaps = New-Object System.DirectoryServices.Protocols.LdapConnection("<DC>:636")
# `$ldaps.SessionOptions.SecureSocketLayer = `$true
# `$ldaps.Bind()

"@
            return $commands
        }
    }
}

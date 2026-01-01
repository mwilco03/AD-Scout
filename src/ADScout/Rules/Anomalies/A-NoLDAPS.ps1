@{
    Id          = 'A-NoLDAPS'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAPS Not Configured'
    Description = 'LDAP over TLS/SSL (LDAPS) is not configured on Domain Controllers. Without LDAPS, credentials and sensitive data transmitted via LDAP are exposed in plaintext on the network.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'LDAPS Configuration'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority' }
        @{ Title = 'LDAP Channel Binding'; Url = 'https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a' }
        @{ Title = 'NIST SC-8 Transmission Confidentiality'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1040', 'T1557')    # Network Sniffing, Adversary-in-the-Middle
    }

    CIS   = @('5.3')
    STIG  = @('V-63583')
    ANSSI = @('vuln1_ldaps')
    NIST  = @('SC-8', 'SC-8(1)', 'SC-23')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            $ldapsConfigured = $false
            $certificateInfo = $null

            try {
                # Check if LDAPS port (636) is listening
                $ldapsPort = 636

                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local check
                    $listener = Get-NetTCPConnection -LocalPort $ldapsPort -State Listen -ErrorAction SilentlyContinue
                    if ($listener) {
                        $ldapsConfigured = $true
                    }

                    # Check for LDAPS certificate
                    $certPath = 'Cert:\LocalMachine\My'
                    $certs = Get-ChildItem -Path $certPath -ErrorAction SilentlyContinue | Where-Object {
                        $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' -and
                        $_.NotAfter -gt (Get-Date)
                    }
                    if ($certs) {
                        $certificateInfo = $certs | Select-Object -First 1 | ForEach-Object {
                            "$($_.Subject) (Expires: $($_.NotAfter.ToString('yyyy-MM-dd')))"
                        }
                    }
                } else {
                    # Remote check via Test-NetConnection
                    try {
                        $test = Test-NetConnection -ComputerName $dc.Name -Port $ldapsPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                        if ($test.TcpTestSucceeded) {
                            $ldapsConfigured = $true
                        }
                    } catch {
                        $ldapsConfigured = $false
                    }
                }

                if (-not $ldapsConfigured) {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dc.Name
                        OperatingSystem     = $dc.OperatingSystem
                        LDAPSPort           = $ldapsPort
                        LDAPSStatus         = 'Not Configured'
                        Certificate         = if ($certificateInfo) { $certificateInfo } else { 'No valid certificate found' }
                        RiskLevel           = 'High'
                        Impact              = 'LDAP traffic transmitted in plaintext'
                        AttackVector        = 'Network sniffing, credential interception, MITM attacks'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController    = $dc.Name
                    OperatingSystem     = $dc.OperatingSystem
                    LDAPSPort           = 636
                    LDAPSStatus         = "Unable to determine: $_"
                    Certificate         = 'Unknown'
                    RiskLevel           = 'Unknown'
                    Impact              = 'Manual verification required'
                    AttackVector        = 'Unknown - check LDAPS configuration'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure LDAPS on all Domain Controllers by installing a valid SSL/TLS certificate and ensuring port 636 is accessible.'
        Impact      = 'Low - LDAPS adds encryption overhead but is essential for security. Clients must be configured to use LDAPS.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Configure LDAPS on Domain Controllers
# DCs without LDAPS: $($Finding.Findings.Count)

# LDAPS requires a valid certificate with:
# - Server Authentication EKU (1.3.6.1.5.5.7.3.1)
# - Subject matching the DC FQDN
# - Valid chain to trusted CA

# Option 1: Use Active Directory Certificate Services (ADCS)
# 1. Install ADCS role on a server
# 2. Configure a Domain Controller certificate template
# 3. Enroll DCs for certificates via autoenrollment

# Option 2: Use third-party CA certificate
# 1. Generate CSR on each DC
# 2. Submit to CA for signing
# 3. Import certificate to Local Computer\Personal store

# Verify LDAPS is working:
`$dc = "$($Finding.Findings[0].DomainController)"

# Test connection
Test-NetConnection -ComputerName `$dc -Port 636

# Test LDAPS bind using PowerShell
`$ldapsUri = "LDAPS://`$dc:636"
try {
    `$connection = [ADSI]`$ldapsUri
    Write-Host "LDAPS connection successful to `$dc"
} catch {
    Write-Host "LDAPS connection failed: `$_"
}

# Alternative: Use ldp.exe
# 1. Open ldp.exe
# 2. Connection > Connect
# 3. Server: DC FQDN, Port: 636, check "SSL"

# Force LDAPS-only (after confirming all clients support it):
# Disable LDAP (port 389) by requiring channel binding
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options
# "Domain controller: LDAP server channel binding token requirements" = Always

# Monitor for plaintext LDAP connections:
# Event ID 2889 in Directory Service log

"@
            return $commands
        }
    }
}

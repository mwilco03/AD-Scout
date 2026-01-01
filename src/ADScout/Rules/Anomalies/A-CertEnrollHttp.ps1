@{
    Id          = 'A-CertEnrollHttp'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Certificate Enrollment via HTTP'
    Description = 'Detects Certificate Authority Web Enrollment endpoints accessible over unencrypted HTTP. This enables NTLM relay attacks (ESC8) where an attacker can coerce authentication and relay it to the CA to obtain certificates as the victim.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC8'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'NTLM Relay to AD CS'; Url = 'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adcs' }
        @{ Title = 'PetitPotam to Domain Admin'; Url = 'https://www.truesec.com/hub/blog/from-strangelove-to-petitpotam-ntlm-relay-to-ad-cs' }
        @{ Title = 'PingCastle Rule A-CertEnrollHttp'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1557.001', 'T1649')  # LLMNR/NBT-NS Poisoning, Steal or Forge Authentication Certificates
    }

    CIS   = @('5.9', '9.2')
    STIG  = @('V-36441')
    ANSSI = @('vuln1_adcs_esc8', 'vuln1_cert_http')
    NIST  = @('SC-8', 'SC-12', 'IA-5')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get configuration naming context
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            # Search for enrollment services
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
            $searcher.Filter = "(objectClass=pKIEnrollmentService)"
            $searcher.PropertiesToLoad.AddRange(@('cn', 'dNSHostName', 'msPKI-Enrollment-Servers', 'certificateTemplates'))

            $enrollmentServices = $searcher.FindAll()

            foreach ($service in $enrollmentServices) {
                $caName = $service.Properties['cn'][0]
                $caHost = $service.Properties['dNSHostName'][0]

                # Check for enrollment server URLs
                $enrollmentServers = $service.Properties['msPKI-Enrollment-Servers']

                if ($enrollmentServers) {
                    foreach ($serverEntry in $enrollmentServers) {
                        # Parse the enrollment server entry (format varies)
                        $serverString = $serverEntry.ToString()

                        # Check for HTTP (not HTTPS) URLs
                        if ($serverString -match 'http://[^\s]+') {
                            $httpUrl = $Matches[0]

                            $findings += [PSCustomObject]@{
                                CAName              = $caName
                                CAHost              = $caHost
                                EnrollmentUrl       = $httpUrl
                                Protocol            = 'HTTP (Unencrypted)'
                                VulnerabilityType   = 'ESC8'
                                Risk                = 'NTLM relay attacks can obtain certificates'
                                AttackScenario      = 'Attacker uses PetitPotam/PrinterBug to coerce DC authentication, relays to HTTP enrollment endpoint'
                                Impact              = 'Complete domain compromise via forged certificate'
                            }
                        }
                    }
                }

                # Also check standard Web Enrollment paths
                $webEnrollmentPaths = @(
                    "http://$caHost/certsrv/",
                    "http://$caHost/CertSrv/",
                    "http://$caHost/certsrv/certfnsh.asp"
                )

                foreach ($path in $webEnrollmentPaths) {
                    # We'll flag these as potential issues - actual HTTP check requires network access
                    # In production, the DLL-based rules would verify actual accessibility
                    $findings += [PSCustomObject]@{
                        CAName              = $caName
                        CAHost              = $caHost
                        EnrollmentUrl       = $path
                        Protocol            = 'HTTP (Potential)'
                        VulnerabilityType   = 'ESC8'
                        Risk                = 'Web enrollment may be accessible over HTTP'
                        AttackScenario      = 'Verify if HTTP enrollment is enabled and accessible'
                        Impact              = 'If accessible, enables NTLM relay to obtain certificates'
                        Note                = 'Verify manually or with network-level check'
                    }
                }
            }

            # Deduplicate findings by URL
            $findings = $findings | Sort-Object EnrollmentUrl -Unique

        } catch {
            Write-Verbose "A-CertEnrollHttp: Error checking enrollment services - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable HTTP access to Certificate Enrollment Web Services. Configure HTTPS-only access with Extended Protection for Authentication (EPA) to prevent NTLM relay.'
        Impact      = 'Low - Clients should use HTTPS enrollment which is more secure.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Certificate Enrollment HTTP Access Remediation (ESC8)
#
# Vulnerable endpoints detected:
$($Finding.Findings | ForEach-Object { "# - $($_.CAName): $($_.EnrollmentUrl)" } | Out-String)

# STEP 1: Disable HTTP on IIS Certificate Enrollment
# On each CA server with Web Enrollment:

# Option A: Require HTTPS in IIS
Import-Module WebAdministration

# Remove HTTP binding from CertSrv site
Get-WebBinding -Name "Default Web Site" |
    Where-Object { `$_.protocol -eq 'http' } |
    Remove-WebBinding

# Or require SSL for the certsrv virtual directory
Set-WebConfiguration -Filter "/system.webServer/security/access" `
    -PSPath "IIS:\Sites\Default Web Site\certsrv" `
    -Value @{sslFlags="Ssl,SslNegotiateCert,Ssl128"}

# STEP 2: Enable Extended Protection for Authentication (EPA)
# This prevents NTLM relay even if HTTPS is compromised

# In IIS Manager:
# 1. Select the CertSrv application
# 2. Open Authentication
# 3. Select Windows Authentication
# 4. Click Advanced Settings
# 5. Set Extended Protection to "Required"

# Via PowerShell:
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\certsrv" `
    -Filter "/system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.tokenChecking" `
    -Value "Require"

Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\certsrv" `
    -Filter "/system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.flags" `
    -Value "AllowDotlessSPN"

# STEP 3: Require HTTPS for NTLM (registry setting)
# On the CA server:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    /v "LdapEnforceChannelBinding" /t REG_DWORD /d 2 /f

# STEP 4: Consider disabling Web Enrollment entirely
# If not needed, remove the role:
# Remove-WindowsFeature ADCS-Web-Enrollment

# STEP 5: Verify remediation
# Test that HTTP access is blocked:
# Invoke-WebRequest -Uri "http://CA-SERVER/certsrv/" -UseDefaultCredentials
# Should fail or redirect to HTTPS

# Test HTTPS with EPA:
# Invoke-WebRequest -Uri "https://CA-SERVER/certsrv/" -UseDefaultCredentials
# Should succeed

"@
            return $commands
        }
    }
}

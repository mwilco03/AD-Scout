@{
    Id          = 'PKI-ESC8-WebEnrollment'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC8 - NTLM Relay to AD CS Web Enrollment'
    Description = 'Detects AD CS Web Enrollment endpoints that may be vulnerable to NTLM relay attacks. Attackers can coerce authentication from a Domain Controller and relay it to the web enrollment endpoint to obtain a certificate for the DC machine account, leading to domain compromise.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC8'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PetitPotam + AD CS'; Url = 'https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/' }
        @{ Title = 'NTLM Relay to AD CS'; Url = 'https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004', 'TA0008')  # Credential Access, Priv Esc, Lateral Movement
        Techniques = @('T1557.001', 'T1649')  # LLMNR/NBT-NS Poisoning and SMB Relay, Steal or Forge Authentication Certificates
    }

    CIS   = @('5.3.7')
    STIG  = @('V-220976')
    ANSSI = @('R71')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $caPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

            $cas = Get-ADObject -SearchBase $caPath -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties * -ErrorAction SilentlyContinue

            foreach ($ca in $cas) {
                $caHost = $ca.dNSHostName
                $caName = $ca.Name

                # Check for web enrollment URLs
                $webEnrollmentUrls = @(
                    "http://$caHost/certsrv/",
                    "https://$caHost/certsrv/"
                )

                # We can't directly test HTTP, but we can flag the potential
                $findings += [PSCustomObject]@{
                    CAName                  = $caName
                    CAHost                  = $caHost
                    DistinguishedName       = $ca.DistinguishedName
                    VulnerabilityType       = 'ESC8 - Web Enrollment NTLM Relay Risk'
                    PotentialEndpoints      = $webEnrollmentUrls -join ', '
                    HTTPEndpoint            = "http://$caHost/certsrv/"
                    HTTPSEndpoint           = "https://$caHost/certsrv/"
                    RiskLevel               = 'Requires Verification'
                    VerificationCommands    = @(
                        "curl -I http://$caHost/certsrv/",
                        "Test-NetConnection -ComputerName $caHost -Port 80",
                        "Test-NetConnection -ComputerName $caHost -Port 443"
                    ) -join '; '
                    AttackScenario          = @(
                        '1. Attacker triggers PetitPotam/PrinterBug against DC',
                        '2. DC authenticates to attacker (NTLM)',
                        '3. Attacker relays to http://CA/certsrv/',
                        "4. CA issues certificate for DC\$ machine account",
                        '5. Attacker uses cert to DCSync domain'
                    ) -join ' -> '
                }
            }
        }
        catch {
            # AD CS may not be installed
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable HTTP on web enrollment, require EPA/channel binding, or disable web enrollment entirely.'
        Impact      = 'Medium - Users/admins using web enrollment will need to use alternative methods'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC8 - NTLM RELAY TO WEB ENROLLMENT
# ================================================================
# This is one of the most dangerous AD CS vulnerabilities.
#
# Attack chain (PetitPotam + ESC8):
# 1. Trigger coerced authentication from DC (PetitPotam, PrinterBug)
# 2. DC sends NTLM auth to attacker's relay server
# 3. Relay to CA web enrollment: http://ca/certsrv/
# 4. Request certificate for DC$@ machine account
# 5. Use certificate to authenticate as DC
# 6. DCSync all hashes from domain
# 7. Full domain compromise

# ================================================================
# POTENTIALLY VULNERABLE ENDPOINTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# CA: $($item.CAName)
# Host: $($item.CAHost)
# HTTP Endpoint: $($item.HTTPEndpoint)
# HTTPS Endpoint: $($item.HTTPSEndpoint)

# Verify if endpoints are accessible:
$($item.VerificationCommands)

"@
            }

            $commands += @"

# ================================================================
# VERIFICATION
# ================================================================

# Check if web enrollment is installed:
# On the CA server, run:
# Get-WindowsFeature ADCS-Web-Enrollment

# Check IIS bindings:
# Import-Module WebAdministration
# Get-WebBinding -Name "Default Web Site"

# Look for HTTP binding (port 80) - this is DANGEROUS

# ================================================================
# REMEDIATION OPTIONS
# ================================================================

# OPTION 1: DISABLE WEB ENROLLMENT (Most Secure)
# If not needed, remove the role:
# Uninstall-WindowsFeature ADCS-Web-Enrollment

# OPTION 2: REQUIRE HTTPS ONLY
# Remove HTTP binding from IIS:
# In IIS Manager:
# 1. Select Default Web Site
# 2. Click Bindings
# 3. Remove the HTTP (port 80) binding
# 4. Ensure only HTTPS (443) remains

# PowerShell:
# Import-Module WebAdministration
# Remove-WebBinding -Name "Default Web Site" -Protocol http

# OPTION 3: ENABLE EPA (Extended Protection for Authentication)
# This prevents NTLM relay by requiring channel binding
#
# In IIS Manager:
# 1. Select the CertSrv application
# 2. Open "Authentication"
# 3. Select "Windows Authentication"
# 4. Click "Advanced Settings"
# 5. Set "Extended Protection" to "Required"

# OPTION 4: REQUIRE KERBEROS ONLY
# Disable NTLM authentication entirely on the web endpoint

# ================================================================
# ADDITIONAL MITIGATIONS
# ================================================================

# 1. Disable PetitPotam coercion:
# - Disable EfsRpc service if not needed
# - Apply Microsoft patch KB5005413

# 2. Protect Domain Controllers:
# - Enable "Network security: Restrict NTLM" policies
# - Block DCs from making outbound NTLM auth

# 3. Enable LDAP signing and channel binding (separate vulnerability)

# ================================================================
# DETECTION
# ================================================================

# Monitor for:
# - Event ID 4768 (TGT request) for machine accounts after cert issuance
# - Event ID 4886/4887 on CA for machine account certificate requests
# - Unusual SMB connections from DCs to non-DC systems

# Certipy can detect vulnerable endpoints:
# certipy find -u user@domain -p password -dc-ip DC_IP -vulnerable

"@
            return $commands
        }
    }
}

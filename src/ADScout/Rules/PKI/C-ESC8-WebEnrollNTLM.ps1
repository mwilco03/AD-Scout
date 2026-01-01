@{
    Id          = 'C-ESC8-WebEnrollNTLM'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC8 - NTLM Relay to AD CS Web Enrollment'
    Description = 'The Certificate Authority Web Enrollment (certsrv) interface is accessible and accepts NTLM authentication. Attackers can relay NTLM authentication from a privileged user to the Web Enrollment endpoint to request a certificate as that user, enabling complete domain compromise.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned ESC8'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PetitPotam to AD CS'; Url = 'https://www.truesec.com/hub/blog/from-petitpotam-to-ad-cs-domain-takeover' }
        @{ Title = 'NTLM Relay'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006', 'TA0008')  # Privilege Escalation, Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1649')  # NTLM Relay, Steal/Forge Certificates
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_adcs_esc8')
    NIST  = @('SI-2')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($ca in $Data) {
            $caName = $ca.Name
            if (-not $caName) { $caName = $ca.'cn' }
            $caHost = $ca.ComputerName
            if (-not $caHost) { $caHost = $ca.dNSHostName }

            $webEnrollmentEnabled = $false
            $ntlmEnabled = $false
            $httpUrl = $null
            $httpsUrl = $null

            # Check if Web Enrollment is installed
            try {
                # Try HTTP
                $httpUrl = "http://$caHost/certsrv/"
                $httpResponse = Invoke-WebRequest -Uri $httpUrl -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue

                if ($httpResponse.StatusCode -eq 200 -or $httpResponse.StatusCode -eq 401) {
                    $webEnrollmentEnabled = $true

                    # Check if NTLM is accepted
                    if ($httpResponse.Headers['WWW-Authenticate']) {
                        $authHeader = $httpResponse.Headers['WWW-Authenticate']
                        if ($authHeader -match 'NTLM|Negotiate') {
                            $ntlmEnabled = $true
                        }
                    }
                }
            } catch {
                # HTTP might be blocked, try HTTPS
            }

            # Try HTTPS
            try {
                $httpsUrl = "https://$caHost/certsrv/"
                # Ignore certificate errors for detection
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                $httpsResponse = Invoke-WebRequest -Uri $httpsUrl -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue

                if ($httpsResponse.StatusCode -eq 200 -or $httpsResponse.StatusCode -eq 401) {
                    $webEnrollmentEnabled = $true

                    if ($httpsResponse.Headers['WWW-Authenticate']) {
                        $authHeader = $httpsResponse.Headers['WWW-Authenticate']
                        if ($authHeader -match 'NTLM|Negotiate') {
                            $ntlmEnabled = $true
                        }
                    }
                }
            } catch {
                # HTTPS also failed or not configured
            }

            # Reset certificate validation
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

            if ($webEnrollmentEnabled -and $ntlmEnabled) {
                $findings += [PSCustomObject]@{
                    CAName              = $caName
                    CAHost              = $caHost
                    WebEnrollmentURL    = if ($httpUrl) { $httpUrl } else { $httpsUrl }
                    HTTPEnabled         = $httpUrl -ne $null
                    HTTPSEnabled        = $httpsUrl -ne $null
                    NTLMAccepted        = $true
                    RiskLevel           = 'Critical'
                    AttackVector        = 'PetitPotam/PrinterBug -> NTLM Relay -> Certificate Request -> Domain Admin'
                    Impact              = 'Domain Controller authentication can be relayed to obtain DC certificate'
                }
            } elseif ($webEnrollmentEnabled) {
                # Web enrollment enabled but couldn't confirm NTLM
                $findings += [PSCustomObject]@{
                    CAName              = $caName
                    CAHost              = $caHost
                    WebEnrollmentURL    = if ($httpUrl) { $httpUrl } else { $httpsUrl }
                    HTTPEnabled         = $httpUrl -ne $null
                    HTTPSEnabled        = $httpsUrl -ne $null
                    NTLMAccepted        = 'Unknown - verify manually'
                    RiskLevel           = 'High'
                    AttackVector        = 'Potential NTLM relay target'
                    Impact              = 'Manual verification required'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable HTTP on Web Enrollment, require EPA (Extended Protection for Authentication) to prevent NTLM relay, or disable Web Enrollment if not needed. Enable HTTPS with certificate authentication.'
        Impact      = 'Medium - Users may need to update how they request certificates. Ensure alternative enrollment methods are available.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix ESC8 - NTLM Relay to AD CS Web Enrollment
# CRITICAL: Domain Controllers can be compromised via relay!
# Vulnerable CAs: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.CAName) on $($_.CAHost): $($_.WebEnrollmentURL)" } | Out-String)

# ATTACK SCENARIO (PetitPotam):
# 1. Attacker triggers DC to authenticate to attacker (PetitPotam, PrinterBug)
# 2. Attacker relays DC$ NTLM auth to CA Web Enrollment
# 3. CA issues certificate for DC$ machine account
# 4. Attacker uses certificate to authenticate as DC
# 5. DCSync -> Domain compromise

# IMMEDIATE MITIGATIONS:

# Option 1: Disable Web Enrollment (if not needed)
# Run on CA server:
# Remove-WindowsFeature ADCS-Web-Enrollment

# Option 2: Enable EPA (Extended Protection for Authentication)
# This prevents NTLM relay attacks
# In IIS Manager:
# 1. Select CertSrv site
# 2. Click Authentication
# 3. Select Windows Authentication -> Advanced Settings
# 4. Set Extended Protection to Required

# Via PowerShell on CA:
# Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name "tokenChecking" -Value "Require" -PSPath "IIS:\Sites\Default Web Site\certsrv"

# Option 3: Disable HTTP, require HTTPS only
# In IIS Manager:
# 1. Select CertSrv site
# 2. Click SSL Settings
# 3. Check "Require SSL"

# Via PowerShell:
# Set-WebConfigurationProperty -Filter "/system.webServer/security/access" -Name "sslFlags" -Value "Ssl" -PSPath "IIS:\Sites\Default Web Site\certsrv"

# Option 4: Disable NTLM, require Kerberos only
# Via IIS Manager or web.config

# VERIFY FIX:
# Test relay with ntlmrelayx (in authorized pentest only):
# ntlmrelayx.py -t http://ca.domain.com/certsrv/certfnsh.asp -smb2support

# ALSO PROTECT AGAINST PETITPOTAM:
# Disable EfsRpcOpenFileRaw RPC
# Apply KB5005413 / Windows security updates
# Disable Print Spooler on DCs (for PrinterBug)

# ALTERNATIVE ENROLLMENT METHODS:
# - Autoenrollment via GPO
# - Certreq.exe command line
# - PowerShell PKI module
# - Smart card enrollment stations

"@
            return $commands
        }
    }
}

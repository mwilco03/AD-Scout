@{
    Id          = 'C-ESC8-WebEnrollment'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC8 - NTLM Relay to AD CS Web Enrollment'
    Description = 'Detects AD CS web enrollment endpoints that may be vulnerable to NTLM relay attacks (ESC8). Attackers can relay machine account authentication to obtain certificates.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC8'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PetitPotam and AD CS'; Url = 'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001')          # LLMNR/NBT-NS Poisoning and SMB Relay
    }

    CIS   = @('5.10')
    STIG  = @('V-36442')
    ANSSI = @('vuln1_adcs_esc8')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($ca in $Data.CertificationAuthorities) {
            # Check for web enrollment enabled
            $webEnrollment = $ca.WebEnrollmentEnabled

            if ($webEnrollment) {
                # Check if HTTPS is enforced
                $httpsEnforced = $ca.WebEnrollmentHttps

                # Check for EPA (Extended Protection for Authentication)
                $epaEnabled = $ca.ExtendedProtection

                $vulnerable = -not $httpsEnforced -or -not $epaEnabled

                if ($vulnerable) {
                    $findings += [PSCustomObject]@{
                        CAName              = $ca.Name
                        CAServer            = $ca.Server
                        WebEnrollmentUrl    = $ca.WebEnrollmentUrl
                        HttpsEnforced       = $httpsEnforced
                        ExtendedProtection  = $epaEnabled
                        Risk                = 'NTLM relay attacks can obtain certificates'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable web enrollment if not required. If required, enforce HTTPS with Extended Protection for Authentication (EPA) and disable NTLM authentication.'
        Impact      = 'Medium - May affect certificate enrollment workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"

# ESC8 - Web enrollment vulnerable to NTLM relay
# Options (in order of preference):

# Option 1: Disable web enrollment if not needed
# Run on CA server:
# Remove-WindowsFeature ADCS-Web-Enrollment

# Option 2: If web enrollment is required, enable EPA
# In IIS Manager:
# 1. Select the CertSrv application
# 2. Open Authentication
# 3. Select Windows Authentication
# 4. Click Advanced Settings
# 5. Set Extended Protection to 'Required'

# Option 3: Enforce HTTPS only
# Remove HTTP binding from CertSrv site in IIS

# Option 4: Disable NTLM
# Configure IIS to use Negotiate:Kerberos only

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# CA: $($item.CAName) on $($item.CAServer)
# URL: $($item.WebEnrollmentUrl)
# Current state - HTTPS: $($item.HttpsEnforced), EPA: $($item.ExtendedProtection)

"@
            }
            return $commands
        }
    }
}

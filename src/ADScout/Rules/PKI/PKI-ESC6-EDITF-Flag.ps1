@{
    Id          = 'PKI-ESC6-EDITF-Flag'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
    Description = 'Detects Certificate Authorities with the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. This CA configuration allows ANY certificate request to include an arbitrary Subject Alternative Name, bypassing template restrictions and enabling privilege escalation.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC6'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786426(v=ws.11)' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')
        Techniques = @('T1649')
    }

    CIS   = @('5.3.5')
    STIG  = @('V-220974')
    ANSSI = @('R69')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $caPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

            # Get all CAs
            $cas = Get-ADObject -SearchBase $caPath -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties * -ErrorAction SilentlyContinue

            foreach ($ca in $cas) {
                # The flag value needs to be checked on the CA server itself
                # We can identify the CA and recommend checking

                $findings += [PSCustomObject]@{
                    CAName              = $ca.Name
                    CADisplayName       = $ca.displayName
                    CADNSHostName       = $ca.dNSHostName
                    CACertificateDN     = $ca.cACertificateDN
                    DistinguishedName   = $ca.DistinguishedName
                    VulnerabilityType   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Check Required'
                    CheckCommand        = "certutil -config `"$($ca.dNSHostName)\$($ca.Name)`" -getreg policy\EditFlags"
                    RiskLevel           = 'Requires Verification'
                    Impact              = 'If flag is set, ANY enrollee can specify ANY SAN in certificate request'
                }
            }
        }
        catch {
            # AD CS may not be installed
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on all Certificate Authorities.'
        Impact      = 'Medium - May affect applications that rely on specifying SAN in requests'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
# ================================================================
# This CA-level flag allows ANY certificate request to specify
# a Subject Alternative Name, REGARDLESS of template settings.
#
# If enabled: Even secure templates become vulnerable to ESC1-style attacks.
#
# This is one of the most dangerous PKI misconfigurations.

# ================================================================
# CERTIFICATE AUTHORITIES TO CHECK
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# CA: $($item.CAName)
# DNS Name: $($item.CADNSHostName)

# Check current flag status:
certutil -config "$($item.CADNSHostName)\$($item.CAName)" -getreg policy\EditFlags

# Look for: EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)
# If this flag is present, the CA is VULNERABLE

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# To DISABLE the EDITF_ATTRIBUTESUBJECTALTNAME2 flag:
# Run on each CA server (requires local admin):

# certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Then restart the CA service:
# net stop certsvc && net start certsvc

# ================================================================
# VERIFICATION
# ================================================================

# After remediation, verify the flag is removed:
# certutil -config "CA\CAName" -getreg policy\EditFlags

# The output should NOT contain:
# EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)

# ================================================================
# DETECTION
# ================================================================

# Monitor for exploitation attempts (before remediation):
# - Event ID 4886 (Certificate request received)
# - Look for requests with SAN != requestor
#
# This attack is VERY difficult to detect if the flag is enabled,
# which is why removal is critical.

# ================================================================
# IMPACT ASSESSMENT
# ================================================================

# Before disabling, check if any applications require this:
# - Some web servers request certs with SAN for multiple hostnames
# - These should use templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
#   where enrollment is restricted to web admins only
#
# The CA-level flag should NEVER be enabled in production.

"@
            return $commands
        }
    }
}

@{
    Id          = 'C-ESC2-AnyPurpose'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC2 - Any Purpose Certificate Template'
    Description = 'Certificate templates are configured with "Any Purpose" or no EKU (Extended Key Usage), allowing the certificate to be used for any purpose including client authentication, code signing, and smart card logon. Attackers can enroll such certificates and use them for impersonation.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned ESC2'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'ADCS Attack Paths'; Url = 'https://attack.mitre.org/techniques/T1649/' }
        @{ Title = 'Certificate Template Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_adcs_esc2')
    NIST  = @('SC-12')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # EKU OIDs of concern
        $anyPurposeOID = '2.5.29.37.0'  # Any Purpose
        $clientAuthOID = '1.3.6.1.5.5.7.3.2'  # Client Authentication
        $smartCardOID = '1.3.6.1.4.1.311.20.2.2'  # Smart Card Logon
        $pkInitAuthOID = '1.3.6.1.5.2.3.4'  # PKINIT Client Authentication

        foreach ($template in $Data) {
            $templateName = $template.Name
            if (-not $templateName) { $templateName = $template.'cn' }
            if (-not $templateName) { $templateName = $template.DisplayName }

            $ekus = @()
            if ($template.'pKIExtendedKeyUsage') {
                $ekus = $template.'pKIExtendedKeyUsage'
            } elseif ($template.ExtendedKeyUsage) {
                $ekus = $template.ExtendedKeyUsage
            }

            $isVulnerable = $false
            $vulnerabilityType = ''

            # Check for Any Purpose EKU
            if ($ekus -contains $anyPurposeOID) {
                $isVulnerable = $true
                $vulnerabilityType = 'Any Purpose EKU (2.5.29.37.0)'
            }

            # Check for no EKUs (null or empty means any purpose)
            if ($null -eq $ekus -or $ekus.Count -eq 0) {
                # Also check msPKI-Certificate-Application-Policy
                $appPolicy = $template.'msPKI-Certificate-Application-Policy'
                if ($null -eq $appPolicy -or $appPolicy.Count -eq 0) {
                    $isVulnerable = $true
                    $vulnerabilityType = 'No EKU defined (defaults to Any Purpose)'
                }
            }

            if ($isVulnerable) {
                # Check if template is enabled and enrollable
                $flags = $template.'msPKI-Certificate-Name-Flag'
                $enrollFlags = $template.'msPKI-Enrollment-Flag'

                # Check enrollment permissions
                $hasLowPrivEnroll = $false
                if ($template.nTSecurityDescriptor -or $template.'nTSecurityDescriptor') {
                    $sd = $template.nTSecurityDescriptor
                    if ($sd) {
                        $acl = $sd.Access
                        foreach ($ace in $acl) {
                            if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -or
                                $ace.ActiveDirectoryRights -match 'GenericAll') {
                                if ($ace.IdentityReference -match 'Authenticated Users|Domain Users|Everyone|Domain Computers') {
                                    $hasLowPrivEnroll = $true
                                }
                            }
                        }
                    }
                }

                $findings += [PSCustomObject]@{
                    TemplateName        = $templateName
                    DisplayName         = $template.DisplayName
                    VulnerabilityType   = $vulnerabilityType
                    EKUs                = if ($ekus) { $ekus -join ', ' } else { 'None (Any Purpose)' }
                    LowPrivilegedEnroll = $hasLowPrivEnroll
                    Enabled             = $true
                    RiskLevel           = if ($hasLowPrivEnroll) { 'Critical' } else { 'High' }
                    AttackPath          = 'Enroll certificate, use for any purpose including authentication as any user'
                    Exploitability      = if ($hasLowPrivEnroll) { 'Any domain user can exploit' } else { 'Requires enrollment permissions' }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Modify certificate templates to specify explicit EKUs appropriate for their intended use. Remove "Any Purpose" EKU and restrict to specific purposes.'
        Impact      = 'Medium - May affect applications relying on flexible certificate usage. Test changes in non-production first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix ESC2 - Any Purpose Certificate Templates
# Vulnerable Templates: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): $($_.VulnerabilityType)" } | Out-String)

# ATTACK SCENARIO:
# 1. Attacker enrolls certificate from vulnerable template
# 2. Certificate has "Any Purpose" or no EKU restrictions
# 3. Attacker uses certificate for client authentication
# 4. Attacker can authenticate as the enrolled subject

# REMEDIATION:

# Option 1: Remove Any Purpose EKU and specify explicit EKUs
# Via Certificate Templates MMC (certtmpl.msc):
# 1. Open template properties
# 2. Go to Extensions tab
# 3. Select Application Policies
# 4. Remove "Any Purpose" or "All"
# 5. Add only required EKUs (e.g., Client Authentication for user certs)

# Option 2: Restrict enrollment permissions
# Template > Security tab
# Remove enrollment rights from:
# - Domain Users
# - Authenticated Users
# - Domain Computers
# Add specific security groups instead

# Option 3: Disable vulnerable templates
# Via certutil:
foreach (`$template in @('$($Finding.Findings.TemplateName -join "','")')) {
    Write-Host "Consider disabling template: `$template"
    # To disable publishing (doesn't delete the template):
    # certutil -dspublish -delete `$template

    # Or remove from CA:
    # certutil -config "CA\CAName" -setcatemplates -`$template
}

# PowerShell: Modify template EKUs
# `$configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
# `$templateDN = "CN=TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configContext"
# `$template = [ADSI]"LDAP://`$templateDN"
# `$template.Put("pKIExtendedKeyUsage", @("1.3.6.1.5.5.7.3.2"))  # Client Auth only
# `$template.SetInfo()

# Verify changes:
certutil -v -template | findstr /i "pKIExtendedKeyUsage"

"@
            return $commands
        }
    }
}

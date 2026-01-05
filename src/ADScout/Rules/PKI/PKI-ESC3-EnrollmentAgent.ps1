@{
    Id          = 'PKI-ESC3-EnrollmentAgent'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC3 - Enrollment Agent Template Abuse'
    Description = 'Detects certificate templates that allow Certificate Request Agent (Enrollment Agent) capabilities with broad enrollment permissions. An attacker can request an enrollment agent certificate, then use it to request certificates on behalf of any user, including Domain Admins.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC3'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'Enrollment Agents'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-enrollment-agent' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')
        Techniques = @('T1649')
    }

    CIS   = @('5.3.3')
    STIG  = @('V-220972')
    ANSSI = @('R67')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Certificate Request Agent OID
        $enrollmentAgentOID = '1.3.6.1.4.1.311.20.2.1'

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

            $templates = Get-ADObject -SearchBase $templatePath -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties * -ErrorAction SilentlyContinue

            $enrollmentAgentTemplates = @()
            $targetTemplates = @()

            foreach ($template in $templates) {
                $ekus = $template.'pKIExtendedKeyUsage'

                # Check for Enrollment Agent capability
                if ($ekus -contains $enrollmentAgentOID) {
                    # Check enrollment permissions
                    $acl = Get-Acl "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                    $enrollees = @()

                    foreach ($ace in $acl.Access) {
                        if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and
                            $ace.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') {
                            $enrollees += $ace.IdentityReference.Value
                        }
                    }

                    $dangerousEnrollees = $enrollees | Where-Object {
                        $_ -match 'Authenticated Users|Domain Users|Domain Computers|Everyone'
                    }

                    if ($dangerousEnrollees) {
                        $enrollmentAgentTemplates += [PSCustomObject]@{
                            TemplateName = $template.Name
                            DisplayName  = $template.DisplayName
                            Enrollees    = ($dangerousEnrollees -join ', ')
                        }
                    }
                }

                # Check for templates that can be used by enrollment agents
                # (templates that allow enrolling on behalf of others)
                $schemaVersion = $template.'msPKI-Template-Schema-Version'
                $raSignatureRequired = $template.'msPKI-RA-Signature'

                # If template requires enrollment agent signature and has Client Auth
                if ($raSignatureRequired -ge 1 -and
                    ($ekus -contains '1.3.6.1.5.5.7.3.2' -or $ekus.Count -eq 0)) {
                    $targetTemplates += [PSCustomObject]@{
                        TemplateName = $template.Name
                        DisplayName  = $template.DisplayName
                    }
                }
            }

            # If we have both enrollment agent templates and target templates, it's exploitable
            if ($enrollmentAgentTemplates.Count -gt 0) {
                foreach ($eaTemplate in $enrollmentAgentTemplates) {
                    $findings += [PSCustomObject]@{
                        TemplateName             = $eaTemplate.TemplateName
                        DisplayName              = $eaTemplate.DisplayName
                        VulnerabilityType        = 'ESC3 - Enrollment Agent Template'
                        DangerousEnrollees       = $eaTemplate.Enrollees
                        TargetTemplatesAvailable = $targetTemplates.Count
                        RiskLevel                = 'Critical'
                        ExploitPath              = @(
                            '1. Attacker enrolls in Enrollment Agent template',
                            '2. Uses EA cert to request certs for other users',
                            '3. Requests Client Auth cert as Domain Admin',
                            '4. Authenticates as Domain Admin'
                        ) -join ' -> '
                    }
                }
            }
        }
        catch {
            # AD CS may not be installed
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict enrollment agent template access to specific trusted users. Implement enrollment agent restrictions on the CA.'
        Impact      = 'Medium - Legitimate enrollment agent workflows may be affected'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC3 - ENROLLMENT AGENT ABUSE
# ================================================================
# Enrollment Agents can request certificates ON BEHALF of other users.
# If untrusted users can become Enrollment Agents, they can
# request certificates as any user, including Domain Admins.

# Attack chain:
# 1. Get Enrollment Agent certificate
# 2. Use EA cert to request Client Auth cert for DA
# 3. Authenticate as Domain Admin using the certificate

# ================================================================
# VULNERABLE TEMPLATES
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Dangerous Enrollees: $($item.DangerousEnrollees)
# Target Templates Available: $($item.TargetTemplatesAvailable)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# STEP 1: RESTRICT ENROLLMENT AGENT TEMPLATE ACCESS
# Only specific trusted users (like PKI admins) should have access

# In certtmpl.msc:
# 1. Find the Enrollment Agent template
# 2. Security tab > Remove "Domain Users" / "Authenticated Users"
# 3. Add only specific trusted security group

# STEP 2: IMPLEMENT ENROLLMENT AGENT RESTRICTIONS
# On the CA, restrict which users enrollment agents can enroll for

# In certsrv.msc (on the CA):
# 1. Right-click CA > Properties
# 2. Go to "Enrollment Agents" tab
# 3. Add restrictions:
#    - Specific enrollment agents
#    - Specific templates they can use
#    - Specific users they can enroll for

# PowerShell (PSPKI module):
# Get-CertificationAuthority | Get-EnrollmentAgentRestriction

# STEP 3: MONITOR ENROLLMENT AGENT USAGE
# Event ID 4886/4887 on CA - watch for suspicious enrollments

# ================================================================
# ALTERNATIVE: DISABLE TEMPLATE
# ================================================================

# If Enrollment Agent functionality is not needed:
# Unpublish the template from all CAs

# Get-CertificationAuthority | Get-CATemplate |
#     Where-Object { `$_.Name -eq "EnrollmentAgent" } |
#     Remove-CATemplate

"@
            return $commands
        }
    }
}

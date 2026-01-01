@{
    Id          = 'A-CertTempNoSecurity'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Certificate Template Without Security Controls'
    Description = 'Detects certificate templates that lack essential security controls such as manager approval, authorized signatures, or proper enrollment restrictions. These templates can be abused for privilege escalation or persistence.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Certified Pre-Owned'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'AD CS Template Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts' }
        @{ Title = 'PingCastle Rule A-CertTempNoSecurity'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1649', 'T1098.001')  # Steal or Forge Authentication Certificates, Additional Cloud Credentials
    }

    CIS   = @('5.9')
    STIG  = @('V-36441')
    ANSSI = @('vuln1_adcs_template_security')
    NIST  = @('SC-12', 'IA-5')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 5
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # msPKI-Enrollment-Flag values
        $CT_FLAG_PEND_ALL_REQUESTS = 0x00000002          # Manager approval required
        $CT_FLAG_PUBLISH_TO_DS = 0x00000008              # Publish to DS
        $CT_FLAG_AUTO_ENROLLMENT = 0x00000020           # Auto-enrollment
        $CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040

        # msPKI-Certificate-Name-Flag values
        $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001  # Enrollee can specify subject

        # msPKI-RA-Signature value for requiring authorized signatures
        # 0 = no signatures required

        try {
            # Get certificate templates from AD
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $searcher.Filter = "(objectClass=pKICertificateTemplate)"
            $searcher.PropertiesToLoad.AddRange(@(
                'cn', 'displayName', 'msPKI-Enrollment-Flag', 'msPKI-Certificate-Name-Flag',
                'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Template-Schema-Version',
                'nTSecurityDescriptor', 'flags'
            ))

            $templates = $searcher.FindAll()

            foreach ($template in $templates) {
                $templateName = $template.Properties['cn'][0]
                $displayName = if ($template.Properties['displayName']) { $template.Properties['displayName'][0] } else { $templateName }
                $enrollmentFlag = if ($template.Properties['mspki-enrollment-flag']) { [int]$template.Properties['mspki-enrollment-flag'][0] } else { 0 }
                $nameFlag = if ($template.Properties['mspki-certificate-name-flag']) { [int]$template.Properties['mspki-certificate-name-flag'][0] } else { 0 }
                $raSignature = if ($template.Properties['mspki-ra-signature']) { [int]$template.Properties['mspki-ra-signature'][0] } else { 0 }
                $ekus = $template.Properties['pkiextendedkeyusage']

                # Check for authentication EKUs
                $authenticationEKUs = @(
                    '1.3.6.1.5.5.7.3.2',      # Client Authentication
                    '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
                    '1.3.6.1.5.2.3.4',        # PKINIT Client Authentication
                    '2.5.29.37.0'             # Any Purpose
                )

                $hasAuthEKU = $false
                foreach ($eku in $ekus) {
                    if ($eku -in $authenticationEKUs) {
                        $hasAuthEKU = $true
                        break
                    }
                }

                # Skip templates without authentication EKUs (less critical)
                if (-not $hasAuthEKU -and $ekus.Count -gt 0) {
                    continue
                }

                $securityIssues = @()

                # Check for missing manager approval on templates with client auth
                if ($hasAuthEKU -and -not ($enrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS)) {
                    $securityIssues += "No manager approval required"
                }

                # Check for no authorized signatures required
                if ($raSignature -eq 0) {
                    $securityIssues += "No authorized signatures required"
                }

                # Check for enrollee-supplied subject without manager approval
                if (($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -and
                    -not ($enrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS)) {
                    $securityIssues += "Enrollee supplies subject without approval"
                }

                # Check for auto-enrollment enabled on sensitive templates
                if ($hasAuthEKU -and ($enrollmentFlag -band $CT_FLAG_AUTO_ENROLLMENT)) {
                    $securityIssues += "Auto-enrollment enabled for authentication template"
                }

                # Report if multiple security issues found
                if ($securityIssues.Count -ge 2) {
                    $findings += [PSCustomObject]@{
                        TemplateName        = $templateName
                        DisplayName         = $displayName
                        SecurityIssues      = ($securityIssues -join '; ')
                        IssueCount          = $securityIssues.Count
                        ManagerApproval     = [bool]($enrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS)
                        AuthorizedSignatures = $raSignature
                        SuppliesSubject     = [bool]($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
                        AutoEnrollment      = [bool]($enrollmentFlag -band $CT_FLAG_AUTO_ENROLLMENT)
                        HasAuthEKU          = $hasAuthEKU
                        Risk                = 'Template lacks security controls'
                        Recommendation      = 'Enable manager approval and/or require authorized signatures'
                    }
                }
            }
        } catch {
            Write-Verbose "A-CertTempNoSecurity: Error checking templates - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable manager approval and/or require authorized signatures for certificate templates. For sensitive templates, disable auto-enrollment and require enrollment agent certificates.'
        Impact      = 'Medium - May affect automated certificate enrollment processes.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Certificate Template Security Remediation
#
# Templates with insufficient security controls:
$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): $($_.SecurityIssues)" } | Out-String)

# OPTION 1: Enable Manager Approval (Recommended for sensitive templates)
# This requires CA manager to approve each certificate request

$($Finding.Findings | ForEach-Object { @"
# Template: $($_.TemplateName)
certutil -dstemplate "$($_.TemplateName)" msPKI-Enrollment-Flag +CT_FLAG_PEND_ALL_REQUESTS

"@ })

# OPTION 2: Require Authorized Signatures
# This requires requests to be signed by an enrollment agent

$($Finding.Findings | ForEach-Object { @"
# Template: $($_.TemplateName) - Require 1 signature
certutil -dstemplate "$($_.TemplateName)" msPKI-RA-Signature 1

"@ })

# OPTION 3: Disable Auto-Enrollment for authentication templates
$($Finding.Findings | Where-Object { $_.AutoEnrollment } | ForEach-Object { @"
# Template: $($_.TemplateName) - Disable auto-enrollment
certutil -dstemplate "$($_.TemplateName)" msPKI-Enrollment-Flag -CT_FLAG_AUTO_ENROLLMENT

"@ })

# OPTION 4: Remove enrollee-supplied subject if not needed
$($Finding.Findings | Where-Object { $_.SuppliesSubject } | ForEach-Object { @"
# Template: $($_.TemplateName) - Remove 'Supply in Request' flag
certutil -dstemplate "$($_.TemplateName)" msPKI-Certificate-Name-Flag -CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

"@ })

# View template configuration:
# certutil -dstemplate "TemplateName"

# List all templates and their flags:
# Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
#     -Filter {objectClass -eq 'pKICertificateTemplate'} `
#     -Properties * | Select-Object Name, msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag, msPKI-RA-Signature

"@
            return $commands
        }
    }
}

@{
    Id          = 'C-ESC1-VulnerableTemplate'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC1 - Vulnerable Certificate Template'
    Description = 'Detects certificate templates vulnerable to ESC1: low-privileged users can enroll and specify arbitrary SANs, enabling domain privilege escalation.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Certified Pre-Owned'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'AD CS Domain Escalation'; Url = 'https://www.thehacker.recipes/ad/movement/ad-cs' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1649')              # Steal or Forge Authentication Certificates
    }

    CIS   = @('5.9')
    STIG  = @('V-36441')
    ANSSI = @('vuln1_adcs_esc1')
    NIST  = @('SC-12')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($template in $Data.Templates) {
            # ESC1 conditions:
            # 1. Client Authentication or Smart Card Logon EKU
            # 2. ENROLLEE_SUPPLIES_SUBJECT flag set
            # 3. Low-privileged users can enroll

            $hasClientAuth = $false
            $allowsSAN = $false
            $lowPrivEnroll = $false

            # Check EKUs
            $clientAuthOids = @(
                '1.3.6.1.5.5.7.3.2',      # Client Authentication
                '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
                '1.3.6.1.5.2.3.4',        # PKINIT Client Authentication
                '2.5.29.37.0'             # Any Purpose
            )

            foreach ($eku in $template.ExtendedKeyUsage) {
                if ($eku -in $clientAuthOids -or $template.ExtendedKeyUsage.Count -eq 0) {
                    $hasClientAuth = $true
                    break
                }
            }

            # Check ENROLLEE_SUPPLIES_SUBJECT (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001)
            if ($template.msPKI-Certificate-Name-Flag -band 0x00000001) {
                $allowsSAN = $true
            }

            # Check enrollment permissions for low-privileged principals
            $lowPrivGroups = @('Domain Users', 'Authenticated Users', 'Everyone', 'Domain Computers')
            foreach ($ace in $template.ACL) {
                if ($ace.Rights -match 'Enroll' -and $ace.IdentityReference -match ($lowPrivGroups -join '|')) {
                    $lowPrivEnroll = $true
                    break
                }
            }

            if ($hasClientAuth -and $allowsSAN -and $lowPrivEnroll) {
                $findings += [PSCustomObject]@{
                    TemplateName       = $template.Name
                    DisplayName        = $template.DisplayName
                    VulnerabilityType  = 'ESC1'
                    AllowsSAN          = $true
                    ClientAuthEnabled  = $true
                    EnrollmentAccess   = 'Low-privileged users'
                    Risk               = 'Any user can request certificate as any other user'
                    DistinguishedName  = $template.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment to privileged users only. Enable Manager Approval for sensitive templates.'
        Impact      = 'Medium - May affect legitimate certificate requests'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ESC1 Vulnerable templates detected
# These templates allow any user to request certificates as any other user

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Option 1: Remove 'Supply in Request' flag
certutil -dstemplate "$($item.TemplateName)" msPKI-Certificate-Name-Flag -CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

# Option 2: Restrict enrollment permissions
# Remove 'Domain Users' and 'Authenticated Users' enrollment rights via certtmpl.msc

# Option 3: Enable Manager Approval
certutil -dstemplate "$($item.TemplateName)" msPKI-Enrollment-Flag +CT_FLAG_PEND_ALL_REQUESTS

"@
            }
            return $commands
        }
    }
}

@{
    Id          = 'C-ESC3-RequestAgent'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC3 - Certificate Request Agent Misconfiguration'
    Description = 'Certificate templates allow enrollment of Certificate Request Agent (Enrollment Agent) certificates by low-privileged users. An attacker with this certificate can request certificates on behalf of any other user, enabling complete domain compromise.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned ESC3'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'Enrollment Agent Attack'; Url = 'https://attack.mitre.org/techniques/T1649/' }
        @{ Title = 'Certificate Request Agent'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-enrollment-agents' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006', 'TA0003')  # Privilege Escalation, Credential Access, Persistence
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_adcs_esc3')
    NIST  = @('SC-12')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Certificate Request Agent EKU OID
        $certRequestAgentOID = '1.3.6.1.4.1.311.20.2.1'

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

            # Check if template has Certificate Request Agent EKU
            $hasCertRequestAgent = $ekus -contains $certRequestAgentOID

            if ($hasCertRequestAgent) {
                # Check enrollment permissions for low-privileged users
                $hasLowPrivEnroll = $false
                $enrollableBy = @()

                if ($template.nTSecurityDescriptor) {
                    $sd = $template.nTSecurityDescriptor
                    $acl = $sd.Access

                    foreach ($ace in $acl) {
                        $isEnrollRight = $ace.ActiveDirectoryRights -match 'ExtendedRight' -or
                                         $ace.ActiveDirectoryRights -match 'GenericAll'
                        $isAllow = $ace.AccessControlType -eq 'Allow'

                        if ($isEnrollRight -and $isAllow) {
                            $identity = $ace.IdentityReference.Value

                            if ($identity -match 'Authenticated Users|Domain Users|Everyone|Domain Computers|Users') {
                                $hasLowPrivEnroll = $true
                                $enrollableBy += $identity
                            }
                        }
                    }
                }

                if ($hasLowPrivEnroll) {
                    $findings += [PSCustomObject]@{
                        TemplateName        = $templateName
                        DisplayName         = $template.DisplayName
                        VulnerabilityType   = 'ESC3 - Certificate Request Agent'
                        EKU                 = 'Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)'
                        EnrollableBy        = ($enrollableBy | Select-Object -Unique) -join ', '
                        RiskLevel           = 'Critical'
                        AttackPath          = '1. Enroll Certificate Request Agent cert, 2. Use to request certs for ANY user, 3. Authenticate as Domain Admin'
                        ImpactScope         = 'Full domain compromise possible'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict enrollment permissions on Certificate Request Agent templates to only authorized enrollment agents. Consider using Enrollment Agent Restrictions on the CA.'
        Impact      = 'Low - Only affects ability to enroll enrollment agent certificates. Legitimate enrollment agents should be specifically authorized.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix ESC3 - Certificate Request Agent Misconfiguration
# CRITICAL: These templates allow domain takeover!
# Vulnerable Templates: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): Enrollable by $($_.EnrollableBy)" } | Out-String)

# ATTACK SCENARIO:
# 1. Attacker enrolls Certificate Request Agent certificate
# 2. Uses this cert to request a certificate for Domain Admin
# 3. Authenticates as Domain Admin using the new certificate
# 4. Complete domain compromise

# IMMEDIATE REMEDIATION:

# Step 1: Remove low-privileged enrollment permissions
# Via Certificate Templates MMC (certtmpl.msc):
# 1. Right-click template > Properties
# 2. Security tab
# 3. Remove Enroll/Autoenroll for:
#    - Domain Users
#    - Authenticated Users
#    - Domain Computers
#    - Everyone

# Step 2: Configure Enrollment Agent Restrictions on CA
# Via Certification Authority MMC (certsrv.msc):
# 1. Right-click CA > Properties
# 2. Enrollment Agents tab
# 3. Enable "Restrict enrollment agents"
# 4. Specify which agents can enroll which templates for which users

# Step 3: Alternatively, disable vulnerable templates entirely
foreach (`$template in @('$($Finding.Findings.TemplateName -join "','")')) {
    Write-Host "Disabling vulnerable template: `$template"

    # Remove from CA issuance
    # certutil -config "CA\CAName" -setcatemplates -`$template

    # Or unpublish from AD
    # certutil -dspublish -delete `$template
}

# Step 4: Create a new secure Enrollment Agent template
# - Limit enrollment to specific security group (e.g., "Enrollment Agents")
# - Enable "CA certificate manager approval"
# - Set short validity period (1 day if possible)

# Step 5: Audit existing Enrollment Agent certificates
certutil -store my | findstr /i "Certificate Request Agent"

# Step 6: Review and revoke suspicious certificates
# certutil -revoke <serial_number> 0

# VERIFY FIX:
# Check template permissions
certutil -v -template `$templateName | findstr /i "Allow Enroll"

"@
            return $commands
        }
    }
}

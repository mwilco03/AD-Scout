@{
    Id          = 'PKI-ESC1-SubjectAltName'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC1 - Certificate Template Allows Requestor-Supplied Subject'
    Description = 'Detects certificate templates where enrollees can supply their own Subject Alternative Name (SAN). This allows any user with enrollment rights to request a certificate for any other user, including Domain Admins, enabling immediate privilege escalation.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'AD CS Attack Paths'; Url = 'https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services/' }
        @{ Title = 'MITRE ATT&CK'; Url = 'https://attack.mitre.org/techniques/T1649/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @('5.3.1')
    STIG  = @('V-220970')
    ANSSI = @('R65')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get the configuration naming context
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

            # Get all certificate templates
            $templates = Get-ADObject -SearchBase $templatePath -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties * -ErrorAction SilentlyContinue

            foreach ($template in $templates) {
                # Check msPKI-Certificate-Name-Flag for CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1)
                $nameFlag = $template.'msPKI-Certificate-Name-Flag'
                $enrolleeSuppliesSubject = ($nameFlag -band 1) -eq 1

                if (-not $enrolleeSuppliesSubject) { continue }

                # Check if template is enabled (has at least one CA that can issue it)
                # Check enrollment permissions
                $acl = Get-Acl "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                $enrollmentRights = @()

                foreach ($ace in $acl.Access) {
                    # Extended Right for Enroll or AutoEnroll
                    if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and
                        ($ace.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' -or  # Enroll
                         $ace.ObjectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')) {  # AutoEnroll
                        $enrollmentRights += [PSCustomObject]@{
                            Principal = $ace.IdentityReference.Value
                            Right     = if ($ace.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') { 'Enroll' } else { 'AutoEnroll' }
                        }
                    }
                }

                # Check for dangerous enrollees (Authenticated Users, Domain Users, Domain Computers)
                $dangerousEnrollees = $enrollmentRights | Where-Object {
                    $_.Principal -match 'Authenticated Users|Domain Users|Domain Computers|Everyone|Users'
                }

                # Check for Client Authentication EKU
                $ekus = $template.'pKIExtendedKeyUsage'
                $hasClientAuth = $ekus -contains '1.3.6.1.5.5.7.3.2' -or  # Client Authentication
                                 $ekus -contains '1.3.6.1.5.2.3.4' -or   # PKINIT Client Authentication
                                 $ekus -contains '1.3.6.1.4.1.311.20.2.2' -or  # Smart Card Logon
                                 $ekus -eq $null -or $ekus.Count -eq 0  # Any Purpose

                if ($dangerousEnrollees -and $hasClientAuth) {
                    $findings += [PSCustomObject]@{
                        TemplateName        = $template.Name
                        DisplayName         = $template.DisplayName
                        DistinguishedName   = $template.DistinguishedName
                        VulnerabilityType   = 'ESC1 - Enrollee Supplies Subject'
                        EnrolleeSuppliesSAN = $true
                        ClientAuthEKU       = $hasClientAuth
                        DangerousEnrollees  = ($dangerousEnrollees.Principal -join ', ')
                        AllEnrollees        = ($enrollmentRights.Principal -join ', ')
                        RiskLevel           = 'Critical'
                        ExploitPath         = 'Any enrollee can request certificate as Domain Admin'
                        Impact              = 'Immediate domain compromise via certificate-based authentication'
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
        Description = 'Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment to trusted principals only.'
        Impact      = 'Medium - May affect legitimate certificate enrollment workflows'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC1 - ENROLLEE SUPPLIES SUBJECT VULNERABILITY
# ================================================================
# This is a CRITICAL vulnerability. Any user who can enroll
# can request a certificate for ANY other user, including
# Domain Admins.
#
# Attack: Attacker requests cert with SAN=administrator@domain.com
#         Uses cert to authenticate as Domain Admin
#         Game over.

# ================================================================
# VULNERABLE TEMPLATES DETECTED
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Display Name: $($item.DisplayName)
# Dangerous Enrollees: $($item.DangerousEnrollees)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION OPTIONS
# ================================================================

# OPTION 1: DISABLE ENROLLEE SUPPLIES SUBJECT (Recommended)
# This requires using Certificate Manager to modify the template

# Open Certificate Templates MMC:
# certtmpl.msc

# For each vulnerable template:
# 1. Right-click > Properties
# 2. Go to "Subject Name" tab
# 3. Select "Build from this Active Directory information"
# 4. This removes the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag

# PowerShell method (requires PSPKI module):
# Install-Module -Name PSPKI
# Import-Module PSPKI
#
# `$template = Get-CertificateTemplate -Name "VulnerableTemplate"
# `$template | Get-CertificateTemplateAcl | Remove-CertificateTemplateAcl -Identity "Domain Users" -AccessType Allow
# OR
# Set-CertificateTemplate -Name "VulnerableTemplate" -SubjectNameFlag "BuildFromAD"

# ================================================================
# OPTION 2: RESTRICT ENROLLMENT PERMISSIONS
# ================================================================

# Remove dangerous principals from enrollment:

`$templateDN = "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"

# View current permissions:
(Get-Acl "AD:`$templateDN").Access |
    Where-Object { `$_.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' } |
    Select-Object IdentityReference, AccessControlType

# Remove Domain Users enrollment right:
# `$acl = Get-Acl "AD:`$templateDN"
# `$acl.RemoveAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
#     ([System.Security.Principal.NTAccount]"Domain Users"), `
#     "ExtendedRight", "Allow", [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"))
# Set-Acl "AD:`$templateDN" `$acl

# ================================================================
# OPTION 3: REQUIRE MANAGER APPROVAL
# ================================================================

# For templates that MUST allow enrollee-supplied subjects:
# 1. Enable "CA certificate manager approval"
# 2. This adds a human review step before issuance

# In certtmpl.msc:
# Template > Properties > Issuance Requirements
# Check "CA certificate manager approval"

# ================================================================
# DETECTION
# ================================================================

# Monitor for exploitation attempts:
# - Event ID 4886 (Certificate Services received certificate request)
# - Event ID 4887 (Certificate Services approved certificate request)
# Look for requests where Subject != Requestor

# Certipy audit (external tool):
# certipy find -u user@domain -p password -dc-ip DC_IP -vulnerable

"@
            return $commands
        }
    }
}

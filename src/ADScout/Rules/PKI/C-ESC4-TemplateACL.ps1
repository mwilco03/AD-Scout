<#
.SYNOPSIS
    Detects ESC4 - Vulnerable certificate template ACLs.

.DESCRIPTION
    Identifies certificate templates with dangerous ACLs where non-privileged users have
    WriteDACL, WriteOwner, or WriteProperty rights. This allows attackers to modify
    template settings to enable ESC1-style attacks.

.NOTES
    Rule ID    : C-ESC4-TemplateACL
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC4-TemplateACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC4 - Vulnerable Certificate Template ACLs'
    Description = 'Identifies certificate templates with dangerous ACLs allowing non-privileged users to modify template settings. Attackers can reconfigure templates to enable privilege escalation.'
    Severity    = 'Critical'
    Weight      = 75
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC4'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'ADCS Attack Paths - ESC4'; Url = 'https://www.yourwaf.com/2023/12/certified-pre-owned-esc4.html' }
        @{ Title = 'Certipy - ADCS Exploitation'; Url = 'https://github.com/ly4k/Certipy' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1649', 'T1222.001')  # Steal or Forge Authentication Certificates, File and Directory Permissions Modification
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_adcs_esc4')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous rights that allow template modification
        $dangerousRights = @(
            'WriteDacl'
            'WriteOwner'
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
        )

        # Legitimate principals that should have template modification rights
        $legitimatePrincipals = @(
            'Enterprise Admins'
            'Domain Admins'
            'Administrators'
            'SYSTEM'
            'Cert Publishers'
            'Certificate Service DCOM Access'
        )

        # Legitimate SIDs
        $legitimateSIDs = @(
            'S-1-5-32-544'      # Administrators
            'S-1-5-18'          # SYSTEM
            'S-1-5-9'           # Enterprise DCs
        )

        if ($Data.CertificateTemplates) {
            foreach ($template in $Data.CertificateTemplates) {
                $templateName = $template.Name
                if (-not $templateName) { $templateName = $template.DisplayName }
                if (-not $templateName) { continue }

                $acl = $template.ACL
                if (-not $acl) { continue }

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    $identity = $ace.IdentityReference.Value
                    $rights = $ace.ActiveDirectoryRights.ToString()

                    # Check if this ACE grants dangerous rights
                    $hasDangerousRights = $false
                    $grantedDangerousRights = @()

                    foreach ($dangerousRight in $dangerousRights) {
                        if ($rights -match $dangerousRight) {
                            $hasDangerousRights = $true
                            $grantedDangerousRights += $dangerousRight
                        }
                    }

                    if (-not $hasDangerousRights) { continue }

                    # Check if principal is legitimate
                    $isLegitimate = $false

                    foreach ($legitPrincipal in $legitimatePrincipals) {
                        if ($identity -like "*\$legitPrincipal" -or $identity -eq $legitPrincipal -or $identity -like "*$legitPrincipal*") {
                            $isLegitimate = $true
                            break
                        }
                    }

                    # Check by SID
                    if (-not $isLegitimate) {
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                            foreach ($legitSID in $legitimateSIDs) {
                                if ($sid -eq $legitSID -or $sid -like "$legitSID*") {
                                    $isLegitimate = $true
                                    break
                                }
                            }

                            # Check for domain-relative privileged SIDs
                            if ($sid -match '-512$' -or $sid -match '-519$') {
                                $isLegitimate = $true
                            }
                        } catch {
                            # If we can't resolve, flag for review
                        }
                    }

                    if (-not $isLegitimate) {
                        $findings += [PSCustomObject]@{
                            TemplateName        = $templateName
                            Principal           = $identity
                            DangerousRights     = ($grantedDangerousRights -join ', ')
                            AllRights           = $rights
                            Inherited           = $ace.IsInherited
                            CanEnableESC1       = 'Yes - Can modify template to allow SAN specification'
                            AttackPath          = 'Modify template settings then request certificate as any user'
                            RiskLevel           = 'Critical'
                            DistinguishedName   = $template.DistinguishedName
                        }
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove dangerous ACL entries from certificate templates. Only Enterprise Admins and Cert Publishers should have modify rights.'
        Impact      = 'Medium - May affect delegated certificate administration workflows.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC4 - Certificate Template ACL Vulnerabilities
#############################################################################
#
# Vulnerable templates allow non-privileged users to modify template settings.
# An attacker can:
# 1. Modify template to enable ENROLLEE_SUPPLIES_SUBJECT
# 2. Enable Client Authentication EKU
# 3. Request certificate as any user (Domain Admin, etc.)
# 4. Authenticate using the forged certificate
#
#############################################################################

# Affected Templates:
$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): $($_.Principal) has $($_.DangerousRights)" } | Out-String)

# View current template ACLs
Import-Module PSPKI -ErrorAction SilentlyContinue

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

#############################################################################
# Template: $($item.TemplateName)
# Dangerous Principal: $($item.Principal)
# Rights: $($item.DangerousRights)
#############################################################################

# Using PSPKI module:
`$template = Get-CertificateTemplate -Name '$($item.TemplateName)'
`$template | Get-CertificateTemplateAcl | Format-List

# Remove the dangerous ACE:
# `$template | Get-CertificateTemplateAcl |
#     Remove-CertificateTemplateAcl -Identity '$($item.Principal)' -Confirm:`$false

# Using ADSI:
`$configNC = (Get-ADRootDSE).configurationNamingContext
`$templateDN = "CN=$($item.TemplateName),CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"
`$templateObj = [ADSI]"LDAP://`$templateDN"
`$acl = `$templateObj.ObjectSecurity

# Find and remove the ACE
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)'
}
foreach (`$ace in `$aceToRemove) {
    `$acl.RemoveAccessRule(`$ace)
}
`$templateObj.ObjectSecurity = `$acl
`$templateObj.CommitChanges()

"@
            }

            $commands += @"

#############################################################################
# Best Practices for Template ACLs
#############################################################################

# 1. Only these groups should have modify rights:
#    - Enterprise Admins
#    - Domain Admins (optional)
#    - Cert Publishers (for specific scenarios)
#
# 2. Enroll rights should be limited to:
#    - Specific security groups
#    - NOT Domain Users, Authenticated Users, or Everyone
#
# 3. Use Manager Approval for sensitive templates
#
# 4. Enable auditing on certificate template changes:
#    - Event ID 4899: Certificate Services template was updated

# Audit all template ACLs:
Get-CertificateTemplate | ForEach-Object {
    Write-Host "Template: `$(`$_.Name)" -ForegroundColor Cyan
    `$_ | Get-CertificateTemplateAcl | Where-Object {
        `$_.Rights -match 'WriteDacl|WriteOwner|GenericAll|GenericWrite'
    } | Format-Table IdentityReference, Rights, AccessControlType
}

"@
            return $commands
        }
    }
}

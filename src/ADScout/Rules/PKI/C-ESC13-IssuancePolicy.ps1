<#
.SYNOPSIS
    Detects ADCS ESC13 - Issuance Policy OID Group Link abuse.

.DESCRIPTION
    ESC13 exploits issuance policy OIDs linked to AD groups. When a certificate
    template has an issuance policy that is linked to a group, users with that
    certificate effectively become members of that group.

.NOTES
    Rule ID    : C-ESC13-IssuancePolicy
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC13-IssuancePolicy'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ADCS ESC13 - Issuance Policy Group Link'
    Description = 'Identifies certificate templates with issuance policies linked to AD groups, enabling privilege escalation through certificate enrollment.'
    Severity    = 'High'
    Weight      = 60
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'ESC13 - Issuance Policy Group Link'; Url = 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53' }
        @{ Title = 'Certipy ESC13'; Url = 'https://github.com/ly4k/Certipy' }
        @{ Title = 'Issuance Policies'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-a--security-groups-and-access-control-lists' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1649', 'T1078.002')  # Steal or Forge Authentication Certificates, Domain Accounts
    }

    CIS   = @('5.2.5')
    STIG  = @('V-254445')
    ANSSI = @('vuln1_adcs_esc13')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $configNC = "CN=Configuration,$((Get-ADDomain).DistinguishedName)"

        # Get all OID objects (issuance policies)
        try {
            $oids = Get-ADObject -Filter { objectClass -eq 'msPKI-Enterprise-Oid' } `
                -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$configNC" `
                -Properties * -ErrorAction SilentlyContinue

            # Find OIDs with group links (msDS-OIDToGroupLink)
            $linkedOIDs = $oids | Where-Object { $_.'msDS-OIDToGroupLink' }

            foreach ($oid in $linkedOIDs) {
                $linkedGroup = $oid.'msDS-OIDToGroupLink'
                $oidValue = $oid.'msPKI-Cert-Template-OID'

                # Get the linked group details
                try {
                    $group = Get-ADGroup -Identity $linkedGroup -Properties * -ErrorAction SilentlyContinue
                    $groupName = $group.Name

                    # Check if linked group is privileged
                    $privilegedGroups = @(
                        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
                        'Administrators', 'Account Operators', 'Server Operators',
                        'Backup Operators', 'Print Operators', 'DnsAdmins'
                    )

                    $isPrivilegedGroup = $privilegedGroups -contains $groupName

                    # Find templates that use this issuance policy
                    $templates = Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } `
                        -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
                        -Properties * -ErrorAction SilentlyContinue

                    $affectedTemplates = @()
                    foreach ($template in $templates) {
                        $templatePolicies = $template.'msPKI-Certificate-Policy'
                        if ($templatePolicies -contains $oidValue) {
                            $affectedTemplates += $template.Name
                        }
                    }

                    $issues = @()
                    $riskLevel = 'Medium'

                    $issues += "OID linked to group: $groupName"

                    if ($isPrivilegedGroup) {
                        $issues += 'Linked to PRIVILEGED group!'
                        $riskLevel = 'Critical'
                    }

                    if ($affectedTemplates.Count -gt 0) {
                        $issues += "Used by templates: $($affectedTemplates -join ', ')"
                    }

                    # Check who can enroll in affected templates
                    foreach ($templateName in $affectedTemplates) {
                        $template = $templates | Where-Object { $_.Name -eq $templateName }
                        if ($template) {
                            $acl = Get-Acl "AD:\$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                            $enrollRights = $acl.Access | Where-Object {
                                $_.ActiveDirectoryRights -match 'ExtendedRight' -and
                                ($_.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' -or  # Enroll
                                 $_.ObjectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')     # AutoEnroll
                            }

                            $dangerousEnrollees = $enrollRights | Where-Object {
                                $_.IdentityReference -match 'Authenticated Users|Domain Users|Everyone'
                            }

                            if ($dangerousEnrollees) {
                                $issues += "Template '$templateName' allows enrollment by $($dangerousEnrollees.IdentityReference -join ', ')"
                                $riskLevel = 'Critical'
                            }
                        }
                    }

                    $findings += [PSCustomObject]@{
                        OIDName           = $oid.Name
                        OIDValue          = $oidValue
                        LinkedGroup       = $groupName
                        LinkedGroupDN     = $linkedGroup
                        IsPrivilegedGroup = $isPrivilegedGroup
                        AffectedTemplates = ($affectedTemplates -join '; ')
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        ESC               = 'ESC13'
                        AttackPath        = 'Enroll in template -> Get certificate -> Certificate grants group membership'
                        DistinguishedName = $oid.DistinguishedName
                    }

                } catch {
                    # Group not found or access denied
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                OIDName           = 'Error'
                OIDValue          = 'N/A'
                LinkedGroup       = 'N/A'
                LinkedGroupDN     = 'N/A'
                IsPrivilegedGroup = 'N/A'
                AffectedTemplates = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                ESC               = 'ESC13'
                AttackPath        = 'N/A'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove or restrict issuance policy to group links, especially for privileged groups.'
        Impact      = 'Medium - May affect applications relying on certificate-based group membership.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC13 - Issuance Policy Group Link Remediation
#############################################################################
#
# ESC13 abuses the msDS-OIDToGroupLink attribute on issuance policy OIDs.
# When a certificate includes an issuance policy that is linked to a group,
# the certificate holder gains effective membership in that group.
#
# Attack path:
# 1. Find OID with group link to privileged group
# 2. Find template using that OID that allows enrollment
# 3. Enroll in template
# 4. Use certificate - system treats user as group member
#
# Vulnerable configurations:
$($Finding.Findings | ForEach-Object { "# - $($_.OIDName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Identify All OID-to-Group Links
#############################################################################

`$configNC = "CN=Configuration,`$((Get-ADDomain).DistinguishedName)"

# Find all OIDs with group links:
Get-ADObject -Filter { objectClass -eq 'msPKI-Enterprise-Oid' } `
    -SearchBase "CN=OID,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties Name, 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink' |
    Where-Object { `$_.'msDS-OIDToGroupLink' } |
    Select-Object Name, @{N='OID';E={`$_.'msPKI-Cert-Template-OID'}},
        @{N='LinkedGroup';E={(Get-ADGroup `$_.'msDS-OIDToGroupLink').Name}} |
    Format-Table -AutoSize

#############################################################################
# Step 2: Remove Dangerous Group Links
#############################################################################

# Remove the group link from OID:
# WARNING: This may affect legitimate certificate-based access

`$oidName = "IssuancePolicyName"  # Replace with actual OID name
`$oid = Get-ADObject -Filter { objectClass -eq 'msPKI-Enterprise-Oid' -and Name -eq `$oidName } `
    -SearchBase "CN=OID,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties 'msDS-OIDToGroupLink'

if (`$oid.'msDS-OIDToGroupLink') {
    # Remove the link
    Set-ADObject -Identity `$oid.DistinguishedName -Clear 'msDS-OIDToGroupLink'
    Write-Host "Removed group link from `$oidName" -ForegroundColor Green
}

#############################################################################
# Step 3: Restrict Template Enrollment
#############################################################################

# If the OID-to-Group link is needed, restrict who can enroll:

`$templateName = "VulnerableTemplateName"  # Replace with actual template name
`$template = Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' -and Name -eq `$templateName } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

# Remove enrollment rights from broad groups:
`$acl = Get-Acl "AD:\`$(`$template.DistinguishedName)"

# Find and remove Authenticated Users enrollment
`$acesToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference -match 'Authenticated Users|Domain Users|Everyone' -and
    `$_.ObjectType -in @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
}

foreach (`$ace in `$acesToRemove) {
    `$acl.RemoveAccessRule(`$ace) | Out-Null
}

Set-Acl -Path "AD:\`$(`$template.DistinguishedName)" -AclObject `$acl

#############################################################################
# Step 4: Use Non-Privileged Groups
#############################################################################

# If OID-to-Group is needed, link to a non-privileged group:

`$safeGroupDN = "CN=CertificateAccess,OU=Groups,DC=domain,DC=com"

Set-ADObject -Identity `$oid.DistinguishedName -Replace @{
    'msDS-OIDToGroupLink' = `$safeGroupDN
}

# Grant the safe group only necessary permissions (not admin rights)

#############################################################################
# Step 5: Remove Issuance Policy from Template
#############################################################################

# Alternative: Remove the issuance policy from the template entirely

`$template = Get-ADObject -Filter { Name -eq `$templateName } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties 'msPKI-Certificate-Policy'

`$currentPolicies = `$template.'msPKI-Certificate-Policy'
`$vulnerableOID = "1.3.6.1.4.1.311.21.8..."  # Replace with actual OID

`$newPolicies = `$currentPolicies | Where-Object { `$_ -ne `$vulnerableOID }

Set-ADObject -Identity `$template.DistinguishedName -Replace @{
    'msPKI-Certificate-Policy' = `$newPolicies
}

#############################################################################
# Step 6: Monitor for Abuse
#############################################################################

# Monitor certificate enrollment for affected templates:
# Event ID 4886: Certificate request received
# Event ID 4887: Certificate approved and issued

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4887
} -MaxEvents 100 | Where-Object {
    `$_.Message -match `$templateName
} | Select-Object TimeCreated, Message

#############################################################################
# Verification
#############################################################################

# Verify no dangerous OID-to-Group links remain:
Get-ADObject -Filter { objectClass -eq 'msPKI-Enterprise-Oid' } `
    -SearchBase "CN=OID,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties 'msDS-OIDToGroupLink' |
    Where-Object { `$_.'msDS-OIDToGroupLink' } |
    ForEach-Object {
        `$group = Get-ADGroup -Identity `$_.'msDS-OIDToGroupLink' -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            OIDName = `$_.Name
            LinkedGroup = `$group.Name
            IsAdmin = `$group.Name -match 'Admin|Operator'
        }
    } | Format-Table -AutoSize

"@
            return $commands
        }
    }
}

@{
    Id          = 'PKI-ESC4-TemplateACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC4 - Vulnerable Certificate Template Access Control'
    Description = 'Detects certificate templates where low-privileged users have write permissions. An attacker with write access can modify the template to add ESC1/ESC2 conditions (enrollee supplies subject, any purpose EKU) and then exploit it for privilege escalation.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC4'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'AD CS Template Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1649', 'T1484')
    }

    CIS   = @('5.3.4')
    STIG  = @('V-220973')
    ANSSI = @('R68')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous permissions to look for
        $dangerousRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteProperty',
            'WriteDacl',
            'WriteOwner'
        )

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

            $templates = Get-ADObject -SearchBase $templatePath -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties * -ErrorAction SilentlyContinue

            foreach ($template in $templates) {
                $acl = Get-Acl "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                $vulnerableACEs = @()

                foreach ($ace in $acl.Access) {
                    # Skip deny ACEs
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    # Check for dangerous rights
                    $hasDangerousRight = $false
                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right) {
                            $hasDangerousRight = $true
                            break
                        }
                    }

                    if (-not $hasDangerousRight) { continue }

                    # Check if it's a low-privileged principal
                    $principal = $ace.IdentityReference.Value
                    if ($principal -match 'Authenticated Users|Domain Users|Domain Computers|Everyone|Users') {
                        $vulnerableACEs += [PSCustomObject]@{
                            Principal = $principal
                            Rights    = $ace.ActiveDirectoryRights.ToString()
                        }
                    }
                }

                if ($vulnerableACEs.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        TemplateName        = $template.Name
                        DisplayName         = $template.DisplayName
                        DistinguishedName   = $template.DistinguishedName
                        VulnerabilityType   = 'ESC4 - Template Write Access'
                        VulnerableACEs      = ($vulnerableACEs | ForEach-Object { "$($_.Principal): $($_.Rights)" }) -join '; '
                        RiskLevel           = 'Critical'
                        ExploitPath         = @(
                            '1. Attacker modifies template settings',
                            '2. Enables ENROLLEE_SUPPLIES_SUBJECT flag',
                            '3. Exploits as ESC1 vulnerability',
                            '4. Requests cert as Domain Admin'
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
        Description = 'Remove write permissions from low-privileged users on certificate templates.'
        Impact      = 'Low - Only affects template management, not enrollment'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC4 - VULNERABLE TEMPLATE ACL
# ================================================================
# Write access to certificate templates allows attackers to
# MODIFY the template and introduce ESC1/ESC2 vulnerabilities.
#
# Attack: Modify template -> Enable ESC1 -> Exploit

# ================================================================
# VULNERABLE TEMPLATES
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Vulnerable ACEs: $($item.VulnerableACEs)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# Remove dangerous permissions from each vulnerable template:

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
`$templateDN = "$($item.DistinguishedName)"
`$acl = Get-Acl "AD:`$templateDN"

# Remove dangerous ACEs:
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -match 'Authenticated Users|Domain Users|Everyone' -and
    `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply changes:
# Set-Acl "AD:`$templateDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# VERIFY REMEDIATION
# ================================================================

# Check permissions after remediation:
`$configNC = (Get-ADRootDSE).configurationNamingContext
`$templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

Get-ADObject -SearchBase `$templatePath -Filter { objectClass -eq 'pKICertificateTemplate' } |
    ForEach-Object {
        `$acl = Get-Acl "AD:`$(`$_.DistinguishedName)"
        `$dangerous = `$acl.Access | Where-Object {
            `$_.IdentityReference.Value -match 'Authenticated Users|Domain Users' -and
            `$_.ActiveDirectoryRights -match 'Write|GenericAll'
        }
        if (`$dangerous) {
            Write-Warning "Template `$(`$_.Name) still has dangerous permissions"
        }
    }

"@
            return $commands
        }
    }
}

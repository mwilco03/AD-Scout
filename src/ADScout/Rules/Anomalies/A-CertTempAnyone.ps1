@{
    Id          = 'A-CertTempAnyone'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Certificate Template Enrollable by Anyone'
    Description = 'Detects certificate templates where Domain Users, Authenticated Users, Everyone, or Domain Computers have enrollment rights. Combined with other template vulnerabilities (ESC1-ESC4), this enables any user to escalate privileges via certificate abuse.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Certified Pre-Owned'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'AD CS Attack Paths'; Url = 'https://www.thehacker.recipes/ad/movement/ad-cs' }
        @{ Title = 'PingCastle Rule A-CertTempAnyone'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0001')  # Privilege Escalation, Initial Access
        Techniques = @('T1649', 'T1078.002')  # Steal or Forge Authentication Certificates, Domain Accounts
    }

    CIS   = @('5.9')
    STIG  = @('V-36441')
    ANSSI = @('vuln1_adcs_enroll_anyone')
    NIST  = @('AC-3', 'SC-12')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Low-privileged groups that should not have enrollment rights on sensitive templates
        $lowPrivGroups = @(
            'Domain Users',
            'Authenticated Users',
            'Everyone',
            'Domain Computers',
            'Users',
            'Computers'
        )

        # SIDs of well-known low-privileged groups
        $lowPrivSIDs = @(
            'S-1-5-11',     # Authenticated Users
            'S-1-1-0',      # Everyone
            'S-1-5-32-545'  # Users
        )

        # Authentication EKUs that make templates high-risk
        $authenticationEKUs = @(
            '1.3.6.1.5.5.7.3.2',      # Client Authentication
            '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
            '1.3.6.1.5.2.3.4',        # PKINIT Client Authentication
            '2.5.29.37.0'             # Any Purpose
        )

        # msPKI-Certificate-Name-Flag
        $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

        try {
            # Get certificate templates from AD
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $searcher.Filter = "(objectClass=pKICertificateTemplate)"
            $searcher.PropertiesToLoad.AddRange(@(
                'cn', 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag',
                'nTSecurityDescriptor', 'msPKI-Enrollment-Flag'
            ))
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl

            $templates = $searcher.FindAll()

            foreach ($template in $templates) {
                $templateName = $template.Properties['cn'][0]
                $displayName = if ($template.Properties['displayName']) { $template.Properties['displayName'][0] } else { $templateName }
                $ekus = $template.Properties['pkiextendedkeyusage']
                $nameFlag = if ($template.Properties['mspki-certificate-name-flag']) { [int]$template.Properties['mspki-certificate-name-flag'][0] } else { 0 }

                # Check for authentication EKUs or empty EKU (all purposes)
                $hasAuthEKU = $false
                $hasAnyPurpose = $false

                if ($ekus.Count -eq 0) {
                    $hasAnyPurpose = $true
                    $hasAuthEKU = $true
                } else {
                    foreach ($eku in $ekus) {
                        if ($eku -in $authenticationEKUs) {
                            $hasAuthEKU = $true
                            if ($eku -eq '2.5.29.37.0') {
                                $hasAnyPurpose = $true
                            }
                            break
                        }
                    }
                }

                # Check enrollment permissions
                $templatePath = $template.Path
                $templateObj = [ADSI]$templatePath
                $acl = $templateObj.ObjectSecurity

                $lowPrivEnrollees = @()

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    $identity = $ace.IdentityReference.Value
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $objectType = $ace.ObjectType.ToString()

                    # Check for Enroll or AutoEnroll extended rights
                    # Enroll: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                    # AutoEnroll: a05b8cc2-17bc-4802-a710-e7c15ab866a2
                    $enrollGUIDs = @(
                        '0e10c968-78fb-11d2-90d4-00c04f79dc55',  # Certificate-Enrollment
                        'a05b8cc2-17bc-4802-a710-e7c15ab866a2'   # Certificate-AutoEnrollment
                    )

                    $hasEnrollRight = ($objectType -in $enrollGUIDs) -or
                                     ($rights -match 'ExtendedRight' -and $objectType -eq '00000000-0000-0000-0000-000000000000') -or
                                     ($rights -match 'GenericAll')

                    if ($hasEnrollRight) {
                        # Check if identity is a low-privileged group
                        $isLowPriv = $false
                        foreach ($lpGroup in $lowPrivGroups) {
                            if ($identity -match [regex]::Escape($lpGroup)) {
                                $isLowPriv = $true
                                break
                            }
                        }

                        # Also check SID
                        if (-not $isLowPriv) {
                            try {
                                $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                                $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                if ($sid -in $lowPrivSIDs) {
                                    $isLowPriv = $true
                                }
                                # Check for Domain Users (RID 513) or Domain Computers (RID 515)
                                if ($sid -match '-513$' -or $sid -match '-515$') {
                                    $isLowPriv = $true
                                }
                            } catch {
                                # SID translation failed, check by pattern
                                if ($identity -match 'S-1-5-11|S-1-1-0|S-1-5-32-545') {
                                    $isLowPriv = $true
                                }
                            }
                        }

                        if ($isLowPriv) {
                            $lowPrivEnrollees += $identity
                        }
                    }
                }

                # Report findings for templates with auth EKU and low-priv enrollees
                if ($hasAuthEKU -and $lowPrivEnrollees.Count -gt 0) {
                    $riskLevel = 'High'
                    $escType = 'Template Abuse'

                    # Escalate to Critical if supplies subject (ESC1 potential)
                    if ($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) {
                        $riskLevel = 'Critical'
                        $escType = 'ESC1 (Supplies Subject + Low-Priv Enroll)'
                    }

                    $findings += [PSCustomObject]@{
                        TemplateName        = $templateName
                        DisplayName         = $displayName
                        EnrollmentRights    = ($lowPrivEnrollees | Select-Object -Unique) -join '; '
                        EnrolleeCount       = ($lowPrivEnrollees | Select-Object -Unique).Count
                        HasAuthEKU          = $hasAuthEKU
                        HasAnyPurpose       = $hasAnyPurpose
                        SuppliesSubject     = [bool]($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
                        VulnerabilityType   = $escType
                        RiskLevel           = $riskLevel
                        Risk                = 'Any domain user can request authentication certificates'
                        AttackScenario      = if ($riskLevel -eq 'Critical') {
                            'User requests certificate as Domain Admin via subject specification'
                        } else {
                            'User obtains certificate for privilege escalation or persistence'
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "A-CertTempAnyone: Error checking templates - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove enrollment rights from low-privileged groups. Restrict enrollment to specific security groups that require certificates.'
        Impact      = 'High - May affect users who legitimately need to enroll for certificates. Create dedicated enrollment groups first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Certificate Template Enrollment Rights Remediation
#
# Templates enrollable by anyone:
$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): $($_.EnrollmentRights) [$($_.VulnerabilityType)]" } | Out-String)

# STEP 1: Identify legitimate users who need these certificates
# Before removing rights, document who currently uses these templates

# STEP 2: Create dedicated enrollment security groups
# Example for each template:
$($Finding.Findings | ForEach-Object { @"
# Template: $($_.TemplateName)
New-ADGroup -Name "Certificate-$($_.TemplateName)-Enroll" ``
    -GroupScope DomainLocal ``
    -GroupCategory Security ``
    -Description "Users authorized to enroll for $($_.TemplateName) certificates"

"@ })

# STEP 3: Remove low-privileged enrollment rights using ADSI
# WARNING: Test in a lab environment first!

`$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
`$templatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

$($Finding.Findings | ForEach-Object { @"
# Remove rights from: $($_.TemplateName)
`$template = [ADSI]"LDAP://CN=$($_.TemplateName),`$templatesPath"
`$acl = `$template.ObjectSecurity

# Remove Authenticated Users enrollment rights
`$authUsersSID = [System.Security.Principal.SecurityIdentifier]"S-1-5-11"
`$acesToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq `$authUsersSID -and
    `$_.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
}
foreach (`$ace in `$acesToRemove) {
    `$acl.RemoveAccessRule(`$ace)
}

# Remove Domain Users enrollment rights
`$domainUsersSID = (Get-ADGroup "Domain Users").SID
`$acesToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq `$domainUsersSID
}
foreach (`$ace in `$acesToRemove) {
    `$acl.RemoveAccessRule(`$ace)
}

`$template.ObjectSecurity = `$acl
`$template.CommitChanges()

"@ })

# STEP 4: Add enrollment rights to the new dedicated group
# Via Certificate Templates MMC (certtmpl.msc):
# 1. Open the template
# 2. Go to Security tab
# 3. Add the new enrollment group
# 4. Grant "Read" and "Enroll" permissions

# STEP 5: Verify changes
# List templates with enrollment rights:
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$((Get-ADRootDSE).configurationNamingContext)" ``
    -Filter {objectClass -eq 'pKICertificateTemplate'} ``
    -Properties nTSecurityDescriptor | ForEach-Object {
        `$_.nTSecurityDescriptor.Access | Where-Object {
            `$_.ActiveDirectoryRights -match 'ExtendedRight|GenericAll' -and
            `$_.IdentityReference -match 'Domain Users|Authenticated Users|Everyone'
        } | Select-Object @{N='Template';E={`$_.Path}}, IdentityReference
    }

"@
            return $commands
        }
    }
}

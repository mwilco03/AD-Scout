@{
    Id          = 'P-DelegationKeyAdmin'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Key Admins Group Has Non-Admin Members'
    Description = 'Detects when the Key Admins or Enterprise Key Admins groups contain members outside of expected administrators. These groups (added in Windows Server 2016) can modify msDS-KeyCredentialLink attribute, enabling shadow credentials attacks for privilege escalation.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Shadow Credentials Attack'; Url = 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab' }
        @{ Title = 'Key Trust Account Mapping'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/kerberos/whats-new-in-kerberos-authentication' }
        @{ Title = 'PingCastle Rule P-DelegationKeyAdmin'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1098', 'T1556')    # Account Manipulation, Modify Authentication Process
    }

    CIS   = @()  # Key Admins groups not covered in CIS benchmarks
    STIG  = @()  # Key Admin STIGs are Windows Server version-specific
    ANSSI = @()
    NIST  = @('AC-2', 'AC-3', 'AC-6')  # Account Management, Access Enforcement, Least Privilege

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 5
        MaxPoints = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Key Admin groups (Windows Server 2016+)
        $keyAdminGroups = @(
            @{ Name = 'Key Admins'; RID = 526; Description = 'Can manage key credentials for objects in the domain' }
            @{ Name = 'Enterprise Key Admins'; RID = 527; Description = 'Can manage key credentials for objects in the forest' }
        )

        # Expected members (typically should be empty or only Domain Admins)
        $expectedMembers = @(
            'Domain Admins',
            'Enterprise Admins',
            'Administrators'
        )

        try {
            $domainSID = $Domain.DomainSID
            if (-not $domainSID -and $Data.Domain) {
                $domainSID = $Data.Domain.DomainSID
            }

            foreach ($keyGroup in $keyAdminGroups) {
                $group = $null

                # Try to find the group in the data
                $group = $Data.Groups | Where-Object {
                    $_.Name -eq $keyGroup.Name -or
                    $_.SamAccountName -eq $keyGroup.Name -or
                    ($_.SID -and $_.SID -match "-$($keyGroup.RID)$")
                } | Select-Object -First 1

                # If not in data, try ADSI
                if (-not $group) {
                    try {
                        $groupSID = "$domainSID-$($keyGroup.RID)"
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($groupSID)
                        $groupAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        $groupName = $groupAccount.Split('\')[-1]

                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $defaultNC = $rootDSE.defaultNamingContext.ToString()

                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://$defaultNC"
                        $searcher.Filter = "(&(objectClass=group)(sAMAccountName=$groupName))"
                        $searcher.PropertiesToLoad.AddRange(@('member', 'distinguishedName', 'name'))

                        $result = $searcher.FindOne()
                        if ($result) {
                            $group = @{
                                Name = $result.Properties['name'][0]
                                DistinguishedName = $result.Properties['distinguishedname'][0]
                                Members = $result.Properties['member']
                            }
                        }
                    } catch {
                        # Group may not exist (pre-2016 domain)
                        continue
                    }
                }

                if (-not $group) { continue }

                # Get members
                $members = @()
                if ($group.Members) {
                    $members = $group.Members
                } elseif ($group.member) {
                    $members = $group.member
                }

                foreach ($member in $members) {
                    if (-not $member) { continue }

                    $memberName = ($member -split ',')[0] -replace 'CN=', ''

                    # Check if this is an expected member
                    $isExpected = $false
                    foreach ($expected in $expectedMembers) {
                        if ($memberName -match [regex]::Escape($expected)) {
                            $isExpected = $true
                            break
                        }
                    }

                    if (-not $isExpected) {
                        # Get more info about the member
                        $memberType = 'Unknown'
                        $memberEnabled = $null

                        try {
                            $memberObj = [ADSI]"LDAP://$member"
                            $objectClass = $memberObj.objectClass
                            if ($objectClass -contains 'user') {
                                $memberType = 'User'
                                $uac = [int]$memberObj.userAccountControl.ToString()
                                $memberEnabled = -not ($uac -band 2)
                            } elseif ($objectClass -contains 'group') {
                                $memberType = 'Group'
                            } elseif ($objectClass -contains 'computer') {
                                $memberType = 'Computer'
                            }
                        } catch { }

                        $findings += [PSCustomObject]@{
                            GroupName           = $keyGroup.Name
                            GroupRID            = $keyGroup.RID
                            GroupPurpose        = $keyGroup.Description
                            MemberName          = $memberName
                            MemberDN            = $member
                            MemberType          = $memberType
                            MemberEnabled       = $memberEnabled
                            Severity            = if ($keyGroup.RID -eq 527) { 'High' } else { 'Medium' }
                            Risk                = "Unexpected member in $($keyGroup.Name)"
                            Impact              = 'Member can set msDS-KeyCredentialLink for shadow credentials attack'
                            AttackScenario      = 'Add key credential to privileged account, then authenticate as that account'
                        }
                    }
                }
            }

            # Also check if msDS-KeyCredentialLink write permission is delegated
            # to non-admins on sensitive objects
            $sensitiveContainers = @(
                "CN=Users",
                "CN=Computers",
                "OU=Domain Controllers"
            )

            $rootDSE = [ADSI]"LDAP://RootDSE"
            $defaultNC = $rootDSE.defaultNamingContext.ToString()
            $schemaNC = $rootDSE.schemaNamingContext.ToString()

            # Get the GUID for msDS-KeyCredentialLink attribute
            $keyCredGUID = $null
            try {
                $searcher = New-Object DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = [ADSI]"LDAP://$schemaNC"
                $searcher.Filter = "(ldapDisplayName=msDS-KeyCredentialLink)"
                $searcher.PropertiesToLoad.Add('schemaIDGUID')
                $result = $searcher.FindOne()
                if ($result) {
                    $guidBytes = $result.Properties['schemaidguid'][0]
                    $keyCredGUID = [guid]$guidBytes
                }
            } catch { }

            if ($keyCredGUID) {
                foreach ($container in $sensitiveContainers) {
                    $containerDN = "$container,$defaultNC"
                    try {
                        $containerObj = [ADSI]"LDAP://$containerDN"
                        $acl = $containerObj.ObjectSecurity

                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }

                            # Check for write property on msDS-KeyCredentialLink
                            $rights = $ace.ActiveDirectoryRights.ToString()
                            if ($rights -match 'WriteProperty|GenericAll|GenericWrite') {
                                # Check if it's for the key credential attribute
                                if ($ace.ObjectType -eq $keyCredGUID -or $rights -match 'GenericAll|GenericWrite') {
                                    $identity = $ace.IdentityReference.Value

                                    # Skip expected principals
                                    $isExpected = $false
                                    foreach ($expected in $expectedMembers) {
                                        if ($identity -match [regex]::Escape($expected) -or
                                            $identity -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators') {
                                            $isExpected = $true
                                            break
                                        }
                                    }

                                    if (-not $isExpected -and $identity -notmatch 'S-1-5-18|SELF') {
                                        $findings += [PSCustomObject]@{
                                            Container           = $container
                                            ContainerDN         = $containerDN
                                            DelegatedTo         = $identity
                                            Permission          = $rights
                                            Attribute           = 'msDS-KeyCredentialLink'
                                            Severity            = 'High'
                                            Risk                = 'Key credential write delegation'
                                            Impact              = 'Can add shadow credentials to objects in container'
                                        }
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }

        } catch {
            Write-Verbose "P-DelegationKeyAdmin: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove non-admin members from Key Admins groups. Review and remove inappropriate msDS-KeyCredentialLink write permissions.'
        Impact      = 'Medium - May affect key-based authentication workflows. Verify no legitimate key management is disrupted.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Key Admins Delegation Remediation
#
# Issues found:
$($Finding.Findings | ForEach-Object { "# - $($_.GroupName): $($_.MemberName) [$($_.MemberType)]" } | Out-String)

# Key Admins groups were added in Windows Server 2016 for:
# - Managing msDS-KeyCredentialLink attribute
# - Key Trust authentication (passwordless)
# - Windows Hello for Business key provisioning

# STEP 1: Review current Key Admins membership
@('Key Admins', 'Enterprise Key Admins') | ForEach-Object {
    `$group = Get-ADGroup -Identity `$_ -ErrorAction SilentlyContinue
    if (`$group) {
        Write-Host "`n=== `$_ ===" -ForegroundColor Yellow
        Get-ADGroupMember -Identity `$_ | Format-Table Name, objectClass, SamAccountName
    }
}

# STEP 2: Remove unexpected members from Key Admins
$($Finding.Findings | Where-Object { $_.GroupName -eq 'Key Admins' } | ForEach-Object { @"
# Remove $($_.MemberName) from Key Admins
Remove-ADGroupMember -Identity "Key Admins" -Members "$($_.MemberName)" -Confirm:`$false
Write-Host "Removed $($_.MemberName) from Key Admins"

"@ })

# STEP 3: Remove unexpected members from Enterprise Key Admins
$($Finding.Findings | Where-Object { $_.GroupName -eq 'Enterprise Key Admins' } | ForEach-Object { @"
# Remove $($_.MemberName) from Enterprise Key Admins
Remove-ADGroupMember -Identity "Enterprise Key Admins" -Members "$($_.MemberName)" -Confirm:`$false
Write-Host "Removed $($_.MemberName) from Enterprise Key Admins"

"@ })

# STEP 4: Check for existing shadow credentials on privileged accounts
# Look for accounts with msDS-KeyCredentialLink set
`$sensitiveGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
`$sensitiveUsers = `$sensitiveGroups | ForEach-Object {
    Get-ADGroupMember -Identity `$_ -Recursive | Where-Object { `$_.objectClass -eq 'user' }
} | Select-Object -Unique

Write-Host "`nChecking for shadow credentials on privileged accounts..."
`$sensitiveUsers | ForEach-Object {
    `$user = Get-ADUser -Identity `$_.SamAccountName -Properties 'msDS-KeyCredentialLink'
    if (`$user.'msDS-KeyCredentialLink') {
        Write-Host "WARNING: `$(`$_.SamAccountName) has key credentials set!" -ForegroundColor Red
        # To remove (CAUTION - may break legitimate WHFB):
        # Set-ADUser -Identity `$_.SamAccountName -Clear 'msDS-KeyCredentialLink'
    }
}

# STEP 5: Audit msDS-KeyCredentialLink permissions on Domain Admins
`$daGroup = Get-ADGroup "Domain Admins"
`$acl = Get-Acl "AD:\`$(`$daGroup.DistinguishedName)"

# Get the GUID for msDS-KeyCredentialLink
`$schemaPath = "LDAP://CN=Schema,CN=Configuration," + (Get-ADDomain).DistinguishedName
`$searcher = [System.DirectoryServices.DirectorySearcher]::new([ADSI]`$schemaPath)
`$searcher.Filter = "(ldapDisplayName=msDS-KeyCredentialLink)"
`$keyCredGUID = [guid](`$searcher.FindOne().Properties['schemaidguid'][0])

Write-Host "`nmsDS-KeyCredentialLink permissions on Domain Admins:"
`$acl.Access | Where-Object {
    (`$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite') -and
    ((`$_.ObjectType -eq `$keyCredGUID) -or (`$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite'))
} | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType

# STEP 6: Remove msDS-KeyCredentialLink delegation if found
$($Finding.Findings | Where-Object { $_.Attribute -eq 'msDS-KeyCredentialLink' } | ForEach-Object { @"
# Remove key credential delegation from $($_.DelegatedTo) on $($_.Container)
`$containerDN = "$($_.ContainerDN)"
`$acl = Get-Acl "AD:\`$containerDN"
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -match "$($_.DelegatedTo)" -and
    `$_.ActiveDirectoryRights -match "WriteProperty|GenericWrite"
}
if (`$aceToRemove) {
    `$acl.RemoveAccessRule(`$aceToRemove)
    Set-Acl "AD:\`$containerDN" `$acl
    Write-Host "Removed delegation from $($_.DelegatedTo)"
}

"@ })

# STEP 7: Monitor for shadow credential attacks
# Enable auditing for object modifications
# Event ID 4662 with msDS-KeyCredentialLink GUID

"@
            return $commands
        }
    }
}

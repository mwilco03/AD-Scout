@{
    Id          = 'A-PreWin2000Other'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Pre-Windows 2000 Compatible Access Has Non-Default Members'
    Description = 'Detects when the "Pre-Windows 2000 Compatible Access" group contains members other than Authenticated Users. This legacy group grants read access to all users and groups, which can expose sensitive information to attackers.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Pre-Windows 2000 Compatible Access'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
        @{ Title = 'Anonymous Access to AD'; Url = 'https://adsecurity.org/?p=3164' }
        @{ Title = 'PingCastle Rule A-PreWin2000Other'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0007', 'TA0043')  # Discovery, Reconnaissance
        Techniques = @('T1087.002', 'T1069.002')  # Account Discovery: Domain, Permission Groups Discovery
    }

    CIS   = @('5.2.4')
    STIG  = @('V-63677')
    ANSSI = @('vuln3_prewin2000')
    NIST  = @('AC-2', 'AC-3')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 5
        MaxPoints = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Pre-Windows 2000 Compatible Access is a builtin group
        # SID: S-1-5-32-554
        $groupName = 'Pre-Windows 2000 Compatible Access'
        $groupSID = 'S-1-5-32-554'

        # Expected members - typically should only have Authenticated Users or be empty
        $expectedMembers = @(
            'Authenticated Users',
            'S-1-5-11'  # Authenticated Users SID
        )

        try {
            # Find the group in data
            $preWin2000Group = $Data.Groups | Where-Object {
                $_.Name -eq $groupName -or
                $_.SamAccountName -eq $groupName -or
                $_.SID -eq $groupSID
            } | Select-Object -First 1

            # If not in data, try ADSI
            if (-not $preWin2000Group) {
                try {
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://CN=Builtin,$((([ADSI]'LDAP://RootDSE').defaultNamingContext))"
                    $searcher.Filter = "(&(objectClass=group)(cn=$groupName))"
                    $searcher.PropertiesToLoad.AddRange(@('member', 'distinguishedName'))

                    $result = $searcher.FindOne()
                    if ($result) {
                        $preWin2000Group = @{
                            Name = $groupName
                            DistinguishedName = $result.Properties['distinguishedname'][0]
                            Members = $result.Properties['member']
                        }
                    }
                } catch { }
            }

            if (-not $preWin2000Group) { return $findings }

            # Get members
            $members = @()
            if ($preWin2000Group.Members) {
                $members = @($preWin2000Group.Members)
            } elseif ($preWin2000Group.member) {
                $members = @($preWin2000Group.member)
            }

            # Check for Anonymous (S-1-5-7) or Everyone (S-1-1-0) - these are critical
            $criticalMembers = @('Anonymous', 'Everyone', 'S-1-5-7', 'S-1-1-0', 'ANONYMOUS LOGON')

            foreach ($member in $members) {
                if (-not $member) { continue }

                $memberName = $member
                if ($member -match 'CN=([^,]+)') {
                    $memberName = $Matches[1]
                }

                # Check if this is an expected member
                $isExpected = $false
                foreach ($expected in $expectedMembers) {
                    if ($memberName -match [regex]::Escape($expected) -or $member -match [regex]::Escape($expected)) {
                        $isExpected = $true
                        break
                    }
                }

                if (-not $isExpected) {
                    # Determine severity based on member
                    $isCritical = $false
                    foreach ($critical in $criticalMembers) {
                        if ($memberName -match [regex]::Escape($critical) -or $member -match [regex]::Escape($critical)) {
                            $isCritical = $true
                            break
                        }
                    }

                    $findings += [PSCustomObject]@{
                        GroupName           = $groupName
                        GroupSID            = $groupSID
                        UnexpectedMember    = $memberName
                        MemberDN            = $member
                        Severity            = if ($isCritical) { 'Critical' } else { 'Medium' }
                        Risk                = if ($isCritical) {
                            'Anonymous/Everyone in Pre-Windows 2000 Compatible Access allows unauthenticated enumeration'
                        } else {
                            'Non-default member in Pre-Windows 2000 Compatible Access'
                        }
                        Impact              = 'Grants broad read access to AD objects'
                        Recommendation      = 'Remove member and verify legacy application compatibility'
                    }
                }
            }

            # Also check if Authenticated Users is removed (making group less restrictive overall)
            $hasAuthenticatedUsers = $false
            foreach ($member in $members) {
                if ($member -match 'Authenticated Users|S-1-5-11') {
                    $hasAuthenticatedUsers = $true
                    break
                }
            }

            # Note: Having only Authenticated Users is the "safe" default
            # Having other members OR Anonymous/Everyone is the problem

        } catch {
            Write-Verbose "A-PreWin2000Other: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove non-default members from Pre-Windows 2000 Compatible Access group. Verify legacy application compatibility before making changes.'
        Impact      = 'Medium - May break legacy applications that rely on anonymous LDAP access. Test thoroughly.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Pre-Windows 2000 Compatible Access Remediation
#
# Non-default members found:
$($Finding.Findings | ForEach-Object { "# - $($_.UnexpectedMember)" } | Out-String)

# This group grants read access to all user and group objects
# Default membership should be only "Authenticated Users"
# Having Anonymous/Everyone enables unauthenticated enumeration

# STEP 1: View current membership
Write-Host "Current members of Pre-Windows 2000 Compatible Access:" -ForegroundColor Yellow
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" | Format-Table Name, objectClass, SID

# STEP 2: Check for applications that require anonymous access
# Common scenarios:
# - Legacy LDAP applications
# - Unix/Linux LDAP clients without SASL/Kerberos
# - Some older print servers
# - Legacy monitoring tools

# STEP 3: Remove non-default members
$($Finding.Findings | ForEach-Object { @"
# Remove $($_.UnexpectedMember)
try {
    Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Members "$($_.UnexpectedMember)" -Confirm:`$false
    Write-Host "Removed: $($_.UnexpectedMember)" -ForegroundColor Green
} catch {
    Write-Host "Failed to remove $($_.UnexpectedMember): `$_" -ForegroundColor Red
}

"@ })

# STEP 4: Verify the change
Write-Host "`nUpdated membership:" -ForegroundColor Yellow
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" | Format-Table Name, objectClass

# STEP 5: If anonymous access is required, use more targeted permissions
# Instead of Pre-Windows 2000 Compatible Access, grant specific OUs:
#
# `$ou = "OU=PublicContacts,DC=domain,DC=com"
# `$acl = Get-Acl "AD:\`$ou"
# `$identity = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-7")  # Anonymous
# `$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
#     `$identity, "ReadProperty", "Allow", "Descendents")
# `$acl.AddAccessRule(`$rule)
# Set-Acl "AD:\`$ou" `$acl

# STEP 6: Disable anonymous LDAP binding at DC level if not needed
# Via GPO: Computer Configuration > Windows Settings > Security Settings >
#          Local Policies > Security Options >
#          "Network access: Do not allow anonymous enumeration of SAM accounts and shares"

# STEP 7: Verify dsHeuristics doesn't allow anonymous (7th char should not be 2)
`$config = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)"
Write-Host "dsHeuristics: `$(`$config.dsHeuristics)"

# STEP 8: Test for anonymous access
# From a non-domain-joined machine:
# ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName

"@
            return $commands
        }
    }
}

@{
    Id          = 'P-ControlPathIndirectMany'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Excessive Indirect Control Paths to Privileged Accounts'
    Description = 'Detects when too many accounts have indirect control paths (via nested groups, ACL inheritance, or delegations) that could lead to privilege escalation. A large attack surface increases the likelihood of successful compromise.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'BloodHound Attack Paths'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html' }
        @{ Title = 'AD Attack Paths'; Url = 'https://adsecurity.org/?p=3658' }
        @{ Title = 'PingCastle Rule P-ControlPathIndirectMany'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0007')  # Privilege Escalation, Discovery
        Techniques = @('T1078.002', 'T1069.002')  # Domain Accounts, Domain Groups
    }

    CIS   = @()  # Control path analysis not covered in CIS benchmarks
    STIG  = @()  # AD delegation STIGs are environment-specific
    ANSSI = @()
    NIST  = @('AC-2', 'AC-3', 'AC-6')  # Account Management, Access Enforcement, Least Privilege

    Scoring = @{
        Type      = 'ThresholdBased'
        Threshold = 50
        Points    = 1
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Control rights that allow escalation
        $controlRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteDacl',
            'WriteOwner',
            'AllExtendedRights',
            'Self',
            'WriteProperty'
        )

        # Extended rights GUIDs for specific escalation paths
        $dangerousExtendedRights = @{
            '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        }

        # Sensitive targets
        $sensitiveGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )

        $controlPathsPerTarget = @{}
        $indirectControllers = @{}

        try {
            foreach ($targetName in $sensitiveGroups) {
                $target = $Data.Groups | Where-Object {
                    $_.Name -eq $targetName -or $_.SamAccountName -eq $targetName
                } | Select-Object -First 1

                if (-not $target) {
                    # Try ADSI
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $defaultNC = $rootDSE.defaultNamingContext.ToString()

                        $searchBase = if ($targetName -in @('Account Operators', 'Server Operators', 'Backup Operators', 'Administrators')) {
                            "CN=Builtin,$defaultNC"
                        } else {
                            "CN=Users,$defaultNC"
                        }

                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://$searchBase"
                        $searcher.Filter = "(&(objectClass=group)(cn=$targetName))"
                        $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'nTSecurityDescriptor'))

                        $result = $searcher.FindOne()
                        if ($result) {
                            $target = @{
                                Name = $targetName
                                DistinguishedName = $result.Properties['distinguishedname'][0]
                            }
                        }
                    } catch { continue }
                }

                if (-not $target) { continue }

                $targetDN = $target.DistinguishedName
                $controllersForTarget = @()

                try {
                    $adsiTarget = [ADSI]"LDAP://$targetDN"
                    $acl = $adsiTarget.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()

                        # Skip SELF and expected admin principals
                        if ($identity -match 'SELF|NT AUTHORITY\\SYSTEM|S-1-5-18') { continue }
                        if ($identity -match 'Domain Admins|Enterprise Admins|Administrators|BUILTIN\\Administrators') { continue }

                        # Check if this is a control right
                        $hasControl = $false
                        foreach ($cr in $controlRights) {
                            if ($rights -match $cr) {
                                $hasControl = $true
                                break
                            }
                        }

                        if (-not $hasControl) { continue }

                        # This identity has control - check if it's a group (indirect path)
                        $identityName = $identity.Split('\')[-1]

                        # Check if it's a group in our data
                        $controllingGroup = $Data.Groups | Where-Object {
                            $_.SamAccountName -eq $identityName -or $_.Name -eq $identityName
                        } | Select-Object -First 1

                        if ($controllingGroup) {
                            # It's a group - count members as indirect controllers
                            $memberCount = 0
                            if ($controllingGroup.Members) {
                                $memberCount = @($controllingGroup.Members).Count
                            }

                            $controllersForTarget += @{
                                Principal = $identity
                                Type = 'Group'
                                MemberCount = $memberCount
                                Rights = $rights
                            }

                            if (-not $indirectControllers.ContainsKey($identity)) {
                                $indirectControllers[$identity] = @()
                            }
                            $indirectControllers[$identity] += $targetName
                        } else {
                            # Direct user/computer with control (also concerning)
                            $controllersForTarget += @{
                                Principal = $identity
                                Type = 'Direct'
                                Rights = $rights
                            }
                        }
                    }
                } catch {
                    Write-Verbose "P-ControlPathIndirectMany: Error checking $targetName - $_"
                }

                $controlPathsPerTarget[$targetName] = $controllersForTarget
            }

            # Calculate total indirect control paths
            $totalIndirectPaths = 0
            $groupsWithControl = @()

            foreach ($target in $controlPathsPerTarget.Keys) {
                $controllers = $controlPathsPerTarget[$target]

                foreach ($controller in $controllers) {
                    if ($controller.Type -eq 'Group') {
                        $totalIndirectPaths += [int]$controller.MemberCount
                        $groupsWithControl += [PSCustomObject]@{
                            ControllingGroup = $controller.Principal
                            MemberCount = $controller.MemberCount
                            TargetGroup = $target
                            Rights = $controller.Rights
                        }
                    }
                }
            }

            # Report if threshold exceeded
            $threshold = 50  # Configurable threshold

            if ($totalIndirectPaths -gt $threshold) {
                $findings += [PSCustomObject]@{
                    TotalIndirectPaths  = $totalIndirectPaths
                    Threshold           = $threshold
                    GroupsWithControl   = $groupsWithControl.Count
                    TopControllers      = ($groupsWithControl | Sort-Object MemberCount -Descending | Select-Object -First 5)
                    Severity            = if ($totalIndirectPaths -gt 200) { 'Critical' } elseif ($totalIndirectPaths -gt 100) { 'High' } else { 'Medium' }
                    Risk                = "$totalIndirectPaths accounts have indirect paths to privileged groups"
                    Impact              = 'Large attack surface for privilege escalation'
                    Recommendation      = 'Review and reduce control delegations to groups with many members'
                }
            }

            # Also report specific problematic groups
            $largeControlGroups = $groupsWithControl | Where-Object { $_.MemberCount -gt 10 }

            foreach ($lcg in $largeControlGroups) {
                $findings += [PSCustomObject]@{
                    ControllingGroup    = $lcg.ControllingGroup
                    ControlledTarget    = $lcg.TargetGroup
                    IndirectControllers = $lcg.MemberCount
                    ControlRights       = $lcg.Rights
                    Severity            = if ($lcg.MemberCount -gt 50) { 'High' } else { 'Medium' }
                    Risk                = "Group with $($lcg.MemberCount) members can control $($lcg.TargetGroup)"
                    Impact              = 'Any member of this group can escalate privileges'
                }
            }

        } catch {
            Write-Verbose "P-ControlPathIndirectMany: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and reduce control paths to privileged groups. Remove unnecessary delegations and reduce group memberships. Use BloodHound for detailed path analysis.'
        Impact      = 'Medium - May affect delegated administration. Document current delegations before changes.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Excessive Indirect Control Paths Remediation
#
# Summary:
# - Total indirect paths: $($Finding.Findings[0].TotalIndirectPaths)
# - Threshold: $($Finding.Findings[0].Threshold)
# - Groups with control: $($Finding.Findings[0].GroupsWithControl)

# STEP 1: Use BloodHound for detailed path visualization
# Download and run SharpHound:
# .\\SharpHound.exe -c All,GPOLocalGroup

# Import into BloodHound and analyze:
# - "Shortest Paths to Domain Admins"
# - "Find Principals with DCSync Rights"
# - "Map Domain Trusts"

# STEP 2: Review top controllers
$($Finding.Findings | Where-Object { $_.ControllingGroup } | ForEach-Object { @"
# Group: $($_.ControllingGroup)
# - Controls: $($_.ControlledTarget)
# - Rights: $($_.ControlRights)
# - Members with indirect access: $($_.IndirectControllers)

# Review members of this group:
Get-ADGroup "$($_.ControllingGroup.Split('\')[-1])" | Get-ADGroupMember | Format-Table Name, objectClass

"@ })

# STEP 3: Remove unnecessary control delegations
# For each problematic group, either:
# Option A: Remove the delegation entirely
# Option B: Replace with a smaller, dedicated admin group

# Example - Remove WriteDacl from a large group:
# `$targetDN = "CN=Domain Admins,CN=Users,DC=domain,DC=com"
# `$acl = Get-Acl "AD:\`$targetDN"
# `$rulesToRemove = `$acl.Access | Where-Object {
#     `$_.IdentityReference.Value -match "LargeGroup" -and
#     `$_.ActiveDirectoryRights -match "WriteDacl"
# }
# foreach (`$rule in `$rulesToRemove) {
#     `$acl.RemoveAccessRule(`$rule)
# }
# Set-Acl "AD:\`$targetDN" `$acl

# STEP 4: Reduce group nesting
# Check for groups within groups:
@('Domain Admins', 'Enterprise Admins', 'Administrators') | ForEach-Object {
    Write-Host "`n=== `$_ nested groups ===" -ForegroundColor Yellow
    Get-ADGroupMember `$_ | Where-Object { `$_.objectClass -eq 'group' } |
        ForEach-Object {
            `$nestedCount = (Get-ADGroupMember `$_.SamAccountName -Recursive).Count
            Write-Host "`$(`$_.Name): `$nestedCount total members"
        }
}

# STEP 5: Implement tiered administration
# Tier 0: Domain controllers and privileged accounts
# Tier 1: Servers and server admins
# Tier 2: Workstations and helpdesk

# Ensure Tier 1/2 groups don't have control over Tier 0 objects

# STEP 6: Create dedicated admin groups
# Instead of giving a large "IT" group control, create:
# - "AD Object Admins" with specific, limited permissions
# - Separate groups for different administrative functions

# STEP 7: Audit control paths regularly
# Schedule monthly BloodHound collection and review
# Alert on new paths to Domain Admins

# STEP 8: PowerShell to list all principals with control
`$sensitiveGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
`$sensitiveGroups | ForEach-Object {
    Write-Host "`n=== Control over `$_ ===" -ForegroundColor Yellow
    `$group = Get-ADGroup `$_
    `$acl = Get-Acl "AD:\`$(`$group.DistinguishedName)"
    `$acl.Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite' -and
        `$_.AccessControlType -eq 'Allow' -and
        `$_.IdentityReference.Value -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators'
    } | Format-Table IdentityReference, ActiveDirectoryRights
}

"@
            return $commands
        }
    }
}

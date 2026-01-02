@{
    Id          = 'P-ControlPathIndirectEveryone'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Indirect Control Path to Everyone'
    Description = 'Detects when privileged objects have control paths that lead to Everyone, Authenticated Users, or other broad groups. This means any domain user might have an indirect path to escalate privileges via nested permissions or group memberships.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'BloodHound Control Paths'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html' }
        @{ Title = 'AD Control Paths'; Url = 'https://adsecurity.org/?p=3658' }
        @{ Title = 'PingCastle Rule P-ControlPathIndirectEveryone'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1078.002', 'T1222.001')  # Valid Accounts: Domain, File and Directory Permissions Modification
    }

    CIS   = @()  # Control path analysis not covered in CIS benchmarks
    STIG  = @()  # AD delegation STIGs are environment-specific
    ANSSI = @()
    NIST  = @('AC-3', 'AC-6')  # Access Enforcement, Least Privilege

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Broad groups that indicate problematic control paths
        $broadGroups = @(
            @{ Name = 'Everyone'; SID = 'S-1-1-0' }
            @{ Name = 'Authenticated Users'; SID = 'S-1-5-11' }
            @{ Name = 'Domain Users'; RIDSuffix = '513' }
            @{ Name = 'Domain Computers'; RIDSuffix = '515' }
            @{ Name = 'Users'; SID = 'S-1-5-32-545' }
        )

        # Sensitive objects to check for control paths
        $sensitiveObjects = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Server Operators',
            'Backup Operators'
        )

        # Dangerous permissions that constitute control
        $controlRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteDacl',
            'WriteOwner',
            'WriteProperty',
            'AddMember',
            'Self'
        )

        try {
            foreach ($sensitiveGroupName in $sensitiveObjects) {
                $group = $Data.Groups | Where-Object { $_.Name -eq $sensitiveGroupName } | Select-Object -First 1

                if (-not $group) {
                    # Try ADSI
                    try {
                        $domainDN = $Domain.DistinguishedName
                        $groupDN = if ($sensitiveGroupName -in @('Account Operators', 'Server Operators', 'Backup Operators', 'Administrators')) {
                            "CN=$sensitiveGroupName,CN=Builtin,$domainDN"
                        } else {
                            "CN=$sensitiveGroupName,CN=Users,$domainDN"
                        }
                        $adsiGroup = [ADSI]"LDAP://$groupDN"
                        if ($adsiGroup.Path) {
                            $group = @{
                                Name = $sensitiveGroupName
                                DistinguishedName = $adsiGroup.distinguishedName.ToString()
                            }
                        }
                    } catch {
                        continue
                    }
                }

                if (-not $group) { continue }

                # Get ACL on the sensitive object
                try {
                    $groupDN = $group.DistinguishedName
                    $adsiObj = [ADSI]"LDAP://$groupDN"
                    $acl = $adsiObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()

                        # Check if rights include control permissions
                        $hasControlRight = $false
                        foreach ($cr in $controlRights) {
                            if ($rights -match $cr) {
                                $hasControlRight = $true
                                break
                            }
                        }

                        if (-not $hasControlRight) { continue }

                        # Check if identity is a broad group (direct control)
                        foreach ($bg in $broadGroups) {
                            $isBroadGroup = $false

                            if ($bg.SID -and $identity -match $bg.SID) {
                                $isBroadGroup = $true
                            } elseif ($bg.RIDSuffix -and $identity -match "-$($bg.RIDSuffix)$") {
                                $isBroadGroup = $true
                            } elseif ($identity -match [regex]::Escape($bg.Name)) {
                                $isBroadGroup = $true
                            }

                            if ($isBroadGroup) {
                                $findings += [PSCustomObject]@{
                                    SensitiveObject     = $sensitiveGroupName
                                    ObjectDN            = $groupDN
                                    ControllingPrincipal = $identity
                                    MatchedBroadGroup   = $bg.Name
                                    ControlRights       = $rights
                                    PathType            = 'Direct'
                                    Severity            = 'Critical'
                                    Risk                = "All domain users can control $sensitiveGroupName"
                                    Impact              = 'Any authenticated user can escalate to privileged access'
                                }
                            }
                        }

                        # Check for indirect paths via group membership
                        # If a group has control, and that group contains broad membership
                        if (-not ($identity -match 'S-1-1-0|S-1-5-11|-513$|-515$')) {
                            try {
                                # Try to resolve the identity to check its members
                                $controllingGroup = $Data.Groups | Where-Object {
                                    $_.SamAccountName -eq $identity.Split('\')[-1] -or
                                    $_.Name -eq $identity.Split('\')[-1]
                                } | Select-Object -First 1

                                if ($controllingGroup -and $controllingGroup.Members) {
                                    foreach ($member in $controllingGroup.Members) {
                                        foreach ($bg in $broadGroups) {
                                            if ($member -match [regex]::Escape($bg.Name) -or
                                                ($bg.SID -and $member -match $bg.SID) -or
                                                ($bg.RIDSuffix -and $member -match "-$($bg.RIDSuffix)$")) {

                                                $findings += [PSCustomObject]@{
                                                    SensitiveObject     = $sensitiveGroupName
                                                    ObjectDN            = $groupDN
                                                    ControllingPrincipal = $identity
                                                    NestedMember        = $member
                                                    MatchedBroadGroup   = $bg.Name
                                                    ControlRights       = $rights
                                                    PathType            = 'Indirect (via group membership)'
                                                    Severity            = 'High'
                                                    Risk                = "Indirect control path via $identity"
                                                    Impact              = 'Privilege escalation possible via nested groups'
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch {
                                # Could not check nested membership
                            }
                        }
                    }
                } catch {
                    Write-Verbose "P-ControlPathIndirectEveryone: Error checking ACL on $sensitiveGroupName - $_"
                }
            }

        } catch {
            Write-Verbose "P-ControlPathIndirectEveryone: Error - $_"
        }

        # Deduplicate findings
        $findings = $findings | Sort-Object SensitiveObject, ControllingPrincipal -Unique

        return $findings
    }

    Remediation = @{
        Description = 'Remove control rights from broad groups and review indirect control paths. Use BloodHound for detailed attack path analysis.'
        Impact      = 'Medium - May break delegated administration. Review all control paths before remediation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Control Path to Everyone Remediation
#
# Dangerous control paths detected:
$($Finding.Findings | ForEach-Object { "# - $($_.SensitiveObject): $($_.ControllingPrincipal) has $($_.ControlRights) [$($_.PathType)]" } | Out-String)

# STEP 1: Use BloodHound for visualization
# Download and run SharpHound collector:
# .\SharpHound.exe -c All
# Import data into BloodHound and analyze paths to Domain Admins

# STEP 2: Review and remove direct control rights
$($Finding.Findings | Where-Object { $_.PathType -eq 'Direct' } | ForEach-Object { @"
# Remove control rights from $($_.ControllingPrincipal) on $($_.SensitiveObject)
`$acl = Get-Acl "AD:\$($_.ObjectDN)"
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference -match "$($_.ControllingPrincipal)" -and
    `$_.ActiveDirectoryRights -match "$($_.ControlRights)"
}
if (`$aceToRemove) {
    `$acl.RemoveAccessRule(`$aceToRemove)
    Set-Acl "AD:\$($_.ObjectDN)" `$acl
    Write-Host "Removed: $($_.ControllingPrincipal) from $($_.SensitiveObject)"
}

"@ })

# STEP 3: Review indirect control paths
$($Finding.Findings | Where-Object { $_.PathType -match 'Indirect' } | ForEach-Object { @"
# Indirect path: $($_.ControllingPrincipal) contains $($_.NestedMember)
# Either remove the nested member or remove the control rights
# Option 1: Remove nested member
# Remove-ADGroupMember -Identity "$($_.ControllingPrincipal.Split('\')[-1])" -Members "$($_.NestedMember)"
# Option 2: Remove control rights (same as above)

"@ })

# STEP 4: Audit current state
Write-Host "Current ACL on sensitive groups:"
@('Domain Admins', 'Enterprise Admins', 'Administrators') | ForEach-Object {
    Write-Host "`n=== `$_ ==="
    Get-ADGroup `$_ | Get-Acl | Select-Object -ExpandProperty Access |
        Where-Object { `$_.ActiveDirectoryRights -match 'Write|GenericAll|Owner' } |
        Format-Table IdentityReference, ActiveDirectoryRights
}

# STEP 5: Set up ongoing monitoring
# Monitor for ACL changes on sensitive groups
# Event ID 5136 (Directory Service Changes)
# Filter for: Domain Admins, Enterprise Admins, Schema Admins

"@
            return $commands
        }
    }
}

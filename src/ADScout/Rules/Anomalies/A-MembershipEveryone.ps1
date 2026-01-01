@{
    Id          = 'A-MembershipEveryone'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Everyone or Anonymous in Sensitive Groups'
    Description = 'Detects when Everyone, Anonymous Logon, or Authenticated Users has been added to sensitive groups such as Pre-Windows 2000 Compatible Access. This enables anonymous enumeration of the domain and is a critical security misconfiguration often introduced during domain setup.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Pre-Windows 2000 Compatibility'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-g--securing-administrators-groups-in-active-directory' }
        @{ Title = 'Anonymous Enumeration'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
        @{ Title = 'PingCastle Rule A-MembershipEveryone'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0007', 'TA0001')  # Discovery, Initial Access
        Techniques = @('T1087.002', 'T1590.001')  # Account Discovery: Domain Account, Gather Victim Network Information
    }

    CIS   = @('5.3.1')
    STIG  = @('V-63337', 'V-63367')
    ANSSI = @('vuln1_anonymous_enum', 'vuln2_prewin2000')
    NIST  = @('AC-3', 'AC-14')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Sensitive groups to check
        $sensitiveGroups = @(
            'Pre-Windows 2000 Compatible Access',
            'Windows Authorization Access Group',
            'Access Control Assistance Operators',
            'Distributed COM Users',
            'Remote Desktop Users',
            'Remote Management Users'
        )

        # Principals that should NOT be in these groups
        $dangerousPrincipals = @(
            'Everyone',
            'Anonymous',
            'Anonymous Logon',
            'ANONYMOUS LOGON',
            'Authenticated Users',
            'NT AUTHORITY\ANONYMOUS LOGON',
            'S-1-1-0',      # Everyone
            'S-1-5-7',      # Anonymous Logon
            'S-1-5-11'      # Authenticated Users
        )

        try {
            foreach ($group in $Data.Groups) {
                $groupName = $group.Name

                # Check if this is a sensitive group
                $isSensitive = $sensitiveGroups | Where-Object { $groupName -match [regex]::Escape($_) }

                if (-not $isSensitive) { continue }

                # Get group members
                $members = @()
                if ($group.Members) {
                    $members = $group.Members
                } else {
                    # Try to get members via ADSI
                    try {
                        $groupDN = $group.DistinguishedName
                        $adsiGroup = [ADSI]"LDAP://$groupDN"
                        $members = @($adsiGroup.Member)
                    } catch {
                        # Fallback: try Get-ADGroupMember if available
                    }
                }

                foreach ($member in $members) {
                    $memberName = $member
                    if ($member -is [System.DirectoryServices.DirectoryEntry]) {
                        $memberName = $member.Name
                    }

                    # Check if member is a dangerous principal
                    $isDangerous = $false
                    foreach ($dp in $dangerousPrincipals) {
                        if ($memberName -match [regex]::Escape($dp) -or $memberName -eq $dp) {
                            $isDangerous = $true
                            break
                        }
                    }

                    if ($isDangerous) {
                        $severity = 'Critical'
                        $impact = 'Anonymous users can enumerate domain'

                        if ($groupName -match 'Pre-Windows 2000') {
                            $impact = 'Anonymous users can enumerate all users, groups, and computers in the domain'
                        }

                        $findings += [PSCustomObject]@{
                            GroupName           = $groupName
                            DangerousMember     = $memberName
                            GroupDN             = $group.DistinguishedName
                            Severity            = $severity
                            Impact              = $impact
                            Risk                = 'Enables anonymous reconnaissance of Active Directory'
                            AttackScenario      = 'Attacker can enumerate domain without credentials using null session'
                        }
                    }
                }
            }

            # Direct check for Pre-Windows 2000 Compatible Access
            try {
                $preWin2000 = [ADSI]"LDAP://CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$($Domain.DistinguishedName)"
                if ($preWin2000.Path) {
                    foreach ($memberDN in $preWin2000.Member) {
                        $memberName = ($memberDN -split ',')[0] -replace 'CN=', ''

                        foreach ($dp in $dangerousPrincipals) {
                            if ($memberName -match [regex]::Escape($dp)) {
                                # Avoid duplicates
                                $existing = $findings | Where-Object {
                                    $_.GroupName -match 'Pre-Windows 2000' -and
                                    $_.DangerousMember -match [regex]::Escape($memberName)
                                }

                                if (-not $existing) {
                                    $findings += [PSCustomObject]@{
                                        GroupName           = 'Pre-Windows 2000 Compatible Access'
                                        DangerousMember     = $memberName
                                        GroupDN             = $preWin2000.distinguishedName.ToString()
                                        Severity            = 'Critical'
                                        Impact              = 'Anonymous users can enumerate all users, groups, and computers'
                                        Risk                = 'Domain enumeration without authentication'
                                        AttackScenario      = 'net user /domain, enum4linux, rpcclient null session'
                                    }
                                }
                                break
                            }
                        }
                    }
                }
            } catch {
                Write-Verbose "A-MembershipEveryone: Error checking Pre-Windows 2000 group - $_"
            }

        } catch {
            Write-Verbose "A-MembershipEveryone: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove Everyone, Anonymous Logon, and Authenticated Users from sensitive groups. For Pre-Windows 2000 Compatible Access, remove all members unless legacy application compatibility requires it.'
        Impact      = 'Medium - May break legacy applications that rely on anonymous LDAP queries. Test thoroughly before implementation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Remove Dangerous Principals from Sensitive Groups
#
# Affected groups and members:
$($Finding.Findings | ForEach-Object { "# - $($_.GroupName): $($_.DangerousMember)" } | Out-String)

# STEP 1: Remove from Pre-Windows 2000 Compatible Access
# This is the most common and critical finding

# Remove Everyone (if present)
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
    -Members "S-1-1-0" -Confirm:`$false -ErrorAction SilentlyContinue

# Remove Anonymous Logon (if present)
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
    -Members "S-1-5-7" -Confirm:`$false -ErrorAction SilentlyContinue

# Remove Authenticated Users (less common but still a risk)
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
    -Members "S-1-5-11" -Confirm:`$false -ErrorAction SilentlyContinue

# Alternative using net command:
# net localgroup "Pre-Windows 2000 Compatible Access" "Anonymous Logon" /delete
# net localgroup "Pre-Windows 2000 Compatible Access" "Everyone" /delete

# STEP 2: Verify the group is empty or contains only required members
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" |
    Select-Object Name, SamAccountName, objectClass

# STEP 3: Check other sensitive groups
$($Finding.Findings | Where-Object { $_.GroupName -notmatch 'Pre-Windows 2000' } | ForEach-Object { @"
# Remove from $($_.GroupName)
Remove-ADGroupMember -Identity "$($_.GroupName)" -Members "$($_.DangerousMember)" -Confirm:`$false
"@ })

# STEP 4: Verify anonymous enumeration is blocked
# Test from a non-domain machine:
# rpcclient -U "" -N <DC-IP> -c "enumdomusers"
# Should return: "result was NT_STATUS_ACCESS_DENIED"

# STEP 5: Additional hardening - restrict anonymous access via GPO
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# - "Network access: Allow anonymous SID/Name translation" = Disabled
# - "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# - "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled

"@
            return $commands
        }
    }
}

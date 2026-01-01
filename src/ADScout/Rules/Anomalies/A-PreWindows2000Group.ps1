@{
    Id          = 'A-PreWindows2000Group'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Pre-Windows 2000 Compatible Access Group'
    Description = 'Detects if the Pre-Windows 2000 Compatible Access group contains members other than Authenticated Users. This legacy group grants read access to AD attributes that can be exploited for reconnaissance and attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Pre-Windows 2000 Compatible Access'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups' }
        @{ Title = 'Anonymous Access to AD'; Url = 'https://adsecurity.org/?p=2288' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1087.002')  # Account Discovery: Domain Account
    }

    CIS   = @('2.1.2')
    STIG  = @('V-220956')
    ANSSI = @('R55')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $preWin2kGroup = Get-ADGroup -Identity "Pre-Windows 2000 Compatible Access" -Properties Members -ErrorAction SilentlyContinue

            if ($preWin2kGroup) {
                $members = Get-ADGroupMember -Identity $preWin2kGroup -ErrorAction SilentlyContinue

                # Check for dangerous members
                $dangerousMembers = $members | Where-Object {
                    $_.SamAccountName -match 'Anonymous|Everyone|Guest' -or
                    $_.objectClass -eq 'foreignSecurityPrincipal'
                }

                $authenticatedUsersPresent = $members | Where-Object {
                    $_.SamAccountName -eq 'Authenticated Users' -or
                    $_.Name -match 'S-1-5-11'  # Authenticated Users SID
                }

                if ($authenticatedUsersPresent) {
                    $findings += [PSCustomObject]@{
                        GroupName           = 'Pre-Windows 2000 Compatible Access'
                        DangerousMember     = 'Authenticated Users'
                        MemberCount         = $members.Count
                        RiskLevel           = 'High'
                        Impact              = @(
                            'Any authenticated user can read sensitive AD attributes',
                            'Enables reconnaissance of all users and groups',
                            'Exposes userPassword attribute if populated',
                            'Can enumerate service accounts for Kerberoasting'
                        ) -join '; '
                        HistoricalContext   = 'Added for NT4 compatibility - rarely needed today'
                    }
                }

                if ($dangerousMembers) {
                    foreach ($member in $dangerousMembers) {
                        $findings += [PSCustomObject]@{
                            GroupName           = 'Pre-Windows 2000 Compatible Access'
                            DangerousMember     = $member.SamAccountName
                            MemberType          = $member.objectClass
                            RiskLevel           = 'Critical'
                            Impact              = 'Anonymous/unauthenticated access to AD'
                        }
                    }
                }
            }
        }
        catch {
            # Group may not exist or cannot be queried
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove Authenticated Users from Pre-Windows 2000 Compatible Access group unless specifically required for legacy systems.'
        Impact      = 'Medium - May affect very old (NT4/2000) systems or applications'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# PRE-WINDOWS 2000 COMPATIBLE ACCESS GROUP
# ================================================================
# This legacy group grants excessive read access to AD attributes.
# By default, "Authenticated Users" is added during domain creation
# with certain compatibility options.

# Impact of having Authenticated Users in this group:
# - Any authenticated user can enumerate ALL users/groups
# - Exposes email addresses, phone numbers, etc.
# - Makes Kerberoasting easier
# - Violates least privilege principle

# ================================================================
# CURRENT MEMBERSHIP
# ================================================================

Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" | ``
    Select-Object Name, SamAccountName, objectClass

# ================================================================
# CHECK IF REMOVAL IS SAFE
# ================================================================

# Before removing, verify no legacy systems require this:
# - Windows NT 4.0 systems?
# - Very old applications using LDAP anonymous bind?
# - Legacy backup/monitoring software?

# Test in non-production first!

# ================================================================
# REMOVE AUTHENTICATED USERS
# ================================================================

# Remove Authenticated Users (most common risky member):
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" ``
    -Members "Authenticated Users" ``
    -Confirm:`$false

# Verify removal:
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access"

# ================================================================
# REMOVE ANONYMOUS LOGON (If Present)
# ================================================================

# This should NEVER be a member:
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" ``
    -Members "ANONYMOUS LOGON" ``
    -Confirm:`$false -ErrorAction SilentlyContinue

# ================================================================
# MONITOR FOR RE-ADDITION
# ================================================================

# Set up alert for group membership changes:
# Event ID 4728, 4732 - Member added to security group
# Filter for "Pre-Windows 2000 Compatible Access"

"@
            return $commands
        }
    }
}

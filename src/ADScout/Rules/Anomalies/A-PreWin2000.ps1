@{
    Id          = 'A-PreWin2000'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Pre-Windows 2000 Compatible Access Enabled'
    Description = 'The "Pre-Windows 2000 Compatible Access" group contains members (especially "Authenticated Users" or "Everyone"), allowing legacy anonymous enumeration of AD objects. This enables unauthenticated attackers to enumerate users, groups, and other AD information.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Pre-Windows 2000 Compatibility'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' }
        @{ Title = 'Anonymous Enumeration'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
        @{ Title = 'AD Security Best Practices'; Url = 'https://adsecurity.org/?p=1684' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1087.002', 'T1069.002')  # Account Discovery: Domain, Permission Groups Discovery: Domain
    }

    CIS   = @('2.3.10.2')
    STIG  = @('V-63597')
    ANSSI = @('vuln1_prewin2000')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous members that shouldn't be in Pre-Windows 2000 Compatible Access
        $dangerousMembers = @(
            'Authenticated Users',
            'Everyone',
            'Anonymous Logon',
            'ANONYMOUS LOGON'
        )

        foreach ($group in $Data) {
            if ($group.SamAccountName -eq 'Pre-Windows 2000 Compatible Access' -or
                $group.Name -eq 'Pre-Windows 2000 Compatible Access') {

                $members = @()
                if ($group.Members) { $members = $group.Members }
                elseif ($group.Member) { $members = $group.Member }

                foreach ($member in $members) {
                    $memberName = $member
                    if ($member -match 'CN=([^,]+)') {
                        $memberName = $Matches[1]
                    }
                    $memberName = $memberName.ToString()

                    # Check if this is a dangerous member
                    $isDangerous = $dangerousMembers | Where-Object {
                        $memberName -match [regex]::Escape($_)
                    }

                    if ($isDangerous) {
                        $findings += [PSCustomObject]@{
                            GroupName           = 'Pre-Windows 2000 Compatible Access'
                            MemberName          = $memberName
                            IsDangerous         = $true
                            RiskLevel           = 'High'
                            Impact              = 'Anonymous users can enumerate AD objects'
                            AttackVector        = 'net user /domain, net group /domain, ldapsearch without auth'
                            Recommendation      = 'Remove this member from the group'
                        }
                    }
                }

                break
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove "Authenticated Users" and similar entries from the Pre-Windows 2000 Compatible Access group. This group should ideally be empty in modern environments.'
        Impact      = 'Low to Medium - Very old legacy applications may break. Most modern applications do not require this compatibility.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Remove Dangerous Members from Pre-Windows 2000 Compatible Access
# Current Dangerous Members: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.MemberName)" } | Out-String)

# IMPACT ASSESSMENT:
# This group grants read access to AD to unauthenticated users
# Modern applications should NOT require this
# Legacy Windows NT/2000 era applications may be affected

# Step 1: Check current membership
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" |
    Select-Object Name, SamAccountName, objectClass

# Step 2: Remove dangerous members

# Remove Authenticated Users (most common dangerous member)
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
    -Members "S-1-5-11" -Confirm:`$false
# S-1-5-11 is the well-known SID for "Authenticated Users"

# If Everyone is present:
# Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
#     -Members "S-1-1-0" -Confirm:`$false

# Step 3: If the group needs to exist for specific applications
# Only add specific service accounts that require it, not broad groups

# Step 4: Verify the change
Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" |
    Select-Object Name, SamAccountName

# Step 5: Test anonymous enumeration is blocked
# From a non-domain-joined machine, try:
# net use \\DC\IPC$ "" /user:""
# net view \\DC
# If properly secured, these should fail

# Alternative: Use PowerShell from non-joined machine
# Get-ADUser -Filter * -Server DC01  # Should require credentials

"@
            return $commands
        }
    }
}

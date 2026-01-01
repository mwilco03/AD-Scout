<#
.SYNOPSIS
    Detects groups nested inside privileged groups.

.DESCRIPTION
    Identifies groups that are members of highly privileged groups like
    Domain Admins or Enterprise Admins. Nested groups create hidden
    privilege paths that are easy to overlook during access reviews.

.NOTES
    Rule ID    : PA-NestedPrivilegedGroup
    Category   : PrivilegedAccounts
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "PA-NestedPrivilegedGroup"
    Name        = "Nested Privileged Group Membership"
    Category    = "PrivilegedAccounts"
    Model       = "GroupHierarchy"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 8
    MaxPoints   = 80
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002", "T1069.002")  # Valid Accounts, Permission Groups Discovery
    CIS         = @()
    STIG        = @()
    ANSSI       = @("R29")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Known privileged group patterns
        $privilegedGroupPatterns = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Backup Operators'
            'Server Operators'
        )

        # Find privileged groups
        $privilegedGroups = $ADData.Groups | Where-Object {
            $groupName = $_.Name
            $privilegedGroupPatterns | Where-Object { $groupName -like "*$_*" }
        }

        $findings = @()

        foreach ($privGroup in $privilegedGroups) {
            # Get members that are groups (not users)
            $nestedGroups = @($privGroup.Members) | Where-Object {
                $_ -match '^CN=.*,(?:OU|CN)=.*,DC='  -and
                $_ -notmatch ',CN=Users,' -and
                # Check if it's a group by looking in Groups collection
                ($ADData.Groups | Where-Object { $_.DistinguishedName -eq $_ })
            }

            foreach ($nestedDN in $nestedGroups) {
                $nestedGroup = $ADData.Groups | Where-Object { $_.DistinguishedName -eq $nestedDN }

                if ($nestedGroup) {
                    $findings += [PSCustomObject]@{
                        ParentGroup          = $privGroup.Name
                        ParentGroupDN        = $privGroup.DistinguishedName
                        NestedGroup          = $nestedGroup.Name
                        NestedGroupDN        = $nestedGroup.DistinguishedName
                        NestedGroupMembers   = $nestedGroup.MemberCount
                        Description          = $nestedGroup.Description
                        Severity             = if ($privGroup.Name -match 'Domain Admins|Enterprise Admins') { 'Critical' } else { 'High' }
                    }
                }
            }
        }

        return $findings
    }

    # === OUTPUT ===
    DetailProperties = @("NestedGroup", "ParentGroup", "NestedGroupMembers", "Severity")
    DetailFormat     = "{NestedGroup} nested in {ParentGroup} ({NestedGroupMembers} members)"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Nested group detected in privileged group
# Parent: $($Finding.ParentGroup)
# Nested: $($Finding.NestedGroup) ($($Finding.NestedGroupMembers) members)

# STEP 1: Review who gets privilege through this nesting
Get-ADGroupMember -Identity '$($Finding.NestedGroup)' -Recursive |
    Select-Object SamAccountName, ObjectClass, DistinguishedName

# STEP 2: If nesting is not needed, remove it
Remove-ADGroupMember -Identity '$($Finding.ParentGroup)' -Members '$($Finding.NestedGroupDN)' -Confirm

# STEP 3: If some users need the privilege, add them directly
# Add-ADGroupMember -Identity '$($Finding.ParentGroup)' -Members 'specific_user'

# Best practice: Avoid group nesting in privileged groups
# - Direct membership is easier to audit
# - Nested groups create hidden privilege paths
# - Changes to nested groups silently expand privileges

"@
    }

    # === DOCUMENTATION ===
    Description = "Groups nested inside privileged groups create hidden privilege paths."

    TechnicalExplanation = @"
Group nesting in privileged groups is problematic because:

1. Hidden privilege escalation
   - Users in nested groups inherit admin rights
   - Not immediately visible in the privileged group's member list
   - Easy to overlook during access reviews

2. Difficult to audit
   - "Who are the Domain Admins?" requires recursive enumeration
   - Simple membership lists miss nested members
   - Compliance audits may miss these users

3. Scope creep risk
   - Changes to nested groups silently expand privileges
   - Adding users to "IT Support" might grant Domain Admin
   - No notification or approval process triggered

4. Attack surface
   - Attackers look for nested group paths
   - Compromising any group in the chain grants privilege
   - BloodHound specifically maps these paths

Example attack path:
   Attacker → compromises user in "IT Helpdesk"
   IT Helpdesk → nested in "IT Department"
   IT Department → nested in "Domain Admins"
   Result → Attacker is now Domain Admin

Best practice: Only add individual users to privileged groups,
never other groups.
"@

    References = @(
        "https://attack.mitre.org/techniques/T1069/002/"
        "https://adsecurity.org/?p=3700"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Groups -and $ADData.Groups.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}

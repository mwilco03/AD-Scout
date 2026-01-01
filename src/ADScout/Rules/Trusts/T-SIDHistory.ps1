<#
.SYNOPSIS
    Detects accounts with SID History that may enable privilege escalation.

.DESCRIPTION
    SID History is used in domain migrations but can be abused to maintain hidden
    access or escalate privileges. Accounts with SID History from privileged
    accounts are especially dangerous.

.NOTES
    Rule ID    : T-SIDHistory
    Category   : Trusts
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'T-SIDHistory'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'Accounts with SID History'
    Description = 'Identifies user and computer accounts with SID History attributes, which can be used for privilege escalation or persistence in domain environments.'
    Severity    = 'High'
    Weight      = 45
    DataSource  = 'Users,Computers'

    References  = @(
        @{ Title = 'SID History Attack'; Url = 'https://attack.mitre.org/techniques/T1134/005/' }
        @{ Title = 'SID History Persistence'; Url = 'https://adsecurity.org/?p=1772' }
        @{ Title = 'Mimikatz SID History Injection'; Url = 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-sid' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1134.005')  # SID-History Injection
    }

    CIS   = @('5.3')
    STIG  = @('V-8527')
    ANSSI = @('R16')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get the domain SID for comparison
        $domainSID = $Domain.DomainSID
        if (-not $domainSID) {
            try {
                $domainSID = (Get-ADDomain).DomainSID.Value
            } catch {
                $domainSID = $null
            }
        }

        # Well-known privileged RIDs
        $privilegedRIDs = @(
            '-500'   # Administrator
            '-502'   # krbtgt
            '-512'   # Domain Admins
            '-516'   # Domain Controllers
            '-518'   # Schema Admins
            '-519'   # Enterprise Admins
            '-520'   # Group Policy Creator Owners
        )

        # Check users
        if ($Data.Users) {
            foreach ($user in $Data.Users) {
                $sidHistory = $user.SIDHistory
                if (-not $sidHistory -or $sidHistory.Count -eq 0) { continue }

                foreach ($historySID in $sidHistory) {
                    $sidString = if ($historySID -is [string]) { $historySID } else { $historySID.Value }
                    if (-not $sidString) { continue }

                    # Determine if this is a privileged SID
                    $isPrivileged = $false
                    $privilegeType = 'Unknown'

                    foreach ($rid in $privilegedRIDs) {
                        if ($sidString -like "*$rid") {
                            $isPrivileged = $true
                            $privilegeType = switch ($rid) {
                                '-500' { 'Administrator' }
                                '-502' { 'krbtgt' }
                                '-512' { 'Domain Admins' }
                                '-516' { 'Domain Controllers' }
                                '-518' { 'Schema Admins' }
                                '-519' { 'Enterprise Admins' }
                                '-520' { 'GPO Creators' }
                            }
                            break
                        }
                    }

                    # Check if SID is from current domain (more suspicious)
                    $isCurrentDomain = $domainSID -and $sidString -like "$domainSID*"

                    # Determine source domain
                    $sourceDomain = 'Unknown/External'
                    if ($isCurrentDomain) {
                        $sourceDomain = 'Current Domain (SUSPICIOUS)'
                    } else {
                        # Try to resolve the SID's domain
                        try {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
                            $domainPart = $sidString -replace '-\d+$'
                            $sourceDomain = "Foreign Domain: $domainPart"
                        } catch {
                            # Keep Unknown
                        }
                    }

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'User'
                        SamAccountName      = $user.SamAccountName
                        DisplayName         = $user.DisplayName
                        Enabled             = $user.Enabled
                        AdminCount          = $user.AdminCount
                        HistorySID          = $sidString
                        SourceDomain        = $sourceDomain
                        IsCurrentDomain     = $isCurrentDomain
                        IsPrivilegedSID     = $isPrivileged
                        PrivilegeType       = $privilegeType
                        RiskLevel           = if ($isPrivileged -or $isCurrentDomain) { 'Critical' } else { 'High' }
                        AttackVector        = if ($isPrivileged) {
                            "Grants $privilegeType rights when accessing resources"
                        } elseif ($isCurrentDomain) {
                            'Same-domain SID History is unusual and may indicate attack'
                        } else {
                            'May provide elevated access in trusted domain'
                        }
                        DistinguishedName   = $user.DistinguishedName
                    }
                }
            }
        }

        # Check computers
        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                $sidHistory = $computer.SIDHistory
                if (-not $sidHistory -or $sidHistory.Count -eq 0) { continue }

                foreach ($historySID in $sidHistory) {
                    $sidString = if ($historySID -is [string]) { $historySID } else { $historySID.Value }
                    if (-not $sidString) { continue }

                    $isCurrentDomain = $domainSID -and $sidString -like "$domainSID*"

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'Computer'
                        SamAccountName      = $computer.Name
                        DisplayName         = $computer.DNSHostName
                        Enabled             = $computer.Enabled
                        AdminCount          = 'N/A'
                        HistorySID          = $sidString
                        SourceDomain        = if ($isCurrentDomain) { 'Current Domain (SUSPICIOUS)' } else { 'External Domain' }
                        IsCurrentDomain     = $isCurrentDomain
                        IsPrivilegedSID     = $false
                        PrivilegeType       = 'N/A'
                        RiskLevel           = if ($isCurrentDomain) { 'Critical' } else { 'Medium' }
                        AttackVector        = 'Computer SID History may enable cross-domain resource access'
                        DistinguishedName   = $computer.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove SID History from accounts unless required for ongoing migration. SID History from the current domain or containing privileged SIDs should be removed immediately.'
        Impact      = 'High - May affect access to resources in migrated domains. Verify business need before removal.'
        Script      = {
            param($Finding, $Domain)

            $criticalFindings = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'Critical' }
            $highFindings = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'High' }

            $commands = @"
#############################################################################
# SID History Remediation
#############################################################################
#
# SID History abuse allows:
# - Privilege escalation via privileged SIDs
# - Persistent backdoor access
# - Cross-domain lateral movement
# - Bypassing access controls
#
# CRITICAL - Same-domain or privileged SID History (IMMEDIATE ACTION):
$($criticalFindings | ForEach-Object { "# - $($_.SamAccountName): $($_.HistorySID) ($($_.PrivilegeType))" } | Out-String)

# HIGH - External domain SID History (REVIEW REQUIRED):
$($highFindings | ForEach-Object { "# - $($_.SamAccountName): $($_.HistorySID)" } | Out-String)

#############################################################################
# Remove SID History
#############################################################################

# CRITICAL: Remove same-domain SID History immediately
# This is almost always an indicator of compromise

"@

            foreach ($item in $criticalFindings) {
                if ($item.ObjectType -eq 'User') {
                    $commands += @"

# Remove SID History from user: $($item.SamAccountName)
# SID to remove: $($item.HistorySID)
# Risk: $($item.AttackVector)
Set-ADUser -Identity '$($item.SamAccountName)' -Remove @{sidHistory='$($item.HistorySID)'}

"@
                } else {
                    $commands += @"

# Remove SID History from computer: $($item.SamAccountName)
Set-ADComputer -Identity '$($item.SamAccountName)' -Remove @{sidHistory='$($item.HistorySID)'}

"@
                }
            }

            $commands += @"

#############################################################################
# For External Domain SID History
#############################################################################

# Before removing, verify:
# 1. Migration is complete
# 2. User no longer needs access to old domain resources
# 3. All resource permissions have been updated

# Example - Remove after verification:
# Set-ADUser -Identity 'jsmith' -Remove @{sidHistory='S-1-5-21-olddomain-1001'}

#############################################################################
# Prevent SID History Injection Attacks
#############################################################################

# 1. Enable SID filtering on trusts (blocks SID History across trusts)
# netdom trust /domain:trusting.domain /enablesidhistory:no

# 2. Monitor for SID History changes
# Event ID 4765 - SID History added to account
# Event ID 4766 - Attempt to add SID History to account failed

# Create alert for these events:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4765,4766} -MaxEvents 100

# 3. Regular audit of SID History
Get-ADUser -Filter { SidHistory -like '*' } -Properties SidHistory |
    Select-Object SamAccountName, @{N='SIDHistory';E={`$_.SidHistory -join ', '}}

Get-ADComputer -Filter { SidHistory -like '*' } -Properties SidHistory |
    Select-Object Name, @{N='SIDHistory';E={`$_.SidHistory -join ', '}}

#############################################################################
# Detection of SID History Injection
#############################################################################

# If same-domain SID History exists, assume compromise:
# 1. Reset affected user passwords
# 2. Review user activity logs
# 3. Check for additional persistence mechanisms
# 4. Consider resetting krbtgt if Domain Admin SID was injected

"@
            return $commands
        }
    }
}

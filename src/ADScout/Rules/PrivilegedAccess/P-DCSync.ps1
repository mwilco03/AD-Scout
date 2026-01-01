<#
.SYNOPSIS
    Detects accounts with DCSync rights that can extract all domain credentials.

.DESCRIPTION
    Identifies principals with Replicating Directory Changes and Replicating Directory Changes All
    rights on the domain root. These rights allow performing DCSync attacks to extract all password
    hashes from Active Directory, including krbtgt.

.NOTES
    Rule ID    : P-DCSync
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-DCSync'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'DCSync Attack - Replication Rights on Non-Admin Accounts'
    Description = 'Identifies accounts with DCSync capabilities (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All). These rights allow extracting all password hashes from Active Directory.'
    Severity    = 'Critical'
    Weight      = 100
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'DCSync - MITRE ATT&CK'; Url = 'https://attack.mitre.org/techniques/T1003/006/' }
        @{ Title = 'Mimikatz DCSync Usage'; Url = 'https://adsecurity.org/?p=1729' }
        @{ Title = 'Detecting DCSync Attacks'; Url = 'https://www.microsoft.com/en-us/security/blog/2020/12/21/detecting-dcsync-attacks-with-microsoft-defender-for-identity/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.006')  # OS Credential Dumping: DCSync
    }

    CIS   = @('5.18')
    STIG  = @('V-63441', 'V-36432')
    ANSSI = @('vuln1_dcsync')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # DCSync required GUIDs
        $replicationRights = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        }

        # Expected privileged principals that legitimately have these rights
        $legitimatePrincipals = @(
            'Domain Controllers'
            'Enterprise Domain Controllers'
            'Administrators'
            'Domain Admins'
            'Enterprise Admins'
            'SYSTEM'
            'ENTERPRISE DOMAIN CONTROLLERS'
            'Cloneable Domain Controllers'
        )

        # Well-known privileged SIDs
        $legitimateSIDs = @(
            'S-1-5-32-544'      # BUILTIN\Administrators
            'S-1-5-9'           # Enterprise Domain Controllers
            'S-1-5-18'          # Local System
        )

        try {
            # Get domain DN
            $domainDN = $null
            if ($Domain.DistinguishedName) {
                $domainDN = $Domain.DistinguishedName
            } elseif ($Domain.Name) {
                $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
            }

            if (-not $domainDN) {
                return @()
            }

            # Get domain object ACL
            $domainObj = [ADSI]"LDAP://$domainDN"
            $acl = $domainObj.ObjectSecurity

            # Track principals with replication rights
            $principalsWithRights = @{}

            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $identity = $ace.IdentityReference.Value
                $objectType = $ace.ObjectType.ToString().ToLower()

                # Check if this is a replication right
                if ($replicationRights.ContainsKey($objectType)) {
                    if (-not $principalsWithRights.ContainsKey($identity)) {
                        $principalsWithRights[$identity] = @{
                            Rights = @()
                            SID = $null
                        }
                    }
                    $principalsWithRights[$identity].Rights += $replicationRights[$objectType]

                    # Try to get SID
                    if (-not $principalsWithRights[$identity].SID) {
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                            $principalsWithRights[$identity].SID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch {
                            $principalsWithRights[$identity].SID = 'Unknown'
                        }
                    }
                }

                # Also check for GenericAll which includes replication rights
                $rights = $ace.ActiveDirectoryRights.ToString()
                if ($rights -match 'GenericAll' -and $objectType -eq '00000000-0000-0000-0000-000000000000') {
                    if (-not $principalsWithRights.ContainsKey($identity)) {
                        $principalsWithRights[$identity] = @{
                            Rights = @('GenericAll (includes DCSync)')
                            SID = $null
                        }
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                            $principalsWithRights[$identity].SID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch {
                            $principalsWithRights[$identity].SID = 'Unknown'
                        }
                    }
                }
            }

            # Evaluate each principal
            foreach ($principal in $principalsWithRights.Keys) {
                $info = $principalsWithRights[$principal]
                $sid = $info.SID
                $rights = $info.Rights

                # Check if principal can perform full DCSync (needs both Get-Changes and Get-Changes-All)
                $canDCSync = ($rights -contains 'DS-Replication-Get-Changes' -and $rights -contains 'DS-Replication-Get-Changes-All') -or
                             ($rights -contains 'GenericAll (includes DCSync)')

                if (-not $canDCSync) { continue }

                # Check if this is a legitimate principal
                $isLegitimate = $false

                # Check by name
                foreach ($legitName in $legitimatePrincipals) {
                    if ($principal -like "*\$legitName" -or $principal -eq $legitName -or $principal -like "*$legitName*") {
                        $isLegitimate = $true
                        break
                    }
                }

                # Check by SID
                if (-not $isLegitimate -and $sid) {
                    foreach ($legitSID in $legitimateSIDs) {
                        if ($sid -eq $legitSID -or $sid -like "$legitSID*") {
                            $isLegitimate = $true
                            break
                        }
                    }

                    # Check for domain-relative SIDs (Domain Admins = -512, Enterprise Admins = -519)
                    if ($sid -match '-512$' -or $sid -match '-519$' -or $sid -match '-516$' -or $sid -match '-498$') {
                        $isLegitimate = $true
                    }
                }

                if (-not $isLegitimate) {
                    $findings += [PSCustomObject]@{
                        Principal           = $principal
                        SID                 = $sid
                        ReplicationRights   = ($rights -join ', ')
                        CanExtractHashes    = $true
                        RiskLevel           = 'Critical'
                        AttackDescription   = 'Can use Mimikatz or similar tools to extract all password hashes including krbtgt'
                        ImmediateRisk       = 'Domain compromise possible. Golden ticket attack enabled.'
                    }
                }
            }

        } catch {
            # Log error but don't fail
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove DCSync rights from unauthorized principals immediately. This is a critical finding that enables full domain compromise.'
        Impact      = 'Critical - These rights should only exist on Domain Controllers and specific replication accounts.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# CRITICAL: DCSync Rights Detected on Non-Admin Accounts
#############################################################################
#
# The following principals have DCSync capabilities and can extract ALL
# password hashes from Active Directory, including:
# - All user passwords
# - krbtgt (enables Golden Ticket attacks)
# - Computer account passwords
# - Service account passwords
#
# IMMEDIATE ACTION REQUIRED
#############################################################################

# Affected Principals:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal): $($_.ReplicationRights)" } | Out-String)

# Step 1: Verify the principals and their legitimacy
`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-Acl "AD:\`$domainDN"

# View current DCSync capable principals
`$replicationGUIDs = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
)

Write-Host "Current principals with replication rights:" -ForegroundColor Yellow
`$acl.Access | Where-Object {
    `$_.ObjectType -in `$replicationGUIDs
} | Select-Object IdentityReference, ObjectType, AccessControlType | Format-Table

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove DCSync rights from: $($item.Principal)
# SID: $($item.SID)
#
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)' -and
    `$_.ObjectType -in `$replicationGUIDs
}
foreach (`$ace in `$aceToRemove) {
    `$acl.RemoveAccessRule(`$ace)
}
Set-Acl "AD:\`$domainDN" `$acl

"@
            }

            $commands += @"

#############################################################################
# POST-REMEDIATION: Assume Breach Protocol
#############################################################################
#
# If these rights were granted by an attacker, assume they have already:
# 1. Extracted all password hashes
# 2. Created Golden Tickets
# 3. Established persistence
#
# Recommended actions:
# 1. Reset the krbtgt password TWICE (wait for replication between resets)
# 2. Reset all privileged account passwords
# 3. Review all security logs for DCSync events (Event ID 4662)
# 4. Check for unauthorized scheduled tasks and services
# 5. Review Azure AD Connect and other sync accounts
#
# Monitor for DCSync activity:
# Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} |
#     Where-Object { `$_.Message -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }

"@
            return $commands
        }
    }
}

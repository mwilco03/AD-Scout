@{
    Id          = 'P-DCReplicationRights'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'DCSync Attack Risk - Replication Rights'
    Description = 'Detects non-Domain Controller accounts with directory replication rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All). These rights allow performing DCSync attacks to extract all password hashes from AD, including the KRBTGT hash.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'ACLs'

    References  = @(
        @{ Title = 'DCSync Attack'; Url = 'https://attack.mitre.org/techniques/T1003/006/' }
        @{ Title = 'Mimikatz DCSync'; Url = 'https://adsecurity.org/?p=1729' }
        @{ Title = 'Detecting DCSync'; Url = 'https://blog.stealthbits.com/detecting-dcsync-attacks-with-stealthdefend/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.006')  # OS Credential Dumping: DCSync
    }

    CIS   = @('5.4.6')
    STIG  = @('V-220935')
    ANSSI = @('R44', 'vuln1_dcsync')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # DCSync requires these rights on the domain NC:
        # - DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
        # - DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

        # Expected to have these rights:
        # - Domain Controllers
        # - Enterprise Domain Controllers
        # - Domain Admins
        # - Enterprise Admins
        # - Administrators

        $expectedPrincipals = @(
            'Domain Controllers',
            'Enterprise Domain Controllers',
            'ENTERPRISE DOMAIN CONTROLLERS',
            'Domain Admins',
            'Enterprise Admins',
            'Administrators',
            'SYSTEM',
            'NT AUTHORITY\SYSTEM',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
        )

        # Check domain ACLs for replication rights
        if ($Data.DomainACLs) {
            foreach ($ace in $Data.DomainACLs) {
                # Check for replication rights
                $hasReplicationRights = $false
                $replicationRights = @()

                if ($ace.ObjectType -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') {
                    $hasReplicationRights = $true
                    $replicationRights += 'DS-Replication-Get-Changes'
                }
                if ($ace.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
                    $hasReplicationRights = $true
                    $replicationRights += 'DS-Replication-Get-Changes-All'
                }
                if ($ace.ActiveDirectoryRights -match 'GenericAll|ExtendedRight' -and
                    -not $ace.ObjectType) {
                    # GenericAll includes all extended rights
                    $hasReplicationRights = $true
                    $replicationRights += 'Full Control (includes replication)'
                }

                if ($hasReplicationRights) {
                    # Check if this is an expected principal
                    $isExpected = $false
                    foreach ($expected in $expectedPrincipals) {
                        if ($ace.IdentityReference -match $expected) {
                            $isExpected = $true
                            break
                        }
                    }

                    if (-not $isExpected) {
                        $findings += [PSCustomObject]@{
                            Principal               = $ace.IdentityReference
                            ReplicationRights       = ($replicationRights -join ', ')
                            AccessControlType       = $ace.AccessControlType
                            IsInherited             = $ace.IsInherited
                            ObjectDN                = $ace.DistinguishedName
                            RiskLevel               = 'Critical'
                            AttackCapability        = @(
                                'Extract ALL password hashes from AD',
                                'Extract KRBTGT hash (Golden Ticket)',
                                'Extract all user NTLM hashes',
                                'Complete domain compromise'
                            ) -join '; '
                            AttackCommand           = 'mimikatz "lsadump::dcsync /domain:domain.com /all /csv"'
                            IsExpectedPrincipal     = $false
                        }
                    }
                }
            }
        }

        # Also check for users with replication rights via group membership
        foreach ($user in $Data.Users) {
            if (-not $user.Enabled) { continue }

            # Check if user has direct replication rights or concerning group memberships
            $hasDCRights = $false

            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    if ($group -match 'Domain Admins|Enterprise Admins|Replicating Directory Changes') {
                        # These are expected - but flag if service account
                        if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                            $findings += [PSCustomObject]@{
                                Principal               = $user.SamAccountName
                                ReplicationRights       = 'Via group membership'
                                GroupMembership         = $group
                                IsServiceAccount        = $true
                                SPNs                    = ($user.ServicePrincipalNames -join '; ')
                                RiskLevel               = 'High'
                                Concern                 = 'Service account in admin group - can DCSync if compromised'
                                IsExpectedPrincipal     = $false
                            }
                        }
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove replication rights from non-DC accounts. Audit all accounts with these rights regularly.'
        Impact      = 'Low - Unless account legitimately needs replication rights'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: DCSYNC ATTACK RISK
# ================================================================
# DCSync allows extracting ALL password hashes from AD without
# accessing a DC directly. Only Domain Controllers should have
# replication rights on the domain naming context.

# Attack impact:
# - Extract every password hash in the domain
# - Extract KRBTGT hash = Golden Ticket = permanent access
# - Complete domain compromise

# ================================================================
# FIND ALL ACCOUNTS WITH REPLICATION RIGHTS
# ================================================================

# PowerShell method:
`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-ACL "AD:`$domainDN"

# Replication right GUIDs:
`$getChanges = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
`$getChangesAll = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

`$acl.Access | Where-Object {
    `$_.ObjectType -eq `$getChanges -or
    `$_.ObjectType -eq `$getChangesAll -or
    `$_.ActiveDirectoryRights -match 'GenericAll'
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType

# ================================================================
# REMOVE UNAUTHORIZED REPLICATION RIGHTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove replication rights from: $($item.Principal)
# Current rights: $($item.ReplicationRights)

`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-ACL "AD:`$domainDN"

# Find and remove the ACE:
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference -match '$($item.Principal)' -and
    (`$_.ObjectType -eq `$getChanges -or `$_.ObjectType -eq `$getChangesAll)
}
if (`$aceToRemove) {
    `$acl.RemoveAccessRule(`$aceToRemove)
    Set-ACL "AD:`$domainDN" -AclObject `$acl
}

"@
            }

            $commands += @"

# ================================================================
# DETECTION: MONITOR FOR DCSYNC ATTACKS
# ================================================================

# Event ID 4662 - Operation performed on AD object
# Filter for:
# - Object Type: domainDNS
# - Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} or {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
# - Account Name: NOT a Domain Controller

# Advanced threat detection query (for SIEM):
# EventID=4662 AND ObjectType="domainDNS" AND Properties contains "1131f6a*"
# AND AccountName NOT IN (Domain Controllers list)

# ================================================================
# ALTERNATIVE: DETECT VIA NETWORK
# ================================================================

# DCSync uses DRS (Directory Replication Service) on RPC
# Monitor for DsGetNCChanges calls from non-DC sources
# Tools: Zeek/Bro scripts, Microsoft ATA/Defender for Identity

"@
            return $commands
        }
    }
}

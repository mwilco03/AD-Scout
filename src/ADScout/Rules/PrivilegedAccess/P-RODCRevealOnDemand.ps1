@{
    Id          = 'P-RODCRevealOnDemand'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'RODC Allowed Password Replication Policy Issues'
    Description = 'Detects when the Allowed RODC Password Replication Group contains accounts, or when the Denied RODC Password Replication Group is missing critical accounts. RODCs should not cache privileged account passwords.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'RODC Password Replication'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-operations-for-read-only-domain-controllers' }
        @{ Title = 'RODC Security'; Url = 'https://adsecurity.org/?p=3592' }
        @{ Title = 'PingCastle Rule P-RODCRevealOnDemand'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1003.003', 'T1078.002')  # OS Credential Dumping: NTDS, Valid Accounts
    }

    CIS   = @()  # RODC password policy not covered in CIS benchmarks
    STIG  = @()  # RODC STIGs are AD-version specific
    ANSSI = @()
    NIST  = @('AC-3', 'IA-5')  # Access Enforcement, Authenticator Management

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Groups to check
        $allowedGroupName = 'Allowed RODC Password Replication Group'
        $deniedGroupName = 'Denied RODC Password Replication Group'

        # Accounts that MUST be in Denied group
        $requiredDeniedAccounts = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'krbtgt'
        )

        try {
            # Check Allowed RODC Password Replication Group
            $allowedGroup = $Data.Groups | Where-Object { $_.Name -eq $allowedGroupName } | Select-Object -First 1

            if (-not $allowedGroup) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $groupDN = "CN=$allowedGroupName,CN=Users,$domainDN"
                    $adsiGroup = [ADSI]"LDAP://$groupDN"
                    if ($adsiGroup.Path) {
                        $allowedGroup = @{
                            Name = $allowedGroupName
                            DistinguishedName = $adsiGroup.distinguishedName.ToString()
                            Members = @($adsiGroup.Member)
                        }
                    }
                } catch { }
            }

            if ($allowedGroup -and $allowedGroup.Members -and $allowedGroup.Members.Count -gt 0) {
                $memberNames = @()
                foreach ($member in $allowedGroup.Members) {
                    if ($member -is [string]) {
                        $memberName = ($member -split ',')[0] -replace 'CN=', ''
                        $memberNames += $memberName
                    } else {
                        $memberNames += $member.ToString()
                    }
                }

                $findings += [PSCustomObject]@{
                    Group               = $allowedGroupName
                    Issue               = 'Group is not empty'
                    MemberCount         = $allowedGroup.Members.Count
                    Members             = ($memberNames | Select-Object -First 10) -join ', '
                    Severity            = 'High'
                    Risk                = 'Accounts in this group have passwords cached on all RODCs'
                    Impact              = 'RODC compromise exposes cached account passwords'
                    Recommendation      = 'Remove all members; use per-RODC msDS-RevealOnDemandGroup instead'
                }
            }

            # Check Denied RODC Password Replication Group
            $deniedGroup = $Data.Groups | Where-Object { $_.Name -eq $deniedGroupName } | Select-Object -First 1

            if (-not $deniedGroup) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $groupDN = "CN=$deniedGroupName,CN=Users,$domainDN"
                    $adsiGroup = [ADSI]"LDAP://$groupDN"
                    if ($adsiGroup.Path) {
                        $deniedGroup = @{
                            Name = $deniedGroupName
                            DistinguishedName = $adsiGroup.distinguishedName.ToString()
                            Members = @($adsiGroup.Member)
                        }
                    }
                } catch { }
            }

            if ($deniedGroup) {
                $deniedMembers = @()
                if ($deniedGroup.Members) {
                    foreach ($member in $deniedGroup.Members) {
                        if ($member -is [string]) {
                            $memberName = ($member -split ',')[0] -replace 'CN=', ''
                            $deniedMembers += $memberName
                        } else {
                            $deniedMembers += $member.ToString()
                        }
                    }
                }

                # Check for missing required accounts
                $missingAccounts = @()
                foreach ($required in $requiredDeniedAccounts) {
                    $found = $deniedMembers | Where-Object { $_ -match [regex]::Escape($required) }
                    if (-not $found) {
                        $missingAccounts += $required
                    }
                }

                if ($missingAccounts.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Group               = $deniedGroupName
                        Issue               = 'Missing required privileged accounts'
                        MissingAccounts     = $missingAccounts -join ', '
                        MissingCount        = $missingAccounts.Count
                        CurrentMembers      = ($deniedMembers | Select-Object -First 5) -join ', '
                        Severity            = 'Critical'
                        Risk                = 'Privileged account passwords could be cached on RODCs'
                        Impact              = 'RODC compromise could yield Domain Admin credentials'
                        Recommendation      = 'Add all privileged accounts to Denied group'
                    }
                }
            }

            # Check individual RODC msDS-RevealOnDemandGroup settings
            if ($Data.DomainControllers) {
                foreach ($dc in $Data.DomainControllers) {
                    if ($dc.IsReadOnly -eq $true) {
                        # Check msDS-Reveal-OnDemandGroup on the RODC
                        if ($dc.RevealOnDemandGroup -and $dc.RevealOnDemandGroup.Count -gt 0) {
                            # Check if any privileged accounts are included
                            foreach ($account in $dc.RevealOnDemandGroup) {
                                foreach ($privileged in $requiredDeniedAccounts) {
                                    if ($account -match [regex]::Escape($privileged)) {
                                        $findings += [PSCustomObject]@{
                                            Group               = 'msDS-Reveal-OnDemandGroup'
                                            RODC                = $dc.Name
                                            Issue               = 'Privileged account in RODC reveal list'
                                            PrivilegedAccount   = $privileged
                                            Severity            = 'Critical'
                                            Risk                = 'Privileged password cached on this RODC'
                                            Impact              = 'RODC compromise yields domain admin'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "P-RODCRevealOnDemand: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Empty the Allowed RODC Password Replication Group and ensure all privileged accounts are in the Denied group. Use per-RODC settings for granular control.'
        Impact      = 'Medium - Users not in allowed lists will need to authenticate to a writable DC.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# RODC Password Replication Policy Remediation
#
# Issues found:
$($Finding.Findings | ForEach-Object { "# - $($_.Group): $($_.Issue)" } | Out-String)

# STEP 1: Empty the Allowed RODC Password Replication Group
# This group should NEVER have members
Get-ADGroupMember "Allowed RODC Password Replication Group" | ForEach-Object {
    Remove-ADGroupMember "Allowed RODC Password Replication Group" -Members `$_.SamAccountName -Confirm:`$false
    Write-Host "Removed `$(`$_.SamAccountName) from Allowed RODC Password Replication Group"
}

# STEP 2: Add all privileged accounts to Denied group
`$deniedGroup = "Denied RODC Password Replication Group"
`$privilegedAccounts = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'krbtgt'
)

foreach (`$account in `$privilegedAccounts) {
    try {
        Add-ADGroupMember `$deniedGroup -Members `$account -ErrorAction SilentlyContinue
        Write-Host "Added `$account to `$deniedGroup"
    } catch {
        Write-Host "Could not add `$account (may already be member)"
    }
}

# STEP 3: Verify Denied group membership
Write-Host "`nDenied RODC Password Replication Group members:"
Get-ADGroupMember `$deniedGroup | Select-Object Name, SamAccountName

# STEP 4: Check per-RODC settings
Get-ADDomainController -Filter {IsReadOnly -eq `$true} | ForEach-Object {
    Write-Host "`nRODC: `$(`$_.Name)"
    Write-Host "Allowed to replicate:"
    Get-ADObject `$_.ComputerObjectDN -Properties msDS-Reveal-OnDemandGroup |
        Select-Object -ExpandProperty msDS-Reveal-OnDemandGroup |
        ForEach-Object { (Get-ADObject `$_).Name }
}

# STEP 5: Clear cached credentials if needed
# On each RODC, you can clear cached passwords:
# repadmin /prp delete <RODC> <account>

# STEP 6: Monitor for password caching
# Check what accounts have been cached:
Get-ADDomainController -Filter {IsReadOnly -eq `$true} | ForEach-Object {
    Write-Host "`nCached accounts on `$(`$_.Name):"
    repadmin /prp view `$_.Name reveal
}

"@
            return $commands
        }
    }
}

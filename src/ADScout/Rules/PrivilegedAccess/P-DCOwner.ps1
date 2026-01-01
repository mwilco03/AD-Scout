@{
    Id          = 'P-DCOwner'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Domain Controller Owned by Non-Admin'
    Description = 'Detects when a Domain Controller computer object is owned by an account other than Domain Admins, Enterprise Admins, or SYSTEM. Object ownership grants implicit full control, allowing modification of security descriptors and potential compromise.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'AD Object Ownership'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups' }
        @{ Title = 'WriteOwner Attack'; Url = 'https://attack.mitre.org/techniques/T1222/001/' }
        @{ Title = 'PingCastle Rule P-DCOwner'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1222.001', 'T1078.002')  # File and Directory Permissions Modification, Domain Accounts
    }

    CIS   = @('5.2')
    STIG  = @('V-63391')
    ANSSI = @('vuln1_dc_owner')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 20
        MaxPoints = 100
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Expected owners (by SID or name pattern)
        $expectedOwnerPatterns = @(
            'Domain Admins',
            'Enterprise Admins',
            'Administrators',
            'BUILTIN\\Administrators',
            'NT AUTHORITY\\SYSTEM',
            'S-1-5-18',             # Local System
            '-512$',               # Domain Admins RID
            '-519$',               # Enterprise Admins RID
            'S-1-5-32-544'         # Builtin Administrators
        )

        try {
            foreach ($dc in $Data.DomainControllers) {
                $dcDN = $dc.DistinguishedName

                if (-not $dcDN) { continue }

                try {
                    $adsiDC = [ADSI]"LDAP://$dcDN"
                    $acl = $adsiDC.ObjectSecurity
                    $owner = $acl.Owner

                    if (-not $owner) { continue }

                    # Check if owner matches expected patterns
                    $isExpectedOwner = $false

                    foreach ($pattern in $expectedOwnerPatterns) {
                        if ($owner -match $pattern) {
                            $isExpectedOwner = $true
                            break
                        }
                    }

                    if (-not $isExpectedOwner) {
                        # Get more details about the owner
                        $ownerSID = $null
                        try {
                            $ownerAccount = New-Object System.Security.Principal.NTAccount($owner)
                            $ownerSID = $ownerAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch { }

                        # Check if owner is a user or computer (not a privileged group)
                        $ownerType = 'Unknown'
                        $isCompromisable = $false

                        if ($ownerSID) {
                            # If it ends with a high RID, likely a regular user
                            if ($ownerSID -match '-\d{4,}$') {
                                $ownerType = 'User/Computer'
                                $isCompromisable = $true
                            }
                        }

                        $findings += [PSCustomObject]@{
                            DCName              = $dc.Name
                            DistinguishedName   = $dcDN
                            CurrentOwner        = $owner
                            OwnerSID            = $ownerSID
                            OwnerType           = $ownerType
                            IsCompromisable     = $isCompromisable
                            Severity            = if ($isCompromisable) { 'Critical' } else { 'High' }
                            Risk                = 'Non-privileged account owns Domain Controller object'
                            Impact              = 'Owner can grant themselves full control over DC object'
                            AttackScenario      = 'Compromising owner account enables DC takeover'
                        }
                    }
                } catch {
                    Write-Verbose "P-DCOwner: Error checking DC $($dc.Name) - $_"
                }
            }

            # Also check the Domain Controllers OU itself
            try {
                $rootDSE = [ADSI]"LDAP://RootDSE"
                $defaultNC = $rootDSE.defaultNamingContext.ToString()
                $dcOU = [ADSI]"LDAP://OU=Domain Controllers,$defaultNC"

                if ($dcOU.Path) {
                    $ouAcl = $dcOU.ObjectSecurity
                    $ouOwner = $ouAcl.Owner

                    $isExpectedOwner = $false
                    foreach ($pattern in $expectedOwnerPatterns) {
                        if ($ouOwner -match $pattern) {
                            $isExpectedOwner = $true
                            break
                        }
                    }

                    if (-not $isExpectedOwner) {
                        $findings += [PSCustomObject]@{
                            DCName              = 'Domain Controllers OU'
                            DistinguishedName   = "OU=Domain Controllers,$defaultNC"
                            CurrentOwner        = $ouOwner
                            ObjectType          = 'OU'
                            Severity            = 'Critical'
                            Risk                = 'Non-privileged account owns Domain Controllers OU'
                            Impact              = 'Owner can modify OU permissions affecting all DCs'
                        }
                    }
                }
            } catch {
                Write-Verbose "P-DCOwner: Error checking DC OU - $_"
            }

        } catch {
            Write-Verbose "P-DCOwner: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Transfer ownership of Domain Controller objects to Domain Admins or Enterprise Admins. Investigate how non-privileged accounts became owners.'
        Impact      = 'Low - Changing ownership to proper admins is safe. Document current owner for investigation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Domain Controller Ownership Remediation
#
# DCs with non-admin owners:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): Owner = $($_.CurrentOwner)" } | Out-String)

# Object ownership grants implicit full control rights.
# A non-admin owner can:
# - Grant themselves explicit full control
# - Modify security descriptors
# - Reset computer password (to compromise DC)

# STEP 1: Document current state for investigation
Get-ADDomainController -Filter * | ForEach-Object {
    `$dc = `$_
    `$acl = Get-Acl "AD:\`$(`$dc.ComputerObjectDN)"
    [PSCustomObject]@{
        DCName = `$dc.Name
        Owner = `$acl.Owner
        DN = `$dc.ComputerObjectDN
    }
} | Export-Csv -Path "DC_Ownership_Before.csv" -NoTypeInformation
Write-Host "Saved current ownership to DC_Ownership_Before.csv"

# STEP 2: Get Domain Admins SID for ownership transfer
`$domainSID = (Get-ADDomain).DomainSID.Value
`$domainAdminsSID = New-Object System.Security.Principal.SecurityIdentifier ("`$domainSID-512")
`$domainAdminsAccount = `$domainAdminsSID.Translate([System.Security.Principal.NTAccount])

# STEP 3: Transfer ownership of each DC to Domain Admins
$($Finding.Findings | ForEach-Object { @"
# Transfer ownership of $($_.DCName)

`$dcDN = "$($_.DistinguishedName)"
`$acl = Get-Acl "AD:\`$dcDN"
Write-Host "Current owner of $($_.DCName): `$(`$acl.Owner)"

# Set Domain Admins as owner
`$acl.SetOwner(`$domainAdminsAccount)
Set-Acl "AD:\`$dcDN" `$acl

Write-Host "Transferred ownership of $($_.DCName) to Domain Admins"

"@ })

# STEP 4: Verify ownership transfer
Get-ADDomainController -Filter * | ForEach-Object {
    `$acl = Get-Acl "AD:\`$(`$_.ComputerObjectDN)"
    Write-Host "`$(`$_.Name): Owner = `$(`$acl.Owner)"
}

# STEP 5: Investigate how non-admin became owner
# Check security event logs for:
# - Event ID 4662: Operation performed on object (with ownership change)
# - Event ID 4780: ACL set on admin accounts
# - Event ID 5136: Directory service object modified

# Query recent owner changes:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | Where-Object {
    `$_.Message -match 'WRITE_OWNER'
} | Select-Object TimeCreated, Message -First 20

# STEP 6: Monitor for future ownership changes
# Enable advanced auditing on Domain Controllers container:
# auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# STEP 7: Transfer ownership via dsacls (alternative method)
# dsacls "CN=DC01,OU=Domain Controllers,DC=domain,DC=com" /takeownership

"@
            return $commands
        }
    }
}

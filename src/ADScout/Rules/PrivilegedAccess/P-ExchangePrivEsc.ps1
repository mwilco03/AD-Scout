@{
    Id          = 'P-ExchangePrivEsc'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Exchange Privilege Escalation Misconfiguration'
    Description = 'Detects Exchange Server installations where the Exchange Windows Permissions group has WriteDACL rights on the domain object, allowing any Exchange server to grant itself DCSync privileges. This is a critical privilege escalation path (CVE-2019-0686, CVE-2019-0724).'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'PrivExchange Attack'; Url = 'https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/' }
        @{ Title = 'Exchange-AD-Privesc'; Url = 'https://github.com/gdedrouas/Exchange-AD-Privesc' }
        @{ Title = 'Microsoft Advisory'; Url = 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0686' }
        @{ Title = 'PingCastle Rule P-ExchangePrivEsc'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1098', 'T1003.006')  # Account Manipulation, DCSync
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_exchange_privesc')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Exchange-related groups that may have dangerous permissions
        $exchangeGroups = @(
            'Exchange Windows Permissions',
            'Exchange Trusted Subsystem',
            'Exchange Servers',
            'Organization Management'
        )

        # Dangerous rights that enable privilege escalation
        $dangerousRights = @(
            'WriteDacl',
            'WriteOwner',
            'GenericAll',
            'GenericWrite'
        )

        # DCSync GUIDs
        $replicationRights = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
            '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
        )

        try {
            # Get domain DN
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
            }

            # Check if Exchange is installed by looking for Exchange groups
            $exchangeInstalled = $false
            foreach ($group in $Data.Groups) {
                if ($group.Name -in $exchangeGroups) {
                    $exchangeInstalled = $true
                    break
                }
            }

            if (-not $exchangeInstalled) {
                # Try to find Exchange configuration container
                try {
                    $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                    $exchangeContainer = [ADSI]"LDAP://CN=Microsoft Exchange,CN=Services,$configNC"
                    if ($exchangeContainer.Path) {
                        $exchangeInstalled = $true
                    }
                } catch {
                    # Exchange not found
                }
            }

            if (-not $exchangeInstalled) {
                return $findings  # No Exchange, no vulnerability
            }

            # Get the domain object ACL
            $domainObj = [ADSI]"LDAP://$domainDN"
            $acl = $domainObj.ObjectSecurity

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()
                $objectType = $ace.ObjectType.ToString().ToLower()

                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Check if this is an Exchange group
                $isExchangeGroup = $false
                foreach ($exGroup in $exchangeGroups) {
                    if ($identity -match [regex]::Escape($exGroup)) {
                        $isExchangeGroup = $true
                        break
                    }
                }

                if (-not $isExchangeGroup) { continue }

                # Check for dangerous rights
                $hasDangerousRight = $false
                $dangerousRightFound = ''

                foreach ($dr in $dangerousRights) {
                    if ($rights -match $dr) {
                        $hasDangerousRight = $true
                        $dangerousRightFound = $dr
                        break
                    }
                }

                # Also check for direct DCSync rights granted
                if ($objectType -in $replicationRights) {
                    $hasDangerousRight = $true
                    $dangerousRightFound = 'DS-Replication Rights'
                }

                if ($hasDangerousRight) {
                    $findings += [PSCustomObject]@{
                        Principal           = $identity
                        DangerousRight      = $dangerousRightFound
                        FullRights          = $rights
                        TargetObject        = $domainDN
                        AccessControlType   = $ace.AccessControlType.ToString()
                        InheritanceType     = $ace.InheritanceType.ToString()
                        CVE                 = 'CVE-2019-0686, CVE-2019-0724'
                        AttackPath          = 'Exchange group can modify domain ACL to grant DCSync rights, then extract all password hashes'
                        Risk                = 'Critical - Any compromised Exchange server can become Domain Admin'
                    }
                }
            }
        } catch {
            # Log error but don't fail
            Write-Verbose "P-ExchangePrivEsc: Error checking Exchange permissions - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove WriteDACL and other dangerous rights from Exchange groups on the domain object. Apply Microsoft security updates and run the Exchange setup /PrepareAD command from updated media.'
        Impact      = 'Medium - Exchange functionality should not be affected if following Microsoft guidance for remediation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Exchange Privilege Escalation Remediation
# CVE-2019-0686 / CVE-2019-0724
#
# This vulnerability allows Exchange servers to escalate to Domain Admin

# Affected principals:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal): $($_.DangerousRight)" } | Out-String)

# STEP 1: Install latest Exchange Security Updates
# Download from: https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

# STEP 2: Run Setup with /PrepareAD to fix permissions
# From an elevated Exchange Management Shell on a server with the latest CU:
# .\Setup.exe /PrepareAD /IAcceptExchangeServerLicenseTerms

# STEP 3: Manually remove dangerous ACEs if needed
`$domainDN = (Get-ADDomain).DistinguishedName

# View current Exchange permissions on domain
Get-Acl "AD:\`$domainDN" | Select-Object -ExpandProperty Access |
    Where-Object { `$_.IdentityReference -match 'Exchange' } |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType

# Remove WriteDACL from Exchange Windows Permissions
`$acl = Get-Acl "AD:\`$domainDN"
`$exchangeSID = (Get-ADGroup "Exchange Windows Permissions").SID

# Find and remove the problematic ACE
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq `$exchangeSID -and
    `$_.ActiveDirectoryRights -match 'WriteDacl'
}

if (`$aceToRemove) {
    `$acl.RemoveAccessRule(`$aceToRemove)
    Set-Acl "AD:\`$domainDN" `$acl
    Write-Host "Removed WriteDACL from Exchange Windows Permissions"
}

# STEP 4: Verify remediation
Get-Acl "AD:\`$domainDN" | Select-Object -ExpandProperty Access |
    Where-Object { `$_.IdentityReference -match 'Exchange' -and `$_.ActiveDirectoryRights -match 'WriteDacl' }

# If the above returns no results, the vulnerability is remediated
"@
            return $commands
        }
    }
}

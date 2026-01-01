@{
    Id          = 'P-ExchangeAdminSDHolder'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Exchange AdminSDHolder Modification'
    Description = 'Detects when Exchange installation has modified the AdminSDHolder object to include Exchange-related permissions. This allows Exchange administrators to potentially modify protected accounts including Domain Admins, Enterprise Admins, and other privileged groups.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AdminSDHolder Attack'; Url = 'https://attack.mitre.org/techniques/T1078/002/' }
        @{ Title = 'Exchange AdminSDHolder'; Url = 'https://adsecurity.org/?p=4119' }
        @{ Title = 'PingCastle Rule P-ExchangeAdminSDHolder'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1078.002', 'T1098')  # Valid Accounts: Domain Accounts, Account Manipulation
    }

    CIS   = @('5.6')
    STIG  = @('V-63337')
    ANSSI = @('vuln1_adminsd_holder', 'vuln1_exchange_adminsd')
    NIST  = @('AC-2', 'AC-6')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Exchange-related groups and users that should NOT have access to AdminSDHolder
        $exchangePrincipals = @(
            'Exchange Trusted Subsystem',
            'Exchange Windows Permissions',
            'Exchange Servers',
            'Organization Management',
            'Exchange Organization Administrators',
            'Exchange Recipient Administrators'
        )

        try {
            # Get domain DN
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
            }

            # Get AdminSDHolder object
            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
            $adminSDHolder = [ADSI]"LDAP://$adminSDHolderDN"

            if (-not $adminSDHolder.Path) {
                return $findings
            }

            $acl = $adminSDHolder.ObjectSecurity

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()

                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Check if this is an Exchange principal
                $isExchangePrincipal = $false
                foreach ($exPrincipal in $exchangePrincipals) {
                    if ($identity -match [regex]::Escape($exPrincipal)) {
                        $isExchangePrincipal = $true
                        break
                    }
                }

                # Also check for Exchange-related patterns in the identity
                if ($identity -match 'Exchange|MSOL_') {
                    $isExchangePrincipal = $true
                }

                if ($isExchangePrincipal) {
                    # Determine the severity based on rights
                    $severity = 'High'
                    if ($rights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty|GenericWrite') {
                        $severity = 'Critical'
                    }

                    $findings += [PSCustomObject]@{
                        Principal           = $identity
                        Rights              = $rights
                        AccessType          = $ace.AccessControlType.ToString()
                        InheritanceType     = $ace.InheritanceType.ToString()
                        IsInherited         = $ace.IsInherited
                        TargetObject        = 'AdminSDHolder'
                        Severity            = $severity
                        Risk                = 'Exchange admins can modify protected admin accounts'
                        Impact              = 'Permissions propagate to Domain Admins, Enterprise Admins, and other protected groups every 60 minutes via SDProp'
                    }
                }
            }

            # Also check for unusual permissions (non-default principals)
            $defaultPrincipals = @(
                'SYSTEM',
                'Domain Admins',
                'Enterprise Admins',
                'Administrators',
                'Account Operators',
                'Pre-Windows 2000 Compatible Access'
            )

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()

                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Check if this is a non-default principal with write access
                $isDefault = $false
                foreach ($defaultPrincipal in $defaultPrincipals) {
                    if ($identity -match [regex]::Escape($defaultPrincipal) -or
                        $identity -match 'BUILTIN|NT AUTHORITY') {
                        $isDefault = $true
                        break
                    }
                }

                # Skip if already found as Exchange principal or is a default
                $alreadyFound = $findings | Where-Object { $_.Principal -eq $identity }
                if ($isDefault -or $alreadyFound) { continue }

                # Flag non-default principals with write access
                if ($rights -match 'Write|GenericAll|GenericWrite|Delete|CreateChild') {
                    $findings += [PSCustomObject]@{
                        Principal           = $identity
                        Rights              = $rights
                        AccessType          = $ace.AccessControlType.ToString()
                        InheritanceType     = $ace.InheritanceType.ToString()
                        IsInherited         = $ace.IsInherited
                        TargetObject        = 'AdminSDHolder'
                        Severity            = 'High'
                        Risk                = 'Non-default principal has write access to AdminSDHolder'
                        Impact              = 'Can modify permissions on all protected admin accounts'
                    }
                }
            }
        } catch {
            Write-Verbose "P-ExchangeAdminSDHolder: Error checking AdminSDHolder - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove Exchange-related permissions from the AdminSDHolder object. This prevents Exchange administrators from having implicit control over privileged domain accounts.'
        Impact      = 'Low - Exchange functionality is not dependent on AdminSDHolder access. Some legacy Exchange delegation may need to be reconfigured.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Exchange AdminSDHolder Modification Remediation
# Remove unauthorized permissions from AdminSDHolder

# Affected principals:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal): $($_.Rights)" } | Out-String)

# IMPORTANT: AdminSDHolder permissions propagate to all protected accounts
# (Domain Admins, Enterprise Admins, Schema Admins, etc.)
# This runs every 60 minutes via the SDProp process

# Get AdminSDHolder DN
`$domainDN = (Get-ADDomain).DistinguishedName
`$adminSDHolderDN = "CN=AdminSDHolder,CN=System,`$domainDN"

# View current AdminSDHolder ACL
Get-Acl "AD:\`$adminSDHolderDN" | Select-Object -ExpandProperty Access |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType

# Remove Exchange permissions from AdminSDHolder
`$acl = Get-Acl "AD:\`$adminSDHolderDN"

# Find Exchange-related ACEs
`$exchangeAces = `$acl.Access | Where-Object {
    `$_.IdentityReference -match 'Exchange'
}

foreach (`$ace in `$exchangeAces) {
    Write-Host "Removing: `$(`$ace.IdentityReference) - `$(`$ace.ActiveDirectoryRights)"
    `$acl.RemoveAccessRule(`$ace)
}

# Apply the modified ACL
Set-Acl "AD:\`$adminSDHolderDN" `$acl

# Force SDProp to run immediately (optional)
# This triggers immediate propagation of AdminSDHolder ACL
`$rootDSE = [ADSI]"LDAP://RootDSE"
`$rootDSE.Put("runProtectAdminGroupsTask", 1)
`$rootDSE.SetInfo()

# Verify remediation
Write-Host "`nRemaining Exchange permissions on AdminSDHolder:"
Get-Acl "AD:\`$adminSDHolderDN" | Select-Object -ExpandProperty Access |
    Where-Object { `$_.IdentityReference -match 'Exchange' }

# If no output, Exchange permissions have been removed
"@
            return $commands
        }
    }
}

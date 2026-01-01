<#
.SYNOPSIS
    Detects conditions enabling Golden GMSA attacks.

.DESCRIPTION
    The Golden GMSA attack allows attackers with access to the KDS root key to
    compute any Group Managed Service Account password. This rule checks for
    weak KDS root key permissions and gMSA configurations.

.NOTES
    Rule ID    : AV-GoldenGMSA
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-GoldenGMSA'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'Golden GMSA Attack Conditions'
    Description = 'Detects conditions enabling Golden GMSA attacks where attackers can compute gMSA passwords by accessing KDS root keys.'
    Severity    = 'Critical'
    Weight      = 85
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'Golden GMSA Attack'; Url = 'https://www.semperis.com/blog/golden-gmsa-attack/' }
        @{ Title = 'GoldenGMSA Tool'; Url = 'https://github.com/Semperis/GoldenGMSA' }
        @{ Title = 'gMSA Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1555', 'T1098')   # Credentials from Password Stores, Account Manipulation
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_golden_gmsa')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Check KDS Root Key configuration
            $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
            $kdsContainer = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configNC"

            $kdsKeys = @()
            try {
                $container = [ADSI]"LDAP://$kdsContainer"
                foreach ($child in $container.Children) {
                    $kdsKeys += $child
                }
            } catch {
                # KDS not configured
            }

            if ($kdsKeys.Count -eq 0) {
                # No KDS root keys - gMSAs can't work
                return @()
            }

            # Check each KDS root key's ACL
            foreach ($key in $kdsKeys) {
                $keyDN = $key.distinguishedName
                $keyName = $key.cn

                try {
                    $acl = $key.ObjectSecurity

                    # Dangerous principals that shouldn't have read access
                    $dangerousPrincipals = @()

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()

                        # Check for read access to the key
                        if ($rights -match 'GenericAll|GenericRead|ReadProperty|Read') {
                            # Skip legitimate principals
                            if ($identity -match 'Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators|SYSTEM') {
                                continue
                            }

                            # Check for unexpected read access
                            $dangerousPrincipals += @{
                                Principal = $identity
                                Rights = $rights
                            }
                        }
                    }

                    if ($dangerousPrincipals.Count -gt 0) {
                        foreach ($dp in $dangerousPrincipals) {
                            $findings += [PSCustomObject]@{
                                ObjectType          = 'KDS Root Key'
                                ObjectName          = $keyName
                                Principal           = $dp.Principal
                                Rights              = $dp.Rights
                                Issue               = 'Non-privileged account can read KDS root key'
                                AttackPath          = 'Read KDS key -> Compute any gMSA password -> Impersonate service accounts'
                                RiskLevel           = 'Critical'
                                DistinguishedName   = $keyDN
                            }
                        }
                    }
                } catch {
                    # Can't check ACL
                }
            }

            # Check for gMSAs with overly permissive password retrieval
            if ($Data.Users) {
                $gmsaAccounts = $Data.Users | Where-Object {
                    $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount'
                }

                foreach ($gmsa in $gmsaAccounts) {
                    $allowedPrincipals = $gmsa.'msDS-GroupMSAMembership'
                    $passwordRetrievers = $gmsa.PrincipalsAllowedToRetrieveManagedPassword

                    # Check if too many accounts can retrieve the password
                    if ($passwordRetrievers) {
                        $retrieverCount = @($passwordRetrievers).Count

                        if ($retrieverCount -gt 10) {
                            $findings += [PSCustomObject]@{
                                ObjectType          = 'gMSA Account'
                                ObjectName          = $gmsa.SamAccountName
                                Principal           = "$retrieverCount principals"
                                Rights              = 'PrincipalsAllowedToRetrieveManagedPassword'
                                Issue               = "gMSA password retrievable by $retrieverCount accounts"
                                AttackPath          = 'Compromise any retriever -> Get gMSA password -> Access services'
                                RiskLevel           = 'Medium'
                                DistinguishedName   = $gmsa.DistinguishedName
                            }
                        }
                    }
                }
            }

            # Check KDS root key age
            foreach ($key in $kdsKeys) {
                $creationTime = $key.'msKds-CreateTime'
                if ($creationTime) {
                    $keyAge = ((Get-Date) - [DateTime]::FromFileTime($creationTime)).Days

                    if ($keyAge -gt 365) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = 'KDS Root Key'
                            ObjectName          = $key.cn
                            Principal           = 'N/A'
                            Rights              = 'N/A'
                            Issue               = "KDS root key is $keyAge days old"
                            AttackPath          = 'Old keys may have been compromised; rotation recommended'
                            RiskLevel           = 'Low'
                            DistinguishedName   = $key.distinguishedName
                        }
                    }
                }
            }

        } catch {
            # Error checking KDS configuration
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict access to KDS root keys and limit gMSA password retrieval to only necessary accounts.'
        Impact      = 'Medium - Changing KDS permissions may affect gMSA functionality. Test carefully.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Golden GMSA Attack Mitigation
#############################################################################
#
# The Golden GMSA attack allows anyone who can read the KDS root key to
# compute ANY gMSA password in the forest - past, present, and future.
#
# Attack Chain:
# 1. Attacker gains read access to KDS root key (via backup, DC compromise, etc.)
# 2. Using GoldenGMSA tool, attacker computes gMSA password
# 3. Attacker authenticates as any gMSA
# 4. If gMSA has privileged access, domain is compromised
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.ObjectType): $($_.ObjectName) - $($_.Issue)" } | Out-String)

#############################################################################
# Step 1: Audit KDS Root Key Access
#############################################################################

# View current KDS root keys
Get-KdsRootKey | Format-List

# Check KDS root key permissions
`$configNC = (Get-ADRootDSE).configurationNamingContext
`$kdsContainer = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,`$configNC"

Get-ADObject -SearchBase `$kdsContainer -Filter { ObjectClass -eq 'msKds-ProvRootKey' } |
    ForEach-Object {
        Write-Host "`n=== `$(`$_.Name) ===" -ForegroundColor Cyan
        (Get-Acl "AD:\`$(`$_.DistinguishedName)").Access |
            Where-Object { `$_.IdentityReference -notmatch 'Domain Controllers|SYSTEM' } |
            Format-Table IdentityReference, ActiveDirectoryRights
    }

#############################################################################
# Step 2: Restrict KDS Root Key Access
#############################################################################

# Only Domain Controllers should have read access to KDS root keys
# Remove any unnecessary permissions

`$kdsKeys = Get-ADObject -SearchBase `$kdsContainer -Filter { ObjectClass -eq 'msKds-ProvRootKey' }

foreach (`$key in `$kdsKeys) {
    `$acl = Get-Acl "AD:\`$(`$key.DistinguishedName)"

    # Review and remove unnecessary access
    `$suspiciousAces = `$acl.Access | Where-Object {
        `$_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Domain Admins|Enterprise Admins' -and
        `$_.ActiveDirectoryRights -match 'Read|GenericAll'
    }

    foreach (`$ace in `$suspiciousAces) {
        Write-Host "Removing: `$(`$ace.IdentityReference)" -ForegroundColor Yellow
        `$acl.RemoveAccessRule(`$ace)
    }

    Set-Acl "AD:\`$(`$key.DistinguishedName)" `$acl
}

#############################################################################
# Step 3: Audit gMSA Password Retrieval Permissions
#############################################################################

# List all gMSAs and who can retrieve their passwords
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object Name,
        @{N='Retrievers';E={`$_.PrincipalsAllowedToRetrieveManagedPassword -join ', '}} |
    Format-Table -Wrap

# Limit password retrieval to only necessary computers
# Set-ADServiceAccount -Identity 'gMSA-SQL' -PrincipalsAllowedToRetrieveManagedPassword 'SQLServer01$','SQLServer02$'

#############################################################################
# Step 4: Create New KDS Root Key (If Compromised)
#############################################################################

# If you suspect KDS root key compromise, create a new one
# Note: There's a 10-hour replication wait by default

# For production (waits 10 hours for replication):
# Add-KdsRootKey -EffectiveImmediately

# For testing ONLY (immediate, but may cause issues):

# Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

#############################################################################
# Step 5: Rotate gMSA Passwords
#############################################################################

# After creating new KDS root key, gMSA passwords will auto-rotate
# Default rotation is 30 days, but you can force it:

# Test-ADServiceAccount -Identity 'gMSA-SQL'
# Reset-ADServiceAccountPassword -Identity 'gMSA-SQL'

#############################################################################
# Detection and Monitoring
#############################################################################

# Monitor for KDS root key access
# Event ID 4662 - Operation performed on object
# Look for access to msKds-ProvRootKey objects

# Monitor for unusual gMSA password retrievals
# Event ID 4662 with msDS-ManagedPassword attribute access

"@
            return $commands
        }
    }
}

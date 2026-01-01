<#
.SYNOPSIS
    Detects unsafe Resource-Based Constrained Delegation (RBCD) configurations.

.DESCRIPTION
    RBCD allows any account with write access to a computer's msDS-AllowedToActOnBehalfOfOtherIdentity
    attribute to configure delegation. This can lead to privilege escalation.

.NOTES
    Rule ID    : P-RBCD-Unsafe
    Category   : PrivilegedAccess
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'P-RBCD-Unsafe'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Unsafe Resource-Based Constrained Delegation'
    Description = 'Identifies computers with RBCD configured or accounts with write access to sensitive computers msDS-AllowedToActOnBehalfOfOtherIdentity attribute.'
    Severity    = 'Critical'
    Weight      = 75
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'RBCD Abuse'; Url = 'https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a' }
        @{ Title = 'Elad Shamir - RBCD'; Url = 'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html' }
        @{ Title = 'BloodHound RBCD Edge'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtoact' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1134.001', 'T1550.003')  # Token Impersonation, Pass the Ticket
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_rbcd')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                # Check for existing RBCD configuration
                $rbcdSids = $computer.'msDS-AllowedToActOnBehalfOfOtherIdentity'

                if ($rbcdSids) {
                    # Determine if this is a sensitive computer
                    $isSensitive = $computer.PrimaryGroupID -eq 516 -or  # DC
                                   $computer.DistinguishedName -match 'Domain Controllers' -or
                                   $computer.Name -match 'CA|ADCS|PKI|ADFS|AAD'

                    # Try to resolve the SIDs
                    $trustedPrincipals = @()
                    try {
                        $descriptor = [System.DirectoryServices.ActiveDirectorySecurity]::new()
                        $descriptor.SetSecurityDescriptorBinaryForm($rbcdSids)

                        foreach ($ace in $descriptor.Access) {
                            $trustedPrincipals += $ace.IdentityReference.Value
                        }
                    } catch {
                        $trustedPrincipals += "Unable to resolve (raw: $([System.BitConverter]::ToString($rbcdSids[0..15]))...)"
                    }

                    $findings += [PSCustomObject]@{
                        ComputerName        = $computer.Name
                        IsSensitive         = $isSensitive
                        RBCDConfigured      = $true
                        TrustedPrincipals   = ($trustedPrincipals -join ', ')
                        Issue               = 'RBCD allows specified accounts to impersonate any user to this computer'
                        AttackPath          = 'Trusted account can request ticket as any user and access this computer'
                        RiskLevel           = if ($isSensitive) { 'Critical' } else { 'High' }
                        DistinguishedName   = $computer.DistinguishedName
                    }
                }
            }
        }

        # Also check for accounts with GenericWrite/GenericAll on sensitive computers
        # This would allow setting RBCD
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $dcDN = $dc.DistinguishedName
                    if (-not $dcDN) { continue }

                    $dcObj = [ADSI]"LDAP://$dcDN"
                    $acl = $dcObj.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $rights = $ace.ActiveDirectoryRights.ToString()

                        # Check for rights that allow RBCD configuration
                        if ($rights -match 'GenericAll|GenericWrite|WriteProperty') {
                            $identity = $ace.IdentityReference.Value

                            # Skip legitimate principals
                            if ($identity -match 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|SELF') {
                                continue
                            }

                            # Check if this specifically allows writing msDS-AllowedToActOnBehalfOfOtherIdentity
                            $objectType = $ace.ObjectType.ToString()
                            $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # msDS-AllowedToActOnBehalfOfOtherIdentity

                            if ($rights -match 'GenericAll|GenericWrite' -or
                                $objectType -eq $rbcdGuid -or
                                $objectType -eq '00000000-0000-0000-0000-000000000000') {

                                $findings += [PSCustomObject]@{
                                    ComputerName        = $dc.Name
                                    IsSensitive         = $true
                                    RBCDConfigured      = $false
                                    TrustedPrincipals   = "Can be set by: $identity"
                                    Issue               = 'Non-admin can configure RBCD on Domain Controller'
                                    AttackPath          = "$identity -> Set RBCD -> Impersonate any user -> Access DC -> DCSync"
                                    RiskLevel           = 'Critical'
                                    DistinguishedName   = $dc.DistinguishedName
                                }
                            }
                        }
                    }
                } catch {
                    # Skip if we can't check ACL
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove unnecessary RBCD configurations and restrict write access to computer objects.'
        Impact      = 'High - May affect applications using RBCD for authentication. Verify each configuration.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Resource-Based Constrained Delegation (RBCD) Security
#############################################################################
#
# RBCD Attack Chain:
# 1. Attacker gains write access to a computer object (or creates one)
# 2. Attacker sets msDS-AllowedToActOnBehalfOfOtherIdentity to trust their account
# 3. Attacker uses S4U2Self/S4U2Proxy to get ticket as any user
# 4. Attacker accesses target computer as the impersonated user
#
# If target is a DC: Complete domain compromise
#
#############################################################################

# RBCD Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.ComputerName): $($_.Issue)" } | Out-String)

#############################################################################
# Step 1: Review and Remove Unnecessary RBCD
#############################################################################

# Find all computers with RBCD configured
Get-ADComputer -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like '*' } `
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, PrincipalsAllowedToDelegateToAccount |
    Select-Object Name, PrincipalsAllowedToDelegateToAccount

"@

            foreach ($item in $Finding.Findings | Where-Object { $_.RBCDConfigured }) {
                $commands += @"

# Review RBCD on: $($item.ComputerName)
# Trusted Principals: $($item.TrustedPrincipals)
# IMPORTANT: Verify this is legitimately needed before removing

# View current RBCD configuration:
Get-ADComputer -Identity '$($item.ComputerName)' -Properties PrincipalsAllowedToDelegateToAccount |
    Select-Object -ExpandProperty PrincipalsAllowedToDelegateToAccount

# Remove RBCD if not needed:
# Set-ADComputer -Identity '$($item.ComputerName)' -PrincipalsAllowedToDelegateToAccount `$null

"@
            }

            $commands += @"

#############################################################################
# Step 2: Protect Sensitive Computers from RBCD Abuse
#############################################################################

# Ensure only authorized principals can write to DC computer objects

# Audit current permissions on DCs:
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Write-Host "`n=== `$(`$dc.Name) ===" -ForegroundColor Cyan
    `$acl = Get-Acl "AD:\`$(`$dc.ComputerObjectDN)"
    `$acl.Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty' -and
        `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
    } | Select-Object IdentityReference, ActiveDirectoryRights
}

#############################################################################
# Step 3: Disable Machine Account Quota (Prevent Attack Vector)
#############################################################################

# If MachineAccountQuota > 0, any user can create computer accounts
# These accounts can be used to configure RBCD attacks

Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota' |
    Select-Object @{N='MachineAccountQuota';E={`$_.'ms-DS-MachineAccountQuota'}}

# Set to 0:
# Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}

#############################################################################
# Step 4: Monitor for RBCD Changes
#############################################################################

# Enable auditing for directory service object modifications
# Event ID 5136 - msDS-AllowedToActOnBehalfOfOtherIdentity modified

# PowerShell monitoring script:
`$computers = Get-ADComputer -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like '*' } `
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, WhenChanged |
    Sort-Object WhenChanged -Descending |
    Select-Object Name, WhenChanged,
        @{N='AllowedToAct';E={`$_.PrincipalsAllowedToDelegateToAccount -join ', '}}

Write-Host "Computers with RBCD configured:" -ForegroundColor Yellow
`$computers | Format-Table

#############################################################################
# Detection with BloodHound
#############################################################################

# Use BloodHound to identify RBCD attack paths:
# 1. Run SharpHound: SharpHound.exe -c All
# 2. Import data into BloodHound
# 3. Query: "Find RBCD Principals"
# 4. Look for paths from low-priv users to Domain Controllers

"@
            return $commands
        }
    }
}

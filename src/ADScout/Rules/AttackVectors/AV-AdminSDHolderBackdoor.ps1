<#
.SYNOPSIS
    Detects modifications to AdminSDHolder for persistence.

.DESCRIPTION
    AdminSDHolder is a template container whose ACL is copied to all protected
    accounts every 60 minutes. Attackers modify it to maintain persistent access
    to privileged accounts.

.NOTES
    Rule ID    : AV-AdminSDHolderBackdoor
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-AdminSDHolderBackdoor'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'AdminSDHolder Persistence Backdoor'
    Description = 'Detects non-default ACL entries on AdminSDHolder that will be propagated to all protected accounts, enabling persistent privileged access.'
    Severity    = 'Critical'
    Weight      = 90
    DataSource  = 'AdminSDHolder'

    References  = @(
        @{ Title = 'AdminSDHolder Persistence'; Url = 'https://adsecurity.org/?p=1906' }
        @{ Title = 'SDProp and AdminSDHolder'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
        @{ Title = 'MITRE - Account Manipulation'; Url = 'https://attack.mitre.org/techniques/T1098/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1098', 'T1222.001')  # Account Manipulation, File Permissions Modification
    }

    CIS   = @('5.1')
    STIG  = @('V-36432')
    ANSSI = @('vuln1_intruders_bad_admincount')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # AdminSDHolder-specific additional trustees beyond standard admin principals
        $adminSDHolderTrustees = @(
            'Print Operators'
            'Server Operators'
            'Replicator'
            'ENTERPRISE DOMAIN CONTROLLERS'
        )

        try {
            # Get AdminSDHolder object
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            }

            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"

            # Use centralized ACL validation with AdminSDHolder-specific trustees
            $aclFindings = Test-ADScoutACLViolation -DistinguishedName $adminSDHolderDN `
                -RightsToCheck '.*' `
                -TargetName 'AdminSDHolder' `
                -TargetType 'Container' `
                -AdditionalLegitPrincipals $adminSDHolderTrustees

            foreach ($finding in $aclFindings) {
                # Categorize dangerous rights
                $dangerousRights = @()
                if ($finding.AllRights -match 'GenericAll') { $dangerousRights += 'Full Control' }
                if ($finding.AllRights -match 'WriteDacl') { $dangerousRights += 'Can modify permissions' }
                if ($finding.AllRights -match 'WriteOwner') { $dangerousRights += 'Can take ownership' }
                if ($finding.AllRights -match 'GenericWrite') { $dangerousRights += 'Can modify attributes' }
                if ($finding.AllRights -match 'WriteProperty') { $dangerousRights += 'Can modify properties' }

                $findings += [PSCustomObject]@{
                    Trustee           = $finding.Principal
                    Rights            = $finding.AllRights
                    DangerousRights   = ($dangerousRights -join ', ')
                    Inherited         = $finding.Inherited
                    Persistence       = 'ACL will propagate to all protected accounts every 60 minutes'
                    AffectedAccounts  = 'Domain Admins, Enterprise Admins, Administrators, krbtgt, etc.'
                    RiskLevel         = 'Critical'
                    AttackType        = 'AdminSDHolder Persistence'
                    DistinguishedName = $adminSDHolderDN
                }
            }

            # Also check if SDProp interval has been modified (should be 60 minutes)
            try {
                $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                $dsService = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
                $dsHeuristics = $dsService.dSHeuristics

                if ($dsHeuristics -and $dsHeuristics.Length -ge 16) {
                    $sdPropInterval = $dsHeuristics.Substring(15, 1)
                    if ($sdPropInterval -ne '0') {
                        # Custom SDProp interval - get value from constants if available
                        $defaultInterval = if ($script:ADScoutConstants) {
                            $script:ADScoutConstants.TimeThresholds.SDPropIntervalMinutes
                        } else { 60 }
                        $intervalMinutes = [int]$sdPropInterval * $defaultInterval

                        $findings += [PSCustomObject]@{
                            Trustee           = 'SDProp Configuration'
                            Rights            = 'N/A'
                            DangerousRights   = "Custom interval: $intervalMinutes minutes"
                            Inherited         = $false
                            Persistence       = 'SDProp interval modified from default 60 minutes'
                            AffectedAccounts  = 'All protected accounts'
                            RiskLevel         = 'High'
                            AttackType        = 'SDProp Interval Modification'
                            DistinguishedName = $dsService.distinguishedName
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not check SDProp interval: $_"
            }
        }
        catch {
            Write-Verbose "Could not access AdminSDHolder: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove unauthorized ACL entries from AdminSDHolder immediately. This is a critical persistence mechanism.'
        Impact      = 'High - Changes propagate to all protected accounts within 60 minutes.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# AdminSDHolder Persistence Backdoor Removal
#############################################################################
#
# AdminSDHolder is a critical security boundary in Active Directory:
# 1. Its ACL is copied to ALL protected accounts by SDProp every 60 minutes
# 2. Protected accounts include: Domain Admins, Enterprise Admins,
#    Administrators, krbtgt, Account Operators, Backup Operators, etc.
# 3. Any ACE added to AdminSDHolder = PERSISTENT access to ALL protected accounts
#
# Attacker technique:
# 1. Compromise privileged account
# 2. Add their controlled account to AdminSDHolder ACL
# 3. Even after password reset/account removal, access is restored every hour
#
# CRITICAL FINDINGS:
$($Finding.Findings | ForEach-Object { "# - $($_.Trustee): $($_.Rights)" } | Out-String)

#############################################################################
# Step 1: Remove Unauthorized ACL Entries
#############################################################################

`$domainDN = (Get-ADDomain).DistinguishedName
`$adminSDHolderDN = "CN=AdminSDHolder,CN=System,`$domainDN"
`$adminSDHolder = [ADSI]"LDAP://`$adminSDHolderDN"
`$acl = `$adminSDHolder.ObjectSecurity

"@

            foreach ($item in $Finding.Findings | Where-Object { $_.AttackType -eq 'AdminSDHolder Persistence' }) {
                $commands += @"

# Remove unauthorized ACE for: $($item.Trustee)
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Trustee)'
}

foreach (`$ace in `$aceToRemove) {
    Write-Host "Removing: $($item.Trustee) - $($item.Rights)" -ForegroundColor Yellow
    `$acl.RemoveAccessRule(`$ace) | Out-Null
}

"@
            }

            $commands += @"

# Apply changes
`$adminSDHolder.ObjectSecurity = `$acl
`$adminSDHolder.CommitChanges()

Write-Host "AdminSDHolder ACL cleaned" -ForegroundColor Green

#############################################################################
# Step 2: Force SDProp to Run Immediately
#############################################################################

# Normally SDProp runs every 60 minutes
# Force it to run now to propagate clean ACLs to all protected accounts

# Method 1: Using LDP or ADSI
`$rootDSE = [ADSI]"LDAP://RootDSE"
`$rootDSE.Put("FixUpInheritance", 1)
`$rootDSE.SetInfo()

# Method 2: Wait for next scheduled run (up to 60 minutes)
# Or restart the NTDS service (NOT recommended in production)

Write-Host "SDProp triggered - ACLs will propagate to protected accounts" -ForegroundColor Green

#############################################################################
# Step 3: Verify AdminSDHolder ACL
#############################################################################

# View current ACL
Write-Host "`nCurrent AdminSDHolder ACL:" -ForegroundColor Cyan
(Get-Acl "AD:\`$adminSDHolderDN").Access |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Format-Table

# Expected trustees:
# - BUILTIN\Administrators
# - DOMAIN\Domain Admins
# - DOMAIN\Enterprise Admins
# - NT AUTHORITY\SYSTEM
# - BUILTIN\Account Operators
# - BUILTIN\Backup Operators
# - BUILTIN\Print Operators
# - BUILTIN\Server Operators

#############################################################################
# Step 4: Check Protected Accounts for Residual Access
#############################################################################

# Protected accounts may still have the backdoor ACE until SDProp runs
# Check a sample of protected accounts:

`$protectedAccounts = @(
    (Get-ADGroup 'Domain Admins').DistinguishedName
    (Get-ADUser 'Administrator').DistinguishedName
    (Get-ADUser 'krbtgt').DistinguishedName
)

foreach (`$dn in `$protectedAccounts) {
    Write-Host "`n=== `$dn ===" -ForegroundColor Cyan
    (Get-Acl "AD:\`$dn").Access | Where-Object {
        `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|Account Operators|Backup Operators'
    } | Select-Object IdentityReference, ActiveDirectoryRights
}

#############################################################################
# Step 5: Assume Breach Procedures
#############################################################################

# If AdminSDHolder was backdoored, assume the attacker has:
# 1. Accessed all protected accounts
# 2. Extracted password hashes via DCSync
# 3. Created additional persistence mechanisms

# Recommended actions:
# 1. Reset krbtgt password TWICE (with replication wait between)
# 2. Reset all privileged account passwords
# 3. Review all other persistence mechanisms
# 4. Check for additional backdoors (GPO, scheduled tasks, etc.)
# 5. Enable advanced auditing on AdminSDHolder

#############################################################################
# Step 6: Enable Auditing on AdminSDHolder
#############################################################################

# Enable success/failure auditing for all access
`$acl = Get-Acl "AD:\`$adminSDHolderDN"
`$everyone = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
`$auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    `$everyone,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
`$acl.AddAuditRule(`$auditRule)
Set-Acl "AD:\`$adminSDHolderDN" `$acl

# Monitor Event ID 5136 for AdminSDHolder modifications

"@
            return $commands
        }
    }
}

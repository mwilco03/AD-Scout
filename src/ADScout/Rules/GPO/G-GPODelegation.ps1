<#
.SYNOPSIS
    Detects dangerous GPO delegation permissions.

.DESCRIPTION
    Excessive GPO delegation allows non-admins to create or modify GPOs,
    potentially enabling privilege escalation. This rule checks for dangerous
    GPO permissions.

.NOTES
    Rule ID    : G-GPODelegation
    Category   : GPO
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'G-GPODelegation'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Dangerous GPO Delegation'
    Description = 'Identifies excessive or dangerous GPO delegation that could allow non-administrators to escalate privileges through GPO modification.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'GPO Delegation'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'GPO Abuse for Privilege Escalation'; Url = 'https://attack.mitre.org/techniques/T1484/001/' }
        @{ Title = 'BloodHound GPO Abuse'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#gpgeneral' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1484.001')  # Group Policy Modification
    }

    CIS   = @('5.3.2')
    STIG  = @('V-254456')
    ANSSI = @('R50')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Safe principals that should have GPO rights
        $safePrincipals = @(
            'Domain Admins',
            'Enterprise Admins',
            'SYSTEM',
            'ENTERPRISE DOMAIN CONTROLLERS'
        )

        # Dangerous permissions
        $dangerousRights = @(
            'GpoEditDeleteModifySecurity',
            'GpoEdit',
            'GpoCustom'
        )

        try {
            # Check GPO creation delegation
            $gpoContainer = "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
            $gpoContainerAcl = Get-Acl "AD:\$gpoContainer" -ErrorAction SilentlyContinue

            foreach ($ace in $gpoContainerAcl.Access) {
                if ($ace.ActiveDirectoryRights -match 'CreateChild|WriteProperty|GenericWrite|GenericAll') {
                    $principal = $ace.IdentityReference.Value

                    # Skip safe principals
                    $isSafe = $false
                    foreach ($safe in $safePrincipals) {
                        if ($principal -match $safe) {
                            $isSafe = $true
                            break
                        }
                    }

                    if (-not $isSafe -and $principal -notmatch 'CREATOR OWNER') {
                        $findings += [PSCustomObject]@{
                            GPOName           = 'GPO Container (Create Rights)'
                            Principal         = $principal
                            Permission        = $ace.ActiveDirectoryRights.ToString()
                            PermissionType    = 'Container'
                            Inherited         = $ace.IsInherited
                            Issues            = "Can CREATE new GPOs: $principal"
                            RiskLevel         = 'Critical'
                            AttackPath        = 'Create GPO -> Link to privileged OU -> Execute code'
                        }
                    }
                }
            }

            # Check individual GPO permissions
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                $permissions = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue

                foreach ($perm in $permissions) {
                    $principal = $perm.Trustee.Name
                    $permission = $perm.Permission

                    # Skip safe principals
                    $isSafe = $false
                    foreach ($safe in $safePrincipals) {
                        if ($principal -match $safe -or $perm.Trustee.SidType -eq 'WellKnownGroup') {
                            # Check if it's SYSTEM or similar
                            if ($principal -in $safePrincipals) {
                                $isSafe = $true
                                break
                            }
                        }
                    }

                    # Check for dangerous permissions
                    if (-not $isSafe -and $permission -in $dangerousRights) {
                        # Determine if this GPO links to sensitive locations
                        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                        $links = $report.GPO.LinksTo

                        $linksToSensitive = $false
                        foreach ($link in $links) {
                            if ($link.SOMPath -match 'Domain Controllers|Tier.?0|Admin|Privileged') {
                                $linksToSensitive = $true
                                break
                            }
                        }

                        $riskLevel = 'Medium'
                        if ($linksToSensitive) { $riskLevel = 'Critical' }
                        if ($permission -eq 'GpoEditDeleteModifySecurity') { $riskLevel = 'High' }

                        $findings += [PSCustomObject]@{
                            GPOName           = $gpo.DisplayName
                            Principal         = $principal
                            Permission        = $permission
                            PermissionType    = 'GPO'
                            Inherited         = $perm.Inherited
                            Issues            = "Non-admin has $permission on GPO"
                            RiskLevel         = $riskLevel
                            AttackPath        = if ($linksToSensitive) { 'Modify GPO -> Affects privileged systems' } else { 'Modify GPO -> Add link to sensitive OU' }
                        }
                    }
                }
            }

            # Check for GPO link permissions on sensitive OUs
            $sensitiveOUs = @(
                (Get-ADDomain).DomainControllersContainer,
                (Get-ADDomain).DistinguishedName
            )

            foreach ($ou in $sensitiveOUs) {
                try {
                    $ouAcl = Get-Acl "AD:\$ou" -ErrorAction SilentlyContinue

                    foreach ($ace in $ouAcl.Access) {
                        # Check for gPLink write permission
                        # gPLink GUID: f30e3bbe-9ff0-11d1-b603-0000f80367c1
                        if ($ace.ObjectType -eq 'f30e3bbe-9ff0-11d1-b603-0000f80367c1' -or
                            ($ace.ActiveDirectoryRights -match 'WriteProperty' -and $ace.ObjectType -eq [Guid]::Empty)) {

                            $principal = $ace.IdentityReference.Value

                            $isSafe = $false
                            foreach ($safe in $safePrincipals) {
                                if ($principal -match $safe) {
                                    $isSafe = $true
                                    break
                                }
                            }

                            if (-not $isSafe) {
                                $findings += [PSCustomObject]@{
                                    GPOName           = "OU: $ou"
                                    Principal         = $principal
                                    Permission        = 'Link GPOs'
                                    PermissionType    = 'OU Link'
                                    Inherited         = $ace.IsInherited
                                    Issues            = "Can LINK GPOs to sensitive OU"
                                    RiskLevel         = 'Critical'
                                    AttackPath        = 'Link malicious GPO -> Execute code on privileged systems'
                                }
                            }
                        }
                    }
                } catch {}
            }

        } catch {
            $findings += [PSCustomObject]@{
                GPOName           = 'Error'
                Principal         = 'N/A'
                Permission        = 'N/A'
                PermissionType    = 'N/A'
                Inherited         = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                AttackPath        = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove dangerous GPO delegation and implement least-privilege GPO management.'
        Impact      = 'Medium - Removing permissions may affect delegated administration workflows.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# GPO Delegation Security
#############################################################################
#
# Dangerous GPO delegation allows attackers to:
# - Create new GPOs with malicious settings
# - Modify existing GPOs to deploy malware
# - Link GPOs to sensitive OUs
#
# Dangerous delegations found:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal) has $($_.Permission) on $($_.GPOName)" } | Out-String)

#############################################################################
# Step 1: Audit Current GPO Permissions
#############################################################################

# List all GPO permissions:
Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    Get-GPPermission -Guid `$gpo.Id -All | ForEach-Object {
        [PSCustomObject]@{
            GPOName = `$gpo.DisplayName
            Trustee = `$_.Trustee.Name
            Permission = `$_.Permission
            Inherited = `$_.Inherited
        }
    }
} | Where-Object { `$_.Permission -match 'Edit|Custom' } |
    Format-Table -AutoSize

#############################################################################
# Step 2: Review GPO Container Permissions
#############################################################################

# Check who can create GPOs:
`$gpoContainer = "CN=Policies,CN=System,`$((Get-ADDomain).DistinguishedName)"
`$acl = Get-Acl "AD:\`$gpoContainer"

`$acl.Access | Where-Object {
    `$_.ActiveDirectoryRights -match 'CreateChild|GenericAll'
} | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Format-Table -AutoSize

#############################################################################
# Step 3: Remove Dangerous Permissions
#############################################################################

# Remove GPO edit permission from a principal:
`$gpoName = "GPO Name"  # Replace with actual GPO
`$dangerousPrincipal = "DOMAIN\User"  # Replace with actual principal

# Get current permissions:
Get-GPPermission -Name `$gpoName -TargetName `$dangerousPrincipal -TargetType User

# Remove permission:
# Set-GPPermission -Name `$gpoName -TargetName `$dangerousPrincipal -TargetType User -PermissionLevel None

#############################################################################
# Step 4: Implement Least Privilege
#############################################################################

# Create dedicated GPO admin groups:
# - GPO-Editors: Can edit specific GPOs
# - GPO-Linkers: Can link GPOs to specific OUs (not DCs)

# Grant edit on specific GPO only:
# Set-GPPermission -Name "Workstation Settings" -TargetName "GPO-Workstation-Admins" -TargetType Group -PermissionLevel GpoEdit

#############################################################################
# Step 5: Protect Sensitive OU Link Permissions
#############################################################################

# Remove GPO link permissions from Domain Controllers OU:
`$dcOU = (Get-ADDomain).DomainControllersContainer
`$acl = Get-Acl "AD:\`$dcOU"

# Find and remove non-admin link permissions
`$gplinkGuid = [Guid]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'

`$acl.Access | Where-Object {
    (`$_.ObjectType -eq `$gplinkGuid -or `$_.ActiveDirectoryRights -match 'WriteProperty') -and
    `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
} | ForEach-Object {
    Write-Host "Would remove: `$(`$_.IdentityReference) - `$(`$_.ActiveDirectoryRights)" -ForegroundColor Yellow
    # `$acl.RemoveAccessRule(`$_)
}

# Set-Acl -Path "AD:\`$dcOU" -AclObject `$acl

#############################################################################
# Step 6: Enable GPO Auditing
#############################################################################

# Monitor for GPO permission changes:
# Event ID 5136: Directory Service Changes
# Event ID 4670: Permissions changed

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5136, 4670
} -MaxEvents 100 | Where-Object {
    `$_.Message -match 'groupPolicyContainer|gPLink'
} | Select-Object TimeCreated, Id, Message | Format-Table -Wrap

#############################################################################
# Step 7: Create GPO Baseline
#############################################################################

# Document current GPO permissions:
`$baseline = Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    Get-GPPermission -Guid `$gpo.Id -All | ForEach-Object {
        [PSCustomObject]@{
            GPOName = `$gpo.DisplayName
            GPOID = `$gpo.Id
            Trustee = `$_.Trustee.Name
            Permission = `$_.Permission
        }
    }
}

`$baseline | Export-Csv -Path "C:\Baseline\GPOPermissions_`$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

#############################################################################
# Verification
#############################################################################

# Re-check for dangerous permissions:
Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    Get-GPPermission -Guid `$gpo.Id -All | Where-Object {
        `$_.Permission -match 'Edit|Custom' -and
        `$_.Trustee.Name -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
    } | ForEach-Object {
        Write-Host "`$(`$gpo.DisplayName): `$(`$_.Trustee.Name) has `$(`$_.Permission)" -ForegroundColor Red
    }
}

"@
            return $commands
        }
    }
}

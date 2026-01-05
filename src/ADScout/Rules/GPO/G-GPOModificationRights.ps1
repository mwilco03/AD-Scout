@{
    Id          = 'G-GPOModificationRights'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Excessive GPO Modification Rights'
    Description = 'Detects non-administrative principals with write permissions on Group Policy Objects. GPO modification allows deploying malicious scripts, scheduled tasks, or security settings to all computers where the GPO is linked.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'GPO Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-gpo' }
        @{ Title = 'BloodHound GPO Edges'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004', 'TA0008')  # Persistence, Priv Esc, Lateral Movement
        Techniques = @('T1484.001')  # Domain Policy Modification: Group Policy Modification
    }

    CIS   = @('5.5.1')
    STIG  = @('V-220941')
    ANSSI = @('R44')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                $gpoPath = "AD:CN={$($gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"

                try {
                    $acl = Get-Acl $gpoPath -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        # Check for write permissions
                        $hasWrite = $ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner'

                        if (-not $hasWrite) { continue }

                        $principal = $ace.IdentityReference.Value

                        # Skip expected principals
                        if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Group Policy Creator Owners|ENTERPRISE DOMAIN CONTROLLERS') {
                            continue
                        }

                        # Check if low-privileged
                        $isLowPriv = $principal -match 'Domain Users|Authenticated Users|Everyone|Users|Domain Computers'

                        # Get GPO links to understand impact
                        $links = @()
                        try {
                            [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                            $linkNodes = $report.SelectNodes("//LinksTo/SOMPath")
                            foreach ($link in $linkNodes) {
                                $links += $link.'#text'
                            }
                        }
                        catch { }

                        $findings += [PSCustomObject]@{
                            GPOName             = $gpo.DisplayName
                            GPOID               = $gpo.Id
                            GPOStatus           = $gpo.GpoStatus
                            Principal           = $principal
                            Permission          = $ace.ActiveDirectoryRights.ToString()
                            IsLowPrivileged     = $isLowPriv
                            Inherited           = $ace.IsInherited
                            LinkedTo            = if ($links.Count -gt 0) { $links -join '; ' } else { 'No links found' }
                            RiskLevel           = if ($isLowPriv) { 'Critical' } else { 'High' }
                            Impact              = 'Can deploy malicious code to all linked OUs'
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            # Could not check GPOs
        }

        return $findings | Sort-Object RiskLevel, GPOName
    }

    Remediation = @{
        Description = 'Remove write permissions from non-administrative principals on GPOs.'
        Impact      = 'Medium - May affect delegated GPO management'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# GPO MODIFICATION RIGHTS
# ================================================================
# Write access to GPOs = ability to run code on all linked computers
#
# Attack:
# 1. Modify GPO to add scheduled task/startup script
# 2. Script runs on all computers in linked OU
# 3. Immediate lateral movement or persistence

# ================================================================
# VULNERABLE GPOs
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName)
# Principal with write: $($item.Principal)
# Permission: $($item.Permission)
# Linked To: $($item.LinkedTo)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove write access from $($item.Principal) on GPO: $($item.GPOName)
`$gpoDN = "CN={$($item.GPOID)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
`$acl = Get-Acl "AD:`$gpoDN"

`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$gpoDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# SYSVOL PERMISSIONS
# ================================================================

# Also check SYSVOL permissions for the GPO folder:
`$domainName = (Get-ADDomain).DNSRoot
`$sysvolPath = "\\`$domainName\SYSVOL\`$domainName\Policies"

# Check specific GPO folder:
# Get-Acl "`$sysvolPath\{GPO-GUID}" | Select-Object -ExpandProperty Access

# ================================================================
# GPO DELEGATION BEST PRACTICES
# ================================================================

# 1. Use Group Policy Creator Owners for GPO creation
# 2. Limit who can LINK GPOs (separate from who can edit)
# 3. Use Security Filtering to limit GPO application
# 4. Regular audit of GPO permissions

# ================================================================
# MONITORING
# ================================================================

# Monitor for GPO changes:
# - Event ID 5136 (Directory Service Changes) on GPO objects
# - Event ID 4739 (Domain Policy was changed)
# - SYSVOL file changes

"@
            return $commands
        }
    }
}

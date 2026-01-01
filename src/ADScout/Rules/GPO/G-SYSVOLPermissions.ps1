@{
    Id          = 'G-SYSVOLPermissions'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Insecure SYSVOL Permissions'
    Description = 'Detects SYSVOL shares or GPO folders with permissions allowing non-administrative users to write. SYSVOL contains GPO files, scripts, and other critical data. Write access allows modifying GPOs or scripts to execute malicious code.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'SYSVOL Permissions'; Url = 'https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-up-default-sysvol-permissions' }
        @{ Title = 'GPO Hijacking'; Url = 'https://attack.mitre.org/techniques/T1484/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1484.001')  # Domain Policy Modification
    }

    CIS   = @('5.5.3')
    STIG  = @('V-220943')
    ANSSI = @('R46')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $domainName = (Get-ADDomain).DNSRoot
            $sysvolPath = "\\$domainName\SYSVOL\$domainName"

            # Check main SYSVOL folder
            try {
                $acl = Get-Acl $sysvolPath -ErrorAction SilentlyContinue

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    $hasWrite = $ace.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership'

                    if ($hasWrite) {
                        $principal = $ace.IdentityReference.Value

                        # Skip expected principals
                        if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|CREATOR OWNER') {
                            continue
                        }

                        $findings += [PSCustomObject]@{
                            Path                = $sysvolPath
                            PathType            = 'SYSVOL Root'
                            Principal           = $principal
                            Permission          = $ace.FileSystemRights.ToString()
                            IsInherited         = $ace.IsInherited
                            RiskLevel           = 'Critical'
                            Impact              = 'Can modify any GPO or script in SYSVOL'
                        }
                    }
                }
            }
            catch { }

            # Check Policies folder
            $policiesPath = "$sysvolPath\Policies"
            try {
                $acl = Get-Acl $policiesPath -ErrorAction SilentlyContinue

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    $hasWrite = $ace.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership'

                    if ($hasWrite) {
                        $principal = $ace.IdentityReference.Value

                        if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|CREATOR OWNER|Group Policy Creator Owners') {
                            continue
                        }

                        $findings += [PSCustomObject]@{
                            Path                = $policiesPath
                            PathType            = 'Policies Folder'
                            Principal           = $principal
                            Permission          = $ace.FileSystemRights.ToString()
                            IsInherited         = $ace.IsInherited
                            RiskLevel           = 'Critical'
                            Impact              = 'Can modify GPO configuration files'
                        }
                    }
                }
            }
            catch { }

            # Check Scripts folder
            $scriptsPath = "$sysvolPath\Scripts"
            try {
                $acl = Get-Acl $scriptsPath -ErrorAction SilentlyContinue

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    $hasWrite = $ace.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership'

                    if ($hasWrite) {
                        $principal = $ace.IdentityReference.Value

                        if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|CREATOR OWNER') {
                            continue
                        }

                        $findings += [PSCustomObject]@{
                            Path                = $scriptsPath
                            PathType            = 'Scripts Folder'
                            Principal           = $principal
                            Permission          = $ace.FileSystemRights.ToString()
                            IsInherited         = $ace.IsInherited
                            RiskLevel           = 'High'
                            Impact              = 'Can modify or add logon scripts'
                        }
                    }
                }
            }
            catch { }

            # Check individual GPO folders
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos | Select-Object -First 10) {  # Limit for performance
                $gpoFolder = "$policiesPath\{$($gpo.Id)}"

                try {
                    $acl = Get-Acl $gpoFolder -ErrorAction SilentlyContinue

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        $hasWrite = $ace.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership'

                        if ($hasWrite) {
                            $principal = $ace.IdentityReference.Value

                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|CREATOR OWNER') {
                                continue
                            }

                            $findings += [PSCustomObject]@{
                                Path                = $gpoFolder
                                PathType            = 'GPO Folder'
                                GPOName             = $gpo.DisplayName
                                Principal           = $principal
                                Permission          = $ace.FileSystemRights.ToString()
                                IsInherited         = $ace.IsInherited
                                RiskLevel           = 'High'
                                Impact              = "Can modify GPO: $($gpo.DisplayName)"
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            # Could not check SYSVOL
        }

        return $findings | Sort-Object RiskLevel, Path
    }

    Remediation = @{
        Description = 'Reset SYSVOL permissions to defaults. Remove write access from non-administrative principals.'
        Impact      = 'Low - Default permissions should work for all scenarios'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SYSVOL PERMISSION SECURITY
# ================================================================
# SYSVOL contains critical Group Policy files and scripts.
# Write access = ability to modify GPOs or inject malicious scripts.

# Default SYSVOL permissions:
# - Administrators: Full Control
# - SYSTEM: Full Control
# - Domain Admins: Full Control
# - Enterprise Admins: Full Control
# - Authenticated Users: Read & Execute
# - CREATOR OWNER: Full Control (subfolders only)

# ================================================================
# INSECURE PERMISSIONS DETECTED
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Path: $($item.Path)
# Type: $($item.PathType)
# Principal: $($item.Principal)
# Permission: $($item.Permission)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# Method 1: Reset to default permissions using icacls

`$domainName = (Get-ADDomain).DNSRoot
`$sysvolPath = "\\`$domainName\SYSVOL\`$domainName"

# Reset Policies folder:
icacls "`$sysvolPath\Policies" /reset /t /c

# Reset Scripts folder:
icacls "`$sysvolPath\Scripts" /reset /t /c

# Method 2: Remove specific bad permissions

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove access for $($item.Principal) from $($item.Path)
icacls "$($item.Path)" /remove:g "$($item.Principal)"

"@
            }

            $commands += @"

# ================================================================
# SET CORRECT PERMISSIONS
# ================================================================

# Apply default SYSVOL permissions:
`$sysvolPath = "C:\Windows\SYSVOL\sysvol\`$((Get-ADDomain).DNSRoot)"

# Policies folder:
icacls "`$sysvolPath\Policies" /inheritance:d
icacls "`$sysvolPath\Policies" /grant "Administrators:(OI)(CI)F"
icacls "`$sysvolPath\Policies" /grant "SYSTEM:(OI)(CI)F"
icacls "`$sysvolPath\Policies" /grant "Authenticated Users:(OI)(CI)RX"

# ================================================================
# VERIFICATION
# ================================================================

# Check current permissions:
icacls "\\`$((Get-ADDomain).DNSRoot)\SYSVOL"
icacls "\\`$((Get-ADDomain).DNSRoot)\SYSVOL\`$((Get-ADDomain).DNSRoot)\Policies"

# ================================================================
# DCDIAG CHECK
# ================================================================

# Use DCDIAG to verify SYSVOL health:
dcdiag /test:netlogons /test:sysvolcheck

"@
            return $commands
        }
    }
}

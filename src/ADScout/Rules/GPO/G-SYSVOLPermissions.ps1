@{
    Id          = 'G-SYSVOLPermissions'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Insecure SYSVOL Permissions'
    Description = 'The SYSVOL share has overly permissive access rights, allowing non-administrative users to modify Group Policy Objects, scripts, or other critical files. This can lead to privilege escalation by modifying GPO settings or logon scripts.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'SYSVOL Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers' }
        @{ Title = 'GPO Abuse'; Url = 'https://attack.mitre.org/techniques/T1484/001/' }
        @{ Title = 'SYSVOL Best Practices'; Url = 'https://adsecurity.org/?p=2288' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0005')  # Privilege Escalation, Defense Evasion
        Techniques = @('T1484.001')  # Domain Policy Modification: Group Policy Modification
    }

    CIS   = @('18.9.84.1')
    STIG  = @('V-63423')
    ANSSI = @('vuln1_sysvol_permissions')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous permissions that shouldn't be on SYSVOL for non-admins
        $dangerousRights = @('FullControl', 'Modify', 'Write', 'CreateFiles', 'AppendData', 'WriteData')

        # Low-privileged groups that shouldn't have write access
        $lowPrivGroups = @(
            'Everyone',
            'Authenticated Users',
            'Domain Users',
            'Users',
            'Domain Computers'
        )

        foreach ($dc in $Data) {
            try {
                $sysvolPath = "\\$($dc.Name)\SYSVOL"
                $domainPath = "$sysvolPath\$($Domain.Name)"

                # Check SYSVOL share permissions
                $sharePath = $sysvolPath

                if (Test-Path $domainPath -ErrorAction SilentlyContinue) {
                    $acl = Get-Acl $domainPath -ErrorAction SilentlyContinue

                    if ($acl) {
                        foreach ($ace in $acl.Access) {
                            $identity = $ace.IdentityReference.Value
                            $rights = $ace.FileSystemRights.ToString()

                            # Check if low-priv group has dangerous rights
                            $isLowPriv = $lowPrivGroups | Where-Object { $identity -match [regex]::Escape($_) }
                            $hasDangerousRights = $dangerousRights | Where-Object { $rights -match $_ }

                            if ($isLowPriv -and $hasDangerousRights) {
                                $findings += [PSCustomObject]@{
                                    DomainController    = $dc.Name
                                    Path                = $domainPath
                                    Identity            = $identity
                                    Rights              = $rights
                                    IsInherited         = $ace.IsInherited
                                    RiskLevel           = 'High'
                                    AttackPath          = 'Modify GPO files, inject malicious scripts'
                                    Impact              = 'Code execution on domain-joined machines via GPO'
                                }
                            }
                        }
                    }

                    # Also check Scripts folder specifically
                    $scriptsPath = "$domainPath\scripts"
                    if (Test-Path $scriptsPath -ErrorAction SilentlyContinue) {
                        $scriptsAcl = Get-Acl $scriptsPath -ErrorAction SilentlyContinue

                        if ($scriptsAcl) {
                            foreach ($ace in $scriptsAcl.Access) {
                                $identity = $ace.IdentityReference.Value
                                $rights = $ace.FileSystemRights.ToString()

                                $isLowPriv = $lowPrivGroups | Where-Object { $identity -match [regex]::Escape($_) }
                                $hasDangerousRights = $dangerousRights | Where-Object { $rights -match $_ }

                                if ($isLowPriv -and $hasDangerousRights) {
                                    $findings += [PSCustomObject]@{
                                        DomainController    = $dc.Name
                                        Path                = $scriptsPath
                                        Identity            = $identity
                                        Rights              = $rights
                                        IsInherited         = $ace.IsInherited
                                        RiskLevel           = 'Critical'
                                        AttackPath          = 'Modify logon/logoff scripts for all users'
                                        Impact              = 'Immediate code execution on user logon'
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                # Cannot access DC SYSVOL - might be network issue
                $findings += [PSCustomObject]@{
                    DomainController    = $dc.Name
                    Path                = "\\$($dc.Name)\SYSVOL"
                    Identity            = 'Unable to check'
                    Rights              = "Error: $_"
                    IsInherited         = $false
                    RiskLevel           = 'Unknown'
                    AttackPath          = 'Manual verification required'
                    Impact              = 'Cannot assess SYSVOL permissions'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reset SYSVOL permissions to secure defaults. Remove write access for non-administrative users and groups.'
        Impact      = 'Medium - May affect legacy scripts or applications that write to SYSVOL. Test before applying.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix Insecure SYSVOL Permissions
# Affected Paths: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.Path): $($_.Identity) has $($_.Rights)" } | Out-String)

# CORRECT SYSVOL PERMISSIONS:
# - Authenticated Users: Read & Execute
# - Server Operators: Modify (for NetLogon share management)
# - Administrators: Full Control
# - SYSTEM: Full Control
# - CREATOR OWNER: Full Control
# - Domain Admins: Full Control

# Step 1: Reset SYSVOL to default permissions
# Run on each DC:
foreach (`$dc in @('$($Finding.Findings.DomainController | Select-Object -Unique | Out-String)')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        `$sysvolPath = "C:\Windows\SYSVOL\sysvol"

        # Reset to inherited permissions from parent
        icacls `$sysvolPath /reset /T /C /Q

        # Or manually set correct permissions:
        # icacls `$sysvolPath /grant "Authenticated Users:(OI)(CI)RX"
        # icacls `$sysvolPath /grant "SYSTEM:(OI)(CI)F"
        # icacls `$sysvolPath /grant "Administrators:(OI)(CI)F"
    }
}

# Step 2: Use secedit to apply default DC security template
# This includes correct SYSVOL permissions
# secedit /configure /cfg %windir%\inf\defltdc.inf /db defltdc.sdb /verbose

# Step 3: Force SYSVOL replication to sync permissions
# repadmin /syncall /AeD

# Step 4: Verify permissions
foreach (`$dc in (Get-ADDomainController -Filter *).Name) {
    Write-Host "`nPermissions on \\`$dc\SYSVOL:"
    icacls "\\`$dc\SYSVOL\$($Domain.Name)"
}

# ALSO CHECK:
# - Scripts folder permissions
# - Individual GPO folder permissions
# - Starter GPOs folder

"@
            return $commands
        }
    }
}

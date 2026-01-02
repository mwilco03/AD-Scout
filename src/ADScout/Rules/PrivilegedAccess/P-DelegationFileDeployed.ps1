@{
    Id          = 'P-DelegationFileDeployed'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'GPO File Deployment with Unsafe Permissions'
    Description = 'Detects when Group Policy deploys files or scripts where non-administrators have write access to the source location. An attacker with write access can modify deployed files to execute malicious code on all affected systems.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'GPO File Deployment Security'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment' }
        @{ Title = 'GPO Persistence'; Url = 'https://attack.mitre.org/techniques/T1484/001/' }
        @{ Title = 'PingCastle Rule P-DelegationFileDeployed'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1484.001', 'T1059.001')  # Domain Policy Modification, PowerShell
    }

    CIS   = @()  # GPO file permissions not directly covered in CIS benchmarks
    STIG  = @()  # GPO security STIGs are environment-specific
    ANSSI = @()
    NIST  = @('AC-3', 'CM-5', 'CM-6')  # Access Enforcement, Access Restrictions, Configuration Settings

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 15
        MaxPoints = 60
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous permissions that allow file modification
        $dangerousPermissions = @(
            'FullControl',
            'Modify',
            'Write',
            'AppendData',
            'CreateFiles'
        )

        # Broad principals that shouldn't have write access
        $dangerousPrincipals = @(
            'Everyone',
            'Authenticated Users',
            'Users',
            'Domain Users',
            'Domain Computers'
        )

        try {
            foreach ($gpo in $Data.GPOs) {
                $gpoName = $gpo.DisplayName
                $gpoPath = $gpo.Path

                if (-not $gpoPath) { continue }

                # Check for file deployments in GPO
                $fileDeployments = @()

                # Check GPO files/scripts locations
                $scriptLocations = @(
                    "$gpoPath\Machine\Scripts",
                    "$gpoPath\User\Scripts",
                    "$gpoPath\Machine\Scripts\Startup",
                    "$gpoPath\Machine\Scripts\Shutdown",
                    "$gpoPath\User\Scripts\Logon",
                    "$gpoPath\User\Scripts\Logoff"
                )

                foreach ($scriptPath in $scriptLocations) {
                    if (Test-Path $scriptPath -ErrorAction SilentlyContinue) {
                        $scripts = Get-ChildItem -Path $scriptPath -File -ErrorAction SilentlyContinue

                        foreach ($script in $scripts) {
                            try {
                                $acl = Get-Acl -Path $script.FullName -ErrorAction SilentlyContinue

                                foreach ($ace in $acl.Access) {
                                    $identity = $ace.IdentityReference.Value
                                    $rights = $ace.FileSystemRights.ToString()

                                    # Check if dangerous principal has write access
                                    $isDangerousPrincipal = $false
                                    foreach ($dp in $dangerousPrincipals) {
                                        if ($identity -match [regex]::Escape($dp)) {
                                            $isDangerousPrincipal = $true
                                            break
                                        }
                                    }

                                    if ($isDangerousPrincipal) {
                                        $hasDangerousPermission = $false
                                        foreach ($perm in $dangerousPermissions) {
                                            if ($rights -match $perm) {
                                                $hasDangerousPermission = $true
                                                break
                                            }
                                        }

                                        if ($hasDangerousPermission) {
                                            $findings += [PSCustomObject]@{
                                                GPOName             = $gpoName
                                                FileType            = 'Script'
                                                FilePath            = $script.FullName
                                                FileName            = $script.Name
                                                VulnerablePrincipal = $identity
                                                DangerousRights     = $rights
                                                Severity            = 'Critical'
                                                Risk                = 'Non-admin can modify GPO-deployed script'
                                                Impact              = 'Code execution on all systems where GPO applies'
                                                AttackScenario      = 'Modify script to add backdoor or harvest credentials'
                                            }
                                        }
                                    }
                                }
                            } catch { }
                        }
                    }
                }

                # Check GPP File preferences
                $gppFilesXml = "$gpoPath\Machine\Preferences\Files\Files.xml"
                if (Test-Path $gppFilesXml -ErrorAction SilentlyContinue) {
                    try {
                        [xml]$filesXml = Get-Content $gppFilesXml -ErrorAction SilentlyContinue

                        foreach ($file in $filesXml.Files.File) {
                            $sourceFile = $file.Properties.fromPath

                            if ($sourceFile) {
                                # Check permissions on the source file
                                if (Test-Path $sourceFile -ErrorAction SilentlyContinue) {
                                    try {
                                        $acl = Get-Acl -Path $sourceFile -ErrorAction SilentlyContinue

                                        foreach ($ace in $acl.Access) {
                                            $identity = $ace.IdentityReference.Value
                                            $rights = $ace.FileSystemRights.ToString()

                                            $isDangerousPrincipal = $false
                                            foreach ($dp in $dangerousPrincipals) {
                                                if ($identity -match [regex]::Escape($dp)) {
                                                    $isDangerousPrincipal = $true
                                                    break
                                                }
                                            }

                                            if ($isDangerousPrincipal) {
                                                $hasDangerousPermission = $false
                                                foreach ($perm in $dangerousPermissions) {
                                                    if ($rights -match $perm) {
                                                        $hasDangerousPermission = $true
                                                        break
                                                    }
                                                }

                                                if ($hasDangerousPermission) {
                                                    $findings += [PSCustomObject]@{
                                                        GPOName             = $gpoName
                                                        FileType            = 'GPP File Deployment'
                                                        SourcePath          = $sourceFile
                                                        DestinationPath     = $file.Properties.targetPath
                                                        VulnerablePrincipal = $identity
                                                        DangerousRights     = $rights
                                                        Severity            = 'High'
                                                        Risk                = 'Non-admin can modify GPP-deployed file'
                                                        Impact              = 'File replacement on target systems'
                                                    }
                                                }
                                            }
                                        }
                                    } catch { }
                                }
                            }
                        }
                    } catch { }
                }

                # Check Scheduled Tasks in GPP
                $gppTasksXml = "$gpoPath\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
                if (Test-Path $gppTasksXml -ErrorAction SilentlyContinue) {
                    try {
                        [xml]$tasksXml = Get-Content $gppTasksXml -ErrorAction SilentlyContinue

                        foreach ($task in $tasksXml.ScheduledTasks.Task) {
                            $command = $task.Properties.appName

                            if ($command -and (Test-Path $command -ErrorAction SilentlyContinue)) {
                                try {
                                    $acl = Get-Acl -Path $command -ErrorAction SilentlyContinue

                                    foreach ($ace in $acl.Access) {
                                        $identity = $ace.IdentityReference.Value
                                        $rights = $ace.FileSystemRights.ToString()

                                        $isDangerousPrincipal = $false
                                        foreach ($dp in $dangerousPrincipals) {
                                            if ($identity -match [regex]::Escape($dp)) {
                                                $isDangerousPrincipal = $true
                                                break
                                            }
                                        }

                                        if ($isDangerousPrincipal) {
                                            $hasDangerousPermission = $false
                                            foreach ($perm in $dangerousPermissions) {
                                                if ($rights -match $perm) {
                                                    $hasDangerousPermission = $true
                                                    break
                                                }
                                            }

                                            if ($hasDangerousPermission) {
                                                $findings += [PSCustomObject]@{
                                                    GPOName             = $gpoName
                                                    FileType            = 'Scheduled Task Executable'
                                                    FilePath            = $command
                                                    TaskName            = $task.name
                                                    VulnerablePrincipal = $identity
                                                    DangerousRights     = $rights
                                                    Severity            = 'Critical'
                                                    Risk                = 'Non-admin can modify scheduled task executable'
                                                    Impact              = 'Code execution via scheduled task'
                                                }
                                            }
                                        }
                                    }
                                } catch { }
                            }
                        }
                    } catch { }
                }
            }

        } catch {
            Write-Verbose "P-DelegationFileDeployed: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Move deployed files to secure locations (SYSVOL or similar) where only Domain Admins have write access. Remove write permissions from non-admin principals.'
        Impact      = 'Medium - Requires relocating files and updating GPO references. Test in non-production first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# GPO File Deployment Permissions Remediation
#
# Vulnerable file deployments found:
$($Finding.Findings | ForEach-Object { "# - $($_.GPOName): $($_.FilePath) - $($_.VulnerablePrincipal) has $($_.DangerousRights)" } | Out-String)

# When non-admins can write to GPO-deployed files:
# - Malware can modify scripts to include backdoors
# - Credentials can be harvested from modified logon scripts
# - Ransomware can spread via modified startup scripts

# STEP 1: Identify all GPO file deployments
Write-Host "Scanning all GPOs for file deployments..." -ForegroundColor Yellow
`$domain = Get-ADDomain
`$gpoPath = "\\`$(`$domain.DNSRoot)\SYSVOL\`$(`$domain.DNSRoot)\Policies"

Get-ChildItem -Path `$gpoPath -Recurse -File | ForEach-Object {
    `$file = `$_
    `$acl = Get-Acl `$file.FullName -ErrorAction SilentlyContinue
    if (`$acl) {
        `$acl.Access | Where-Object {
            `$_.IdentityReference.Value -match 'Everyone|Authenticated Users|Domain Users' -and
            `$_.FileSystemRights -match 'Write|Modify|FullControl'
        } | ForEach-Object {
            [PSCustomObject]@{
                File = `$file.FullName
                Principal = `$_.IdentityReference.Value
                Rights = `$_.FileSystemRights
            }
        }
    }
} | Format-Table -AutoSize

# STEP 2: Fix permissions on vulnerable files
$($Finding.Findings | ForEach-Object { @"
# Fix permissions on $($_.FilePath)
`$filePath = "$($_.FilePath)"
if (Test-Path `$filePath) {
    `$acl = Get-Acl `$filePath

    # Remove vulnerable access rules
    `$acl.Access | Where-Object {
        `$_.IdentityReference.Value -match "$($_.VulnerablePrincipal)" -and
        `$_.FileSystemRights -match "Write|Modify|FullControl|AppendData"
    } | ForEach-Object {
        `$acl.RemoveAccessRule(`$_)
    }

    # Ensure only admins have write access
    `$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Domain Admins",
        "FullControl",
        "Allow"
    )
    `$acl.AddAccessRule(`$adminRule)

    Set-Acl `$filePath `$acl
    Write-Host "Fixed permissions on $($_.FileName)" -ForegroundColor Green
}

"@ })

# STEP 3: Best practices for GPO file deployments

# Move files to SYSVOL (inherits secure permissions)
# Example: \\domain.com\SYSVOL\domain.com\scripts\

# Create a secure scripts folder:
`$secureScriptsPath = "\\`$(`$domain.DNSRoot)\SYSVOL\`$(`$domain.DNSRoot)\scripts\secure"
if (-not (Test-Path `$secureScriptsPath)) {
    New-Item -Path `$secureScriptsPath -ItemType Directory
    `$acl = Get-Acl `$secureScriptsPath

    # Remove inherited permissions
    `$acl.SetAccessRuleProtection(`$true, `$false)

    # Add Domain Admins with full control
    `$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Domain Admins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    `$acl.AddAccessRule(`$adminRule)

    # Add Authenticated Users with read-only
    `$readRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Authenticated Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    `$acl.AddAccessRule(`$readRule)

    Set-Acl `$secureScriptsPath `$acl
    Write-Host "Created secure scripts folder at `$secureScriptsPath"
}

# STEP 4: Update GPOs to use secure location
# Open GPMC and update script paths to point to \\domain.com\SYSVOL\domain.com\scripts\secure\

# STEP 5: Verify no vulnerable permissions remain
Get-ChildItem -Path `$gpoPath -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs -File | ForEach-Object {
    `$acl = Get-Acl `$_.FullName
    `$vulnAces = `$acl.Access | Where-Object {
        `$_.IdentityReference.Value -match 'Everyone|Authenticated Users|Domain Users' -and
        `$_.FileSystemRights -match 'Write|Modify|FullControl'
    }
    if (`$vulnAces) {
        Write-Host "STILL VULNERABLE: `$(`$_.FullName)" -ForegroundColor Red
    }
}

# STEP 6: Monitor for unauthorized changes
# Enable auditing on SYSVOL\scripts folders:
# auditpol /set /subcategory:"File System" /success:enable /failure:enable

"@
            return $commands
        }
    }
}

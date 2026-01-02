@{
    Id          = 'T-FileDeployedOutOfDomain'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'GPO References Files from External Domain'
    Description = 'Detects when Group Policy Objects reference files, scripts, or executables from domains other than the current domain. This creates a dependency on external resources that may be compromised or unavailable.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'GPO Security Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'Trust Abuse'; Url = 'https://attack.mitre.org/techniques/T1199/' }
        @{ Title = 'PingCastle Rule T-FileDeployedOutOfDomain'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1199', 'T1484.001')  # Trusted Relationship, Domain Policy Modification
    }

    CIS   = @()  # GPO file location not covered in CIS benchmarks
    STIG  = @()  # Cross-domain file references vary by environment
    ANSSI = @()
    NIST  = @('AC-3', 'CM-5', 'SC-7')  # Access Enforcement, Access Restrictions, Boundary Protection

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 10
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get current domain name
        $currentDomain = $null
        if ($Domain.DNSRoot) {
            $currentDomain = $Domain.DNSRoot
        } elseif ($Domain.Name) {
            $currentDomain = $Domain.Name
        } else {
            try {
                $rootDSE = [ADSI]"LDAP://RootDSE"
                $currentDomain = ($rootDSE.defaultNamingContext.ToString() -replace 'DC=', '' -replace ',', '.')
            } catch { }
        }

        if (-not $currentDomain) { return $findings }

        # Patterns to look for UNC paths
        $uncPattern = '\\\\([^\\]+)\\([^\\]+)'

        try {
            foreach ($gpo in $Data.GPOs) {
                $gpoName = $gpo.DisplayName
                $gpoPath = $gpo.Path

                if (-not $gpoPath) { continue }

                # Check various GPO components for external references

                # 1. Check Scripts (startup, shutdown, logon, logoff)
                $scriptLocations = @(
                    @{ Path = "$gpoPath\Machine\Scripts\scripts.ini"; Type = 'Machine Scripts' }
                    @{ Path = "$gpoPath\User\Scripts\scripts.ini"; Type = 'User Scripts' }
                )

                foreach ($scriptLoc in $scriptLocations) {
                    if (Test-Path $scriptLoc.Path -ErrorAction SilentlyContinue) {
                        $content = Get-Content $scriptLoc.Path -Raw -ErrorAction SilentlyContinue

                        if ($content -match $uncPattern) {
                            $matches = [regex]::Matches($content, $uncPattern)
                            foreach ($match in $matches) {
                                $server = $match.Groups[1].Value
                                $share = $match.Groups[2].Value

                                # Check if server is from a different domain
                                if ($server -notmatch [regex]::Escape($currentDomain) -and
                                    $server -notmatch '^localhost$|^127\.|^::1$') {

                                    $findings += [PSCustomObject]@{
                                        GPOName             = $gpoName
                                        ReferenceType       = $scriptLoc.Type
                                        ExternalPath        = $match.Value
                                        ExternalServer      = $server
                                        Share               = $share
                                        CurrentDomain       = $currentDomain
                                        Severity            = 'High'
                                        Risk                = 'Script references external domain'
                                        Impact              = 'External domain compromise affects this domain'
                                        Recommendation      = 'Move files to local domain SYSVOL'
                                    }
                                }
                            }
                        }
                    }
                }

                # 2. Check GPP File deployments
                $gppLocations = @(
                    @{ Path = "$gpoPath\Machine\Preferences\Files\Files.xml"; Type = 'GPP Files (Machine)' }
                    @{ Path = "$gpoPath\User\Preferences\Files\Files.xml"; Type = 'GPP Files (User)' }
                )

                foreach ($gppLoc in $gppLocations) {
                    if (Test-Path $gppLoc.Path -ErrorAction SilentlyContinue) {
                        try {
                            [xml]$xml = Get-Content $gppLoc.Path -ErrorAction SilentlyContinue

                            foreach ($file in $xml.Files.File) {
                                $fromPath = $file.Properties.fromPath

                                if ($fromPath -match $uncPattern) {
                                    $server = $Matches[1]
                                    $share = $Matches[2]

                                    if ($server -notmatch [regex]::Escape($currentDomain) -and
                                        $server -notmatch '^localhost$|^127\.|^::1$') {

                                        $findings += [PSCustomObject]@{
                                            GPOName             = $gpoName
                                            ReferenceType       = $gppLoc.Type
                                            ExternalPath        = $fromPath
                                            ExternalServer      = $server
                                            TargetPath          = $file.Properties.targetPath
                                            CurrentDomain       = $currentDomain
                                            Severity            = 'High'
                                            Risk                = 'File deployment references external domain'
                                            Impact              = 'Files from untrusted source deployed to clients'
                                        }
                                    }
                                }
                            }
                        } catch { }
                    }
                }

                # 3. Check Scheduled Tasks
                $taskLocations = @(
                    @{ Path = "$gpoPath\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"; Type = 'Scheduled Tasks (Machine)' }
                    @{ Path = "$gpoPath\User\Preferences\ScheduledTasks\ScheduledTasks.xml"; Type = 'Scheduled Tasks (User)' }
                )

                foreach ($taskLoc in $taskLocations) {
                    if (Test-Path $taskLoc.Path -ErrorAction SilentlyContinue) {
                        try {
                            [xml]$xml = Get-Content $taskLoc.Path -ErrorAction SilentlyContinue

                            foreach ($task in $xml.ScheduledTasks.Task) {
                                $appName = $task.Properties.appName
                                $arguments = $task.Properties.Arguments

                                foreach ($path in @($appName, $arguments)) {
                                    if ($path -match $uncPattern) {
                                        $server = $Matches[1]

                                        if ($server -notmatch [regex]::Escape($currentDomain) -and
                                            $server -notmatch '^localhost$|^127\.|^::1$') {

                                            $findings += [PSCustomObject]@{
                                                GPOName             = $gpoName
                                                ReferenceType       = $taskLoc.Type
                                                TaskName            = $task.name
                                                ExternalPath        = $path
                                                ExternalServer      = $server
                                                CurrentDomain       = $currentDomain
                                                Severity            = 'Critical'
                                                Risk                = 'Scheduled task executes from external domain'
                                                Impact              = 'Code execution from external source'
                                            }
                                        }
                                    }
                                }
                            }
                        } catch { }
                    }
                }

                # 4. Check Services
                $servicesPath = "$gpoPath\Machine\Preferences\Services\Services.xml"
                if (Test-Path $servicesPath -ErrorAction SilentlyContinue) {
                    try {
                        [xml]$xml = Get-Content $servicesPath -ErrorAction SilentlyContinue

                        foreach ($service in $xml.NTServices.NTService) {
                            $servicePath = $service.Properties.pathToExecutable

                            if ($servicePath -match $uncPattern) {
                                $server = $Matches[1]

                                if ($server -notmatch [regex]::Escape($currentDomain) -and
                                    $server -notmatch '^localhost$|^127\.|^::1$') {

                                    $findings += [PSCustomObject]@{
                                        GPOName             = $gpoName
                                        ReferenceType       = 'GPP Services'
                                        ServiceName         = $service.name
                                        ExternalPath        = $servicePath
                                        ExternalServer      = $server
                                        CurrentDomain       = $currentDomain
                                        Severity            = 'Critical'
                                        Risk                = 'Service executes from external domain'
                                        Impact              = 'Service hijacking possible from external domain'
                                    }
                                }
                            }
                        }
                    } catch { }
                }

                # 5. Check Software Installation
                $softwarePaths = @(
                    "$gpoPath\Machine\Applications",
                    "$gpoPath\User\Applications"
                )

                foreach ($softwarePath in $softwarePaths) {
                    if (Test-Path $softwarePath -ErrorAction SilentlyContinue) {
                        $aasFiles = Get-ChildItem -Path $softwarePath -Filter "*.aas" -ErrorAction SilentlyContinue

                        foreach ($aasFile in $aasFiles) {
                            $content = Get-Content $aasFile.FullName -Raw -ErrorAction SilentlyContinue

                            if ($content -match $uncPattern) {
                                $server = $Matches[1]

                                if ($server -notmatch [regex]::Escape($currentDomain) -and
                                    $server -notmatch '^localhost$|^127\.|^::1$') {

                                    $findings += [PSCustomObject]@{
                                        GPOName             = $gpoName
                                        ReferenceType       = 'Software Installation'
                                        FilePath            = $aasFile.FullName
                                        ExternalServer      = $server
                                        CurrentDomain       = $currentDomain
                                        Severity            = 'High'
                                        Risk                = 'Software installation references external domain'
                                        Impact              = 'Malicious software could be installed from external source'
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "T-FileDeployedOutOfDomain: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Move all GPO-referenced files to local domain SYSVOL or approved internal shares. Remove dependencies on external domains.'
        Impact      = 'Medium - Requires relocating files and updating GPO references. May affect cross-domain administration.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# GPO External File References Remediation
#
# External references found:
$($Finding.Findings | ForEach-Object { "# - GPO: $($_.GPOName), Type: $($_.ReferenceType), Server: $($_.ExternalServer)" } | Out-String)

# Risks of external file references:
# 1. Trusted domain compromise affects this domain
# 2. Network issues prevent GPO from applying correctly
# 3. External admins can modify files affecting local systems
# 4. May violate security boundaries and compliance requirements

# STEP 1: Inventory all external references
Write-Host "Scanning all GPOs for external references..." -ForegroundColor Yellow

`$currentDomain = (Get-ADDomain).DNSRoot
`$gpoPath = "\\`$currentDomain\SYSVOL\`$currentDomain\Policies"

Get-ChildItem -Path `$gpoPath -Recurse -Include *.ini,*.xml -File | ForEach-Object {
    `$file = `$_
    `$content = Get-Content `$file.FullName -Raw -ErrorAction SilentlyContinue
    if (`$content -match '\\\\([^\\]+)\\') {
        `$server = `$Matches[1]
        if (`$server -notmatch `$currentDomain) {
            [PSCustomObject]@{
                GPOFile = `$file.FullName
                ExternalServer = `$server
            }
        }
    }
} | Format-Table -AutoSize

# STEP 2: Create local copies of external files
$($Finding.Findings | ForEach-Object { @"
# Copy files from $($_.ExternalServer) to local SYSVOL
# Source: $($_.ExternalPath)
`$localPath = "\\`$currentDomain\SYSVOL\`$currentDomain\scripts\$(($_.ExternalPath -split '\\')[-1])"

if (Test-Path "$($_.ExternalPath)") {
    Copy-Item -Path "$($_.ExternalPath)" -Destination `$localPath -Force
    Write-Host "Copied to `$localPath"
} else {
    Write-Host "WARNING: Source file not accessible: $($_.ExternalPath)" -ForegroundColor Yellow
}

"@ })

# STEP 3: Update GPO references to use local paths
# This must be done via GPMC or by editing the XML/INI files directly

# Example for scripts.ini:
# [Startup]
# 0CmdLine=\\externaldomain.com\share\script.ps1
#
# Change to:
# 0CmdLine=\\currentdomain.com\SYSVOL\currentdomain.com\scripts\script.ps1

# STEP 4: Update via GPMC (recommended)
# 1. Open GPMC (gpmc.msc)
# 2. Find the GPO with external reference
# 3. Edit the GPO
# 4. Navigate to the setting (Scripts, File deployment, etc.)
# 5. Update the path to local SYSVOL location
# 6. Save and test

# STEP 5: Verify no external references remain
Get-ChildItem -Path `$gpoPath -Recurse -Include *.ini,*.xml -File | ForEach-Object {
    `$content = Get-Content `$_.FullName -Raw -ErrorAction SilentlyContinue
    if (`$content -match '\\\\([^\\]+)\\' -and `$Matches[1] -notmatch `$currentDomain) {
        Write-Host "STILL HAS EXTERNAL REFERENCE: `$(`$_.FullName)" -ForegroundColor Red
    }
}

# STEP 6: If trust relationship required, document it
# External file references may be intentional in multi-domain environments
# Document the requirement and ensure:
# - The external domain has appropriate security controls
# - Network path is available and monitored
# - Changes to external files are audited

# STEP 7: Consider removing unnecessary trusts
# If external domain is no longer needed:
# Get-ADTrust -Filter * | Where-Object { `$_.Name -eq "externaldomain.com" }
# Remove-ADTrust -Identity "externaldomain.com" -Confirm

"@
            return $commands
        }
    }
}

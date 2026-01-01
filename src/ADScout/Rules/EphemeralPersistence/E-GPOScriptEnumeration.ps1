@{
    Id          = 'E-GPOScriptEnumeration'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'GPO Logon/Startup Scripts Detected'
    Description = 'Enumerates and analyzes scripts configured in Group Policy Objects. GPO scripts (logon, logoff, startup, shutdown) execute automatically and are a common persistence mechanism. This rule identifies all configured scripts and flags suspicious patterns like obfuscated scripts, scripts modified recently, or unusual script types.'
    Severity    = 'Medium'
    Weight      = 20

    References  = @(
        @{ Title = 'GPO Script Abuse'; Url = 'https://attack.mitre.org/techniques/T1037/001/' }
        @{ Title = 'Startup Script Persistence'; Url = 'https://attack.mitre.org/techniques/T1037/003/' }
        @{ Title = 'GPO Attacks'; Url = 'https://adsecurity.org/?p=2716' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002')  # Persistence, Execution
        Techniques = @('T1037.001', 'T1037.003', 'T1484.001')  # Logon Script, Startup Script, GPO Modification
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_gpo_scripts')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get SYSVOL path from a DC
        $sysvolPath = "\\$($Domain.Name)\SYSVOL\$($Domain.Name)\Policies"

        if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
            # Try alternate path
            $sysvolPath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies"
        }

        if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                GPOName       = 'N/A'
                GPOId         = 'N/A'
                ScriptType    = 'Error'
                ScriptPath    = $sysvolPath
                RiskLevel     = 'Unknown'
                RiskFactors   = 'Unable to access SYSVOL path'
                Impact        = 'Cannot enumerate GPO scripts - verify network access'
            })
        }

        # Script types to check
        $scriptTypes = @(
            @{ Type = 'User Logon';     Path = 'User\Scripts\Logon' }
            @{ Type = 'User Logoff';    Path = 'User\Scripts\Logoff' }
            @{ Type = 'Machine Startup'; Path = 'Machine\Scripts\Startup' }
            @{ Type = 'Machine Shutdown'; Path = 'Machine\Scripts\Shutdown' }
        )

        # Suspicious patterns
        $suspiciousPatterns = @(
            @{ Pattern = 'powershell.*-enc'; Description = 'Encoded PowerShell command' }
            @{ Pattern = 'powershell.*-e\s+'; Description = 'Encoded PowerShell (short flag)' }
            @{ Pattern = 'cmd.*\/c.*powershell'; Description = 'PowerShell via cmd.exe' }
            @{ Pattern = 'bypass|hidden|noprofile'; Description = 'PowerShell evasion flags' }
            @{ Pattern = 'iex|invoke-expression'; Description = 'Dynamic code execution' }
            @{ Pattern = 'downloadstring|downloadfile|webclient'; Description = 'Download and execute pattern' }
            @{ Pattern = 'base64|frombase64'; Description = 'Base64 encoding' }
            @{ Pattern = 'certutil.*-decode'; Description = 'Certutil decode (LOLBin)' }
            @{ Pattern = 'bitsadmin.*\/transfer'; Description = 'BITS transfer (LOLBin)' }
            @{ Pattern = 'mshta|wscript|cscript'; Description = 'Script host execution' }
            @{ Pattern = 'regsvr32|rundll32'; Description = 'Binary proxy execution' }
        )

        # Recent modification threshold
        $recentThreshold = (Get-Date).AddDays(-30)

        try {
            $gpoDirs = Get-ChildItem -Path $sysvolPath -Directory -ErrorAction SilentlyContinue

            foreach ($gpoDir in $gpoDirs) {
                $gpoId = $gpoDir.Name

                # Try to get GPO display name
                $gpoDisplayName = $gpoId
                try {
                    if (Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue) {
                        Import-Module GroupPolicy -ErrorAction SilentlyContinue
                        $gpo = Get-GPO -Guid $gpoId.Trim('{}') -ErrorAction SilentlyContinue
                        if ($gpo) {
                            $gpoDisplayName = $gpo.DisplayName
                        }
                    }
                }
                catch { }

                foreach ($scriptType in $scriptTypes) {
                    $scriptDir = Join-Path $gpoDir.FullName $scriptType.Path

                    if (Test-Path $scriptDir -ErrorAction SilentlyContinue) {
                        # Get all script files
                        $scripts = Get-ChildItem -Path $scriptDir -File -ErrorAction SilentlyContinue

                        foreach ($script in $scripts) {
                            $riskLevel = 'Low'
                            $riskFactors = @()

                            # Check file extension
                            $extension = $script.Extension.ToLower()
                            switch ($extension) {
                                '.ps1' {
                                    $riskLevel = 'Medium'
                                    $riskFactors += 'PowerShell script'
                                }
                                '.exe' {
                                    $riskLevel = 'High'
                                    $riskFactors += 'Executable binary'
                                }
                                { $_ -in @('.vbs', '.vbe', '.js', '.jse', '.wsf') } {
                                    $riskLevel = 'Medium'
                                    $riskFactors += 'Scripting language'
                                }
                            }

                            # Check modification time
                            if ($script.LastWriteTime -gt $recentThreshold) {
                                if ($riskLevel -ne 'High') { $riskLevel = 'Medium' }
                                $riskFactors += "Recently modified: $($script.LastWriteTime)"
                            }

                            # Check script content for suspicious patterns
                            if ($extension -in @('.ps1', '.bat', '.cmd', '.vbs', '.js')) {
                                try {
                                    $content = Get-Content $script.FullName -Raw -ErrorAction SilentlyContinue
                                    if ($content) {
                                        foreach ($pattern in $suspiciousPatterns) {
                                            if ($content -match $pattern.Pattern) {
                                                $riskLevel = 'High'
                                                $riskFactors += $pattern.Description
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }

                            # Machine startup scripts are higher risk (run as SYSTEM)
                            if ($scriptType.Type -like 'Machine*') {
                                if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                                $riskFactors += 'Runs as SYSTEM'
                            }

                            $findings += [PSCustomObject]@{
                                GPOName           = $gpoDisplayName
                                GPOId             = $gpoId
                                ScriptType        = $scriptType.Type
                                ScriptName        = $script.Name
                                ScriptPath        = $script.FullName
                                Extension         = $extension
                                Size              = $script.Length
                                LastModified      = $script.LastWriteTime
                                RiskLevel         = $riskLevel
                                RiskFactors       = ($riskFactors -join '; ')
                                AttackPath        = "Execute code via $($scriptType.Type) script"
                                Impact            = if ($scriptType.Type -like 'Machine*') {
                                    'Code execution as SYSTEM on domain computers'
                                } else {
                                    'Code execution in user context on logon'
                                }
                            }
                        }

                        # Also check scripts.ini and psscripts.ini
                        $iniFiles = @('scripts.ini', 'psscripts.ini')
                        foreach ($iniFile in $iniFiles) {
                            $iniPath = Join-Path $scriptDir $iniFile
                            if (Test-Path $iniPath -ErrorAction SilentlyContinue) {
                                try {
                                    $iniContent = Get-Content $iniPath -Raw -ErrorAction SilentlyContinue
                                    if ($iniContent) {
                                        # Parse for external script references
                                        $externalPaths = [regex]::Matches($iniContent, '\\\\[^\s\]]+')
                                        foreach ($match in $externalPaths) {
                                            $findings += [PSCustomObject]@{
                                                GPOName           = $gpoDisplayName
                                                GPOId             = $gpoId
                                                ScriptType        = "$($scriptType.Type) (INI Reference)"
                                                ScriptName        = $iniFile
                                                ScriptPath        = $match.Value
                                                Extension         = 'External Reference'
                                                Size              = 0
                                                LastModified      = (Get-Item $iniPath).LastWriteTime
                                                RiskLevel         = 'Medium'
                                                RiskFactors       = 'External script reference in INI file'
                                                AttackPath        = 'Execute external script via GPO'
                                                Impact            = 'Code execution from external location'
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{
                GPOName       = 'Error'
                GPOId         = 'N/A'
                ScriptType    = 'Error'
                ScriptPath    = $_.Exception.Message
                RiskLevel     = 'Unknown'
                RiskFactors   = "Enumeration error: $($_.Exception.Message)"
                Impact        = 'Unable to complete GPO script enumeration'
            }
        }

        # Sort by risk level
        $riskOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Unknown' = 4 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, GPOName

        return $findings
    }

    Remediation = @{
        Description = 'Review all GPO scripts for legitimacy. Remove unauthorized scripts. Implement change monitoring on SYSVOL script directories. Use Group Policy to restrict script execution policies.'
        Impact      = 'High - Removing GPO scripts may break legitimate automation. Test in non-production first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# GPO Script Enumeration Results
# Total scripts found: $($Finding.Findings.Count)
# High Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)
# Medium Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'Medium').Count)

# HIGH RISK scripts (investigate immediately):
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | ForEach-Object {
"# - [$($_.GPOName)] $($_.ScriptType): $($_.ScriptPath)"
"#   Risk: $($_.RiskFactors)"
} | Out-String)

# INVESTIGATION STEPS:

# 1. Review script contents:
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | ForEach-Object {
"Get-Content '$($_.ScriptPath)'"
} | Out-String)

# 2. Check GPO links to identify affected OUs:
foreach (`$gpoId in @('$($Finding.Findings.GPOId | Select-Object -Unique | ForEach-Object { $_.Trim('{}') } | Where-Object { $_ -ne 'N/A' -and $_ -ne 'Error' } -join "','")')) {
    `$gpo = Get-GPO -Guid `$gpoId -ErrorAction SilentlyContinue
    if (`$gpo) {
        Write-Host "`n`$(`$gpo.DisplayName):"
        (Get-GPOReport -Guid `$gpoId -ReportType Xml) | Select-String "LinksTo"
    }
}

# 3. Check script file permissions:
$($Finding.Findings | Select-Object -First 5 | ForEach-Object {
"Get-Acl '$($_.ScriptPath)' | Format-List"
} | Out-String)

# 4. Remove suspicious script (backup first!):
# Copy-Item "script.ps1" "script.ps1.bak"
# Remove-Item "script.ps1"

# 5. Enable SYSVOL change auditing:
# Configure "Audit Object Access" and SACL on SYSVOL

# 6. Monitor for GPO modifications:
# Event ID 5136 (Directory Service Changes)
# Event ID 4663 (File System audit on SYSVOL)

"@
            return $commands
        }
    }
}

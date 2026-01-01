@{
    Id          = 'E-TSPersistence'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'Terminal Services Initial Program Configured'
    Description = 'Detects user accounts with Terminal Services initial program (msTSInitialProgram) configured. This attribute specifies a program to run automatically when the user connects via RDP/Terminal Services. Attackers can abuse this for persistence by setting malicious executables that run on every RDP connection.'
    Severity    = 'High'
    Weight      = 25

    References  = @(
        @{ Title = 'TS Initial Program Abuse'; Url = 'https://attack.mitre.org/techniques/T1547/' }
        @{ Title = 'RDP Persistence'; Url = 'https://pentestlab.blog/2019/10/01/persistence-rdp/' }
        @{ Title = 'Terminal Services Configuration'; Url = 'https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-configuration' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0002')  # Persistence, Execution
        Techniques = @('T1547', 'T1021.001')  # Boot or Logon Autostart, Remote Desktop Protocol
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_ts_persistence')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Privileged group patterns
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Remote Desktop Users'
        )

        # Known legitimate TS programs
        $legitimatePrograms = @(
            'explorer.exe',
            '%SystemRoot%\explorer.exe',
            'C:\Windows\explorer.exe',
            '%windir%\explorer.exe'
        )

        # Suspicious patterns
        $suspiciousPatterns = @(
            @{ Pattern = '\.ps1|powershell'; Desc = 'PowerShell script/command' }
            @{ Pattern = '\.bat|\.cmd|cmd\.exe'; Desc = 'Batch file or command prompt' }
            @{ Pattern = '\.vbs|\.vbe|wscript|cscript'; Desc = 'VBScript' }
            @{ Pattern = '\\temp\\|\\tmp\\|%temp%'; Desc = 'Temp directory path' }
            @{ Pattern = '\\appdata\\|%appdata%'; Desc = 'AppData directory' }
            @{ Pattern = '\\users\\public\\|%public%'; Desc = 'Public directory' }
            @{ Pattern = 'mshta|rundll32|regsvr32'; Desc = 'LOLBin execution' }
            @{ Pattern = '-enc|-e\s|bypass|hidden'; Desc = 'PowerShell evasion' }
            @{ Pattern = 'http:|https:|ftp:'; Desc = 'URL reference' }
            @{ Pattern = '^\\\\'; Desc = 'UNC path execution' }
        )

        foreach ($user in $Data) {
            # Check TSInitialProgram
            if ([string]::IsNullOrWhiteSpace($user.TSInitialProgram)) {
                continue
            }

            $program = $user.TSInitialProgram.Trim()
            $riskLevel = 'Medium'
            $riskFactors = @()

            # Check if it's a known legitimate program
            $isLegitimate = $false
            foreach ($legit in $legitimatePrograms) {
                if ($program -eq $legit -or $program -like "*$legit") {
                    $isLegitimate = $true
                    $riskLevel = 'Low'
                    $riskFactors += 'Known legitimate program'
                    break
                }
            }

            if (-not $isLegitimate) {
                $riskFactors += 'Non-standard TS initial program'

                # Check for suspicious patterns
                foreach ($pattern in $suspiciousPatterns) {
                    if ($program -match $pattern.Pattern) {
                        $riskLevel = 'High'
                        $riskFactors += $pattern.Desc
                    }
                }
            }

            # Check if user is privileged
            $isPrivileged = $false
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
                $riskFactors += 'Privileged account'
                if ($riskLevel -ne 'High') { $riskLevel = 'High' }
            }

            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match [regex]::Escape($privGroup)) {
                            $isPrivileged = $true
                            if ($privGroup -eq 'Remote Desktop Users') {
                                $riskFactors += 'RDP access enabled'
                            }
                            else {
                                $riskFactors += "Member of $privGroup"
                                if ($riskLevel -ne 'High') { $riskLevel = 'High' }
                            }
                            break
                        }
                    }
                }
            }

            # Check TS home directory too
            $tsHomePath = $null
            if (-not [string]::IsNullOrWhiteSpace($user.TSHomeDirectory)) {
                $tsHomePath = $user.TSHomeDirectory
                if ($tsHomePath -match '^\\\\') {
                    $riskFactors += "TS home directory: $tsHomePath"
                }
            }

            # Check TS work directory
            if (-not [string]::IsNullOrWhiteSpace($user.TSWorkDirectory)) {
                if ($user.TSWorkDirectory -match '^\\\\') {
                    $riskFactors += "TS work directory (UNC): $($user.TSWorkDirectory)"
                }
            }

            # Recently changed
            $recentThreshold = (Get-Date).AddDays(-7)
            if ($user.WhenChanged -and $user.WhenChanged -gt $recentThreshold) {
                $riskFactors += "Recently modified: $($user.WhenChanged)"
                if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
            }

            $findings += [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                TSInitialProgram  = $program
                TSWorkDirectory   = $user.TSWorkDirectory
                TSHomeDirectory   = $user.TSHomeDirectory
                TSHomeDrive       = $user.TSHomeDrive
                IsPrivileged      = $isPrivileged
                RiskLevel         = $riskLevel
                RiskFactors       = ($riskFactors -join '; ')
                Enabled           = $user.Enabled
                WhenChanged       = $user.WhenChanged
                AttackPath        = 'Execute arbitrary code on RDP connection'
                Impact            = 'Code execution in user context on every RDP session'
            }
        }

        # Sort by risk level
        $riskOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, SamAccountName

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove unnecessary Terminal Services initial programs. Clear msTSInitialProgram attribute for affected accounts. Implement monitoring for changes to TS attributes.'
        Impact      = 'Low - Clearing TS initial program returns users to default explorer shell.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Terminal Services Initial Program Analysis
# Total accounts with TS programs: $($Finding.Findings.Count)
# High Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)
# Medium Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'Medium').Count)

# HIGH RISK - Investigate immediately:
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | ForEach-Object {
"# - $($_.SamAccountName): $($_.TSInitialProgram)"
"#   Risk: $($_.RiskFactors)"
} | Out-String)

# INVESTIGATION STEPS:

# 1. Query all TS attributes for affected users:
foreach (`$user in @('$($Finding.Findings.SamAccountName -join "','")')) {
    Get-ADUser `$user -Properties msTSInitialProgram, msTSWorkDirectory, msTSHomeDirectory, msTSHomeDrive |
        Select-Object SamAccountName, msTSInitialProgram, msTSWorkDirectory, msTSHomeDirectory
}

# 2. Check if the program exists and its properties:
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | Select-Object -First 3 | ForEach-Object {
"`$path = '$($_.TSInitialProgram)'"
"if (Test-Path `$path) { Get-Item `$path | Select-Object FullName, LastWriteTime, Length }"
} | Out-String)

# 3. To CLEAR Terminal Services initial program:
# Set-ADUser -Identity "username" -Clear msTSInitialProgram

# 4. To clear all TS settings:
# Set-ADUser -Identity "username" -Clear msTSInitialProgram, msTSWorkDirectory, msTSHomeDirectory, msTSHomeDrive

# 5. Bulk clear for all high-risk accounts:
# `$highRiskUsers = @('$($Finding.Findings | Where-Object RiskLevel -eq 'High' | Select-Object -ExpandProperty SamAccountName -join "','")')
# foreach (`$user in `$highRiskUsers) {
#     Set-ADUser -Identity `$user -Clear msTSInitialProgram
# }

# 6. Monitor for TS attribute changes:
# Event ID 5136 with attributes: msTSInitialProgram, msTSWorkDirectory, etc.

# NOTE: Legitimate use cases for TS initial programs:
# - Kiosk mode applications
# - Published applications
# - Custom shells for specific roles
# Verify with application owners before removing

"@
            return $commands
        }
    }
}

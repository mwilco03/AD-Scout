@{
    Id          = 'E-LoginScript'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'User Login Script Configured'
    Description = 'Detects user accounts with the scriptPath attribute configured. Login scripts execute automatically when users log on, making them an attractive persistence mechanism for attackers. Scripts pointing to non-standard locations, recently modified paths, or scripts on privileged accounts are high-risk indicators.'
    Severity    = 'Medium'
    Weight      = 20

    References  = @(
        @{ Title = 'Logon Scripts'; Url = 'https://attack.mitre.org/techniques/T1037/001/' }
        @{ Title = 'AD Persistence'; Url = 'https://adsecurity.org/?p=2288' }
        @{ Title = 'Login Script Abuse'; Url = 'https://www.thehacker.recipes/ad/persistence/logon-script' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1037.001')  # Boot or Logon Initialization Scripts: Logon Script (Windows)
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_logon_scripts')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Known suspicious script extensions
        $executableExtensions = @('.exe', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.msc')

        # Privileged group patterns
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators'
        )

        foreach ($user in $Data) {
            if ([string]::IsNullOrWhiteSpace($user.ScriptPath)) {
                continue
            }

            $scriptPath = $user.ScriptPath.Trim()
            $riskLevel = 'Low'
            $riskFactors = @()

            # Check if user is privileged
            $isPrivileged = $false
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
                $riskFactors += 'Privileged account (AdminCount=1)'
            }

            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match [regex]::Escape($privGroup)) {
                            $isPrivileged = $true
                            $riskFactors += "Member of $privGroup"
                            break
                        }
                    }
                }
            }

            # Check for UNC paths (potential lateral movement)
            if ($scriptPath -match '^\\\\') {
                # UNC path
                $uncHost = ($scriptPath -split '\\')[2]

                # Check if it's pointing to a non-domain location
                if ($uncHost -and $Domain.Name -and $uncHost -notmatch [regex]::Escape($Domain.Name)) {
                    $riskLevel = 'High'
                    $riskFactors += "UNC path to external host: $uncHost"
                }
                else {
                    # Check if pointing outside NETLOGON
                    if ($scriptPath -notmatch '\\NETLOGON\\' -and $scriptPath -notmatch '\\SYSVOL\\') {
                        $riskLevel = 'Medium'
                        $riskFactors += 'UNC path outside NETLOGON/SYSVOL'
                    }
                }
            }

            # Check for absolute local paths (unusual)
            if ($scriptPath -match '^[A-Za-z]:\\') {
                $riskLevel = 'High'
                $riskFactors += 'Absolute local path (unusual for domain logon scripts)'
            }

            # Check for suspicious extensions
            $extension = [System.IO.Path]::GetExtension($scriptPath).ToLower()
            if ($extension -in @('.ps1', '.exe', '.vbs', '.vbe')) {
                if ($riskLevel -ne 'High') { $riskLevel = 'Medium' }
                $riskFactors += "Executable script type: $extension"
            }

            # Elevate risk for privileged accounts
            if ($isPrivileged) {
                if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                elseif ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
            }

            # Check for recently changed accounts (potential compromise indicator)
            $recentThreshold = (Get-Date).AddDays(-7)
            if ($user.WhenChanged -and $user.WhenChanged -gt $recentThreshold) {
                $riskFactors += "Account modified recently: $($user.WhenChanged)"
                if ($riskLevel -ne 'High') { $riskLevel = 'Medium' }
            }

            $findings += [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                ScriptPath        = $scriptPath
                IsPrivileged      = $isPrivileged
                RiskLevel         = $riskLevel
                RiskFactors       = ($riskFactors -join '; ')
                Enabled           = $user.Enabled
                WhenChanged       = $user.WhenChanged
                AttackPath        = 'Execute code on user logon'
                Impact            = 'Code execution in user context, potential lateral movement'
            }
        }

        # Sort by risk level for prioritization
        $riskOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, SamAccountName

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove unnecessary login scripts. Ensure all legitimate scripts are stored in NETLOGON share and properly secured. Monitor for unauthorized script modifications.'
        Impact      = 'Low - Removing login scripts may affect user experience if scripts perform legitimate functions like drive mappings.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Review Login Script Findings
# Total accounts with login scripts: $($Finding.Findings.Count)
# High Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)
# Medium Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'Medium').Count)

# HIGH RISK - Investigate immediately:
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | ForEach-Object { "# - $($_.SamAccountName): $($_.ScriptPath) - $($_.RiskFactors)" } | Out-String)

# REMEDIATION STEPS:

# 1. Review each script path for legitimacy
foreach (`$user in @('$($Finding.Findings.SamAccountName -join "','")')) {
    `$adUser = Get-ADUser `$user -Properties ScriptPath, WhenChanged
    Write-Host "`$(`$adUser.SamAccountName): `$(`$adUser.ScriptPath)"
}

# 2. To remove a login script:
# Set-ADUser -Identity "username" -ScriptPath `$null

# 3. To move scripts to NETLOGON (proper location):

# 4. Audit NETLOGON share permissions:
# Get-Acl "\\$($Domain.Name)\NETLOGON" | Format-List

# 5. Enable auditing on script modifications:
# Configure "Audit Object Access" in GPO for NETLOGON share

# 6. Monitor for changes using PowerShell:
# Get-ADUser -Filter {ScriptPath -like '*'} -Properties ScriptPath, WhenChanged |
#     Where-Object { `$_.WhenChanged -gt (Get-Date).AddDays(-7) }

"@
            return $commands
        }
    }
}

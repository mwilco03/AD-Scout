@{
    Id          = 'E-ProfilePathAbuse'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'Suspicious Profile or Home Directory Path'
    Description = 'Detects user accounts with profile paths or home directories pointing to potentially malicious locations. Roaming profiles and home directories can be abused to deliver malicious payloads (via ntuser.dat, startup folder, or shortcut files). External UNC paths or unusual locations are high-risk indicators.'
    Severity    = 'Medium'
    Weight      = 20

    References  = @(
        @{ Title = 'Profile Path Abuse'; Url = 'https://attack.mitre.org/techniques/T1547/001/' }
        @{ Title = 'Roaming Profile Attacks'; Url = 'https://www.harmj0y.net/blog/redteaming/abusing-group-policy-for-lateral-movement/' }
        @{ Title = 'Home Folder Persistence'; Url = 'https://pentestlab.blog/2019/10/01/persistence-shortcut-modification/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0008')  # Persistence, Lateral Movement
        Techniques = @('T1547.001', 'T1039')  # Boot or Logon Autostart: Registry Run Keys, Network Share Discovery
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_profile_paths')

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
            'Account Operators',
            'Backup Operators'
        )

        foreach ($user in $Data) {
            # Check both ProfilePath and HomeDirectory
            $pathsToCheck = @()

            if (-not [string]::IsNullOrWhiteSpace($user.ProfilePath)) {
                $pathsToCheck += @{
                    Type = 'ProfilePath'
                    Path = $user.ProfilePath.Trim()
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($user.HomeDirectory)) {
                $pathsToCheck += @{
                    Type = 'HomeDirectory'
                    Path = $user.HomeDirectory.Trim()
                }
            }

            if ($pathsToCheck.Count -eq 0) {
                continue
            }

            # Check if user is privileged
            $isPrivileged = $false
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
            }
            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match [regex]::Escape($privGroup)) {
                            $isPrivileged = $true
                            break
                        }
                    }
                }
            }

            foreach ($pathInfo in $pathsToCheck) {
                $path = $pathInfo.Path
                $pathType = $pathInfo.Type
                $riskLevel = 'Low'
                $riskFactors = @()

                # Check for UNC paths
                if ($path -match '^\\\\([^\\]+)\\') {
                    $uncHost = $matches[1]

                    # Check if pointing to external domain
                    $domainName = if ($Domain.Name) { $Domain.Name } elseif ($Domain.DNSRoot) { $Domain.DNSRoot } else { '' }

                    if ($domainName -and $uncHost -notmatch [regex]::Escape($domainName)) {
                        # Could be external - check if it looks like an IP
                        if ($uncHost -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                            $riskLevel = 'High'
                            $riskFactors += "UNC path to IP address: $uncHost"
                        }
                        elseif ($uncHost -match '\.') {
                            # Contains dots - might be external FQDN
                            $riskLevel = 'High'
                            $riskFactors += "UNC path to external host: $uncHost"
                        }
                        else {
                            $riskLevel = 'Medium'
                            $riskFactors += "UNC path to non-domain host: $uncHost"
                        }
                    }
                    else {
                        $riskFactors += "UNC path: $uncHost"
                    }

                    # Check for non-standard shares
                    if ($path -notmatch '\\(profiles|users|home|shares|dfs)\$?\\' -and
                        $path -notmatch '\\NETLOGON\\' -and
                        $path -notmatch '\\SYSVOL\\') {
                        if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                        $riskFactors += 'Non-standard share path'
                    }
                }

                # Check for local paths (unusual for domain users)
                if ($path -match '^[A-Za-z]:\\') {
                    $riskLevel = 'Medium'
                    $riskFactors += 'Local path configured (unusual for domain profiles)'
                }

                # Check for suspicious path components
                $suspiciousPatterns = @(
                    @{ Pattern = '\\temp\\|\\tmp\\'; Desc = 'Temp directory' }
                    @{ Pattern = '\\appdata\\'; Desc = 'AppData directory' }
                    @{ Pattern = '\\public\\'; Desc = 'Public directory' }
                    @{ Pattern = 'c\$|admin\$'; Desc = 'Administrative share' }
                    @{ Pattern = '\.exe|\.dll|\.bat|\.ps1'; Desc = 'Executable extension in path' }
                )

                foreach ($pattern in $suspiciousPatterns) {
                    if ($path -match $pattern.Pattern) {
                        if ($riskLevel -ne 'High') { $riskLevel = 'Medium' }
                        $riskFactors += $pattern.Desc
                    }
                }

                # Privileged accounts with UNC paths are higher risk
                if ($isPrivileged -and $path -match '^\\\\') {
                    if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                    if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
                    $riskFactors += 'Privileged account with UNC path'
                }

                # Recently changed accounts
                $recentThreshold = (Get-Date).AddDays(-7)
                if ($user.WhenChanged -and $user.WhenChanged -gt $recentThreshold) {
                    $riskFactors += "Recently modified: $($user.WhenChanged)"
                    if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                }

                # Only report if there are risk factors beyond just having a path
                if ($riskFactors.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        SamAccountName    = $user.SamAccountName
                        DistinguishedName = $user.DistinguishedName
                        PathType          = $pathType
                        Path              = $path
                        HomeDrive         = $user.HomeDrive
                        IsPrivileged      = $isPrivileged
                        RiskLevel         = $riskLevel
                        RiskFactors       = ($riskFactors -join '; ')
                        Enabled           = $user.Enabled
                        WhenChanged       = $user.WhenChanged
                        AttackPath        = if ($pathType -eq 'ProfilePath') {
                            'Plant malicious ntuser.dat or startup items in profile'
                        } else {
                            'Plant malicious shortcuts or startup items in home folder'
                        }
                        Impact            = 'Code execution on user logon, credential theft'
                    }
                }
            }
        }

        # Sort by risk level
        $riskOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, SamAccountName

        return $findings
    }

    Remediation = @{
        Description = 'Review and validate all profile and home directory paths. Remove paths pointing to external or suspicious locations. Implement monitoring on profile path attribute changes.'
        Impact      = 'Medium - Changing profile paths requires user data migration. Test thoroughly.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Profile/Home Directory Path Analysis
# Total suspicious paths: $($Finding.Findings.Count)
# High Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)
# Medium Risk: $(($Finding.Findings | Where-Object RiskLevel -eq 'Medium').Count)

# HIGH RISK - External or IP-based paths (investigate immediately):
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | ForEach-Object {
"# - $($_.SamAccountName): $($_.PathType) = $($_.Path)"
"#   Risk: $($_.RiskFactors)"
} | Out-String)

# INVESTIGATION STEPS:

# 1. Verify path accessibility and contents:
$($Finding.Findings | Where-Object RiskLevel -eq 'High' | Select-Object -First 5 | ForEach-Object {
"Test-Path '$($_.Path)'"
"Get-ChildItem '$($_.Path)' -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime"
} | Out-String)

# 2. Check for malicious items in profiles:
# Look for: ntuser.dat (modified recently), Startup folder items, .lnk files

# 3. Query users with external profile paths:
Get-ADUser -Filter {ProfilePath -like '*'} -Properties ProfilePath, WhenChanged |
    Where-Object { `$_.ProfilePath -match '^\\\\' } |
    Select-Object SamAccountName, ProfilePath, WhenChanged

# 4. To clear a profile path:
# Set-ADUser -Identity "username" -ProfilePath `$null

# 5. To set a proper internal path:
# Set-ADUser -Identity "username" -ProfilePath "\\fileserver\profiles\username"

# 6. Monitor for profile path changes:
# Event ID 5136 with attributes: profilePath, homeDirectory

# PROFILE PATH ATTACKS TO LOOK FOR:
# - Modified ntuser.dat (registry hive - can contain Run keys)
# - Shell:startup folder items
# - Malicious .lnk shortcuts
# - DLL search order hijacking in profile paths

"@
            return $commands
        }
    }
}

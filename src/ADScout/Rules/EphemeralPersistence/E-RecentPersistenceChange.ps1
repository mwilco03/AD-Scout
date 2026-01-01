@{
    Id          = 'E-RecentPersistenceChange'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'Recent Persistence-Related Attribute Changes'
    Description = 'Detects user accounts where persistence-related attributes (scriptPath, profilePath, homeDirectory, msTSInitialProgram, msDS-KeyCredentialLink) were modified recently. Recent changes to these attributes may indicate an active attack or unauthorized modification. This rule correlates account modification times with the presence of persistence attributes.'
    Severity    = 'High'
    Weight      = 25

    References  = @(
        @{ Title = 'AD Persistence Detection'; Url = 'https://attack.mitre.org/tactics/TA0003/' }
        @{ Title = 'Detecting AD Attacks'; Url = 'https://adsecurity.org/?p=1772' }
        @{ Title = 'AD Change Monitoring'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion
        Techniques = @('T1037.001', 'T1556.005', 'T1547')  # Logon Script, Modify Auth Process, Boot/Logon Autostart
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_recent_changes')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Time thresholds
        $criticalThreshold = (Get-Date).AddDays(-1)   # Last 24 hours
        $highThreshold = (Get-Date).AddDays(-7)       # Last 7 days
        $mediumThreshold = (Get-Date).AddDays(-30)    # Last 30 days

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
            # Skip if no persistence attributes are set
            $hasPersistenceAttrib = $false
            $persistenceAttribs = @()

            if (-not [string]::IsNullOrWhiteSpace($user.ScriptPath)) {
                $hasPersistenceAttrib = $true
                $persistenceAttribs += "ScriptPath: $($user.ScriptPath)"
            }

            if (-not [string]::IsNullOrWhiteSpace($user.ProfilePath)) {
                $hasPersistenceAttrib = $true
                $persistenceAttribs += "ProfilePath: $($user.ProfilePath)"
            }

            if (-not [string]::IsNullOrWhiteSpace($user.HomeDirectory)) {
                $hasPersistenceAttrib = $true
                $persistenceAttribs += "HomeDirectory: $($user.HomeDirectory)"
            }

            if (-not [string]::IsNullOrWhiteSpace($user.TSInitialProgram)) {
                $hasPersistenceAttrib = $true
                $persistenceAttribs += "TSInitialProgram: $($user.TSInitialProgram)"
            }

            if ($user.KeyCredentialLink -and @($user.KeyCredentialLink | Where-Object { $_ }).Count -gt 0) {
                $hasPersistenceAttrib = $true
                $keyCount = @($user.KeyCredentialLink | Where-Object { $_ }).Count
                $persistenceAttribs += "KeyCredentialLink: $keyCount credential(s)"
            }

            if (-not $hasPersistenceAttrib) {
                continue
            }

            # Check modification time
            if (-not $user.WhenChanged) {
                continue
            }

            $modTime = $user.WhenChanged
            $riskLevel = 'Low'
            $urgency = ''

            if ($modTime -gt $criticalThreshold) {
                $riskLevel = 'Critical'
                $urgency = 'Modified in last 24 hours'
            }
            elseif ($modTime -gt $highThreshold) {
                $riskLevel = 'High'
                $urgency = 'Modified in last 7 days'
            }
            elseif ($modTime -gt $mediumThreshold) {
                $riskLevel = 'Medium'
                $urgency = 'Modified in last 30 days'
            }
            else {
                # Older than 30 days - likely legitimate, skip
                continue
            }

            $riskFactors = @()
            $riskFactors += $urgency
            $riskFactors += "Persistence attributes: $($persistenceAttribs.Count)"

            # Check if user is privileged
            $isPrivileged = $false
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
                $riskFactors += 'Privileged account (AdminCount=1)'
                # Elevate risk for privileged accounts
                if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
                if ($riskLevel -eq 'High') { $riskLevel = 'Critical' }
            }

            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match [regex]::Escape($privGroup)) {
                            $isPrivileged = $true
                            $riskFactors += "Member of $privGroup"
                            if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
                            if ($riskLevel -eq 'High') { $riskLevel = 'Critical' }
                            break
                        }
                    }
                }
            }

            # Check for service accounts (more suspicious)
            if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                $riskFactors += 'Service account with SPN'
                if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
            }

            if ($user.SamAccountName -match '^(svc|service|app|sql|iis)[-_]') {
                $riskFactors += 'Service account naming pattern'
            }

            # Check for new accounts with persistence (very suspicious)
            if ($user.WhenCreated) {
                $createdRecently = $user.WhenCreated -gt $mediumThreshold
                $createdAndModifiedClose = ($modTime - $user.WhenCreated).TotalHours -lt 24

                if ($createdRecently) {
                    $riskFactors += "New account (created: $($user.WhenCreated))"
                    if ($riskLevel -ne 'Critical') { $riskLevel = 'High' }
                }

                if ($createdAndModifiedClose) {
                    $riskFactors += 'Persistence added shortly after account creation'
                    $riskLevel = 'Critical'
                }
            }

            # Check for disabled accounts (could be reactivation prep)
            if ($user.Enabled -eq $false) {
                $riskFactors += 'Disabled account with persistence attributes'
                if ($riskLevel -eq 'Medium') { $riskLevel = 'High' }
            }

            $findings += [PSCustomObject]@{
                SamAccountName        = $user.SamAccountName
                DistinguishedName     = $user.DistinguishedName
                WhenCreated           = $user.WhenCreated
                WhenChanged           = $modTime
                DaysSinceChange       = [math]::Round(((Get-Date) - $modTime).TotalDays, 1)
                PersistenceAttributes = ($persistenceAttribs -join '; ')
                IsPrivileged          = $isPrivileged
                Enabled               = $user.Enabled
                RiskLevel             = $riskLevel
                RiskFactors           = ($riskFactors -join '; ')
                AttackPath            = 'Recently configured persistence mechanism'
                Impact                = 'Active compromise indicator - immediate investigation required'
            }
        }

        # Sort by risk level and recency
        $riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, WhenChanged -Descending

        return $findings
    }

    Remediation = @{
        Description = 'Investigate recent changes to persistence-related attributes. Correlate with security logs to identify the source of changes. Remove unauthorized persistence mechanisms and reset compromised accounts.'
        Impact      = 'High - This may indicate an active attack. Coordinate with incident response.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ALERT: Recent Persistence-Related Changes Detected
# This may indicate an active attack - investigate immediately!

# Total accounts with recent changes: $($Finding.Findings.Count)
# Critical (last 24h): $(($Finding.Findings | Where-Object RiskLevel -eq 'Critical').Count)
# High (last 7 days): $(($Finding.Findings | Where-Object RiskLevel -eq 'High').Count)

# CRITICAL - Changes in last 24 hours (INVESTIGATE NOW):
$($Finding.Findings | Where-Object RiskLevel -eq 'Critical' | ForEach-Object {
"# - $($_.SamAccountName) [Changed: $($_.WhenChanged)]"
"#   Attributes: $($_.PersistenceAttributes)"
"#   Risk: $($_.RiskFactors)"
""
} | Out-String)

# IMMEDIATE INVESTIGATION STEPS:

# 1. Get detailed change information from AD replication metadata:
foreach (`$user in @('$($Finding.Findings | Where-Object RiskLevel -eq 'Critical' | Select-Object -First 5 -ExpandProperty SamAccountName | Where-Object { $_ } -join "','")')) {
    Write-Host "`n=== `$user ===" -ForegroundColor Yellow
    Get-ADReplicationAttributeMetadata -Object (Get-ADUser `$user).DistinguishedName -Server (Get-ADDomainController).HostName |
        Where-Object { `$_.AttributeName -in @('scriptPath', 'profilePath', 'homeDirectory', 'msTSInitialProgram', 'msDS-KeyCredentialLink') } |
        Select-Object AttributeName, LastOriginatingChangeTime, LastOriginatingChangeDirectoryServerIdentity, Version
}

# 2. Check Security Event Logs for the change source:
# Event ID 5136 (Directory Service Changes)
# Event ID 4738 (User Account Changed)

`$criticalUsers = @('$($Finding.Findings | Where-Object RiskLevel -eq 'Critical' | Select-Object -ExpandProperty SamAccountName -join "','")').Split(',')
`$startTime = (Get-Date).AddDays(-1)

# On Domain Controller:
# Get-WinEvent -FilterHashtable @{
#     LogName = 'Security'
#     ID = 5136, 4738
#     StartTime = `$startTime
# } | Where-Object { `$criticalUsers -contains (`$_.Properties[1].Value) }

# 3. Check who made the changes (requires advanced auditing):
# The LastOriginatingChangeDirectoryServerIdentity shows which DC processed the change
# Cross-reference with authentication logs on that DC

# 4. Collect evidence before remediation:
foreach (`$user in `$criticalUsers) {
    `$adUser = Get-ADUser `$user -Properties *
    `$adUser | Select-Object * | ConvertTo-Json | Out-File "Evidence_`$user_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
}

# 5. Disable affected accounts (if confirmed compromise):
# Disable-ADAccount -Identity "username"

# 6. Remove persistence attributes:
# Set-ADUser -Identity "username" -Clear scriptPath, profilePath, msTSInitialProgram
# Set-ADUser -Identity "username" -Clear 'msDS-KeyCredentialLink'

# 7. Force password reset:
# Set-ADAccountPassword -Identity "username" -Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force)
# Set-ADUser -Identity "username" -ChangePasswordAtLogon `$true

# INCIDENT RESPONSE CHECKLIST:
# [ ] Document timeline of changes
# [ ] Identify source of changes (user/system that made the change)
# [ ] Check for lateral movement from source
# [ ] Preserve evidence before remediation
# [ ] Disable compromised accounts
# [ ] Reset credentials
# [ ] Hunt for additional persistence
# [ ] Notify security team / incident response

"@
            return $commands
        }
    }
}

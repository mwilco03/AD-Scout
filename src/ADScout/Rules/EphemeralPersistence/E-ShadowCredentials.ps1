@{
    Id          = 'E-ShadowCredentials'
    Version     = '1.0.0'
    Category    = 'EphemeralPersistence'
    Title       = 'Shadow Credentials Detected (msDS-KeyCredentialLink)'
    Description = 'Detects accounts with msDS-KeyCredentialLink attribute populated. This attribute enables certificate-based authentication (Windows Hello for Business) but can be abused by attackers to add rogue credentials and take over accounts without knowing the password. This is a critical persistence and privilege escalation technique.'
    Severity    = 'Critical'
    Weight      = 35

    References  = @(
        @{ Title = 'Shadow Credentials Attack'; Url = 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab' }
        @{ Title = 'Whisker Tool'; Url = 'https://github.com/eladshamir/Whisker' }
        @{ Title = 'PyWhisker'; Url = 'https://github.com/ShutdownRepo/pywhisker' }
        @{ Title = 'Key Trust Account Mapping'; Url = 'https://attack.mitre.org/techniques/T1556/005/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004', 'TA0006')  # Persistence, Privilege Escalation, Credential Access
        Techniques = @('T1556.005', 'T1098.001')  # Modify Authentication Process: Reversible Encryption, Account Manipulation: Additional Cloud Credentials
    }

    CIS   = @('5.1', '5.6')  # Account Management, PKI Certificate policies
    STIG  = @('V-36435', 'V-36432')  # AD object permissions, Privileged account protection
    ANSSI = @('vuln1_shadow_credentials')

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
            'Backup Operators',
            'Server Operators',
            'Domain Controllers',
            'Key Admins',
            'Enterprise Key Admins'
        )

        foreach ($user in $Data) {
            # Check if KeyCredentialLink has any entries
            if (-not $user.KeyCredentialLink -or $user.KeyCredentialLink.Count -eq 0) {
                continue
            }

            # Filter out empty entries
            $keyCredentials = @($user.KeyCredentialLink | Where-Object { $_ -and $_.Length -gt 0 })
            if ($keyCredentials.Count -eq 0) {
                continue
            }

            $riskLevel = 'High'
            $riskFactors = @()

            # Count credentials
            $credCount = $keyCredentials.Count
            $riskFactors += "Key credentials present: $credCount"

            # Multiple key credentials is suspicious
            if ($credCount -gt 1) {
                $riskLevel = 'Critical'
                $riskFactors += "Multiple key credentials ($credCount) - unusual"
            }

            # Check if user is privileged
            $isPrivileged = $false
            if ($user.AdminCount -eq 1) {
                $isPrivileged = $true
                $riskLevel = 'Critical'
                $riskFactors += 'Privileged account (AdminCount=1)'
            }

            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match [regex]::Escape($privGroup)) {
                            $isPrivileged = $true
                            $riskLevel = 'Critical'
                            $riskFactors += "Member of $privGroup"
                            break
                        }
                    }
                }
            }

            # Check for service accounts (based on naming convention or SPN)
            $isServiceAccount = $false
            if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                $isServiceAccount = $true
                $riskFactors += 'Service account with SPN'
            }

            if ($user.SamAccountName -match '^(svc|service|app|sql|iis)[-_]') {
                $isServiceAccount = $true
                $riskFactors += 'Service account naming pattern'
            }

            # Service accounts with key credentials are highly suspicious
            if ($isServiceAccount) {
                $riskLevel = 'Critical'
                $riskFactors += 'Service accounts rarely use Windows Hello'
            }

            # Recently changed accounts are more suspicious
            $recentThreshold = (Get-Date).AddDays(-30)
            if ($user.WhenChanged -and $user.WhenChanged -gt $recentThreshold) {
                $riskFactors += "Recently modified: $($user.WhenChanged)"
            }

            # Try to decode key credential info (basic parsing)
            $keyInfo = @()
            foreach ($keyCred in $keyCredentials) {
                try {
                    # Key credentials are binary, but we can detect their presence
                    if ($keyCred -is [byte[]]) {
                        $keyInfo += "Binary key credential ($(($keyCred).Length) bytes)"
                    }
                    else {
                        $keyInfo += "Key credential present"
                    }
                }
                catch {
                    $keyInfo += "Key credential (unable to parse)"
                }
            }

            $findings += [PSCustomObject]@{
                SamAccountName        = $user.SamAccountName
                DistinguishedName     = $user.DistinguishedName
                KeyCredentialCount    = $credCount
                KeyCredentialInfo     = ($keyInfo -join '; ')
                IsPrivileged          = $isPrivileged
                IsServiceAccount      = $isServiceAccount
                RiskLevel             = $riskLevel
                RiskFactors           = ($riskFactors -join '; ')
                Enabled               = $user.Enabled
                WhenChanged           = $user.WhenChanged
                AttackPath            = 'Authenticate as user without password via PKINIT'
                Impact                = 'Complete account takeover, persistent access without password knowledge'
            }
        }

        # Sort by risk level
        $riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $findings = $findings | Sort-Object { $riskOrder[$_.RiskLevel] }, SamAccountName

        return $findings
    }

    Remediation = @{
        Description = 'Investigate all accounts with msDS-KeyCredentialLink entries. Remove unauthorized key credentials. Implement monitoring for changes to this attribute. Consider restricting who can modify this attribute via ACLs.'
        Impact      = 'Medium - Removing legitimate Windows Hello for Business credentials will require users to re-enroll.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Shadow Credentials Investigation
# CRITICAL: Accounts with msDS-KeyCredentialLink entries detected
# Total: $($Finding.Findings.Count)

# CRITICAL RISK accounts (investigate IMMEDIATELY):
$($Finding.Findings | Where-Object RiskLevel -eq 'Critical' | ForEach-Object {
"# - $($_.SamAccountName) [$($_.KeyCredentialCount) keys] - $($_.RiskFactors)"
} | Out-String)

# INVESTIGATION STEPS:

# 1. List all key credentials for a user:
foreach (`$user in @('$($Finding.Findings.SamAccountName -join "','")')) {
    `$obj = Get-ADUser `$user -Properties 'msDS-KeyCredentialLink'
    Write-Host "`n`$user has `$((`$obj.'msDS-KeyCredentialLink').Count) key credential(s)"
}

# 2. Check if Windows Hello for Business is deployed:
# If NOT deployed, ALL key credentials are likely malicious!
# Get-GPOReport -All -ReportType Xml | Select-String "KeyCredential"

# 3. To REMOVE a shadow credential (use Whisker or PowerShell):
# Using PowerShell (clear all key credentials):
# Set-ADUser -Identity "username" -Clear 'msDS-KeyCredentialLink'

# 4. Using Whisker to list/remove specific keys:
# Whisker.exe list /target:username
# Whisker.exe remove /target:username /deviceid:<GUID>

# 5. Monitor for future shadow credential attacks:
# Enable auditing on msDS-KeyCredentialLink attribute changes
# Event ID 5136 (Directory Service Changes) with attribute "msDS-KeyCredentialLink"

# 6. Restrict who can modify msDS-KeyCredentialLink:
# By default, users can add key credentials to their own account
# Consider restricting via ACLs for sensitive accounts

# 7. Check for tools/evidence:
# - Whisker.exe, pywhisker
# - Certify.exe, Certipy
# - Event logs for PKINIT authentication

# DETECTION QUERY (Event Log):

"@
            return $commands
        }
    }
}

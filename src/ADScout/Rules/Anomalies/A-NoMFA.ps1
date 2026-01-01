@{
    Id          = 'A-NoMFA'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Multi-Factor Authentication Not Enforced for Privileged Accounts'
    Description = 'Privileged accounts (Domain Admins, Enterprise Admins, etc.) are not protected by multi-factor authentication. Single-factor authentication for high-privilege accounts significantly increases the risk of credential-based attacks.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'MFA for Privileged Accounts'; Url = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks' }
        @{ Title = 'NIST MFA Requirements'; Url = 'https://pages.nist.gov/800-63-3/sp800-63b.html' }
        @{ Title = 'Smart Card Authentication'; Url = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-and-remote-desktop-services' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0006')  # Initial Access, Credential Access
        Techniques = @('T1078', 'T1110')    # Valid Accounts, Brute Force
    }

    CIS   = @('5.1.1.4')
    STIG  = @('V-63319')
    ANSSI = @('vuln1_mfa')
    NIST  = @('IA-2(1)', 'IA-2(2)', 'IA-2(6)')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Privileged groups to check
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )

        # Check for users who SHOULD have MFA but don't show indicators
        foreach ($user in $Data) {
            $isPrivileged = $false
            $privilegedGroupMemberships = @()

            # Check if user is in privileged groups
            if ($user.MemberOf) {
                foreach ($group in $user.MemberOf) {
                    $groupName = if ($group -match 'CN=([^,]+)') { $Matches[1] } else { $group }
                    if ($privilegedGroups -contains $groupName) {
                        $isPrivileged = $true
                        $privilegedGroupMemberships += $groupName
                    }
                }
            }

            if ($isPrivileged -and $user.Enabled) {
                # Check for MFA indicators
                $hasMFAIndicators = $false

                # Check for smart card required flag
                $smartCardRequired = $user.SmartcardLogonRequired -eq $true

                # Check if in Protected Users group (enforces Kerberos restrictions)
                $inProtectedUsers = $user.MemberOf | Where-Object { $_ -match 'Protected Users' }

                # Check for Windows Hello for Business (if attribute available)
                $hasWHfB = $user.'msDS-KeyCredentialLink' -ne $null

                if ($smartCardRequired -or $hasWHfB) {
                    $hasMFAIndicators = $true
                }

                if (-not $hasMFAIndicators) {
                    $findings += [PSCustomObject]@{
                        SamAccountName          = $user.SamAccountName
                        DisplayName             = $user.DisplayName
                        DistinguishedName       = $user.DistinguishedName
                        PrivilegedGroups        = ($privilegedGroupMemberships -join ', ')
                        SmartCardRequired       = $smartCardRequired
                        InProtectedUsers        = [bool]$inProtectedUsers
                        WindowsHelloConfigured  = [bool]$hasWHfB
                        RiskLevel               = 'Critical'
                        Impact                  = 'Privileged account vulnerable to credential theft'
                        AttackVector            = 'Phishing, password spraying, credential stuffing, pass-the-hash'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enforce multi-factor authentication for all privileged accounts using smart cards, Windows Hello for Business, or Azure MFA.'
        Impact      = 'Medium - Users must configure and use MFA methods. Plan for enrollment and fallback procedures.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enforce MFA for Privileged Accounts
# Accounts requiring MFA: $($Finding.Findings.Count)

# Affected privileged accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.SamAccountName) ($($_.PrivilegedGroups))" } | Out-String)

# === OPTION 1: Require Smart Card Logon ===
# Most secure for on-premises privileged accounts

foreach (`$user in @('$($Finding.Findings.SamAccountName -join "','")')) {
    Set-ADUser -Identity `$user -SmartcardLogonRequired `$true
    Write-Host "Smart card required for `$user"
}

# Verify the setting:
Get-ADUser -Filter { SmartcardLogonRequired -eq `$true } | Select-Object SamAccountName

# === OPTION 2: Windows Hello for Business ===
# Modern passwordless authentication

# Configure via GPO:
# Computer Configuration > Administrative Templates > Windows Components
# > Windows Hello for Business
# - "Use Windows Hello for Business" = Enabled
# - "Use certificate for on-premises authentication" = Enabled

# === OPTION 3: Azure AD MFA (Hybrid) ===
# For hybrid environments with Azure AD Connect

# 1. Enable Azure AD MFA for privileged users
# 2. Configure Conditional Access policies requiring MFA for admin roles
# 3. Use Azure AD Privileged Identity Management (PIM) for JIT access

# === OPTION 4: Protected Users Group ===
# Add privileged accounts to Protected Users group for additional restrictions

foreach (`$user in @('$($Finding.Findings.SamAccountName -join "','")')) {
    Add-ADGroupMember -Identity "Protected Users" -Members `$user
    Write-Host "Added `$user to Protected Users group"
}

# === VERIFICATION ===
# Check current MFA status:
Get-ADUser -Filter * -Properties SmartcardLogonRequired, MemberOf |
    Where-Object { `$_.SmartcardLogonRequired -eq `$true } |
    Select-Object SamAccountName, SmartcardLogonRequired

# Check Protected Users membership:
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name

"@
            return $commands
        }
    }
}

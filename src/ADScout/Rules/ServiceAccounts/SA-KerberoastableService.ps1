<#
.SYNOPSIS
    Detects service accounts vulnerable to Kerberoasting.

.DESCRIPTION
    Service accounts with SPNs and weak passwords are vulnerable to Kerberoasting.
    This rule identifies service accounts that are at high risk of credential theft
    through Kerberos ticket attacks.

.NOTES
    Rule ID    : SA-KerberoastableService
    Category   : ServiceAccounts
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'SA-KerberoastableService'
    Version     = '1.0.0'
    Category    = 'ServiceAccounts'
    Title       = 'Kerberoastable Service Accounts'
    Description = 'Identifies service accounts with SPNs that are vulnerable to Kerberoasting attacks due to weak passwords, lack of AES encryption, or excessive privileges.'
    Severity    = 'High'
    Weight      = 60
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Kerberoasting'; Url = 'https://attack.mitre.org/techniques/T1558/003/' }
        @{ Title = 'Detecting Kerberoasting'; Url = 'https://adsecurity.org/?p=3458' }
        @{ Title = 'Service Account Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558.003')  # Kerberoasting
    }

    CIS   = @('5.18')
    STIG  = @('V-63379')
    ANSSI = @('R48')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get users with SPNs (Kerberoastable accounts)
        try {
            $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
                -Properties ServicePrincipalName, PasswordLastSet, Enabled, MemberOf,
                    Description, AdminCount, 'msDS-SupportedEncryptionTypes', Created,
                    PasswordNeverExpires, PasswordNotRequired, LastLogonDate `
                -ErrorAction SilentlyContinue

            foreach ($user in $spnUsers) {
                $issues = @()
                $riskLevel = 'Medium'

                # Skip disabled accounts
                if (-not $user.Enabled) {
                    continue
                }

                # Check password age
                if ($user.PasswordLastSet) {
                    $pwdAge = ((Get-Date) - $user.PasswordLastSet).Days
                    if ($pwdAge -gt 365) {
                        $issues += "Password is $pwdAge days old"
                        $riskLevel = 'High'
                    }
                    if ($pwdAge -gt 730) {
                        $issues += 'Password over 2 years old - likely weak'
                        $riskLevel = 'Critical'
                    }
                }

                # Check password never expires
                if ($user.PasswordNeverExpires) {
                    $issues += 'Password never expires'
                }

                # Check encryption types - prefer AES only
                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                if ($null -eq $encTypes -or $encTypes -eq 0) {
                    $issues += 'No encryption types set (defaults include RC4)'
                    $riskLevel = 'High'
                } else {
                    # Bit flags: 0x1=DES, 0x2=DES, 0x4=RC4, 0x8=AES128, 0x10=AES256
                    if ($encTypes -band 0x4) {
                        $issues += 'RC4 encryption enabled (easily crackable)'
                    }
                    if ($encTypes -band 0x3) {
                        $issues += 'DES encryption enabled (weak)'
                        $riskLevel = 'Critical'
                    }
                }

                # Check for privileged group membership
                $privilegedGroups = @(
                    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
                    'Administrators', 'Account Operators', 'Server Operators',
                    'Backup Operators', 'Print Operators'
                )

                $memberGroups = $user.MemberOf | ForEach-Object {
                    (Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue).Name
                }

                $isPrivileged = $false
                foreach ($group in $memberGroups) {
                    if ($group -in $privilegedGroups) {
                        $issues += "Member of privileged group: $group"
                        $isPrivileged = $true
                        $riskLevel = 'Critical'
                    }
                }

                # Check AdminCount (protected by SDProp)
                if ($user.AdminCount -eq 1) {
                    $issues += 'AdminCount = 1 (privileged account)'
                    if ($riskLevel -ne 'Critical') { $riskLevel = 'High' }
                }

                # Check if it's a gMSA (these are safe - strong passwords)
                if ($user.ObjectClass -eq 'msDS-GroupManagedServiceAccount') {
                    continue  # Skip gMSAs - they have 256-char random passwords
                }

                # Calculate Kerberoasting risk score
                $spnCount = $user.ServicePrincipalName.Count
                if ($spnCount -gt 5) {
                    $issues += "High SPN count ($spnCount)"
                }

                if ($issues.Count -gt 0 -or $isPrivileged) {
                    # Always report accounts with SPNs for awareness
                    if ($issues.Count -eq 0) {
                        $issues += 'Has SPNs - review for necessity'
                        $riskLevel = 'Low'
                    }

                    $findings += [PSCustomObject]@{
                        AccountName       = $user.SamAccountName
                        DisplayName       = $user.DisplayName
                        Enabled           = $user.Enabled
                        Created           = $user.Created
                        PasswordLastSet   = $user.PasswordLastSet
                        PasswordAge       = if ($user.PasswordLastSet) { "$pwdAge days" } else { 'Unknown' }
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        SPNCount          = $spnCount
                        SPNs              = ($user.ServicePrincipalName | Select-Object -First 3) -join '; '
                        EncryptionTypes   = if ($encTypes) { "0x$($encTypes.ToString('X'))" } else { 'Not set' }
                        AdminCount        = $user.AdminCount
                        IsPrivileged      = $isPrivileged
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        AttackPath        = 'Request TGS -> Extract hash -> Offline crack -> Compromise service'
                        DistinguishedName = $user.DistinguishedName
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                AccountName       = 'Error'
                DisplayName       = 'Check Failed'
                Enabled           = 'N/A'
                Created           = 'N/A'
                PasswordLastSet   = 'N/A'
                PasswordAge       = 'N/A'
                PasswordNeverExpires = 'N/A'
                SPNCount          = 0
                SPNs              = 'N/A'
                EncryptionTypes   = 'N/A'
                AdminCount        = 'N/A'
                IsPrivileged      = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                AttackPath        = 'N/A'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Migrate to gMSAs, enforce strong passwords, and disable RC4/DES encryption for service accounts.'
        Impact      = 'Medium - Password changes and encryption changes require service restart and testing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Kerberoasting Mitigation
#############################################################################
#
# Kerberoasting allows any domain user to request service tickets for
# accounts with SPNs, then crack them offline. Mitigation requires:
# 1. Strong passwords (25+ chars)
# 2. AES-only encryption
# 3. Regular password rotation
# 4. Migration to gMSAs where possible
#
# At-risk accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Migrate to gMSAs (Preferred Solution)
#############################################################################

# gMSAs have 256-character random passwords that auto-rotate
# They are effectively immune to Kerberoasting

# Create gMSA for a service:
`$gmsaName = 'gMSA_ServiceName'
`$hostGroup = 'gMSA_ServiceName_Hosts'

# Create host group:
New-ADGroup -Name `$hostGroup -GroupScope DomainLocal `
    -Path 'OU=Service Accounts,DC=domain,DC=com' `
    -Description 'Hosts allowed to use gMSA_ServiceName'

# Add server(s) to group:
# Add-ADGroupMember -Identity `$hostGroup -Members 'SERVER01$','SERVER02$'

# Create gMSA:
New-ADServiceAccount -Name `$gmsaName `
    -DNSHostName "`$gmsaName.domain.com" `
    -PrincipalsAllowedToRetrieveManagedPassword `$hostGroup `
    -Path 'OU=Service Accounts,DC=domain,DC=com'

# Copy SPNs from old account:
# `$oldSpns = (Get-ADUser -Identity 'OldServiceAccount' -Properties ServicePrincipalName).ServicePrincipalName
# Set-ADServiceAccount -Identity `$gmsaName -ServicePrincipalNames @{Add=`$oldSpns}

#############################################################################
# Step 2: For Accounts That Cannot Use gMSA
#############################################################################

# Set strong password (25+ characters):
`$serviceAccount = 'svc_application'
`$newPassword = [System.Web.Security.Membership]::GeneratePassword(30,5)

# Store securely, then set:
# Set-ADAccountPassword -Identity `$serviceAccount -NewPassword (ConvertTo-SecureString `$newPassword -AsPlainText -Force)

# Enable AES encryption only (disable RC4):
Set-ADUser -Identity `$serviceAccount -Replace @{
    'msDS-SupportedEncryptionTypes' = 24  # 0x18 = AES128 + AES256 only
}

# Force password change (triggers re-encryption of Kerberos keys):
Set-ADUser -Identity `$serviceAccount -ChangePasswordAtLogon `$false
# Then reset password

#############################################################################
# Step 3: Disable RC4 for Kerberos (Domain-Wide)
#############################################################################

# WARNING: This may break legacy systems. Test thoroughly!

# Via GPO:
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options
# -> "Network security: Configure encryption types allowed for Kerberos"
# -> Enable only AES128 and AES256

# Registry (on DCs):
# Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
#     -Name 'SupportedEncryptionTypes' -Value 24 -Type DWord

#############################################################################
# Step 4: Remove Unnecessary SPNs
#############################################################################

# List all SPNs for an account:
Get-ADUser -Identity `$serviceAccount -Properties ServicePrincipalName |
    Select-Object -ExpandProperty ServicePrincipalName

# Remove unused SPNs:
# Set-ADUser -Identity `$serviceAccount -ServicePrincipalNames @{Remove='HTTP/oldserver.domain.com'}

# Find duplicate SPNs (can indicate attacks):
`$allSpns = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName

#############################################################################
# Step 5: Implement Password Rotation
#############################################################################

# Create Fine-Grained Password Policy for service accounts:
New-ADFineGrainedPasswordPolicy -Name 'ServiceAccount_Policy' `
    -Precedence 10 `
    -MinPasswordLength 25 `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled `$true `
    -ReversibleEncryptionEnabled `$false

# Apply to service accounts OU:
# Add-ADFineGrainedPasswordPolicySubject -Identity 'ServiceAccount_Policy' `
#     -Subjects 'OU=Service Accounts,DC=domain,DC=com'

#############################################################################
# Step 6: Remove Privileged Group Membership
#############################################################################

# Service accounts should NOT be in privileged groups:
`$privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Administrators')

Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties MemberOf |
    ForEach-Object {
        `$user = `$_
        `$user.MemberOf | ForEach-Object {
            `$group = Get-ADGroup -Identity `$_
            if (`$group.Name -in `$privilegedGroups) {
                Write-Host "CRITICAL: `$(`$user.SamAccountName) is in `$(`$group.Name)" -ForegroundColor Red
                # Remove-ADGroupMember -Identity `$group -Members `$user -Confirm:`$false
            }
        }
    }

#############################################################################
# Step 7: Monitor for Kerberoasting
#############################################################################

# Event ID 4769: Kerberos Service Ticket requested
# Look for:
# - Ticket encryption type 0x17 (RC4)
# - High volume of TGS requests
# - Requests from unusual sources

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4769
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match 'Ticket Encryption Type:\s+0x17'
} | Group-Object { `$_.Properties[0].Value } |
    Sort-Object Count -Descending |
    Select-Object Count, Name -First 10

#############################################################################
# Verification
#############################################################################

# Check encryption types for all SPN accounts:
Get-ADUser -Filter { ServicePrincipalName -like '*' } `
    -Properties SamAccountName, 'msDS-SupportedEncryptionTypes', PasswordLastSet |
    Select-Object SamAccountName,
        @{N='EncTypes';E={`$_.'msDS-SupportedEncryptionTypes'}},
        @{N='RC4Enabled';E={(`$_.'msDS-SupportedEncryptionTypes' -band 4) -ne 0}},
        @{N='PwdAge';E={((Get-Date) - `$_.PasswordLastSet).Days}} |
    Format-Table -AutoSize

"@
            return $commands
        }
    }
}

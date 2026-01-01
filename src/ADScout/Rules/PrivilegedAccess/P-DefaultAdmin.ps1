@{
    Id          = 'P-DefaultAdmin'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Default Administrator Account Active and Used'
    Description = 'The built-in Administrator account (RID 500) is enabled and actively used for regular operations. This account cannot be locked out and is a primary target for attackers. Best practice is to disable it or reserve it for emergency use only.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Administrator Account Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory' }
        @{ Title = 'Password Spraying'; Url = 'https://attack.mitre.org/techniques/T1110/003/' }
        @{ Title = 'CIS Benchmark - Administrator Account'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0006')  # Initial Access, Credential Access
        Techniques = @('T1078.002', 'T1110.003')  # Valid Accounts: Domain, Password Spraying
    }

    CIS   = @('1.1.1')
    STIG  = @('V-63357')
    ANSSI = @('vuln2_default_admin')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find the built-in Administrator account (RID 500)
        foreach ($user in $Data) {
            # Check if this is the RID 500 account
            $sid = $user.SID
            $isRID500 = $false

            if ($sid) {
                $sidString = if ($sid -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid.Value
                } elseif ($sid -is [byte[]]) {
                    (New-Object System.Security.Principal.SecurityIdentifier($sid, 0)).Value
                } else {
                    $sid.ToString()
                }

                # RID 500 is the built-in Administrator
                $isRID500 = $sidString -match '-500$'
            }

            if ($isRID500) {
                # Check if enabled
                $isEnabled = $user.Enabled -ne $false

                # Check for recent logon activity
                $lastLogon = $user.LastLogonDate
                $isActive = $lastLogon -gt (Get-Date).AddDays(-90)

                # Check if renamed (good practice, but still a risk if active)
                $isRenamed = $user.SamAccountName -ne 'Administrator'

                if ($isEnabled) {
                    $riskLevel = 'Medium'
                    $riskFactors = @()

                    if ($isActive) {
                        $riskLevel = 'High'
                        $riskFactors += 'Actively used in last 90 days'
                    }
                    if (-not $isRenamed) {
                        $riskFactors += 'Still named Administrator (easy target)'
                    }
                    if ($user.PasswordNeverExpires) {
                        $riskFactors += 'Password never expires'
                    }

                    $findings += [PSCustomObject]@{
                        AccountName         = $user.SamAccountName
                        SID                 = $sidString
                        Enabled             = $isEnabled
                        IsRenamed           = $isRenamed
                        LastLogon           = $lastLogon
                        IsActive            = $isActive
                        PasswordLastSet     = $user.PasswordLastSet
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        RiskLevel           = $riskLevel
                        RiskFactors         = ($riskFactors -join '; ')
                        AttackVector        = 'Cannot be locked out, primary target for brute force, credential stuffing'
                    }
                }
                break  # Found the RID 500 account
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the built-in Administrator account for regular use. Create named admin accounts for daily operations and reserve the built-in account for emergency scenarios only.'
        Impact      = 'Low - Use named accounts for administration. Keep the password for emergency break-glass scenarios.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"

# Secure the Built-in Administrator Account
# Current Status: $($Finding.Findings[0].Enabled)
# Last Logon: $($Finding.Findings[0].LastLogon)
# Risk Factors: $($Finding.Findings[0].RiskFactors)

# Step 1: Create dedicated admin accounts (if not already done)
# New-ADUser -Name "AdminFirstLast" -SamAccountName "admin.firstlast" `
#     -UserPrincipalName "admin.firstlast@domain.com" `
#     -AccountPassword (Read-Host -AsSecureString "Password") `
#     -ChangePasswordAtLogon `$true -Enabled `$true

# Add to Domain Admins (if needed)
# Add-ADGroupMember -Identity "Domain Admins" -Members "admin.firstlast"

# Step 2: Rename the built-in Administrator (obfuscation)
`$adminAccount = Get-ADUser -Filter "SID -like '*-500'" -Properties SamAccountName
if (`$adminAccount.SamAccountName -eq 'Administrator') {
    # Rename to something non-obvious
    Rename-ADObject -Identity `$adminAccount.DistinguishedName -NewName "BreakGlassAdmin"
    Set-ADUser -Identity `$adminAccount -SamAccountName "breakglassadmin"
    Write-Host "Administrator account renamed to BreakGlassAdmin"
}

# Step 3: Set a complex password and document for emergency use
`$newPassword = ConvertTo-SecureString -String (New-Guid).ToString() -AsPlainText -Force
Set-ADAccountPassword -Identity `$adminAccount -NewPassword `$newPassword -Reset
# Store this password securely (vault, sealed envelope, etc.)

# Step 4: Disable the account (optional - depends on emergency requirements)
# Disable-ADAccount -Identity `$adminAccount
# Write-Host "Built-in Administrator account disabled"

# Step 5: Enable auditing for the account
# Monitor Event ID 4624 (Logon), 4625 (Failed Logon) for this account

# Verify changes:
Get-ADUser -Filter "SID -like '*-500'" -Properties * |
    Select-Object SamAccountName, Enabled, PasswordLastSet, LastLogonDate

"@
            return $commands
        }
    }
}

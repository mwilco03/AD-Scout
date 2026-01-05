@{
    Id          = 'K-SilverTicketRisk'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Silver Ticket Risk - Service Account Password Age'
    Description = 'Detects service accounts with passwords that have not been changed for extended periods. Service account password hashes can be used to forge Silver Tickets for specific services, enabling persistent access without touching the DC. Long-unchanged passwords also indicate potential Kerberoasting targets with crackable passwords.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Silver Ticket Attack'; Url = 'https://attack.mitre.org/techniques/T1558/002/' }
        @{ Title = 'Service Account Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
        @{ Title = 'Kerberoasting and Silver Tickets'; Url = 'https://adsecurity.org/?p=2293' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0006')  # Persistence, Credential Access
        Techniques = @('T1558.002', 'T1558.003')  # Silver Ticket, Kerberoasting
    }

    CIS   = @('5.4.4')
    STIG  = @('V-220930')
    ANSSI = @('R42')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($user in $Data) {
            # Only check enabled accounts with SPNs (service accounts)
            if (-not $user.Enabled) { continue }
            if (-not $user.ServicePrincipalNames -or $user.ServicePrincipalNames.Count -eq 0) { continue }

            # Calculate password age
            $passwordAge = $null
            if ($user.PasswordLastSet) {
                $passwordAge = (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
            }

            # Skip if password was recently changed
            if ($passwordAge -and $passwordAge -lt 90) { continue }

            # Determine risk level
            $riskLevel = 'Low'
            $risks = @()

            if (-not $passwordAge) {
                $riskLevel = 'Critical'
                $risks += 'Password has never been set/changed'
            }
            elseif ($passwordAge -gt 365) {
                $riskLevel = 'Critical'
                $risks += "Password unchanged for $passwordAge days (over 1 year)"
                $risks += 'High likelihood password has been Kerberoasted and cracked'
            }
            elseif ($passwordAge -gt 180) {
                $riskLevel = 'High'
                $risks += "Password unchanged for $passwordAge days"
                $risks += 'Kerberoasting target with potentially weak password'
            }
            elseif ($passwordAge -gt 90) {
                $riskLevel = 'Medium'
                $risks += "Password unchanged for $passwordAge days"
            }

            # Check for additional risk factors
            if ($user.PasswordNeverExpires) {
                $risks += 'Password never expires flag set'
            }
            if ($user.AdminCount -eq 1) {
                $riskLevel = 'Critical'
                $risks += 'PRIVILEGED service account - Silver Ticket = admin access'
            }
            if ($user.TrustedForDelegation) {
                $risks += 'Trusted for delegation - can impersonate users'
            }

            $findings += [PSCustomObject]@{
                SamAccountName          = $user.SamAccountName
                DisplayName             = $user.DisplayName
                DistinguishedName       = $user.DistinguishedName
                ServicePrincipalNames   = ($user.ServicePrincipalNames -join '; ')
                SPNCount                = $user.ServicePrincipalNames.Count
                PasswordLastSet         = $user.PasswordLastSet
                PasswordAgeDays         = $passwordAge
                PasswordNeverExpires    = $user.PasswordNeverExpires
                AdminCount              = $user.AdminCount
                TrustedForDelegation    = $user.TrustedForDelegation
                RiskLevel               = $riskLevel
                Risks                   = ($risks -join '; ')
                SilverTicketImpact      = @(
                    'Forged tickets for specific services (SQL, HTTP, CIFS)',
                    'Access persists until service account password changed',
                    'Does not require DC contact - works offline',
                    'Harder to detect than Golden Tickets'
                ) -join '; '
                Recommendation          = if ($riskLevel -eq 'Critical') {
                    'Immediately rotate password and consider gMSA migration'
                } else {
                    'Rotate password and implement regular rotation'
                }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}, PasswordAgeDays -Descending
    }

    Remediation = @{
        Description = 'Rotate service account passwords and migrate to Group Managed Service Accounts (gMSA) where possible for automatic password rotation.'
        Impact      = 'Medium - Service restarts may be required after password change'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# SILVER TICKET RISK - SERVICE ACCOUNT PASSWORDS
# ================================================================
# Silver Tickets allow attackers to forge TGS tickets for specific
# services. Unlike Golden Tickets, they:
# - Don't require Domain Admin compromise (just service account)
# - Don't touch the DC (harder to detect)
# - Persist until the service account password is changed

# ================================================================
# HIGH-RISK SERVICE ACCOUNTS
# ================================================================

"@
            $critical = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'Critical' }
            $high = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'High' }

            foreach ($item in $critical) {
                $commands += @"

# ================================================================
# CRITICAL: $($item.SamAccountName)
# Password Age: $($item.PasswordAgeDays) days
# SPNs: $($item.ServicePrincipalNames)
# Risks: $($item.Risks)
# ================================================================

# 1. Identify services using this account:
Get-WmiObject Win32_Service | Where-Object { `$_.StartName -like "*$($item.SamAccountName)*" } | ``
    Select-Object Name, StartName, State, PathName

# 2. Rotate password:
`$newPassword = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 32 | ForEach-Object { [char]`$_ })
Set-ADAccountPassword -Identity '$($item.SamAccountName)' -Reset -NewPassword (ConvertTo-SecureString `$newPassword -AsPlainText -Force)

# 3. Update services with new password
# (Must be done on each server running the service)

"@
            }

            $commands += @"

# ================================================================
# MIGRATE TO GROUP MANAGED SERVICE ACCOUNTS (gMSA)
# ================================================================
# gMSA provides automatic password rotation (every 30 days)
# and eliminates Silver Ticket persistence risk.

# Step 1: Create KDS Root Key (if not exists - wait 10 hours in production)
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)

# Step 2: Create gMSA for each service:
# New-ADServiceAccount -Name 'gMSA_SQLService' ``
#     -DNSHostName 'sql01.domain.com' ``
#     -PrincipalsAllowedToRetrieveManagedPassword 'SQL-Servers' ``
#     -ServicePrincipalNames 'MSSQLSvc/sql01.domain.com:1433'

# Step 3: Install gMSA on target server:
# Install-ADServiceAccount -Identity 'gMSA_SQLService'

# Step 4: Configure service to use gMSA (account ends with $):
# sc.exe config "MSSQLSERVER" obj= "DOMAIN\gMSA_SQLService$" password= ""

# ================================================================
# IMPLEMENT PASSWORD ROTATION POLICY
# ================================================================

# For accounts that cannot use gMSA, implement fine-grained policy:
New-ADFineGrainedPasswordPolicy -Name "Service Account Policy" ``
    -Precedence 50 ``
    -MinPasswordLength 25 ``
    -PasswordHistoryCount 24 ``
    -MaxPasswordAge (New-TimeSpan -Days 90) ``
    -ComplexityEnabled `$true

# Apply to service account OU:
# Add-ADFineGrainedPasswordPolicySubject -Identity "Service Account Policy" -Subjects "OU=Service Accounts,DC=domain,DC=com"

# ================================================================
# DISABLE RC4 FOR KERBEROS
# ================================================================

# Force AES encryption for all service accounts:
Get-ADUser -Filter { ServicePrincipalName -like '*' } | ``
    Set-ADUser -KerberosEncryptionType 'AES128,AES256'

"@
            return $commands
        }
    }
}

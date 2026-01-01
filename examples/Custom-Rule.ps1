<#
.SYNOPSIS
    Example of creating and using custom AD-Scout rules.

.DESCRIPTION
    Demonstrates how to create, register, and use custom security rules.
#>

#Requires -Version 5.1

Import-Module ADScout -Force

Write-Host "AD-Scout Custom Rule Example" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Create a directory for custom rules
$customRulesPath = './MyCustomRules'
if (-not (Test-Path $customRulesPath)) {
    New-Item -Path $customRulesPath -ItemType Directory | Out-Null
}

# Example 1: Create a new rule using the template
Write-Host "`n1. Creating a new rule from template..." -ForegroundColor Yellow
New-ADScoutRule -Name 'OldPasswords' -Category StaleObjects -Path $customRulesPath -Description 'Detects accounts with passwords older than 365 days'

Write-Host "Rule template created at: $customRulesPath/S-OldPasswords.ps1" -ForegroundColor Green

# Example 2: Create a complete custom rule manually
Write-Host "`n2. Creating a complete custom rule..." -ForegroundColor Yellow

$customRule = @'
<#
.SYNOPSIS
    Detects accounts with very old passwords.

.DESCRIPTION
    Identifies enabled user accounts where the password has not been
    changed in over 365 days.

.NOTES
    Rule ID    : S-OldPasswords
    Category   : StaleObjects
    Author     : Custom
    Version    : 1.0.0
#>

@{
    Id          = "S-OldPasswords"
    Name        = "Passwords Older Than 365 Days"
    Category    = "StaleObjects"
    Model       = "PasswordAge"
    Version     = "1.0.0"

    Computation = "PerDiscover"
    Points      = 2
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @("T1078.002")
    CIS         = @("5.2")
    STIG        = @()
    ANSSI       = @()

    ScriptBlock = {
        param([hashtable]$ADData)

        $threshold = (Get-Date).AddDays(-365)

        $ADData.Users | Where-Object {
            $_.Enabled -eq $true -and
            $_.PasswordLastSet -and
            $_.PasswordLastSet -lt $threshold
        } | Select-Object @(
            'SamAccountName'
            'DistinguishedName'
            'PasswordLastSet'
            @{Name='DaysOld'; Expression={
                [math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays)
            }}
        )
    }

    DetailProperties = @("SamAccountName", "DaysOld")
    DetailFormat     = "{SamAccountName} ({DaysOld} days old)"

    Remediation = {
        param($Finding)
        @"
# Reset password for: $($Finding.SamAccountName)
# Password is $($Finding.DaysOld) days old

# Force password change at next logon:
Set-ADUser -Identity '$($Finding.SamAccountName)' -ChangePasswordAtLogon `$true

# Or reset to a new random password:
# `$newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 4)
# Set-ADAccountPassword -Identity '$($Finding.SamAccountName)' -NewPassword (ConvertTo-SecureString `$newPassword -AsPlainText -Force) -Reset

"@
    }

    Description = "User accounts with passwords unchanged for over 365 days increase credential compromise risk."

    TechnicalExplanation = @"
Long-lived passwords are more vulnerable to:
- Historical breach exposure
- Accumulated brute-force attempts
- Password spraying attacks
- Credential stuffing from other breaches
"@

    References = @(
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $null -ne $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}
'@

$customRule | Out-File "$customRulesPath/S-OldPasswords.ps1" -Encoding UTF8 -Force
Write-Host "Custom rule saved to: $customRulesPath/S-OldPasswords.ps1" -ForegroundColor Green

# Example 3: Register the custom rule path
Write-Host "`n3. Registering custom rule path..." -ForegroundColor Yellow
Register-ADScoutRule -Path $customRulesPath
Write-Host "Custom rule path registered" -ForegroundColor Green

# Example 4: Verify the rule is available
Write-Host "`n4. Verifying custom rule is loaded..." -ForegroundColor Yellow
$rule = Get-ADScoutRule -Id 'S-OldPasswords'
if ($rule) {
    Write-Host "Custom rule found:" -ForegroundColor Green
    $rule | Format-List Id, Name, Category, Description
}

# Example 5: Run scan including custom rules
Write-Host "`n5. Running scan with custom rules..." -ForegroundColor Yellow
Invoke-ADScoutScan -Category StaleObjects | Export-ADScoutReport -Format Console

Write-Host "`nCustom rule example complete!" -ForegroundColor Green

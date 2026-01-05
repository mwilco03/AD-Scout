@{
    Id          = 'S-InactiveUsers'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Inactive User Accounts'
    Description = 'Identifies user accounts that have not logged in for over 90 days. Inactive accounts increase attack surface and may indicate terminated employees.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Identity and Access Management Best Practices'; Url = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion (stale accounts evade review)
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.19')
    STIG  = @('V-36450')
    ANSSI = @('vuln2_stale_users')
    NIST  = @('AC-2(3)', 'IA-4(4)')

    Scoring = @{
        Type       = 'TriggerOnThreshold'
        Threshold  = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $thresholdDays = 90
        $thresholdDate = (Get-Date).AddDays(-$thresholdDays)

        foreach ($user in $Data) {
            # Skip service accounts (handled by different rule)
            if ($user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0) { continue }

            $lastLogon = $user.LastLogonDate

            # Check if inactive
            $isInactive = $false
            if ($null -eq $lastLogon) {
                $isInactive = $true
                $inactiveDays = 'Never logged on'
            }
            elseif ($lastLogon -lt $thresholdDate) {
                $isInactive = $true
                $inactiveDays = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
            }

            if ($isInactive -and $user.Enabled) {
                $findings += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    LastLogon         = $lastLogon
                    InactiveDays      = $inactiveDays
                    PasswordLastSet   = $user.PasswordLastSet
                    WhenCreated       = $user.WhenCreated
                    Department        = $user.Department
                    Manager           = $user.Manager
                    Enabled           = $user.Enabled
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Verify inactive accounts with HR/managers and disable those confirmed as no longer needed. Implement automated account lifecycle management.'
        Impact      = 'High - Verify with HR before disabling to avoid locking out legitimate users'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Inactive user accounts detected (no logon in 90+ days)
# IMPORTANT: Verify with HR/managers before disabling

# Export list for review:

`$inactiveUsers = @(
"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

    [PSCustomObject]@{
        SamAccountName = '$($item.SamAccountName)'
        DisplayName    = '$($item.DisplayName)'
        LastLogon      = '$($item.LastLogon)'
        Department     = '$($item.Department)'
    }
"@
            }

            $commands += @"

)

`$inactiveUsers | Export-Csv -Path 'InactiveUsers.csv' -NoTypeInformation

# After HR approval, disable accounts:

# foreach (`$user in `$inactiveUsers) {
#     Disable-ADAccount -Identity `$user.SamAccountName
#     Move-ADObject -Identity (Get-ADUser `$user.SamAccountName).DistinguishedName -TargetPath 'OU=Disabled Users,...'
# }
"@
            return $commands
        }
    }
}

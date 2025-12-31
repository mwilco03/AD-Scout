@{
    Id          = 'S-InactiveComputers'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Inactive Computer Accounts'
    Description = 'Identifies computer accounts that have not authenticated in over 90 days. Inactive computer accounts can be used for persistence and indicate poor lifecycle management.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Finding Stale Computer Accounts'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/auto-disable-computer-accounts' }
        @{ Title = 'Computer Account Hygiene'; Url = 'https://adsecurity.org/?p=1684' }
    )

    MITRE = @{
        Tactics    = @('TA0003')  # Persistence
        Techniques = @('T1078.002')  # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.18')
    STIG  = @('V-36449')
    ANSSI = @('vuln2_stale_computers')

    Scoring = @{
        Type       = 'TriggerOnThreshold'
        Threshold  = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $thresholdDays = 90
        $thresholdDate = (Get-Date).AddDays(-$thresholdDays)

        foreach ($computer in $Data) {
            # Skip domain controllers
            if ($computer.IsDomainController) { continue }

            $lastLogon = $computer.LastLogonDate
            $passwordLastSet = $computer.PasswordLastSet

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

            if ($isInactive -and $computer.Enabled) {
                $findings += [PSCustomObject]@{
                    Name              = $computer.Name
                    DNSHostName       = $computer.DNSHostName
                    OperatingSystem   = $computer.OperatingSystem
                    LastLogon         = $lastLogon
                    InactiveDays      = $inactiveDays
                    PasswordLastSet   = $passwordLastSet
                    Enabled           = $computer.Enabled
                    DistinguishedName = $computer.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable or delete inactive computer accounts after confirming they are no longer in use. Implement automated lifecycle management.'
        Impact      = 'Medium - Verify computers are truly inactive before removal'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Inactive computer accounts detected (no logon in 90+ days)
# Verify each computer is no longer in use before disabling/deleting

# Step 1: Disable inactive computers (safer than immediate deletion)

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Computer: $($item.Name)
# Last Logon: $($item.LastLogon)
# Inactive Days: $($item.InactiveDays)

# Disable the account:
Disable-ADAccount -Identity '$($item.DistinguishedName)'

# Move to 'Disabled Computers' OU (create if needed):

# `$disabledOU = 'OU=Disabled Computers,$((Get-ADDomain).DistinguishedName)'
# Move-ADObject -Identity '$($item.DistinguishedName)' -TargetPath `$disabledOU

"@
            }

            $commands += @"


# Bulk disable all computers inactive for 90+ days:

# `$threshold = (Get-Date).AddDays(-90)

# Get-ADComputer -Filter 'LastLogonDate -lt `$threshold -and Enabled -eq `$true' -Properties LastLogonDate |
#     ForEach-Object { Disable-ADAccount -Identity `$_ }

# Delete after 30 additional days of being disabled:

# Get-ADComputer -Filter 'Enabled -eq `$false' -SearchBase 'OU=Disabled Computers,...' |
#     Where-Object { `$_.Modified -lt (Get-Date).AddDays(-30) } |
#     Remove-ADComputer -Confirm:`$false
"@
            return $commands
        }
    }
}

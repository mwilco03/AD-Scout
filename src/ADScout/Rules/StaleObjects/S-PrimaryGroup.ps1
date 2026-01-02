@{
    Id          = 'S-PrimaryGroup'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Non-Standard Primary Group'
    Description = 'Detects user accounts with a non-standard Primary Group ID. By default, users have Domain Users (RID 513) as their primary group. A different value may indicate a migration artifact, misconfiguration, or attempt to hide group membership.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Primary Group ID'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts' }
        @{ Title = 'SID History Attacks'; Url = 'https://attack.mitre.org/techniques/T1134/005/' }
        @{ Title = 'PingCastle Rule S-PrimaryGroup'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0005', 'TA0003')  # Defense Evasion, Persistence
        Techniques = @('T1134.005', 'T1078.002')  # SID-History Injection, Domain Accounts
    }

    CIS   = @()  # Primary group ID not covered in CIS benchmarks
    STIG  = @()  # Account attribute STIGs are AD-version specific
    ANSSI = @()
    NIST  = @('AC-2', 'CM-6')  # Account Management, Configuration Settings

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 2
        MaxPoints = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Standard Primary Group RIDs
        $standardUserPGID = 513    # Domain Users
        $standardComputerPGID = 515  # Domain Computers
        $dcPGID = 516              # Domain Controllers
        $rodcPGID = 521            # Read-only Domain Controllers

        # Privileged group RIDs that would be concerning
        $privilegedRIDs = @{
            512 = 'Domain Admins'
            518 = 'Schema Admins'
            519 = 'Enterprise Admins'
            544 = 'Administrators'
        }

        try {
            foreach ($user in $Data.Users) {
                $primaryGroupID = [int]$user.PrimaryGroupID

                # Skip if standard
                if ($primaryGroupID -eq $standardUserPGID) { continue }

                # Skip computer accounts (they have different standard)
                if ($user.ObjectClass -contains 'computer') { continue }

                # Skip service accounts and managed accounts
                if ($user.ObjectClass -contains 'msDS-GroupManagedServiceAccount') { continue }
                if ($user.ObjectClass -contains 'msDS-ManagedServiceAccount') { continue }

                # Determine severity based on the primary group
                $severity = 'Low'
                $groupName = "RID $primaryGroupID"
                $risk = 'Non-standard primary group'

                if ($privilegedRIDs.ContainsKey($primaryGroupID)) {
                    $severity = 'High'
                    $groupName = $privilegedRIDs[$primaryGroupID]
                    $risk = 'Primary group set to privileged group - may hide membership'
                } elseif ($primaryGroupID -eq $dcPGID -or $primaryGroupID -eq $rodcPGID) {
                    $severity = 'Critical'
                    $groupName = if ($primaryGroupID -eq 516) { 'Domain Controllers' } else { 'Read-only Domain Controllers' }
                    $risk = 'User has DC/RODC primary group - potential backdoor'
                }

                $findings += [PSCustomObject]@{
                    AccountName         = $user.SamAccountName
                    DistinguishedName   = $user.DistinguishedName
                    PrimaryGroupID      = $primaryGroupID
                    PrimaryGroupName    = $groupName
                    ExpectedPGID        = $standardUserPGID
                    Enabled             = $user.Enabled
                    Severity            = $severity
                    Risk                = $risk
                    Impact              = 'Primary group membership not shown in normal group queries'
                }
            }

            # Also check for computers with non-standard primary group
            foreach ($computer in $Data.Computers) {
                $primaryGroupID = [int]$computer.PrimaryGroupID

                # Standard for computers is 515 (Domain Computers)
                # DCs have 516, RODCs have 521

                $isDC = $computer.DistinguishedName -match 'OU=Domain Controllers'

                if ($isDC) {
                    if ($primaryGroupID -ne $dcPGID -and $primaryGroupID -ne $rodcPGID) {
                        $findings += [PSCustomObject]@{
                            AccountName         = $computer.SamAccountName
                            DistinguishedName   = $computer.DistinguishedName
                            PrimaryGroupID      = $primaryGroupID
                            ObjectType          = 'DomainController'
                            ExpectedPGID        = $dcPGID
                            Severity            = 'High'
                            Risk                = 'DC has non-standard primary group'
                        }
                    }
                } else {
                    if ($primaryGroupID -ne $standardComputerPGID) {
                        # Check for computers with DC primary group (very suspicious)
                        if ($primaryGroupID -eq $dcPGID) {
                            $findings += [PSCustomObject]@{
                                AccountName         = $computer.SamAccountName
                                DistinguishedName   = $computer.DistinguishedName
                                PrimaryGroupID      = $primaryGroupID
                                ObjectType          = 'Computer'
                                ExpectedPGID        = $standardComputerPGID
                                Severity            = 'Critical'
                                Risk                = 'Non-DC computer has Domain Controllers primary group'
                            }
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "S-PrimaryGroup: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reset the Primary Group ID to the default value (513 for users, 515 for computers). Investigate why the value was changed.'
        Impact      = 'Low - Resetting to default is safe. Verify the account is still member of required groups.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Non-Standard Primary Group Remediation
#
# Accounts with non-standard Primary Group:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): PrimaryGroupID = $($_.PrimaryGroupID) ($($_.PrimaryGroupName))" } | Out-String)

# The Primary Group ID determines an account's primary group membership.
# This membership doesn't show in normal group queries, which can be
# used to hide privileged access.

# STEP 1: Investigate why the primary group was changed
# Check account history, migration logs, or admin actions

# STEP 2: Reset user accounts to Domain Users (RID 513)
$($Finding.Findings | Where-Object { $_.ObjectType -ne 'Computer' -and $_.ObjectType -ne 'DomainController' } | ForEach-Object { @"
# Reset $($_.AccountName) to Domain Users (513)
# First ensure the user is a member of Domain Users
Add-ADGroupMember -Identity "Domain Users" -Members "$($_.AccountName)" -ErrorAction SilentlyContinue
# Then set the primary group
Set-ADUser -Identity "$($_.AccountName)" -Replace @{primaryGroupID = 513}
Write-Host "Reset primary group for $($_.AccountName)"

"@ })

# STEP 3: Reset computer accounts to Domain Computers (RID 515)
$($Finding.Findings | Where-Object { $_.ObjectType -eq 'Computer' } | ForEach-Object { @"
# Reset $($_.AccountName) to Domain Computers (515)
Add-ADGroupMember -Identity "Domain Computers" -Members "$($_.AccountName)" -ErrorAction SilentlyContinue
Set-ADComputer -Identity "$($_.AccountName.TrimEnd('$'))" -Replace @{primaryGroupID = 515}

"@ })

# STEP 4: Verify the changes
Get-ADUser -Filter * -Properties PrimaryGroupID |
    Where-Object { `$_.PrimaryGroupID -ne 513 } |
    Select-Object SamAccountName, PrimaryGroupID

Get-ADComputer -Filter * -Properties PrimaryGroupID |
    Where-Object { `$_.PrimaryGroupID -notin @(515, 516, 521) } |
    Select-Object SamAccountName, PrimaryGroupID

# STEP 5: Monitor for future changes
# Create an alert for Event ID 4738 (user account changed)
# Filter for changes to primaryGroupId attribute

# STEP 6: PowerShell to set via ADSI if AD module not available
# `$user = [ADSI]"LDAP://CN=UserName,OU=Users,DC=domain,DC=com"
# `$user.Put("primaryGroupID", 513)
# `$user.SetInfo()

"@
            return $commands
        }
    }
}

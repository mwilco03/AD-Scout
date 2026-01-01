@{
    Id          = 'P-RODCKrbtgtOrphaned'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Orphaned RODC Krbtgt Accounts'
    Description = 'Detects orphaned RODC krbtgt accounts (krbtgt_XXXXX) that remain after RODC decommissioning. These accounts can be used to forge tickets that appear valid to the orphaned RODC number.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'RODC Krbtgt Accounts'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/rodc-guidance-for-administering-the-read-only-domain-controller' }
        @{ Title = 'RODC Security'; Url = 'https://adsecurity.org/?p=3592' }
        @{ Title = 'PingCastle Rule P-RODCKrbtgt'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1558.001', 'T1078.002')  # Golden Ticket, Valid Accounts
    }

    CIS   = @('5.5')
    STIG  = @('V-63363')
    ANSSI = @('vuln1_rodc_krbtgt')
    NIST  = @('AC-2', 'IA-4')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 10
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get all RODC krbtgt accounts
            $rodcKrbtgtAccounts = @()

            # From collected user data
            foreach ($user in $Data.Users) {
                if ($user.SamAccountName -match '^krbtgt_[0-9]+$') {
                    $rodcKrbtgtAccounts += $user
                }
            }

            # If not found in data, query directly
            if ($rodcKrbtgtAccounts.Count -eq 0) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                    $searcher.Filter = "(sAMAccountName=krbtgt_*)"
                    $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'distinguishedName', 'whenCreated', 'pwdLastSet', 'msDS-KrbTgtLinkBl'))

                    $results = $searcher.FindAll()
                    foreach ($result in $results) {
                        $rodcKrbtgtAccounts += @{
                            SamAccountName = $result.Properties['samaccountname'][0]
                            DistinguishedName = $result.Properties['distinguishedname'][0]
                            WhenCreated = $result.Properties['whencreated'][0]
                            PasswordLastSet = $result.Properties['pwdlastset'][0]
                            RODCLink = $result.Properties['msds-krbtgtlinkbl']
                        }
                    }
                } catch {
                    Write-Verbose "P-RODCKrbtgtOrphaned: Error querying krbtgt accounts - $_"
                }
            }

            # Get list of active RODCs
            $activeRODCs = @()
            if ($Data.DomainControllers) {
                $activeRODCs = $Data.DomainControllers | Where-Object { $_.IsReadOnly -eq $true }
            } else {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://OU=Domain Controllers,$domainDN"
                    $searcher.Filter = "(&(objectClass=computer)(primaryGroupID=521))"  # RODC group
                    $searcher.PropertiesToLoad.AddRange(@('cn', 'distinguishedName'))

                    $results = $searcher.FindAll()
                    foreach ($result in $results) {
                        $activeRODCs += @{
                            Name = $result.Properties['cn'][0]
                            DistinguishedName = $result.Properties['distinguishedname'][0]
                        }
                    }
                } catch {
                    Write-Verbose "P-RODCKrbtgtOrphaned: Error querying RODCs - $_"
                }
            }

            # Check for orphaned krbtgt accounts
            foreach ($krbtgt in $rodcKrbtgtAccounts) {
                $accountName = if ($krbtgt.SamAccountName) { $krbtgt.SamAccountName } else { $krbtgt['SamAccountName'] }
                $accountDN = if ($krbtgt.DistinguishedName) { $krbtgt.DistinguishedName } else { $krbtgt['DistinguishedName'] }

                # Extract the RODC number from krbtgt_XXXXX
                $rodcNumber = $accountName -replace 'krbtgt_', ''

                # Check if there's a linked RODC
                $rodcLink = $null
                if ($krbtgt.RODCLink) {
                    $rodcLink = $krbtgt.RODCLink
                } elseif ($krbtgt['RODCLink']) {
                    $rodcLink = $krbtgt['RODCLink']
                }

                $isOrphaned = $false
                $reason = ''

                if (-not $rodcLink -or $rodcLink.Count -eq 0) {
                    # No back-link to RODC - definitely orphaned
                    $isOrphaned = $true
                    $reason = 'No RODC back-link (msDS-KrbTgtLinkBl is empty)'
                } else {
                    # Check if the linked RODC still exists
                    $linkedRODC = $rodcLink | ForEach-Object {
                        $linkDN = $_
                        $activeRODCs | Where-Object {
                            $_.DistinguishedName -eq $linkDN -or
                            $_.Name -eq (($linkDN -split ',')[0] -replace 'CN=', '')
                        }
                    }

                    if (-not $linkedRODC) {
                        $isOrphaned = $true
                        $reason = 'Linked RODC no longer exists'
                    }
                }

                if ($isOrphaned) {
                    $pwdLastSet = $null
                    if ($krbtgt.PasswordLastSet) {
                        $pwdLastSet = [DateTime]::FromFileTime($krbtgt.PasswordLastSet)
                    } elseif ($krbtgt['PasswordLastSet']) {
                        $pwdLastSet = [DateTime]::FromFileTime([long]$krbtgt['PasswordLastSet'])
                    }

                    $findings += [PSCustomObject]@{
                        AccountName         = $accountName
                        RODCNumber          = $rodcNumber
                        DistinguishedName   = $accountDN
                        PasswordLastSet     = $pwdLastSet
                        PasswordAge         = if ($pwdLastSet) { ((Get-Date) - $pwdLastSet).Days } else { 'Unknown' }
                        OrphanReason        = $reason
                        Severity            = 'High'
                        Risk                = 'Orphaned RODC krbtgt can be used for ticket forgery'
                        Impact              = 'Attacker with password hash can forge tickets for RODC number'
                        Recommendation      = 'Delete the orphaned krbtgt account'
                    }
                }
            }

        } catch {
            Write-Verbose "P-RODCKrbtgtOrphaned: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Delete orphaned RODC krbtgt accounts. These accounts should be removed after RODC decommissioning.'
        Impact      = 'Low - Orphaned accounts serve no legitimate purpose. Deletion is safe.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Orphaned RODC Krbtgt Account Remediation
#
# Orphaned accounts found:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.OrphanReason) (Password age: $($_.PasswordAge) days)" } | Out-String)

# BACKGROUND:
# When an RODC is promoted, a unique krbtgt_XXXXX account is created
# for that RODC. When the RODC is decommissioned, the account should
# be deleted. Orphaned accounts can be used to forge Kerberos tickets.

# STEP 1: Verify the accounts are truly orphaned
# Check if any RODC still references these accounts

Get-ADDomainController -Filter {IsReadOnly -eq `$true} | ForEach-Object {
    `$rodc = `$_
    Write-Host "RODC: `$(`$rodc.Name)"
    Get-ADObject `$rodc.ComputerObjectDN -Properties msDS-KrbTgtLink |
        Select-Object @{N='KrbTgtLink';E={`$_.'msDS-KrbTgtLink'}}
}

# STEP 2: Delete orphaned krbtgt accounts
# WARNING: Verify each account is truly orphaned before deletion

$($Finding.Findings | ForEach-Object { @"
# Delete $($_.AccountName)
Remove-ADUser -Identity "$($_.AccountName)" -Confirm:`$false
Write-Host "Deleted orphaned account: $($_.AccountName)"

"@ })

# STEP 3: Alternative - Disable before deletion (safer)
$($Finding.Findings | ForEach-Object { @"
# Disable first, then delete after verification
Disable-ADAccount -Identity "$($_.AccountName)"
# Schedule deletion after verification period:
# Remove-ADUser -Identity "$($_.AccountName)"

"@ })

# STEP 4: Verify deletion
Write-Host "`nRemaining RODC krbtgt accounts:"
Get-ADUser -Filter "SamAccountName -like 'krbtgt_*'" |
    Select-Object SamAccountName, Enabled, DistinguishedName

# STEP 5: Clean up after RODC decommissioning (preventive)
# When decommissioning an RODC, use:
# 1. Demote the RODC properly using dcpromo or Server Manager
# 2. If forced removal, clean metadata:
#    ntdsutil > metadata cleanup > remove selected server
# 3. Delete the krbtgt_XXXXX account manually if not auto-deleted

# STEP 6: Audit existing RODCs
Get-ADDomainController -Filter {IsReadOnly -eq `$true} | ForEach-Object {
    `$rodc = `$_
    `$krbtgt = Get-ADUser -Filter "SamAccountName -like 'krbtgt_*'" -Properties msDS-KrbTgtLinkBl |
        Where-Object { `$_.'msDS-KrbTgtLinkBl' -contains `$rodc.ComputerObjectDN }

    Write-Host "`$(`$rodc.Name): krbtgt account = `$(`$krbtgt.SamAccountName)"
}

"@
            return $commands
        }
    }
}

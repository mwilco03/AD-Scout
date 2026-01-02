@{
    Id          = 'P-UnconstrainedDelegation'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Unconstrained Delegation Enabled'
    Description = 'Detects computers (other than DCs) and users with unconstrained Kerberos delegation enabled. These systems can impersonate any user to any service, making them high-value targets for attackers.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Kerberos Delegation Overview'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview' }
        @{ Title = 'MITRE ATT&CK - Steal or Forge Kerberos Tickets'; Url = 'https://attack.mitre.org/techniques/T1558/' }
        @{ Title = 'Printer Bug + Unconstrained Delegation'; Url = 'https://adsecurity.org/?p=4056' }
        @{ Title = 'Microsoft Defender - Unsecure Kerberos Delegation'; Url = 'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1558', 'T1550.003')  # Steal or Forge Kerberos Tickets, Pass the Ticket
    }

    CIS   = @()  # No direct CIS mapping for delegation
    STIG  = @('V-92285')  # AD Domain STIG - Unconstrained delegation
    ANSSI = @()  # No direct ANSSI mapping
    NIST  = @('AC-6', 'CM-7')  # Least Privilege, Least Functionality

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 10
        MaxPoints = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # TRUSTED_FOR_DELEGATION = 0x80000 = 524288
        $TRUSTED_FOR_DELEGATION = 524288
        $ACCOUNTDISABLE = 2

        try {
            # Check computers
            foreach ($computer in $Data.Computers) {
                $uac = 0
                if ($computer.userAccountControl) {
                    $uac = [int]$computer.userAccountControl
                } elseif ($computer.UserAccountControl) {
                    $uac = [int]$computer.UserAccountControl
                }

                if ($uac -band $TRUSTED_FOR_DELEGATION) {
                    $isEnabled = -not ($uac -band $ACCOUNTDISABLE)
                    $computerName = $computer.Name ?? $computer.name
                    $dn = $computer.DistinguishedName ?? $computer.distinguishedName ?? ''

                    # Skip Domain Controllers (they have unconstrained delegation by default)
                    $isDC = $computer.PrimaryGroupID -eq 516 -or
                            $dn -match 'OU=Domain Controllers'

                    if ($isDC) { continue }

                    $os = $computer.OperatingSystem ?? $computer.operatingSystem ?? 'Unknown'

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'Computer'
                        Name                = $computerName
                        SamAccountName      = $computer.SamAccountName ?? $computer.sAMAccountName
                        DistinguishedName   = $dn
                        OperatingSystem     = $os
                        Enabled             = $isEnabled
                        Severity            = if ($isEnabled) { 'High' } else { 'Medium' }
                        Risk                = 'Unconstrained delegation on non-DC computer'
                        Impact              = 'Can capture TGTs from any authenticating user'
                        AttackScenario      = 'PrinterBug + unconstrained delegation = DC compromise'
                    }
                }
            }

            # Check users (rare but possible)
            foreach ($user in $Data.Users) {
                $uac = 0
                if ($user.userAccountControl) {
                    $uac = [int]$user.userAccountControl
                } elseif ($user.UserAccountControl) {
                    $uac = [int]$user.UserAccountControl
                }

                if ($uac -band $TRUSTED_FOR_DELEGATION) {
                    $isEnabled = -not ($uac -band $ACCOUNTDISABLE)

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'User'
                        Name                = $user.Name ?? $user.name
                        SamAccountName      = $user.SamAccountName ?? $user.sAMAccountName
                        DistinguishedName   = $user.DistinguishedName ?? $user.distinguishedName
                        Enabled             = $isEnabled
                        Severity            = if ($isEnabled) { 'Critical' } else { 'High' }
                        Risk                = 'Unconstrained delegation on user account'
                        Impact              = 'User can impersonate any user to any service'
                        AttackScenario      = 'Compromise this account for domain takeover'
                    }
                }
            }

            # If no data, try LDAP search
            if (($Data.Computers.Count -eq 0) -or ($null -eq $Data.Computers)) {
                try {
                    $rootDSE = [ADSI]"LDAP://RootDSE"
                    $defaultNC = $rootDSE.defaultNamingContext.ToString()

                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://$defaultNC"
                    $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
                    $searcher.PropertiesToLoad.AddRange(@('name', 'sAMAccountName', 'distinguishedName', 'operatingSystem', 'userAccountControl'))
                    $searcher.PageSize = 1000

                    $results = $searcher.FindAll()
                    foreach ($result in $results) {
                        $dn = $result.Properties['distinguishedname'][0]

                        # Skip DCs
                        if ($dn -match 'OU=Domain Controllers') { continue }

                        $findings += [PSCustomObject]@{
                            ObjectType          = 'Computer'
                            Name                = $result.Properties['name'][0]
                            SamAccountName      = $result.Properties['samaccountname'][0]
                            DistinguishedName   = $dn
                            OperatingSystem     = $result.Properties['operatingsystem'][0]
                            Severity            = 'High'
                            Risk                = 'Unconstrained delegation on non-DC computer'
                            Source              = 'LDAP Query'
                        }
                    }
                } catch {
                    Write-Verbose "P-UnconstrainedDelegation: LDAP search error - $_"
                }
            }

        } catch {
            Write-Verbose "P-UnconstrainedDelegation: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable unconstrained delegation on all non-DC computers. Migrate to constrained delegation or resource-based constrained delegation.'
        Impact      = 'High - May break applications using delegation. Test thoroughly and implement constrained delegation alternatives.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Unconstrained Delegation Remediation
#
# Objects with unconstrained delegation:
$($Finding.Findings | ForEach-Object { "# - $($_.ObjectType): $($_.Name) [$($_.OperatingSystem)]" } | Out-String)

# Unconstrained delegation allows:
# - Capturing TGT from any authenticating user
# - Using PrinterBug/PetitPotam to force DC authentication
# - Impersonating captured users to any service

# STEP 1: List all objects with unconstrained delegation
Write-Host "Objects with unconstrained delegation:" -ForegroundColor Yellow

# Computers (excluding DCs)
Get-ADComputer -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation, OperatingSystem |
    Where-Object { `$_.DistinguishedName -notmatch 'Domain Controllers' } |
    Select-Object Name, OperatingSystem, DistinguishedName | Format-Table -AutoSize

# Users
Get-ADUser -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation |
    Select-Object Name, SamAccountName, Enabled | Format-Table -AutoSize

# STEP 2: Identify what services need delegation
# Before removing, understand what breaks:
# - Web servers with Kerberos authentication
# - SQL Server with linked servers
# - File servers with DFS

# Check SPNs on affected computers:
$($Finding.Findings | Where-Object { $_.ObjectType -eq 'Computer' } | ForEach-Object { @"
Write-Host "`nSPNs on $($_.Name):"
Get-ADComputer "$($_.Name.TrimEnd('$'))" -Properties servicePrincipalName | Select-Object -ExpandProperty servicePrincipalName

"@ })

# STEP 3: Remove unconstrained delegation
$($Finding.Findings | ForEach-Object { @"
# Remove unconstrained delegation from $($_.Name)
Set-AD$($_.ObjectType) -Identity "$($_.SamAccountName)" -TrustedForDelegation `$false
Write-Host "Removed unconstrained delegation from: $($_.Name)" -ForegroundColor Green

"@ })

# STEP 4: Implement constrained delegation instead
# Example: Allow IIS server to delegate to SQL only
# Set-ADComputer -Identity "WebServer" -TrustedForDelegation `$false
# Set-ADComputer -Identity "WebServer" -Add @{
#     'msDS-AllowedToDelegateTo' = @('MSSQLSvc/sqlserver.domain.com:1433')
# }

# STEP 5: Better: Use Resource-Based Constrained Delegation (RBCD)
# RBCD is configured on the TARGET, not the source
# Example: Allow WebServer to delegate to SQLServer
#
# `$webServer = Get-ADComputer "WebServer"
# Set-ADComputer "SQLServer" -PrincipalsAllowedToDelegateToAccount `$webServer

# STEP 6: Protect against PrinterBug/PetitPotam
# Even without unconstrained delegation, protect DCs:
# - Disable Print Spooler on DCs: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled
# - Block SMB from DCs to untrusted hosts
# - Enable Extended Protection for Authentication

Write-Host @"

MIGRATION TO CONSTRAINED DELEGATION:

1. Identify delegation requirements:
   - What service does the source need to access?
   - On which servers?

2. Configure Constrained Delegation:
   Set-ADComputer -Identity "SourceServer" `
       -TrustedForDelegation `$false `
       -Add @{'msDS-AllowedToDelegateTo' = @('HTTP/target.domain.com')}

3. Or use Resource-Based Constrained Delegation:
   Set-ADComputer -Identity "TargetServer" `
       -PrincipalsAllowedToDelegateToAccount (Get-ADComputer "SourceServer")

4. Test application functionality

5. Monitor for Kerberos delegation errors in event logs

"@ -ForegroundColor Cyan

# STEP 7: Verify changes
Write-Host "`nRemaining unconstrained delegation:" -ForegroundColor Yellow
Get-ADComputer -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation |
    Where-Object { `$_.DistinguishedName -notmatch 'Domain Controllers' } |
    Select-Object Name

"@
            return $commands
        }
    }
}

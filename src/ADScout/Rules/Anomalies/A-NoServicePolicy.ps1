@{
    Id          = 'A-NoServicePolicy'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'No Service Account Security Policy'
    Description = 'Detects when there is no Managed Service Account (MSA) or Group Managed Service Account (gMSA) policy in place. Organizations should use gMSAs instead of regular accounts for services to enable automatic password rotation.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'Group Managed Service Accounts'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
        @{ Title = 'Service Account Security'; Url = 'https://attack.mitre.org/techniques/T1078/002/' }
        @{ Title = 'PingCastle Rule A-NoServicePolicy'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1078.002', 'T1558.003')  # Domain Accounts, Kerberoasting
    }

    CIS   = @('5.2')
    STIG  = @('V-63405')
    ANSSI = @('vuln2_service_accounts')
    NIST  = @('IA-5', 'AC-2')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Count gMSAs in the domain
            $gmsaCount = 0
            $msaCount = 0
            $regularServiceAccounts = @()

            foreach ($user in $Data.Users) {
                # Check for gMSA (objectClass contains msDS-GroupManagedServiceAccount)
                if ($user.ObjectClass -contains 'msDS-GroupManagedServiceAccount') {
                    $gmsaCount++
                }
                # Check for standalone MSA
                elseif ($user.ObjectClass -contains 'msDS-ManagedServiceAccount') {
                    $msaCount++
                }
                # Check for regular service accounts (by naming convention or SPN)
                elseif ($user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0) {
                    # Has SPN but is not a managed account
                    if ($user.ObjectClass -notcontains 'computer') {
                        $regularServiceAccounts += $user
                    }
                }
            }

            # If no gMSAs, query directly
            if ($gmsaCount -eq 0) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                    $searcher.Filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                    $gmsaCount = $searcher.FindAll().Count
                } catch { }
            }

            # Check if KDS root key exists (required for gMSA)
            $kdsKeyExists = $false
            try {
                $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
                $kdsContainer = [ADSI]"LDAP://CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configNC"
                if ($kdsContainer.Children) {
                    $kdsKeyExists = ($kdsContainer.Children | Measure-Object).Count -gt 0
                }
            } catch { }

            # Report findings
            if (-not $kdsKeyExists) {
                $findings += [PSCustomObject]@{
                    Issue               = 'No KDS Root Key'
                    Status              = 'gMSA infrastructure not configured'
                    GMSACount           = $gmsaCount
                    MSACount            = $msaCount
                    Severity            = 'High'
                    Risk                = 'Cannot create Group Managed Service Accounts'
                    Impact              = 'Services must use regular accounts with static passwords'
                    Recommendation      = 'Create KDS Root Key: Add-KdsRootKey -EffectiveImmediately'
                }
            }

            if ($gmsaCount -eq 0 -and $kdsKeyExists) {
                $findings += [PSCustomObject]@{
                    Issue               = 'No gMSAs in use'
                    Status              = 'gMSA infrastructure exists but not utilized'
                    GMSACount           = 0
                    MSACount            = $msaCount
                    RegularSvcAccounts  = $regularServiceAccounts.Count
                    Severity            = 'Medium'
                    Risk                = 'Service accounts using static passwords'
                    Impact              = 'Kerberoasting and credential theft risks'
                    Recommendation      = 'Migrate service accounts to gMSA'
                }
            }

            if ($regularServiceAccounts.Count -gt 0) {
                $sampleAccounts = $regularServiceAccounts | Select-Object -First 5 | ForEach-Object { $_.SamAccountName }

                $findings += [PSCustomObject]@{
                    Issue               = 'Regular accounts with SPNs'
                    Status              = 'Service accounts not using gMSA'
                    Count               = $regularServiceAccounts.Count
                    SampleAccounts      = $sampleAccounts -join ', '
                    GMSACount           = $gmsaCount
                    Severity            = 'Medium'
                    Risk                = 'Kerberoastable service accounts'
                    Impact              = 'Password hashes can be requested and cracked offline'
                    Recommendation      = 'Convert to gMSA or implement strong passwords with rotation'
                }
            }

        } catch {
            Write-Verbose "A-NoServicePolicy: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Implement Group Managed Service Accounts (gMSA) for all service accounts. Create the KDS root key and migrate services from regular accounts.'
        Impact      = 'Medium - Service migrations require testing. gMSAs provide automatic password rotation.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Service Account Policy Remediation
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.Issue): $($_.Status)" } | Out-String)

# STEP 1: Create KDS Root Key (if not exists)
# For production, use -EffectiveTime to set a future date
# For testing, use -EffectiveImmediately

# Check if KDS root key exists
`$kdsKeys = Get-KdsRootKey
if (-not `$kdsKeys) {
    # Production (wait 10 hours for replication):
    # Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(10))

    # Lab/Testing (immediate, not for production):
    Add-KdsRootKey -EffectiveImmediately
    Write-Host "Created KDS Root Key"
} else {
    Write-Host "KDS Root Key already exists: `$(`$kdsKeys.KeyId)"
}

# STEP 2: Create a gMSA for a service
# Example: Create gMSA for SQL Server

`$gmsaName = "gMSA_SQLServer"
`$dnsHostName = "`$gmsaName.`$((Get-ADDomain).DNSRoot)"
`$serviceHosts = @("SQLServer1`$", "SQLServer2`$")  # Computers that can use this gMSA

New-ADServiceAccount -Name `$gmsaName `
    -DNSHostName `$dnsHostName `
    -PrincipalsAllowedToRetrieveManagedPassword `$serviceHosts `
    -Enabled `$true

Write-Host "Created gMSA: `$gmsaName"

# STEP 3: Install gMSA on target server
# Run on the server that will use the gMSA:
# Install-ADServiceAccount -Identity gMSA_SQLServer
# Test-ADServiceAccount -Identity gMSA_SQLServer

# STEP 4: Configure service to use gMSA
# In Services console or via sc.exe:
# sc.exe config "ServiceName" obj= "DOMAIN\gMSA_SQLServer`$" password= ""
# Note: Password is blank for gMSA

# STEP 5: Identify existing service accounts to migrate
Write-Host "`nExisting service accounts (with SPNs):"
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, @{N='SPNs';E={`$_.ServicePrincipalName -join '; '}}, PasswordLastSet |
    Format-Table -AutoSize

# STEP 6: Create migration plan
# For each service account:
# 1. Document current SPNs and permissions
# 2. Create equivalent gMSA
# 3. Test service with gMSA in non-production
# 4. Migrate production service
# 5. Disable old service account

# STEP 7: Set password policy for remaining service accounts
# If gMSA migration isn't possible, ensure:
# - Minimum 25+ character passwords
# - Regular password rotation (90 days max)
# - Monitoring for Kerberoasting attempts

# STEP 8: Monitor gMSA usage
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object Name, Enabled, PrincipalsAllowedToRetrieveManagedPassword

"@
            return $commands
        }
    }
}

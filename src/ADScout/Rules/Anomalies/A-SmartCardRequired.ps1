@{
    Id          = 'A-SmartCardRequired'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Smart Card Not Required for Administrators'
    Description = 'Detects when privileged accounts (Domain Admins, Enterprise Admins, Schema Admins) do not have the "Smart card is required for interactive logon" flag set. Smart card authentication provides stronger security than passwords for privileged accounts.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Smart Card Authentication'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-and-remote-desktop-services' }
        @{ Title = 'Privileged Access Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access' }
        @{ Title = 'PingCastle Rule A-SmartCardRequired'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1078.002', 'T1110')  # Domain Accounts, Brute Force
    }

    CIS   = @()  # Smart card requirements vary by organization policy
    STIG  = @()  # Smart card STIGs are environment-specific
    ANSSI = @()
    NIST  = @('IA-2(1)', 'IA-2(2)')  # Multi-Factor Authentication

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 2
        MaxPoints = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # UAC flag for smart card required
        $SMARTCARD_REQUIRED = 0x40000  # 262144

        # Privileged groups to check
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators'
        )

        try {
            # Get members of privileged groups
            $privilegedUsers = @{}

            foreach ($groupName in $privilegedGroups) {
                $group = $Data.Groups | Where-Object { $_.Name -eq $groupName } | Select-Object -First 1

                if ($group -and $group.Members) {
                    foreach ($member in $group.Members) {
                        $memberName = if ($member -is [string]) {
                            ($member -split ',')[0] -replace 'CN=', ''
                        } else {
                            $member.SamAccountName
                        }

                        if (-not $privilegedUsers.ContainsKey($memberName)) {
                            $privilegedUsers[$memberName] = @()
                        }
                        $privilegedUsers[$memberName] += $groupName
                    }
                } else {
                    # Try via ADSI
                    try {
                        $domainDN = $Domain.DistinguishedName
                        $groupDN = if ($groupName -eq 'Administrators') {
                            "CN=$groupName,CN=Builtin,$domainDN"
                        } else {
                            "CN=$groupName,CN=Users,$domainDN"
                        }

                        $adsiGroup = [ADSI]"LDAP://$groupDN"
                        if ($adsiGroup.Member) {
                            foreach ($memberDN in $adsiGroup.Member) {
                                $memberName = ($memberDN -split ',')[0] -replace 'CN=', ''
                                if (-not $privilegedUsers.ContainsKey($memberName)) {
                                    $privilegedUsers[$memberName] = @()
                                }
                                $privilegedUsers[$memberName] += $groupName
                            }
                        }
                    } catch { }
                }
            }

            # Check each privileged user for smart card requirement
            foreach ($userName in $privilegedUsers.Keys) {
                $user = $Data.Users | Where-Object {
                    $_.SamAccountName -eq $userName -or $_.Name -eq $userName
                } | Select-Object -First 1

                if (-not $user) {
                    # Try to get user via ADSI
                    try {
                        $domainDN = $Domain.DistinguishedName
                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                        $searcher.Filter = "(sAMAccountName=$userName)"
                        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'userAccountControl', 'distinguishedName'))
                        $result = $searcher.FindOne()
                        if ($result) {
                            $user = @{
                                SamAccountName = $result.Properties['samaccountname'][0]
                                UserAccountControl = [int]$result.Properties['useraccountcontrol'][0]
                                DistinguishedName = $result.Properties['distinguishedname'][0]
                            }
                        }
                    } catch { }
                }

                if ($user) {
                    $uac = if ($user.UserAccountControl) { [int]$user.UserAccountControl } else { 0 }
                    $smartCardRequired = ($uac -band $SMARTCARD_REQUIRED) -ne 0

                    if (-not $smartCardRequired) {
                        $groups = $privilegedUsers[$userName] -join ', '

                        $findings += [PSCustomObject]@{
                            AccountName         = $userName
                            PrivilegedGroups    = $groups
                            SmartCardRequired   = $false
                            UserAccountControl  = "0x{0:X}" -f $uac
                            Severity            = 'Medium'
                            Risk                = 'Privileged account can authenticate with password'
                            Impact              = 'Password-based attacks (spray, theft) possible'
                            Recommendation      = 'Enable smart card requirement for privileged accounts'
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "A-SmartCardRequired: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable the "Smart card is required for interactive logon" flag for all privileged accounts. Deploy smart cards and certificate infrastructure.'
        Impact      = 'High - Requires smart card infrastructure. Users will not be able to log on without smart card.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Smart Card Requirement for Administrators Remediation
#
# Privileged accounts without smart card requirement:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.PrivilegedGroups)" } | Out-String)

# IMPORTANT: Ensure smart card infrastructure is in place before enabling!
# - Certificate Authority configured
# - Smart cards provisioned for all admins
# - Smart card readers deployed

# STEP 1: Verify prerequisites
# Check if AD CS is installed for smart card certificates
Get-Service -Name CertSvc -ErrorAction SilentlyContinue

# Check for smart card certificate templates
`$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
`$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC" `
    -Filter {name -like '*SmartCard*'}
Write-Host "Smart Card templates found: `$(`$templates.Count)"

# STEP 2: Enable smart card requirement for specific accounts
# WARNING: User must have a smart card enrolled first!

$($Finding.Findings | ForEach-Object { @"
# Enable for $($_.AccountName) - VERIFY SMART CARD IS ENROLLED FIRST
# Set-ADUser -Identity "$($_.AccountName)" -SmartcardLogonRequired `$true

"@ })

# STEP 3: Enable for all members of Domain Admins at once
# Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser |
#     ForEach-Object {
#         Set-ADUser -Identity `$_.SamAccountName -SmartcardLogonRequired `$true
#         Write-Host "Enabled smart card for: `$(`$_.SamAccountName)"
#     }

# STEP 4: Create dedicated admin accounts with smart card
# Instead of modifying existing accounts, create new Tier 0 admin accounts
`$newAdmin = @{
    Name = "Admin_JDoe_T0"
    SamAccountName = "Admin_JDoe_T0"
    UserPrincipalName = "Admin_JDoe_T0@`$((Get-ADDomain).DNSRoot)"
    Path = "OU=Tier 0 Admins,OU=Admin,`$((Get-ADDomain).DistinguishedName)"
    Enabled = `$true
    SmartcardLogonRequired = `$true
}
# New-ADUser @newAdmin

# STEP 5: Configure smart card GPO settings
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options:
# - "Interactive logon: Require smart card" = Enabled (for admin workstations)
# - "Interactive logon: Smart card removal behavior" = Lock Workstation

# STEP 6: Verify smart card configuration
Get-ADUser -Filter * -Properties SmartcardLogonRequired |
    Where-Object { `$_.SmartcardLogonRequired -eq `$true } |
    Select-Object SamAccountName, SmartcardLogonRequired

# STEP 7: Monitor for password-based logon attempts on admin accounts
# Create alert for Event ID 4624 with Logon Type 2/10 for admin accounts

"@
            return $commands
        }
    }
}

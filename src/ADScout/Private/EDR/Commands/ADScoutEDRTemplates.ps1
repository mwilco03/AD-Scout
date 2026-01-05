#Requires -Version 5.1

<#
.SYNOPSIS
    Pre-canned READ-ONLY execution templates for AD queries via EDR platforms.

.DESCRIPTION
    Provides ready-to-use command templates for common Active Directory
    security reconnaissance tasks. These templates are designed to work
    through EDR platforms like CrowdStrike Falcon, allowing security
    professionals to gather AD data without direct admin access.

    SECURITY: All templates in this file MUST be read-only reconnaissance
    operations. Write operations are NOT permitted through EDR execution.
    Every template must have IsWriteOperation = $false.

.NOTES
    Author: AD-Scout Contributors
    License: MIT
#>

# Template registry
$script:EDRTemplates = @{}

function Register-ADScoutEDRTemplate {
    <#
    .SYNOPSIS
        Registers a pre-canned EDR execution template.

    .DESCRIPTION
        SECURITY: All templates must be marked with IsWriteOperation = $false.
        Templates marked as write operations will be rejected.

    .PARAMETER Template
        Hashtable containing template definition. Must include:
        - Id: Unique template identifier
        - Name: Human-readable name
        - Category: Template category
        - ScriptBlock: PowerShell code to execute
        - IsWriteOperation: Must be $false (read-only enforcement)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Template
    )

    # Validate required fields
    $requiredFields = @('Id', 'Name', 'Category', 'ScriptBlock', 'IsWriteOperation')
    foreach ($field in $requiredFields) {
        if (-not $Template.ContainsKey($field)) {
            throw "Template missing required field: $field"
        }
    }

    # SECURITY: Reject write operation templates
    if ($Template.IsWriteOperation -eq $true) {
        throw "SECURITY: Cannot register template '$($Template.Id)' - write operations are not permitted. EDR execution is read-only."
    }

    $script:EDRTemplates[$Template.Id] = $Template
    Write-Verbose "Registered EDR Template: $($Template.Id) (read-only)"
}

function Get-ADScoutEDRTemplate {
    <#
    .SYNOPSIS
        Gets registered EDR execution templates.

    .PARAMETER Name
        Template ID or name pattern to filter by.

    .PARAMETER Category
        Filter templates by category.
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Category
    )

    $templates = $script:EDRTemplates.Values

    if ($Name) {
        $templates = $templates | Where-Object {
            $_.Id -like "*$Name*" -or $_.Name -like "*$Name*"
        }
    }

    if ($Category) {
        $templates = $templates | Where-Object { $_.Category -eq $Category }
    }

    return $templates
}

# =============================================================================
# Domain Reconnaissance Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-DomainInfo'
    Name               = 'Get Domain Information'
    Category           = 'Reconnaissance'
    Description        = 'Retrieves basic domain information including forest, domain controllers, and functional levels.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    Domain = $null
    Error = $null
}

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $result.Domain = @{
        Name = $domain.Name
        Forest = $domain.Forest.Name
        DomainMode = $domain.DomainMode.ToString()
        ForestMode = $domain.Forest.ForestMode.ToString()
        DomainControllers = @($domain.DomainControllers | ForEach-Object {
            @{
                Name = $_.Name
                IPAddress = $_.IPAddress
                OSVersion = $_.OSVersion
                Roles = @($_.Roles)
                SiteName = $_.SiteName
            }
        })
        PDCEmulator = $domain.PdcRoleOwner.Name
        RIDMaster = $domain.RidRoleOwner.Name
        InfrastructureMaster = $domain.InfrastructureRoleOwner.Name
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-TrustInfo'
    Name               = 'Get Domain Trusts'
    Category           = 'Reconnaissance'
    Description        = 'Enumerates all domain and forest trusts with their attributes.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    Trusts = @()
    Error = $null
}

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Domain trusts
    foreach ($trust in $domain.GetAllTrustRelationships()) {
        $result.Trusts += @{
            SourceName = $trust.SourceName
            TargetName = $trust.TargetName
            TrustType = $trust.TrustType.ToString()
            TrustDirection = $trust.TrustDirection.ToString()
            SelectiveAuthentication = $trust.SelectiveAuthentication
        }
    }

    # Forest trusts
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($trust in $forest.GetAllTrustRelationships()) {
        $result.Trusts += @{
            SourceName = $trust.SourceName
            TargetName = $trust.TargetName
            TrustType = $trust.TrustType.ToString()
            TrustDirection = $trust.TrustDirection.ToString()
            ForestTrust = $true
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Privileged Account Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-PrivilegedGroups'
    Name               = 'Get Privileged Group Members'
    Category           = 'PrivilegedAccounts'
    Description        = 'Enumerates members of high-privilege AD groups (Domain Admins, Enterprise Admins, etc.).'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    PrivilegedGroups = @()
    Error = $null
}

$privilegedGroupSIDs = @(
    'S-1-5-32-544',      # Administrators
    'S-1-5-32-548',      # Account Operators
    'S-1-5-32-549',      # Server Operators
    'S-1-5-32-550',      # Print Operators
    'S-1-5-32-551',      # Backup Operators
    'S-1-5-21-*-512',    # Domain Admins
    'S-1-5-21-*-518',    # Schema Admins
    'S-1-5-21-*-519'     # Enterprise Admins
)

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(|(objectClass=group))"
    $searcher.PropertiesToLoad.AddRange(@('name', 'member', 'objectSid', 'distinguishedName'))
    $searcher.PageSize = 1000

    $domainSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -split '-')[0..6] -join '-'

    foreach ($group in $searcher.FindAll()) {
        $groupSID = (New-Object System.Security.Principal.SecurityIdentifier($group.Properties['objectsid'][0], 0)).Value
        $isPrivileged = $false

        foreach ($pattern in $privilegedGroupSIDs) {
            if ($groupSID -like $pattern.Replace('S-1-5-21-*', $domainSID)) {
                $isPrivileged = $true
                break
            }
            if ($groupSID -eq $pattern) {
                $isPrivileged = $true
                break
            }
        }

        if ($isPrivileged) {
            $members = @()
            if ($group.Properties['member']) {
                foreach ($memberDN in $group.Properties['member']) {
                    $members += $memberDN
                }
            }

            $result.PrivilegedGroups += @{
                Name = $group.Properties['name'][0]
                SID = $groupSID
                DistinguishedName = $group.Properties['distinguishedname'][0]
                MemberCount = $members.Count
                Members = $members
            }
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-AdminSDHolder'
    Name               = 'Get AdminSDHolder Protected Objects'
    Category           = 'PrivilegedAccounts'
    Description        = 'Finds accounts with AdminCount=1 that are protected by AdminSDHolder.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    ProtectedObjects = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(adminCount=1)(|(objectClass=user)(objectClass=group)))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'objectClass', 'distinguishedName',
        'memberOf', 'userAccountControl', 'whenCreated', 'whenChanged'
    ))
    $searcher.PageSize = 1000

    foreach ($obj in $searcher.FindAll()) {
        $props = $obj.Properties
        $result.ProtectedObjects += @{
            SamAccountName = $props['samaccountname'][0]
            ObjectClass = $props['objectclass'] -join ','
            DistinguishedName = $props['distinguishedname'][0]
            MemberOf = @($props['memberof'])
            UserAccountControl = $props['useraccountcontrol'][0]
            WhenCreated = $props['whencreated'][0]
            WhenChanged = $props['whenchanged'][0]
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Kerberos Security Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-SPNAccounts'
    Name               = 'Get Service Principal Name Accounts'
    Category           = 'Kerberos'
    Description        = 'Finds user accounts with SPNs set (potential Kerberoasting targets).'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    SPNAccounts = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'servicePrincipalName', 'distinguishedName',
        'pwdLastSet', 'userAccountControl', 'memberOf', 'adminCount'
    ))
    $searcher.PageSize = 1000

    foreach ($user in $searcher.FindAll()) {
        $props = $user.Properties
        $pwdLastSet = $null
        if ($props['pwdlastset'][0]) {
            $pwdLastSet = [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('o')
        }

        $result.SPNAccounts += @{
            SamAccountName = $props['samaccountname'][0]
            ServicePrincipalNames = @($props['serviceprincipalname'])
            DistinguishedName = $props['distinguishedname'][0]
            PasswordLastSet = $pwdLastSet
            UserAccountControl = $props['useraccountcontrol'][0]
            AdminCount = $props['admincount'][0]
            MemberOf = @($props['memberof'])
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-ASREPRoastable'
    Name               = 'Get AS-REP Roastable Accounts'
    Category           = 'Kerberos'
    Description        = 'Finds accounts that do not require Kerberos pre-authentication.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    ASREPRoastableAccounts = @()
    Error = $null
}

# UAC flag for DONT_REQUIRE_PREAUTH = 4194304
$DONT_REQUIRE_PREAUTH = 4194304

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$DONT_REQUIRE_PREAUTH))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'distinguishedName', 'userAccountControl',
        'pwdLastSet', 'memberOf', 'adminCount', 'lastLogon'
    ))
    $searcher.PageSize = 1000

    foreach ($user in $searcher.FindAll()) {
        $props = $user.Properties
        $pwdLastSet = $null
        if ($props['pwdlastset'][0]) {
            $pwdLastSet = [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('o')
        }
        $lastLogon = $null
        if ($props['lastlogon'][0]) {
            $lastLogon = [DateTime]::FromFileTime($props['lastlogon'][0]).ToString('o')
        }

        $result.ASREPRoastableAccounts += @{
            SamAccountName = $props['samaccountname'][0]
            DistinguishedName = $props['distinguishedname'][0]
            UserAccountControl = $props['useraccountcontrol'][0]
            PasswordLastSet = $pwdLastSet
            LastLogon = $lastLogon
            AdminCount = $props['admincount'][0]
            MemberOf = @($props['memberof'])
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-UnconstrainedDelegation'
    Name               = 'Get Unconstrained Delegation Accounts'
    Category           = 'Kerberos'
    Description        = 'Finds accounts trusted for unconstrained delegation.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    UnconstrainedDelegation = @()
    Error = $null
}

# UAC flag for TRUSTED_FOR_DELEGATION = 524288
$TRUSTED_FOR_DELEGATION = 524288

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=$TRUSTED_FOR_DELEGATION)"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'objectClass', 'distinguishedName',
        'userAccountControl', 'operatingSystem', 'dNSHostName'
    ))
    $searcher.PageSize = 1000

    foreach ($obj in $searcher.FindAll()) {
        $props = $obj.Properties
        $result.UnconstrainedDelegation += @{
            SamAccountName = $props['samaccountname'][0]
            ObjectClass = $props['objectclass'] -join ','
            DistinguishedName = $props['distinguishedname'][0]
            UserAccountControl = $props['useraccountcontrol'][0]
            OperatingSystem = $props['operatingsystem'][0]
            DNSHostName = $props['dnshostname'][0]
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-ConstrainedDelegation'
    Name               = 'Get Constrained Delegation Configuration'
    Category           = 'Kerberos'
    Description        = 'Finds accounts with constrained delegation configured.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    ConstrainedDelegation = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(msDS-AllowedToDelegateTo=*)"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'objectClass', 'distinguishedName',
        'msDS-AllowedToDelegateTo', 'userAccountControl'
    ))
    $searcher.PageSize = 1000

    foreach ($obj in $searcher.FindAll()) {
        $props = $obj.Properties
        $result.ConstrainedDelegation += @{
            SamAccountName = $props['samaccountname'][0]
            ObjectClass = $props['objectclass'] -join ','
            DistinguishedName = $props['distinguishedname'][0]
            AllowedToDelegateTo = @($props['msds-allowedtodelegateto'])
            UserAccountControl = $props['useraccountcontrol'][0]
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Stale Objects Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-StaleComputers'
    Name               = 'Get Stale Computer Accounts'
    Category           = 'StaleObjects'
    Description        = 'Finds computer accounts that have not authenticated recently.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 180
    Parameters         = @{
        DaysInactive = @{ Type = 'int'; Default = 90; Description = 'Days since last logon' }
    }
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$daysInactive = ${DaysInactive}
if (-not $daysInactive) { $daysInactive = 90 }
$cutoffDate = (Get-Date).AddDays(-$daysInactive)
$cutoffFileTime = $cutoffDate.ToFileTime()

$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    DaysInactive = $daysInactive
    CutoffDate = $cutoffDate.ToString('o')
    StaleComputers = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=computer)(lastLogonTimestamp<=$cutoffFileTime))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'distinguishedName', 'lastLogonTimestamp',
        'operatingSystem', 'operatingSystemVersion', 'whenCreated', 'pwdLastSet'
    ))
    $searcher.PageSize = 1000

    foreach ($computer in $searcher.FindAll()) {
        $props = $computer.Properties
        $lastLogon = $null
        if ($props['lastlogontimestamp'][0]) {
            $lastLogon = [DateTime]::FromFileTime($props['lastlogontimestamp'][0]).ToString('o')
        }
        $pwdLastSet = $null
        if ($props['pwdlastset'][0]) {
            $pwdLastSet = [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('o')
        }

        $result.StaleComputers += @{
            SamAccountName = $props['samaccountname'][0]
            DistinguishedName = $props['distinguishedname'][0]
            LastLogon = $lastLogon
            PasswordLastSet = $pwdLastSet
            OperatingSystem = $props['operatingsystem'][0]
            OSVersion = $props['operatingsystemversion'][0]
            WhenCreated = $props['whencreated'][0]
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-StaleUsers'
    Name               = 'Get Stale User Accounts'
    Category           = 'StaleObjects'
    Description        = 'Finds user accounts that have not authenticated recently.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 180
    Parameters         = @{
        DaysInactive = @{ Type = 'int'; Default = 90; Description = 'Days since last logon' }
    }
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$daysInactive = ${DaysInactive}
if (-not $daysInactive) { $daysInactive = 90 }
$cutoffDate = (Get-Date).AddDays(-$daysInactive)
$cutoffFileTime = $cutoffDate.ToFileTime()

$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    DaysInactive = $daysInactive
    CutoffDate = $cutoffDate.ToString('o')
    StaleUsers = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(!(objectClass=computer))(lastLogonTimestamp<=$cutoffFileTime))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'distinguishedName', 'lastLogonTimestamp',
        'userAccountControl', 'whenCreated', 'pwdLastSet', 'memberOf', 'adminCount'
    ))
    $searcher.PageSize = 1000

    foreach ($user in $searcher.FindAll()) {
        $props = $user.Properties
        $lastLogon = $null
        if ($props['lastlogontimestamp'][0]) {
            $lastLogon = [DateTime]::FromFileTime($props['lastlogontimestamp'][0]).ToString('o')
        }
        $pwdLastSet = $null
        if ($props['pwdlastset'][0]) {
            $pwdLastSet = [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('o')
        }

        $result.StaleUsers += @{
            SamAccountName = $props['samaccountname'][0]
            DistinguishedName = $props['distinguishedname'][0]
            LastLogon = $lastLogon
            PasswordLastSet = $pwdLastSet
            UserAccountControl = $props['useraccountcontrol'][0]
            AdminCount = $props['admincount'][0]
            MemberOf = @($props['memberof'])
            WhenCreated = $props['whencreated'][0]
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Password Policy Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-PasswordPolicy'
    Name               = 'Get Domain Password Policy'
    Category           = 'PasswordPolicy'
    Description        = 'Retrieves the default domain password policy and any fine-grained policies.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    DefaultPolicy = $null
    FineGrainedPolicies = @()
    Error = $null
}

try {
    # Get default domain policy from domain object
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=domain)"
    $searcher.PropertiesToLoad.AddRange(@(
        'minPwdLength', 'minPwdAge', 'maxPwdAge', 'pwdHistoryLength',
        'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow'
    ))

    $domain = $searcher.FindOne()
    if ($domain) {
        $props = $domain.Properties
        $result.DefaultPolicy = @{
            MinPasswordLength = $props['minpwdlength'][0]
            MinPasswordAge = $props['minpwdage'][0]
            MaxPasswordAge = $props['maxpwdage'][0]
            PasswordHistoryLength = $props['pwdhistorylength'][0]
            PasswordProperties = $props['pwdproperties'][0]
            LockoutThreshold = $props['lockoutthreshold'][0]
            LockoutDuration = $props['lockoutduration'][0]
            LockoutObservationWindow = $props['lockoutobservationwindow'][0]
        }
    }

    # Get fine-grained password policies (requires 2008+ domain)
    $searcher.Filter = "(objectClass=msDS-PasswordSettings)"
    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.AddRange(@(
        'name', 'msDS-PasswordSettingsPrecedence', 'msDS-MinimumPasswordLength',
        'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge', 'msDS-PasswordHistoryLength',
        'msDS-PasswordComplexityEnabled', 'msDS-LockoutThreshold', 'msDS-LockoutDuration',
        'msDS-PSOAppliesTo'
    ))

    foreach ($pso in $searcher.FindAll()) {
        $props = $pso.Properties
        $result.FineGrainedPolicies += @{
            Name = $props['name'][0]
            Precedence = $props['msds-passwordsettingsprecedence'][0]
            MinPasswordLength = $props['msds-minimumpasswordlength'][0]
            MinPasswordAge = $props['msds-minimumpasswordage'][0]
            MaxPasswordAge = $props['msds-maximumpasswordage'][0]
            PasswordHistoryLength = $props['msds-passwordhistorylength'][0]
            ComplexityEnabled = $props['msds-passwordcomplexityenabled'][0]
            LockoutThreshold = $props['msds-lockoutthreshold'][0]
            LockoutDuration = $props['msds-lockoutduration'][0]
            AppliesTo = @($props['msds-psoappliesTo'])
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-PasswordNeverExpires'
    Name               = 'Get Accounts with Non-Expiring Passwords'
    Category           = 'PasswordPolicy'
    Description        = 'Finds user accounts configured with passwords that never expire.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    PasswordNeverExpiresAccounts = @()
    Error = $null
}

# UAC flag for DONT_EXPIRE_PASSWORD = 65536
$DONT_EXPIRE_PASSWORD = 65536

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=$DONT_EXPIRE_PASSWORD))"
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName', 'distinguishedName', 'userAccountControl',
        'pwdLastSet', 'memberOf', 'adminCount', 'lastLogon'
    ))
    $searcher.PageSize = 1000

    foreach ($user in $searcher.FindAll()) {
        $props = $user.Properties
        $pwdLastSet = $null
        if ($props['pwdlastset'][0]) {
            $pwdLastSet = [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('o')
        }
        $lastLogon = $null
        if ($props['lastlogon'][0]) {
            $lastLogon = [DateTime]::FromFileTime($props['lastlogon'][0]).ToString('o')
        }

        $result.PasswordNeverExpiresAccounts += @{
            SamAccountName = $props['samaccountname'][0]
            DistinguishedName = $props['distinguishedname'][0]
            UserAccountControl = $props['useraccountcontrol'][0]
            PasswordLastSet = $pwdLastSet
            LastLogon = $lastLogon
            AdminCount = $props['admincount'][0]
            MemberOf = @($props['memberof'])
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# GPO Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-GPOList'
    Name               = 'Get Group Policy Objects'
    Category           = 'GPO'
    Description        = 'Enumerates all Group Policy Objects and their links.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    GPOs = @()
    Error = $null
}

try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=groupPolicyContainer)"
    $searcher.PropertiesToLoad.AddRange(@(
        'displayName', 'name', 'gPCFileSysPath', 'versionNumber',
        'flags', 'whenCreated', 'whenChanged'
    ))
    $searcher.PageSize = 1000

    foreach ($gpo in $searcher.FindAll()) {
        $props = $gpo.Properties
        $result.GPOs += @{
            DisplayName = $props['displayname'][0]
            GUID = $props['name'][0]
            FileSysPath = $props['gpcfilesyspath'][0]
            Version = $props['versionnumber'][0]
            Flags = $props['flags'][0]
            WhenCreated = $props['whencreated'][0]
            WhenChanged = $props['whenchanged'][0]
        }
    }

    # Get GPO links from OUs
    $searcher.Filter = "(gPLink=*)"
    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'gPLink', 'name'))

    $gpoLinks = @{}
    foreach ($container in $searcher.FindAll()) {
        $props = $container.Properties
        $gpLink = $props['gplink'][0]
        if ($gpLink) {
            # Parse GPO links: [LDAP://cn={GUID},cn=policies,...;0]
            $matches = [regex]::Matches($gpLink, '\[LDAP://cn=\{([^}]+)\}[^;]*;(\d+)\]')
            foreach ($match in $matches) {
                $gpoGuid = $match.Groups[1].Value
                $linkOptions = $match.Groups[2].Value
                if (-not $gpoLinks.ContainsKey($gpoGuid)) {
                    $gpoLinks[$gpoGuid] = @()
                }
                $gpoLinks[$gpoGuid] += @{
                    LinkedTo = $props['distinguishedname'][0]
                    LinkOptions = $linkOptions
                    Enforced = ($linkOptions -band 2) -eq 2
                    Disabled = ($linkOptions -band 1) -eq 1
                }
            }
        }
    }

    # Add links to GPO results
    foreach ($gpo in $result.GPOs) {
        $guid = $gpo.GUID -replace '[{}]', ''
        $gpo.Links = if ($gpoLinks.ContainsKey($guid)) { $gpoLinks[$guid] } else { @() }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Endpoint Configuration Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-LocalAdmins'
    Name               = 'Get Local Administrators'
    Category           = 'EndpointConfig'
    Description        = 'Enumerates members of the local Administrators group on the endpoint.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $true
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    LocalAdministrators = @()
    Error = $null
}

try {
    $admins = net localgroup Administrators 2>$null
    $inMembers = $false
    foreach ($line in $admins) {
        if ($line -match '^-+$') {
            $inMembers = $true
            continue
        }
        if ($inMembers -and $line -match '\S' -and $line -notmatch 'command completed') {
            $result.LocalAdministrators += $line.Trim()
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 5 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-SecurityConfig'
    Name               = 'Get Endpoint Security Configuration'
    Category           = 'EndpointConfig'
    Description        = 'Retrieves security-relevant configuration from the endpoint (firewall, AV, etc.).'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $true
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    OSInfo = $null
    Firewall = $null
    Antivirus = @()
    SecurityServices = @()
    LSAProtection = $null
    CredentialGuard = $null
    Error = $null
}

try {
    # OS Information
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $result.OSInfo = @{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            LastBootUpTime = $os.LastBootUpTime.ToString('o')
        }
    }

    # Firewall Status
    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fw) {
        $result.Firewall = @($fw | ForEach-Object {
            @{
                Profile = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction.ToString()
                DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
            }
        })
    }

    # Antivirus (Windows Security Center)
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    if ($av) {
        $result.Antivirus = @($av | ForEach-Object {
            @{
                DisplayName = $_.displayName
                InstanceGuid = $_.instanceGuid
                ProductState = $_.productState
                PathToSignedProductExe = $_.pathToSignedProductExe
            }
        })
    }

    # Security Services
    $secServices = @('WinDefend', 'Sense', 'MsMpSvc', 'CSFalconService', 'CbDefense')
    foreach ($svc in $secServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            $result.SecurityServices += @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
            }
        }
    }

    # LSA Protection
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
    $result.LSAProtection = if ($lsa.RunAsPPL -eq 1) { $true } else { $false }

    # Credential Guard
    $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($cg) {
        $result.CredentialGuard = @{
            SecurityServicesConfigured = $cg.SecurityServicesConfigured
            SecurityServicesRunning = $cg.SecurityServicesRunning
            VirtualizationBasedSecurityStatus = $cg.VirtualizationBasedSecurityStatus
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-InstalledSoftware'
    Name               = 'Get Installed Software'
    Category           = 'EndpointConfig'
    Description        = 'Lists installed software with focus on security-relevant applications.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    InstalledSoftware = @()
    Error = $null
}

try {
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $regPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                $result.InstalledSoftware += @{
                    DisplayName = $_.DisplayName
                    DisplayVersion = $_.DisplayVersion
                    Publisher = $_.Publisher
                    InstallDate = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                }
            }
    }

    # Remove duplicates
    $result.InstalledSoftware = $result.InstalledSoftware |
        Sort-Object DisplayName -Unique
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 5 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-ScheduledTasks'
    Name               = 'Get Scheduled Tasks'
    Category           = 'EndpointConfig'
    Description        = 'Enumerates scheduled tasks for persistence detection.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $true
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    ScheduledTasks = @()
    Error = $null
}

try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Disabled' }

    foreach ($task in $tasks) {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

        $result.ScheduledTasks += @{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = $task.State.ToString()
            Author = $task.Author
            Description = $task.Description
            Principal = @{
                UserId = $task.Principal.UserId
                RunLevel = $task.Principal.RunLevel.ToString()
                LogonType = $task.Principal.LogonType.ToString()
            }
            Actions = @($task.Actions | ForEach-Object {
                @{
                    Execute = $_.Execute
                    Arguments = $_.Arguments
                    WorkingDirectory = $_.WorkingDirectory
                }
            })
            LastRunTime = if ($info.LastRunTime) { $info.LastRunTime.ToString('o') } else { $null }
            NextRunTime = if ($info.NextRunTime) { $info.NextRunTime.ToString('o') } else { $null }
        }
    }
} catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

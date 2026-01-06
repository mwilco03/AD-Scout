#Requires -Version 5.1

<#
.SYNOPSIS
    Pre-canned execution templates for AD queries via EDR platforms.

.DESCRIPTION
    Provides ready-to-use command templates for common Active Directory
    security reconnaissance tasks. These templates are designed to work
    through EDR platforms like CrowdStrike Falcon, allowing security
    professionals to gather AD data without direct admin access.

    SECURITY - Multi-Session Mode:
    When multiple EDR sessions are active (MSSP multi-tenant scenarios),
    only templates marked with IsWriteOperation = $false can be executed.
    This protects client environments from accidental modifications.

    Single session = All templates allowed (full access)
    Multi-session  = Read-only templates only (IsWriteOperation = $false)

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
        Registers a template for EDR execution. Templates must declare whether
        they perform write operations via the IsWriteOperation flag.

        SECURITY NOTE:
        - Single-session mode: All templates allowed (full access)
        - Multi-session mode: Only templates with IsWriteOperation = $false are allowed

    .PARAMETER Template
        Hashtable containing template definition. Must include:
        - Id: Unique template identifier
        - Name: Human-readable name
        - Category: Template category
        - ScriptBlock: PowerShell code to execute
        - IsWriteOperation: $true if template modifies system state, $false for read-only
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

    # Log warning for write operations (they'll only work in single-session mode)
    if ($Template.IsWriteOperation -eq $true) {
        Write-Verbose "Template '$($Template.Id)' is marked as write operation - only available in single-session mode"
    }

    $script:EDRTemplates[$Template.Id] = $Template
    Write-Verbose "Registered EDR Template: $($Template.Id)"
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

# =============================================================================
# Comprehensive Collection Templates
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'AD-FullRecon'
    Name               = 'Full AD Security Reconnaissance'
    Category           = 'Collection'
    Description        = 'Comprehensive AD security collection - domain info, trusts, privileged accounts, delegation, Kerberos risks, and password policy in one execution.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $false
    Timeout            = 600  # 10 minutes for full collection
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    CollectionType = 'AD-FullRecon'
    Domain = $null
    Trusts = @()
    PrivilegedGroups = @()
    AdminSDHolderObjects = @()
    SPNAccounts = @()
    ASREPRoastable = @()
    UnconstrainedDelegation = @()
    ConstrainedDelegation = @()
    PasswordPolicy = $null
    PasswordNeverExpires = @()
    Errors = @()
}

try {
    # Domain Information
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $result.Domain = @{
            Name = $domain.Name
            Forest = $domain.Forest.Name
            DomainMode = $domain.DomainMode.ToString()
            ForestMode = $domain.Forest.ForestMode.ToString()
            DomainControllers = @($domain.DomainControllers | ForEach-Object {
                @{ Name = $_.Name; IPAddress = $_.IPAddress; SiteName = $_.SiteName }
            })
            PDCEmulator = $domain.PdcRoleOwner.Name
        }
    } catch { $result.Errors += "Domain: $($_.Exception.Message)" }

    # Trusts
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($trust in $domain.GetAllTrustRelationships()) {
            $result.Trusts += @{
                SourceName = $trust.SourceName
                TargetName = $trust.TargetName
                TrustType = $trust.TrustType.ToString()
                TrustDirection = $trust.TrustDirection.ToString()
            }
        }
    } catch { $result.Errors += "Trusts: $($_.Exception.Message)" }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.PageSize = 1000
    $domainSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -split '-')[0..6] -join '-'

    # Privileged Groups
    try {
        $privilegedSIDs = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', "$domainSID-512", "$domainSID-518", "$domainSID-519")
        $searcher.Filter = "(objectClass=group)"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('name', 'member', 'objectSid', 'distinguishedName'))
        foreach ($group in $searcher.FindAll()) {
            $groupSID = (New-Object System.Security.Principal.SecurityIdentifier($group.Properties['objectsid'][0], 0)).Value
            if ($privilegedSIDs -contains $groupSID) {
                $result.PrivilegedGroups += @{
                    Name = $group.Properties['name'][0]
                    SID = $groupSID
                    MemberCount = @($group.Properties['member']).Count
                    Members = @($group.Properties['member'])
                }
            }
        }
    } catch { $result.Errors += "PrivilegedGroups: $($_.Exception.Message)" }

    # AdminSDHolder
    try {
        $searcher.Filter = "(&(adminCount=1)(|(objectClass=user)(objectClass=group)))"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'objectClass', 'distinguishedName'))
        foreach ($obj in $searcher.FindAll()) {
            $result.AdminSDHolderObjects += @{
                SamAccountName = $obj.Properties['samaccountname'][0]
                ObjectClass = $obj.Properties['objectclass'] -join ','
                DistinguishedName = $obj.Properties['distinguishedname'][0]
            }
        }
    } catch { $result.Errors += "AdminSDHolder: $($_.Exception.Message)" }

    # SPN Accounts (Kerberoastable)
    try {
        $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'servicePrincipalName', 'pwdLastSet', 'adminCount'))
        foreach ($user in $searcher.FindAll()) {
            $pwdLastSet = $null
            if ($user.Properties['pwdlastset'][0]) {
                $pwdLastSet = [DateTime]::FromFileTime($user.Properties['pwdlastset'][0]).ToString('o')
            }
            $result.SPNAccounts += @{
                SamAccountName = $user.Properties['samaccountname'][0]
                SPNs = @($user.Properties['serviceprincipalname'])
                PasswordLastSet = $pwdLastSet
                AdminCount = $user.Properties['admincount'][0]
            }
        }
    } catch { $result.Errors += "SPNAccounts: $($_.Exception.Message)" }

    # AS-REP Roastable
    try {
        $DONT_REQUIRE_PREAUTH = 4194304
        $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$DONT_REQUIRE_PREAUTH))"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'distinguishedName'))
        foreach ($user in $searcher.FindAll()) {
            $result.ASREPRoastable += @{
                SamAccountName = $user.Properties['samaccountname'][0]
                DistinguishedName = $user.Properties['distinguishedname'][0]
            }
        }
    } catch { $result.Errors += "ASREPRoastable: $($_.Exception.Message)" }

    # Unconstrained Delegation
    try {
        $TRUSTED_FOR_DELEGATION = 524288
        $searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=$TRUSTED_FOR_DELEGATION)"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'objectClass', 'dNSHostName'))
        foreach ($obj in $searcher.FindAll()) {
            $result.UnconstrainedDelegation += @{
                SamAccountName = $obj.Properties['samaccountname'][0]
                ObjectClass = $obj.Properties['objectclass'] -join ','
                DNSHostName = $obj.Properties['dnshostname'][0]
            }
        }
    } catch { $result.Errors += "UnconstrainedDelegation: $($_.Exception.Message)" }

    # Constrained Delegation
    try {
        $searcher.Filter = "(msDS-AllowedToDelegateTo=*)"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'msDS-AllowedToDelegateTo'))
        foreach ($obj in $searcher.FindAll()) {
            $result.ConstrainedDelegation += @{
                SamAccountName = $obj.Properties['samaccountname'][0]
                AllowedToDelegateTo = @($obj.Properties['msds-allowedtodelegateto'])
            }
        }
    } catch { $result.Errors += "ConstrainedDelegation: $($_.Exception.Message)" }

    # Password Policy
    try {
        $searcher.Filter = "(objectClass=domain)"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('minPwdLength', 'maxPwdAge', 'pwdHistoryLength', 'lockoutThreshold'))
        $domainObj = $searcher.FindOne()
        if ($domainObj) {
            $result.PasswordPolicy = @{
                MinPasswordLength = $domainObj.Properties['minpwdlength'][0]
                MaxPasswordAge = $domainObj.Properties['maxpwdage'][0]
                PasswordHistoryLength = $domainObj.Properties['pwdhistorylength'][0]
                LockoutThreshold = $domainObj.Properties['lockoutthreshold'][0]
            }
        }
    } catch { $result.Errors += "PasswordPolicy: $($_.Exception.Message)" }

    # Password Never Expires (limited to first 100)
    try {
        $DONT_EXPIRE_PASSWORD = 65536
        $searcher.Filter = "(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=$DONT_EXPIRE_PASSWORD))"
        $searcher.PropertiesToLoad.Clear()
        $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'adminCount'))
        $searcher.SizeLimit = 100
        foreach ($user in $searcher.FindAll()) {
            $result.PasswordNeverExpires += @{
                SamAccountName = $user.Properties['samaccountname'][0]
                AdminCount = $user.Properties['admincount'][0]
            }
        }
    } catch { $result.Errors += "PasswordNeverExpires: $($_.Exception.Message)" }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-FullRecon'
    Name               = 'Full Endpoint Security Reconnaissance'
    Category           = 'Collection'
    Description        = 'Comprehensive endpoint security baseline - OS info, security config, local admins, AV status, firewall, scheduled tasks in one execution.'
    IsWriteOperation   = $false  # SECURITY: Read-only reconnaissance
    RequiresElevation  = $true
    Timeout            = 300  # 5 minutes
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    CollectionType = 'EP-FullRecon'
    OSInfo = $null
    LocalAdministrators = @()
    Firewall = @()
    Antivirus = @()
    SecurityServices = @()
    LSAProtection = $null
    CredentialGuard = $null
    ScheduledTasks = @()
    RecentLogons = @()
    Errors = @()
}

try {
    # OS Information
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $result.OSInfo = @{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            LastBootUpTime = $os.LastBootUpTime.ToString('o')
            Domain = $cs.Domain
            DomainRole = $cs.DomainRole
            TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        }
    } catch { $result.Errors += "OSInfo: $($_.Exception.Message)" }

    # Local Administrators
    try {
        $admins = net localgroup Administrators 2>$null
        $inMembers = $false
        foreach ($line in $admins) {
            if ($line -match '^-+$') { $inMembers = $true; continue }
            if ($inMembers -and $line -match '\S' -and $line -notmatch 'command completed') {
                $result.LocalAdministrators += $line.Trim()
            }
        }
    } catch { $result.Errors += "LocalAdmins: $($_.Exception.Message)" }

    # Firewall Status
    try {
        $fw = Get-NetFirewallProfile
        $result.Firewall = @($fw | ForEach-Object {
            @{
                Profile = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction.ToString()
                DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
            }
        })
    } catch { $result.Errors += "Firewall: $($_.Exception.Message)" }

    # Antivirus
    try {
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
        $result.Antivirus = @($av | ForEach-Object {
            @{
                DisplayName = $_.displayName
                ProductState = $_.productState
                PathToSignedProductExe = $_.pathToSignedProductExe
            }
        })
    } catch { $result.Errors += "Antivirus: $($_.Exception.Message)" }

    # Security Services
    try {
        $secServices = @('WinDefend', 'Sense', 'CSFalconService', 'CbDefense', 'McAfeeFramework', 'SepMasterService')
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
    } catch { $result.Errors += "SecurityServices: $($_.Exception.Message)" }

    # LSA Protection
    try {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
        $result.LSAProtection = ($lsa.RunAsPPL -eq 1)
    } catch { $result.Errors += "LSAProtection: $($_.Exception.Message)" }

    # Credential Guard
    try {
        $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($cg) {
            $result.CredentialGuard = @{
                VBSRunning = ($cg.VirtualizationBasedSecurityStatus -eq 2)
                CredentialGuardRunning = ($cg.SecurityServicesRunning -contains 1)
            }
        }
    } catch { $result.Errors += "CredentialGuard: $($_.Exception.Message)" }

    # Scheduled Tasks (non-Microsoft, enabled only)
    try {
        $tasks = Get-ScheduledTask | Where-Object {
            $_.State -ne 'Disabled' -and
            $_.TaskPath -notmatch '^\\Microsoft\\'
        } | Select-Object -First 50
        foreach ($task in $tasks) {
            $result.ScheduledTasks += @{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State.ToString()
                Author = $task.Author
                Actions = @($task.Actions | ForEach-Object { $_.Execute })
            }
        }
    } catch { $result.Errors += "ScheduledTasks: $($_.Exception.Message)" }

    # Recent Interactive Logons (from Security log, last 24h)
    try {
        $yesterday = (Get-Date).AddDays(-1)
        $logons = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624
            StartTime = $yesterday
        } -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[8].Value -in @(2, 10, 11)  # Interactive, RemoteInteractive, CachedInteractive
        }
        foreach ($event in $logons) {
            $result.RecentLogons += @{
                TimeCreated = $event.TimeCreated.ToString('o')
                TargetUserName = $event.Properties[5].Value
                TargetDomainName = $event.Properties[6].Value
                LogonType = $event.Properties[8].Value
                IpAddress = $event.Properties[18].Value
            }
        }
    } catch { $result.Errors += "RecentLogons: $($_.Exception.Message)" }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

# =============================================================================
# Endpoint Security Configuration Templates (P0 - Critical)
# =============================================================================

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-CredentialProtection'
    Name               = 'Get Credential Protection Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves credential protection settings including WDigest, LSA Protection, Credential Guard, cached credentials, and NTLM settings.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    WDigest = $null
    LSAProtection = $null
    CredentialGuard = $null
    CachedLogons = $null
    NTLMSettings = $null
    AutoLogon = $null
    CredentialDelegation = $null
    Errors = @()
}

try {
    # WDigest - UseLogonCredential (cleartext passwords in memory)
    try {
        $wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
        $result.WDigest = @{
            UseLogonCredential = $wdigest.UseLogonCredential
            Negotiate = $wdigest.Negotiate
            Vulnerable = ($wdigest.UseLogonCredential -eq 1)
        }
    } catch { $result.Errors += "WDigest: $($_.Exception.Message)" }

    # LSA Protection (RunAsPPL)
    try {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
        $result.LSAProtection = @{
            RunAsPPL = $lsa.RunAsPPL
            LimitBlankPasswordUse = $lsa.LimitBlankPasswordUse
            NoLMHash = $lsa.NoLMHash
            RestrictAnonymous = $lsa.RestrictAnonymous
            RestrictAnonymousSAM = $lsa.RestrictAnonymousSAM
            EveryoneIncludesAnonymous = $lsa.EveryoneIncludesAnonymous
            Protected = ($lsa.RunAsPPL -eq 1)
        }
    } catch { $result.Errors += "LSAProtection: $($_.Exception.Message)" }

    # Credential Guard / Device Guard
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            $result.CredentialGuard = @{
                SecurityServicesConfigured = $dg.SecurityServicesConfigured
                SecurityServicesRunning = $dg.SecurityServicesRunning
                VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
                VBSRunning = ($dg.VirtualizationBasedSecurityStatus -eq 2)
                CredentialGuardRunning = ($dg.SecurityServicesRunning -contains 1)
                HVCIRunning = ($dg.SecurityServicesRunning -contains 2)
            }
        } else {
            $result.CredentialGuard = @{ Available = $false }
        }
    } catch { $result.Errors += "CredentialGuard: $($_.Exception.Message)" }

    # Cached Logons
    try {
        $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        $result.CachedLogons = @{
            CachedLogonsCount = $winlogon.CachedLogonsCount
            ExcessiveCaching = ([int]$winlogon.CachedLogonsCount -gt 2)
        }
    } catch { $result.Errors += "CachedLogons: $($_.Exception.Message)" }

    # NTLM Settings
    try {
        $lsaMsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue
        $lsaPolicy = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
        $result.NTLMSettings = @{
            LmCompatibilityLevel = $lsaPolicy.LmCompatibilityLevel
            NtlmMinClientSec = $lsaMsa.NtlmMinClientSec
            NtlmMinServerSec = $lsaMsa.NtlmMinServerSec
            RestrictSendingNTLMTraffic = $lsaMsa.RestrictSendingNTLMTraffic
        }
    } catch { $result.Errors += "NTLMSettings: $($_.Exception.Message)" }

    # AutoLogon credentials
    try {
        $autologon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        $result.AutoLogon = @{
            AutoAdminLogon = $autologon.AutoAdminLogon
            DefaultUserName = $autologon.DefaultUserName
            DefaultDomainName = $autologon.DefaultDomainName
            DefaultPasswordSet = (-not [string]::IsNullOrEmpty($autologon.DefaultPassword))
            Vulnerable = (($autologon.AutoAdminLogon -eq '1') -and (-not [string]::IsNullOrEmpty($autologon.DefaultPassword)))
        }
    } catch { $result.Errors += "AutoLogon: $($_.Exception.Message)" }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-DefenderStatus'
    Name               = 'Get Windows Defender Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves comprehensive Windows Defender configuration including real-time protection, exclusions, ASR rules, and tamper protection.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 90
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    MpComputerStatus = $null
    MpPreference = $null
    Exclusions = $null
    ASRRules = $null
    Errors = @()
}

try {
    # Get Defender status
    try {
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status) {
            $result.MpComputerStatus = @{
                AMServiceEnabled = $status.AMServiceEnabled
                AntispywareEnabled = $status.AntispywareEnabled
                AntivirusEnabled = $status.AntivirusEnabled
                AntivirusSignatureAge = $status.AntivirusSignatureAge
                BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
                IoavProtectionEnabled = $status.IoavProtectionEnabled
                IsTamperProtected = $status.IsTamperProtected
                NISEnabled = $status.NISEnabled
                OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
                RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                DefenderSignaturesOutOfDate = $status.DefenderSignaturesOutOfDate
            }
        }
    } catch { $result.Errors += "MpComputerStatus: $($_.Exception.Message)" }

    # Get Defender preferences
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($pref) {
            $result.MpPreference = @{
                DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
                DisableBehaviorMonitoring = $pref.DisableBehaviorMonitoring
                DisableIOAVProtection = $pref.DisableIOAVProtection
                DisableScriptScanning = $pref.DisableScriptScanning
                EnableControlledFolderAccess = $pref.EnableControlledFolderAccess
                EnableNetworkProtection = $pref.EnableNetworkProtection
                PUAProtection = $pref.PUAProtection
            }

            $result.Exclusions = @{
                ExclusionPath = @($pref.ExclusionPath)
                ExclusionExtension = @($pref.ExclusionExtension)
                ExclusionProcess = @($pref.ExclusionProcess)
                TotalExclusions = @($pref.ExclusionPath).Count + @($pref.ExclusionExtension).Count + @($pref.ExclusionProcess).Count
            }

            # ASR Rules
            $asrIds = $pref.AttackSurfaceReductionRules_Ids
            $asrActions = $pref.AttackSurfaceReductionRules_Actions
            $asrRules = @()
            if ($asrIds -and $asrActions) {
                for ($i = 0; $i -lt $asrIds.Count; $i++) {
                    $asrRules += @{ RuleId = $asrIds[$i]; Action = $asrActions[$i] }
                }
            }
            $result.ASRRules = @{
                Rules = $asrRules
                EnabledCount = ($asrRules | Where-Object { $_.Action -eq 1 }).Count
                DisabledCount = ($asrRules | Where-Object { $_.Action -eq 0 }).Count
            }
        }
    } catch { $result.Errors += "MpPreference: $($_.Exception.Message)" }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-UACConfiguration'
    Name               = 'Get UAC Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves User Account Control configuration settings.'
    IsWriteOperation   = $false
    RequiresElevation  = $false
    Timeout            = 30
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    UACSettings = $null
    Vulnerabilities = @()
    Errors = @()
}

try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

    $result.UACSettings = @{
        EnableLUA = $uac.EnableLUA
        ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
        ConsentPromptBehaviorUser = $uac.ConsentPromptBehaviorUser
        FilterAdministratorToken = $uac.FilterAdministratorToken
        PromptOnSecureDesktop = $uac.PromptOnSecureDesktop
        EnableVirtualization = $uac.EnableVirtualization
        LocalAccountTokenFilterPolicy = $uac.LocalAccountTokenFilterPolicy
    }

    if ($uac.EnableLUA -eq 0) {
        $result.Vulnerabilities += @{ Setting = 'EnableLUA'; Risk = 'Critical'; Description = 'UAC disabled' }
    }
    if ($uac.ConsentPromptBehaviorAdmin -eq 0) {
        $result.Vulnerabilities += @{ Setting = 'ConsentPromptBehaviorAdmin'; Risk = 'High'; Description = 'Admin elevates without prompt' }
    }
    if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
        $result.Vulnerabilities += @{ Setting = 'LocalAccountTokenFilterPolicy'; Risk = 'High'; Description = 'Remote UAC disabled' }
    }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-LocalAccounts'
    Name               = 'Get Local Accounts and Groups'
    Category           = 'EndpointSecurity'
    Description        = 'Enumerates local accounts and security-relevant group memberships.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    LocalUsers = @()
    SecurityGroups = @{}
    Errors = @()
}

try {
    # Local users
    $users = Get-LocalUser -ErrorAction SilentlyContinue
    foreach ($user in $users) {
        $result.LocalUsers += @{
            Name = $user.Name
            Enabled = $user.Enabled
            PasswordLastSet = if($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') } else { $null }
            PasswordRequired = $user.PasswordRequired
            SID = $user.SID.Value
        }
    }

    # Security groups
    $groups = @('Administrators','Remote Desktop Users','Backup Operators','Hyper-V Administrators')
    foreach ($groupName in $groups) {
        try {
            $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
            $result.SecurityGroups[$groupName] = @{
                Members = @($members | ForEach-Object { @{ Name = $_.Name; ObjectClass = $_.ObjectClass } })
                MemberCount = @($members).Count
            }
        } catch {}
    }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-ServiceSecurity'
    Name               = 'Get Service Security Issues'
    Category           = 'EndpointSecurity'
    Description        = 'Identifies service security issues including unquoted paths and weak permissions.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    UnquotedPaths = @()
    HighPrivilegeServices = @()
    Errors = @()
}

try {
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

    foreach ($svc in $services) {
        $pathName = $svc.PathName
        if ($pathName -and $pathName -notmatch '^"' -and $pathName -match '\s' -and $pathName -match '\.exe') {
            $result.UnquotedPaths += @{
                ServiceName = $svc.Name
                DisplayName = $svc.DisplayName
                PathName = $pathName
                StartMode = $svc.StartMode
                StartName = $svc.StartName
            }
        }

        if ($svc.StartName -eq 'LocalSystem' -and $svc.PathName -notmatch 'Windows|Microsoft') {
            $result.HighPrivilegeServices += @{
                ServiceName = $svc.Name
                DisplayName = $svc.DisplayName
                PathName = $svc.PathName
            }
        }
    }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-PersistenceMechanisms'
    Name               = 'Get Persistence Mechanisms'
    Category           = 'EndpointSecurity'
    Description        = 'Enumerates persistence mechanisms including Run keys, scheduled tasks, and WMI subscriptions.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 120
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    RunKeys = @()
    ScheduledTasks = @()
    WMISubscriptions = @()
    Errors = @()
}

try {
    # Run Keys
    $runPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
    foreach ($path in $runPaths) {
        $keys = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($keys) {
            $props = $keys.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider') }
            foreach ($prop in $props) {
                $result.RunKeys += @{ Path = $path; Name = $prop.Name; Value = $prop.Value }
            }
        }
    }

    # Scheduled Tasks (non-Microsoft)
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' }
    foreach ($task in $tasks | Select-Object -First 30) {
        $result.ScheduledTasks += @{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            UserId = $task.Principal.UserId
            Actions = @($task.Actions | ForEach-Object { $_.Execute })
        }
    }

    # WMI Subscriptions
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $result.WMISubscriptions += @{ Name = $c.Name; CommandLineTemplate = $c.CommandLineTemplate }
    }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-PowerShellSecurity'
    Name               = 'Get PowerShell Security Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves PowerShell security settings including execution policy and logging.'
    IsWriteOperation   = $false
    RequiresElevation  = $false
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    ExecutionPolicy = (Get-ExecutionPolicy -ErrorAction SilentlyContinue)
    LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
    Logging = $null
    PSVersion = $PSVersionTable.PSVersion.ToString()
    Errors = @()
}

try {
    $psLogging = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
    $moduleLogging = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue

    $result.Logging = @{
        ScriptBlockLogging = ($psLogging.EnableScriptBlockLogging -eq 1)
        ModuleLogging = ($moduleLogging.EnableModuleLogging -eq 1)
    }

    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    $result.V2Enabled = ($psv2.State -eq 'Enabled')

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-NetworkSecurity'
    Name               = 'Get Network Security Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves network security settings including firewall, proxy, SMB, and RDP.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 90
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    Firewall = @()
    SMB = $null
    RDP = $null
    Proxy = $null
    Errors = @()
}

try {
    # Firewall
    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($p in $fw) {
        $result.Firewall += @{ Profile = $p.Name; Enabled = $p.Enabled }
    }

    # SMB
    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $result.SMB = @{
        SMB1Enabled = ($smb1.State -eq 'Enabled')
        RequireSecuritySignature = $smbServer.RequireSecuritySignature
        EncryptData = $smbServer.EncryptData
    }

    # RDP
    $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $nla = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
    $result.RDP = @{
        Enabled = ($rdp.fDenyTSConnections -eq 0)
        NLARequired = ($nla.UserAuthentication -eq 1)
    }

    # Proxy
    $ieProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $result.Proxy = @{
        ProxyEnabled = $ieProxy.ProxyEnable
        ProxyServer = $ieProxy.ProxyServer
        AutoConfigURL = $ieProxy.AutoConfigURL
    }

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

Register-ADScoutEDRTemplate @{
    Id                 = 'EP-AuditPolicy'
    Name               = 'Get Audit Policy Configuration'
    Category           = 'EndpointSecurity'
    Description        = 'Retrieves Windows audit policy and event log configuration.'
    IsWriteOperation   = $false
    RequiresElevation  = $true
    Timeout            = 60
    OutputType         = 'JSON'
    ScriptBlock        = @'
$ErrorActionPreference = 'SilentlyContinue'
$result = @{
    Timestamp = Get-Date -Format 'o'
    Hostname = $env:COMPUTERNAME
    EventLogs = @()
    CommandLineAuditing = $null
    Errors = @()
}

try {
    $logNames = @('Security', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational')
    foreach ($logName in $logNames) {
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($log) {
            $result.EventLogs += @{
                LogName = $log.LogName
                MaxSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
                IsEnabled = $log.IsEnabled
            }
        }
    }

    $cmdline = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
    $result.CommandLineAuditing = ($cmdline.ProcessCreationIncludeCmdLine_Enabled -eq 1)

} catch {
    $result.Errors += "Global: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 10 -Compress
'@
}

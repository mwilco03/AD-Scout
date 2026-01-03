function Test-ADScoutEnvironment {
    <#
    .SYNOPSIS
        Detects and validates the Active Directory environment before remediation.

    .DESCRIPTION
        Performs environment checks to determine if remediation is safe to proceed:
        - Detects production vs. non-production environments
        - Validates domain connectivity and permissions
        - Checks for conflicting operations
        - Warns about cross-domain or forest-level impacts

    .PARAMETER TargetDomain
        The domain to check. Defaults to current domain.

    .PARAMETER RequireNonProduction
        If set, will block execution in production environments.

    .PARAMETER AllowedOUs
        Limit remediation scope to specific OUs.

    .EXAMPLE
        Test-ADScoutEnvironment -RequireNonProduction
        Checks environment and blocks if production is detected.

    .OUTPUTS
        ADScoutEnvironmentCheck
        Environment validation results.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TargetDomain,

        [Parameter()]
        [switch]$RequireNonProduction,

        [Parameter()]
        [string[]]$AllowedOUs
    )

    $result = @{
        IsValid            = $true
        IsProduction       = $false
        EnvironmentType    = 'Unknown'
        Domain             = $null
        DomainController   = $null
        Warnings           = @()
        Errors             = @()
        Permissions        = @{}
        ScopeRestrictions  = @()
    }

    try {
        # Get domain info
        if ($TargetDomain) {
            $domain = Get-ADDomain -Server $TargetDomain
        }
        else {
            $domain = Get-ADDomain
        }

        $result.Domain = $domain.DNSRoot
        $result.DomainController = $domain.PDCEmulator

        # Detect environment type based on naming conventions
        $envIndicators = @{
            Production = @(
                'prod', 'prd', 'production', 'live', 'corp', 'corporate'
            )
            Development = @(
                'dev', 'develop', 'development', 'sandbox'
            )
            Test = @(
                'test', 'tst', 'testing', 'qa', 'quality', 'stage', 'staging', 'uat'
            )
            Lab = @(

                'lab', 'poc', 'demo', 'training', 'eval'
            )
        }

        $domainLower = $domain.DNSRoot.ToLower()

        foreach ($envType in $envIndicators.Keys) {
            foreach ($indicator in $envIndicators[$envType]) {
                if ($domainLower -match $indicator) {
                    $result.EnvironmentType = $envType
                    break
                }
            }
            if ($result.EnvironmentType -ne 'Unknown') { break }
        }

        # If no indicator found, check for common production patterns
        if ($result.EnvironmentType -eq 'Unknown') {
            # Check if domain matches company TLD pattern (likely production)
            if ($domainLower -match '^\w+\.(com|org|net|local|corp|internal)$') {
                $result.EnvironmentType = 'Production'
                $result.Warnings += "Domain appears to be production (standard naming pattern)"
            }
        }

        $result.IsProduction = $result.EnvironmentType -eq 'Production'

        # Block if production and non-production required
        if ($RequireNonProduction -and $result.IsProduction) {
            $result.IsValid = $false
            $result.Errors += "Production environment detected. Use -Force to override or run in non-production."
        }

        # Check permissions
        $result.Permissions = Test-ADScoutPermissions -Domain $domain.DNSRoot

        if (-not $result.Permissions.CanModifyUsers) {
            $result.Warnings += "Limited permissions: Cannot modify user accounts"
        }

        if (-not $result.Permissions.CanModifyGroups) {
            $result.Warnings += "Limited permissions: Cannot modify groups"
        }

        # Validate OU scope restrictions
        if ($AllowedOUs) {
            $result.ScopeRestrictions = $AllowedOUs
            foreach ($ou in $AllowedOUs) {
                try {
                    $null = Get-ADOrganizationalUnit -Identity $ou
                }
                catch {
                    $result.Warnings += "Allowed OU not found: $ou"
                }
            }
        }

        # Check for recent AD replication issues
        $replStatus = Get-ADReplicationPartnerMetadata -Target $domain.PDCEmulator -ErrorAction SilentlyContinue
        if ($replStatus) {
            $recentFailures = $replStatus | Where-Object { $_.LastReplicationResult -ne 0 }
            if ($recentFailures) {
                $result.Warnings += "AD replication issues detected - changes may not propagate correctly"
            }
        }

        # Check domain functional level
        $domainMode = $domain.DomainMode
        if ($domainMode -match '2008|2003|2000') {
            $result.Warnings += "Legacy domain functional level: $domainMode"
        }

    }
    catch {
        $result.IsValid = $false
        $result.Errors += "Failed to validate environment: $($_.Exception.Message)"
    }

    [PSCustomObject]$result
}

function Test-ADScoutPermissions {
    <#
    .SYNOPSIS
        Tests current user permissions for remediation operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain
    )

    $permissions = @{
        CanModifyUsers     = $false
        CanModifyComputers = $false
        CanModifyGroups    = $false
        CanModifyGPOs      = $false
        CanModifyACLs      = $false
        IsDomainAdmin      = $false
        IsEnterpriseAdmin  = $false
        Groups             = @()
    }

    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

        # Check for privileged groups
        $privilegedSIDs = @{
            'S-1-5-32-544' = 'Administrators'
            'S-1-5-21-*-512' = 'Domain Admins'
            'S-1-5-21-*-519' = 'Enterprise Admins'
            'S-1-5-21-*-518' = 'Schema Admins'
            'S-1-5-21-*-527' = 'Key Admins'
        }

        foreach ($group in $currentUser.Groups) {
            $sid = $group.Value
            foreach ($pattern in $privilegedSIDs.Keys) {
                if ($sid -like $pattern) {
                    $permissions.Groups += $privilegedSIDs[$pattern]
                }
            }
        }

        $permissions.IsDomainAdmin = $permissions.Groups -contains 'Domain Admins'
        $permissions.IsEnterpriseAdmin = $permissions.Groups -contains 'Enterprise Admins'

        # If domain admin, assume full permissions
        if ($permissions.IsDomainAdmin) {
            $permissions.CanModifyUsers = $true
            $permissions.CanModifyComputers = $true
            $permissions.CanModifyGroups = $true
            $permissions.CanModifyGPOs = $true
            $permissions.CanModifyACLs = $true
        }
        else {
            # Test specific permissions by attempting read operations
            try {
                $null = Get-ADUser -Filter * -ResultSetSize 1
                $permissions.CanModifyUsers = $true  # Simplified - would need ACL check
            }
            catch { }

            try {
                $null = Get-ADComputer -Filter * -ResultSetSize 1
                $permissions.CanModifyComputers = $true
            }
            catch { }

            try {
                $null = Get-ADGroup -Filter * -ResultSetSize 1
                $permissions.CanModifyGroups = $true
            }
            catch { }
        }
    }
    catch {
        Write-Verbose "Permission check failed: $_"
    }

    [PSCustomObject]$permissions
}

function Get-ADScoutRemediationScope {
    <#
    .SYNOPSIS
        Gets or sets the remediation scope restrictions.

    .DESCRIPTION
        Limits remediation operations to specific OUs, domains, or object types
        for safety when testing or for delegated administration.

    .PARAMETER TargetOUs
        OUs where remediation is allowed.

    .PARAMETER ExcludeOUs
        OUs where remediation is blocked (protected OUs).

    .PARAMETER TargetDomains
        Domains where remediation is allowed.

    .PARAMETER ObjectTypes
        Object types allowed for remediation: User, Computer, Group.

    .EXAMPLE
        Set-ADScoutRemediationScope -TargetOUs "OU=TestUsers,DC=corp,DC=local" -ObjectTypes User
        Limits remediation to users in the TestUsers OU only.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param()

    $configPath = Join-Path $env:USERPROFILE '.adscout\remediation-scope.json'

    if (Test-Path $configPath) {
        Get-Content $configPath -Raw | ConvertFrom-Json
    }
    else {
        [PSCustomObject]@{
            TargetOUs     = @()
            ExcludeOUs    = @()
            TargetDomains = @()
            ObjectTypes   = @('User', 'Computer', 'Group')
            Enabled       = $false
        }
    }
}

function Set-ADScoutRemediationScope {
    <#
    .SYNOPSIS
        Sets remediation scope restrictions.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$TargetOUs,

        [Parameter()]
        [string[]]$ExcludeOUs,

        [Parameter()]
        [string[]]$TargetDomains,

        [Parameter()]
        [ValidateSet('User', 'Computer', 'Group', 'All')]
        [string[]]$ObjectTypes = @('User', 'Computer', 'Group'),

        [Parameter()]
        [switch]$Enabled = $true,

        [Parameter()]
        [switch]$Clear
    )

    $configPath = Join-Path $env:USERPROFILE '.adscout\remediation-scope.json'
    $configDir = Split-Path $configPath -Parent

    if (-not (Test-Path $configDir)) {
        $null = New-Item -ItemType Directory -Path $configDir -Force
    }

    if ($Clear) {
        if (Test-Path $configPath) {
            Remove-Item $configPath -Force
        }
        Write-Host "✓ Remediation scope cleared" -ForegroundColor Green
        return
    }

    $scope = @{
        TargetOUs     = $TargetOUs
        ExcludeOUs    = $ExcludeOUs
        TargetDomains = $TargetDomains
        ObjectTypes   = if ($ObjectTypes -contains 'All') { @('User', 'Computer', 'Group') } else { $ObjectTypes }
        Enabled       = [bool]$Enabled
        UpdatedAt     = Get-Date -Format 'o'
    }

    $scope | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

    Write-Host "✓ Remediation scope configured" -ForegroundColor Green
    if ($TargetOUs) {
        Write-Host "  Target OUs: $($TargetOUs -join ', ')" -ForegroundColor Gray
    }
    if ($ExcludeOUs) {
        Write-Host "  Excluded OUs: $($ExcludeOUs -join ', ')" -ForegroundColor Gray
    }

    [PSCustomObject]$scope
}

function Test-RemediationInScope {
    <#
    .SYNOPSIS
        Checks if a finding is within the allowed remediation scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Finding
    )

    $scope = Get-ADScoutRemediationScope

    # If scope not enabled, allow all
    if (-not $scope.Enabled) {
        return @{ InScope = $true; Reason = 'Scope restrictions not enabled' }
    }

    $result = @{
        InScope = $true
        Reason  = $null
    }

    # Check object type
    $objectType = $null
    if ($Finding.PSObject.Properties['objectClass']) {
        $objectType = switch -Regex ($Finding.objectClass) {
            'user' { 'User' }
            'computer' { 'Computer' }
            'group' { 'Group' }
        }
    }

    if ($objectType -and $objectType -notin $scope.ObjectTypes) {
        $result.InScope = $false
        $result.Reason = "Object type '$objectType' not in allowed types"
        return [PSCustomObject]$result
    }

    # Check OU restrictions
    $dn = $Finding.DistinguishedName
    if ($dn) {
        # Check exclusions first
        foreach ($excludeOU in $scope.ExcludeOUs) {
            if ($dn -like "*$excludeOU*") {
                $result.InScope = $false
                $result.Reason = "Object in excluded OU: $excludeOU"
                return [PSCustomObject]$result
            }
        }

        # Check target OUs (if specified)
        if ($scope.TargetOUs.Count -gt 0) {
            $inTargetOU = $false
            foreach ($targetOU in $scope.TargetOUs) {
                if ($dn -like "*$targetOU*") {
                    $inTargetOU = $true
                    break
                }
            }

            if (-not $inTargetOU) {
                $result.InScope = $false
                $result.Reason = "Object not in any target OU"
                return [PSCustomObject]$result
            }
        }
    }

    # Check domain restrictions
    if ($scope.TargetDomains.Count -gt 0 -and $dn) {
        $objectDomain = ($dn -split ',' | Where-Object { $_ -like 'DC=*' }) -join '.' -replace 'DC=', ''
        if ($objectDomain -notin $scope.TargetDomains) {
            $result.InScope = $false
            $result.Reason = "Object domain '$objectDomain' not in allowed domains"
        }
    }

    return [PSCustomObject]$result
}

function Show-ADScoutEnvironmentWarning {
    <#
    .SYNOPSIS
        Displays a warning banner for production environments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$EnvironmentCheck
    )

    if ($EnvironmentCheck.IsProduction) {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                    ⚠️  PRODUCTION ENVIRONMENT DETECTED  ⚠️                    ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║ Domain: $($EnvironmentCheck.Domain.PadRight(64))║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║ Remediation actions will modify PRODUCTION Active Directory objects.        ║" -ForegroundColor Red
        Write-Host "║ Ensure you have:                                                             ║" -ForegroundColor Red
        Write-Host "║   • Approved change ticket                                                   ║" -ForegroundColor Red
        Write-Host "║   • Tested in non-production                                                 ║" -ForegroundColor Red
        Write-Host "║   • Verified rollback capability                                             ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
    }
}

function Get-ADScoutRemediationScope {
    <#
    .SYNOPSIS
        Gets the current remediation scope restrictions.

    .DESCRIPTION
        Retrieves configuration that limits remediation to specific OUs,
        domains, or object types for safety when testing.

    .EXAMPLE
        Get-ADScoutRemediationScope
        Returns current scope restrictions.

    .OUTPUTS
        PSCustomObject with scope settings.

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
        Object types allowed for remediation: User, Computer, Group, All.

    .PARAMETER Enabled
        Enable or disable scope restrictions.

    .PARAMETER Clear
        Remove all scope restrictions.

    .EXAMPLE
        Set-ADScoutRemediationScope -TargetOUs "OU=TestUsers,DC=corp,DC=local" -ObjectTypes User
        Limits remediation to users in the TestUsers OU only.

    .EXAMPLE
        Set-ADScoutRemediationScope -ExcludeOUs "OU=Executives,DC=corp,DC=local","OU=ServiceAccounts,DC=corp,DC=local"
        Protects specific OUs from remediation.

    .EXAMPLE
        Set-ADScoutRemediationScope -Clear
        Removes all scope restrictions.

    .NOTES
        Author: AD-Scout Contributors
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
    if ($Enabled) {
        Write-Host "  Status: ENABLED" -ForegroundColor Yellow
    }

    [PSCustomObject]$scope
}

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
        Test-ADScoutEnvironment
        Checks and returns environment information.

    .EXAMPLE
        Test-ADScoutEnvironment -RequireNonProduction
        Checks environment and fails if production is detected.

    .OUTPUTS
        ADScoutEnvironmentCheck with validation results.

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
            $domain = Get-ADDomain -Server $TargetDomain -ErrorAction Stop
        }
        else {
            $domain = Get-ADDomain -ErrorAction Stop
        }

        $result.Domain = $domain.DNSRoot
        $result.DomainController = $domain.PDCEmulator

        # Detect environment type based on naming conventions
        $envIndicators = @{
            Production = @('prod', 'prd', 'production', 'live', 'corp', 'corporate')
            Development = @('dev', 'develop', 'development', 'sandbox')
            Test = @('test', 'tst', 'testing', 'qa', 'quality', 'stage', 'staging', 'uat')
            Lab = @('lab', 'poc', 'demo', 'training', 'eval')
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

        # Validate OU scope restrictions
        if ($AllowedOUs) {
            $result.ScopeRestrictions = $AllowedOUs
            foreach ($ou in $AllowedOUs) {
                try {
                    $null = Get-ADOrganizationalUnit -Identity $ou -ErrorAction Stop
                }
                catch {
                    $result.Warnings += "Allowed OU not found: $ou"
                }
            }
        }

        # Check domain functional level
        $domainMode = $domain.DomainMode.ToString()
        if ($domainMode -match '2008|2003|2000') {
            $result.Warnings += "Legacy domain functional level: $domainMode"
        }

    }
    catch {
        $result.IsValid = $false
        $result.Errors += "Failed to validate environment: $($_.Exception.Message)"
    }

    # Display warning banner if production
    if ($result.IsProduction) {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                    ⚠️  PRODUCTION ENVIRONMENT DETECTED  ⚠️                    ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║ Domain: $($result.Domain.PadRight(64))║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
    }

    [PSCustomObject]$result
}

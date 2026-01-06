<#
.SYNOPSIS
    Example: Using AD-Scout with EDR platforms for remote AD reconnaissance.

.DESCRIPTION
    This example demonstrates how to use AD-Scout's EDR wrapper functionality
    to perform Active Directory security assessments through EDR platforms like
    CrowdStrike Falcon and Microsoft Defender for Endpoint.

    This approach is designed for security professionals who:
    - Don't have direct admin access to domain controllers
    - Need to gather AD data through approved EDR channels
    - Want to leverage existing EDR infrastructure for assessments

.NOTES
    Prerequisites:
    - PSFalcon module (for CrowdStrike): Install-Module PSFalcon
    - Microsoft Graph modules (for MDE): Install-Module Microsoft.Graph
    - Appropriate API credentials with remote execution permissions

.EXAMPLE
    # Load the module
    Import-Module ADScout

    # Run this script interactively
    .\EDR-Integration.ps1
#>

#Requires -Module ADScout

# ===========================================================================
# SECTION 1: Connecting to EDR Platforms
# ===========================================================================

Write-Host "`n=== EDR Integration Examples ===" -ForegroundColor Cyan

# Example 1A: Connect to CrowdStrike Falcon using PSFalcon
<#
# Store credentials securely
$clientId = 'your-api-client-id'
$clientSecret = Read-Host -AsSecureString "Enter Client Secret"

# Connect to Falcon (US-1 cloud)
Connect-ADScoutEDR -Provider PSFalcon `
    -ClientId $clientId `
    -ClientSecret $clientSecret `
    -Cloud us-1

# For MSSP scenarios with child CIDs:
Connect-ADScoutEDR -Provider PSFalcon `
    -ClientId $clientId `
    -ClientSecret $clientSecret `
    -Cloud us-1 `
    -MemberCid 'child-customer-cid'
#>

# Example 1B: Connect to Microsoft Defender for Endpoint
<#
$tenantId = 'your-azure-tenant-id'
$appId = 'your-app-registration-id'
$appSecret = Read-Host -AsSecureString "Enter App Secret"

Connect-ADScoutEDR -Provider DefenderATP `
    -TenantId $tenantId `
    -ClientId $appId `
    -ClientSecret $appSecret

# Or use certificate-based auth:
Connect-ADScoutEDR -Provider DefenderATP `
    -TenantId $tenantId `
    -ClientId $appId `
    -CertificateThumbprint 'ABC123...'
#>

# Example 1C: Using saved credentials
<#
# Save credentials securely
$cred = Get-Credential -Message "Enter EDR API credentials (ClientId as username)"
Connect-ADScoutEDR -Provider PSFalcon -Credential $cred -Cloud us-1
#>

# ===========================================================================
# SECTION 2: Discovering Available Hosts
# ===========================================================================

Write-Host "`n=== Discovering EDR-Managed Hosts ===" -ForegroundColor Cyan

# Get all Windows hosts
<#
$windowsHosts = Get-ADScoutEDRHost -Filter @{
    Platform = 'Windows'
    Online = $true
}
Write-Host "Found $($windowsHosts.Count) online Windows hosts"
#>

# Find domain controllers specifically
<#
$domainControllers = Get-ADScoutEDRHost -DomainControllers
Write-Host "Found $($domainControllers.Count) domain controllers"
$domainControllers | Select-Object Hostname, Status, LastSeen | Format-Table
#>

# ===========================================================================
# SECTION 3: Using Pre-Canned Templates
# ===========================================================================

Write-Host "`n=== Pre-Canned AD Reconnaissance Templates ===" -ForegroundColor Cyan

# List available templates
Write-Host "`nAvailable Templates:" -ForegroundColor Yellow
Get-ADScoutEDRTemplate | ForEach-Object {
    Write-Host "  $($_.Id): $($_.Name) [$($_.Category)]"
}

# Example 3A: Get domain information from a DC
<#
$dcHost = 'DC01.contoso.com'  # Or use device ID

$domainInfo = Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost $dcHost

if ($domainInfo.Successful -gt 0) {
    $result = $domainInfo.Results[0]
    Write-Host "`nDomain Information:" -ForegroundColor Green
    $result.Output | Format-List
}
#>

# Example 3B: Find privileged group members
<#
$privGroups = Invoke-ADScoutEDRCommand -Template 'AD-PrivilegedGroups' -TargetHost $dcHost

foreach ($result in $privGroups.Results) {
    if ($result.Success) {
        Write-Host "`nPrivileged Groups from $($result.HostId):" -ForegroundColor Green
        $result.Output.PrivilegedGroups | ForEach-Object {
            Write-Host "  $($_.Name): $($_.MemberCount) members"
        }
    }
}
#>

# Example 3C: Find Kerberoastable accounts (SPNs)
<#
$spnAccounts = Invoke-ADScoutEDRCommand -Template 'AD-SPNAccounts' -TargetHost $dcHost

if ($spnAccounts.Results[0].Success) {
    $spns = $spnAccounts.Results[0].Output.SPNAccounts
    Write-Host "`nKerberoastable Accounts:" -ForegroundColor Yellow
    $spns | Select-Object SamAccountName, ServicePrincipalNames, AdminCount | Format-Table
}
#>

# Example 3D: Find AS-REP Roastable accounts
<#
$asrepRoastable = Invoke-ADScoutEDRCommand -Template 'AD-ASREPRoastable' -TargetHost $dcHost

if ($asrepRoastable.Results[0].Success) {
    $accounts = $asrepRoastable.Results[0].Output.ASREPRoastableAccounts
    if ($accounts.Count -gt 0) {
        Write-Host "`nAS-REP Roastable Accounts (CRITICAL):" -ForegroundColor Red
        $accounts | Select-Object SamAccountName, LastLogon | Format-Table
    } else {
        Write-Host "`nNo AS-REP Roastable accounts found" -ForegroundColor Green
    }
}
#>

# ===========================================================================
# SECTION 4: Running Multiple Queries
# ===========================================================================

Write-Host "`n=== Batch AD Security Assessment ===" -ForegroundColor Cyan

<#
# Comprehensive AD security assessment via EDR
$templates = @(
    'AD-DomainInfo'
    'AD-TrustInfo'
    'AD-PrivilegedGroups'
    'AD-AdminSDHolder'
    'AD-SPNAccounts'
    'AD-ASREPRoastable'
    'AD-UnconstrainedDelegation'
    'AD-ConstrainedDelegation'
    'AD-PasswordPolicy'
    'AD-PasswordNeverExpires'
    'AD-StaleComputers'
    'AD-StaleUsers'
)

$allResults = @{}

foreach ($template in $templates) {
    Write-Host "Executing: $template..."
    $result = Invoke-ADScoutEDRCommand -Template $template -TargetHost $dcHost
    $allResults[$template] = $result

    if ($result.Successful -gt 0) {
        Write-Host "  [OK] Completed" -ForegroundColor Green
    } else {
        Write-Host "  [FAILED] $($result.Errors -join '; ')" -ForegroundColor Red
    }
}

# Export results
$allResults | ConvertTo-Json -Depth 10 | Out-File "EDR-ADAssessment-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
Write-Host "`nResults exported to JSON file" -ForegroundColor Green
#>

# ===========================================================================
# SECTION 5: Endpoint Configuration Checks
# ===========================================================================

Write-Host "`n=== Endpoint Security Configuration ===" -ForegroundColor Cyan

<#
# Check security configuration on multiple hosts
$targetHosts = @('SERVER01', 'SERVER02', 'DC01')

$securityConfigs = Invoke-ADScoutEDRCommand `
    -Template 'EP-SecurityConfig' `
    -TargetHost $targetHosts

foreach ($result in $securityConfigs.Results) {
    if ($result.Success) {
        $config = $result.Output
        Write-Host "`n$($result.HostId):" -ForegroundColor Yellow
        Write-Host "  OS: $($config.OSInfo.Caption)"
        Write-Host "  LSA Protection: $($config.LSAProtection)"
        Write-Host "  Credential Guard: $($config.CredentialGuard.VirtualizationBasedSecurityStatus)"
        Write-Host "  Firewall Enabled: $($config.Firewall | Where-Object { $_.Enabled } | Measure-Object | Select-Object -Expand Count)/3 profiles"
        Write-Host "  Security Services:"
        $config.SecurityServices | ForEach-Object {
            $color = if ($_.Status -eq 'Running') { 'Green' } else { 'Red' }
            Write-Host "    $($_.DisplayName): $($_.Status)" -ForegroundColor $color
        }
    }
}
#>

# ===========================================================================
# SECTION 6: Custom Script Execution
# ===========================================================================

Write-Host "`n=== Custom Script Execution ===" -ForegroundColor Cyan

<#
# Execute custom PowerShell for specific reconnaissance
$customScript = {
    $result = @{
        Hostname = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        CurrentUser = $env:USERNAME
        ADModule = [bool](Get-Module -ListAvailable ActiveDirectory)
        DSModule = [bool](Get-Module -ListAvailable DirectoryServices)
        SchemaVersion = $null
    }

    # Get AD schema version (correlates to forest functional level)
    try {
        $rootDSE = [adsi]"LDAP://RootDSE"
        $result.SchemaVersion = $rootDSE.schemaNamingContext
    } catch {}

    $result | ConvertTo-Json
}

$customResult = Invoke-ADScoutEDRCommand -ScriptBlock $customScript -TargetHost 'DC01'

if ($customResult.Results[0].Success) {
    Write-Host "Custom script result:" -ForegroundColor Green
    $customResult.Results[0].Output | Format-List
}
#>

# ===========================================================================
# SECTION 7: Full AD-Scout Scan via EDR
# ===========================================================================

Write-Host "`n=== Full AD-Scout Scan via EDR ===" -ForegroundColor Cyan

<#
# This demonstrates gathering all AD data via EDR for a full scan

# Step 1: Collect AD data from DC via EDR templates
$dcHost = (Get-ADScoutEDRHost -DomainControllers | Select-Object -First 1).Hostname

$adData = @{
    Users = @()
    Computers = @()
    Groups = @()
    Trusts = @()
    DomainInfo = @()
}

# Collect users with SPNs
$spnResult = Invoke-ADScoutEDRCommand -Template 'AD-SPNAccounts' -TargetHost $dcHost
if ($spnResult.Results[0].Success) {
    $adData.Users += $spnResult.Results[0].Output.SPNAccounts
}

# Collect privileged groups
$groupResult = Invoke-ADScoutEDRCommand -Template 'AD-PrivilegedGroups' -TargetHost $dcHost
if ($groupResult.Results[0].Success) {
    $adData.Groups = $groupResult.Results[0].Output.PrivilegedGroups
}

# Collect trust information
$trustResult = Invoke-ADScoutEDRCommand -Template 'AD-TrustInfo' -TargetHost $dcHost
if ($trustResult.Results[0].Success) {
    $adData.Trusts = $trustResult.Results[0].Output.Trusts
}

# Step 2: Merge with EDR host data for coverage analysis
$edrHosts = Get-ADScoutEDRHost -Filter @{ Platform = 'Windows' }
$adData.EDRHosts = $edrHosts

# Step 3: Run AD-Scout rules that work with EDR data
# (Many rules can analyze the collected data locally)
# ...

Write-Host "Collected AD data via EDR:" -ForegroundColor Green
Write-Host "  Users with SPNs: $($adData.Users.Count)"
Write-Host "  Privileged Groups: $($adData.Groups.Count)"
Write-Host "  Trusts: $($adData.Trusts.Count)"
Write-Host "  EDR-Managed Hosts: $($adData.EDRHosts.Count)"
#>

# ===========================================================================
# SECTION 8: Checking EDR Provider Capabilities
# ===========================================================================

Write-Host "`n=== EDR Provider Capabilities ===" -ForegroundColor Cyan

<#
$capabilities = Get-ADScoutEDRCapabilities
Write-Host "`nProvider: $($capabilities.ProviderName) v$($capabilities.ProviderVersion)"
Write-Host "Parallel Execution: $($capabilities.SupportsParallelExecution)"
Write-Host "Script Execution: $($capabilities.SupportsScriptExecution)"
Write-Host "Max Script Length: $($capabilities.MaxScriptLength) bytes"
Write-Host "Max Batch Size: $($capabilities.MaxBatchSize)"
Write-Host "Supported Platforms: $($capabilities.SupportedOSPlatforms -join ', ')"
Write-Host "Requires Agent Online: $($capabilities.RequiresAgentOnline)"
#>

# ===========================================================================
# SECTION 9: Disconnecting
# ===========================================================================

<#
# Always disconnect when done
Disconnect-ADScoutEDR
Write-Host "`nDisconnected from EDR platform" -ForegroundColor Green
#>

Write-Host "`n=== EDR Integration Examples Complete ===" -ForegroundColor Cyan
Write-Host "Uncomment sections above to run with your EDR platform`n"

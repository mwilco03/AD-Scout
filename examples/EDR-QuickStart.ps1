<#
.SYNOPSIS
    Quick Start: AD reconnaissance through CrowdStrike Falcon or Microsoft Defender.

.DESCRIPTION
    Minimal example showing how to gather Active Directory security data through
    EDR platforms when you don't have direct access to domain controllers.

.NOTES
    For security professionals without admin access to DCs who need to gather
    AD security data through approved EDR channels.
#>

#Requires -Module ADScout

# =============================================================================
# CrowdStrike Falcon Example (PSFalcon)
# =============================================================================

# Step 1: Install PSFalcon if needed
# Install-Module PSFalcon -Scope CurrentUser

# Step 2: Connect to Falcon
$falconClientId = Read-Host "Enter Falcon API Client ID"
$falconSecret = Read-Host "Enter Falcon API Client Secret" -AsSecureString

Connect-ADScoutEDR -Provider PSFalcon -ClientId $falconClientId -ClientSecret $falconSecret -Cloud us-1

# Step 3: Find a domain controller
$dcs = Get-ADScoutEDRHost -DomainControllers
$targetDC = $dcs | Select-Object -First 1
Write-Host "Using DC: $($targetDC.Hostname)"

# Step 4: Run AD security reconnaissance
$results = @{}

# Domain info
$results['DomainInfo'] = Invoke-ADScoutEDRCommand -Template 'AD-DomainInfo' -TargetHost $targetDC.Hostname

# Kerberoastable accounts
$results['SPNAccounts'] = Invoke-ADScoutEDRCommand -Template 'AD-SPNAccounts' -TargetHost $targetDC.Hostname

# Privileged groups
$results['PrivGroups'] = Invoke-ADScoutEDRCommand -Template 'AD-PrivilegedGroups' -TargetHost $targetDC.Hostname

# AS-REP Roastable
$results['ASREP'] = Invoke-ADScoutEDRCommand -Template 'AD-ASREPRoastable' -TargetHost $targetDC.Hostname

# Step 5: Review findings
foreach ($key in $results.Keys) {
    $r = $results[$key]
    if ($r.Successful -gt 0) {
        Write-Host "`n[$key] Success" -ForegroundColor Green
        $r.Results[0].Output | ConvertTo-Json -Depth 3 | Write-Host
    }
    else {
        Write-Host "`n[$key] Failed: $($r.Errors -join '; ')" -ForegroundColor Red
    }
}

# Step 6: Disconnect
Disconnect-ADScoutEDR

# =============================================================================
# Microsoft Defender for Endpoint Example
# =============================================================================

<#
# Connect to MDE
Connect-ADScoutEDR -Provider DefenderATP `
    -TenantId 'your-tenant-id' `
    -ClientId 'your-app-id' `
    -ClientSecret (ConvertTo-SecureString 'your-secret' -AsPlainText -Force)

# Same workflow as above...
$dcs = Get-ADScoutEDRHost -DomainControllers
$results = Invoke-ADScoutEDRCommand -Template 'AD-PrivilegedGroups' -TargetHost $dcs[0].Hostname

Disconnect-ADScoutEDR
#>

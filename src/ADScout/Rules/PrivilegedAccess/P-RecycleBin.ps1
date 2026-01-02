@{
    Id          = 'P-RecycleBin'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'AD Recycle Bin Not Enabled'
    Description = 'Detects when the Active Directory Recycle Bin feature is not enabled. Without the Recycle Bin, deleted AD objects require authoritative restore from backup, which is time-consuming and risky.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AD Recycle Bin'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#ad_recycle_bin' }
        @{ Title = 'Enable AD Recycle Bin'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/advanced-ad-ds-management-using-active-directory-administrative-center--level-200-#BKMK_EnableRecycleBin' }
        @{ Title = 'PingCastle Rule P-RecycleBin'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1531')    # Account Access Removal
    }

    CIS   = @()  # No direct CIS mapping for AD Recycle Bin
    STIG  = @()  # No direct STIG for Recycle Bin enablement
    ANSSI = @()
    NIST  = @('CP-9', 'CP-10')  # Information System Backup, Recovery

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $recycleBinEnabled = $false

            # Check if AD Recycle Bin is enabled
            if ($Domain.RecycleBinEnabled) {
                $recycleBinEnabled = $Domain.RecycleBinEnabled
            } elseif ($Data.Domain -and $Data.Domain.RecycleBinEnabled) {
                $recycleBinEnabled = $Data.Domain.RecycleBinEnabled
            } else {
                # Check directly via AD Optional Features
                try {
                    $recycleBinDN = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADRootDSE).configurationNamingContext
                    $recycleBinFeature = Get-ADOptionalFeature -Identity $recycleBinDN -ErrorAction SilentlyContinue

                    if ($recycleBinFeature) {
                        $recycleBinEnabled = $recycleBinFeature.EnabledScopes.Count -gt 0
                    }
                } catch {
                    # Try ADSI approach
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $configNC = $rootDSE.configurationNamingContext.ToString()

                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
                        $searcher.Filter = "(cn=Recycle Bin Feature)"
                        $searcher.PropertiesToLoad.Add('msDS-EnabledFeature')

                        $result = $searcher.FindOne()
                        if ($result) {
                            $enabledScopes = $result.Properties['msds-enabledfeature']
                            $recycleBinEnabled = $enabledScopes.Count -gt 0
                        }
                    } catch { }
                }
            }

            if (-not $recycleBinEnabled) {
                # Get forest functional level to check if Recycle Bin can be enabled
                $forestLevel = $null
                try {
                    $forest = Get-ADForest -ErrorAction SilentlyContinue
                    $forestLevel = $forest.ForestMode
                } catch {
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $forestLevel = $rootDSE.forestFunctionality.ToString()
                    } catch { }
                }

                # Recycle Bin requires Windows Server 2008 R2 forest functional level or higher
                $canEnable = $false
                if ($forestLevel -match '2008R2|2012|2016|2019|2022|Windows2008R2|Windows2012|Windows2016' -or [int]$forestLevel -ge 4) {
                    $canEnable = $true
                }

                $findings += [PSCustomObject]@{
                    Feature             = 'AD Recycle Bin'
                    Status              = 'Not Enabled'
                    ForestFunctionalLevel = $forestLevel
                    CanEnable           = $canEnable
                    Severity            = 'Medium'
                    Risk                = 'Deleted objects require authoritative restore from backup'
                    Impact              = 'Accidental deletion is difficult to recover from'
                    Recommendation      = if ($canEnable) { 'Enable AD Recycle Bin' } else { 'Raise forest functional level first' }
                }
            }

            # Also check tombstone lifetime
            try {
                $rootDSE = [ADSI]"LDAP://RootDSE"
                $configNC = $rootDSE.configurationNamingContext.ToString()
                $dsService = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
                $tombstoneLifetime = $dsService.tombstoneLifetime.Value

                if (-not $tombstoneLifetime) {
                    $tombstoneLifetime = 180  # Default
                }

                if ($tombstoneLifetime -lt 180) {
                    $findings += [PSCustomObject]@{
                        Setting             = 'Tombstone Lifetime'
                        CurrentValue        = "$tombstoneLifetime days"
                        RecommendedValue    = '180 days or more'
                        Severity            = 'Low'
                        Risk                = 'Short tombstone lifetime limits recovery window'
                        Impact              = 'Deleted objects may become unrecoverable sooner'
                    }
                }
            } catch { }

        } catch {
            Write-Verbose "P-RecycleBin: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable the Active Directory Recycle Bin feature. This is a one-way, irreversible operation but provides significant benefits for object recovery.'
        Impact      = 'Low - No negative impact. Slightly increases storage due to preserving deleted objects.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# AD Recycle Bin Remediation
#
# Current status:
$($Finding.Findings | ForEach-Object { "# - $($_.Feature): $($_.Status) (Forest Level: $($_.ForestFunctionalLevel))" } | Out-String)

# AD Recycle Bin benefits:
# - Restore deleted objects with all attributes intact
# - No need for authoritative restore from backup
# - Recovery can be done while AD is online
# - Objects retained for tombstone lifetime (default 180 days)

# IMPORTANT: Enabling Recycle Bin is IRREVERSIBLE
# However, there are no negative consequences

# STEP 1: Verify prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check forest functional level
`$forest = Get-ADForest
Write-Host "Forest Mode: `$(`$forest.ForestMode)"
Write-Host "Required: Windows2008R2Forest or higher"

if (`$forest.ForestMode -lt "Windows2008R2Forest") {
    Write-Host "`nERROR: Forest functional level too low" -ForegroundColor Red
    Write-Host "Raise forest functional level first:"
    Write-Host "  Set-ADForestMode -Identity `$(`$forest.Name) -ForestMode Windows2008R2Forest"
    return
}

# Check all DCs are Windows Server 2008 R2 or higher
Write-Host "`nDomain Controllers:"
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem | Format-Table -AutoSize

# STEP 2: Enable AD Recycle Bin
Write-Host "`nEnabling AD Recycle Bin..." -ForegroundColor Yellow

# Get the identity for the enable command
`$partitions = (Get-ADRootDSE).namingContexts
`$configNC = `$partitions | Where-Object { `$_ -match 'Configuration' }

Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target `$forest.Name `
    -Confirm:`$false

Write-Host "AD Recycle Bin enabled successfully!" -ForegroundColor Green

# STEP 3: Verify it's enabled
`$recycleBin = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' }
if (`$recycleBin.EnabledScopes) {
    Write-Host "`nRecycle Bin is now enabled for:"
    `$recycleBin.EnabledScopes | ForEach-Object { Write-Host "  - `$_" }
} else {
    Write-Host "`nWARNING: Recycle Bin may not be enabled" -ForegroundColor Yellow
}

# STEP 4: Test object recovery
Write-Host @"

To test AD Recycle Bin:
1. Create a test user:
   New-ADUser -Name "RecycleBinTest" -SamAccountName "recycleBinTest"

2. Delete the user:
   Remove-ADUser -Identity "recycleBinTest" -Confirm:`$false

3. View deleted objects:
   Get-ADObject -Filter { Name -like "*RecycleBinTest*" } -IncludeDeletedObjects

4. Restore the user:
   Get-ADObject -Filter { Name -like "*RecycleBinTest*" } -IncludeDeletedObjects |
       Restore-ADObject

"@ -ForegroundColor Cyan

# STEP 5: Set tombstone lifetime if needed (default is 180 days)
# Increase if you need longer recovery window:
# Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=com" `
#     -Replace @{tombstoneLifetime=365}

# STEP 6: Recovering deleted objects
Write-Host @"

RECOVERY COMMANDS:

# List all deleted objects:
Get-ADObject -Filter { isDeleted -eq `$true } -IncludeDeletedObjects

# Find specific deleted user:
Get-ADObject -Filter { Name -like "*username*" -and isDeleted -eq `$true } -IncludeDeletedObjects

# Restore a deleted object:
Get-ADObject -Filter { Name -eq "DeletedUser" } -IncludeDeletedObjects | Restore-ADObject

# Restore with new parent (if original OU deleted):
Restore-ADObject -Identity "guid-of-object" -TargetPath "OU=Users,DC=domain,DC=com"

"@ -ForegroundColor Cyan

"@
            return $commands
        }
    }
}

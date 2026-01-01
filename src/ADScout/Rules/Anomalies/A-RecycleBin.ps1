@{
    Id          = 'A-RecycleBin'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Active Directory Recycle Bin Not Enabled'
    Description = 'The Active Directory Recycle Bin feature is not enabled. Without this feature, accidentally deleted AD objects cannot be easily recovered with all their attributes intact, requiring complex authoritative restores from backup.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AD Recycle Bin'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-' }
        @{ Title = 'Enable AD Recycle Bin'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin' }
        @{ Title = 'Object Recovery'; Url = 'https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1485')  # Data Destruction
    }

    CIS   = @('5.29')
    STIG  = @()
    ANSSI = @('vuln3_recycle_bin')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $recycleBinEnabled = $false

            # Check if Recycle Bin feature is enabled
            # It's enabled if the optional feature is listed in msDS-EnabledFeature

            try {
                $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                $featureDN = "CN=Partitions,$configNC"
                $partitions = [ADSI]"LDAP://$featureDN"

                # Check for Recycle Bin feature
                $recycleFeatureGuid = 'Feature-GUID-For-Recycle-Bin'

                # Alternative: Try PowerShell cmdlet
                $optionalFeature = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } -ErrorAction SilentlyContinue

                if ($optionalFeature -and $optionalFeature.EnabledScopes.Count -gt 0) {
                    $recycleBinEnabled = $true
                }
            } catch {
                # Try alternative method
                try {
                    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    $featureScope = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
                    $feature = [ADSI]"LDAP://$featureScope"

                    if ($feature.'msDS-EnabledFeatureBL') {
                        $recycleBinEnabled = $true
                    }
                } catch {
                    $recycleBinEnabled = $false
                }
            }

            if (-not $recycleBinEnabled) {
                # Get forest/domain functional level
                $forestLevel = 'Unknown'
                try {
                    $forestLevel = (Get-ADForest).ForestMode
                } catch { }

                $findings += [PSCustomObject]@{
                    Feature             = 'Active Directory Recycle Bin'
                    Status              = 'Not Enabled'
                    ForestFunctionalLevel = $forestLevel
                    RequiredLevel       = 'Windows Server 2008 R2 or higher'
                    RiskLevel           = 'Medium'
                    Impact              = 'Deleted objects cannot be easily recovered'
                    Consequence         = 'Accidental deletions require complex backup restores'
                    RecoveryWithout     = 'Authoritative restore from backup, manual attribute re-creation'
                }
            }
        } catch {
            $findings += [PSCustomObject]@{
                Feature             = 'Active Directory Recycle Bin'
                Status              = "Unable to determine: $_"
                ForestFunctionalLevel = 'Unknown'
                RequiredLevel       = 'Windows Server 2008 R2 or higher'
                RiskLevel           = 'Unknown'
                Impact              = 'Manual verification required'
                Consequence         = 'Check if Recycle Bin is enabled'
                RecoveryWithout     = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable the Active Directory Recycle Bin feature. This is a one-way operation that cannot be undone, but provides significant protection against accidental deletions.'
        Impact      = 'None - Enabling Recycle Bin has no negative impact and only provides benefits.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable Active Directory Recycle Bin
# Current Status: $($Finding.Findings[0].Status)
# Forest Functional Level: $($Finding.Findings[0].ForestFunctionalLevel)

# PREREQUISITES:
# - Forest functional level must be Windows Server 2008 R2 or higher
# - All DCs must run Windows Server 2008 R2 or higher
# - This is a ONE-WAY operation (cannot be disabled once enabled)
# - Enterprise Admins membership required

# Step 1: Verify forest functional level
Get-ADForest | Select-Object ForestMode

# If forest level is too low, raise it:
# Set-ADForestMode -Identity "domain.com" -ForestMode Windows2008R2Forest
# (Requires all DCs to be 2008 R2+)

# Step 2: Enable Recycle Bin
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target (Get-ADForest).Name `
    -Confirm:`$false

# Step 3: Verify it's enabled
Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } |
    Select-Object Name, EnabledScopes

# USING THE RECYCLE BIN:

# View deleted objects
Get-ADObject -Filter {isDeleted -eq `$true} -IncludeDeletedObjects |
    Select-Object Name, ObjectClass, WhenChanged

# Restore a deleted object
# Restore-ADObject -Identity "CN=DeletedUser\0ADEL:guid,CN=Deleted Objects,DC=domain,DC=com"

# Or find and restore by name
Get-ADObject -Filter {isDeleted -eq `$true -and Name -like "*John*"} -IncludeDeletedObjects |
    Restore-ADObject

# IMPORTANT NOTES:
# - Deleted objects are retained for tombstoneLifetime (default 180 days)
# - Recycle Bin extends this with msDS-deletedObjectLifetime
# - Objects retain all attributes when in Recycle Bin

"@
            return $commands
        }
    }
}

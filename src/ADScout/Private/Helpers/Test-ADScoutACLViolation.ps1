function Test-ADScoutACLViolation {
    <#
    .SYNOPSIS
        Checks an AD object's ACL for dangerous permissions granted to non-privileged principals.

    .DESCRIPTION
        Centralized function to analyze Active Directory object ACLs for security violations.
        Identifies dangerous rights (GenericAll, WriteDACL, WriteOwner, etc.) granted to
        non-privileged accounts. Uses externalized SID data for legitimate principal detection.

    .PARAMETER DistinguishedName
        The distinguished name of the AD object to check.

    .PARAMETER RightsToCheck
        The AD rights to check for. Supports regex patterns.
        Default: 'GenericAll|WriteDACL|WriteOwner|GenericWrite'

    .PARAMETER TargetName
        Friendly name of the target object for reporting.

    .PARAMETER TargetType
        Type of the target object (e.g., 'User', 'Group', 'Computer', 'GPO').

    .PARAMETER AdditionalLegitPrincipals
        Additional principal names to consider legitimate for this specific check.

    .PARAMETER IncludeInherited
        Include inherited ACEs in the results. Default: $true

    .EXAMPLE
        Test-ADScoutACLViolation -DistinguishedName "CN=Domain Admins,CN=Users,DC=contoso,DC=com" `
            -TargetName "Domain Admins" -TargetType "Group" -RightsToCheck "GenericAll"

    .OUTPUTS
        PSCustomObject[] - Array of findings with Principal, Rights, TargetObject, etc.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,

        [Parameter()]
        [string]$RightsToCheck = 'GenericAll|WriteDACL|WriteOwner|GenericWrite',

        [Parameter()]
        [string]$TargetName,

        [Parameter()]
        [string]$TargetType = 'Object',

        [Parameter()]
        [string[]]$AdditionalLegitPrincipals = @(),

        [Parameter()]
        [bool]$IncludeInherited = $true
    )

    begin {
        # Get legitimate principals from externalized data or use fallback
        $legitimatePrincipals = if ($script:ADScoutSidData -and $script:ADScoutSidData.legitimateAdminPrincipals) {
            $script:ADScoutSidData.legitimateAdminPrincipals.names
        }
        else {
            @(
                'Domain Admins'
                'Enterprise Admins'
                'Administrators'
                'SYSTEM'
                'SELF'
                'CREATOR OWNER'
                'Account Operators'
                'Backup Operators'
                'Server Operators'
            )
        }

        # Get legitimate SID patterns from externalized data or use fallback
        $legitimateSIDPatterns = if ($script:ADScoutSidData -and $script:ADScoutSidData.legitimateAdminPrincipals) {
            $script:ADScoutSidData.legitimateAdminPrincipals.sids
        }
        else {
            @(
                'S-1-5-32-544'      # Administrators
                'S-1-5-18'          # SYSTEM
                'S-1-5-10'          # SELF
                'S-1-3-0'           # Creator Owner
                'S-1-5-9'           # Enterprise DCs
            )
        }

        # Domain admin RIDs
        $legitimateDomainRIDs = if ($script:ADScoutSidData -and $script:ADScoutSidData.legitimateAdminPrincipals) {
            $script:ADScoutSidData.legitimateAdminPrincipals.domainRids
        }
        else {
            @('512', '519')  # Domain Admins, Enterprise Admins
        }

        # Merge with additional legitimate principals
        $allLegitPrincipals = $legitimatePrincipals + $AdditionalLegitPrincipals
    }

    process {
        $findings = @()

        try {
            if (-not $DistinguishedName) { return $findings }

            # Get ADSI object and ACL
            $adsiObj = [ADSI]"LDAP://$DistinguishedName"
            $acl = $adsiObj.ObjectSecurity

            if (-not $acl) {
                Write-Verbose "Could not retrieve ACL for: $DistinguishedName"
                return $findings
            }

            # Determine target name if not provided
            if (-not $TargetName) {
                $TargetName = ($DistinguishedName -split ',')[0] -replace '^CN=', ''
            }

            foreach ($ace in $acl.Access) {
                # Skip Deny ACEs
                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Skip if rights don't match
                if ($ace.ActiveDirectoryRights -notmatch $RightsToCheck) { continue }

                # Skip inherited if requested
                if (-not $IncludeInherited -and $ace.IsInherited) { continue }

                $identity = $ace.IdentityReference.Value
                $identitySid = $null

                # Try to get SID for identity
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                    $identitySid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    # Could not translate, will rely on name matching
                }

                # Check if legitimate by name
                $isLegitimate = $false
                foreach ($legit in $allLegitPrincipals) {
                    if ($identity -like "*$legit*") {
                        $isLegitimate = $true
                        break
                    }
                }

                # Check if legitimate by SID pattern
                if (-not $isLegitimate -and $identitySid) {
                    foreach ($sidPattern in $legitimateSIDPatterns) {
                        if ($identitySid -eq $sidPattern -or $identitySid -like "$sidPattern*") {
                            $isLegitimate = $true
                            break
                        }
                    }

                    # Check domain RIDs
                    if (-not $isLegitimate -and $identitySid -match '-(\d+)$') {
                        $rid = $Matches[1]
                        if ($legitimateDomainRIDs -contains $rid) {
                            $isLegitimate = $true
                        }
                    }
                }

                if (-not $isLegitimate) {
                    $matchedRights = ($ace.ActiveDirectoryRights -split ',\s*' |
                        Where-Object { $_ -match $RightsToCheck }) -join ', '

                    $findings += [PSCustomObject]@{
                        TargetObject      = $TargetName
                        TargetType        = $TargetType
                        Principal         = $identity
                        PrincipalSID      = $identitySid
                        Rights            = $matchedRights
                        AllRights         = $ace.ActiveDirectoryRights.ToString()
                        Inherited         = $ace.IsInherited
                        InheritanceFlags  = $ace.InheritanceFlags.ToString()
                        PropagationFlags  = $ace.PropagationFlags.ToString()
                        DistinguishedName = $DistinguishedName
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error checking ACL for $DistinguishedName : $_"
        }

        return $findings
    }
}

function Get-ADScoutLegitimateAdminPrincipals {
    <#
    .SYNOPSIS
        Returns the list of legitimate administrative principals.

    .DESCRIPTION
        Retrieves legitimate admin principal names and SIDs from centralized
        configuration. Used for consistent ACL validation across rules.

    .EXAMPLE
        $legit = Get-ADScoutLegitimateAdminPrincipals
        $legit.Names  # Array of principal names
        $legit.SIDs   # Array of SID patterns

    .OUTPUTS
        PSCustomObject with Names, SIDs, and DomainRIDs properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    if ($script:ADScoutSidData -and $script:ADScoutSidData.legitimateAdminPrincipals) {
        return [PSCustomObject]@{
            Names      = $script:ADScoutSidData.legitimateAdminPrincipals.names
            SIDs       = $script:ADScoutSidData.legitimateAdminPrincipals.sids
            DomainRIDs = $script:ADScoutSidData.legitimateAdminPrincipals.domainRids
        }
    }
    else {
        # Fallback to hardcoded values
        return [PSCustomObject]@{
            Names = @(
                'Domain Admins'
                'Enterprise Admins'
                'Administrators'
                'SYSTEM'
                'SELF'
                'CREATOR OWNER'
                'Account Operators'
                'Backup Operators'
                'Server Operators'
            )
            SIDs = @(
                'S-1-5-32-544'  # Administrators
                'S-1-5-18'      # SYSTEM
                'S-1-5-10'      # SELF
                'S-1-3-0'       # Creator Owner
                'S-1-5-9'       # Enterprise DCs
            )
            DomainRIDs = @('512', '519')
        }
    }
}

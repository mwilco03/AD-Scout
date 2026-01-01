function Get-ADScoutPeerBaseline {
    <#
    .SYNOPSIS
        Groups AD objects by OU for peer-based statistical comparison.

    .DESCRIPTION
        Enables peer-group analysis by grouping users/objects based on their
        OU location. This allows comparing a user to others in the same
        organizational unit rather than the entire domain.

        This is important because IT staff legitimately have more group
        memberships than HR staff - comparing within peer groups reduces
        false positives.

    .PARAMETER Objects
        AD objects (users, computers) with DistinguishedName property.

    .PARAMETER ValueProperty
        Property name or scriptblock to extract the numeric value for analysis.
        Default extracts group membership count from MemberOf.

    .PARAMETER GroupByOU
        Extract OU from DistinguishedName for grouping. Default is $true.

    .PARAMETER OUDepth
        How many OU levels to include in grouping. Default is 1 (immediate OU).
        Use 2+ for more specific grouping (e.g., "IT\Helpdesk" vs just "IT").

    .EXAMPLE
        # Compare users to peers in same OU
        $peerGroups = Get-ADScoutPeerBaseline -Objects $ADData.Users

        # Each group has its own statistics
        $peerGroups | ForEach-Object {
            $_.Statistics  # Mean, StdDev for this OU
            $_.Objects     # Users in this OU
        }

    .EXAMPLE
        # Custom value extraction (logon count instead of group count)
        $peerGroups = Get-ADScoutPeerBaseline -Objects $ADData.Users `
            -ValueProperty { $_.LogonCount }

    .NOTES
        Used for reducing false positives in frequency analysis.
        Admins in IT OU will have higher group counts than users in Sales OU.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Objects,

        [Parameter()]
        [object]$ValueProperty = { @($_.MemberOf).Count },

        [Parameter()]
        [switch]$GroupByOU = $true,

        [Parameter()]
        [int]$OUDepth = 1
    )

    begin {
        $allObjects = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($obj in $Objects) {
            $allObjects.Add($obj)
        }
    }

    end {
        if ($allObjects.Count -eq 0) {
            return @()
        }

        # Extract OU from DistinguishedName
        function Get-OUPath {
            param([string]$DistinguishedName, [int]$Depth)

            if ([string]::IsNullOrEmpty($DistinguishedName)) {
                return "Unknown"
            }

            # Parse DN to extract OU components
            $parts = $DistinguishedName -split ',(?=(?:OU|DC)=)'
            $ouParts = $parts | Where-Object { $_ -match '^OU=' }

            if ($ouParts.Count -eq 0) {
                # User might be in Users container or root
                $dcParts = $parts | Where-Object { $_ -match '^DC=' }
                return ($dcParts -join ',')
            }

            # Take first N OU levels (closest to the object)
            $selectedOUs = $ouParts | Select-Object -First $Depth
            return ($selectedOUs -join ',')
        }

        # Group objects by OU
        $grouped = $allObjects | Group-Object -Property {
            Get-OUPath -DistinguishedName $_.DistinguishedName -Depth $OUDepth
        }

        # Calculate statistics for each group
        $results = foreach ($group in $grouped) {
            # Extract values using the property/scriptblock
            $values = foreach ($obj in $group.Group) {
                if ($ValueProperty -is [scriptblock]) {
                    & $ValueProperty -InputObject $obj
                }
                else {
                    $obj.$ValueProperty
                }
            }

            # Filter out nulls and ensure numeric
            $numericValues = @($values | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })

            $stats = if ($numericValues.Count -gt 0) {
                Get-ADScoutStatistics -Values $numericValues
            }
            else {
                @{ Count = 0; Mean = 0; StdDev = 0; Q1 = 0; Q3 = 0; IQR = 0 }
            }

            [PSCustomObject]@{
                OUPath       = $group.Name
                ObjectCount  = $group.Count
                Statistics   = $stats
                Objects      = $group.Group
                Values       = $numericValues
            }
        }

        return $results
    }
}

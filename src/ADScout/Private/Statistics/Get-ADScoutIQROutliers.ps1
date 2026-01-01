function Get-ADScoutIQROutliers {
    <#
    .SYNOPSIS
        Identifies outliers using the Interquartile Range (IQR) method.

    .DESCRIPTION
        Uses the IQR method to detect outliers, which is more robust than
        Z-scores for skewed distributions (common in AD data like group counts).

        Outlier thresholds:
        - Lower fence: Q1 - (Multiplier * IQR)
        - Upper fence: Q3 + (Multiplier * IQR)

        Standard multipliers:
        - 1.5: Standard outliers
        - 3.0: Extreme outliers only

    .PARAMETER Values
        Array of numeric values to analyze.

    .PARAMETER Multiplier
        IQR multiplier for fence calculation. Default is 1.5.

    .PARAMETER UpperOnly
        Only detect high outliers (above upper fence).
        Useful for "excessive" detections like too many group memberships.

    .PARAMETER IncludeAll
        Return all values with their outlier status, not just outliers.

    .EXAMPLE
        # Find users with excessive group membership
        $outliers = Get-ADScoutIQROutliers -Values $groupCounts -UpperOnly

    .EXAMPLE
        # Use stricter threshold (extreme outliers only)
        $extreme = Get-ADScoutIQROutliers -Values $groupCounts -Multiplier 3.0

    .NOTES
        Preferred over Z-score for group membership analysis where
        distribution is typically right-skewed (many users with few groups,
        few users with many groups).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [double[]]$Values,

        [Parameter()]
        [double]$Multiplier = 1.5,

        [Parameter()]
        [switch]$UpperOnly,

        [Parameter()]
        [switch]$IncludeAll
    )

    begin {
        $allValues = [System.Collections.Generic.List[double]]::new()
    }

    process {
        foreach ($v in $Values) {
            $allValues.Add($v)
        }
    }

    end {
        if ($allValues.Count -lt 4) {
            Write-Verbose "IQR method requires at least 4 values for meaningful quartiles"
            return @()
        }

        # Calculate statistics including quartiles
        $stats = Get-ADScoutStatistics -Values $allValues

        # Calculate fences
        $lowerFence = $stats.Q1 - ($Multiplier * $stats.IQR)
        $upperFence = $stats.Q3 + ($Multiplier * $stats.IQR)

        # Identify outliers
        $results = foreach ($value in $allValues) {
            $isLowerOutlier = $value -lt $lowerFence
            $isUpperOutlier = $value -gt $upperFence

            if ($UpperOnly) {
                $isOutlier = $isUpperOutlier
            }
            else {
                $isOutlier = $isLowerOutlier -or $isUpperOutlier
            }

            # Calculate how far beyond the fence
            $deviation = if ($isUpperOutlier) {
                $value - $upperFence
            }
            elseif ($isLowerOutlier) {
                $lowerFence - $value
            }
            else {
                0
            }

            [PSCustomObject]@{
                Value          = $value
                IsOutlier      = $isOutlier
                IsUpperOutlier = $isUpperOutlier
                IsLowerOutlier = $isLowerOutlier
                LowerFence     = [math]::Round($lowerFence, 4)
                UpperFence     = [math]::Round($upperFence, 4)
                Deviation      = [math]::Round($deviation, 4)
                Q1             = $stats.Q1
                Q3             = $stats.Q3
                IQR            = $stats.IQR
            }
        }

        if ($IncludeAll) {
            return $results
        }
        else {
            return $results | Where-Object { $_.IsOutlier }
        }
    }
}

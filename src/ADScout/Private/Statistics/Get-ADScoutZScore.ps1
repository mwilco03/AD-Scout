function Get-ADScoutZScore {
    <#
    .SYNOPSIS
        Calculates Z-scores for values and identifies outliers.

    .DESCRIPTION
        Computes Z-scores (standard deviations from mean) for each value
        in a dataset. Can return all Z-scores or filter to outliers only.

        Z-score formula: Z = (value - mean) / standard_deviation

        Common thresholds:
        - Z > 2.0: ~95th percentile (warning)
        - Z > 3.0: ~99th percentile (critical)

    .PARAMETER Values
        Array of numeric values to analyze.

    .PARAMETER Threshold
        Z-score threshold for outlier detection. Default is 2.0.
        Only values with |Z| > Threshold are returned when filtering.

    .PARAMETER IncludeAll
        Return all values with their Z-scores, not just outliers.

    .EXAMPLE
        # Get outliers (Z > 2.0)
        $outliers = Get-ADScoutZScore -Values $groupCounts -Threshold 2.0

    .EXAMPLE
        # Get all values with Z-scores
        $all = Get-ADScoutZScore -Values $groupCounts -IncludeAll

    .NOTES
        Used by A-ExcessiveGroupMembership and similar rules.
        For skewed distributions, consider Get-ADScoutIQROutliers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [double[]]$Values,

        [Parameter()]
        [double]$Threshold = 2.0,

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
        if ($allValues.Count -lt 2) {
            Write-Verbose "Z-score requires at least 2 values"
            return @()
        }

        # Calculate statistics
        $stats = Get-ADScoutStatistics -Values $allValues

        # Handle zero standard deviation (all values identical)
        if ($stats.StdDev -eq 0) {
            Write-Verbose "Standard deviation is 0 - all values are identical"
            if ($IncludeAll) {
                return $allValues | ForEach-Object {
                    [PSCustomObject]@{
                        Value     = $_
                        ZScore    = 0
                        IsOutlier = $false
                        Mean      = $stats.Mean
                        StdDev    = $stats.StdDev
                    }
                }
            }
            return @()
        }

        # Calculate Z-scores
        $results = foreach ($value in $allValues) {
            $zscore = ($value - $stats.Mean) / $stats.StdDev
            $isOutlier = [math]::Abs($zscore) -gt $Threshold

            [PSCustomObject]@{
                Value     = $value
                ZScore    = [math]::Round($zscore, 4)
                IsOutlier = $isOutlier
                Mean      = $stats.Mean
                StdDev    = $stats.StdDev
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

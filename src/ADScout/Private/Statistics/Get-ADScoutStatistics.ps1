function Get-ADScoutStatistics {
    <#
    .SYNOPSIS
        Calculates comprehensive statistics for a numeric dataset.

    .DESCRIPTION
        Computes mean, median, standard deviation, quartiles, and IQR
        for use in anomaly detection rules. Returns a hashtable with
        all statistical measures needed for Z-score and IQR analysis.

    .PARAMETER Values
        Array of numeric values to analyze.

    .EXAMPLE
        $groupCounts = $users | ForEach-Object { @($_.MemberOf).Count }
        $stats = Get-ADScoutStatistics -Values $groupCounts

        # Returns: Mean, Median, StdDev, Q1, Q3, IQR, Min, Max, Count

    .NOTES
        Used by Anomaly category rules for frequency analysis.
        See DESIGN_DOCUMENT.md for statistical methodology.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [double[]]$Values
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
        # Handle empty or single-value datasets
        if ($allValues.Count -eq 0) {
            return @{
                Count  = 0
                Mean   = 0
                Median = 0
                StdDev = 0
                Min    = 0
                Max    = 0
                Q1     = 0
                Q3     = 0
                IQR    = 0
            }
        }

        if ($allValues.Count -eq 1) {
            $val = $allValues[0]
            return @{
                Count  = 1
                Mean   = $val
                Median = $val
                StdDev = 0
                Min    = $val
                Max    = $val
                Q1     = $val
                Q3     = $val
                IQR    = 0
            }
        }

        # Sort for percentile calculations
        $sorted = $allValues | Sort-Object
        $count = $sorted.Count

        # Basic statistics
        $sum = ($sorted | Measure-Object -Sum).Sum
        $mean = $sum / $count
        $min = $sorted[0]
        $max = $sorted[$count - 1]

        # Median (Q2)
        if ($count % 2 -eq 0) {
            $median = ($sorted[($count / 2) - 1] + $sorted[$count / 2]) / 2
        }
        else {
            $median = $sorted[[math]::Floor($count / 2)]
        }

        # Standard deviation (population)
        $sumSquaredDiff = 0
        foreach ($v in $sorted) {
            $sumSquaredDiff += [math]::Pow(($v - $mean), 2)
        }
        $variance = $sumSquaredDiff / $count
        $stdDev = [math]::Sqrt($variance)

        # Quartiles using linear interpolation method
        # Q1 = 25th percentile, Q3 = 75th percentile
        $q1Index = 0.25 * ($count - 1)
        $q3Index = 0.75 * ($count - 1)

        $q1Lower = [math]::Floor($q1Index)
        $q1Upper = [math]::Ceiling($q1Index)
        $q1Fraction = $q1Index - $q1Lower

        $q3Lower = [math]::Floor($q3Index)
        $q3Upper = [math]::Ceiling($q3Index)
        $q3Fraction = $q3Index - $q3Lower

        if ($q1Lower -eq $q1Upper) {
            $q1 = $sorted[$q1Lower]
        }
        else {
            $q1 = $sorted[$q1Lower] + $q1Fraction * ($sorted[$q1Upper] - $sorted[$q1Lower])
        }

        if ($q3Lower -eq $q3Upper) {
            $q3 = $sorted[$q3Lower]
        }
        else {
            $q3 = $sorted[$q3Lower] + $q3Fraction * ($sorted[$q3Upper] - $sorted[$q3Lower])
        }

        $iqr = $q3 - $q1

        return @{
            Count  = $count
            Mean   = [math]::Round($mean, 4)
            Median = [math]::Round($median, 4)
            StdDev = [math]::Round($stdDev, 4)
            Min    = $min
            Max    = $max
            Q1     = [math]::Round($q1, 4)
            Q3     = [math]::Round($q3, 4)
            IQR    = [math]::Round($iqr, 4)
        }
    }
}

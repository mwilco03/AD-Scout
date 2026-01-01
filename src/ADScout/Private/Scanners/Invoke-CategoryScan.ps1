function Invoke-CategoryScan {
    <#
    .SYNOPSIS
        Scans a specific category of rules against collected data.

    .DESCRIPTION
        Loads all rules for a given category, collects the necessary data,
        and evaluates each rule in parallel (when available).

    .PARAMETER Category
        The rule category to scan (e.g., 'StaleObjects', 'PrivilegedAccess').

    .PARAMETER CollectedData
        Hashtable of pre-collected AD data keyed by data type.

    .PARAMETER Domain
        The domain being scanned.

    .PARAMETER ThrottleLimit
        Maximum parallel threads for rule evaluation.

    .OUTPUTS
        Array of ADScout.Finding objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [hashtable]$CollectedData,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [int]$ThrottleLimit = 4
    )

    begin {
        Write-ADScoutLog -Message "Starting category scan: $Category" -Level Info
        $findings = [System.Collections.Generic.List[object]]::new()
    }

    process {
        try {
            # Get all rules for this category
            $rules = Get-ADScoutRule -Category $Category

            if (-not $rules -or $rules.Count -eq 0) {
                Write-ADScoutLog -Message "No rules found for category: $Category" -Level Warning
                return @()
            }

            Write-ADScoutLog -Message "Found $($rules.Count) rules in category $Category" -Level Verbose

            # Evaluate each rule
            foreach ($rule in $rules) {
                # Determine which data the rule needs
                $dataType = $rule.DataSource
                $data = $null

                if ($dataType -and $CollectedData.ContainsKey($dataType)) {
                    $data = $CollectedData[$dataType]
                }
                elseif ($CollectedData.ContainsKey('All')) {
                    $data = $CollectedData['All']
                }

                # Evaluate the rule
                $finding = Invoke-RuleEvaluation -Rule $rule -Data $data -Domain $Domain

                if ($null -ne $finding) {
                    $findings.Add($finding)
                }
            }
        }
        catch {
            Write-ADScoutLog -Message "Error in category scan for $Category : $_" -Level Error
            throw
        }
    }

    end {
        Write-ADScoutLog -Message "Category scan complete: $Category - Found $($findings.Count) issues" -Level Info
        return $findings.ToArray()
    }
}

function Export-ADScoutCSVReport {
    <#
    .SYNOPSIS
        Exports AD-Scout results to CSV format.

    .DESCRIPTION
        Generates a flat CSV file for spreadsheet analysis.
        Each row represents one finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Delimiter = ','
    )

    $csvData = @()

    foreach ($result in $Results) {
        if ($result.Findings) {
            foreach ($finding in $result.Findings) {
                # Flatten finding properties
                $findingProperties = @{}
                if ($finding -is [PSCustomObject] -or $finding -is [hashtable]) {
                    $finding.PSObject.Properties | ForEach-Object {
                        $findingProperties[$_.Name] = $_.Value
                    }
                }

                $row = [PSCustomObject]@{
                    RuleId        = $result.RuleId
                    RuleName      = $result.RuleName
                    Category      = $result.Category
                    Score         = $result.Score
                    MaxScore      = $result.MaxScore
                    Description   = $result.Description
                    MITRE         = ($result.MITRE -join ';')
                    CIS           = ($result.CIS -join ';')
                    STIG          = ($result.STIG -join ';')
                    FindingData   = ($finding | ConvertTo-Json -Compress -Depth 3)
                    SamAccountName = $findingProperties.SamAccountName
                    DistinguishedName = $findingProperties.DistinguishedName
                    ExecutedAt    = if ($result.ExecutedAt) { $result.ExecutedAt.ToString('o') } else { $null }
                }

                $csvData += $row
            }
        }
        else {
            # Rule with no specific findings (e.g., threshold-based)
            $row = [PSCustomObject]@{
                RuleId        = $result.RuleId
                RuleName      = $result.RuleName
                Category      = $result.Category
                Score         = $result.Score
                MaxScore      = $result.MaxScore
                Description   = $result.Description
                MITRE         = ($result.MITRE -join ';')
                CIS           = ($result.CIS -join ';')
                STIG          = ($result.STIG -join ';')
                FindingData   = ''
                SamAccountName = ''
                DistinguishedName = ''
                ExecutedAt    = if ($result.ExecutedAt) { $result.ExecutedAt.ToString('o') } else { $null }
            }

            $csvData += $row
        }
    }

    $csvData | Export-Csv -Path $Path -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8

    Write-Verbose "CSV report saved to: $Path ($($csvData.Count) rows)"
}

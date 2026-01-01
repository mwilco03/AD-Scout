function Invoke-RuleEvaluation {
    <#
    .SYNOPSIS
        Evaluates a single rule against collected AD data.

    .DESCRIPTION
        Takes a rule definition and the relevant collected data, executes the
        rule's scriptblock, and returns structured findings.

    .PARAMETER Rule
        The rule hashtable containing Id, Category, Detect scriptblock, etc.

    .PARAMETER Data
        The collected AD data to evaluate against.

    .PARAMETER Domain
        The domain being scanned.

    .OUTPUTS
        PSCustomObject with finding details or $null if no issues found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Data,

        [Parameter()]
        [string]$Domain
    )

    begin {
        Write-ADScoutLog -Message "Evaluating rule: $($Rule.Id)" -Level Verbose
    }

    process {
        try {
            # Skip if no data provided
            if ($null -eq $Data) {
                Write-ADScoutLog -Message "No data provided for rule $($Rule.Id), skipping" -Level Verbose
                return $null
            }

            # Execute the detection scriptblock
            $detectResult = & $Rule.Detect -Data $Data -Domain $Domain

            # Handle different return types
            $findings = @()

            if ($null -eq $detectResult) {
                return $null
            }

            # Normalize to array
            if ($detectResult -isnot [array]) {
                $detectResult = @($detectResult)
            }

            # Calculate score based on scoring type
            $score = Get-RuleScore -Rule $Rule -Findings $detectResult

            # Build finding object
            if ($detectResult.Count -gt 0) {
                $finding = [PSCustomObject]@{
                    PSTypeName    = 'ADScout.Finding'
                    RuleId        = $Rule.Id
                    Category      = $Rule.Category
                    Severity      = $Rule.Severity
                    Title         = $Rule.Title
                    Description   = $Rule.Description
                    Score         = $score
                    MaxScore      = $Rule.Weight
                    AffectedCount = $detectResult.Count
                    Findings      = $detectResult
                    Remediation   = $Rule.Remediation
                    References    = $Rule.References
                    MITRE         = $Rule.MITRE
                    Timestamp     = [datetime]::UtcNow
                    Domain        = $Domain
                }

                return $finding
            }

            return $null
        }
        catch {
            Write-ADScoutLog -Message "Error evaluating rule $($Rule.Id): $_" -Level Error

            # Return error finding
            return [PSCustomObject]@{
                PSTypeName  = 'ADScout.Finding'
                RuleId      = $Rule.Id
                Category    = $Rule.Category
                Severity    = 'Error'
                Title       = "Rule Evaluation Error: $($Rule.Title)"
                Description = "Failed to evaluate rule: $_"
                Score       = 0
                MaxScore    = $Rule.Weight
                Error       = $_.Exception.Message
                Timestamp   = [datetime]::UtcNow
                Domain      = $Domain
            }
        }
    }
}

function Get-RuleScore {
    <#
    .SYNOPSIS
        Calculates the score for a rule based on its scoring type.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Rule,

        [Parameter()]
        [array]$Findings
    )

    $weight = $Rule.Weight
    $count = $Findings.Count
    $scoringType = $Rule.Scoring.Type

    switch ($scoringType) {
        'TriggerOnPresence' {
            # Full score if any finding exists
            if ($count -gt 0) { return $weight } else { return 0 }
        }

        'PerDiscovery' {
            # Score per finding, up to max
            $perItem = $Rule.Scoring.PerItem
            return [Math]::Min($count * $perItem, $weight)
        }

        'TriggerOnThreshold' {
            # Full score only if count exceeds threshold
            $threshold = $Rule.Scoring.Threshold
            if ($count -ge $threshold) { return $weight } else { return 0 }
        }

        'TriggerIfLessThan' {
            # Full score if count is below minimum
            $minimum = $Rule.Scoring.Minimum
            if ($count -lt $minimum) { return $weight } else { return 0 }
        }

        default {
            # Default to presence-based
            if ($count -gt 0) { return $weight } else { return 0 }
        }
    }
}

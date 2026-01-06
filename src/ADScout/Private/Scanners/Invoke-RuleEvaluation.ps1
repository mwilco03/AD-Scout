function Invoke-RuleEvaluation {
    <#
    .SYNOPSIS
        Evaluates a single rule against collected AD data.

    .DESCRIPTION
        Takes a normalized rule definition and the relevant collected data, executes the
        rule's ScriptBlock, and returns structured findings.

        Supports both parameter patterns:
        - Schema A: param([hashtable]$ADData)
        - Schema B: param($Data, $Domain)

    .PARAMETER Rule
        The normalized rule object from Get-ADScoutRule.

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
        $Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        [Alias('Data')]
        $ADData,

        [Parameter()]
        [string]$Domain
    )

    begin {
        Write-ADScoutLog -Message "Evaluating rule: $($Rule.Id)" -Level Verbose
    }

    process {
        try {
            # Skip if no data provided
            if ($null -eq $ADData) {
                Write-ADScoutLog -Message "No data provided for rule $($Rule.Id), skipping" -Level Verbose
                return $null
            }

            # Validate DataSource requirements
            $dataSourceValidation = Test-RuleDataSourceAvailable -Rule $Rule -ADData $ADData
            if (-not $dataSourceValidation.Available) {
                Write-ADScoutLog -Message "Rule $($Rule.Id) skipped: $($dataSourceValidation.Reason)" -Level Verbose
                return $null
            }

            # Check prerequisites if defined
            if ($Rule.Prerequisites) {
                try {
                    # Support both parameter patterns for prerequisites
                    $prereqResult = Invoke-RuleScriptBlock -ScriptBlock $Rule.Prerequisites -ADData $ADData -Domain $Domain
                    if (-not $prereqResult) {
                        Write-ADScoutLog -Message "Prerequisites not met for rule $($Rule.Id), skipping" -Level Verbose
                        return $null
                    }
                }
                catch {
                    Write-ADScoutLog -Message "Prerequisite check failed for rule $($Rule.Id): $_" -Level Verbose
                    return $null
                }
            }

            # Execute the detection scriptblock - support both parameter patterns
            $detectResult = Invoke-RuleScriptBlock -ScriptBlock $Rule.ScriptBlock -ADData $ADData -Domain $Domain

            # Handle different return types
            if ($null -eq $detectResult) {
                return $null
            }

            # Normalize to array
            if ($detectResult -isnot [array]) {
                $detectResult = @($detectResult)
            }

            # Filter out $null entries
            $detectResult = @($detectResult | Where-Object { $null -ne $_ })

            if ($detectResult.Count -eq 0) {
                return $null
            }

            # Calculate score based on scoring type
            $score = Get-RuleScore -Rule $Rule -Findings $detectResult

            # Build finding object
            $finding = [PSCustomObject]@{
                PSTypeName    = 'ADScout.Finding'
                RuleId        = $Rule.Id
                RuleName      = $Rule.Name
                Category      = $Rule.Category
                Severity      = $Rule.Severity
                Description   = $Rule.Description
                Score         = $score
                MaxScore      = $Rule.MaxPoints
                FindingCount  = $detectResult.Count
                Findings      = $detectResult
                Remediation   = $Rule.Remediation
                References    = $Rule.References
                MITRE         = $Rule.MITRE
                CIS           = $Rule.CIS
                STIG          = $Rule.STIG
                TechnicalExplanation = $Rule.TechnicalExplanation
                ExecutedAt    = [datetime]::UtcNow
                Domain        = $Domain
            }

            return $finding
        }
        catch {
            Write-ADScoutLog -Message "Error evaluating rule $($Rule.Id): $_" -Level Error

            # Return error finding
            return [PSCustomObject]@{
                PSTypeName   = 'ADScout.Finding'
                RuleId       = $Rule.Id
                RuleName     = $Rule.Name
                Category     = $Rule.Category
                Severity     = 'Error'
                Description  = "Failed to evaluate rule: $_"
                Score        = 0
                MaxScore     = $Rule.MaxPoints
                FindingCount = 0
                Error        = $_.Exception.Message
                ExecutedAt   = [datetime]::UtcNow
                Domain       = $Domain
            }
        }
    }
}

function Invoke-RuleScriptBlock {
    <#
    .SYNOPSIS
        Invokes a rule scriptblock with proper parameter binding.

    .DESCRIPTION
        Handles both Schema A (param($ADData)) and Schema B (param($Data, $Domain)) patterns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [AllowNull()]
        $ADData,

        [Parameter()]
        [string]$Domain
    )

    # Detect parameter pattern by inspecting the scriptblock's AST
    $paramBlock = $ScriptBlock.Ast.ParamBlock
    $usesSchemaA = $false
    $usesSchemaB = $false

    if ($paramBlock -and $paramBlock.Parameters) {
        $paramNames = $paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }

        if ($paramNames -contains 'ADData') {
            $usesSchemaA = $true
        }
        if ($paramNames -contains 'Data') {
            $usesSchemaB = $true
        }
    }

    # Invoke with appropriate parameters
    if ($usesSchemaA) {
        # Schema A: param([hashtable]$ADData)
        return & $ScriptBlock -ADData $ADData
    }
    elseif ($usesSchemaB) {
        # Schema B: param($Data, $Domain)
        return & $ScriptBlock -Data $ADData -Domain $Domain
    }
    else {
        # Fallback: try positional parameters
        return & $ScriptBlock $ADData $Domain
    }
}

function Test-RuleDataSourceAvailable {
    <#
    .SYNOPSIS
        Validates that required data sources are available for a rule.

    .DESCRIPTION
        Checks the rule's DataSource property against available data in ADData
        and returns whether the rule can be executed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        $ADData
    )

    $result = @{
        Available = $true
        Reason    = $null
    }

    if (-not $Rule.DataSource) {
        return $result
    }

    # Map DataSource values to required ADData keys
    $dataSourceMap = @{
        'Users'              = @{ Key = 'Users'; Check = { $ADData.Users -and $ADData.Users.Count -gt 0 } }
        'Computers'          = @{ Key = 'Computers'; Check = { $ADData.Computers -and $ADData.Computers.Count -gt 0 } }
        'Groups'             = @{ Key = 'Groups'; Check = { $ADData.Groups -and $ADData.Groups.Count -gt 0 } }
        'GPOs'               = @{ Key = 'GPOs'; Check = { $ADData.GPOs -and $ADData.GPOs.Count -gt 0 } }
        'GPO'                = @{ Key = 'GPOs'; Check = { $ADData.GPOs -and $ADData.GPOs.Count -gt 0 } }
        'Trusts'             = @{ Key = 'Trusts'; Check = { $ADData.Trusts } }
        'Certificates'       = @{ Key = 'Certificates'; Check = { $ADData.Certificates } }
        'DomainControllers'  = @{ Key = 'DomainControllers'; Check = { $ADData.DomainControllers -and $ADData.DomainControllers.Count -gt 0 } }
        'Mailboxes'          = @{ Key = 'EmailConnected'; Check = { $ADData.EmailConnected -eq $true } }
        'Email'              = @{ Key = 'EmailConnected'; Check = { $ADData.EmailConnected -eq $true } }
        'EndpointSecurity'   = @{ Key = 'EndpointConnected'; Check = { $ADData.EndpointConnected -eq $true } }
        'Endpoint'           = @{ Key = 'EndpointConnected'; Check = { $ADData.EndpointConnected -eq $true } }
        'EntraID'            = @{ Key = 'EntraConnected'; Check = { $ADData.EntraConnected -eq $true } }
        'Entra'              = @{ Key = 'EntraConnected'; Check = { $ADData.EntraConnected -eq $true } }
        'Domain'             = @{ Key = 'Domain'; Check = { $true } }  # Always available via ADSI
        'AdminSDHolder'      = @{ Key = 'Domain'; Check = { $true } }  # Self-contained rules query directly
        'PKI'                = @{ Key = 'Certificates'; Check = { $true } }  # Self-contained
        'ADCS'               = @{ Key = 'Certificates'; Check = { $true } }  # Self-contained
    }

    # Parse DataSource (can be comma-separated)
    $sources = $Rule.DataSource -split '[,\s]+' | Where-Object { $_ }

    foreach ($source in $sources) {
        $sourceCheck = $dataSourceMap[$source]

        if ($sourceCheck) {
            $checkResult = & $sourceCheck.Check
            if (-not $checkResult) {
                $result.Available = $false
                $result.Reason = "DataSource '$source' not available (requires $($sourceCheck.Key))"
                return $result
            }
        }
        # Unknown DataSource - allow rule to run (might be self-contained)
    }

    return $result
}

function Get-RuleScore {
    <#
    .SYNOPSIS
        Calculates the score for a rule based on its scoring type.

    .DESCRIPTION
        Uses the normalized rule properties (Computation, Points, MaxPoints, Threshold)
        to calculate the appropriate score based on findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule,

        [Parameter()]
        [array]$Findings
    )

    $maxPoints = $Rule.MaxPoints
    $points = $Rule.Points
    $count = $Findings.Count
    $scoringType = $Rule.Computation

    switch ($scoringType) {
        'TriggerOnPresence' {
            # Full score if any finding exists
            if ($count -gt 0) { return $maxPoints } else { return 0 }
        }

        'PerDiscover' {
            # Score per finding, up to max
            return [Math]::Min($count * $points, $maxPoints)
        }

        'TriggerOnThreshold' {
            # Full score only if count exceeds threshold
            $threshold = $Rule.Threshold
            if ($threshold -and $count -ge $threshold) { return $maxPoints } else { return 0 }
        }

        'TriggerIfLessThan' {
            # Full score if count is below minimum
            $threshold = $Rule.Threshold
            if ($threshold -and $count -lt $threshold) { return $maxPoints } else { return 0 }
        }

        default {
            # Default to per-discovery scoring
            return [Math]::Min($count * $points, $maxPoints)
        }
    }
}

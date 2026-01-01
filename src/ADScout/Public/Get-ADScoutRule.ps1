function Get-ADScoutRule {
    <#
    .SYNOPSIS
        Gets available AD-Scout security rules.

    .DESCRIPTION
        Retrieves security rules available for scanning. Rules can be filtered
        by ID, category, or loaded from specific paths.

    .PARAMETER Id
        Filter by specific rule ID(s).

    .PARAMETER Category
        Filter by rule category.

    .PARAMETER Path
        Additional paths to search for rules.

    .EXAMPLE
        Get-ADScoutRule
        Returns all available rules.

    .EXAMPLE
        Get-ADScoutRule -Category StaleObjects
        Returns all rules in the StaleObjects category.

    .EXAMPLE
        Get-ADScoutRule -Id "S-PwdNeverExpires"
        Returns the specific rule by ID.

    .OUTPUTS
        PSCustomObject[]
        Collection of rule definitions.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string[]]$Id,

        [Parameter()]
        [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI')]
        [string[]]$Category,

        [Parameter()]
        [string[]]$Path
    )

    begin {
        Write-Verbose "Getting AD-Scout rules"
        $rules = @()
    }

    process {
        # Get all rule paths
        $rulePaths = Get-ADScoutRulePaths

        if ($Path) {
            $rulePaths += $Path
        }

        # Load rules from all paths
        foreach ($rulePath in $rulePaths) {
            if (-not (Test-Path $rulePath)) {
                Write-Verbose "Rule path not found: $rulePath"
                continue
            }

            $ruleFiles = Get-ChildItem -Path $rulePath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -ne '_RuleTemplate.ps1' }

            foreach ($file in $ruleFiles) {
                try {
                    Write-Verbose "Loading rule from: $($file.FullName)"
                    $rule = . $file.FullName

                    if ($rule -is [hashtable] -and $rule.Id) {
                        # Normalize rule schema - support both Schema A and Schema B
                        # Schema A: Uses ScriptBlock, Name, Computation, Points, MaxPoints
                        # Schema B: Uses Detect, Title, Scoring hashtable, Weight

                        # Normalize Name (Schema A: Name, Schema B: Title)
                        $ruleName = if ($rule.Name) { $rule.Name } else { $rule.Title }

                        # Normalize ScriptBlock (Schema A: ScriptBlock, Schema B: Detect)
                        $ruleScriptBlock = if ($rule.ScriptBlock) { $rule.ScriptBlock } else { $rule.Detect }

                        # Normalize Computation (Schema A: Computation, Schema B: Scoring.Type)
                        $ruleComputation = if ($rule.Computation) {
                            $rule.Computation
                        } elseif ($rule.Scoring -and $rule.Scoring.Type) {
                            # Map Schema B scoring types to Schema A
                            switch ($rule.Scoring.Type) {
                                'PerDiscovery' { 'PerDiscover' }
                                default { $rule.Scoring.Type }
                            }
                        } else {
                            'PerDiscover'
                        }

                        # Normalize Points (Schema A: Points, Schema B: Scoring.PerItem or 1)
                        $rulePoints = if ($rule.Points) {
                            $rule.Points
                        } elseif ($rule.Scoring -and $rule.Scoring.PerItem) {
                            $rule.Scoring.PerItem
                        } else {
                            1
                        }

                        # Normalize MaxPoints (Schema A: MaxPoints, Schema B: Weight)
                        $ruleMaxPoints = if ($rule.MaxPoints) {
                            $rule.MaxPoints
                        } elseif ($rule.Weight) {
                            $rule.Weight
                        } else {
                            100
                        }

                        # Normalize Threshold (Schema A: Threshold, Schema B: Scoring.Threshold or Scoring.Minimum)
                        $ruleThreshold = if ($null -ne $rule.Threshold) {
                            $rule.Threshold
                        } elseif ($rule.Scoring -and $null -ne $rule.Scoring.Threshold) {
                            $rule.Scoring.Threshold
                        } elseif ($rule.Scoring -and $null -ne $rule.Scoring.Minimum) {
                            $rule.Scoring.Minimum
                        } else {
                            $null
                        }

                        # Normalize MITRE (Schema A: array, Schema B: hashtable with Techniques)
                        $ruleMITRE = if ($rule.MITRE -is [array]) {
                            $rule.MITRE
                        } elseif ($rule.MITRE -is [hashtable] -and $rule.MITRE.Techniques) {
                            $rule.MITRE.Techniques
                        } else {
                            @()
                        }

                        # Normalize CIS/STIG/ANSSI (ensure arrays)
                        $ruleCIS = if ($rule.CIS -is [array]) { $rule.CIS } else { @($rule.CIS) | Where-Object { $_ } }
                        $ruleSTIG = if ($rule.STIG -is [array]) { $rule.STIG } else { @($rule.STIG) | Where-Object { $_ } }
                        $ruleANSSI = if ($rule.ANSSI -is [array]) { $rule.ANSSI } else { @($rule.ANSSI) | Where-Object { $_ } }

                        # Normalize Description
                        $ruleDescription = $rule.Description

                        # Normalize Remediation (Schema A: scriptblock, Schema B: hashtable with Script)
                        $ruleRemediation = if ($rule.Remediation -is [scriptblock]) {
                            $rule.Remediation
                        } elseif ($rule.Remediation -is [hashtable] -and $rule.Remediation.Script) {
                            $rule.Remediation.Script
                        } else {
                            $null
                        }

                        # Normalize TechnicalExplanation
                        $ruleTechnicalExplanation = if ($rule.TechnicalExplanation) {
                            $rule.TechnicalExplanation
                        } elseif ($rule.Remediation -is [hashtable] -and $rule.Remediation.Description) {
                            $rule.Remediation.Description
                        } else {
                            $null
                        }

                        # Normalize References (Schema A: array of strings, Schema B: array of hashtables)
                        $ruleReferences = if ($rule.References -and $rule.References[0] -is [hashtable]) {
                            $rule.References | ForEach-Object { $_.Url }
                        } else {
                            $rule.References
                        }

                        # Convert hashtable to PSCustomObject for better display
                        $ruleObject = [PSCustomObject]@{
                            PSTypeName    = 'ADScoutRule'
                            Id            = $rule.Id
                            Name          = $ruleName
                            Category      = $rule.Category
                            Model         = $rule.Model
                            Version       = $rule.Version
                            Computation   = $ruleComputation
                            Points        = $rulePoints
                            MaxPoints     = $ruleMaxPoints
                            Threshold     = $ruleThreshold
                            MITRE         = $ruleMITRE
                            CIS           = $ruleCIS
                            STIG          = $ruleSTIG
                            ANSSI         = $ruleANSSI
                            ScriptBlock   = $ruleScriptBlock
                            DetailProperties = $rule.DetailProperties
                            DetailFormat  = $rule.DetailFormat
                            Remediation   = $ruleRemediation
                            Description   = $ruleDescription
                            TechnicalExplanation = $ruleTechnicalExplanation
                            References    = $ruleReferences
                            Prerequisites = $rule.Prerequisites
                            AppliesTo     = $rule.AppliesTo
                            DataSource    = $rule.DataSource
                            Severity      = $rule.Severity
                            SourceFile    = $file.FullName
                        }

                        $rules += $ruleObject
                    }
                }
                catch {
                    Write-Warning "Failed to load rule from $($file.FullName): $_"
                }
            }
        }
    }

    end {
        # Filter by ID if specified
        if ($Id) {
            $rules = $rules | Where-Object { $_.Id -in $Id }
        }

        # Filter by Category if specified
        if ($Category) {
            $rules = $rules | Where-Object { $_.Category -in $Category }
        }

        # Remove duplicates (later paths override earlier for same ID)
        $uniqueRules = @{}
        foreach ($rule in $rules) {
            $uniqueRules[$rule.Id] = $rule
        }

        Write-Verbose "Returning $($uniqueRules.Count) rules"

        # Return sorted by category then ID
        $uniqueRules.Values | Sort-Object Category, Id
    }
}

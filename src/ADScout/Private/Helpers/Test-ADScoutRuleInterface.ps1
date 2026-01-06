function Test-ADScoutRuleInterface {
    <#
    .SYNOPSIS
        Validates that a rule conforms to the expected interface.

    .DESCRIPTION
        Checks that a rule has required properties and valid parameter signatures.
        Returns validation result with details about any issues found.

    .PARAMETER Rule
        The normalized rule object to validate.

    .OUTPUTS
        Hashtable with Valid (bool), Message (string), and Warnings (array).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule
    )

    $result = @{
        Valid    = $true
        Message  = $null
        Warnings = @()
    }

    # Check required properties
    if (-not $Rule.Id) {
        $result.Valid = $false
        $result.Message = 'Missing required property: Id'
        return $result
    }

    if (-not $Rule.Category) {
        $result.Valid = $false
        $result.Message = 'Missing required property: Category'
        return $result
    }

    if (-not $Rule.ScriptBlock) {
        $result.Valid = $false
        $result.Message = 'Missing required property: ScriptBlock (Detect)'
        return $result
    }

    # Validate ScriptBlock parameter signature
    $paramBlock = $Rule.ScriptBlock.Ast.ParamBlock
    if ($paramBlock -and $paramBlock.Parameters) {
        $paramNames = $paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }

        # Check for supported patterns
        $hasADData = $paramNames -contains 'ADData'
        $hasData = $paramNames -contains 'Data'
        $hasDomain = $paramNames -contains 'Domain'

        if (-not $hasADData -and -not $hasData) {
            $result.Warnings += "Non-standard parameter signature. Expected 'ADData' or 'Data'. Found: $($paramNames -join ', ')"
        }

        # Preferred pattern is Schema A: param($ADData)
        if ($hasData -and -not $hasADData) {
            # Schema B pattern - still supported but not preferred
            # No warning needed as this is valid
        }
    }
    else {
        # No param block - might be okay if rule doesn't need parameters
        $result.Warnings += 'No parameter block defined in ScriptBlock'
    }

    # Validate DataSource if specified
    $validDataSources = @(
        'Users', 'Computers', 'Groups', 'GPOs', 'GPO', 'Trusts',
        'Certificates', 'DomainControllers', 'Mailboxes', 'Email',
        'EndpointSecurity', 'Endpoint', 'EntraID', 'Entra',
        'Domain', 'AdminSDHolder', 'PKI', 'ADCS'
    )

    if ($Rule.DataSource) {
        $sources = $Rule.DataSource -split '[,\s]+' | Where-Object { $_ }
        foreach ($source in $sources) {
            if ($source -notin $validDataSources) {
                $result.Warnings += "Unknown DataSource: '$source'"
            }
        }
    }

    # Validate Severity if specified
    $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info', 'Informational')
    if ($Rule.Severity -and $Rule.Severity -notin $validSeverities) {
        $result.Warnings += "Non-standard Severity: '$($Rule.Severity)'. Expected one of: $($validSeverities -join ', ')"
    }

    # Validate Computation type
    $validComputations = @('TriggerOnPresence', 'PerDiscover', 'PerDiscovery', 'TriggerOnThreshold', 'TriggerIfLessThan')
    if ($Rule.Computation -and $Rule.Computation -notin $validComputations) {
        $result.Warnings += "Unknown Computation type: '$($Rule.Computation)'. Expected one of: $($validComputations -join ', ')"
    }

    # Check for description
    if (-not $Rule.Description) {
        $result.Warnings += 'Missing Description property'
    }

    # Check for MITRE mapping (recommended for security rules)
    if (-not $Rule.MITRE -or $Rule.MITRE.Count -eq 0) {
        # This is just informational, not a warning
    }

    # If there are warnings but rule is still valid, aggregate message
    if ($result.Warnings.Count -gt 0 -and $result.Valid) {
        $result.Message = $result.Warnings -join '; '
    }

    return $result
}

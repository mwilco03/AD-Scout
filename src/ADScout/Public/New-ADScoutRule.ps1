function New-ADScoutRule {
    <#
    .SYNOPSIS
        Creates a new AD-Scout rule from template.

    .DESCRIPTION
        Generates a new rule file based on the AD-Scout rule template.
        The rule can then be customized and added to the scanning process.

    .PARAMETER Name
        The name for the new rule (used in the file name and rule ID).

    .PARAMETER Category
        The category for the rule.

    .PARAMETER Path
        Directory where the rule file will be created.
        Defaults to the module's Rules directory under the specified category.

    .PARAMETER Description
        Brief description of what the rule checks.

    .PARAMETER Force
        Overwrite existing rule file if it exists.

    .EXAMPLE
        New-ADScoutRule -Name "WeakPassword" -Category Anomalies
        Creates a new rule file in the Anomalies category.

    .EXAMPLE
        New-ADScoutRule -Name "CustomCheck" -Category PrivilegedAccounts -Path ./MyRules
        Creates a new rule file in a custom directory.

    .OUTPUTS
        System.IO.FileInfo
        The created rule file.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9-_]*$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Kerberos', 'GPO', 'PKI')]
        [string]$Category,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Description = "Description of what this rule checks.",

        [Parameter()]
        [switch]$Force
    )

    begin {
        # Determine the prefix based on category
        $categoryPrefix = switch ($Category) {
            'Anomalies'          { 'A' }
            'StaleObjects'       { 'S' }
            'PrivilegedAccounts' { 'P' }
            'Trusts'             { 'T' }
            'Kerberos'           { 'K' }
            'GPO'                { 'G' }
            'PKI'                { 'C' }
            default              { 'X' }
        }

        $ruleId = "$categoryPrefix-$Name"

        # Determine output path
        if (-not $Path) {
            $modulePath = Split-Path -Parent $PSScriptRoot
            $Path = Join-Path $modulePath "Rules\$Category"
        }

        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        $fileName = "$ruleId.ps1"
        $filePath = Join-Path $Path $fileName
    }

    process {
        # Check if file exists
        if ((Test-Path $filePath) -and -not $Force) {
            Write-Error "Rule file already exists: $filePath. Use -Force to overwrite."
            return
        }

        # Generate rule content
        $ruleContent = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    Detailed description including security implications.

.NOTES
    Rule ID    : $ruleId
    Category   : $Category
    Author     : [Your Name]
    Version    : 1.0.0
#>

@{
    # === IDENTITY ===
    Id          = "$ruleId"
    Name        = "$Name"
    Category    = "$Category"
    Model       = "SubCategory"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"           # TriggerOnPresence | PerDiscover | TriggerOnThreshold | TriggerIfLessThan
    Points      = 1                        # Points per finding (or total for TriggerOnPresence)
    MaxPoints   = 100                      # Cap for cumulative scoring
    Threshold   = `$null                    # For threshold-based rules

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @()                      # e.g., @("T1078.002", "T1558.003")
    CIS         = @()                      # e.g., @("5.1.2")
    STIG        = @()                      # e.g., @("V-8527")
    ANSSI       = @()                      # e.g., @("R36")

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]`$ADData)

        # Return objects that violate this rule
        # These become the finding details
        `$ADData.Users | Where-Object {
            # Your condition here
            `$false
        } | Select-Object SamAccountName, DistinguishedName
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName")
    DetailFormat     = "{SamAccountName}"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]`$Finding)
        @"

# Remediation for: `$(`$Finding.SamAccountName)
# Add remediation commands here

"@
    }

    # === DOCUMENTATION ===
    Description = "$Description"

    TechnicalExplanation = @"
Detailed technical explanation of:
- Why this is a security issue
- How attackers exploit this
- What the impact could be
"@

    References = @(
        # "https://example.com/reference1"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]`$ADData)
        `$true  # Return `$false to skip this rule
    }

    AppliesTo = @("OnPremises", "Hybrid")  # OnPremises | Hybrid | CloudOnly
}
"@

        if ($PSCmdlet.ShouldProcess($filePath, "Create rule file")) {
            $ruleContent | Out-File -FilePath $filePath -Encoding UTF8 -Force

            Write-Verbose "Created rule file: $filePath"

            Get-Item $filePath
        }
    }
}

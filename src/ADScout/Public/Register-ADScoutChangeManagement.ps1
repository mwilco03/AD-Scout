function Register-ADScoutChangeManagement {
    <#
    .SYNOPSIS
        Registers a change management integration for AD-Scout remediation tracking.

    .DESCRIPTION
        Configures integration with change management systems (JIRA, ServiceNow, etc.)
        to automatically create, update, and link remediation activities to change tickets.
        Supports multiple providers through an extensible adapter pattern.

    .PARAMETER Provider
        The change management provider to configure.
        Currently supported: JIRA
        Planned: ServiceNow, AzureDevOps, Remedy, Custom

    .PARAMETER ServerUrl
        The base URL of the change management server.

    .PARAMETER Credential
        Credentials for authenticating to the change management system.
        For JIRA: Username and API token.

    .PARAMETER ApiToken
        API token for authentication (alternative to full Credential).

    .PARAMETER ProjectKey
        The project key where tickets will be created (e.g., "ITSEC" for JIRA).

    .PARAMETER IssueType
        The type of issue to create. Defaults to "Task" for JIRA.

    .PARAMETER DefaultLabels
        Labels to apply to all created tickets.

    .PARAMETER TestConnection
        Test the connection without saving configuration.

    .EXAMPLE
        Register-ADScoutChangeManagement -Provider JIRA -ServerUrl "https://company.atlassian.net" `
            -ApiToken $token -ProjectKey "ITSEC"
        Configures JIRA integration for the ITSEC project.

    .EXAMPLE
        Register-ADScoutChangeManagement -Provider JIRA -TestConnection
        Tests the existing JIRA configuration.

    .OUTPUTS
        ADScoutChangeManagementConfig
        The registered configuration.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('JIRA', 'ServiceNow', 'AzureDevOps', 'Custom')]
        [string]$Provider,

        [Parameter()]
        [string]$ServerUrl,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$ApiToken,

        [Parameter()]
        [string]$ProjectKey,

        [Parameter()]
        [string]$IssueType = 'Task',

        [Parameter()]
        [string[]]$DefaultLabels = @('ad-scout', 'security-remediation'),

        [Parameter()]
        [hashtable]$CustomFields = @{},

        [Parameter()]
        [switch]$TestConnection
    )

    # Get or create config directory
    $configPath = Join-Path $env:USERPROFILE '.adscout'
    if (-not (Test-Path $configPath)) {
        $null = New-Item -ItemType Directory -Path $configPath -Force
    }

    $configFile = Join-Path $configPath 'change-management.json'

    # Load existing config or create new
    $config = if (Test-Path $configFile) {
        Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        @{ Providers = @{} }
    }

    # Build provider configuration
    $providerConfig = @{
        Provider      = $Provider
        ServerUrl     = $ServerUrl
        ProjectKey    = $ProjectKey
        IssueType     = $IssueType
        DefaultLabels = $DefaultLabels
        CustomFields  = $CustomFields
        ConfiguredAt  = Get-Date -Format 'o'
    }

    # Handle credentials securely
    if ($Credential) {
        $providerConfig.Username = $Credential.UserName
        $providerConfig.ApiToken = $Credential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    }
    elseif ($ApiToken) {
        $providerConfig.ApiToken = $ApiToken | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    }

    # Test connection if requested
    if ($TestConnection) {
        Write-Host "Testing connection to $Provider..." -ForegroundColor Cyan

        $testResult = switch ($Provider) {
            'JIRA' { Test-JiraConnection -Config $providerConfig }
            'ServiceNow' { Test-ServiceNowConnection -Config $providerConfig }
            'AzureDevOps' { Test-AzureDevOpsConnection -Config $providerConfig }
            default { @{ Success = $false; Message = "Provider not implemented: $Provider" } }
        }

        if ($testResult.Success) {
            Write-Host "✓ Connection successful!" -ForegroundColor Green
            Write-Host "  Server: $($testResult.ServerInfo)" -ForegroundColor Gray
        }
        else {
            Write-Host "✗ Connection failed: $($testResult.Message)" -ForegroundColor Red
        }

        return [PSCustomObject]$testResult
    }

    # Save configuration
    $config.Providers[$Provider] = $providerConfig
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8

    Write-Host "✓ $Provider integration configured successfully" -ForegroundColor Green

    [PSCustomObject]@{
        PSTypeName   = 'ADScoutChangeManagementConfig'
        Provider     = $Provider
        ServerUrl    = $ServerUrl
        ProjectKey   = $ProjectKey
        ConfiguredAt = $providerConfig.ConfiguredAt
    }
}

function Get-ADScoutChangeManagement {
    <#
    .SYNOPSIS
        Gets the current change management configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Provider
    )

    $configFile = Join-Path $env:USERPROFILE '.adscout\change-management.json'

    if (-not (Test-Path $configFile)) {
        Write-Warning "No change management configuration found. Use Register-ADScoutChangeManagement to configure."
        return
    }

    $config = Get-Content $configFile -Raw | ConvertFrom-Json

    if ($Provider) {
        $config.Providers.$Provider
    }
    else {
        foreach ($p in $config.Providers.PSObject.Properties) {
            [PSCustomObject]@{
                Provider     = $p.Name
                ServerUrl    = $p.Value.ServerUrl
                ProjectKey   = $p.Value.ProjectKey
                ConfiguredAt = $p.Value.ConfiguredAt
            }
        }
    }
}

function New-ADScoutChangeTicket {
    <#
    .SYNOPSIS
        Creates a change ticket for AD-Scout remediation activities.

    .DESCRIPTION
        Creates a ticket in the configured change management system to track
        remediation activities. Supports JIRA initially with extensibility
        for other providers.

    .PARAMETER Title
        The ticket title/summary.

    .PARAMETER Description
        Detailed description of the remediation.

    .PARAMETER Results
        AD-Scout scan results to include in the ticket.

    .PARAMETER BatchId
        Remediation batch ID to link.

    .PARAMETER Provider
        Which change management provider to use. Defaults to first configured.

    .PARAMETER Priority
        Ticket priority. Maps to provider-specific values.

    .PARAMETER Assignee
        User to assign the ticket to.

    .PARAMETER Labels
        Additional labels for the ticket.

    .EXAMPLE
        $results = Invoke-ADScoutScan -RuleId "S-PwdNeverExpires"
        New-ADScoutChangeTicket -Title "Remediate Password Never Expires" -Results $results

    .EXAMPLE
        New-ADScoutChangeTicket -Title "Security Remediation Batch" -BatchId "abc12345"
        Creates a ticket linked to a specific remediation batch.

    .OUTPUTS
        ADScoutChangeTicket
        The created ticket information including key/ID and URL.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$BatchId,

        [Parameter()]
        [ValidateSet('JIRA', 'ServiceNow', 'AzureDevOps')]
        [string]$Provider,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$Priority = 'Medium',

        [Parameter()]
        [string]$Assignee,

        [Parameter()]
        [string[]]$Labels
    )

    # Get configuration
    $config = Get-ADScoutChangeManagementConfig -Provider $Provider

    if (-not $config) {
        throw "No change management provider configured. Use Register-ADScoutChangeManagement first."
    }

    # Build description from results if provided
    if ($Results -and -not $Description) {
        $Description = Build-TicketDescription -Results $Results -BatchId $BatchId
    }

    # Create ticket based on provider
    $ticket = switch ($config.Provider) {
        'JIRA' {
            New-JiraIssue -Config $config -Title $Title -Description $Description `
                -Priority $Priority -Assignee $Assignee -Labels $Labels
        }
        'ServiceNow' {
            New-ServiceNowIncident -Config $config -Title $Title -Description $Description `
                -Priority $Priority -Assignee $Assignee
        }
        'AzureDevOps' {
            New-AzureDevOpsWorkItem -Config $config -Title $Title -Description $Description `
                -Priority $Priority -Assignee $Assignee -Labels $Labels
        }
        default {
            throw "Provider not implemented: $($config.Provider)"
        }
    }

    Write-Host "✓ Created ticket: $($ticket.Key)" -ForegroundColor Green
    Write-Host "  URL: $($ticket.Url)" -ForegroundColor Gray

    $ticket
}

function Update-ADScoutChangeTicket {
    <#
    .SYNOPSIS
        Updates an existing change ticket with remediation status.

    .DESCRIPTION
        Updates the linked change ticket with current remediation status,
        adding comments or transitioning the ticket based on remediation results.

    .PARAMETER TicketKey
        The ticket key/ID to update.

    .PARAMETER Status
        New status for the ticket.

    .PARAMETER Comment
        Comment to add to the ticket.

    .PARAMETER RemediationResult
        Remediation result object from Invoke-ADScoutRemediation.

    .EXAMPLE
        Update-ADScoutChangeTicket -TicketKey "ITSEC-1234" -Status "InProgress" `
            -Comment "Starting remediation batch abc12345"

    .EXAMPLE
        $result = Invoke-ADScoutRemediation -Results $scanResults -PassThru
        Update-ADScoutChangeTicket -TicketKey "ITSEC-1234" -RemediationResult $result

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TicketKey,

        [Parameter()]
        [ValidateSet('Open', 'InProgress', 'Completed', 'Failed', 'RolledBack')]
        [string]$Status,

        [Parameter()]
        [string]$Comment,

        [Parameter()]
        [PSCustomObject]$RemediationResult,

        [Parameter()]
        [string]$Provider
    )

    $config = Get-ADScoutChangeManagementConfig -Provider $Provider

    if (-not $config) {
        throw "No change management provider configured."
    }

    # Build comment from remediation result if provided
    if ($RemediationResult -and -not $Comment) {
        $Comment = Build-RemediationComment -Result $RemediationResult
    }

    switch ($config.Provider) {
        'JIRA' {
            if ($Comment) {
                Add-JiraComment -Config $config -IssueKey $TicketKey -Comment $Comment
            }
            if ($Status) {
                Set-JiraIssueStatus -Config $config -IssueKey $TicketKey -Status $Status
            }
        }
        'ServiceNow' {
            Update-ServiceNowIncident -Config $config -IncidentId $TicketKey -Status $Status -Comment $Comment
        }
        'AzureDevOps' {
            Update-AzureDevOpsWorkItem -Config $config -WorkItemId $TicketKey -Status $Status -Comment $Comment
        }
    }

    Write-Host "✓ Updated ticket: $TicketKey" -ForegroundColor Green
}

#region Helper Functions

function Get-ADScoutChangeManagementConfig {
    param([string]$Provider)

    $configFile = Join-Path $env:USERPROFILE '.adscout\change-management.json'

    if (-not (Test-Path $configFile)) {
        return $null
    }

    $config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable

    if ($Provider) {
        if ($config.Providers.ContainsKey($Provider)) {
            return $config.Providers[$Provider]
        }
        return $null
    }

    # Return first configured provider
    $firstProvider = $config.Providers.Keys | Select-Object -First 1
    if ($firstProvider) {
        return $config.Providers[$firstProvider]
    }

    return $null
}

function Build-TicketDescription {
    param(
        [PSCustomObject[]]$Results,
        [string]$BatchId
    )

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("h2. AD-Scout Security Remediation")
    $null = $sb.AppendLine("")

    if ($BatchId) {
        $null = $sb.AppendLine("*Batch ID:* $BatchId")
        $null = $sb.AppendLine("")
    }

    $null = $sb.AppendLine("h3. Findings Summary")
    $null = $sb.AppendLine("||Rule||Findings||Score||")

    foreach ($result in $Results) {
        $null = $sb.AppendLine("|$($result.RuleId) - $($result.RuleName)|$($result.FindingCount)|$($result.Score)|")
    }

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("h3. Remediation Steps")
    $null = $sb.AppendLine("# Review findings in AD-Scout report")
    $null = $sb.AppendLine("# Execute remediation with: {{Invoke-ADScoutRemediation -Results \$results -WhatIf}}")
    $null = $sb.AppendLine("# Review WhatIf output")
    $null = $sb.AppendLine("# Execute remediation: {{Invoke-ADScoutRemediation -Results \$results -EnableRollback}}")
    $null = $sb.AppendLine("# Verify changes")
    $null = $sb.AppendLine("# Close ticket")

    return $sb.ToString()
}

function Build-RemediationComment {
    param([PSCustomObject]$Result)

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("h4. Remediation Execution Report")
    $null = $sb.AppendLine("*Batch ID:* $($Result.BatchId)")
    $null = $sb.AppendLine("*Executed:* $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("||Metric||Count||")
    $null = $sb.AppendLine("|Total Findings|$($Result.Summary.TotalFindings)|")
    $null = $sb.AppendLine("|Completed|$($Result.Summary.Completed)|")
    $null = $sb.AppendLine("|Skipped|$($Result.Summary.Skipped)|")
    $null = $sb.AppendLine("|Failed|$($Result.Summary.Failed)|")
    $null = $sb.AppendLine("")

    if ($Result.Summary.Failed -gt 0) {
        $null = $sb.AppendLine("{color:red}*Some remediations failed. Review required.*{color}")
    }
    else {
        $null = $sb.AppendLine("{color:green}*All remediations completed successfully.*{color}")
    }

    if ($Result.RollbackPath) {
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("_Rollback available at: $($Result.RollbackPath)_")
    }

    return $sb.ToString()
}

#endregion

#region JIRA Provider

function Test-JiraConnection {
    param([hashtable]$Config)

    try {
        $apiToken = if ($Config.ApiToken -is [string] -and $Config.ApiToken.Length -gt 100) {
            # Encrypted token - decrypt it
            $secureString = $Config.ApiToken | ConvertTo-SecureString
            [PSCredential]::new('user', $secureString).GetNetworkCredential().Password
        }
        else {
            $Config.ApiToken
        }

        $headers = Get-JiraAuthHeaders -Username $Config.Username -ApiToken $apiToken
        $uri = "$($Config.ServerUrl)/rest/api/3/myself"

        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

        return @{
            Success    = $true
            ServerInfo = "$($Config.ServerUrl) (User: $($response.displayName))"
            User       = $response
        }
    }
    catch {
        return @{
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

function Get-JiraAuthHeaders {
    param(
        [string]$Username,
        [string]$ApiToken
    )

    $pair = "${Username}:${ApiToken}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [Convert]::ToBase64String($bytes)

    @{
        'Authorization' = "Basic $base64"
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }
}

function New-JiraIssue {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Description,
        [string]$Priority,
        [string]$Assignee,
        [string[]]$Labels
    )

    $apiToken = if ($Config.ApiToken -is [string] -and $Config.ApiToken.Length -gt 100) {
        $secureString = $Config.ApiToken | ConvertTo-SecureString
        [PSCredential]::new('user', $secureString).GetNetworkCredential().Password
    }
    else {
        $Config.ApiToken
    }

    $headers = Get-JiraAuthHeaders -Username $Config.Username -ApiToken $apiToken

    # Map priority
    $jiraPriority = switch ($Priority) {
        'Critical' { 'Highest' }
        'High'     { 'High' }
        'Medium'   { 'Medium' }
        'Low'      { 'Low' }
        default    { 'Medium' }
    }

    # Build issue payload
    $allLabels = @($Config.DefaultLabels) + @($Labels) | Where-Object { $_ } | Select-Object -Unique

    $body = @{
        fields = @{
            project   = @{ key = $Config.ProjectKey }
            summary   = $Title
            description = @{
                type    = 'doc'
                version = 1
                content = @(
                    @{
                        type    = 'paragraph'
                        content = @(
                            @{
                                type = 'text'
                                text = $Description
                            }
                        )
                    }
                )
            }
            issuetype = @{ name = $Config.IssueType }
            priority  = @{ name = $jiraPriority }
            labels    = $allLabels
        }
    }

    if ($Assignee) {
        $body.fields.assignee = @{ accountId = $Assignee }
    }

    $uri = "$($Config.ServerUrl)/rest/api/3/issue"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body ($body | ConvertTo-Json -Depth 10)

        [PSCustomObject]@{
            PSTypeName = 'ADScoutChangeTicket'
            Key        = $response.key
            Id         = $response.id
            Url        = "$($Config.ServerUrl)/browse/$($response.key)"
            Provider   = 'JIRA'
            CreatedAt  = Get-Date
        }
    }
    catch {
        throw "Failed to create JIRA issue: $($_.Exception.Message)"
    }
}

function Add-JiraComment {
    param(
        [hashtable]$Config,
        [string]$IssueKey,
        [string]$Comment
    )

    $apiToken = if ($Config.ApiToken -is [string] -and $Config.ApiToken.Length -gt 100) {
        $secureString = $Config.ApiToken | ConvertTo-SecureString
        [PSCredential]::new('user', $secureString).GetNetworkCredential().Password
    }
    else {
        $Config.ApiToken
    }

    $headers = Get-JiraAuthHeaders -Username $Config.Username -ApiToken $apiToken

    $body = @{
        body = @{
            type    = 'doc'
            version = 1
            content = @(
                @{
                    type    = 'paragraph'
                    content = @(
                        @{
                            type = 'text'
                            text = $Comment
                        }
                    )
                }
            )
        }
    }

    $uri = "$($Config.ServerUrl)/rest/api/3/issue/$IssueKey/comment"

    Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body ($body | ConvertTo-Json -Depth 10)
}

function Set-JiraIssueStatus {
    param(
        [hashtable]$Config,
        [string]$IssueKey,
        [string]$Status
    )

    $apiToken = if ($Config.ApiToken -is [string] -and $Config.ApiToken.Length -gt 100) {
        $secureString = $Config.ApiToken | ConvertTo-SecureString
        [PSCredential]::new('user', $secureString).GetNetworkCredential().Password
    }
    else {
        $Config.ApiToken
    }

    $headers = Get-JiraAuthHeaders -Username $Config.Username -ApiToken $apiToken

    # Get available transitions
    $transitionsUri = "$($Config.ServerUrl)/rest/api/3/issue/$IssueKey/transitions"
    $transitions = Invoke-RestMethod -Uri $transitionsUri -Headers $headers -Method Get

    # Map status to transition
    $statusMap = @{
        'Open'       = @('To Do', 'Open', 'Backlog')
        'InProgress' = @('In Progress', 'In Development', 'Started')
        'Completed'  = @('Done', 'Closed', 'Resolved', 'Complete')
        'Failed'     = @('Blocked', 'On Hold')
        'RolledBack' = @('Reopened', 'To Do')
    }

    $targetNames = $statusMap[$Status]
    $transition = $transitions.transitions | Where-Object { $_.name -in $targetNames } | Select-Object -First 1

    if ($transition) {
        $body = @{ transition = @{ id = $transition.id } }
        $uri = "$($Config.ServerUrl)/rest/api/3/issue/$IssueKey/transitions"
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body ($body | ConvertTo-Json)
    }
}

#endregion

#region ServiceNow Provider (Placeholder for future implementation)

function Test-ServiceNowConnection {
    param([hashtable]$Config)

    return @{
        Success = $false
        Message = "ServiceNow integration is planned for a future release."
    }
}

function New-ServiceNowIncident {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Description,
        [string]$Priority,
        [string]$Assignee
    )

    throw "ServiceNow integration is planned for a future release."
}

function Update-ServiceNowIncident {
    param(
        [hashtable]$Config,
        [string]$IncidentId,
        [string]$Status,
        [string]$Comment
    )

    throw "ServiceNow integration is planned for a future release."
}

#endregion

#region Azure DevOps Provider (Placeholder for future implementation)

function Test-AzureDevOpsConnection {
    param([hashtable]$Config)

    return @{
        Success = $false
        Message = "Azure DevOps integration is planned for a future release."
    }
}

function New-AzureDevOpsWorkItem {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Description,
        [string]$Priority,
        [string]$Assignee,
        [string[]]$Labels
    )

    throw "Azure DevOps integration is planned for a future release."
}

function Update-AzureDevOpsWorkItem {
    param(
        [hashtable]$Config,
        [string]$WorkItemId,
        [string]$Status,
        [string]$Comment
    )

    throw "Azure DevOps integration is planned for a future release."
}

#endregion

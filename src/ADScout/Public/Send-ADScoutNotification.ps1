function Register-ADScoutNotification {
    <#
    .SYNOPSIS
        Configures notification channels for AD-Scout remediation events.

    .DESCRIPTION
        Sets up notification destinations for remediation completion, failures,
        and other events. Supports email, Microsoft Teams, Slack, and webhooks.

    .PARAMETER Channel
        Notification channel type: Email, Teams, Slack, Webhook.

    .PARAMETER Name
        Friendly name for this notification configuration.

    .PARAMETER Endpoint
        Channel endpoint (SMTP server, webhook URL, etc.).

    .PARAMETER Credential
        Credentials for authentication (email).

    .PARAMETER Recipients
        Email recipients or channel IDs.

    .PARAMETER Events
        Events to notify on: Completed, Failed, Started, All.

    .PARAMETER MinimumSeverity
        Only notify for remediations at or above this risk level.

    .EXAMPLE
        Register-ADScoutNotification -Channel Email -Name "Security Team" `
            -Endpoint "smtp.company.com" -Recipients "security@company.com"

    .EXAMPLE
        Register-ADScoutNotification -Channel Teams -Name "IT Ops" `
            -Endpoint "https://outlook.office.com/webhook/..."

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Email', 'Teams', 'Slack', 'Webhook')]
        [string]$Channel,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string[]]$Recipients,

        [Parameter()]
        [ValidateSet('Started', 'Completed', 'Failed', 'HighRisk', 'All')]
        [string[]]$Events = @('Completed', 'Failed'),

        [Parameter()]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'Low',

        [Parameter()]
        [switch]$Enabled = $true,

        [Parameter()]
        [switch]$TestNotification
    )

    # Load or create config
    $configPath = Join-Path $env:USERPROFILE '.adscout\notifications.json'
    $configDir = Split-Path $configPath -Parent

    if (-not (Test-Path $configDir)) {
        $null = New-Item -ItemType Directory -Path $configDir -Force
    }

    $config = if (Test-Path $configPath) {
        Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        @{ Channels = @{} }
    }

    # Build channel config
    $channelConfig = @{
        Channel         = $Channel
        Name            = $Name
        Endpoint        = $Endpoint
        Recipients      = $Recipients
        Events          = $Events
        MinimumSeverity = $MinimumSeverity
        Enabled         = [bool]$Enabled
        CreatedAt       = Get-Date -Format 'o'
    }

    if ($Credential) {
        $channelConfig.Username = $Credential.UserName
        $channelConfig.Password = $Credential.GetNetworkCredential().Password |
            ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    }

    # Test notification if requested
    if ($TestNotification) {
        $testResult = Send-ADScoutNotification -ChannelConfig $channelConfig -TestMode
        if (-not $testResult.Success) {
            Write-Error "Test notification failed: $($testResult.Error)"
            return
        }
        Write-Host "✓ Test notification sent successfully" -ForegroundColor Green
    }

    # Save configuration
    $config.Channels[$Name] = $channelConfig
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

    Write-Host "✓ Notification channel '$Name' registered" -ForegroundColor Green

    [PSCustomObject]@{
        Name     = $Name
        Channel  = $Channel
        Endpoint = $Endpoint
        Events   = $Events
        Enabled  = $Enabled
    }
}

function Get-ADScoutNotification {
    <#
    .SYNOPSIS
        Gets configured notification channels.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name
    )

    $configPath = Join-Path $env:USERPROFILE '.adscout\notifications.json'

    if (-not (Test-Path $configPath)) {
        return
    }

    $config = Get-Content $configPath -Raw | ConvertFrom-Json

    if ($Name) {
        $config.Channels.$Name
    }
    else {
        foreach ($channelName in $config.Channels.PSObject.Properties.Name) {
            $ch = $config.Channels.$channelName
            [PSCustomObject]@{
                Name     = $channelName
                Channel  = $ch.Channel
                Endpoint = $ch.Endpoint
                Events   = $ch.Events
                Enabled  = $ch.Enabled
            }
        }
    }
}

function Send-ADScoutNotification {
    <#
    .SYNOPSIS
        Sends a notification about remediation events.

    .DESCRIPTION
        Dispatches notifications to configured channels based on event type
        and severity thresholds.

    .PARAMETER RemediationResult
        Result object from Invoke-ADScoutRemediation -PassThru.

    .PARAMETER Event
        The event type triggering this notification.

    .PARAMETER Message
        Custom message to include.

    .PARAMETER ChannelName
        Specific channel to notify. If not specified, uses all matching channels.

    .EXAMPLE
        Send-ADScoutNotification -RemediationResult $result -Event Completed

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Result')]
        [PSCustomObject]$RemediationResult,

        [Parameter(ParameterSetName = 'Result')]
        [ValidateSet('Started', 'Completed', 'Failed', 'HighRisk')]
        [string]$Event = 'Completed',

        [Parameter(ParameterSetName = 'Custom', Mandatory)]
        [string]$Message,

        [Parameter(ParameterSetName = 'Custom')]
        [string]$Title = 'AD-Scout Notification',

        [Parameter()]
        [string]$ChannelName,

        [Parameter(DontShow)]
        [hashtable]$ChannelConfig,

        [Parameter(DontShow)]
        [switch]$TestMode
    )

    # Test mode - single channel config passed directly
    if ($TestMode -and $ChannelConfig) {
        return Send-ToChannel -Config $ChannelConfig -Title "AD-Scout Test Notification" `
            -Message "This is a test notification from AD-Scout." -Event 'Test'
    }

    # Load notification config
    $configPath = Join-Path $env:USERPROFILE '.adscout\notifications.json'
    if (-not (Test-Path $configPath)) {
        Write-Verbose "No notification channels configured."
        return
    }

    $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable

    # Determine which channels to notify
    $channels = if ($ChannelName) {
        @{ $ChannelName = $config.Channels[$ChannelName] }
    }
    else {
        $config.Channels
    }

    # Build notification content
    if ($RemediationResult) {
        $title = "AD-Scout Remediation $Event"
        $message = Build-RemediationNotificationMessage -Result $RemediationResult -Event $Event
        $severity = if ($RemediationResult.Summary.Failed -gt 0) { 'High' } else { 'Low' }
    }
    else {
        $title = $Title
        $severity = 'Low'
    }

    # Send to matching channels
    $results = @()
    foreach ($chName in $channels.Keys) {
        $ch = $channels[$chName]

        # Skip disabled channels
        if (-not $ch.Enabled) { continue }

        # Check event filter
        if ($Event -and $ch.Events -notcontains 'All' -and $ch.Events -notcontains $Event) {
            continue
        }

        # Check severity threshold
        $severityOrder = @{ 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Critical' = 4 }
        if ($severityOrder[$severity] -lt $severityOrder[$ch.MinimumSeverity]) {
            continue
        }

        $results += Send-ToChannel -Config $ch -Title $title -Message $message -Event $Event
    }

    return $results
}

function Send-ToChannel {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Message,
        [string]$Event
    )

    $result = @{
        Channel = $Config.Name
        Type    = $Config.Channel
        Success = $false
        Error   = $null
    }

    try {
        switch ($Config.Channel) {
            'Email' {
                Send-EmailNotification -Config $Config -Title $Title -Message $Message
            }
            'Teams' {
                Send-TeamsNotification -Config $Config -Title $Title -Message $Message -Event $Event
            }
            'Slack' {
                Send-SlackNotification -Config $Config -Title $Title -Message $Message -Event $Event
            }
            'Webhook' {
                Send-WebhookNotification -Config $Config -Title $Title -Message $Message -Event $Event
            }
        }
        $result.Success = $true
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

function Build-RemediationNotificationMessage {
    param(
        [PSCustomObject]$Result,
        [string]$Event
    )

    $summary = $Result.Summary
    $statusEmoji = switch ($Event) {
        'Started'   { '🚀' }
        'Completed' { '✅' }
        'Failed'    { '❌' }
        'HighRisk'  { '⚠️' }
        default     { 'ℹ️' }
    }

    @"
$statusEmoji AD-Scout Remediation $Event

Batch ID: $($Result.BatchId)
$(if ($summary.ChangeTicket) { "Change Ticket: $($summary.ChangeTicket)" })

Results:
• Total Actions: $($summary.TotalFindings)
• Completed: $($summary.Completed)
• Failed: $($summary.Failed)
• Skipped: $($summary.Skipped)

Duration: $($summary.Duration.ToString('mm\:ss'))
"@
}

function Send-EmailNotification {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Message
    )

    $smtpParams = @{
        SmtpServer = $Config.Endpoint
        From       = if ($Config.From) { $Config.From } else { "adscout@$env:USERDNSDOMAIN" }
        To         = $Config.Recipients
        Subject    = $Title
        Body       = $Message
    }

    if ($Config.Username) {
        $password = $Config.Password | ConvertTo-SecureString
        $credential = [PSCredential]::new($Config.Username, $password)
        $smtpParams.Credential = $credential
    }

    if ($Config.UseSSL) {
        $smtpParams.UseSsl = $true
    }

    if ($Config.Port) {
        $smtpParams.Port = $Config.Port
    }

    Send-MailMessage @smtpParams
}

function Send-TeamsNotification {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Message,
        [string]$Event
    )

    $themeColor = switch ($Event) {
        'Started'   { '0078D4' }  # Blue
        'Completed' { '28A745' }  # Green
        'Failed'    { 'DC3545' }  # Red
        'HighRisk'  { 'FFC107' }  # Yellow
        default     { '6C757D' }  # Gray
    }

    $card = @{
        '@type'      = 'MessageCard'
        '@context'   = 'http://schema.org/extensions'
        themeColor   = $themeColor
        summary      = $Title
        sections     = @(
            @{
                activityTitle = $Title
                text          = $Message -replace "`n", "<br>"
                markdown      = $true
            }
        )
    }

    $body = $card | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri $Config.Endpoint -Method Post -Body $body -ContentType 'application/json'
}

function Send-SlackNotification {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Message,
        [string]$Event
    )

    $color = switch ($Event) {
        'Started'   { '#0078D4' }
        'Completed' { '#28A745' }
        'Failed'    { '#DC3545' }
        'HighRisk'  { '#FFC107' }
        default     { '#6C757D' }
    }

    $payload = @{
        attachments = @(
            @{
                color     = $color
                title     = $Title
                text      = $Message
                footer    = 'AD-Scout'
                ts        = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            }
        )
    }

    if ($Config.Channel) {
        $payload.channel = $Config.Channel
    }

    $body = $payload | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri $Config.Endpoint -Method Post -Body $body -ContentType 'application/json'
}

function Send-WebhookNotification {
    param(
        [hashtable]$Config,
        [string]$Title,
        [string]$Message,
        [string]$Event
    )

    $payload = @{
        title     = $Title
        message   = $Message
        event     = $Event
        timestamp = Get-Date -Format 'o'
        source    = 'AD-Scout'
        hostname  = $env:COMPUTERNAME
    }

    $headers = @{
        'Content-Type' = 'application/json'
    }

    if ($Config.ApiKey) {
        $headers['Authorization'] = "Bearer $($Config.ApiKey)"
    }

    $body = $payload | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri $Config.Endpoint -Method Post -Headers $headers -Body $body
}

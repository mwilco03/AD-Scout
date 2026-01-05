function Get-ADScoutMailboxData {
    <#
    .SYNOPSIS
        Collects mailbox and email security data from Exchange/Microsoft 365.

    .DESCRIPTION
        Retrieves mailbox configurations including forwarding rules, delegations,
        inbox rules, and permissions. Supports both Exchange On-Premises and
        Exchange Online (Microsoft 365).

    .PARAMETER ConnectionType
        Target environment: 'ExchangeOnline' or 'ExchangeOnPremises'.

    .PARAMETER Server
        Exchange server for on-premises connections.

    .PARAMETER Credential
        Credentials for Exchange connections.

    .PARAMETER IncludeInboxRules
        Also collect inbox rules for each mailbox.

    .PARAMETER IncludePermissions
        Also collect mailbox permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('ExchangeOnline', 'ExchangeOnPremises', 'Auto')]
        [string]$ConnectionType = 'Auto',

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$IncludeInboxRules,

        [Parameter()]
        [switch]$IncludePermissions,

        [Parameter()]
        [string[]]$InternalDomains
    )

    # Check cache first
    $cacheKey = "Mailboxes:$ConnectionType`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached mailbox data"
        return $cached
    }

    Write-Verbose "Collecting mailbox data from Exchange"

    $mailboxData = @{
        Mailboxes           = @()
        ForwardingRules     = @()
        InboxRules          = @()
        MailboxPermissions  = @()
        SendAsPermissions   = @()
        SendOnBehalfPermissions = @()
        TransportRules      = @()
        ConnectionType      = $null
        InternalDomains     = $InternalDomains
        CollectionTime      = Get-Date
    }

    # Detect connection type
    if ($ConnectionType -eq 'Auto') {
        if (Get-Command Get-EXOMailbox -ErrorAction SilentlyContinue) {
            $ConnectionType = 'ExchangeOnline'
        }
        elseif (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) {
            $ConnectionType = 'ExchangeOnPremises'
        }
        else {
            Write-Warning "No Exchange cmdlets available. Please connect to Exchange first."
            Write-Warning "For Exchange Online: Connect-ExchangeOnline"
            Write-Warning "For On-Premises: Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn"
            return $mailboxData
        }
    }

    $mailboxData.ConnectionType = $ConnectionType

    try {
        # Collect mailboxes with forwarding configuration
        Write-Verbose "Collecting mailbox configurations..."

        if ($ConnectionType -eq 'ExchangeOnline') {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties @(
                'ForwardingAddress',
                'ForwardingSmtpAddress',
                'DeliverToMailboxAndForward',
                'RecipientType',
                'RecipientTypeDetails',
                'WhenMailboxCreated',
                'IsMailboxEnabled'
            ) -ErrorAction Stop
        }
        else {
            $params = @{
                ResultSize = 'Unlimited'
            }
            if ($Server) { $params.Server = $Server }

            $mailboxes = Get-Mailbox @params -ErrorAction Stop
        }

        foreach ($mbx in $mailboxes) {
            $mailboxInfo = [PSCustomObject]@{
                Identity                    = $mbx.Identity
                DisplayName                 = $mbx.DisplayName
                PrimarySmtpAddress          = $mbx.PrimarySmtpAddress
                UserPrincipalName           = $mbx.UserPrincipalName
                SamAccountName              = $mbx.SamAccountName
                RecipientType               = $mbx.RecipientType
                RecipientTypeDetails        = $mbx.RecipientTypeDetails
                ForwardingAddress           = $mbx.ForwardingAddress
                ForwardingSmtpAddress       = $mbx.ForwardingSmtpAddress
                DeliverToMailboxAndForward  = $mbx.DeliverToMailboxAndForward
                IsMailboxEnabled            = $mbx.IsMailboxEnabled
                WhenMailboxCreated          = $mbx.WhenMailboxCreated
                DistinguishedName           = $mbx.DistinguishedName
            }

            $mailboxData.Mailboxes += $mailboxInfo

            # Track forwarding separately for easy detection
            if ($mbx.ForwardingAddress -or $mbx.ForwardingSmtpAddress) {
                $forwardTarget = if ($mbx.ForwardingSmtpAddress) {
                    $mbx.ForwardingSmtpAddress.ToString()
                } else {
                    $mbx.ForwardingAddress.ToString()
                }

                # Determine if external
                $isExternal = $true
                if ($InternalDomains) {
                    foreach ($domain in $InternalDomains) {
                        if ($forwardTarget -like "*@$domain") {
                            $isExternal = $false
                            break
                        }
                    }
                }

                $mailboxData.ForwardingRules += [PSCustomObject]@{
                    MailboxIdentity            = $mbx.Identity
                    MailboxAddress             = $mbx.PrimarySmtpAddress
                    DisplayName                = $mbx.DisplayName
                    ForwardingType             = if ($mbx.ForwardingSmtpAddress) { 'SMTP' } else { 'Internal' }
                    ForwardingTarget           = $forwardTarget
                    DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
                    IsExternal                 = $isExternal
                }
            }
        }

        Write-Verbose "Collected $($mailboxData.Mailboxes.Count) mailboxes"

        # Collect inbox rules if requested
        if ($IncludeInboxRules) {
            Write-Verbose "Collecting inbox rules..."

            foreach ($mbx in $mailboxes) {
                try {
                    if ($ConnectionType -eq 'ExchangeOnline') {
                        $rules = Get-InboxRule -Mailbox $mbx.Identity -ErrorAction SilentlyContinue
                    }
                    else {
                        $rules = Get-InboxRule -Mailbox $mbx.Identity -ErrorAction SilentlyContinue
                    }

                    foreach ($rule in $rules) {
                        # Analyze rule for suspicious patterns
                        $isSuspicious = $false
                        $suspiciousReasons = @()

                        # Check for forwarding actions
                        if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                            $isSuspicious = $true
                            $suspiciousReasons += 'ForwardingAction'
                        }

                        # Check for delete actions (hiding evidence)
                        if ($rule.DeleteMessage -or $rule.MoveToFolder -eq 'Deleted Items') {
                            $suspiciousReasons += 'DeleteAction'
                        }

                        # Check for mark as read (stealth)
                        if ($rule.MarkAsRead) {
                            $suspiciousReasons += 'MarkAsRead'
                        }

                        # Check if rule targets all mail
                        if (-not $rule.From -and -not $rule.SubjectContainsWords -and
                            -not $rule.BodyContainsWords -and -not $rule.FromAddressContainsWords) {
                            if ($rule.ForwardTo -or $rule.RedirectTo) {
                                $suspiciousReasons += 'BroadScope'
                                $isSuspicious = $true
                            }
                        }

                        $mailboxData.InboxRules += [PSCustomObject]@{
                            MailboxIdentity          = $mbx.Identity
                            MailboxAddress           = $mbx.PrimarySmtpAddress
                            RuleName                 = $rule.Name
                            RuleIdentity             = $rule.Identity
                            Enabled                  = $rule.Enabled
                            Priority                 = $rule.Priority
                            ForwardTo                = ($rule.ForwardTo -join '; ')
                            ForwardAsAttachmentTo    = ($rule.ForwardAsAttachmentTo -join '; ')
                            RedirectTo               = ($rule.RedirectTo -join '; ')
                            DeleteMessage            = $rule.DeleteMessage
                            MarkAsRead               = $rule.MarkAsRead
                            MoveToFolder             = $rule.MoveToFolder
                            From                     = ($rule.From -join '; ')
                            SubjectContainsWords     = ($rule.SubjectContainsWords -join '; ')
                            IsSuspicious             = $isSuspicious
                            SuspiciousReasons        = ($suspiciousReasons -join '; ')
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve inbox rules for $($mbx.Identity): $_"
                }
            }
            Write-Verbose "Collected $($mailboxData.InboxRules.Count) inbox rules"
        }

        # Collect mailbox permissions if requested
        if ($IncludePermissions) {
            Write-Verbose "Collecting mailbox permissions..."

            foreach ($mbx in $mailboxes) {
                try {
                    # Full Access permissions
                    if ($ConnectionType -eq 'ExchangeOnline') {
                        $permissions = Get-EXOMailboxPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue
                    }
                    else {
                        $permissions = Get-MailboxPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue
                    }

                    foreach ($perm in $permissions) {
                        # Skip self and inherited
                        if ($perm.User -like '*SELF*' -or $perm.IsInherited) { continue }
                        if ($perm.User -like 'NT AUTHORITY\*') { continue }
                        if ($perm.Deny) { continue }

                        if ($perm.AccessRights -contains 'FullAccess') {
                            $mailboxData.MailboxPermissions += [PSCustomObject]@{
                                MailboxIdentity    = $mbx.Identity
                                MailboxAddress     = $mbx.PrimarySmtpAddress
                                DisplayName        = $mbx.DisplayName
                                Trustee            = $perm.User
                                AccessRights       = ($perm.AccessRights -join ', ')
                                IsInherited        = $perm.IsInherited
                                PermissionType     = 'FullAccess'
                            }
                        }
                    }

                    # Send As permissions
                    if ($ConnectionType -eq 'ExchangeOnline') {
                        $sendAs = Get-EXORecipientPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue
                    }
                    else {
                        $sendAs = Get-RecipientPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue
                    }

                    foreach ($sa in $sendAs) {
                        if ($sa.Trustee -like '*SELF*') { continue }
                        if ($sa.AccessRights -contains 'SendAs') {
                            $mailboxData.SendAsPermissions += [PSCustomObject]@{
                                MailboxIdentity    = $mbx.Identity
                                MailboxAddress     = $mbx.PrimarySmtpAddress
                                DisplayName        = $mbx.DisplayName
                                Trustee            = $sa.Trustee
                                AccessControlType  = $sa.AccessControlType
                                PermissionType     = 'SendAs'
                            }
                        }
                    }

                    # Send on Behalf
                    if ($mbx.GrantSendOnBehalfTo) {
                        foreach ($delegate in $mbx.GrantSendOnBehalfTo) {
                            $mailboxData.SendOnBehalfPermissions += [PSCustomObject]@{
                                MailboxIdentity    = $mbx.Identity
                                MailboxAddress     = $mbx.PrimarySmtpAddress
                                DisplayName        = $mbx.DisplayName
                                Delegate           = $delegate
                                PermissionType     = 'SendOnBehalf'
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve permissions for $($mbx.Identity): $_"
                }
            }
            Write-Verbose "Collected $($mailboxData.MailboxPermissions.Count) full access permissions"
            Write-Verbose "Collected $($mailboxData.SendAsPermissions.Count) send-as permissions"
            Write-Verbose "Collected $($mailboxData.SendOnBehalfPermissions.Count) send-on-behalf permissions"
        }

        # Collect transport rules (organization-wide)
        Write-Verbose "Collecting transport rules..."
        try {
            $transportRules = Get-TransportRule -ErrorAction SilentlyContinue

            foreach ($rule in $transportRules) {
                $isSuspicious = $false
                $suspiciousReasons = @()

                # Check for concerning actions
                if ($rule.BlindCopyTo) {
                    $isSuspicious = $true
                    $suspiciousReasons += 'BlindCopyToExternal'
                }
                if ($rule.RedirectMessageTo) {
                    $isSuspicious = $true
                    $suspiciousReasons += 'RedirectMessage'
                }
                if ($rule.SetSCL -eq -1) {
                    $isSuspicious = $true
                    $suspiciousReasons += 'BypassSpamFilter'
                }
                if ($rule.SetHeaderName -or $rule.RemoveHeader) {
                    $suspiciousReasons += 'HeaderManipulation'
                }

                $mailboxData.TransportRules += [PSCustomObject]@{
                    Name                    = $rule.Name
                    Identity                = $rule.Identity
                    State                   = $rule.State
                    Priority                = $rule.Priority
                    From                    = $rule.From
                    SentTo                  = $rule.SentTo
                    BlindCopyTo             = ($rule.BlindCopyTo -join '; ')
                    RedirectMessageTo       = ($rule.RedirectMessageTo -join '; ')
                    SetSCL                  = $rule.SetSCL
                    DeleteMessage           = $rule.DeleteMessage
                    RejectMessageReasonText = $rule.RejectMessageReasonText
                    IsSuspicious            = $isSuspicious
                    SuspiciousReasons       = ($suspiciousReasons -join '; ')
                    WhenChanged             = $rule.WhenChanged
                }
            }
            Write-Verbose "Collected $($mailboxData.TransportRules.Count) transport rules"
        }
        catch {
            Write-Verbose "Could not retrieve transport rules: $_"
        }
    }
    catch {
        Write-Error "Failed to collect mailbox data: $_"
    }

    # Cache the results
    Set-ADScoutCache -Key $cacheKey -Value $mailboxData

    return $mailboxData
}

function Get-ADScoutMailFlowConfig {
    <#
    .SYNOPSIS
        Collects mail flow and connector configuration.

    .DESCRIPTION
        Retrieves inbound/outbound connectors, accepted domains, and
        remote domains configuration for security analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('ExchangeOnline', 'ExchangeOnPremises', 'Auto')]
        [string]$ConnectionType = 'Auto'
    )

    $mailFlowData = @{
        AcceptedDomains    = @()
        RemoteDomains      = @()
        InboundConnectors  = @()
        OutboundConnectors = @()
        SendConnectors     = @()
        ReceiveConnectors  = @()
    }

    try {
        # Accepted Domains
        $mailFlowData.AcceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.Name
                DomainName  = $_.DomainName
                DomainType  = $_.DomainType
                Default     = $_.Default
            }
        }

        # Remote Domains
        $mailFlowData.RemoteDomains = Get-RemoteDomain -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name                        = $_.Name
                DomainName                  = $_.DomainName
                AutoForwardEnabled          = $_.AutoForwardEnabled
                AllowedOOFType              = $_.AllowedOOFType
                TNEFEnabled                 = $_.TNEFEnabled
                DeliveryReportEnabled       = $_.DeliveryReportEnabled
                NDREnabled                  = $_.NDREnabled
            }
        }

        # Connectors (Exchange Online)
        if (Get-Command Get-InboundConnector -ErrorAction SilentlyContinue) {
            $mailFlowData.InboundConnectors = Get-InboundConnector -ErrorAction SilentlyContinue
            $mailFlowData.OutboundConnectors = Get-OutboundConnector -ErrorAction SilentlyContinue
        }

        # Connectors (On-Premises)
        if (Get-Command Get-SendConnector -ErrorAction SilentlyContinue) {
            $mailFlowData.SendConnectors = Get-SendConnector -ErrorAction SilentlyContinue
            $mailFlowData.ReceiveConnectors = Get-ReceiveConnector -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Verbose "Error collecting mail flow config: $_"
    }

    return $mailFlowData
}

function Get-ADScoutMobileDevices {
    <#
    .SYNOPSIS
        Collects mobile device and ActiveSync configurations.

    .DESCRIPTION
        Retrieves mobile device statistics and policies for security analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Mailboxes
    )

    $devices = @()

    try {
        if ($Mailboxes) {
            foreach ($mbx in $Mailboxes) {
                $stats = Get-MobileDeviceStatistics -Mailbox $mbx -ErrorAction SilentlyContinue
                foreach ($device in $stats) {
                    $devices += [PSCustomObject]@{
                        Mailbox          = $mbx
                        DeviceType       = $device.DeviceType
                        DeviceModel      = $device.DeviceModel
                        DeviceOS         = $device.DeviceOS
                        DeviceAccessState = $device.DeviceAccessState
                        LastSyncTime     = $device.LastSuccessSync
                        FirstSyncTime    = $device.FirstSyncTime
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Error collecting mobile devices: $_"
    }

    return $devices
}

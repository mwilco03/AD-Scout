function Get-ADScoutEndpointData {
    <#
    .SYNOPSIS
        Collects endpoint security configuration data from target computers.

    .DESCRIPTION
        Retrieves security configuration data from endpoints using EDR providers
        (PSRemoting, CrowdStrike Falcon, Microsoft Defender ATP) or direct
        PowerShell Remoting. Collects credential protection, Defender status,
        UAC configuration, local accounts, services, persistence mechanisms,
        and network security settings.

    .PARAMETER ComputerName
        Target computers to collect data from. If not specified, collects from
        domain computers discovered via AD.

    .PARAMETER Credential
        Credentials to use for remote collection.

    .PARAMETER UseEDR
        Use connected EDR provider for collection instead of PSRemoting.

    .PARAMETER SampleSize
        Maximum number of computers to sample. Defaults to 50.

    .PARAMETER IncludeDomainControllers
        Include domain controllers in the collection.

    .EXAMPLE
        Get-ADScoutEndpointData
        Collects endpoint data from a sample of domain computers.

    .EXAMPLE
        Get-ADScoutEndpointData -ComputerName 'WKS01', 'WKS02' -Credential $cred
        Collects from specific computers with credentials.

    .EXAMPLE
        Get-ADScoutEndpointData -UseEDR
        Uses connected EDR provider (CrowdStrike, Defender ATP) for collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$UseEDR,

        [Parameter()]
        [int]$SampleSize = 50,

        [Parameter()]
        [switch]$IncludeDomainControllers
    )

    # Check cache
    $cacheKey = "EndpointData:$($ComputerName -join ','):$SampleSize"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached endpoint data"
        return $cached
    }

    Write-Verbose "Collecting endpoint security configuration data"

    # Initialize result structure
    $result = @{
        CredentialProtection   = @()
        DefenderStatus         = @()
        UACConfiguration       = @()
        LocalAccounts          = @()
        ServiceSecurity        = @()
        PersistenceMechanisms  = @()
        PowerShellSecurity     = @()
        NetworkSecurity        = @()
        AuditPolicy            = @()
        CollectionTime         = Get-Date
        CollectionMethod       = $null
        TargetCount            = 0
        SuccessCount           = 0
        FailedTargets          = @()
    }

    # Determine target computers
    $targets = @()
    if ($ComputerName) {
        $targets = $ComputerName
    }
    else {
        # Get sample of domain computers
        Write-Verbose "Discovering domain computers for sampling..."
        try {
            $adParams = @{
                Filter     = 'OperatingSystem -like "*Windows*" -and Enabled -eq $true'
                Properties = @('OperatingSystem', 'LastLogonDate', 'IPv4Address')
            }

            $computers = Get-ADComputer @adParams -ErrorAction SilentlyContinue |
                Where-Object { $_.LastLogonDate -gt (Get-Date).AddDays(-30) }

            if (-not $IncludeDomainControllers) {
                $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HostName
                $computers = $computers | Where-Object { $_.DNSHostName -notin $dcs }
            }

            $targets = $computers |
                Get-Random -Count ([Math]::Min($SampleSize, $computers.Count)) |
                Select-Object -ExpandProperty DNSHostName
        }
        catch {
            Write-Warning "Failed to discover domain computers: $_"
            return $result
        }
    }

    $result.TargetCount = $targets.Count
    Write-Verbose "Targeting $($targets.Count) computers for endpoint data collection"

    if ($targets.Count -eq 0) {
        Write-Verbose "No targets available for endpoint data collection"
        return $result
    }

    # Check if EDR provider is connected
    $edrProvider = $null
    if ($UseEDR) {
        $edrProvider = Get-ADScoutEDRProvider -ErrorAction SilentlyContinue
    }

    if ($edrProvider) {
        $result.CollectionMethod = "EDR:$($edrProvider.ProviderName)"
        Write-Verbose "Using EDR provider: $($edrProvider.ProviderName)"

        # Use EDR templates for collection
        $templates = @(
            'EP-CredentialProtection',
            'EP-DefenderStatus',
            'EP-UACConfiguration',
            'EP-LocalAccounts',
            'EP-ServiceSecurity',
            'EP-PersistenceMechanisms',
            'EP-PowerShellSecurity',
            'EP-NetworkSecurity',
            'EP-AuditPolicy'
        )

        foreach ($target in $targets) {
            try {
                foreach ($templateId in $templates) {
                    $template = Get-ADScoutEDRTemplate -Name $templateId
                    if ($template) {
                        $cmdResult = Invoke-ADScoutEDRCommand -ComputerName $target -TemplateId $templateId -ErrorAction SilentlyContinue
                        if ($cmdResult) {
                            $data = $cmdResult | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($data) {
                                $category = $templateId -replace '^EP-', ''
                                $result[$category] += $data
                            }
                        }
                    }
                }
                $result.SuccessCount++
            }
            catch {
                Write-Verbose "EDR collection failed for $target : $_"
                $result.FailedTargets += $target
            }
        }
    }
    else {
        # Use PowerShell Remoting
        $result.CollectionMethod = 'PSRemoting'
        Write-Verbose "Using PowerShell Remoting for collection"

        $remoteParams = @{
            ComputerName  = $targets
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'remoteErrors'
        }
        if ($Credential) { $remoteParams['Credential'] = $Credential }

        # Credential Protection collection
        Write-Verbose "Collecting credential protection configuration..."
        $credResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            @{
                Hostname = $env:COMPUTERNAME
                WDigest = @{
                    UseLogonCredential = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA 0).UseLogonCredential
                    Vulnerable = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA 0).UseLogonCredential -eq 1)
                }
                LSAProtection = @{
                    RunAsPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0).RunAsPPL
                    Protected = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0).RunAsPPL -eq 1)
                }
                CredentialGuard = @{
                    VBSRunning = $false
                    CredentialGuardRunning = $false
                }
                CachedLogons = @{
                    CachedLogonsCount = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA 0).CachedLogonsCount
                }
            }
        }
        $result.CredentialProtection = @($credResults | Where-Object { $_ })

        # Defender Status collection
        Write-Verbose "Collecting Defender status..."
        $defenderResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $status = Get-MpComputerStatus -EA 0
            $pref = Get-MpPreference -EA 0
            @{
                Hostname = $env:COMPUTERNAME
                MpComputerStatus = @{
                    RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                    AntivirusEnabled = $status.AntivirusEnabled
                    BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
                    IsTamperProtected = $status.IsTamperProtected
                    DefenderSignaturesOutOfDate = $status.DefenderSignaturesOutOfDate
                }
                MpPreference = @{
                    DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
                    DisableBehaviorMonitoring = $pref.DisableBehaviorMonitoring
                }
                Exclusions = @{
                    ExclusionPath = @($pref.ExclusionPath)
                    ExclusionExtension = @($pref.ExclusionExtension)
                    ExclusionProcess = @($pref.ExclusionProcess)
                    TotalExclusions = @($pref.ExclusionPath).Count + @($pref.ExclusionExtension).Count + @($pref.ExclusionProcess).Count
                }
            }
        }
        $result.DefenderStatus = @($defenderResults | Where-Object { $_ })

        # UAC Configuration collection
        Write-Verbose "Collecting UAC configuration..."
        $uacResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA 0
            $vulns = @()
            if ($uac.EnableLUA -eq 0) { $vulns += @{Setting='EnableLUA';Risk='Critical';Description='UAC disabled'} }
            if ($uac.ConsentPromptBehaviorAdmin -eq 0) { $vulns += @{Setting='ConsentPromptBehaviorAdmin';Risk='High';Description='Admin elevates without prompt'} }
            if ($uac.LocalAccountTokenFilterPolicy -eq 1) { $vulns += @{Setting='LocalAccountTokenFilterPolicy';Risk='High';Description='Remote UAC disabled'} }
            @{
                Hostname = $env:COMPUTERNAME
                UACSettings = @{
                    EnableLUA = $uac.EnableLUA
                    ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
                    LocalAccountTokenFilterPolicy = $uac.LocalAccountTokenFilterPolicy
                    PromptOnSecureDesktop = $uac.PromptOnSecureDesktop
                }
                Vulnerabilities = $vulns
            }
        }
        $result.UACConfiguration = @($uacResults | Where-Object { $_ })

        # Local Accounts collection
        Write-Verbose "Collecting local accounts..."
        $localResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $admins = Get-LocalGroupMember -Group 'Administrators' -EA 0
            @{
                Hostname = $env:COMPUTERNAME
                SecurityGroups = @{
                    Administrators = @{
                        Members = @($admins | ForEach-Object { @{Name=$_.Name;ObjectClass=$_.ObjectClass} })
                        MemberCount = @($admins).Count
                    }
                }
            }
        }
        $result.LocalAccounts = @($localResults | Where-Object { $_ })

        # Service Security collection
        Write-Verbose "Collecting service security..."
        $svcResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $services = Get-CimInstance Win32_Service -EA 0
            $unquoted = @()
            foreach ($svc in $services) {
                if ($svc.PathName -and $svc.PathName -notmatch '^"' -and $svc.PathName -match '\s' -and $svc.PathName -match '\.exe') {
                    $unquoted += @{ServiceName=$svc.Name;DisplayName=$svc.DisplayName;PathName=$svc.PathName;StartName=$svc.StartName;StartMode=$svc.StartMode}
                }
            }
            @{
                Hostname = $env:COMPUTERNAME
                UnquotedPaths = $unquoted
            }
        }
        $result.ServiceSecurity = @($svcResults | Where-Object { $_ })

        # Network Security collection
        Write-Verbose "Collecting network security..."
        $netResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $fw = Get-NetFirewallProfile -EA 0
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA 0
            $smbCfg = Get-SmbServerConfiguration -EA 0
            $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -EA 0
            $nla = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -EA 0
            @{
                Hostname = $env:COMPUTERNAME
                Firewall = @($fw | ForEach-Object { @{Profile=$_.Name;Enabled=$_.Enabled} })
                SMB = @{
                    SMB1Enabled = ($smb1.State -eq 'Enabled')
                    RequireSecuritySignature = $smbCfg.RequireSecuritySignature
                    EncryptData = $smbCfg.EncryptData
                }
                RDP = @{
                    Enabled = ($rdp.fDenyTSConnections -eq 0)
                    NLARequired = ($nla.UserAuthentication -eq 1)
                }
            }
        }
        $result.NetworkSecurity = @($netResults | Where-Object { $_ })

        # PowerShell Security collection
        Write-Verbose "Collecting PowerShell security..."
        $psResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $psLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA 0
            $modLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA 0
            $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA 0
            @{
                Hostname = $env:COMPUTERNAME
                ExecutionPolicy = (Get-ExecutionPolicy -EA 0)
                LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
                Logging = @{
                    ScriptBlockLogging = ($psLog.EnableScriptBlockLogging -eq 1)
                    ModuleLogging = ($modLog.EnableModuleLogging -eq 1)
                }
                V2Enabled = ($psv2.State -eq 'Enabled')
            }
        }
        $result.PowerShellSecurity = @($psResults | Where-Object { $_ })

        # Persistence Mechanisms collection
        Write-Verbose "Collecting persistence mechanisms..."
        $persResults = Invoke-Command @remoteParams -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'
            $runKeys = @()
            $runPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
            foreach ($path in $runPaths) {
                $keys = Get-ItemProperty $path -EA 0
                if ($keys) {
                    $props = $keys.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider') }
                    foreach ($prop in $props) {
                        $runKeys += @{Path=$path;Name=$prop.Name;Value=$prop.Value}
                    }
                }
            }
            $tasks = Get-ScheduledTask -EA 0 | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | Select-Object -First 20
            $schedTasks = @($tasks | ForEach-Object { @{TaskName=$_.TaskName;TaskPath=$_.TaskPath;UserId=$_.Principal.UserId;Actions=@($_.Actions|ForEach-Object{$_.Execute})} })
            @{
                Hostname = $env:COMPUTERNAME
                RunKeys = $runKeys
                ScheduledTasks = $schedTasks
                WMISubscriptions = @()
            }
        }
        $result.PersistenceMechanisms = @($persResults | Where-Object { $_ })

        # Count successes
        $result.SuccessCount = $result.CredentialProtection.Count
        $result.FailedTargets = @($remoteErrors | ForEach-Object { $_.TargetObject } | Select-Object -Unique)
    }

    Write-Verbose "Endpoint collection complete: $($result.SuccessCount)/$($result.TargetCount) successful"

    # Cache results
    Set-ADScoutCache -Key $cacheKey -Value $result -TTL 600

    return $result
}

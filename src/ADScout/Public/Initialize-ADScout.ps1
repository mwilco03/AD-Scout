function Initialize-ADScout {
    <#
    .SYNOPSIS
        Initializes AD-Scout environment with auto-detection and guided setup.

    .DESCRIPTION
        Detects domain environment, available modules, and connectivity.
        Prompts only for values that cannot be auto-detected.
        Stores configuration for subsequent runs.

    .PARAMETER Mode
        Deployment mode: Assessment (one-time), Dashboard (continuous), SIEM (Elasticsearch export).
        If not specified, prompts user to select.

    .PARAMETER Force
        Re-run initialization even if configuration exists.

    .PARAMETER IncludeEntraID
        Include Entra ID/Azure AD assessment. Triggers SSO authentication flow.

    .PARAMETER NonInteractive
        Skip all prompts. Use only auto-detected values and parameters.

    .EXAMPLE
        Initialize-ADScout
        Interactive initialization with auto-detection.

    .EXAMPLE
        Initialize-ADScout -Mode Assessment -IncludeEntraID
        Initialize for one-time assessment including Entra ID.

    .EXAMPLE
        Initialize-ADScout -Mode SIEM -NonInteractive
        Non-interactive SIEM mode using only auto-detected values.

    .OUTPUTS
        PSCustomObject with detected/configured environment details.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Assessment', 'Dashboard', 'SIEM')]
        [string]$Mode,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$IncludeEntraID,

        [Parameter()]
        [switch]$NonInteractive
    )

    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              AD-Scout Environment Initialization             ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Check for existing configuration
    $configPath = Join-Path $HOME '.adscout' 'config.json'
    $existingConfig = $null
    if ((Test-Path $configPath) -and -not $Force) {
        try {
            $existingConfig = Get-Content $configPath -Raw | ConvertFrom-Json
            Write-Host "  Found existing configuration from $($existingConfig.InitializedAt)" -ForegroundColor Gray
            if (-not $NonInteractive) {
                $useExisting = Read-Host "  Use existing configuration? [Y/n]"
                if ($useExisting -ne 'n' -and $useExisting -ne 'N') {
                    Write-Host "  Using existing configuration." -ForegroundColor Green
                    return $existingConfig
                }
            }
        } catch {
            Write-Verbose "Could not load existing config: $_"
        }
    }

    # ═══════════════════════════════════════════════════════════════
    # Phase 1: Environment Detection
    # ═══════════════════════════════════════════════════════════════
    Write-Host "Phase 1: Environment Detection" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $environment = @{
        # Machine context
        ComputerName     = $env:COMPUTERNAME
        Username         = $env:USERNAME
        IsElevated       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        # Domain detection from environment
        Domain           = $env:USERDNSDOMAIN
        DomainNetBIOS    = $env:USERDOMAIN
        LogonServer      = ($env:LOGONSERVER -replace '\\\\', '')

        # Will be populated if AD module available
        DomainDN         = $null
        PDCEmulator      = $null
        ForestRoot       = $null
        DomainSID        = $null
        FunctionalLevel  = $null

        # Module availability
        HasADModule      = $false
        HasGraphModule   = $false
        HasGraphAuth     = $false

        # Connectivity
        IsDomainJoined   = $null -ne $env:USERDNSDOMAIN
        CanReachDC       = $false
        CanReachGraph    = $false
    }

    # Check domain membership
    if ($environment.IsDomainJoined) {
        Write-Host "  [✓] Domain-joined: $($environment.Domain)" -ForegroundColor Green
        Write-Host "      Logon Server: $($environment.LogonServer)" -ForegroundColor Gray
    } else {
        Write-Host "  [!] Not domain-joined - limited functionality" -ForegroundColor Yellow
        Write-Host "      Specify -Domain and -Credential for remote assessment" -ForegroundColor Gray
    }

    # Check ActiveDirectory module
    $adModule = Get-Module ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue
    if ($adModule) {
        $environment.HasADModule = $true
        Write-Host "  [✓] ActiveDirectory module: v$($adModule.Version)" -ForegroundColor Green

        # Try to get enhanced domain info
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adDomain = Get-ADDomain -ErrorAction Stop
            $adForest = Get-ADForest -ErrorAction Stop

            $environment.DomainDN = $adDomain.DistinguishedName
            $environment.PDCEmulator = $adDomain.PDCEmulator
            $environment.ForestRoot = $adForest.RootDomain
            $environment.DomainSID = $adDomain.DomainSID.Value
            $environment.FunctionalLevel = $adDomain.DomainMode.ToString()
            $environment.CanReachDC = $true

            Write-Host "      PDC Emulator: $($environment.PDCEmulator)" -ForegroundColor Gray
            Write-Host "      Forest Root: $($environment.ForestRoot)" -ForegroundColor Gray
            Write-Host "      Functional Level: $($environment.FunctionalLevel)" -ForegroundColor Gray
        } catch {
            Write-Host "  [!] AD module loaded but query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [!] ActiveDirectory module not installed" -ForegroundColor Yellow
        Write-Host "      Install: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Gray
    }

    # Check Microsoft.Graph module
    $graphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue
    if ($graphModule) {
        $environment.HasGraphModule = $true
        Write-Host "  [✓] Microsoft.Graph module: v$($graphModule.Version | Select-Object -First 1)" -ForegroundColor Green

        # Check for existing Graph connection
        try {
            $graphContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($graphContext) {
                $environment.HasGraphAuth = $true
                $environment.CanReachGraph = $true
                Write-Host "      Connected as: $($graphContext.Account)" -ForegroundColor Gray
            }
        } catch { }
    } else {
        Write-Host "  [○] Microsoft.Graph module not installed (optional)" -ForegroundColor DarkGray
        Write-Host "      Install: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Gray
    }

    # Elevation status
    if ($environment.IsElevated) {
        Write-Host "  [✓] Running elevated (Administrator)" -ForegroundColor Green
    } else {
        Write-Host "  [○] Not elevated - some checks may be limited" -ForegroundColor DarkGray
    }

    Write-Host ""

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Mode Selection
    # ═══════════════════════════════════════════════════════════════
    Write-Host "Phase 2: Deployment Mode" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    if (-not $Mode -and -not $NonInteractive) {
        Write-Host "  Select deployment mode:" -ForegroundColor White
        Write-Host "    [1] Assessment  - One-time security assessment with report" -ForegroundColor Gray
        Write-Host "    [2] Dashboard   - Continuous monitoring with web dashboard" -ForegroundColor Gray
        Write-Host "    [3] SIEM        - Export findings to Elasticsearch/Kibana" -ForegroundColor Gray
        Write-Host ""

        $modeChoice = Read-Host "  Enter choice [1-3]"
        $Mode = switch ($modeChoice) {
            '1' { 'Assessment' }
            '2' { 'Dashboard' }
            '3' { 'SIEM' }
            default { 'Assessment' }
        }
    } elseif (-not $Mode) {
        $Mode = 'Assessment'
    }

    Write-Host "  [✓] Mode: $Mode" -ForegroundColor Green

    $config = @{
        Mode             = $Mode
        Environment      = $environment
        SIEM             = $null
        EntraID          = $null
        InitializedAt    = (Get-Date).ToString('o')
        Version          = '0.2.0'
    }

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: Mode-Specific Configuration
    # ═══════════════════════════════════════════════════════════════

    # SIEM Configuration
    if ($Mode -eq 'SIEM') {
        Write-Host ""
        Write-Host "Phase 3: SIEM Configuration" -ForegroundColor Yellow
        Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        if ($NonInteractive) {
            $config.SIEM = @{
                ElasticsearchUrl = $env:ADSCOUT_ES_URL ?? 'http://localhost:9200'
                IndexName        = $env:ADSCOUT_ES_INDEX ?? 'adscout-findings'
                ApiKey           = $env:ADSCOUT_ES_APIKEY
            }
        } else {
            $esUrl = Read-Host "  Elasticsearch URL [http://localhost:9200]"
            if (-not $esUrl) { $esUrl = 'http://localhost:9200' }

            $esIndex = Read-Host "  Index name [adscout-findings]"
            if (-not $esIndex) { $esIndex = 'adscout-findings' }

            $esApiKey = Read-Host "  API Key (optional, press Enter to skip)"

            $config.SIEM = @{
                ElasticsearchUrl = $esUrl
                IndexName        = $esIndex
                ApiKey           = if ($esApiKey) { $esApiKey } else { $null }
            }
        }

        Write-Host "  [✓] SIEM configured: $($config.SIEM.ElasticsearchUrl)" -ForegroundColor Green
    }

    # ═══════════════════════════════════════════════════════════════
    # Phase 4: Entra ID Authentication
    # ═══════════════════════════════════════════════════════════════

    if ($IncludeEntraID -or (-not $NonInteractive -and $environment.HasGraphModule)) {
        Write-Host ""
        Write-Host "Phase 4: Entra ID Integration" -ForegroundColor Yellow
        Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        $connectEntra = $IncludeEntraID
        if (-not $IncludeEntraID -and -not $NonInteractive) {
            $entraChoice = Read-Host "  Include Entra ID (Azure AD) assessment? [y/N]"
            $connectEntra = $entraChoice -eq 'y' -or $entraChoice -eq 'Y'
        }

        if ($connectEntra) {
            if (-not $environment.HasGraphModule) {
                Write-Host "  [!] Microsoft.Graph module required for Entra ID" -ForegroundColor Yellow
                Write-Host "      Install: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Gray
            } elseif ($environment.HasGraphAuth) {
                Write-Host "  [✓] Already authenticated to Microsoft Graph" -ForegroundColor Green
                $config.EntraID = @{
                    Enabled     = $true
                    Account     = (Get-MgContext).Account
                    TenantId    = (Get-MgContext).TenantId
                    AuthMethod  = 'Existing'
                }
            } else {
                Write-Host "  Entra ID requires authentication. Choose method:" -ForegroundColor White
                Write-Host "    [1] Interactive (browser popup)" -ForegroundColor Gray
                Write-Host "    [2] Device Code (for terminals without browser)" -ForegroundColor Gray
                Write-Host ""

                $authChoice = if ($NonInteractive) { '2' } else { Read-Host "  Enter choice [1-2]" }

                $scopes = @(
                    'Directory.Read.All'
                    'Policy.Read.All'
                    'IdentityRiskyUser.Read.All'
                    'AuditLog.Read.All'
                    'UserAuthenticationMethod.Read.All'
                )

                try {
                    if ($authChoice -eq '2') {
                        Write-Host ""
                        Write-Host "  Device Code Authentication" -ForegroundColor Cyan
                        Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
                        Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome
                    } else {
                        Write-Host "  Opening browser for authentication..." -ForegroundColor Gray
                        Connect-MgGraph -Scopes $scopes -NoWelcome
                    }

                    $context = Get-MgContext
                    if ($context) {
                        $environment.HasGraphAuth = $true
                        $environment.CanReachGraph = $true
                        Write-Host "  [✓] Connected to Entra ID" -ForegroundColor Green
                        Write-Host "      Account: $($context.Account)" -ForegroundColor Gray
                        Write-Host "      Tenant: $($context.TenantId)" -ForegroundColor Gray

                        $config.EntraID = @{
                            Enabled     = $true
                            Account     = $context.Account
                            TenantId    = $context.TenantId
                            AuthMethod  = if ($authChoice -eq '2') { 'DeviceCode' } else { 'Interactive' }
                        }
                    }
                } catch {
                    Write-Host "  [✗] Entra ID authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                    $config.EntraID = @{ Enabled = $false; Error = $_.Exception.Message }
                }
            }
        } else {
            $config.EntraID = @{ Enabled = $false }
        }
    }

    # ═══════════════════════════════════════════════════════════════
    # Phase 5: Save Configuration
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "Phase 5: Saving Configuration" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    # Create config directory
    $configDir = Split-Path $configPath -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    # Convert to saveable format (flatten environment)
    $saveConfig = [PSCustomObject]@{
        Mode            = $config.Mode
        Domain          = $environment.Domain
        DomainDN        = $environment.DomainDN
        PDCEmulator     = $environment.PDCEmulator
        ForestRoot      = $environment.ForestRoot
        SIEM            = $config.SIEM
        EntraID         = $config.EntraID
        InitializedAt   = $config.InitializedAt
        Version         = $config.Version
    }

    $saveConfig | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding UTF8
    Write-Host "  [✓] Configuration saved to: $configPath" -ForegroundColor Green

    # ═══════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                  Initialization Complete                     ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor White

    switch ($Mode) {
        'Assessment' {
            Write-Host "    Invoke-ADScoutScan | Export-ADScoutReport -Format HTML" -ForegroundColor Cyan
        }
        'Dashboard' {
            Write-Host "    Invoke-ADScoutScan | Show-ADScoutDashboard" -ForegroundColor Cyan
        }
        'SIEM' {
            Write-Host "    Invoke-ADScoutScan | Export-ADScoutNDJSON | Send-ToElasticsearch" -ForegroundColor Cyan
        }
    }
    Write-Host ""

    # Return full config object
    $config.Environment = $environment
    return [PSCustomObject]$config
}

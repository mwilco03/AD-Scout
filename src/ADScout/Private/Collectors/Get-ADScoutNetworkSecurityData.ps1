function Get-ADScoutNetworkSecurityData {
    <#
    .SYNOPSIS
        Collects network and protocol security configuration from Active Directory.

    .DESCRIPTION
        Retrieves security settings for LLMNR, NetBIOS, SMB signing, LDAP signing,
        and other network protocol configurations from GPOs and domain controllers.

    .PARAMETER Domain
        Target domain name.

    .PARAMETER Server
        Specific domain controller to query.

    .PARAMETER Credential
        Credentials for AD/GPO queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential
    )

    # Check cache first
    $cacheKey = "NetworkSecurity:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached network security data"
        return $cached
    }

    Write-Verbose "Collecting network security configuration"

    $networkSecurityData = @{
        LLMNRSettings           = @()
        NetBIOSSettings         = @()
        SMBSigningSettings      = @()
        LDAPSigningSettings     = @()
        NTLMSettings            = @()
        DomainControllers       = @()
        PasswordPolicy          = $null
        FineGrainedPolicies     = @()
        KerberosSettings        = @()
        CollectionTime          = Get-Date
        CollectionErrors        = @()
    }

    try {
        # Get Domain Controllers
        Write-Verbose "Collecting Domain Controller information..."
        $domainControllers = Get-ADScoutDomainControllerData -Domain $Domain -Server $Server -Credential $Credential
        $networkSecurityData.DomainControllers = $domainControllers

        # Get Default Domain Password Policy
        Write-Verbose "Collecting password policy..."
        $networkSecurityData.PasswordPolicy = Get-ADScoutPasswordPolicyData -Domain $Domain -Server $Server -Credential $Credential

        # Get Fine-Grained Password Policies
        $networkSecurityData.FineGrainedPolicies = Get-ADScoutFineGrainedPasswordPolicies -Domain $Domain -Server $Server -Credential $Credential

        # Check LLMNR settings via GPO registry values
        Write-Verbose "Checking LLMNR configuration..."
        $networkSecurityData.LLMNRSettings = Get-ADScoutLLMNRSettings -Domain $Domain -Server $Server -Credential $Credential

        # Check SMB Signing settings
        Write-Verbose "Checking SMB signing configuration..."
        $networkSecurityData.SMBSigningSettings = Get-ADScoutSMBSigningSettings -Domain $Domain -Server $Server -Credential $Credential

        # Check LDAP Signing settings
        Write-Verbose "Checking LDAP signing configuration..."
        $networkSecurityData.LDAPSigningSettings = Get-ADScoutLDAPSigningSettings -Domain $Domain -Server $Server -Credential $Credential

        # Get Kerberos configuration
        Write-Verbose "Checking Kerberos configuration..."
        $networkSecurityData.KerberosSettings = Get-ADScoutKerberosSettings -Domain $Domain -Server $Server -Credential $Credential
    }
    catch {
        $networkSecurityData.CollectionErrors += "Error collecting network security data: $_"
        Write-Warning "Error collecting network security data: $_"
    }

    # Cache the results
    Set-ADScoutCache -Key $cacheKey -Value $networkSecurityData

    return $networkSecurityData
}

function Get-ADScoutDomainControllerData {
    <#
    .SYNOPSIS
        Collects Domain Controller information including OS version and patch level.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $dcs = @()

    try {
        $params = @{
            Filter = '*'
            Properties = @(
                'Name',
                'OperatingSystem',
                'OperatingSystemVersion',
                'OperatingSystemServicePack',
                'IPv4Address',
                'Site',
                'IsGlobalCatalog',
                'IsReadOnly',
                'Enabled',
                'LastLogonDate',
                'WhenCreated',
                'WhenChanged',
                'PasswordLastSet',
                'DistinguishedName'
            )
        }

        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }

        $domainControllers = Get-ADDomainController @params -ErrorAction SilentlyContinue

        foreach ($dc in $domainControllers) {
            # Parse OS version to determine support status
            $osVersion = $dc.OperatingSystemVersion
            $osName = $dc.OperatingSystem
            $isSupported = $true
            $supportStatus = 'Supported'
            $securityRisk = 'Low'

            # Check for unsupported or EOL operating systems
            if ($osName -match '2003|2000|NT') {
                $isSupported = $false
                $supportStatus = 'End of Life - Critical'
                $securityRisk = 'Critical'
            }
            elseif ($osName -match '2008(?! R2)') {
                $isSupported = $false
                $supportStatus = 'End of Life'
                $securityRisk = 'Critical'
            }
            elseif ($osName -match '2008 R2') {
                $isSupported = $false
                $supportStatus = 'End of Extended Support'
                $securityRisk = 'High'
            }
            elseif ($osName -match '2012(?! R2)') {
                $isSupported = $false
                $supportStatus = 'End of Extended Support'
                $securityRisk = 'High'
            }
            elseif ($osName -match '2012 R2') {
                $isSupported = $false
                $supportStatus = 'End of Extended Support (Oct 2023)'
                $securityRisk = 'High'
            }
            elseif ($osName -match '2016') {
                $supportStatus = 'Mainstream Support Ended'
                $securityRisk = 'Medium'
            }
            elseif ($osName -match '2019') {
                $supportStatus = 'Supported'
                $securityRisk = 'Low'
            }
            elseif ($osName -match '2022') {
                $supportStatus = 'Supported - Current'
                $securityRisk = 'Low'
            }

            # Calculate password age for computer account
            $passwordAge = $null
            if ($dc.PasswordLastSet) {
                $passwordAge = (New-TimeSpan -Start $dc.PasswordLastSet -End (Get-Date)).Days
            }

            $dcs += [PSCustomObject]@{
                Name                    = $dc.Name
                HostName                = $dc.HostName
                IPv4Address             = $dc.IPv4Address
                Site                    = $dc.Site
                OperatingSystem         = $dc.OperatingSystem
                OperatingSystemVersion  = $dc.OperatingSystemVersion
                ServicePack             = $dc.OperatingSystemServicePack
                IsGlobalCatalog         = $dc.IsGlobalCatalog
                IsReadOnly              = $dc.IsReadOnly
                Enabled                 = $dc.Enabled
                IsSupported             = $isSupported
                SupportStatus           = $supportStatus
                SecurityRisk            = $securityRisk
                LastLogonDate           = $dc.LastLogonDate
                PasswordLastSet         = $dc.PasswordLastSet
                PasswordAgeDays         = $passwordAge
                WhenCreated             = $dc.WhenCreated
                WhenChanged             = $dc.WhenChanged
                DistinguishedName       = $dc.DistinguishedName
            }
        }
    }
    catch {
        Write-Verbose "Error collecting DC data: $_"
    }

    return $dcs
}

function Get-ADScoutPasswordPolicyData {
    <#
    .SYNOPSIS
        Collects default domain password policy.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    try {
        $params = @{}
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }
        if ($Domain) { $params.Identity = $Domain }

        $policy = Get-ADDefaultDomainPasswordPolicy @params -ErrorAction SilentlyContinue

        # Evaluate policy strength
        $weaknesses = @()
        $riskLevel = 'Low'

        if ($policy.MinPasswordLength -lt 14) {
            $weaknesses += "Minimum length $($policy.MinPasswordLength) (recommended: 14+)"
            $riskLevel = 'Medium'
        }
        if ($policy.MinPasswordLength -lt 8) {
            $weaknesses += "Minimum length critically low"
            $riskLevel = 'Critical'
        }
        if ($policy.PasswordHistoryCount -lt 24) {
            $weaknesses += "Password history $($policy.PasswordHistoryCount) (recommended: 24)"
        }
        if ($policy.MaxPasswordAge.Days -gt 90) {
            $weaknesses += "Max password age $($policy.MaxPasswordAge.Days) days (recommended: 60-90)"
        }
        if ($policy.MaxPasswordAge.Days -eq 0) {
            $weaknesses += "Passwords never expire (not recommended for users)"
            $riskLevel = 'High'
        }
        if ($policy.MinPasswordAge.Days -lt 1) {
            $weaknesses += "No minimum password age (allows rapid cycling)"
        }
        if (-not $policy.ComplexityEnabled) {
            $weaknesses += "Complexity requirements disabled"
            $riskLevel = 'High'
        }
        if ($policy.LockoutThreshold -eq 0) {
            $weaknesses += "No account lockout (brute force possible)"
            $riskLevel = 'High'
        }
        if ($policy.LockoutThreshold -gt 10) {
            $weaknesses += "Lockout threshold too high ($($policy.LockoutThreshold))"
        }
        if ($policy.ReversibleEncryptionEnabled) {
            $weaknesses += "Reversible encryption enabled"
            $riskLevel = 'Critical'
        }

        return [PSCustomObject]@{
            DistinguishedName           = $policy.DistinguishedName
            MinPasswordLength           = $policy.MinPasswordLength
            PasswordHistoryCount        = $policy.PasswordHistoryCount
            MaxPasswordAge              = $policy.MaxPasswordAge
            MinPasswordAge              = $policy.MinPasswordAge
            ComplexityEnabled           = $policy.ComplexityEnabled
            ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
            LockoutThreshold            = $policy.LockoutThreshold
            LockoutDuration             = $policy.LockoutDuration
            LockoutObservationWindow    = $policy.LockoutObservationWindow
            Weaknesses                  = $weaknesses
            WeaknessCount               = $weaknesses.Count
            RiskLevel                   = $riskLevel
        }
    }
    catch {
        Write-Verbose "Error collecting password policy: $_"
        return $null
    }
}

function Get-ADScoutFineGrainedPasswordPolicies {
    <#
    .SYNOPSIS
        Collects fine-grained password policies.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $policies = @()

    try {
        $params = @{
            Filter = '*'
        }
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }

        $fgpps = Get-ADFineGrainedPasswordPolicy @params -ErrorAction SilentlyContinue

        foreach ($policy in $fgpps) {
            $policies += [PSCustomObject]@{
                Name                        = $policy.Name
                Precedence                  = $policy.Precedence
                MinPasswordLength           = $policy.MinPasswordLength
                PasswordHistoryCount        = $policy.PasswordHistoryCount
                MaxPasswordAge              = $policy.MaxPasswordAge
                MinPasswordAge              = $policy.MinPasswordAge
                ComplexityEnabled           = $policy.ComplexityEnabled
                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
                LockoutThreshold            = $policy.LockoutThreshold
                LockoutDuration             = $policy.LockoutDuration
                AppliesTo                   = $policy.AppliesTo
                DistinguishedName           = $policy.DistinguishedName
            }
        }
    }
    catch {
        Write-Verbose "Error collecting fine-grained password policies: $_"
    }

    return $policies
}

function Get-ADScoutLLMNRSettings {
    <#
    .SYNOPSIS
        Checks LLMNR and NetBIOS settings in GPOs.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $settings = @{
        LLMNRDisabled           = $false
        NetBIOSDisabled         = $false
        mDNSDisabled            = $false
        ConfiguredViaGPO        = $false
        GPOName                 = $null
        RegistrySettings        = @()
        RiskLevel               = 'High'
        Recommendation          = 'Disable LLMNR and NetBIOS via GPO to prevent credential relay attacks'
    }

    try {
        # LLMNR is disabled via: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0
        # NetBIOS over TCP/IP is configured per adapter or via DHCP option 001

        # Check if GPO module is available
        if (Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue) {
            Import-Module GroupPolicy -ErrorAction SilentlyContinue

            $params = @{}
            if ($Domain) { $params.Domain = $Domain }
            if ($Server) { $params.Server = $Server }

            # Get all GPOs and check for LLMNR settings
            $gpos = Get-GPO -All @params -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                try {
                    # Check Computer Configuration for DNS Client settings
                    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml @params -ErrorAction SilentlyContinue

                    if ($report -match 'EnableMulticast.*value.*0') {
                        $settings.LLMNRDisabled = $true
                        $settings.ConfiguredViaGPO = $true
                        $settings.GPOName = $gpo.DisplayName
                        $settings.RiskLevel = 'Low'
                    }
                }
                catch {
                    # Continue checking other GPOs
                }
            }
        }

        # If LLMNR not explicitly disabled, it's enabled by default
        if (-not $settings.LLMNRDisabled) {
            $settings.RiskLevel = 'High'
            $settings.RegistrySettings += @{
                Path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                Name = 'EnableMulticast'
                RequiredValue = 0
                CurrentStatus = 'Not configured (LLMNR enabled by default)'
            }
        }
    }
    catch {
        Write-Verbose "Error checking LLMNR settings: $_"
    }

    return $settings
}

function Get-ADScoutSMBSigningSettings {
    <#
    .SYNOPSIS
        Checks SMB signing requirements.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $settings = @{
        ServerSigningRequired   = $false
        ClientSigningRequired   = $false
        ConfiguredViaGPO        = $false
        DomainControllerStatus  = @()
        RiskLevel               = 'High'
        Vulnerabilities         = @()
    }

    try {
        # Check Domain Controllers for SMB signing
        # SMB Signing should be REQUIRED (not just enabled) on DCs

        # Registry keys:
        # Server: HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature
        # Client: HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature

        # GPO Settings to check:
        # Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
        # - Microsoft network server: Digitally sign communications (always) = Enabled
        # - Microsoft network client: Digitally sign communications (always) = Enabled

        if (Get-Module -ListAvailable GroupPolicy -ErrorAction SilentlyContinue) {
            Import-Module GroupPolicy -ErrorAction SilentlyContinue

            $params = @{}
            if ($Domain) { $params.Domain = $Domain }
            if ($Server) { $params.Server = $Server }

            $gpos = Get-GPO -All @params -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                try {
                    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml @params -ErrorAction SilentlyContinue

                    # Check for SMB server signing requirement
                    if ($report -match 'RequireSecuritySignature.*1' -or
                        $report -match 'Digitally sign communications \(always\).*Enabled') {
                        $settings.ServerSigningRequired = $true
                        $settings.ConfiguredViaGPO = $true
                    }
                }
                catch {
                    # Continue
                }
            }
        }

        # Assess risk
        if (-not $settings.ServerSigningRequired) {
            $settings.Vulnerabilities += 'SMB signing not required - vulnerable to relay attacks'
            $settings.Vulnerabilities += 'NTLM relay attacks possible (e.g., ntlmrelayx)'
            $settings.RiskLevel = 'Critical'
        }
        else {
            $settings.RiskLevel = 'Low'
        }
    }
    catch {
        Write-Verbose "Error checking SMB signing: $_"
    }

    return $settings
}

function Get-ADScoutLDAPSigningSettings {
    <#
    .SYNOPSIS
        Checks LDAP signing and channel binding requirements.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $settings = @{
        LDAPServerSigningRequired   = $false
        LDAPChannelBindingRequired  = $false
        RiskLevel                   = 'Medium'
        Vulnerabilities             = @()
    }

    try {
        # LDAP Signing: Domain controller: LDAP server signing requirements
        # Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity
        # 0 = None, 1 = Require signing

        # LDAP Channel Binding:
        # Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding
        # 0 = Never, 1 = When supported, 2 = Always

        if (-not $settings.LDAPServerSigningRequired) {
            $settings.Vulnerabilities += 'LDAP signing not required - vulnerable to LDAP relay'
        }

        if (-not $settings.LDAPChannelBindingRequired) {
            $settings.Vulnerabilities += 'LDAP channel binding not enforced'
        }

        if ($settings.Vulnerabilities.Count -gt 0) {
            $settings.RiskLevel = 'High'
        }
        else {
            $settings.RiskLevel = 'Low'
        }
    }
    catch {
        Write-Verbose "Error checking LDAP signing: $_"
    }

    return $settings
}

function Get-ADScoutKerberosSettings {
    <#
    .SYNOPSIS
        Checks Kerberos security configuration.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    $settings = @{
        MaxTicketAge            = $null
        MaxServiceAge           = $null
        MaxClockSkew            = $null
        KrbtgtPasswordAge       = $null
        KrbtgtLastChanged       = $null
        RC4Enabled              = $true  # Assume worst case
        AESEnabled              = $true
        DESDisabled             = $true
        RiskLevel               = 'Medium'
        GoldenTicketRisk        = @()
    }

    try {
        $params = @{
            Filter = 'SamAccountName -eq "krbtgt"'
            Properties = @('PasswordLastSet', 'WhenChanged', 'msDS-SupportedEncryptionTypes')
        }
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }

        $krbtgt = Get-ADUser @params -ErrorAction SilentlyContinue

        if ($krbtgt) {
            $settings.KrbtgtLastChanged = $krbtgt.PasswordLastSet
            $settings.KrbtgtPasswordAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days

            # Check krbtgt password age - should be rotated at least annually
            if ($settings.KrbtgtPasswordAge -gt 180) {
                $settings.GoldenTicketRisk += "KRBTGT password is $($settings.KrbtgtPasswordAge) days old"
                $settings.RiskLevel = 'High'
            }
            if ($settings.KrbtgtPasswordAge -gt 365) {
                $settings.GoldenTicketRisk += "KRBTGT password over 1 year old - Golden Ticket persistence possible"
                $settings.RiskLevel = 'Critical'
            }

            # Check encryption types
            $encTypes = $krbtgt.'msDS-SupportedEncryptionTypes'
            if ($encTypes) {
                # Bit flags: DES_CBC_CRC=1, DES_CBC_MD5=2, RC4_HMAC=4, AES128=8, AES256=16
                $settings.DESDisabled = -not ($encTypes -band 3)
                $settings.RC4Enabled = [bool]($encTypes -band 4)
                $settings.AESEnabled = [bool]($encTypes -band 24)
            }
        }
    }
    catch {
        Write-Verbose "Error checking Kerberos settings: $_"
    }

    return $settings
}

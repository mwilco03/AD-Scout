@{
    Id          = 'A-RDPSecurity'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Remote Desktop Security Weaknesses'
    Description = 'Remote Desktop Protocol (RDP) security settings are not properly configured on Domain Controllers. Weak RDP configuration allows credential theft, session hijacking, and provides attack vectors for ransomware and lateral movement.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'RDP Security Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access' }
        @{ Title = 'NIST AC-17 Remote Access'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'Securing RDP'; Url = 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa19-168a' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1021.001', 'T1563.002')  # Remote Desktop Protocol, RDP Hijacking
    }

    CIS   = @('18.9.65.3.9.1', '18.9.65.3.9.2', '18.9.65.3.9.3')
    STIG  = @('V-63687', 'V-63691', 'V-63695')
    ANSSI = @('vuln1_rdp')
    NIST  = @('AC-17', 'AC-17(1)', 'AC-17(2)', 'SC-8')

    Scoring = @{
        Type = 'PerDiscovery'
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            $securityIssues = @()

            try {
                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local checks
                    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                    $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

                    # Check if RDP is enabled
                    $rdpEnabled = (Get-ItemProperty -Path $regPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0

                    if ($rdpEnabled) {
                        # Check NLA (Network Level Authentication)
                        $nlaEnabled = (Get-ItemProperty -Path $rdpTcpPath -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1
                        if (-not $nlaEnabled) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'Network Level Authentication'
                                Status      = 'Disabled'
                                Risk        = 'Allows connections without pre-authentication'
                                Recommended = 'Enable NLA'
                            }
                        }

                        # Check Security Layer (0=RDP, 1=Negotiate, 2=TLS)
                        $securityLayer = (Get-ItemProperty -Path $rdpTcpPath -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer
                        if ($securityLayer -lt 2) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'RDP Security Layer'
                                Status      = if ($securityLayer -eq 0) { 'RDP (Weak)' } else { 'Negotiate' }
                                Risk        = 'Allows weak encryption or downgrade attacks'
                                Recommended = 'Set to TLS 1.2'
                            }
                        }

                        # Check Encryption Level (1=Low, 2=Client Compatible, 3=High, 4=FIPS)
                        $encryptionLevel = (Get-ItemProperty -Path $rdpTcpPath -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel
                        if ($encryptionLevel -lt 3) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'Encryption Level'
                                Status      = switch ($encryptionLevel) { 1 { 'Low' } 2 { 'Client Compatible' } default { 'Unknown' } }
                                Risk        = 'Weak encryption can be intercepted'
                                Recommended = 'High or FIPS'
                            }
                        }

                        # Check for restricted admin mode capability (helps prevent credential caching)
                        $restrictedAdmin = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableRestrictedAdmin' -ErrorAction SilentlyContinue).DisableRestrictedAdmin
                        if ($restrictedAdmin -eq 1) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'Restricted Admin Mode'
                                Status      = 'Disabled'
                                Risk        = 'Credentials cached in memory on remote system'
                                Recommended = 'Enable Restricted Admin'
                            }
                        }

                        # Check if RDP is exposed (port 3389 listening on all interfaces)
                        $rdpListeners = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
                        if ($rdpListeners | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' }) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'RDP Network Exposure'
                                Status      = 'Listening on all interfaces'
                                Risk        = 'RDP accessible from any network'
                                Recommended = 'Restrict to management network'
                            }
                        }
                    }
                } else {
                    # Remote DC - check if RDP port is accessible
                    try {
                        $rdpTest = Test-NetConnection -ComputerName $dc.Name -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                        if ($rdpTest.TcpTestSucceeded) {
                            $securityIssues += [PSCustomObject]@{
                                Setting     = 'RDP Accessibility'
                                Status      = 'Port 3389 accessible'
                                Risk        = 'RDP enabled - verify security settings manually'
                                Recommended = 'Verify NLA, TLS, and encryption settings'
                            }
                        }
                    } catch {
                        # Could not test
                    }
                }

                if ($securityIssues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dc.Name
                        OperatingSystem     = $dc.OperatingSystem
                        SecurityIssues      = $securityIssues
                        IssueCount          = $securityIssues.Count
                        RiskLevel           = 'High'
                        Impact              = 'RDP attacks, credential theft, lateral movement'
                        NISTControl         = 'AC-17 Remote Access'
                    }
                }
            } catch {
                # Error checking RDP settings
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Harden RDP configuration on Domain Controllers by enabling NLA, TLS encryption, and restricting access.'
        Impact      = 'Low - May require updated RDP clients. Test connectivity after changes.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Harden RDP Security on Domain Controllers
# DCs with RDP issues: $($Finding.Findings.Count)

# === ENABLE NETWORK LEVEL AUTHENTICATION (NLA) ===
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1

# Via GPO:
# Computer Configuration > Administrative Templates > Windows Components
# > Remote Desktop Services > Remote Desktop Session Host > Security
# "Require user authentication for remote connections by using NLA" = Enabled

# === SET TLS SECURITY LAYER ===
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'SecurityLayer' -Value 2

# Via GPO:
# "Require use of specific security layer for remote (RDP) connections" = SSL

# === SET HIGH ENCRYPTION LEVEL ===
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'MinEncryptionLevel' -Value 3

# Via GPO:
# "Set client connection encryption level" = High Level

# === ENABLE RESTRICTED ADMIN MODE ===
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'DisableRestrictedAdmin' -Value 0

# Use with: mstsc /restrictedAdmin

# === CONSIDER REMOTE CREDENTIAL GUARD ===
# Provides better protection than Restricted Admin
# Requires Windows 10/Server 2016+
# Via GPO:
# "Restrict delegation of credentials to remote servers" = Enabled with Require Remote Credential Guard

# === RESTRICT RDP ACCESS ===
# Only allow specific admin groups:
# 1. Remove 'Administrators' from Remote Desktop Users
# 2. Add specific RDP admin group

# Via GPO:
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > User Rights Assignment
# "Allow log on through Remote Desktop Services" = Domain Admins, specific RDP admin group

# === NETWORK RESTRICTIONS ===
# Use Windows Firewall to restrict RDP to management subnet:
New-NetFirewallRule -DisplayName "RDP - Mgmt Only" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/24 -Action Allow

# Block all other RDP:
New-NetFirewallRule -DisplayName "RDP - Block Others" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -Action Block

# === VERIFICATION ===
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
    Select-Object UserAuthentication, SecurityLayer, MinEncryptionLevel

"@
            return $commands
        }
    }
}

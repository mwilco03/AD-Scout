<#
.SYNOPSIS
    Detects insecure DNS zone configurations.

.DESCRIPTION
    DNS zones with insecure settings can allow zone transfers, dynamic updates,
    or cache poisoning. This rule checks for common DNS misconfigurations in
    Active Directory-integrated zones.

.NOTES
    Rule ID    : I-DNSZoneSecurity
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-DNSZoneSecurity'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'Insecure DNS Zone Configuration'
    Description = 'Identifies DNS zones with insecure configurations that could enable zone transfers, unauthorized updates, or DNS-based attacks.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'DNS Zone Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/networking/dns/deploy/secure-dns' }
        @{ Title = 'DNS Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/003/' }
        @{ Title = 'AD-Integrated DNS'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/dns-and-ad-ds' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0007')  # Credential Access, Discovery
        Techniques = @('T1557.003', 'T1018')  # DNS Poisoning, Remote System Discovery
    }

    CIS   = @('9.1.1')
    STIG  = @('V-254446')
    ANSSI = @('R41')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get a DC to query DNS
        $dnsServer = $null
        if ($Data.DomainControllers) {
            $dc = $Data.DomainControllers | Select-Object -First 1
            $dnsServer = if ($dc.Name) { $dc.Name } else { $dc.DnsHostName }
        }

        if (-not $dnsServer) {
            $dnsServer = (Get-ADDomainController).HostName
        }

        try {
            # Get all DNS zones
            $zones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction SilentlyContinue

            foreach ($zone in $zones) {
                $issues = @()
                $riskLevel = 'Medium'

                # Skip cache and trust anchors
                if ($zone.ZoneName -match '^TrustAnchors$|^_msdcs\.|^RootDNSServers') {
                    continue
                }

                # Check zone transfer settings
                if ($zone.SecureSecondaries -eq 'TransferAnyServer') {
                    $issues += 'Zone transfers allowed to ANY server'
                    $riskLevel = 'Critical'
                } elseif ($zone.SecureSecondaries -eq 'TransferToSecureServers') {
                    # Okay but verify the list
                } elseif ($zone.SecureSecondaries -eq 'NoTransfer') {
                    # Secure
                }

                # Check dynamic updates
                if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    $issues += 'Non-secure dynamic updates allowed'
                    $riskLevel = 'High'
                } elseif ($zone.DynamicUpdate -eq 'None') {
                    # May be intentional for static zones
                }

                # Check if AD-integrated
                if (-not $zone.IsAutoCreated) {
                    if (-not $zone.IsDsIntegrated) {
                        $issues += 'Not AD-integrated (file-based zone)'
                        if ($zone.ZoneType -eq 'Primary') {
                            $issues += 'Primary zone without AD replication security'
                        }
                    }
                }

                # Check for aging/scavenging
                if ($zone.IsDsIntegrated -and $zone.ZoneType -eq 'Primary') {
                    if (-not $zone.AgingEnabled) {
                        $issues += 'Aging not enabled (stale records accumulate)'
                    }
                }

                # Check reverse lookup zones for the domain
                if ($zone.IsReverseLookupZone) {
                    if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                        $issues += 'Reverse zone allows non-secure updates'
                    }
                }

                # Check DNSSEC
                $dnssec = Get-DnsServerDnsSecZoneSetting -ZoneName $zone.ZoneName -ComputerName $dnsServer -ErrorAction SilentlyContinue
                if ($dnssec) {
                    if (-not $dnssec.DenialOfExistence) {
                        # DNSSEC not configured
                    }
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        ZoneName          = $zone.ZoneName
                        ZoneType          = $zone.ZoneType
                        IsADIntegrated    = $zone.IsDsIntegrated
                        DynamicUpdate     = $zone.DynamicUpdate
                        ZoneTransfer      = $zone.SecureSecondaries
                        AgingEnabled      = $zone.AgingEnabled
                        IsReverseLookup   = $zone.IsReverseLookupZone
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        DNSServer         = $dnsServer
                    }
                }
            }

            # Check DNS server settings
            $dnsSettings = Get-DnsServerSetting -ComputerName $dnsServer -All -ErrorAction SilentlyContinue
            if ($dnsSettings) {
                $serverIssues = @()

                # Check cache locking
                $cacheLocking = Get-DnsServerCache -ComputerName $dnsServer -ErrorAction SilentlyContinue
                if ($cacheLocking.LockingPercent -lt 100) {
                    $serverIssues += "Cache locking at $($cacheLocking.LockingPercent)% (should be 100%)"
                }

                # Check if recursion is enabled (potential for DDoS amplification)
                $recursion = Get-DnsServerRecursion -ComputerName $dnsServer -ErrorAction SilentlyContinue
                if ($recursion.Enable -and -not $recursion.SecureResponse) {
                    $serverIssues += 'Recursion enabled without secure response'
                }

                # Check socket pool size (protection against Kaminsky attack)
                if ($dnsSettings.SocketPoolSize -lt 2500) {
                    $serverIssues += "Socket pool size $($dnsSettings.SocketPoolSize) (should be 2500+)"
                }

                if ($serverIssues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        ZoneName          = 'DNS Server Settings'
                        ZoneType          = 'Server'
                        IsADIntegrated    = $true
                        DynamicUpdate     = 'N/A'
                        ZoneTransfer      = 'N/A'
                        AgingEnabled      = 'N/A'
                        IsReverseLookup   = $false
                        Issues            = ($serverIssues -join '; ')
                        RiskLevel         = 'Medium'
                        DNSServer         = $dnsServer
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                ZoneName          = 'Error'
                ZoneType          = 'N/A'
                IsADIntegrated    = 'N/A'
                DynamicUpdate     = 'N/A'
                ZoneTransfer      = 'N/A'
                AgingEnabled      = 'N/A'
                IsReverseLookup   = $false
                Issues            = "DNS check failed: $_"
                RiskLevel         = 'Unknown'
                DNSServer         = $dnsServer
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Secure DNS zones by restricting transfers, requiring secure updates, and enabling DNSSEC.'
        Impact      = 'Low - DNS security improvements typically do not affect normal operations.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# DNS Zone Security Hardening
#############################################################################
#
# Insecure DNS configurations can enable:
# - Zone transfers to attackers (reconnaissance)
# - DNS record poisoning (redirect traffic)
# - Stale record exploitation
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.ZoneName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Restrict Zone Transfers
#############################################################################

# Get list of zones:
`$dnsServer = (Get-ADDomainController).HostName
`$zones = Get-DnsServerZone -ComputerName `$dnsServer

foreach (`$zone in `$zones) {
    if (`$zone.ZoneType -eq 'Primary') {
        # Disable zone transfers entirely (AD-integrated zones don't need them):
        Set-DnsServerPrimaryZone -ComputerName `$dnsServer -Name `$zone.ZoneName `
            -SecureSecondaries NoTransfer

        # Or restrict to specific servers:
        # Set-DnsServerPrimaryZone -ComputerName `$dnsServer -Name `$zone.ZoneName `
        #     -SecureSecondaries TransferToSecureServers `
        #     -SecondaryServers '10.0.0.1','10.0.0.2'

        Write-Host "Secured zone transfers for `$(`$zone.ZoneName)" -ForegroundColor Green
    }
}

#############################################################################
# Step 2: Configure Secure Dynamic Updates
#############################################################################

# Set zones to secure updates only:
foreach (`$zone in `$zones) {
    if (`$zone.IsDsIntegrated -and `$zone.DynamicUpdate -ne 'Secure') {
        Set-DnsServerPrimaryZone -ComputerName `$dnsServer -Name `$zone.ZoneName `
            -DynamicUpdate Secure

        Write-Host "Enabled secure dynamic updates for `$(`$zone.ZoneName)" -ForegroundColor Green
    }
}

#############################################################################
# Step 3: Enable Aging and Scavenging
#############################################################################

# Enable aging on zones:
foreach (`$zone in `$zones) {
    if (`$zone.IsDsIntegrated -and -not `$zone.AgingEnabled) {
        Set-DnsServerZoneAging -ComputerName `$dnsServer -Name `$zone.ZoneName `
            -Aging `$true `
            -RefreshInterval 7.00:00:00 `
            -NoRefreshInterval 7.00:00:00

        Write-Host "Enabled aging for `$(`$zone.ZoneName)" -ForegroundColor Green
    }
}

# Enable scavenging on DNS server:
Set-DnsServerScavenging -ComputerName `$dnsServer `
    -ScavengingState `$true `
    -ScavengingInterval 7.00:00:00

#############################################################################
# Step 4: Configure Cache Locking
#############################################################################

# Set cache locking to 100% to prevent cache poisoning:
Set-DnsServerCache -ComputerName `$dnsServer -LockingPercent 100

#############################################################################
# Step 5: Increase Socket Pool Size
#############################################################################

# Larger socket pool protects against Kaminsky-style attacks:
`$currentSettings = Get-DnsServerSetting -ComputerName `$dnsServer -All
if (`$currentSettings.SocketPoolSize -lt 2500) {
    dnscmd `$dnsServer /config /socketpoolsize 2500
    Write-Host "Increased socket pool size to 2500" -ForegroundColor Green
}

#############################################################################
# Step 6: Configure DNS Response Rate Limiting (RRL)
#############################################################################

# Enable RRL to mitigate DDoS amplification:
Set-DnsServerResponseRateLimiting -ComputerName `$dnsServer `
    -Mode Enable `
    -ResponsesPerSec 5 `
    -ErrorsPerSec 5 `
    -WindowInSec 5

#############################################################################
# Step 7: Enable DNSSEC (Optional but Recommended)
#############################################################################

# Sign AD-integrated zones with DNSSEC:
# Note: Requires key management infrastructure

# Generate Key Signing Key (KSK):
# Add-DnsServerSigningKey -ZoneName 'domain.com' -ComputerName `$dnsServer `
#     -Type KeySigningKey -CryptoAlgorithm RsaSha256 -KeyLength 2048

# Generate Zone Signing Key (ZSK):
# Add-DnsServerSigningKey -ZoneName 'domain.com' -ComputerName `$dnsServer `
#     -Type ZoneSigningKey -CryptoAlgorithm RsaSha256 -KeyLength 1024

# Sign the zone:
# Invoke-DnsServerZoneSign -ZoneName 'domain.com' -ComputerName `$dnsServer

#############################################################################
# Step 8: Configure DNS Logging
#############################################################################

# Enable DNS analytical logging:
Set-DnsServerDiagnostics -ComputerName `$dnsServer `
    -EventLogLevel 7 `
    -LogFilePath 'C:\DNS\Logs' `
    -EnableLogging `$true `
    -EnableLogFileRollover `$true `
    -MaxMBFileSize 500

# Enable DNS query logging (high volume):
Set-DnsServerDiagnostics -ComputerName `$dnsServer `
    -Queries `$true `
    -Answers `$true

#############################################################################
# Verification
#############################################################################

# Verify zone settings:
Get-DnsServerZone -ComputerName `$dnsServer |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, SecureSecondaries, AgingEnabled |
    Format-Table -AutoSize

# Verify server settings:
Get-DnsServerSetting -ComputerName `$dnsServer -All |
    Select-Object SocketPoolSize

Get-DnsServerCache -ComputerName `$dnsServer |
    Select-Object LockingPercent

"@
            return $commands
        }
    }
}

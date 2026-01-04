@{
    Id          = 'S-DC-SubnetMissing'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Domain Controller Subnet Not Declared'
    Description = 'Detects when Domain Controller IP addresses are not found in any declared Active Directory subnet. This affects site-aware services like DFS, site-based GPO processing, and optimal DC selection.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'AD Sites and Subnets'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design' }
        @{ Title = 'Subnet Configuration'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-subnet-design' }
        @{ Title = 'PingCastle Rule S-DC-SubnetMissing'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1016')   # System Network Configuration Discovery
    }

    CIS   = @()  # Subnet configuration not covered in CIS benchmarks
    STIG  = @()  # AD Sites and Services STIGs are environment-specific
    ANSSI = @()
    NIST  = @('CM-6', 'CM-7')  # Configuration Settings, Least Functionality

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 5
        MaxPoints = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get all declared subnets
            $subnets = @()

            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            $subnetSearcher = New-Object DirectoryServices.DirectorySearcher
            $subnetSearcher.SearchRoot = [ADSI]"LDAP://CN=Subnets,CN=Sites,$configNC"
            $subnetSearcher.Filter = "(objectClass=subnet)"
            $subnetSearcher.PropertiesToLoad.AddRange(@('cn', 'siteObject', 'name'))

            $subnetResults = $subnetSearcher.FindAll()

            foreach ($subnet in $subnetResults) {
                $subnetName = $subnet.Properties['cn'][0]
                $siteDN = $subnet.Properties['siteobject'][0]
                $siteName = if ($siteDN) { ($siteDN -split ',')[0] -replace 'CN=', '' } else { 'Unknown' }

                # Parse subnet into IP range
                if ($subnetName -match '^(.+)/(\d+)$') {
                    $network = $Matches[1]
                    $prefix = [int]$Matches[2]

                    $subnets += @{
                        Name = $subnetName
                        Network = $network
                        Prefix = $prefix
                        Site = $siteName
                    }
                }
            }

            # Check each DC's IP address against subnets
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                $dcHost = $dc.DNSHostName

                # Get DC IP addresses
                $dcIPs = @()

                if ($dc.IPv4Address) {
                    $dcIPs += $dc.IPv4Address
                }

                if ($dc.IPv6Address) {
                    $dcIPs += $dc.IPv6Address
                }

                # If no IP in data, try to resolve
                if ($dcIPs.Count -eq 0 -and $dcHost) {
                    try {
                        $dnsResult = [System.Net.Dns]::GetHostAddresses($dcHost)
                        $dcIPs = $dnsResult | ForEach-Object { $_.IPAddressToString }
                    } catch {
                        Write-Verbose "S-DC-SubnetMissing: Could not resolve IP for $dcHost : $_"
                    }
                }

                foreach ($ip in $dcIPs) {
                    # Skip IPv6 link-local
                    if ($ip -match '^fe80:') { continue }
                    # Skip loopback
                    if ($ip -eq '127.0.0.1' -or $ip -eq '::1') { continue }

                    $subnetFound = $false
                    $matchedSubnet = $null

                    foreach ($subnet in $subnets) {
                        # Simple subnet matching (works for common cases)
                        if (Test-SubnetMatch -IPAddress $ip -Network $subnet.Network -Prefix $subnet.Prefix) {
                            $subnetFound = $true
                            $matchedSubnet = $subnet.Name
                            break
                        }
                    }

                    if (-not $subnetFound) {
                        $findings += [PSCustomObject]@{
                            DCName              = $dcName
                            HostName            = $dcHost
                            IPAddress           = $ip
                            DeclaredSubnets     = $subnets.Count
                            SubnetFound         = $false
                            Severity            = 'Medium'
                            Risk                = 'DC IP not in any declared subnet'
                            Impact              = 'Clients may not find optimal DC, site-based GPO issues'
                            Recommendation      = "Add subnet for $ip to AD Sites and Services"
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "S-DC-SubnetMissing: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Create Active Directory subnets for all DC IP address ranges and associate them with appropriate sites.'
        Impact      = 'Low - Adding subnets improves AD functionality. No service disruption.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Domain Controller Subnet Missing Remediation
#
# DCs with undeclared subnets:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): $($_.IPAddress)" } | Out-String)

# Subnets should be declared in AD Sites and Services for:
# - Optimal DC selection for clients
# - DFS namespace referral optimization
# - Site-based GPO processing
# - Replication topology optimization

# STEP 1: View current sites and subnets
Get-ADReplicationSite -Filter * | Format-Table Name, Description
Get-ADReplicationSubnet -Filter * | Format-Table Name, Site

# STEP 2: Create subnets for missing DC IPs
$($Finding.Findings | ForEach-Object { @"
# Create subnet for $($_.IPAddress)
# Determine the appropriate subnet (e.g., /24 for a typical network)
# Example: If IP is 192.168.1.10, create 192.168.1.0/24

# New-ADReplicationSubnet -Name "192.168.1.0/24" -Site "Default-First-Site-Name" -Description "Network for $($_.DCName)"

"@ })

# STEP 3: Create new sites if needed
# If DCs are in different physical locations, create appropriate sites:
# New-ADReplicationSite -Name "BranchOffice1" -Description "Branch office location"

# STEP 4: Associate subnets with sites
# Each subnet should be linked to a site:
# Set-ADReplicationSubnet -Identity "192.168.1.0/24" -Site "SiteName"

# STEP 5: Configure site links for replication
# Ensure site links are properly configured:
Get-ADReplicationSiteLink -Filter * | Format-Table Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded

# STEP 6: Verify DC site placement
Get-ADDomainController -Filter * | Select-Object Name, Site, IPv4Address

# STEP 7: Force site recalculation
# On each DC, run:
# nltest /dsregdns

# STEP 8: Best practices for subnet naming
# Use CIDR notation: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# Document subnet purpose in Description field
# Review subnets when network changes occur

"@
            return $commands
        }
    }
}

# Helper function for subnet matching
function Test-SubnetMatch {
    param(
        [string]$IPAddress,
        [string]$Network,
        [int]$Prefix
    )

    try {
        # Only handle IPv4 for simplicity
        if ($IPAddress -match ':') { return $false }
        if ($Network -match ':') { return $false }

        $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
        $netBytes = [System.Net.IPAddress]::Parse($Network).GetAddressBytes()

        # Create mask
        $maskBits = ('1' * $Prefix).PadRight(32, '0')
        $mask = @()
        for ($i = 0; $i -lt 4; $i++) {
            $mask += [Convert]::ToInt32($maskBits.Substring($i * 8, 8), 2)
        }

        # Compare
        for ($i = 0; $i -lt 4; $i++) {
            if (($ipBytes[$i] -band $mask[$i]) -ne ($netBytes[$i] -band $mask[$i])) {
                return $false
            }
        }

        return $true
    } catch {
        return $false
    }
}

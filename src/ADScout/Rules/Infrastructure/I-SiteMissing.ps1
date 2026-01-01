<#
.SYNOPSIS
    Detects missing AD sites or unconfigured site topology.

.DESCRIPTION
    Proper AD site configuration is essential for efficient authentication and
    replication. Missing sites can cause performance issues and authentication
    delays.

.NOTES
    Rule ID    : I-SiteMissing
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-SiteMissing'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'Missing AD Sites or Subnet Coverage'
    Description = 'Identifies gaps in AD site topology including missing subnet-to-site mappings and single-site configurations that may cause performance issues.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'Sites,Subnets'

    References  = @(
        @{ Title = 'AD Sites and Services'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/designing-the-site-topology' }
        @{ Title = 'Site Link Configuration'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-link-design' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1018')   # Remote System Discovery
    }

    CIS   = @('4.1')
    STIG  = @()
    ANSSI = @('R14')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
            $sitesContainer = [ADSI]"LDAP://CN=Sites,$configNC"

            # Get all sites
            $sites = @()
            foreach ($site in $sitesContainer.Children) {
                if ($site.objectClass -contains 'site') {
                    $sites += $site
                }
            }

            # Check if only default site exists
            if ($sites.Count -eq 1 -and $sites[0].Name -eq 'Default-First-Site-Name') {
                $findings += [PSCustomObject]@{
                    Issue               = 'Only Default-First-Site-Name exists'
                    ObjectType          = 'Site Topology'
                    ObjectName          = 'Default-First-Site-Name'
                    Description         = 'No additional sites configured. All DCs and clients use single site.'
                    RiskLevel           = 'Medium'
                    Impact              = 'Suboptimal authentication routing in multi-location environments'
                    Recommendation      = 'Create sites for each physical location with DCs'
                    DistinguishedName   = $sites[0].distinguishedName
                }
            }

            # Get all subnets
            $subnetsContainer = [ADSI]"LDAP://CN=Subnets,CN=Sites,$configNC"
            $subnets = @()
            foreach ($subnet in $subnetsContainer.Children) {
                if ($subnet.objectClass -contains 'subnet') {
                    $subnets += $subnet
                }
            }

            # Check for subnets without site assignment
            foreach ($subnet in $subnets) {
                $siteObject = $subnet.siteObject
                if (-not $siteObject) {
                    $findings += [PSCustomObject]@{
                        Issue               = 'Subnet without site assignment'
                        ObjectType          = 'Subnet'
                        ObjectName          = $subnet.Name
                        Description         = 'Subnet is not associated with any AD site'
                        RiskLevel           = 'Medium'
                        Impact              = 'Clients in this subnet cannot determine local DC'
                        Recommendation      = 'Assign subnet to appropriate site'
                        DistinguishedName   = $subnet.distinguishedName
                    }
                }
            }

            # Check for sites without subnets
            foreach ($site in $sites) {
                $siteName = $site.Name
                $hasSubnet = $false

                foreach ($subnet in $subnets) {
                    if ($subnet.siteObject -and $subnet.siteObject -like "*$siteName*") {
                        $hasSubnet = $true
                        break
                    }
                }

                if (-not $hasSubnet -and $siteName -ne 'Default-First-Site-Name') {
                    $findings += [PSCustomObject]@{
                        Issue               = 'Site without subnet associations'
                        ObjectType          = 'Site'
                        ObjectName          = $siteName
                        Description         = 'Site has no subnets assigned'
                        RiskLevel           = 'Low'
                        Impact              = 'No clients will be mapped to this site'
                        Recommendation      = 'Add subnets or remove unused site'
                        DistinguishedName   = $site.distinguishedName
                    }
                }
            }

            # Check for sites without Domain Controllers
            if ($Data.DomainControllers) {
                $dcSites = $Data.DomainControllers | ForEach-Object { $_.Site } | Select-Object -Unique

                foreach ($site in $sites) {
                    if ($site.Name -notin $dcSites -and $site.Name -ne 'Default-First-Site-Name') {
                        $findings += [PSCustomObject]@{
                            Issue               = 'Site without Domain Controller'
                            ObjectType          = 'Site'
                            ObjectName          = $site.Name
                            Description         = 'Site has no Domain Controllers'
                            RiskLevel           = 'Medium'
                            Impact              = 'Clients may authenticate to remote DCs over WAN'
                            Recommendation      = 'Add DC to site or configure appropriate site links'
                            DistinguishedName   = $site.distinguishedName
                        }
                    }
                }
            }

        } catch {
            # Error accessing site information
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure proper AD site topology with sites for each location, subnets mapped to sites, and DCs in each site.'
        Impact      = 'Low - Site changes primarily affect authentication routing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# AD Site Topology Configuration
#############################################################################
#
# Proper site configuration provides:
# - Optimal DC selection for authentication
# - Efficient replication topology
# - Reduced WAN traffic
# - Faster logon times for remote users
#
# Issues Found:
$($Finding.Findings | ForEach-Object { "# - $($_.ObjectName): $($_.Issue)" } | Out-String)

#############################################################################
# Create New AD Site
#############################################################################

# Create a new site
New-ADReplicationSite -Name "Site-NewYork" -Description "New York Office"

# Create subnet and associate with site
New-ADReplicationSubnet -Name "10.10.0.0/16" -Site "Site-NewYork" -Location "New York, NY"

#############################################################################
# Associate Existing Subnet with Site
#############################################################################

# Find subnets without site assignments
Get-ADReplicationSubnet -Filter * -Properties Site | Where-Object { -not `$_.Site }

# Assign subnet to site
Set-ADReplicationSubnet -Identity "10.20.0.0/16" -Site "Site-Chicago"

#############################################################################
# Move Domain Controller to Site
#############################################################################

# View current DC site assignments
Get-ADDomainController -Filter * | Select-Object Name, Site

# Move DC to new site
Move-ADDirectoryServer -Identity "DC01" -Site "Site-NewYork"

#############################################################################
# Configure Site Links
#############################################################################

# Create site link between sites
New-ADReplicationSiteLink -Name "NewYork-Chicago" `
    -SitesIncluded "Site-NewYork","Site-Chicago" `
    -Cost 100 `
    -ReplicationFrequencyInMinutes 15

# Configure site link for existing sites
Set-ADReplicationSiteLink -Identity "DEFAULTIPSITELINK" `
    -Cost 100 `
    -ReplicationFrequencyInMinutes 15

#############################################################################
# Verification
#############################################################################

# View all sites
Get-ADReplicationSite -Filter *

# View all subnets with site assignments
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site, Location

# View site links
Get-ADReplicationSiteLink -Filter * | Select-Object Name, SitesIncluded, Cost

# Test DC locator
nltest /dsgetdc:$((Get-ADDomain).DNSRoot) /site:Site-NewYork

"@
            return $commands
        }
    }
}

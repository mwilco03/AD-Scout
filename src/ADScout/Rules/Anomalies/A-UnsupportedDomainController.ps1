@{
    Id          = 'A-UnsupportedDomainController'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Domain Controller Running Unsupported OS'
    Description = 'Detects Domain Controllers running Windows Server versions that are no longer supported by Microsoft. Unsupported operating systems do not receive security updates, leaving them vulnerable to known exploits and compliance violations.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'Windows Server Lifecycle'; Url = 'https://learn.microsoft.com/en-us/lifecycle/products/?products=windows-server' }
        @{ Title = 'End of Support for Windows Server 2012/2012 R2'; Url = 'https://learn.microsoft.com/en-us/lifecycle/announcements/windows-server-2012-2012-r2-end-of-support' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1210', 'T1068')     # Exploitation of Remote Services, Exploitation for Privilege Escalation
    }

    CIS   = @('2.1')
    STIG  = @('V-220706')
    ANSSI = @('R01')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data.NetworkSecurity.DomainControllers) {
            if (-not $dc.IsSupported -or $dc.SecurityRisk -in 'Critical', 'High') {

                # Identify known CVEs for unsupported OS
                $knownVulnerabilities = @()

                if ($dc.OperatingSystem -match '2008|2003|2000') {
                    $knownVulnerabilities += 'MS17-010 (EternalBlue) - Remote Code Execution'
                    $knownVulnerabilities += 'MS14-068 (Kerberos) - Privilege Escalation'
                    $knownVulnerabilities += 'CVE-2020-1472 (Zerologon) - Domain Takeover'
                    $knownVulnerabilities += 'Hundreds of unpatched CVEs since EOL'
                }
                elseif ($dc.OperatingSystem -match '2012') {
                    $knownVulnerabilities += 'CVE-2020-1472 (Zerologon) if unpatched'
                    $knownVulnerabilities += 'CVE-2021-42287/42278 (sAMAccountName spoofing)'
                    $knownVulnerabilities += 'No new security patches since Oct 2023'
                }

                $findings += [PSCustomObject]@{
                    DCName                  = $dc.Name
                    HostName                = $dc.HostName
                    IPv4Address             = $dc.IPv4Address
                    Site                    = $dc.Site
                    OperatingSystem         = $dc.OperatingSystem
                    OSVersion               = $dc.OperatingSystemVersion
                    ServicePack             = $dc.ServicePack
                    IsSupported             = $dc.IsSupported
                    SupportStatus           = $dc.SupportStatus
                    SecurityRisk            = $dc.SecurityRisk
                    IsGlobalCatalog         = $dc.IsGlobalCatalog
                    IsReadOnly              = $dc.IsReadOnly
                    KnownVulnerabilities    = ($knownVulnerabilities -join '; ')
                    PasswordAgeDays         = $dc.PasswordAgeDays
                    LastLogon               = $dc.LastLogonDate
                    ComplianceImpact        = @(
                        'PCI-DSS: Unsupported OS violates Requirement 6.2',
                        'HIPAA: Violates Technical Safeguards',
                        'SOC2: Control failure for system security',
                        'CIS: Critical control violation'
                    ) -join '; '
                    RiskLevel               = $dc.SecurityRisk
                }
            }
        }

        return $findings | Sort-Object -Property @{E='SecurityRisk';D=$true}
    }

    Remediation = @{
        Description = 'Upgrade or replace Domain Controllers running unsupported operating systems. This is a critical security and compliance requirement.'
        Impact      = 'High - Requires planned migration to new DC infrastructure'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: UNSUPPORTED DOMAIN CONTROLLERS
# ================================================================
# These DCs are running End-of-Life operating systems.
# They do NOT receive security patches and are vulnerable to
# known exploits including:
# - EternalBlue (MS17-010)
# - Zerologon (CVE-2020-1472)
# - PrintNightmare (CVE-2021-34527)
# - sAMAccountName spoofing (CVE-2021-42287)

# ================================================================
# IMMEDIATE ACTIONS
# ================================================================

# 1. Identify all unsupported DCs:
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, OperatingSystemVersion

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# DC: $($item.DCName) - $($item.OperatingSystem)
# Status: $($item.SupportStatus)
# Risk: $($item.SecurityRisk)
# ================================================================

# Known Vulnerabilities:
# $($item.KnownVulnerabilities)

"@
            }

            $commands += @"

# ================================================================
# MIGRATION PLAN
# ================================================================

# Phase 1: Deploy new DCs
# 1. Deploy new Windows Server 2022 DCs
# 2. Transfer FSMO roles from old DCs
# 3. Update DNS to prefer new DCs
# 4. Monitor replication health

# Phase 2: Demote old DCs
# 1. Verify all FSMO roles transferred:
netdom query fsmo

# 2. Verify replication:
repadmin /replsummary

# 3. Demote old DC:
# Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartitions

# Phase 3: Cleanup
# 1. Remove computer account from AD
# 2. Remove DNS records
# 3. Decommission server

# ================================================================
# TRANSFER FSMO ROLES
# ================================================================

# View current FSMO holders:
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster

# Move all roles to new DC:
Move-ADDirectoryServerOperationMasterRole -Identity "NewDC01" -OperationMasterRole PDCEmulator,RIDMaster,InfrastructureMaster,SchemaMaster,DomainNamingMaster

# ================================================================
# TEMPORARY HARDENING (Until Migration)
# ================================================================

# If immediate migration is not possible:

# 1. Isolate at network level - strict firewall rules
# 2. Disable unused services
# 3. Enable advanced auditing
# 4. Monitor for exploitation attempts
# 5. Apply last available patches
# 6. Consider Extended Security Updates (ESU) if available

"@
            return $commands
        }
    }
}

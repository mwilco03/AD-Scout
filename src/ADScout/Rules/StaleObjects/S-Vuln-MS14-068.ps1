@{
    Id          = 'S-Vuln-MS14-068'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Kerberos PAC Elevation Vulnerability (MS14-068)'
    Description = 'Detects Domain Controllers that may be vulnerable to MS14-068, a critical Kerberos vulnerability that allows any authenticated user to forge a PAC and elevate to Domain Admin. DCs running Windows Server 2003-2012 R2 without KB3011780 are vulnerable.'
    Severity    = 'Critical'
    Weight      = 100
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'MS14-068 Microsoft Advisory'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068' }
        @{ Title = 'PyKEK Exploit'; Url = 'https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068' }
        @{ Title = 'MITRE ATT&CK'; Url = 'https://attack.mitre.org/techniques/T1558/001/' }
        @{ Title = 'PingCastle Rule S-Vuln-MS14-068'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1558.001', 'T1068')  # Golden Ticket, Exploitation for Privilege Escalation
    }

    CIS   = @()  # Patching addressed via OS-specific CIS benchmarks
    STIG  = @()  # CVE-based vulnerabilities addressed via patching
    ANSSI = @()
    NIST  = @('SI-2', 'RA-5')  # Flaw Remediation, Vulnerability Scanning

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Vulnerable OS versions (before patch)
        # Windows Server 2003, 2008, 2008 R2, 2012, 2012 R2
        # The patch KB3011780 was released November 2014

        $vulnerableOSPatterns = @(
            'Windows Server 2003',
            'Windows Server 2008',      # Includes 2008 and 2008 R2
            'Windows Server 2012'       # Includes 2012 and 2012 R2
        )

        # Build numbers that indicate patched systems (approximate)
        # These are the minimum build numbers after the November 2014 patches
        $patchedBuilds = @{
            '2003' = 5.2     # Actually need to check hotfix
            '2008' = 6.0     # Need hotfix check
            '2008 R2' = 6.1  # Need hotfix check
            '2012' = 6.2     # Need hotfix check
            '2012 R2' = 6.3  # Need hotfix check
        }

        try {
            foreach ($dc in $Data.DomainControllers) {
                $osVersion = $dc.OperatingSystem
                $osBuild = $dc.OperatingSystemVersion
                $dcName = $dc.Name

                # Skip if no OS info
                if (-not $osVersion) { continue }

                # Skip Windows Server 2016+ (not vulnerable)
                if ($osVersion -match 'Server 2016|Server 2019|Server 2022|Server 2025') {
                    continue
                }

                # Check if this is a potentially vulnerable OS
                $isVulnerableOS = $false
                foreach ($pattern in $vulnerableOSPatterns) {
                    if ($osVersion -match [regex]::Escape($pattern)) {
                        $isVulnerableOS = $true
                        break
                    }
                }

                if (-not $isVulnerableOS) { continue }

                # Check hotfix installation if we have that data
                $hasHotfix = $false
                if ($dc.InstalledHotfixes) {
                    # KB3011780 is the critical patch
                    # KB3039066 and later supersede it
                    $patchKBs = @('KB3011780', 'KB3039066', 'KB3045685', 'KB3046002')
                    foreach ($kb in $patchKBs) {
                        if ($dc.InstalledHotfixes -contains $kb) {
                            $hasHotfix = $true
                            break
                        }
                    }
                }

                # If we can't verify hotfix, report as potentially vulnerable
                $certainty = if ($hasHotfix) { 'Patched' } else { 'Potentially Vulnerable' }

                if (-not $hasHotfix) {
                    $findings += [PSCustomObject]@{
                        DCName              = $dcName
                        HostName            = $dc.DNSHostName
                        OperatingSystem     = $osVersion
                        OSVersion           = $osBuild
                        Vulnerability       = 'MS14-068'
                        CVE                 = 'CVE-2014-6324'
                        RequiredPatch       = 'KB3011780'
                        PatchStatus         = $certainty
                        Severity            = 'Critical'
                        CVSS                = '9.0'
                        Risk                = 'Any authenticated user can become Domain Admin'
                        Exploitability      = 'Public exploits available (PyKEK, Mimikatz, Impacket)'
                        AttackScenario      = 'Attacker forges PAC in TGS to claim Domain Admin privileges'
                    }
                }
            }

            # If no DC data, check via ADSI
            if ($Data.DomainControllers.Count -eq 0) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://OU=Domain Controllers,$domainDN"
                    $searcher.Filter = "(objectClass=computer)"
                    $searcher.PropertiesToLoad.AddRange(@('cn', 'operatingSystem', 'operatingSystemVersion', 'dNSHostName'))

                    $dcs = $searcher.FindAll()

                    foreach ($dc in $dcs) {
                        $osVersion = $dc.Properties['operatingsystem'][0]

                        if (-not $osVersion) { continue }

                        # Skip patched versions
                        if ($osVersion -match 'Server 2016|Server 2019|Server 2022|Server 2025') {
                            continue
                        }

                        $isVulnerableOS = $false
                        foreach ($pattern in $vulnerableOSPatterns) {
                            if ($osVersion -match [regex]::Escape($pattern)) {
                                $isVulnerableOS = $true
                                break
                            }
                        }

                        if ($isVulnerableOS) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Properties['cn'][0]
                                HostName            = $dc.Properties['dnshostname'][0]
                                OperatingSystem     = $osVersion
                                Vulnerability       = 'MS14-068'
                                CVE                 = 'CVE-2014-6324'
                                RequiredPatch       = 'KB3011780'
                                PatchStatus         = 'Potentially Vulnerable - Manual Verification Required'
                                Severity            = 'Critical'
                                Risk                = 'Any authenticated user can become Domain Admin'
                            }
                        }
                    }
                } catch {
                    Write-Verbose "S-Vuln-MS14-068: Error querying DCs via ADSI - $_"
                }
            }

        } catch {
            Write-Verbose "S-Vuln-MS14-068: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Apply security update KB3011780 immediately to all Domain Controllers. This is a critical vulnerability that allows any authenticated user to elevate to Domain Admin.'
        Impact      = 'Low - Security update only. Requires DC restart.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# MS14-068 Kerberos PAC Vulnerability Remediation
# CVE-2014-6324 - CRITICAL
#
# Potentially vulnerable Domain Controllers:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): $($_.OperatingSystem) [$($_.PatchStatus)]" } | Out-String)

# THIS IS A CRITICAL VULNERABILITY
# Any authenticated domain user can become Domain Admin!
# Patch IMMEDIATELY

# STEP 1: Download the security update
# KB3011780: https://www.microsoft.com/en-us/download/details.aspx?id=44852

# For different OS versions:
# Windows Server 2003: KB3011780
# Windows Server 2008/2008 R2: KB3011780
# Windows Server 2012/2012 R2: KB3011780

# STEP 2: Check if the patch is already installed
$($Finding.Findings | ForEach-Object { @"
# Check $($_.DCName):
Invoke-Command -ComputerName "$($_.HostName)" -ScriptBlock {
    Get-HotFix -Id KB3011780, KB3039066, KB3045685 -ErrorAction SilentlyContinue |
        Select-Object HotFixID, InstalledOn
}

"@ })

# STEP 3: Install the update on all vulnerable DCs
# Using WSUS or manual installation:

# Manual installation via wusa:
# wusa.exe Windows6.1-KB3011780-x64.msu /quiet /norestart

# STEP 4: Schedule restart during maintenance window
# The update requires a restart to take effect

$($Finding.Findings | ForEach-Object { @"
# Restart $($_.DCName) (schedule appropriately):
# shutdown /r /m \\$($_.HostName) /t 0

"@ })

# STEP 5: Verify patch installation after restart
$($Finding.Findings | ForEach-Object { @"
Invoke-Command -ComputerName "$($_.HostName)" -ScriptBlock {
    `$kb = Get-HotFix -Id KB3011780 -ErrorAction SilentlyContinue
    if (`$kb) { "PATCHED: KB3011780 installed on `$(`$env:COMPUTERNAME)" }
    else { "VULNERABLE: KB3011780 NOT found on `$(`$env:COMPUTERNAME)" }
}

"@ })

# STEP 6: Monitor for exploitation attempts
# Check Security Event Log for Event ID 4769 (TGS requests) with:
# - Unusual encryption types
# - Requests from non-DC sources for DC SPNs
# - Failure audit codes related to PAC validation

# STEP 7: Consider upgrading DCs to Server 2016 or later
# Modern DCs are not vulnerable and provide additional security features

# STEP 8: Rotate krbtgt password twice after patching
# This invalidates any forged tickets that may have been created
# Reset-ComputerMachinePassword (wait for replication)
# Reset-ComputerMachinePassword (second reset)

"@
            return $commands
        }
    }
}

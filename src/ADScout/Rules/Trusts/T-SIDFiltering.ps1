@{
    Id          = 'T-SIDFiltering'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'SID Filtering Disabled on Trust'
    Description = 'Detects domain or forest trusts where SID filtering (quarantine) is disabled. Without SID filtering, a compromised trusted domain can inject arbitrary SIDs to gain privileged access in the trusting domain.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'SID Filtering'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust' }
        @{ Title = 'SID History Attack'; Url = 'https://attack.mitre.org/techniques/T1134/005/' }
        @{ Title = 'Trust Abuse'; Url = 'https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/' }
        @{ Title = 'PingCastle Rule T-SIDFiltering'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1134.005', 'T1199')  # SID-History Injection, Trusted Relationship
    }

    CIS   = @('5.6')
    STIG  = @('V-63631')
    ANSSI = @('R41', 'vuln1_sid_filtering')
    NIST  = @('AC-3', 'AC-17')

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 20
        MaxPoints = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get all trusts
            $trusts = @()

            if ($Data.Trusts) {
                $trusts = $Data.Trusts
            } else {
                # Try to get trusts directly
                try {
                    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
                } catch {
                    # Try ADSI/netdom
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $defaultNC = $rootDSE.defaultNamingContext.ToString()

                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://CN=System,$defaultNC"
                        $searcher.Filter = "(objectClass=trustedDomain)"
                        $searcher.PropertiesToLoad.AddRange(@('name', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes'))

                        $results = $searcher.FindAll()
                        foreach ($result in $results) {
                            $trusts += @{
                                Name = $result.Properties['name'][0]
                                Target = $result.Properties['trustpartner'][0]
                                Direction = $result.Properties['trustdirection'][0]
                                TrustType = $result.Properties['trusttype'][0]
                                TrustAttributes = $result.Properties['trustattributes'][0]
                            }
                        }
                    } catch { }
                }
            }

            foreach ($trust in $trusts) {
                $trustName = $trust.Name ?? $trust.Target ?? 'Unknown'
                $trustDirection = $trust.Direction ?? $trust.TrustDirection
                $trustType = $trust.TrustType ?? $trust.Type
                $trustAttributes = [int]($trust.TrustAttributes ?? $trust.trustAttributes ?? 0)

                # Trust attributes flags
                # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004 (SID filtering enabled for domain trusts)
                # TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008 (forest trust)
                # TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010 (selective auth, implies SID filtering)
                # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040 (treat as external, SID filtering ON)

                $sidFilteringEnabled = $false
                $sidHistoryEnabled = $false

                # Check for SID filtering (quarantine)
                if ($trustAttributes -band 0x4) {
                    $sidFilteringEnabled = $true  # Quarantine enabled
                }

                # Check for SID History (TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL when OFF, SID history allowed)
                # For forest trusts: SID filtering is on by default, SID history can be enabled
                $isForestTrust = ($trustAttributes -band 0x8) -ne 0

                # Check SID history flag
                # NETDOM output check would be more reliable
                try {
                    $netdomOutput = netdom trust $trustName /domain:$env:USERDOMAIN /quarantine 2>$null
                    if ($netdomOutput -match 'SID filtering is not enabled') {
                        $sidFilteringEnabled = $false
                    } elseif ($netdomOutput -match 'SID filtering is enabled') {
                        $sidFilteringEnabled = $true
                    }
                } catch { }

                # For inbound or bidirectional trusts, SID filtering matters
                # Direction: 1=Inbound, 2=Outbound, 3=Bidirectional
                $isInbound = $trustDirection -eq 1 -or $trustDirection -eq 3 -or $trustDirection -match 'Inbound|BiDirectional'

                if ($isInbound -and -not $sidFilteringEnabled) {
                    $findings += [PSCustomObject]@{
                        TrustName           = $trustName
                        TrustDirection      = $( switch ($trustDirection) {
                            1 { 'Inbound' }
                            2 { 'Outbound' }
                            3 { 'Bidirectional' }
                            default { $trustDirection }
                        })
                        TrustType           = $( switch ($trustType) {
                            1 { 'Downlevel (Windows NT)' }
                            2 { 'Uplevel (Windows 2000+)' }
                            3 { 'MIT (Kerberos)' }
                            4 { 'Forest' }
                            default { $trustType }
                        })
                        IsForestTrust       = $isForestTrust
                        SIDFilteringEnabled = $sidFilteringEnabled
                        TrustAttributes     = $trustAttributes
                        Severity            = if ($isForestTrust) { 'Critical' } else { 'High' }
                        Risk                = 'SID filtering disabled on inbound trust'
                        Impact              = 'Trusted domain can inject SIDs to escalate privileges'
                        AttackScenario      = 'Attacker in trusted domain injects Enterprise Admins SID'
                    }
                }

                # Check for SID History enabled on forest trust (separate risk)
                if ($isForestTrust) {
                    try {
                        $netdomOutput = netdom trust $trustName /domain:$env:USERDOMAIN /enablesidhistory 2>$null
                        if ($netdomOutput -match 'SID history is enabled') {
                            $findings += [PSCustomObject]@{
                                TrustName           = $trustName
                                TrustType           = 'Forest Trust'
                                Issue               = 'SID History enabled'
                                Severity            = 'High'
                                Risk                = 'SID history migration enabled on forest trust'
                                Impact              = 'Users from trusted forest can have SID history honored'
                                Recommendation      = 'Disable SID history if migration is complete'
                            }
                        }
                    } catch { }
                }
            }

        } catch {
            Write-Verbose "T-SIDFiltering: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable SID filtering on all inbound domain and forest trusts. Disable SID history if migration is complete.'
        Impact      = 'Medium - May break SID history-based access if migration is ongoing. Test thoroughly.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# SID Filtering Remediation
#
# Trusts with SID filtering issues:
$($Finding.Findings | ForEach-Object { "# - $($_.TrustName): $($_.Risk)" } | Out-String)

# SID filtering (quarantine) protects against:
# - SID history injection attacks
# - Privilege escalation from trusted domains
# - Cross-forest attacks

# Without SID filtering:
# - Attacker can add Enterprise Admins SID to their SID history
# - Authenticate to trusting domain with elevated privileges
# - Full forest compromise from single domain compromise

# STEP 1: List all trusts and their SID filtering status
Write-Host "Trust relationships:" -ForegroundColor Yellow
Get-ADTrust -Filter * | ForEach-Object {
    `$trust = `$_
    `$quarantine = "Unknown"

    try {
        `$output = netdom trust `$trust.Name /domain:`$env:USERDOMAIN /quarantine 2>`$null
        if (`$output -match 'SID filtering is not enabled') { `$quarantine = "DISABLED" }
        elseif (`$output -match 'SID filtering is enabled') { `$quarantine = "Enabled" }
    } catch {}

    [PSCustomObject]@{
        Name = `$trust.Name
        Direction = `$trust.Direction
        TrustType = `$trust.TrustType
        SIDFiltering = `$quarantine
    }
} | Format-Table -AutoSize

# STEP 2: Enable SID filtering on each trust
$($Finding.Findings | Where-Object { $_.SIDFilteringEnabled -eq $false } | ForEach-Object { @"
# Enable SID filtering on trust: $($_.TrustName)
netdom trust $($_.TrustName) /domain:`$env:USERDOMAIN /quarantine:yes
Write-Host "Enabled SID filtering on: $($_.TrustName)" -ForegroundColor Green

"@ })

# STEP 3: Enable SID filtering via PowerShell (alternative)
# Set-ADTrust -Identity "TrustedDomain" -SIDFilteringQuarantined `$true

# STEP 4: Disable SID history on forest trusts (if migration complete)
$($Finding.Findings | Where-Object { $_.Issue -eq 'SID History enabled' } | ForEach-Object { @"
# Disable SID history on forest trust: $($_.TrustName)
netdom trust $($_.TrustName) /domain:`$env:USERDOMAIN /enablesidhistory:no
Write-Host "Disabled SID history on: $($_.TrustName)" -ForegroundColor Green

"@ })

# STEP 5: Verify changes
Write-Host "`nVerifying SID filtering status:" -ForegroundColor Yellow
Get-ADTrust -Filter * | ForEach-Object {
    `$output = netdom trust `$_.Name /domain:`$env:USERDOMAIN /quarantine 2>`$null
    Write-Host "`$(`$_.Name): `$output"
}

# STEP 6: Additional hardening - Selective Authentication
# For highest security, enable selective authentication on the trust:
# This requires explicit permissions for each resource
# netdom trust TrustedDomain /domain:TrustingDomain /selectiveauth:yes

# Or via AD:
# Set-ADTrust -Identity "TrustedDomain" -SelectiveAuthentication `$true

Write-Host @"

ADDITIONAL RECOMMENDATIONS:

1. Enable Selective Authentication
   - Requires explicit "Allowed to Authenticate" permission
   - Most restrictive trust option
   - Use for untrusted partner domains

2. Monitor for SID history abuse:
   - Event ID 4675: SIDs were filtered
   - Event ID 4769: Kerberos service ticket with SID history

3. Regularly audit trust relationships:
   - Remove trusts no longer needed
   - Review trust direction (prefer one-way outbound)

4. Consider trust minimization:
   - Forest trusts instead of domain trusts
   - One-way trusts where possible
   - Shortest trust path

"@ -ForegroundColor Cyan

"@
            return $commands
        }
    }
}

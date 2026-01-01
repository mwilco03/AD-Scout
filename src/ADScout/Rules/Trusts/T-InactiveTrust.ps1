@{
    Id          = 'T-InactiveTrust'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'Inactive or Broken Domain Trust'
    Description = 'Domain trusts exist that are inactive, broken, or point to domains that no longer exist. These orphaned trusts expand the attack surface and may allow exploitation through defunct but trusted connections.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Trusts'

    References  = @(
        @{ Title = 'Domain Trusts'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust' }
        @{ Title = 'Trust Abuse'; Url = 'https://attack.mitre.org/techniques/T1482/' }
        @{ Title = 'Managing Trusts'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/virtual-dc/adds-on-azure-vm' }
    )

    MITRE = @{
        Tactics    = @('TA0007', 'TA0008')  # Discovery, Lateral Movement
        Techniques = @('T1482')  # Domain Trust Discovery
    }

    CIS   = @('5.23')
    STIG  = @()
    ANSSI = @('vuln2_inactive_trust')
    NIST  = @('AC-2')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 10
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($trust in $Data) {
            $trustIssues = @()
            $trustStatus = 'Unknown'

            # Get trust properties
            $targetDomain = $trust.Target
            if (-not $targetDomain) { $targetDomain = $trust.Name }

            $trustDirection = $trust.Direction
            $trustType = $trust.TrustType

            # Check if we can resolve the trusted domain
            $canResolve = $false
            try {
                $dnsResult = [System.Net.Dns]::GetHostAddresses($targetDomain)
                if ($dnsResult) { $canResolve = $true }
            } catch {
                $canResolve = $false
                $trustIssues += "Cannot resolve domain name: $targetDomain"
            }

            # Check trust validation if we can reach it
            if ($canResolve) {
                try {
                    # Try to validate the trust
                    $trustTest = $null
                    if (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
                        # This tests the local domain's channel, not cross-domain
                        # We'll check via LDAP connectivity instead
                    }

                    # Try LDAP connection to remote domain
                    $ldapTest = $false
                    try {
                        $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $targetDomain)
                        $targetDomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                        if ($targetDomainObj) {
                            $ldapTest = $true
                            $trustStatus = 'Active'
                        }
                    } catch {
                        $ldapTest = $false
                        $trustIssues += "Cannot connect to domain: $_"
                        $trustStatus = 'Unreachable'
                    }
                } catch {
                    $trustIssues += "Trust validation failed: $_"
                    $trustStatus = 'Validation Failed'
                }
            } else {
                $trustStatus = 'Unresolvable'
            }

            # Check for other trust issues
            if ($trust.TrustAttributes) {
                # Check for forest transitive trust with SID filtering disabled
                if (($trust.TrustAttributes -band 0x8) -eq 0 -and $trust.ForestTransitive) {
                    $trustIssues += 'SID filtering may be disabled on forest trust'
                }
            }

            # Flag if there are issues
            if ($trustIssues.Count -gt 0 -or $trustStatus -ne 'Active') {
                $findings += [PSCustomObject]@{
                    TrustedDomain       = $targetDomain
                    TrustDirection      = $trustDirection
                    TrustType           = $trustType
                    TrustStatus         = $trustStatus
                    CanResolve          = $canResolve
                    Issues              = ($trustIssues -join '; ')
                    RiskLevel           = if (-not $canResolve) { 'High' } else { 'Medium' }
                    Impact              = 'Orphaned trusts expand attack surface without business benefit'
                    Recommendation      = if (-not $canResolve) { 'Remove orphaned trust' } else { 'Investigate and validate trust' }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and remove inactive or orphaned domain trusts. Validate remaining trusts are still required for business operations.'
        Impact      = 'High - Removing trusts will break cross-domain authentication. Verify trust is not in use before removal.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Review and Clean Up Inactive Domain Trusts
# Inactive/Broken Trusts Found: $($Finding.Findings.Count)

# Affected Trusts:
$($Finding.Findings | ForEach-Object { "# - $($_.TrustedDomain): Status=$($_.TrustStatus), Issues=$($_.Issues)" } | Out-String)

# Step 1: List all current trusts
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes,
    @{N='DisallowTransitivity';E={`$_.TrustAttributes -band 1}},
    @{N='ForestTransitive';E={`$_.TrustAttributes -band 8}},
    @{N='SIDFilteringEnabled';E={`$_.TrustAttributes -band 4}}

# Step 2: Validate each trust
foreach (`$trust in @('$($Finding.Findings.TrustedDomain -join "','")')) {
    Write-Host "Testing trust: `$trust"

    # Test DNS resolution
    try {
        `$dns = [System.Net.Dns]::GetHostAddresses(`$trust)
        Write-Host "  DNS: OK (`$(`$dns[0].IPAddressToString))"
    } catch {
        Write-Host "  DNS: FAILED" -ForegroundColor Red
    }

    # Test LDAP connectivity
    try {
        `$context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', `$trust)
        `$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(`$context)
        Write-Host "  LDAP: OK (`$(`$domain.Name))"
    } catch {
        Write-Host "  LDAP: FAILED" -ForegroundColor Red
    }

    # Test trust relationship (from DC)
    # nltest /domain_trusts
}

# Step 3: Verify trust is not actively used
# Check for:
# - Users from trusted domain in local groups
# - Resources accessed by trusted domain users
# - Applications relying on trust

# Get users from trusted domains in local groups
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {
    `$_.distinguishedName -notmatch (Get-ADDomain).DistinguishedName
}

# Step 4: Remove orphaned trusts (CAREFUL!)
# Remove-ADTrust -Identity "OrphanedDomain.com" -Confirm:`$true

# Step 5: Document remaining trusts
Get-ADTrust -Filter * | Export-Csv -Path "DomainTrusts.csv" -NoTypeInformation

"@
            return $commands
        }
    }
}

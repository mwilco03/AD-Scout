@{
    Id          = 'T-TGTDelegation'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'TGT Delegation Enabled on Forest Trust'
    Description = 'Detects forest trusts where TGT delegation is enabled. This allows services in the trusted forest to request TGTs on behalf of users, enabling potential credential theft and privilege escalation across forest boundaries.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Trusts'

    References  = @(
        @{ Title = 'TGT Delegation Attack'; Url = 'https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d' }
        @{ Title = 'Forest Trust Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models' }
        @{ Title = 'PingCastle Rule T-TGTDelegation'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1558', 'T1550.003')  # Steal or Forge Kerberos Tickets, Pass the Ticket
    }

    CIS   = @()  # Forest trust settings not covered in CIS benchmarks
    STIG  = @()  # Trust delegation STIGs are AD-version specific
    ANSSI = @()
    NIST  = @('AC-4', 'AC-17')  # Information Flow Enforcement, Remote Access

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Trust attribute flags
        $TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
        $TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION = 0x00000200
        $TRUST_ATTRIBUTE_NO_TGT_DELEGATION = 0x00000400

        try {
            foreach ($trust in $Data.Trusts) {
                $trustName = $trust.Name
                $trustAttributes = [int]$trust.TrustAttributes
                $trustDirection = $trust.TrustDirection
                $trustType = $trust.TrustType

                # Check if this is a forest trust
                $isForestTrust = ($trustAttributes -band $TRUST_ATTRIBUTE_FOREST_TRANSITIVE) -ne 0

                # Check TGT delegation settings
                $tgtDelegationEnabled = ($trustAttributes -band $TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION) -ne 0
                $tgtDelegationDisabled = ($trustAttributes -band $TRUST_ATTRIBUTE_NO_TGT_DELEGATION) -ne 0

                # For forest trusts, TGT delegation is concerning
                # For external trusts, it's less common but still a risk
                if ($tgtDelegationEnabled -or (-not $tgtDelegationDisabled -and $isForestTrust)) {
                    $severity = 'High'
                    $risk = 'TGT delegation allows credential forwarding across trust'

                    if ($isForestTrust) {
                        $severity = 'Critical'
                        $risk = 'Forest trust with TGT delegation enables cross-forest credential theft'
                    }

                    $findings += [PSCustomObject]@{
                        TrustName               = $trustName
                        TrustPartner            = $trust.Target
                        TrustDirection          = switch ($trustDirection) {
                            0 { 'Disabled' }
                            1 { 'Inbound' }
                            2 { 'Outbound' }
                            3 { 'Bidirectional' }
                            default { $trustDirection }
                        }
                        TrustType               = switch ($trustType) {
                            1 { 'Windows NT' }
                            2 { 'Active Directory' }
                            3 { 'MIT Kerberos' }
                            default { $trustType }
                        }
                        IsForestTrust           = $isForestTrust
                        TGTDelegationEnabled    = $tgtDelegationEnabled
                        TGTDelegationDisabled   = $tgtDelegationDisabled
                        TrustAttributes         = "0x{0:X8}" -f $trustAttributes
                        Severity                = $severity
                        Risk                    = $risk
                        AttackScenario          = 'Attacker in trusted forest can obtain TGTs for users in this forest via unconstrained delegation'
                    }
                }
            }

            # Also check via ADSI if trust data wasn't collected
            if ($Data.Trusts.Count -eq 0) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://CN=System,$domainDN"
                    $searcher.Filter = "(objectClass=trustedDomain)"
                    $searcher.PropertiesToLoad.AddRange(@('cn', 'trustAttributes', 'trustDirection', 'trustPartner', 'trustType'))

                    $trusts = $searcher.FindAll()

                    foreach ($trust in $trusts) {
                        $trustName = $trust.Properties['cn'][0]
                        $trustAttributes = [int]$trust.Properties['trustattributes'][0]

                        $isForestTrust = ($trustAttributes -band $TRUST_ATTRIBUTE_FOREST_TRANSITIVE) -ne 0
                        $tgtDelegationEnabled = ($trustAttributes -band $TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION) -ne 0
                        $tgtDelegationDisabled = ($trustAttributes -band $TRUST_ATTRIBUTE_NO_TGT_DELEGATION) -ne 0

                        if ($tgtDelegationEnabled -or (-not $tgtDelegationDisabled -and $isForestTrust)) {
                            $findings += [PSCustomObject]@{
                                TrustName               = $trustName
                                TrustPartner            = $trust.Properties['trustpartner'][0]
                                IsForestTrust           = $isForestTrust
                                TGTDelegationEnabled    = $tgtDelegationEnabled
                                TGTDelegationDisabled   = $tgtDelegationDisabled
                                TrustAttributes         = "0x{0:X8}" -f $trustAttributes
                                Severity                = if ($isForestTrust) { 'Critical' } else { 'High' }
                                Risk                    = 'TGT delegation allows credential forwarding across trust'
                            }
                        }
                    }
                } catch {
                    Write-Verbose "T-TGTDelegation: Error querying trusts via ADSI - $_"
                }
            }

        } catch {
            Write-Verbose "T-TGTDelegation: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable TGT delegation on forest trusts by setting the TRUST_ATTRIBUTE_NO_TGT_DELEGATION flag. This prevents cross-forest credential theft via unconstrained delegation.'
        Impact      = 'Medium - May break legitimate cross-forest delegation scenarios. Test applications that use delegation across forests.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# TGT Delegation on Forest Trust Remediation
#
# Affected trusts:
$($Finding.Findings | ForEach-Object { "# - $($_.TrustName): TGT Delegation = $($_.TGTDelegationEnabled), Forest Trust = $($_.IsForestTrust)" } | Out-String)

# TGT delegation allows services using unconstrained delegation in the
# trusted forest to obtain TGTs for users in this forest. This breaks
# the forest security boundary.

# STEP 1: View current trust attributes
Get-ADTrust -Filter * | Select-Object Name, Direction, ForestTransitive,
    @{N='TGTDelegation';E={
        if (`$_.TrustAttributes -band 0x200) { 'Enabled' }
        elseif (`$_.TrustAttributes -band 0x400) { 'Disabled' }
        else { 'Not Set' }
    }},
    @{N='Attributes';E={"0x{0:X}" -f `$_.TrustAttributes}}

# STEP 2: Disable TGT delegation using netdom
# Run from an elevated command prompt on a DC

$($Finding.Findings | ForEach-Object { @"
# Disable TGT delegation for trust: $($_.TrustName)
netdom trust $($Domain.Name) /domain:$($_.TrustPartner) /DisableTGTDelegation:Yes

"@ })

# STEP 3: Alternative using PowerShell (requires AD module)
$($Finding.Findings | ForEach-Object { @"
# Disable TGT delegation for: $($_.TrustName)
Set-ADTrust -Identity "$($_.TrustName)" -TGTDelegation `$false

"@ })

# STEP 4: Verify the change
Get-ADTrust -Filter * | Format-Table Name, @{N='TGTDelegation';E={
    if (`$_.TrustAttributes -band 0x400) { 'Disabled (Secure)' }
    elseif (`$_.TrustAttributes -band 0x200) { 'Enabled (INSECURE)' }
    else { 'Not Set' }
}}

# STEP 5: Also consider enabling Selective Authentication
# This provides additional security by requiring explicit access grants
# netdom trust $($Domain.Name) /domain:TRUSTEDFOREST /SelectiveAuth:Yes

# STEP 6: Review unconstrained delegation in both forests
# Remove unconstrained delegation from servers where possible
Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName, TrustedForDelegation

"@
            return $commands
        }
    }
}

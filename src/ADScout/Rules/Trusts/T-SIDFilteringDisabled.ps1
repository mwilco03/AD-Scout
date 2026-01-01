@{
    Id          = 'T-SIDFilteringDisabled'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'SID Filtering Disabled on Trusts'
    Description = 'Detects trusts where SID filtering (quarantine) is disabled. Without SID filtering, compromised trusted domains can forge SID history to gain access.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Trusts'

    References  = @(
        @{ Title = 'SID Filtering and Claims Transformation'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/sid-filtering-and-claims-transformation' }
        @{ Title = 'How SID History Attacks Work'; Url = 'https://adsecurity.org/?p=1772' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1134.005')          # Access Token Manipulation: SID-History Injection
    }

    CIS   = @('5.7')
    STIG  = @('V-36439')
    ANSSI = @('vuln1_trusts_sidfiltering')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($trust in $Data) {
            # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
            $sidFilteringEnabled = ($trust.TrustAttributes -band 0x00000004) -ne 0

            # For forest trusts, check TRUST_ATTRIBUTE_FOREST_TRANSITIVE without QUARANTINE
            $isForestTrust = ($trust.TrustAttributes -band 0x00000008) -ne 0

            if (-not $sidFilteringEnabled -and $trust.TrustType -in @('External', 'Forest')) {
                $findings += [PSCustomObject]@{
                    TrustedDomain      = $trust.Target
                    TrustDirection     = $trust.Direction
                    TrustType          = $trust.TrustType
                    SIDFilteringStatus = 'Disabled'
                    Risk               = 'SID History injection attacks possible'
                    WhenCreated        = $trust.WhenCreated
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable SID filtering on all external and forest trusts. This prevents SID history attacks from compromised trusted domains.'
        Impact      = 'Medium - May affect users migrated with SID history'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable SID filtering on trusts
# Note: This may affect migrated users who rely on SID history

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Enable SID filtering for: $($item.TrustedDomain)
netdom trust $env:USERDNSDOMAIN /domain:$($item.TrustedDomain) /quarantine:yes

# Verify SID filtering is enabled:
netdom trust $env:USERDNSDOMAIN /domain:$($item.TrustedDomain) /verify

"@
            }
            return $commands
        }
    }
}

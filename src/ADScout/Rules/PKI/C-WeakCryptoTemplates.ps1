@{
    Id          = 'C-WeakCryptoTemplates'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'Certificate Templates with Weak Cryptography'
    Description = 'Detects certificate templates configured with weak cryptographic settings (RSA < 2048 bits, SHA-1, or deprecated algorithms).'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Certificates'

    References  = @(
        @{ Title = 'Key Size Recommendations'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage/configure-cryptographic-settings' }
        @{ Title = 'SHA-1 Deprecation'; Url = 'https://learn.microsoft.com/en-us/security/engineering/sha-1-deprecation' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1588.004')  # Obtain Capabilities: Digital Certificates
    }

    CIS   = @('5.11')
    STIG  = @('V-36443')
    ANSSI = @('vuln2_adcs_weakcrypto')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($template in $Data.Templates) {
            $issues = @()

            # Check minimum key size
            if ($template.MinimumKeySize -lt 2048) {
                $issues += "RSA key size: $($template.MinimumKeySize) bits (should be >= 2048)"
            }

            # Check signature algorithm
            if ($template.SignatureAlgorithm -match 'SHA1|MD5|MD2') {
                $issues += "Weak signature algorithm: $($template.SignatureAlgorithm)"
            }

            # Check hash algorithm
            if ($template.HashAlgorithm -match 'SHA1|MD5|MD2') {
                $issues += "Weak hash algorithm: $($template.HashAlgorithm)"
            }

            if ($issues.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    TemplateName      = $template.Name
                    DisplayName       = $template.DisplayName
                    Issues            = $issues -join '; '
                    MinimumKeySize    = $template.MinimumKeySize
                    SignatureAlgorithm = $template.SignatureAlgorithm
                    HashAlgorithm     = $template.HashAlgorithm
                    DistinguishedName = $template.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Update certificate templates to use RSA 2048+ bit keys and SHA-256 or stronger hashing algorithms.'
        Impact      = 'Low - New certificates will use stronger cryptography'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Update weak cryptographic settings on certificate templates
# Use Certificate Templates Console (certtmpl.msc) or certutil

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Issues: $($item.Issues)

# Set minimum key size to 2048:
certutil -dstemplate "$($item.TemplateName)" msPKI-Minimal-Key-Size 2048

# Note: Signature/hash algorithms may need to be updated via template properties in certtmpl.msc

"@
            }
            return $commands
        }
    }
}

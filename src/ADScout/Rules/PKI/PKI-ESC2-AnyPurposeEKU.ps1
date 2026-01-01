@{
    Id          = 'PKI-ESC2-AnyPurposeEKU'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC2 - Certificate Template with Any Purpose or No EKU'
    Description = 'Detects certificate templates configured with "Any Purpose" EKU or no EKU restrictions. These certificates can be used for any purpose including client authentication, code signing, or as subordinate CA certificates, creating multiple attack paths.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC2'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'Certificate Template EKUs'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')
        Techniques = @('T1649')
    }

    CIS   = @('5.3.2')
    STIG  = @('V-220971')
    ANSSI = @('R66')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

            $templates = Get-ADObject -SearchBase $templatePath -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties * -ErrorAction SilentlyContinue

            foreach ($template in $templates) {
                $ekus = $template.'pKIExtendedKeyUsage'

                # ESC2 conditions:
                # 1. No EKU (null or empty) - means Any Purpose
                # 2. Contains "Any Purpose" OID (2.5.29.37.0)
                # 3. Contains SubCA OID (allows creating subordinate CAs)

                $isVulnerable = $false
                $vulnerabilityType = @()

                if ($null -eq $ekus -or $ekus.Count -eq 0) {
                    $isVulnerable = $true
                    $vulnerabilityType += 'No EKU Defined (Any Purpose)'
                }

                if ($ekus -contains '2.5.29.37.0') {
                    $isVulnerable = $true
                    $vulnerabilityType += 'Any Purpose EKU'
                }

                if (-not $isVulnerable) { continue }

                # Check enrollment permissions
                $acl = Get-Acl "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                $dangerousEnrollees = @()

                foreach ($ace in $acl.Access) {
                    if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and
                        $ace.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') {
                        if ($ace.IdentityReference.Value -match 'Authenticated Users|Domain Users|Domain Computers|Everyone') {
                            $dangerousEnrollees += $ace.IdentityReference.Value
                        }
                    }
                }

                if ($dangerousEnrollees.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        TemplateName        = $template.Name
                        DisplayName         = $template.DisplayName
                        DistinguishedName   = $template.DistinguishedName
                        VulnerabilityType   = ($vulnerabilityType -join ', ')
                        CurrentEKUs         = if ($ekus) { $ekus -join ', ' } else { 'None (Any Purpose)' }
                        DangerousEnrollees  = ($dangerousEnrollees -join ', ')
                        RiskLevel           = 'Critical'
                        AttackPaths         = @(
                            'Client Authentication impersonation',
                            'Code Signing abuse',
                            'Subordinate CA creation (if schema allows)'
                        ) -join '; '
                    }
                }
            }
        }
        catch {
            # AD CS may not be installed
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure specific EKUs for each certificate template. Remove Any Purpose EKU and restrict enrollment.'
        Impact      = 'Medium - Review certificate usage before restricting EKUs'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC2 - ANY PURPOSE / NO EKU VULNERABILITY
# ================================================================
# Templates with "Any Purpose" or no EKU can be used for:
# - Client Authentication (impersonation)
# - Server Authentication
# - Code Signing (malware signing)
# - Subordinate CA (if permitted)

# ================================================================
# VULNERABLE TEMPLATES
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Template: $($item.TemplateName)
# Vulnerability: $($item.VulnerabilityType)
# Current EKUs: $($item.CurrentEKUs)
# Dangerous Enrollees: $($item.DangerousEnrollees)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# For each vulnerable template, specify explicit EKUs:

# Open Certificate Templates MMC:
# certtmpl.msc

# 1. Right-click template > Properties
# 2. Go to "Extensions" tab
# 3. Select "Application Policies"
# 4. Click "Edit"
# 5. Remove "Any Purpose" if present
# 6. Add ONLY the specific purposes needed:
#    - Client Authentication (1.3.6.1.5.5.7.3.2)
#    - Server Authentication (1.3.6.1.5.5.7.3.1)
#    - Code Signing (1.3.6.1.5.5.7.3.3)
#    - etc.

# Common EKU OIDs:
# 1.3.6.1.5.5.7.3.1  - Server Authentication
# 1.3.6.1.5.5.7.3.2  - Client Authentication
# 1.3.6.1.5.5.7.3.3  - Code Signing
# 1.3.6.1.5.5.7.3.4  - Email Protection
# 1.3.6.1.4.1.311.20.2.2 - Smart Card Logon

# ================================================================
# RESTRICT ENROLLMENT
# ================================================================

# If template must remain with broad EKUs:
# Restrict WHO can enroll

`$templateDN = "CN=TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"

# Remove broad enrollment:
# Remove "Authenticated Users" and "Domain Users"
# Add only specific groups that need this template

"@
            return $commands
        }
    }
}

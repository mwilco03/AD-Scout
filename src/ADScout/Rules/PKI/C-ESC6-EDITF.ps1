@{
    Id          = 'C-ESC6-EDITF'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC6 - CA Allows Arbitrary SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)'
    Description = 'The Certificate Authority has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing certificate requesters to specify an arbitrary Subject Alternative Name (SAN). Attackers can request certificates with a SAN for any user, including Domain Admins, and use them for authentication.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned ESC6'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/request-certificate-subject-alternative-name' }
        @{ Title = 'CA Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ca-security' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006', 'TA0003')  # Privilege Escalation, Credential Access, Persistence
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @()
    STIG  = @()
    ANSSI = @('vuln1_adcs_esc6')
    NIST  = @('SC-12')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check each CA for EDITF_ATTRIBUTESUBJECTALTNAME2
        foreach ($ca in $Data) {
            $caName = $ca.Name
            if (-not $caName) { $caName = $ca.'cn' }

            $policyFlags = $ca.'flags'
            if (-not $policyFlags) { $policyFlags = $ca.PolicyModuleFlags }

            # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 = 262144
            $editfFlag = 0x40000
            $hasEDITF = $false

            try {
                # Try to query CA configuration
                if ($ca.ConfigString) {
                    $caConfig = $ca.ConfigString
                } else {
                    $caConfig = "$($ca.ComputerName)\$caName"
                }

                # Use certutil to check the flag
                $certutilOutput = certutil -getreg "CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags" 2>$null

                if ($certutilOutput) {
                    # Parse the EditFlags value
                    $editFlagsMatch = $certutilOutput | Select-String -Pattern 'EditFlags REG_DWORD = ([0-9a-fx]+)'
                    if ($editFlagsMatch) {
                        $editFlagsValue = [int]$editFlagsMatch.Matches.Groups[1].Value
                        $hasEDITF = ($editFlagsValue -band $editfFlag) -eq $editfFlag
                    }
                }
            } catch {
                # Could not check via certutil, try registry if available
            }

            # Also check from AD attributes if available
            if (-not $hasEDITF -and $policyFlags) {
                try {
                    if ($policyFlags -is [int] -or $policyFlags -is [long]) {
                        $hasEDITF = ($policyFlags -band $editfFlag) -eq $editfFlag
                    }
                } catch { }
            }

            if ($hasEDITF) {
                $findings += [PSCustomObject]@{
                    CAName              = $caName
                    CAHost              = $ca.ComputerName
                    ConfigString        = "$($ca.ComputerName)\$caName"
                    EDITF_SUBJECTALTNAME2 = $true
                    RiskLevel           = 'Critical'
                    AttackPath          = 'Request cert with SAN for any user -> Authenticate as that user'
                    Impact              = 'Any user can impersonate any other user including Domain Admin'
                    Exploitability      = 'Easy - single certificate request'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on all Certificate Authorities unless there is a specific business requirement and proper access controls are in place.'
        Impact      = 'Medium - Applications that rely on specifying custom SANs may break. Review certificate templates first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix ESC6 - Disable EDITF_ATTRIBUTESUBJECTALTNAME2
# CRITICAL: This flag allows complete domain takeover!
# Vulnerable CAs: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.CAName) on $($_.CAHost)" } | Out-String)

# ATTACK SCENARIO:
# 1. Attacker finds CA with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
# 2. Attacker requests a certificate with SAN: UPN=administrator@domain.com
# 3. CA issues certificate with the requested SAN
# 4. Attacker authenticates to any service as Administrator

# IMMEDIATE REMEDIATION:

# Step 1: Disable the flag on each CA
foreach (`$ca in @('$($Finding.Findings.CAName -join "','")')) {
    Write-Host "Disabling EDITF_ATTRIBUTESUBJECTALTNAME2 on `$ca"

    # Get current EditFlags
    certutil -getreg "CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags"

    # Calculate new value (remove 0x40000 flag)
    # Current EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000 = 262144
    # Run this on the CA server:

    # `$currentFlags = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\`$ca\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy").EditFlags
    # `$newFlags = `$currentFlags -band (-bnot 0x40000)
    # certutil -setreg "CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags" `$newFlags
}

# Alternative: Use certutil directly (run on CA server)
# certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Step 2: Restart the Certificate Services
# net stop certsvc && net start certsvc

# Step 3: Verify the change
certutil -getreg "CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags"
# Should NOT include 0x40000 in the flags

# Step 4: Audit recently issued certificates
# Check for certificates with suspicious SANs
certutil -view -out "SerialNumber,UPN,SAN" -restrict "NotAfter>`$(Get-Date).AddDays(-30)"

# Step 5: Consider revoking suspicious certificates
# If certificates were issued with admin SANs to non-admin users

# NOTE: If SAN requests are legitimately needed:
# - Use certificate templates with "Supply in the request" disabled
# - Use "Build from this Active Directory information" instead
# - Restrict enrollment permissions to trusted principals

"@
            return $commands
        }
    }
}

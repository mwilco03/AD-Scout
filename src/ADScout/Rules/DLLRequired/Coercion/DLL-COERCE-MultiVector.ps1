<#
.SYNOPSIS
    Detects Domain Controllers vulnerable to multiple coercion attack vectors.

.DESCRIPTION
    Uses SMBLibrary to perform comprehensive coercion vulnerability assessment.
    Detects all major coercion vectors: PrinterBug, PetitPotam, DFSCoerce,
    ShadowCoerce, and CheeseOunce.

.NOTES
    Rule ID    : DLL-COERCE-MultiVector
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-COERCE-MultiVector'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'Multiple Coercion Attack Vectors Available'
    Description = 'Multiple authentication coercion vectors are available on Domain Controllers, significantly increasing the attack surface for NTLM relay attacks.'
    Severity    = 'Critical'
    Weight      = 60
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'Coercion Attack Overview'; Url = 'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications' }
        @{ Title = 'PrinterBug'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'PetitPotam'; Url = 'https://github.com/topotam/PetitPotam' }
        @{ Title = 'DFSCoerce'; Url = 'https://github.com/Wh04m1001/DFSCoerce' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1187', 'T1557.001')
    }

    CIS   = @('5.2', '5.3')
    ANSSI = @('vuln1_coercion')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
        Maximum = 120
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-COERCE-MultiVector: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-CoercionScan -ComputerName $dcName -TimeoutMs 10000

                # Only report if multiple vectors are vulnerable
                if ($scanResult.Status -eq 'Success' -and $scanResult.VulnerableCount -ge 2) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        VulnerableVectors     = ($scanResult.VulnerableVectors -join ', ')
                        VectorCount           = $scanResult.VulnerableCount
                        PrinterBug            = $scanResult.PrinterBug.Vulnerable
                        PetitPotam            = $scanResult.PetitPotam.Vulnerable
                        DFSCoerce             = $scanResult.DFSCoerce.Vulnerable
                        ShadowCoerce          = $scanResult.ShadowCoerce.Vulnerable
                        CheeseOunce           = $scanResult.CheeseOunce.Vulnerable
                        RiskLevel             = $scanResult.RiskLevel
                        AttackVector          = 'Authentication coercion -> NTLM Relay -> Domain Compromise'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-COERCE-MultiVector: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Implement comprehensive coercion attack mitigations.'
        Impact      = 'Medium - Requires service changes and NTLM restrictions.'
        Script      = {
            param($Finding, $Domain)

            @"
# Comprehensive Coercion Attack Mitigation
#
# Multiple coercion vectors detected - implement defense in depth:

# 1. DISABLE PRINT SPOOLER ON DCs (blocks PrinterBug)
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# 2. APPLY KB5005413 (blocks PetitPotam)
# Install latest Windows security updates

# 3. ENABLE EPA ON ADCS (prevents relay to certificate services)
# On ADCS IIS:
# appcmd set config "Default Web Site/CertSrv" `
#     -section:windowsAuthentication /extendedProtection.tokenChecking:"Require"

# 4. REQUIRE SMB SIGNING (prevents SMB relay)
Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force

# 5. RESTRICT NTLM (most comprehensive protection)
# Via Group Policy:
# "Network security: Restrict NTLM: Incoming NTLM traffic" = "Deny all"
# "Network security: Restrict NTLM: NTLM authentication in this domain" = "Deny all"

# Before blocking NTLM, enable auditing to identify dependencies:
# "Network security: Restrict NTLM: Audit NTLM authentication in this domain" = "Enable all"

# Check NTLM usage:
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 100 |
    Select-Object TimeCreated, Message

# 6. ENABLE LDAP SIGNING AND CHANNEL BINDING
# Prevents LDAP relay
# Via Group Policy or registry

# 7. USE RPC FILTERS (blocks specific RPC calls)
# Block EFSRPC, DFSNM, FSRVP UUIDs at firewall/filter level

# 8. DEPLOY CREDENTIAL GUARD (prevents credential theft)
# Requires compatible hardware and GPO configuration

# Verify mitigations:
Get-Service Spooler | Select-Object Status, StartType
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
"@
        }
    }
}

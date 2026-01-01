<#
.SYNOPSIS
    Detects PetitPotam (EFSRPC) coercion vulnerability on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary to detect if EFSRPC is accessible on Domain Controllers.
    PetitPotam enables authentication coercion attacks that can lead to
    domain compromise when combined with ADCS relay attacks.

.NOTES
    Rule ID    : DLL-COERCE-PetitPotam
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-COERCE-PetitPotam'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'PetitPotam (EFSRPC) Coercion Vulnerable'
    Description = 'EFSRPC is accessible on Domain Controllers, enabling PetitPotam coercion attacks that can lead to domain compromise via NTLM relay.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'PetitPotam'; Url = 'https://github.com/topotam/PetitPotam' }
        @{ Title = 'Microsoft Advisory'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/ADV210003' }
        @{ Title = 'Mitigating NTLM Relay'; Url = 'https://support.microsoft.com/kb5005413' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1187', 'T1557.001')
    }

    CIS   = @('5.3')
    STIG  = @('V-78123')
    ANSSI = @('vuln1_petitpotam')
    NIST  = @('IA-2', 'SC-23')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-COERCE-PetitPotam: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-EFSRPCScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.Vulnerable) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        EFSRPCAccessible      = $scanResult.EFSRPCPipeAccessible
                        AccessiblePipe        = $scanResult.AccessiblePipe
                        PetitPotamVulnerable  = $scanResult.PetitPotamVulnerable
                        AnonymousAccess       = $scanResult.AnonymousAccess
                        RiskLevel             = 'Critical'
                        AttackPath            = 'PetitPotam -> NTLM Relay -> ADCS -> DC Certificate -> DCSync'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-COERCE-PetitPotam: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Apply KB5005413 patch, enable EPA on ADCS, and restrict NTLM.'
        Impact      = 'Medium - NTLM restrictions may affect legacy applications.'
        Script      = {
            param($Finding, $Domain)

            @"
# Mitigate PetitPotam Attack
#
# PetitPotam Attack Chain:
# 1. Attacker uses MS-EFSRPC to coerce DC authentication
# 2. DC authenticates to attacker-controlled server via NTLM
# 3. Attacker relays NTLM to ADCS Web Enrollment
# 4. Attacker obtains certificate as the DC
# 5. Attacker authenticates as DC and performs DCSync

# Step 1: Apply Security Updates (KB5005413)
# Install the latest Windows security updates on all DCs

# Step 2: Enable Extended Protection for Authentication (EPA) on ADCS
# On ADCS servers, configure IIS:
# appcmd set config "Default Web Site/CertSrv" `
#     -section:system.webServer/security/authentication/windowsAuthentication `
#     /extendedProtection.tokenChecking:"Require" /commit:apphost

# Step 3: Block EFS RPC over SMB (via RPC Filter or Firewall)
# Create RPC filter to block MS-EFSRPC UUID:
# c681d488-d850-11d0-8c52-00c04fd90f7e

# Using netsh RPC filter:
# netsh rpc filter add rule layer=um actiontype=block
# netsh rpc filter add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
# netsh rpc filter add filter

# Step 4: Restrict NTLM (strongest protection)
# Via GPO:
# "Network security: Restrict NTLM: Incoming NTLM traffic" = "Deny all accounts"
# "Network security: Restrict NTLM: NTLM authentication in this domain" = "Deny all"

# Step 5: Require SMB Signing
# Prevents relay even if coercion succeeds
Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force

# Verification:
# Test with PetitPotam detection tool in controlled environment
"@
        }
    }
}

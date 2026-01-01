<#
.SYNOPSIS
    Detects DFSCoerce vulnerability on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary to detect if DFSNM (DFS Namespace Management) is
    accessible for DFSCoerce attacks. Similar to PetitPotam but uses
    the MS-DFSNM protocol.

.NOTES
    Rule ID    : DLL-COERCE-DFSCoerce
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-COERCE-DFSCoerce'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'DFSCoerce (MS-DFSNM) Coercion Vulnerable'
    Description = 'DFSNM is accessible on Domain Controllers, enabling DFSCoerce authentication coercion attacks.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'DFSCoerce'; Url = 'https://github.com/Wh04m1001/DFSCoerce' }
        @{ Title = 'MS-DFSNM Protocol'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1187', 'T1557.001')
    }

    ANSSI = @('vuln1_dfscoerce')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-COERCE-DFSCoerce: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-DFSCoerceScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.DFSCoerceVulnerable) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        DFSPipeAccessible     = $scanResult.DFSPipeAccessible
                        NetDFSAccessible      = $scanResult.NetDFSAccessible
                        AnonymousAccess       = $scanResult.AnonymousAccess
                        RiskLevel             = 'High'
                        AttackVector          = 'DFSCoerce -> NTLM Relay -> Domain Compromise'
                        Protocol              = 'MS-DFSNM'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-COERCE-DFSCoerce: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure RPC filters to block DFSNM coercion and enable SMB signing.'
        Impact      = 'Low to Medium - DFS functionality may be affected.'
        Script      = {
            param($Finding, $Domain)

            @"
# Mitigate DFSCoerce Attack

# DFSCoerce uses MS-DFSNM to coerce authentication similar to PetitPotam

# Step 1: Create RPC filter to block DFSNM coercion
# MS-DFSNM UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673

netsh rpc filter add rule layer=um actiontype=block
netsh rpc filter add condition field=if_uuid matchtype=equal data=4fc742e0-4a10-11cf-8273-00aa004ae673
netsh rpc filter add filter

# Step 2: Require SMB signing (prevents relay)
Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force

# Step 3: Restrict NTLM authentication
# Via Group Policy:
# "Network security: Restrict NTLM: Incoming NTLM traffic" = "Deny all"

# Step 4: Enable Extended Protection on ADCS
# Prevents relay to certificate services

# Verify:
netsh rpc filter show filter
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature

# Note: If DFS is required, ensure proper authentication is enforced
"@
        }
    }
}

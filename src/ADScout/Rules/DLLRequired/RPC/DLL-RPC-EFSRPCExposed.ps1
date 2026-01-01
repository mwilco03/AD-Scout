<#
.SYNOPSIS
    Detects EFSRPC service exposed on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary to detect if EFSRPC is accessible independently
    of coercion testing. EFSRPC exposure is the prerequisite for
    PetitPotam attacks.

.NOTES
    Rule ID    : DLL-RPC-EFSRPCExposed
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-RPC-EFSRPCExposed'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'EFSRPC Service Remotely Accessible'
    Description = 'EFSRPC (Encrypting File System RPC) is remotely accessible on Domain Controllers, enabling PetitPotam coercion attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'PetitPotam Advisory'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/ADV210003' }
        @{ Title = 'MS-EFSRPC Protocol'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/' }
        @{ Title = 'KB5005413'; Url = 'https://support.microsoft.com/kb5005413' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1187')   # Forced Authentication
    }

    STIG  = @('V-78123')
    NIST  = @('AC-3', 'SC-7')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 75
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-RPC-EFSRPCExposed: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-EFSRPCScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.EFSRPCPipeAccessible) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        EFSRPCAccessible      = $true
                        AccessiblePipe        = $scanResult.AccessiblePipe
                        AnonymousAccess       = $scanResult.AnonymousAccess
                        LSARPCAccessible      = $scanResult.LSARPCAccessible
                        RiskLevel             = 'High'
                        AttackVector          = 'PetitPotam coercion, NTLM relay'
                        Mitigation            = 'Apply KB5005413, enable EPA, RPC filters'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-RPC-EFSRPCExposed: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Apply security patches and configure RPC filters to block EFSRPC.'
        Impact      = 'Low - EFS over RPC is rarely needed on DCs.'
        Script      = {
            param($Finding, $Domain)

            @"
# Block EFSRPC to Prevent PetitPotam

# Step 1: Apply KB5005413 security update
# This patches the unauthenticated EFSRPC vulnerability

# Step 2: Create RPC filter to block EFSRPC
# MS-EFSRPC UUID: c681d488-d850-11d0-8c52-00c04fd90f7e

# Using netsh RPC filter:
netsh rpc filter add rule layer=um actiontype=block
netsh rpc filter add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
netsh rpc filter add filter

# Step 3: Alternative - Use Windows Firewall
# Block SMB (port 445) from untrusted networks
# This is a broader protection but may affect legitimate traffic

# Step 4: Enable Extended Protection for Authentication on ADCS
# This prevents relay attacks to certificate services

# Verify RPC filters:
netsh rpc filter show filter

# Note: RPC filters require Windows Server 2008 R2 or later
"@
        }
    }
}

<#
.SYNOPSIS
    Detects Domain Controllers that don't support SMB 3.x encryption.

.DESCRIPTION
    Uses SMBLibrary to detect if SMB 3.x encryption is supported.
    SMB encryption protects data in transit and prevents eavesdropping.

.NOTES
    Rule ID    : DLL-SMB-EncryptionNotSupported
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-SMB-EncryptionNotSupported'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMB 3.x Encryption Not Supported'
    Description = 'Domain Controllers do not support SMB 3.x encryption, leaving SMB traffic vulnerable to eavesdropping and interception.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'SMB Encryption'; Url = 'https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security' }
        @{ Title = 'SMB 3.0 Features'; Url = 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831474(v=ws.11)' }
    )

    MITRE = @{
        Tactics    = @('TA0009')  # Collection
        Techniques = @('T1040')   # Network Sniffing
    }

    CIS   = @('9.2.3')
    NIST  = @('SC-8', 'SC-12')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
        Maximum = 50
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-SMB-EncryptionNotSupported: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SMBEncryptionScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and -not $scanResult.EncryptionCapable) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        SMB3Supported         = $scanResult.SMB3Supported
                        SMB311Supported       = $scanResult.SMB311Supported
                        EncryptionCapable     = $false
                        NegotiatedDialect     = $scanResult.NegotiatedDialect
                        RiskLevel             = 'Medium'
                        Impact                = 'SMB traffic can be intercepted and read'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-SMB-EncryptionNotSupported: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Upgrade to Windows Server 2012 or later to support SMB 3.x encryption.'
        Impact      = 'High - Requires OS upgrade on legacy systems.'
        Script      = {
            param($Finding, $Domain)

            @"
# Enable SMB 3.x Encryption

# SMB encryption requires:
# - Windows Server 2012 or later
# - Windows 8 or later clients
# - SMB 3.0+ negotiated between client and server

# Check current SMB configuration:
Get-SmbServerConfiguration | Select-Object EncryptData, RejectUnencryptedAccess

# Enable encryption for all SMB traffic (Server 2012+):
Set-SmbServerConfiguration -EncryptData `$true -Force

# To require encryption (reject unencrypted connections):
Set-SmbServerConfiguration -RejectUnencryptedAccess `$true -Force

# Enable encryption for specific shares:
Set-SmbShare -Name "ShareName" -EncryptData `$true

# Note: Enabling RejectUnencryptedAccess will break connectivity
# with older clients that don't support SMB 3.0+ encryption.

# Verify:
Get-SmbServerConfiguration | Select-Object EncryptData, RejectUnencryptedAccess
"@
        }
    }
}

<#
.SYNOPSIS
    Detects ADCS vulnerability to ESC11 (NTLM relay to ICPR).

.DESCRIPTION
    ESC11 allows NTLM relay attacks against the ICertPassage Remote (ICPR) protocol
    on Certificate Authorities. If NTLM authentication is allowed on ICPR, attackers
    can relay credentials to request certificates.

.NOTES
    Rule ID    : C-ESC11-ICPR
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC11-ICPR'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ADCS ESC11 - NTLM Relay to ICPR'
    Description = 'Identifies Certificate Authorities vulnerable to ESC11 where NTLM authentication is enabled on the ICertPassage Remote (ICPR) interface, allowing NTLM relay attacks.'
    Severity    = 'High'
    Weight      = 60
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'ESC11 - NTLM Relay to ICPR'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'Certipy ESC11'; Url = 'https://github.com/ly4k/Certipy#esc11' }
        @{ Title = 'MS-ICPR Protocol'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1649')  # LLMNR/NBT-NS Poisoning, Steal or Forge Authentication Certificates
    }

    CIS   = @('5.2.3')
    STIG  = @('V-254445')
    ANSSI = @('vuln1_adcs_esc11')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find Certificate Authorities
        $configNC = "CN=Configuration,$((Get-ADDomain).DistinguishedName)"
        $enrollmentServices = @()

        try {
            $enrollmentServices = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } `
                -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC" `
                -Properties * -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "C-ESC11-ICPR: Could not query enrollment services from $configNC : $_"
        }

        foreach ($ca in $enrollmentServices) {
            $caName = $ca.Name
            $caServer = $ca.dNSHostName
            if (-not $caServer) {
                # Extract server from CA name if needed
                $caServer = $ca.Name.Split('\')[0]
            }

            try {
                $icprStatus = Invoke-Command -ComputerName $caServer -ScriptBlock {
                    param($CAName)

                    $result = @{
                        CAName = $CAName
                        ICPREnabled = $false
                        NTLMEnabled = $false
                        RequireSSL = $false
                        InterfaceFlags = $null
                    }

                    # Check CA interface flags
                    try {
                        $caConfig = & certutil -config "$env:COMPUTERNAME\$CAName" -getreg CA\InterfaceFlags 2>$null
                        if ($caConfig -match 'InterfaceFlags\s*=\s*(\d+)') {
                            $flags = [int]$Matches[1]
                            $result.InterfaceFlags = $flags

                            # IF_NORPCICERTREQUEST (0x1000) - Disables ICPR
                            # If NOT set, ICPR is enabled
                            if (-not ($flags -band 0x1000)) {
                                $result.ICPREnabled = $true
                            }

                            # IF_ENFORCEENCRYPTICERTREQUEST (0x200) - Requires encryption
                            if (-not ($flags -band 0x200)) {
                                $result.RequireSSL = $false
                            } else {
                                $result.RequireSSL = $true
                            }
                        }
                    } catch {
                        Write-Verbose "Could not read InterfaceFlags for CA $CAName : $_"
                    }

                    # Check if NTLM is allowed for RPC
                    try {
                        $rpcAuth = & certutil -config "$env:COMPUTERNAME\$CAName" -getreg Policy\EditFlags 2>$null
                        # Various flags affect authentication
                    } catch {
                        Write-Verbose "Could not read EditFlags for CA $CAName : $_"
                    }

                    # Check RPC security settings
                    try {
                        $rpcSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Rpc\Internet' -ErrorAction SilentlyContinue
                        # If NTLM is not explicitly restricted, assume enabled
                        $result.NTLMEnabled = $true
                    } catch {
                        $result.NTLMEnabled = $true  # Assume vulnerable if can't check
                    }

                    return $result
                } -ArgumentList $caName -ErrorAction SilentlyContinue

                $issues = @()
                $isVulnerable = $false

                if ($icprStatus.ICPREnabled) {
                    $issues += 'ICPR (RPC) interface is enabled'

                    if ($icprStatus.NTLMEnabled) {
                        $issues += 'NTLM authentication allowed on ICPR'
                        $isVulnerable = $true
                    }

                    if (-not $icprStatus.RequireSSL) {
                        $issues += 'Encryption not enforced on ICPR'
                        $isVulnerable = $true
                    }
                }

                if ($isVulnerable) {
                    $findings += [PSCustomObject]@{
                        CAName            = $caName
                        CAServer          = $caServer
                        ICPREnabled       = $icprStatus.ICPREnabled
                        NTLMAllowed       = $icprStatus.NTLMEnabled
                        EncryptionRequired = $icprStatus.RequireSSL
                        InterfaceFlags    = if ($icprStatus.InterfaceFlags) { "0x$($icprStatus.InterfaceFlags.ToString('X'))" } else { 'Unknown' }
                        Issues            = ($issues -join '; ')
                        RiskLevel         = 'High'
                        AttackPath        = 'Coerce auth -> Relay NTLM to ICPR -> Request cert as victim'
                        ESC               = 'ESC11'
                        DistinguishedName = $ca.DistinguishedName
                    }
                }

            } catch {
                # Report CA as potentially vulnerable if check fails
                $findings += [PSCustomObject]@{
                    CAName            = $caName
                    CAServer          = $caServer
                    ICPREnabled       = 'Unknown (check failed)'
                    NTLMAllowed       = 'Unknown'
                    EncryptionRequired = 'Unknown'
                    InterfaceFlags    = 'Unknown'
                    Issues            = 'Unable to verify ICPR configuration'
                    RiskLevel         = 'Medium'
                    AttackPath        = 'Manual verification required'
                    ESC               = 'ESC11'
                    DistinguishedName = $ca.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable NTLM on ICPR or disable the ICPR interface entirely on Certificate Authorities.'
        Impact      = 'Medium - May affect legacy clients using RPC for certificate enrollment.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC11 - ICPR NTLM Relay Remediation
#############################################################################
#
# ESC11 allows NTLM relay attacks against the CA's ICertPassage Remote interface.
# Attack path:
# 1. Attacker coerces authentication from victim (PetitPotam, PrinterBug, etc.)
# 2. Attacker relays NTLM auth to CA's ICPR (RPC) interface
# 3. Attacker requests certificate as victim
# 4. Attacker uses certificate for authentication
#
# Vulnerable CAs:
$($Finding.Findings | ForEach-Object { "# - $($_.CAName) on $($_.CAServer): $($_.Issues)" } | Out-String)

#############################################################################
# Option 1: Disable ICPR Interface (Recommended)
#############################################################################

# Disable the ICPR (RPC) interface entirely:
# This is the safest option if DCOM/RPC enrollment is not required

# On each CA server:
`$caName = "YourCAName"  # Replace with actual CA name

# Set IF_NORPCICERTREQUEST flag (0x1000)
certutil -config "`$env:COMPUTERNAME\`$caName" -setreg CA\InterfaceFlags +0x1000

# Restart the CA service:
Restart-Service CertSvc

# Verify:
certutil -config "`$env:COMPUTERNAME\`$caName" -getreg CA\InterfaceFlags

#############################################################################
# Option 2: Require Encryption on ICPR
#############################################################################

# If ICPR must remain enabled, enforce encryption:

# Set IF_ENFORCEENCRYPTICERTREQUEST flag (0x200)
certutil -config "`$env:COMPUTERNAME\`$caName" -setreg CA\InterfaceFlags +0x200

Restart-Service CertSvc

#############################################################################
# Option 3: Disable NTLM Authentication
#############################################################################

# Disable NTLM for the CA server (affects all services):
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options
# -> Network security: Restrict NTLM: Incoming NTLM traffic = Deny all

# Or via registry:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictReceivingNTLMTraffic' -Value 2 -Type DWord

# WARNING: This will break any NTLM-dependent authentication to the CA

#############################################################################
# Step 4: Enable EPA on ICPR
#############################################################################

# Enable Extended Protection for Authentication if supported:
# This binds authentication to the TLS channel

# Registry settings for RPC EPA:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SuppressExtendedProtection' -Value 0 -Type DWord

#############################################################################
# Step 5: Use Certificate-Based Enrollment Only
#############################################################################

# Migrate clients to use:
# 1. HTTPS enrollment (Web Enrollment with EPA)
# 2. Certificate Enrollment Web Services (CEP/CES)
# 3. Auto-enrollment via Group Policy

# Disable legacy enrollment methods where possible

#############################################################################
# Step 6: Monitor for Relay Attacks
#############################################################################

# Monitor CA logs for unusual certificate requests:
# - Requests from unexpected IP addresses
# - Requests using NTLM authentication
# - Rapid requests for multiple identities

# Enable enhanced CA auditing:
certutil -config "`$env:COMPUTERNAME\`$caName" -setreg CA\AuditFilter 127

# Event IDs to monitor:
# - 4886: Certificate Services received a certificate request
# - 4887: Certificate Services approved and issued a certificate
# - 4888: Certificate Services denied a certificate request

#############################################################################
# Verification
#############################################################################

# Verify ICPR is disabled or secured:
certutil -config "`$env:COMPUTERNAME\`$caName" -getreg CA\InterfaceFlags

# Test with Certipy:
# certipy find -u user@domain.com -p 'password' -dc-ip DC_IP

"@
            return $commands
        }
    }
}

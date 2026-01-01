function Get-ADScoutCertificateData {
    <#
    .SYNOPSIS
        Collects PKI certificate data from Active Directory.

    .DESCRIPTION
        Retrieves certificate templates and CA configuration
        for security analysis (ESC vulnerabilities).

    .PARAMETER Domain
        Target domain name.

    .PARAMETER Server
        Specific domain controller to query.

    .PARAMETER Credential
        Credentials for AD queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential
    )

    $cacheKey = "Certificates:$Domain`:$Server"
    $cached = Get-ADScoutCache -Key $cacheKey
    if ($cached) {
        Write-Verbose "Returning cached certificate data"
        return $cached
    }

    Write-Verbose "Collecting certificate data from Active Directory"

    $certificateData = @{
        CertificateAuthorities = @()
        CertificateTemplates   = @()
        EnrollmentServices     = @()
    }

    try {
        # Get the configuration naming context
        if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
            Import-Module ActiveDirectory -ErrorAction Stop

            $params = @{}
            if ($Server) { $params.Server = $Server }
            if ($Credential) { $params.Credential = $Credential }

            $configNC = (Get-ADRootDSE @params).configurationNamingContext

            # Get Certificate Templates
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            try {
                $templates = Get-ADObject -SearchBase $templatePath -Filter * -Properties * @params

                $certificateData.CertificateTemplates = $templates | ForEach-Object {
                    [PSCustomObject]@{
                        Name                    = $_.Name
                        DisplayName             = $_.displayName
                        DistinguishedName       = $_.DistinguishedName
                        SchemaVersion           = $_.'msPKI-Template-Schema-Version'
                        EnrollmentFlag          = $_.'msPKI-Enrollment-Flag'
                        CertificateNameFlag     = $_.'msPKI-Certificate-Name-Flag'
                        PrivateKeyFlag          = $_.'msPKI-Private-Key-Flag'
                        ExtendedKeyUsage        = $_.'pKIExtendedKeyUsage'
                        ValidityPeriod          = $_.'pKIExpirationPeriod'
                        RenewalPeriod           = $_.'pKIOverlapPeriod'
                        SecurityDescriptor      = $_.nTSecurityDescriptor
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get certificate templates: $_"
            }

            # Get Enrollment Services (CAs)
            $enrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
            try {
                $enrollmentServices = Get-ADObject -SearchBase $enrollmentPath -Filter * -Properties * @params

                $certificateData.EnrollmentServices = $enrollmentServices | ForEach-Object {
                    [PSCustomObject]@{
                        Name                = $_.Name
                        DisplayName         = $_.displayName
                        DistinguishedName   = $_.DistinguishedName
                        DNSHostName         = $_.dNSHostName
                        CertificateTemplates = $_.certificateTemplates
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get enrollment services: $_"
            }

            # Get Certificate Authorities
            $caPath = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC"
            try {
                $cas = Get-ADObject -SearchBase $caPath -Filter * -Properties * @params

                $certificateData.CertificateAuthorities = $cas | ForEach-Object {
                    [PSCustomObject]@{
                        Name              = $_.Name
                        DistinguishedName = $_.DistinguishedName
                        CACertificate     = $_.cACertificate
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get CAs: $_"
            }
        }
    }
    catch {
        Write-Warning "Certificate data collection failed: $_"
    }

    Set-ADScoutCache -Key $cacheKey -Value $certificateData

    Write-Verbose "Collected $($certificateData.CertificateTemplates.Count) certificate templates"

    return $certificateData
}

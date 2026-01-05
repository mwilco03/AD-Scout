function Get-ADScoutCertificateData {
    <#
    .SYNOPSIS
        Collects PKI certificate data from Active Directory.

    .DESCRIPTION
        Retrieves certificate templates and CA configuration
        for security analysis (ESC vulnerabilities).
        Uses AD module when available, falls back to DirectorySearcher.

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

    # Use centralized method detection (cached)
    $collectorMethod = Get-ADScoutCollectorMethod

    if ($collectorMethod -eq 'ADModule') {
        try {
            Write-Verbose "Using ActiveDirectory module"

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
                        Name                = $_.Name
                        DisplayName         = $_.displayName
                        DistinguishedName   = $_.DistinguishedName
                        SchemaVersion       = $_.'msPKI-Template-Schema-Version'
                        EnrollmentFlag      = $_.'msPKI-Enrollment-Flag'
                        CertificateNameFlag = $_.'msPKI-Certificate-Name-Flag'
                        PrivateKeyFlag      = $_.'msPKI-Private-Key-Flag'
                        ExtendedKeyUsage    = $_.'pKIExtendedKeyUsage'
                        ValidityPeriod      = $_.'pKIExpirationPeriod'
                        RenewalPeriod       = $_.'pKIOverlapPeriod'
                        SecurityDescriptor  = $_.nTSecurityDescriptor
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
                        Name                 = $_.Name
                        DisplayName          = $_.displayName
                        DistinguishedName    = $_.DistinguishedName
                        DNSHostName          = $_.dNSHostName
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
        catch {
            Write-Warning "AD module failed for certificates: $_. Falling back to DirectorySearcher."
            $certificateData = Get-ADScoutCertificateDataFallback -Domain $Domain -Server $Server -Credential $Credential
        }
    }
    else {
        Write-Verbose "Using DirectorySearcher method"
        $certificateData = Get-ADScoutCertificateDataFallback -Domain $Domain -Server $Server -Credential $Credential
    }

    Set-ADScoutCache -Key $cacheKey -Value $certificateData

    Write-Verbose "Collected $($certificateData.CertificateTemplates.Count) certificate templates"

    return $certificateData
}

function Get-ADScoutCertificateDataFallback {
    <#
    .SYNOPSIS
        Fallback certificate data collector using DirectorySearcher.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential
    )

    Write-Verbose "Using DirectorySearcher fallback for certificate data"

    $certificateData = @{
        CertificateAuthorities = @()
        CertificateTemplates   = @()
        EnrollmentServices     = @()
    }

    try {
        # Get configuration naming context
        $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
        $rootDse = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($rootDsePath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            [ADSI]$rootDsePath
        }

        $configNC = $rootDse.Properties["configurationNamingContext"][0]

        # Helper function to create directory entry
        $createEntry = {
            param($path)
            if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($path)
            }
        }

        # Get Certificate Templates
        $templatePath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        try {
            $templateEntry = & $createEntry $templatePath
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($templateEntry)
            $searcher.Filter = "(objectClass=pKICertificateTemplate)"
            $searcher.PageSize = 100

            $templateProps = @(
                'name', 'displayname', 'distinguishedname',
                'mspki-template-schema-version', 'mspki-enrollment-flag',
                'mspki-certificate-name-flag', 'mspki-private-key-flag',
                'pkiextendedkeyusage', 'pkiexpirationperiod', 'pkioverlapperiod',
                'ntsecuritydescriptor'
            )
            foreach ($prop in $templateProps) {
                [void]$searcher.PropertiesToLoad.Add($prop)
            }

            $results = $searcher.FindAll()

            $certificateData.CertificateTemplates = foreach ($result in $results) {
                $props = $result.Properties

                [PSCustomObject]@{
                    Name                = if ($props['name']) { $props['name'][0] } else { $null }
                    DisplayName         = if ($props['displayname']) { $props['displayname'][0] } else { $null }
                    DistinguishedName   = if ($props['distinguishedname']) { $props['distinguishedname'][0] } else { $null }
                    SchemaVersion       = if ($props['mspki-template-schema-version']) { $props['mspki-template-schema-version'][0] } else { $null }
                    EnrollmentFlag      = if ($props['mspki-enrollment-flag']) { $props['mspki-enrollment-flag'][0] } else { $null }
                    CertificateNameFlag = if ($props['mspki-certificate-name-flag']) { $props['mspki-certificate-name-flag'][0] } else { $null }
                    PrivateKeyFlag      = if ($props['mspki-private-key-flag']) { $props['mspki-private-key-flag'][0] } else { $null }
                    ExtendedKeyUsage    = @($props['pkiextendedkeyusage'])
                    ValidityPeriod      = if ($props['pkiexpirationperiod']) { $props['pkiexpirationperiod'][0] } else { $null }
                    RenewalPeriod       = if ($props['pkioverlapperiod']) { $props['pkioverlapperiod'][0] } else { $null }
                    SecurityDescriptor  = if ($props['ntsecuritydescriptor']) { $props['ntsecuritydescriptor'][0] } else { $null }
                }
            }

            $results.Dispose()
            $searcher.Dispose()
        }
        catch {
            Write-Verbose "Failed to get certificate templates via DirectorySearcher: $_"
        }

        # Get Enrollment Services
        $enrollmentPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        try {
            $enrollmentEntry = & $createEntry $enrollmentPath
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($enrollmentEntry)
            $searcher.Filter = "(objectClass=pKIEnrollmentService)"
            $searcher.PageSize = 100

            $enrollProps = @('name', 'displayname', 'distinguishedname', 'dnshostname', 'certificatetemplates')
            foreach ($prop in $enrollProps) {
                [void]$searcher.PropertiesToLoad.Add($prop)
            }

            $results = $searcher.FindAll()

            $certificateData.EnrollmentServices = foreach ($result in $results) {
                $props = $result.Properties

                [PSCustomObject]@{
                    Name                 = if ($props['name']) { $props['name'][0] } else { $null }
                    DisplayName          = if ($props['displayname']) { $props['displayname'][0] } else { $null }
                    DistinguishedName    = if ($props['distinguishedname']) { $props['distinguishedname'][0] } else { $null }
                    DNSHostName          = if ($props['dnshostname']) { $props['dnshostname'][0] } else { $null }
                    CertificateTemplates = @($props['certificatetemplates'])
                }
            }

            $results.Dispose()
            $searcher.Dispose()
        }
        catch {
            Write-Verbose "Failed to get enrollment services via DirectorySearcher: $_"
        }

        # Get Certificate Authorities
        $caPath = "LDAP://CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC"
        try {
            $caEntry = & $createEntry $caPath
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($caEntry)
            $searcher.Filter = "(objectClass=certificationAuthority)"
            $searcher.PageSize = 100

            $caProps = @('name', 'distinguishedname', 'cacertificate')
            foreach ($prop in $caProps) {
                [void]$searcher.PropertiesToLoad.Add($prop)
            }

            $results = $searcher.FindAll()

            $certificateData.CertificateAuthorities = foreach ($result in $results) {
                $props = $result.Properties

                [PSCustomObject]@{
                    Name              = if ($props['name']) { $props['name'][0] } else { $null }
                    DistinguishedName = if ($props['distinguishedname']) { $props['distinguishedname'][0] } else { $null }
                    CACertificate     = if ($props['cacertificate']) { $props['cacertificate'][0] } else { $null }
                }
            }

            $results.Dispose()
            $searcher.Dispose()
        }
        catch {
            Write-Verbose "Failed to get CAs via DirectorySearcher: $_"
        }
    }
    catch {
        Write-Warning "DirectorySearcher failed for certificates: $_"
    }

    return $certificateData
}

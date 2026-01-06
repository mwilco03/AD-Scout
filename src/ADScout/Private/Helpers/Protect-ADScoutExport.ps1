function Protect-ADScoutExport {
    <#
    .SYNOPSIS
        Encrypts AD-Scout export data for secure storage and transmission.

    .DESCRIPTION
        Provides encryption-at-rest for sensitive assessment data using:
        - Password-based encryption (AES-256-CBC with PBKDF2)
        - Certificate-based encryption (CMS/PKCS#7)

        Encrypted exports include integrity verification and metadata.

    .PARAMETER InputPath
        Path to the file to encrypt.

    .PARAMETER OutputPath
        Path for the encrypted output file. Defaults to input path with .enc extension.

    .PARAMETER Password
        SecureString password for password-based encryption.

    .PARAMETER Certificate
        X509Certificate2 for certificate-based encryption.

    .PARAMETER CertificateThumbprint
        Thumbprint of certificate in local store.

    .PARAMETER DeleteOriginal
        Remove the unencrypted original after encryption.

    .EXAMPLE
        Protect-ADScoutExport -InputPath "findings.json" -Password (Read-Host -AsSecureString)

    .EXAMPLE
        Protect-ADScoutExport -InputPath "findings.json" -CertificateThumbprint "ABC123..."

    .OUTPUTS
        PSCustomObject with encryption metadata
    #>
    [CmdletBinding(DefaultParameterSetName = 'Password')]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputPath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter(Mandatory, ParameterSetName = 'Password')]
        [SecureString]$Password,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter()]
        [switch]$DeleteOriginal
    )

    try {
        # Determine output path
        if (-not $OutputPath) {
            $OutputPath = "$InputPath.enc"
        }

        # Read input file
        $plainBytes = [System.IO.File]::ReadAllBytes($InputPath)
        $fileHash = Get-FileHash -Path $InputPath -Algorithm SHA256

        # Create metadata header
        $metadata = @{
            EncryptedAt     = (Get-Date).ToString('o')
            OriginalName    = [System.IO.Path]::GetFileName($InputPath)
            OriginalSize    = $plainBytes.Length
            OriginalHash    = $fileHash.Hash
            EncryptionType  = $PSCmdlet.ParameterSetName
            ADScoutVersion  = (Get-Module ADScout -ErrorAction SilentlyContinue).Version.ToString()
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Password' {
                # Password-based encryption using AES-256-CBC
                $encryptedData = Protect-DataWithPassword -PlainBytes $plainBytes -Password $Password

                $metadata.Algorithm = 'AES-256-CBC'
                $metadata.KDF = 'PBKDF2-SHA256'
                $metadata.Iterations = 100000

                # Combine metadata + salt + IV + encrypted data
                $metadataJson = $metadata | ConvertTo-Json -Compress
                $metadataBytes = [System.Text.Encoding]::UTF8.GetBytes($metadataJson)

                $output = @{
                    Version     = 1
                    Type        = 'PasswordEncrypted'
                    Metadata    = [Convert]::ToBase64String($metadataBytes)
                    Salt        = [Convert]::ToBase64String($encryptedData.Salt)
                    IV          = [Convert]::ToBase64String($encryptedData.IV)
                    Data        = [Convert]::ToBase64String($encryptedData.CipherBytes)
                }

                $output | ConvertTo-Json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
            }

            'Certificate' {
                # Certificate-based encryption using CMS
                $encryptedBytes = Protect-CmsMessage -Content $plainBytes -To $Certificate -OutFile $null
                $metadata.Algorithm = 'CMS/PKCS#7'
                $metadata.RecipientThumbprint = $Certificate.Thumbprint

                $metadataJson = $metadata | ConvertTo-Json -Compress
                $metadataBytes = [System.Text.Encoding]::UTF8.GetBytes($metadataJson)

                $output = @{
                    Version     = 1
                    Type        = 'CertificateEncrypted'
                    Metadata    = [Convert]::ToBase64String($metadataBytes)
                    Data        = [Convert]::ToBase64String($encryptedBytes)
                }

                $output | ConvertTo-Json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
            }

            'Thumbprint' {
                # Find certificate by thumbprint
                $cert = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                        Where-Object { $_.Thumbprint -eq $CertificateThumbprint } |
                        Select-Object -First 1

                if (-not $cert) {
                    throw "Certificate with thumbprint $CertificateThumbprint not found"
                }

                # Recurse with found certificate
                return Protect-ADScoutExport -InputPath $InputPath -OutputPath $OutputPath -Certificate $cert -DeleteOriginal:$DeleteOriginal
            }
        }

        # Delete original if requested
        if ($DeleteOriginal) {
            # Secure delete - overwrite then remove
            $random = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $overwriteBytes = [byte[]]::new($plainBytes.Length)
            $random.GetBytes($overwriteBytes)
            [System.IO.File]::WriteAllBytes($InputPath, $overwriteBytes)
            Remove-Item -Path $InputPath -Force
            Write-Verbose "Original file securely deleted"
        }

        Write-Verbose "Encrypted file saved to: $OutputPath"

        return [PSCustomObject]@{
            EncryptedPath   = $OutputPath
            OriginalPath    = $InputPath
            EncryptionType  = $metadata.EncryptionType
            OriginalHash    = $metadata.OriginalHash
            EncryptedAt     = $metadata.EncryptedAt
            OriginalDeleted = $DeleteOriginal.IsPresent
        }
    }
    catch {
        Write-Error "Encryption failed: $_"
    }
}

function Unprotect-ADScoutExport {
    <#
    .SYNOPSIS
        Decrypts AD-Scout encrypted export data.

    .PARAMETER InputPath
        Path to the encrypted file.

    .PARAMETER OutputPath
        Path for the decrypted output.

    .PARAMETER Password
        SecureString password for password-encrypted files.

    .PARAMETER Certificate
        Certificate with private key for certificate-encrypted files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputPath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [SecureString]$Password,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        # Read encrypted file
        $encryptedData = Get-Content -Path $InputPath -Raw | ConvertFrom-Json

        if ($encryptedData.Version -ne 1) {
            throw "Unsupported encryption version: $($encryptedData.Version)"
        }

        # Parse metadata
        $metadataBytes = [Convert]::FromBase64String($encryptedData.Metadata)
        $metadata = [System.Text.Encoding]::UTF8.GetString($metadataBytes) | ConvertFrom-Json

        # Determine output path
        if (-not $OutputPath) {
            $OutputPath = $metadata.OriginalName
        }

        switch ($encryptedData.Type) {
            'PasswordEncrypted' {
                if (-not $Password) {
                    $Password = Read-Host -Prompt "Enter decryption password" -AsSecureString
                }

                $salt = [Convert]::FromBase64String($encryptedData.Salt)
                $iv = [Convert]::FromBase64String($encryptedData.IV)
                $cipherBytes = [Convert]::FromBase64String($encryptedData.Data)

                $plainBytes = Unprotect-DataWithPassword -CipherBytes $cipherBytes -Password $Password -Salt $salt -IV $iv
            }

            'CertificateEncrypted' {
                if (-not $Certificate) {
                    # Try to find certificate by thumbprint
                    $thumbprint = $metadata.RecipientThumbprint
                    $Certificate = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                                   Where-Object { $_.Thumbprint -eq $thumbprint -and $_.HasPrivateKey } |
                                   Select-Object -First 1

                    if (-not $Certificate) {
                        throw "Certificate with private key not found. Thumbprint: $thumbprint"
                    }
                }

                $cmsBytes = [Convert]::FromBase64String($encryptedData.Data)
                $plainBytes = Unprotect-CmsMessage -Content $cmsBytes
            }

            default {
                throw "Unknown encryption type: $($encryptedData.Type)"
            }
        }

        # Verify integrity
        $tempPath = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllBytes($tempPath, $plainBytes)
        $decryptedHash = (Get-FileHash -Path $tempPath -Algorithm SHA256).Hash
        Remove-Item -Path $tempPath -Force

        if ($decryptedHash -ne $metadata.OriginalHash) {
            throw "Integrity check failed. File may be corrupted or tampered with."
        }

        # Write decrypted file
        [System.IO.File]::WriteAllBytes($OutputPath, $plainBytes)

        Write-Verbose "Decrypted file saved to: $OutputPath"

        return [PSCustomObject]@{
            DecryptedPath  = $OutputPath
            OriginalName   = $metadata.OriginalName
            IntegrityValid = $true
            DecryptedAt    = (Get-Date).ToString('o')
        }
    }
    catch {
        Write-Error "Decryption failed: $_"
    }
}

function Protect-DataWithPassword {
    <#
    .SYNOPSIS
        Encrypts data using password-based AES-256-CBC.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$PlainBytes,

        [Parameter(Mandatory)]
        [SecureString]$Password
    )

    # Generate salt and derive key
    $salt = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($salt)

    # Convert SecureString to bytes
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr)
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($passwordString)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
    }

    # PBKDF2 key derivation
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $pbkdf2.GetBytes(32)  # 256 bits
    $iv = $pbkdf2.GetBytes(16)   # 128 bits

    # AES encryption
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $encryptor = $aes.CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)

    # Clear sensitive data
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    [Array]::Clear($key, 0, $key.Length)
    $aes.Dispose()

    return @{
        Salt        = $salt
        IV          = $iv
        CipherBytes = $cipherBytes
    }
}

function Unprotect-DataWithPassword {
    <#
    .SYNOPSIS
        Decrypts data using password-based AES-256-CBC.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$CipherBytes,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [Parameter(Mandatory)]
        [byte[]]$Salt,

        [Parameter(Mandatory)]
        [byte[]]$IV
    )

    # Convert SecureString to bytes
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr)
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($passwordString)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
    }

    # PBKDF2 key derivation
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $Salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $pbkdf2.GetBytes(32)

    # AES decryption
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $IV

    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)

    # Clear sensitive data
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    [Array]::Clear($key, 0, $key.Length)
    $aes.Dispose()

    return $plainBytes
}

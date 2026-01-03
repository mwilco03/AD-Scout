function Get-ADScoutSecret {
    <#
    .SYNOPSIS
        Retrieves secrets using SecretManagement or fallback methods.

    .DESCRIPTION
        Provides a unified interface for retrieving secrets from various sources:
        - Microsoft.PowerShell.SecretManagement module (Azure KeyVault, etc.)
        - Windows Credential Manager
        - Encrypted local storage (fallback)

    .PARAMETER Name
        The name/key of the secret to retrieve.

    .PARAMETER VaultName
        The secret vault to use (if using SecretManagement).

    .PARAMETER AsPlainText
        Return the secret as plain text string instead of SecureString.

    .EXAMPLE
        Get-ADScoutSecret -Name "JIRA-ApiToken"
        Retrieves the JIRA API token from the default vault.

    .EXAMPLE
        Get-ADScoutSecret -Name "SMTP-Password" -VaultName "AzureKeyVault" -AsPlainText
        Retrieves the SMTP password from Azure KeyVault as plain text.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$VaultName,

        [Parameter()]
        [switch]$AsPlainText
    )

    $secret = $null

    # Try SecretManagement module first
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement) {
        try {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

            $getSecretParams = @{ Name = "ADScout-$Name" }
            if ($VaultName) {
                $getSecretParams.Vault = $VaultName
            }

            $secret = Get-Secret @getSecretParams -ErrorAction Stop

            if ($AsPlainText -and $secret -is [securestring]) {
                $secret = [PSCredential]::new('user', $secret).GetNetworkCredential().Password
            }

            return $secret
        }
        catch {
            Write-Verbose "SecretManagement lookup failed: $_"
        }
    }

    # Try Windows Credential Manager
    try {
        $credTarget = "ADScout:$Name"
        $cred = Get-StoredCredential -Target $credTarget -ErrorAction SilentlyContinue

        if ($cred) {
            $secret = if ($AsPlainText) {
                $cred.GetNetworkCredential().Password
            }
            else {
                $cred.Password
            }
            return $secret
        }
    }
    catch {
        Write-Verbose "Credential Manager lookup failed: $_"
    }

    # Fallback to local encrypted storage
    $secretPath = Join-Path $env:USERPROFILE ".adscout\secrets\$Name.secret"
    if (Test-Path $secretPath) {
        try {
            $encrypted = Get-Content $secretPath -Raw
            $secureString = $encrypted | ConvertTo-SecureString

            $secret = if ($AsPlainText) {
                [PSCredential]::new('user', $secureString).GetNetworkCredential().Password
            }
            else {
                $secureString
            }
            return $secret
        }
        catch {
            Write-Verbose "Local secret retrieval failed: $_"
        }
    }

    Write-Warning "Secret not found: $Name"
    return $null
}

function Set-ADScoutSecret {
    <#
    .SYNOPSIS
        Stores a secret for AD-Scout use.

    .DESCRIPTION
        Stores secrets using the best available method:
        - SecretManagement module if available
        - Windows Credential Manager if available
        - Encrypted local file as fallback

    .PARAMETER Name
        The name/key for the secret.

    .PARAMETER Secret
        The secret value (SecureString or plain text).

    .PARAMETER VaultName
        Target vault for SecretManagement.

    .PARAMETER Credential
        Store as a full credential (username + password).

    .EXAMPLE
        Set-ADScoutSecret -Name "JIRA-ApiToken" -Secret (Read-Host -AsSecureString)
        Stores the JIRA API token securely.

    .EXAMPLE
        Set-ADScoutSecret -Name "SMTP" -Credential (Get-Credential)
        Stores SMTP credentials.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(ParameterSetName = 'Secret')]
        [object]$Secret,

        [Parameter(ParameterSetName = 'Credential')]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$VaultName
    )

    $secretName = "ADScout-$Name"

    # Convert plain text to SecureString if needed
    if ($Secret -is [string]) {
        $secureSecret = $Secret | ConvertTo-SecureString -AsPlainText -Force
    }
    elseif ($Secret -is [securestring]) {
        $secureSecret = $Secret
    }
    elseif ($Credential) {
        $secureSecret = $Credential.Password
    }

    # Try SecretManagement first
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement) {
        try {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

            $setSecretParams = @{
                Name   = $secretName
                Secret = $secureSecret
            }
            if ($VaultName) {
                $setSecretParams.Vault = $VaultName
            }

            Set-Secret @setSecretParams -ErrorAction Stop
            Write-Host "✓ Secret stored in SecretManagement vault" -ForegroundColor Green
            return
        }
        catch {
            Write-Verbose "SecretManagement storage failed: $_"
        }
    }

    # Try Windows Credential Manager
    try {
        $credTarget = "ADScout:$Name"

        if ($Credential) {
            cmdkey /add:$credTarget /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password) | Out-Null
        }
        else {
            $plainSecret = [PSCredential]::new('user', $secureSecret).GetNetworkCredential().Password
            cmdkey /add:$credTarget /user:"ADScout" /pass:$plainSecret | Out-Null
        }

        Write-Host "✓ Secret stored in Windows Credential Manager" -ForegroundColor Green
        return
    }
    catch {
        Write-Verbose "Credential Manager storage failed: $_"
    }

    # Fallback to encrypted local storage
    $secretDir = Join-Path $env:USERPROFILE ".adscout\secrets"
    if (-not (Test-Path $secretDir)) {
        $null = New-Item -ItemType Directory -Path $secretDir -Force
        # Set restrictive ACL
        $acl = Get-Acl $secretDir
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl $secretDir $acl
    }

    $secretPath = Join-Path $secretDir "$Name.secret"
    $encrypted = $secureSecret | ConvertFrom-SecureString
    $encrypted | Set-Content -Path $secretPath -Encoding UTF8

    if ($Credential) {
        $credPath = Join-Path $secretDir "$Name.user"
        $Credential.UserName | Set-Content -Path $credPath -Encoding UTF8
    }

    Write-Host "✓ Secret stored in encrypted local storage" -ForegroundColor Green
    Write-Warning "Local storage uses DPAPI - secret is tied to this user/machine"
}

function Remove-ADScoutSecret {
    <#
    .SYNOPSIS
        Removes a stored secret.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$VaultName
    )

    $secretName = "ADScout-$Name"

    # Remove from SecretManagement
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement) {
        try {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

            $removeParams = @{ Name = $secretName }
            if ($VaultName) {
                $removeParams.Vault = $VaultName
            }

            if ($PSCmdlet.ShouldProcess($secretName, "Remove from SecretManagement")) {
                Remove-Secret @removeParams -ErrorAction SilentlyContinue
            }
        }
        catch { }
    }

    # Remove from Credential Manager
    try {
        $credTarget = "ADScout:$Name"
        if ($PSCmdlet.ShouldProcess($credTarget, "Remove from Credential Manager")) {
            cmdkey /delete:$credTarget 2>&1 | Out-Null
        }
    }
    catch { }

    # Remove local storage
    $secretPath = Join-Path $env:USERPROFILE ".adscout\secrets\$Name.secret"
    $credPath = Join-Path $env:USERPROFILE ".adscout\secrets\$Name.user"

    if ($PSCmdlet.ShouldProcess($secretPath, "Remove local secret file")) {
        if (Test-Path $secretPath) { Remove-Item $secretPath -Force }
        if (Test-Path $credPath) { Remove-Item $credPath -Force }
    }

    Write-Host "✓ Secret removed: $Name" -ForegroundColor Green
}

function Get-ADScoutCredential {
    <#
    .SYNOPSIS
        Retrieves a credential for AD-Scout integrations.

    .DESCRIPTION
        Wrapper for Get-ADScoutSecret that returns a PSCredential object.
        Useful for JIRA, email, and other integrations requiring credentials.

    .PARAMETER Name
        The name of the stored credential.

    .EXAMPLE
        $cred = Get-ADScoutCredential -Name "JIRA"
        Connect-JiraServer -Credential $cred

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$VaultName
    )

    $password = Get-ADScoutSecret -Name $Name -VaultName $VaultName

    if (-not $password) {
        return $null
    }

    # Try to get username
    $username = $null
    $userPath = Join-Path $env:USERPROFILE ".adscout\secrets\$Name.user"
    if (Test-Path $userPath) {
        $username = Get-Content $userPath -Raw
    }

    if (-not $username) {
        $username = Read-Host "Enter username for $Name"
    }

    if ($password -is [string]) {
        $password = $password | ConvertTo-SecureString -AsPlainText -Force
    }

    [PSCredential]::new($username, $password)
}

function Get-StoredCredential {
    <#
    .SYNOPSIS
        Helper to retrieve Windows Credential Manager credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target
    )

    # Use cmdkey to check if credential exists
    $output = cmdkey /list:$Target 2>&1

    if ($output -match 'not found') {
        return $null
    }

    # For full credential retrieval, we'd need CredRead API
    # This is a simplified version - just checking existence
    # In production, consider using CredentialManager module

    Write-Verbose "Credential exists for target: $Target"
    return $null  # Would need P/Invoke for actual retrieval
}

function Initialize-ADScoutSecretVault {
    <#
    .SYNOPSIS
        Sets up SecretManagement with a vault for AD-Scout.

    .DESCRIPTION
        Configures the SecretManagement module with a vault for storing
        AD-Scout credentials securely.

    .PARAMETER VaultType
        Type of vault to create: Local, AzureKeyVault, HashiCorpVault.

    .PARAMETER VaultName
        Name for the vault. Defaults to "ADScoutVault".

    .EXAMPLE
        Initialize-ADScoutSecretVault -VaultType Local
        Creates a local SecretStore vault.

    .EXAMPLE
        Initialize-ADScoutSecretVault -VaultType AzureKeyVault -VaultName "prod-adscout-kv"
        Configures Azure KeyVault integration.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Local', 'AzureKeyVault', 'HashiCorpVault')]
        [string]$VaultType,

        [Parameter()]
        [string]$VaultName = 'ADScoutVault',

        [Parameter()]
        [hashtable]$VaultParameters = @{}
    )

    # Check for SecretManagement
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
        Write-Host "Installing Microsoft.PowerShell.SecretManagement..." -ForegroundColor Cyan
        Install-Module Microsoft.PowerShell.SecretManagement -Force -Scope CurrentUser
    }

    Import-Module Microsoft.PowerShell.SecretManagement

    switch ($VaultType) {
        'Local' {
            # Install SecretStore if needed
            if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
                Write-Host "Installing Microsoft.PowerShell.SecretStore..." -ForegroundColor Cyan
                Install-Module Microsoft.PowerShell.SecretStore -Force -Scope CurrentUser
            }

            # Register vault
            $vaultParams = @{
                Name         = $VaultName
                ModuleName   = 'Microsoft.PowerShell.SecretStore'
                DefaultVault = $true
            }

            Register-SecretVault @vaultParams

            # Configure for non-interactive use (optional)
            if ($VaultParameters.NoPassword) {
                Set-SecretStoreConfiguration -Scope CurrentUser -Authentication None -Confirm:$false
            }

            Write-Host "✓ Local SecretStore vault '$VaultName' configured" -ForegroundColor Green
        }

        'AzureKeyVault' {
            if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
                throw "Az.KeyVault module required. Install with: Install-Module Az.KeyVault"
            }

            $kvParams = @{
                Name       = $VaultName
                ModuleName = 'Az.KeyVault'
                VaultParameters = @{
                    AZKVaultName = $VaultParameters.KeyVaultName
                    SubscriptionId = $VaultParameters.SubscriptionId
                }
            }

            Register-SecretVault @kvParams

            Write-Host "✓ Azure KeyVault '$($VaultParameters.KeyVaultName)' registered as '$VaultName'" -ForegroundColor Green
        }

        'HashiCorpVault' {
            Write-Warning "HashiCorp Vault integration requires manual setup."
            Write-Host "See: https://github.com/jspearman/SecretManagement.Hashicorp.Vault.KV"
        }
    }
}

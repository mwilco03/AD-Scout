#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for the EphemeralPersistence category rules.

.DESCRIPTION
    Validates ephemeral persistence detection rules including login scripts,
    shadow credentials, GPO scripts, profile paths, and Terminal Services persistence.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force
}

Describe 'E-LoginScript Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'E-LoginScript'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'E-LoginScript'
        }

        It 'Should be in EphemeralPersistence category' {
            $rule.Category | Should -Be 'EphemeralPersistence'
        }

        It 'Should have MITRE ATT&CK mapping for logon scripts' {
            $rule.MITRE.Techniques | Should -Contain 'T1037.001'
        }
    }

    Context 'Rule Execution with Login Scripts' {
        BeforeAll {
            $mockDomain = [PSCustomObject]@{
                Name = 'test.local'
                DNSRoot = 'test.local'
            }

            $mockUsers = @(
                # User with external UNC script path - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'external_script_user'
                    DistinguishedName = 'CN=ExternalScriptUser,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ScriptPath        = '\\external.evil.com\share\script.bat'
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-30)
                }
                # Privileged user with local script - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'admin_with_script'
                    DistinguishedName = 'CN=AdminWithScript,OU=Admins,DC=test,DC=local'
                    Enabled           = $true
                    ScriptPath        = 'C:\scripts\login.ps1'
                    AdminCount        = 1
                    MemberOf          = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                    WhenChanged       = (Get-Date).AddDays(-5)
                }
                # Normal user with NETLOGON script - LOW risk
                [PSCustomObject]@{
                    SamAccountName    = 'normal_user'
                    DistinguishedName = 'CN=NormalUser,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ScriptPath        = '\\test.local\NETLOGON\logon.bat'
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-100)
                }
                # User with no script
                [PSCustomObject]@{
                    SamAccountName    = 'no_script_user'
                    DistinguishedName = 'CN=NoScriptUser,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ScriptPath        = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-50)
                }
            )
        }

        It 'Should execute without errors' {
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
        }

        It 'Should find users with script paths' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.Count | Should -BeGreaterThan 0
        }

        It 'Should flag external UNC path as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $externalUser = $findings | Where-Object { $_.SamAccountName -eq 'external_script_user' }
            $externalUser.RiskLevel | Should -Be 'High'
        }

        It 'Should flag privileged user with local path as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'admin_with_script' }
            $adminUser.RiskLevel | Should -Be 'High'
        }

        It 'Should NOT find user without script path' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.SamAccountName | Should -Not -Contain 'no_script_user'
        }

        It 'Should identify privileged accounts' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'admin_with_script' }
            $adminUser.IsPrivileged | Should -Be $true
        }
    }

    Context 'Edge Cases' {
        It 'Should handle empty user list' {
            $mockDomain = [PSCustomObject]@{ Name = 'test.local' }
            $findings = & $rule.Detect @() $mockDomain
            $findings.Count | Should -Be 0
        }

        It 'Should handle null script paths gracefully' {
            $mockDomain = [PSCustomObject]@{ Name = 'test.local' }
            $mockUsers = @(
                [PSCustomObject]@{
                    SamAccountName = 'user1'
                    ScriptPath     = $null
                }
                [PSCustomObject]@{
                    SamAccountName = 'user2'
                    ScriptPath     = ''
                }
                [PSCustomObject]@{
                    SamAccountName = 'user3'
                    ScriptPath     = '   '
                }
            )
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.Count | Should -Be 0
        }
    }
}

Describe 'E-ShadowCredentials Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'E-ShadowCredentials'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'E-ShadowCredentials'
        }

        It 'Should be Critical severity' {
            $rule.Severity | Should -Be 'Critical'
        }

        It 'Should have MITRE ATT&CK mapping' {
            $rule.MITRE.Techniques | Should -Contain 'T1556.005'
        }
    }

    Context 'Rule Execution with Shadow Credentials' {
        BeforeAll {
            $mockDomain = [PSCustomObject]@{ Name = 'test.local' }

            # Simulate key credential data (binary blob)
            $mockKeyCredential = [byte[]](1..50)

            $mockUsers = @(
                # Privileged user with key credentials - CRITICAL
                [PSCustomObject]@{
                    SamAccountName        = 'admin_shadow'
                    DistinguishedName     = 'CN=AdminShadow,OU=Admins,DC=test,DC=local'
                    Enabled               = $true
                    AdminCount            = 1
                    MemberOf              = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                    ServicePrincipalNames = @()
                    KeyCredentialLink     = @($mockKeyCredential)
                    WhenChanged           = (Get-Date).AddDays(-5)
                }
                # Service account with key credentials - CRITICAL
                [PSCustomObject]@{
                    SamAccountName        = 'svc_account'
                    DistinguishedName     = 'CN=SvcAccount,OU=ServiceAccounts,DC=test,DC=local'
                    Enabled               = $true
                    AdminCount            = $null
                    MemberOf              = @()
                    ServicePrincipalNames = @('HTTP/webapp.test.local')
                    KeyCredentialLink     = @($mockKeyCredential)
                    WhenChanged           = (Get-Date).AddDays(-2)
                }
                # User with multiple key credentials - CRITICAL
                [PSCustomObject]@{
                    SamAccountName        = 'multi_key_user'
                    DistinguishedName     = 'CN=MultiKeyUser,OU=Users,DC=test,DC=local'
                    Enabled               = $true
                    AdminCount            = $null
                    MemberOf              = @()
                    ServicePrincipalNames = @()
                    KeyCredentialLink     = @($mockKeyCredential, $mockKeyCredential, $mockKeyCredential)
                    WhenChanged           = (Get-Date).AddDays(-1)
                }
                # Normal user without key credentials
                [PSCustomObject]@{
                    SamAccountName        = 'normal_user'
                    DistinguishedName     = 'CN=NormalUser,OU=Users,DC=test,DC=local'
                    Enabled               = $true
                    AdminCount            = $null
                    MemberOf              = @()
                    ServicePrincipalNames = @()
                    KeyCredentialLink     = @()
                    WhenChanged           = (Get-Date).AddDays(-30)
                }
            )
        }

        It 'Should execute without errors' {
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
        }

        It 'Should find users with key credentials' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.Count | Should -Be 3
        }

        It 'Should flag privileged user as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'admin_shadow' }
            $adminUser.RiskLevel | Should -Be 'Critical'
        }

        It 'Should flag service account as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $svcUser = $findings | Where-Object { $_.SamAccountName -eq 'svc_account' }
            $svcUser.RiskLevel | Should -Be 'Critical'
            $svcUser.IsServiceAccount | Should -Be $true
        }

        It 'Should flag multiple key credentials as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $multiUser = $findings | Where-Object { $_.SamAccountName -eq 'multi_key_user' }
            $multiUser.RiskLevel | Should -Be 'Critical'
            $multiUser.KeyCredentialCount | Should -Be 3
        }

        It 'Should NOT find user without key credentials' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.SamAccountName | Should -Not -Contain 'normal_user'
        }
    }
}

Describe 'E-ProfilePathAbuse Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'E-ProfilePathAbuse'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'E-ProfilePathAbuse'
        }

        It 'Should be in EphemeralPersistence category' {
            $rule.Category | Should -Be 'EphemeralPersistence'
        }
    }

    Context 'Rule Execution with Profile Paths' {
        BeforeAll {
            $mockDomain = [PSCustomObject]@{
                Name    = 'test.local'
                DNSRoot = 'test.local'
            }

            $mockUsers = @(
                # User with external IP profile path - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'external_profile'
                    DistinguishedName = 'CN=ExternalProfile,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ProfilePath       = '\\192.168.1.100\profiles\user'
                    HomeDirectory     = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-5)
                }
                # Privileged user with UNC home directory - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'admin_unc_home'
                    DistinguishedName = 'CN=AdminUncHome,OU=Admins,DC=test,DC=local'
                    Enabled           = $true
                    ProfilePath       = $null
                    HomeDirectory     = '\\fileserver.test.local\homes\admin'
                    AdminCount        = 1
                    MemberOf          = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                    WhenChanged       = (Get-Date).AddDays(-2)
                }
                # User with local profile path - Medium risk
                [PSCustomObject]@{
                    SamAccountName    = 'local_profile'
                    DistinguishedName = 'CN=LocalProfile,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ProfilePath       = 'C:\Users\localprofile'
                    HomeDirectory     = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-30)
                }
                # User with no profile/home paths
                [PSCustomObject]@{
                    SamAccountName    = 'no_paths_user'
                    DistinguishedName = 'CN=NoPathsUser,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    ProfilePath       = $null
                    HomeDirectory     = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-50)
                }
            )
        }

        It 'Should execute without errors' {
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
        }

        It 'Should flag external IP path as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $extUser = $findings | Where-Object { $_.SamAccountName -eq 'external_profile' }
            $extUser.RiskLevel | Should -Be 'High'
        }

        It 'Should flag privileged user with UNC as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'admin_unc_home' }
            $adminUser.RiskLevel | Should -Be 'High'
        }

        It 'Should flag local profile path as Medium risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $localUser = $findings | Where-Object { $_.SamAccountName -eq 'local_profile' }
            $localUser.RiskLevel | Should -Be 'Medium'
        }
    }
}

Describe 'E-TSPersistence Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'E-TSPersistence'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'E-TSPersistence'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }

    Context 'Rule Execution with TS Initial Programs' {
        BeforeAll {
            $mockDomain = [PSCustomObject]@{ Name = 'test.local' }

            $mockUsers = @(
                # User with PowerShell TS program - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'ts_powershell'
                    DistinguishedName = 'CN=TSPowerShell,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    TSInitialProgram  = 'powershell.exe -enc VGVzdA=='
                    TSWorkDirectory   = $null
                    TSHomeDirectory   = $null
                    TSHomeDrive       = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-1)
                }
                # Privileged user with custom program - HIGH risk
                [PSCustomObject]@{
                    SamAccountName    = 'admin_ts_program'
                    DistinguishedName = 'CN=AdminTSProgram,OU=Admins,DC=test,DC=local'
                    Enabled           = $true
                    TSInitialProgram  = 'C:\custom\app.exe'
                    TSWorkDirectory   = 'C:\custom'
                    TSHomeDirectory   = $null
                    TSHomeDrive       = $null
                    AdminCount        = 1
                    MemberOf          = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                    WhenChanged       = (Get-Date).AddDays(-3)
                }
                # User with legitimate explorer - LOW risk
                [PSCustomObject]@{
                    SamAccountName    = 'ts_explorer'
                    DistinguishedName = 'CN=TSExplorer,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    TSInitialProgram  = 'explorer.exe'
                    TSWorkDirectory   = $null
                    TSHomeDirectory   = $null
                    TSHomeDrive       = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-60)
                }
                # User with no TS program
                [PSCustomObject]@{
                    SamAccountName    = 'no_ts_user'
                    DistinguishedName = 'CN=NoTSUser,OU=Users,DC=test,DC=local'
                    Enabled           = $true
                    TSInitialProgram  = $null
                    TSWorkDirectory   = $null
                    TSHomeDirectory   = $null
                    TSHomeDrive       = $null
                    AdminCount        = $null
                    MemberOf          = @()
                    WhenChanged       = (Get-Date).AddDays(-30)
                }
            )
        }

        It 'Should execute without errors' {
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
        }

        It 'Should find users with TS initial programs' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.Count | Should -Be 3
        }

        It 'Should flag PowerShell TS program as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $psUser = $findings | Where-Object { $_.SamAccountName -eq 'ts_powershell' }
            $psUser.RiskLevel | Should -Be 'High'
        }

        It 'Should flag privileged user as High risk' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'admin_ts_program' }
            $adminUser.RiskLevel | Should -Be 'High'
        }

        It 'Should NOT find user without TS program' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.SamAccountName | Should -Not -Contain 'no_ts_user'
        }
    }
}

Describe 'E-RecentPersistenceChange Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'E-RecentPersistenceChange'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'E-RecentPersistenceChange'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }

    Context 'Rule Execution with Recent Changes' {
        BeforeAll {
            $mockDomain = [PSCustomObject]@{ Name = 'test.local' }

            $mockUsers = @(
                # User with script changed in last 24h - CRITICAL
                [PSCustomObject]@{
                    SamAccountName     = 'recent_script'
                    DistinguishedName  = 'CN=RecentScript,OU=Users,DC=test,DC=local'
                    Enabled            = $true
                    ScriptPath         = '\\server\scripts\login.bat'
                    ProfilePath        = $null
                    HomeDirectory      = $null
                    TSInitialProgram   = $null
                    KeyCredentialLink  = @()
                    AdminCount         = $null
                    MemberOf           = @()
                    ServicePrincipalNames = @()
                    WhenCreated        = (Get-Date).AddDays(-100)
                    WhenChanged        = (Get-Date).AddHours(-12)
                }
                # Privileged user changed in last 7 days - CRITICAL
                [PSCustomObject]@{
                    SamAccountName     = 'recent_admin'
                    DistinguishedName  = 'CN=RecentAdmin,OU=Admins,DC=test,DC=local'
                    Enabled            = $true
                    ScriptPath         = '\\server\scripts\admin.ps1'
                    ProfilePath        = $null
                    HomeDirectory      = $null
                    TSInitialProgram   = $null
                    KeyCredentialLink  = @()
                    AdminCount         = 1
                    MemberOf           = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                    ServicePrincipalNames = @()
                    WhenCreated        = (Get-Date).AddDays(-365)
                    WhenChanged        = (Get-Date).AddDays(-3)
                }
                # New account with persistence - CRITICAL
                [PSCustomObject]@{
                    SamAccountName     = 'new_with_persistence'
                    DistinguishedName  = 'CN=NewWithPersistence,OU=Users,DC=test,DC=local'
                    Enabled            = $true
                    ScriptPath         = '\\server\scripts\new.bat'
                    ProfilePath        = $null
                    HomeDirectory      = $null
                    TSInitialProgram   = $null
                    KeyCredentialLink  = @()
                    AdminCount         = $null
                    MemberOf           = @()
                    ServicePrincipalNames = @()
                    WhenCreated        = (Get-Date).AddDays(-2)
                    WhenChanged        = (Get-Date).AddDays(-1)
                }
                # Old persistence attribute - should NOT be flagged
                [PSCustomObject]@{
                    SamAccountName     = 'old_persistence'
                    DistinguishedName  = 'CN=OldPersistence,OU=Users,DC=test,DC=local'
                    Enabled            = $true
                    ScriptPath         = '\\server\scripts\old.bat'
                    ProfilePath        = $null
                    HomeDirectory      = $null
                    TSInitialProgram   = $null
                    KeyCredentialLink  = @()
                    AdminCount         = $null
                    MemberOf           = @()
                    ServicePrincipalNames = @()
                    WhenCreated        = (Get-Date).AddDays(-500)
                    WhenChanged        = (Get-Date).AddDays(-60)
                }
            )
        }

        It 'Should execute without errors' {
            { & $rule.Detect $mockUsers $mockDomain } | Should -Not -Throw
        }

        It 'Should flag 24-hour change as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $recentUser = $findings | Where-Object { $_.SamAccountName -eq 'recent_script' }
            $recentUser.RiskLevel | Should -Be 'Critical'
        }

        It 'Should flag privileged user change as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $adminUser = $findings | Where-Object { $_.SamAccountName -eq 'recent_admin' }
            $adminUser.RiskLevel | Should -Be 'Critical'
        }

        It 'Should flag new account with persistence as Critical' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $newUser = $findings | Where-Object { $_.SamAccountName -eq 'new_with_persistence' }
            $newUser.RiskLevel | Should -Be 'Critical'
        }

        It 'Should NOT flag old persistence' {
            $findings = & $rule.Detect $mockUsers $mockDomain
            $findings.SamAccountName | Should -Not -Contain 'old_persistence'
        }
    }
}

Describe 'EphemeralPersistence Rules Integration' {
    Context 'All Rules Load Successfully' {
        It 'Should load E-LoginScript rule' {
            $rule = Get-ADScoutRule -Id 'E-LoginScript'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-ShadowCredentials rule' {
            $rule = Get-ADScoutRule -Id 'E-ShadowCredentials'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-GPOScriptEnumeration rule' {
            $rule = Get-ADScoutRule -Id 'E-GPOScriptEnumeration'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-ProfilePathAbuse rule' {
            $rule = Get-ADScoutRule -Id 'E-ProfilePathAbuse'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-TSPersistence rule' {
            $rule = Get-ADScoutRule -Id 'E-TSPersistence'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-RecentPersistenceChange rule' {
            $rule = Get-ADScoutRule -Id 'E-RecentPersistenceChange'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-GPPScheduledTasks rule' {
            $rule = Get-ADScoutRule -Id 'E-GPPScheduledTasks'
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should load E-WMIEventSubscription rule' {
            $rule = Get-ADScoutRule -Id 'E-WMIEventSubscription'
            $rule | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Rules Category Consistency' {
        BeforeAll {
            $rules = Get-ADScoutRule -Category 'EphemeralPersistence'
        }

        It 'Should find all EphemeralPersistence rules' {
            $rules.Count | Should -BeGreaterOrEqual 8
        }

        It 'All rules should have Detect scriptblock' {
            foreach ($rule in $rules) {
                $rule.Detect | Should -Not -BeNullOrEmpty
            }
        }

        It 'All rules should have Remediation info' {
            foreach ($rule in $rules) {
                $rule.Remediation | Should -Not -BeNullOrEmpty
            }
        }

        It 'All rules should have MITRE ATT&CK mappings' {
            foreach ($rule in $rules) {
                $rule.MITRE | Should -Not -BeNullOrEmpty
            }
        }
    }
}

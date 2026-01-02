#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for Entra ID (Azure AD) security rules.

.DESCRIPTION
    Comprehensive tests for all Entra ID rules including rule definitions,
    detection logic, and remediation scripts.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force

    # Mock Test-ADScoutGraphConnection to return true for testing
    Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $true }
}

Describe 'Entra ID Rules - Discovery' {
    Context 'Rule Loading' {
        It 'Should find Entra ID rules' {
            $rules = Get-ADScoutRule -Category EntraID
            $rules | Should -Not -BeNullOrEmpty
        }

        It 'Should find at least 9 Entra ID rules' {
            $rules = Get-ADScoutRule -Category EntraID
            $rules.Count | Should -BeGreaterOrEqual 9
        }

        It 'All Entra ID rules should have EntraID category' {
            $rules = Get-ADScoutRule -Category EntraID
            $rules | ForEach-Object {
                $_.Category | Should -Be 'EntraID'
            }
        }

        It 'All Entra ID rules should have DataSource specified' {
            $rules = Get-ADScoutRule -Category EntraID
            $rules | ForEach-Object {
                $_.DataSource | Should -Not -BeNullOrEmpty -Because "Rule $($_.Id) should have DataSource"
            }
        }
    }
}

Describe 'EID-PrivilegedNoMFA Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-PrivilegedNoMFA'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'EID-PrivilegedNoMFA'
        }

        It 'Should be Critical severity' {
            $rule.Severity | Should -Be 'Critical'
        }

        It 'Should have MITRE ATT&CK mappings' {
            $rule.MITRE | Should -Not -BeNullOrEmpty
            $rule.MITRE | Should -Contain 'T1078.004'
        }

        It 'Should have DataSource set to EntraUsers' {
            $rule.DataSource | Should -Be 'EntraUsers'
        }

        It 'Should have remediation script' {
            $rule.Remediation | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Detection Logic' {
        BeforeAll {
            # Mock Entra ID user data
            $script:mockEntraUsers = @(
                [PSCustomObject]@{
                    Id                = 'user1-guid'
                    UserPrincipalName = 'admin@contoso.com'
                    DisplayName       = 'Admin User'
                    AccountEnabled    = $true
                    IsPrivileged      = $true
                    IsGlobalAdmin     = $true
                    IsMfaRegistered   = $false
                    IsMfaCapable      = $false
                    DirectoryRoles    = @('Global Administrator')
                    LastSignInDateTime = (Get-Date).AddDays(-1)
                }
                [PSCustomObject]@{
                    Id                = 'user2-guid'
                    UserPrincipalName = 'secadmin@contoso.com'
                    DisplayName       = 'Security Admin'
                    AccountEnabled    = $true
                    IsPrivileged      = $true
                    IsGlobalAdmin     = $false
                    IsMfaRegistered   = $true
                    IsMfaCapable      = $true
                    DirectoryRoles    = @('Security Administrator')
                    LastSignInDateTime = (Get-Date).AddDays(-2)
                }
                [PSCustomObject]@{
                    Id                = 'user3-guid'
                    UserPrincipalName = 'user@contoso.com'
                    DisplayName       = 'Regular User'
                    AccountEnabled    = $true
                    IsPrivileged      = $false
                    IsGlobalAdmin     = $false
                    IsMfaRegistered   = $false
                    IsMfaCapable      = $false
                    DirectoryRoles    = @()
                    LastSignInDateTime = (Get-Date).AddDays(-3)
                }
                [PSCustomObject]@{
                    Id                = 'user4-guid'
                    UserPrincipalName = 'disabledadmin@contoso.com'
                    DisplayName       = 'Disabled Admin'
                    AccountEnabled    = $false
                    IsPrivileged      = $true
                    IsGlobalAdmin     = $true
                    IsMfaRegistered   = $false
                    IsMfaCapable      = $false
                    DirectoryRoles    = @('Global Administrator')
                    LastSignInDateTime = (Get-Date).AddDays(-100)
                }
            )

            # Mock the collector function
            Mock -ModuleName ADScout Get-ADScoutEntraUserData { return $script:mockEntraUsers }
        }

        It 'Should find privileged users without MFA' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings | Should -Not -BeNullOrEmpty
        }

        It 'Should find admin@contoso.com (privileged, no MFA)' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Contain 'admin@contoso.com'
        }

        It 'Should NOT find secadmin@contoso.com (has MFA)' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Not -Contain 'secadmin@contoso.com'
        }

        It 'Should NOT find user@contoso.com (not privileged)' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Not -Contain 'user@contoso.com'
        }

        It 'Should NOT find disabledadmin@contoso.com (disabled account)' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Not -Contain 'disabledadmin@contoso.com'
        }
    }
}

Describe 'EID-GlobalAdminCount Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-GlobalAdminCount'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraRoles' {
            $rule.DataSource | Should -Be 'EntraRoles'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }

        It 'Should use TriggerOnThreshold computation' {
            $rule.Computation | Should -Be 'TriggerOnThreshold'
        }
    }
}

Describe 'EID-NoConditionalAccess Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-NoConditionalAccess'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraPolicies' {
            $rule.DataSource | Should -Be 'EntraPolicies'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }
}

Describe 'EID-StaleUsers Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-StaleUsers'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraUsers' {
            $rule.DataSource | Should -Be 'EntraUsers'
        }

        It 'Should be Medium severity' {
            $rule.Severity | Should -Be 'Medium'
        }

        It 'Should use PerDiscover computation with max points' {
            $rule.Computation | Should -Be 'PerDiscover'
            $rule.MaxPoints | Should -BeGreaterThan 0
        }
    }

    Context 'Detection Logic' {
        BeforeAll {
            $script:mockStaleUsers = @(
                [PSCustomObject]@{
                    Id                  = 'stale1-guid'
                    UserPrincipalName   = 'stale@contoso.com'
                    DisplayName         = 'Stale User'
                    AccountEnabled      = $true
                    HasLicenses         = $true
                    DaysSinceLastSignIn = 120
                    LastSignInDateTime  = (Get-Date).AddDays(-120)
                }
                [PSCustomObject]@{
                    Id                  = 'active1-guid'
                    UserPrincipalName   = 'active@contoso.com'
                    DisplayName         = 'Active User'
                    AccountEnabled      = $true
                    HasLicenses         = $true
                    DaysSinceLastSignIn = 5
                    LastSignInDateTime  = (Get-Date).AddDays(-5)
                }
                [PSCustomObject]@{
                    Id                  = 'unlicensed1-guid'
                    UserPrincipalName   = 'unlicensed@contoso.com'
                    DisplayName         = 'Unlicensed User'
                    AccountEnabled      = $true
                    HasLicenses         = $false
                    DaysSinceLastSignIn = 200
                    LastSignInDateTime  = (Get-Date).AddDays(-200)
                }
            )

            Mock -ModuleName ADScout Get-ADScoutEntraUserData { return $script:mockStaleUsers }
        }

        It 'Should find stale licensed users' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Contain 'stale@contoso.com'
        }

        It 'Should NOT find active users' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Not -Contain 'active@contoso.com'
        }
    }
}

Describe 'EID-AppSecretsExpiring Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-AppSecretsExpiring'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraApps' {
            $rule.DataSource | Should -Be 'EntraApps'
        }

        It 'Should be Medium severity' {
            $rule.Severity | Should -Be 'Medium'
        }
    }
}

Describe 'EID-StaleGuestAccounts Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-StaleGuestAccounts'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraUsers' {
            $rule.DataSource | Should -Be 'EntraUsers'
        }
    }
}

Describe 'EID-LegacyAuthEnabled Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-LegacyAuthEnabled'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraPolicies' {
            $rule.DataSource | Should -Be 'EntraPolicies'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }
}

Describe 'EID-HybridPrivilegeSync Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-HybridPrivilegeSync'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraUsers' {
            $rule.DataSource | Should -Be 'EntraUsers'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }

    Context 'Detection Logic' {
        BeforeAll {
            $script:mockHybridUsers = @(
                [PSCustomObject]@{
                    Id                = 'hybrid1-guid'
                    UserPrincipalName = 'hybridadmin@contoso.com'
                    DisplayName       = 'Hybrid Admin'
                    AccountEnabled    = $true
                    IsPrivileged      = $true
                    IsHybrid          = $true
                    OnPremisesSamAccountName = 'hybridadmin'
                    DirectoryRoles    = @('Global Administrator')
                }
                [PSCustomObject]@{
                    Id                = 'cloudonly1-guid'
                    UserPrincipalName = 'cloudadmin@contoso.com'
                    DisplayName       = 'Cloud Admin'
                    AccountEnabled    = $true
                    IsPrivileged      = $true
                    IsHybrid          = $false
                    DirectoryRoles    = @('Global Administrator')
                }
            )

            Mock -ModuleName ADScout Get-ADScoutEntraUserData { return $script:mockHybridUsers }
        }

        It 'Should find privileged hybrid users' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Contain 'hybridadmin@contoso.com'
        }

        It 'Should NOT find cloud-only privileged users' {
            $findings = & $rule.ScriptBlock -Data @{} -Domain 'contoso.com'
            $findings.UserPrincipalName | Should -Not -Contain 'cloudadmin@contoso.com'
        }
    }
}

Describe 'EID-OverprivilegedApps Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'EID-OverprivilegedApps'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have DataSource set to EntraApps' {
            $rule.DataSource | Should -Be 'EntraApps'
        }

        It 'Should be High severity' {
            $rule.Severity | Should -Be 'High'
        }
    }
}

Describe 'Entra ID Rule Framework Mappings' {
    BeforeAll {
        $rules = Get-ADScoutRule -Category EntraID
    }

    Context 'MITRE ATT&CK Mappings' {
        It 'All Entra ID rules should have MITRE mappings' {
            foreach ($rule in $rules) {
                $rule.MITRE | Should -Not -BeNullOrEmpty -Because "Rule $($rule.Id) should have MITRE mapping"
            }
        }

        It 'MITRE mappings should use T1078.004 (Cloud Accounts) where appropriate' {
            $cloudAccountRules = $rules | Where-Object { $_.MITRE -contains 'T1078.004' }
            $cloudAccountRules.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Remediation Scripts' {
        It 'All Entra ID rules should have remediation' {
            foreach ($rule in $rules) {
                $rule.Remediation | Should -Not -BeNullOrEmpty -Because "Rule $($rule.Id) should have remediation"
            }
        }
    }
}

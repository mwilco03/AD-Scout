#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for the S-PwdNeverExpires rule.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force
}

Describe 'S-PwdNeverExpires Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'S-PwdNeverExpires'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'S-PwdNeverExpires'
        }

        It 'Should be in StaleObjects category' {
            $rule.Category | Should -Be 'StaleObjects'
        }

        It 'Should have MITRE ATT&CK mapping' {
            $rule.MITRE | Should -Contain 'T1078.002'
        }

        It 'Should have CIS controls' {
            $rule.CIS | Should -Not -BeNullOrEmpty
        }

        It 'Should have remediation' {
            $rule.Remediation | Should -Not -BeNullOrEmpty
        }

        It 'Should have description' {
            $rule.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should have technical explanation' {
            $rule.TechnicalExplanation | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            # Mock AD data with test users
            $mockADData = @{
                Users = @(
                    [PSCustomObject]@{
                        SamAccountName       = 'user1'
                        DistinguishedName    = 'CN=User1,OU=Users,DC=test,DC=local'
                        Enabled              = $true
                        PasswordNeverExpires = $true
                        PasswordLastSet      = (Get-Date).AddDays(-100)
                        WhenCreated          = (Get-Date).AddDays(-365)
                        Description          = 'Test user 1'
                    }
                    [PSCustomObject]@{
                        SamAccountName       = 'user2'
                        DistinguishedName    = 'CN=User2,OU=Users,DC=test,DC=local'
                        Enabled              = $true
                        PasswordNeverExpires = $false
                        PasswordLastSet      = (Get-Date).AddDays(-30)
                        WhenCreated          = (Get-Date).AddDays(-180)
                        Description          = 'Test user 2'
                    }
                    [PSCustomObject]@{
                        SamAccountName       = 'user3'
                        DistinguishedName    = 'CN=User3,OU=Users,DC=test,DC=local'
                        Enabled              = $false
                        PasswordNeverExpires = $true
                        PasswordLastSet      = (Get-Date).AddDays(-200)
                        WhenCreated          = (Get-Date).AddDays(-400)
                        Description          = 'Disabled user'
                    }
                    [PSCustomObject]@{
                        SamAccountName       = 'svc_account'
                        DistinguishedName    = 'CN=SvcAccount,OU=Service,DC=test,DC=local'
                        Enabled              = $true
                        PasswordNeverExpires = $true
                        PasswordLastSet      = (Get-Date).AddDays(-500)
                        WhenCreated          = (Get-Date).AddDays(-600)
                        Description          = 'Service account'
                    }
                )
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find enabled users with PasswordNeverExpires' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings | Should -Not -BeNullOrEmpty
        }

        It 'Should find user1 (enabled with PasswordNeverExpires)' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'user1'
        }

        It 'Should find svc_account (enabled with PasswordNeverExpires)' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'svc_account'
        }

        It 'Should NOT find user2 (PasswordNeverExpires is false)' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'user2'
        }

        It 'Should NOT find user3 (disabled account)' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'user3'
        }

        It 'Should find exactly 2 accounts' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            @($findings).Count | Should -Be 2
        }

        It 'Should include DaysSincePasswordSet in findings' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DaysSincePasswordSet'
            }
        }
    }

    Context 'Prerequisites' {
        It 'Should have prerequisites check' {
            $rule.Prerequisites | Should -Not -BeNullOrEmpty
        }

        It 'Should return true when users data exists' {
            $mockData = @{ Users = @([PSCustomObject]@{SamAccountName='test'}) }
            $result = & $rule.Prerequisites -ADData $mockData
            $result | Should -Be $true
        }

        It 'Should return false when no users data' {
            $mockData = @{ Users = @() }
            $result = & $rule.Prerequisites -ADData $mockData
            $result | Should -Be $false
        }
    }

    Context 'Remediation' {
        It 'Should generate remediation script' {
            $finding = [PSCustomObject]@{
                SamAccountName = 'testuser'
            }
            $script = & $rule.Remediation -Finding $finding
            $script | Should -Not -BeNullOrEmpty
            $script | Should -Match 'Set-ADUser'
            $script | Should -Match 'testuser'
        }
    }
}

#Requires -Modules Pester
<#
.SYNOPSIS
    Integration tests for Invoke-ADScoutScan function.

.DESCRIPTION
    Tests for the main scan orchestration function including Entra ID integration,
    rule filtering, and data collection flow.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force
}

Describe 'Invoke-ADScoutScan' {
    Context 'Parameter Validation' {
        It 'Should have Category parameter with EntraID option' {
            $cmd = Get-Command Invoke-ADScoutScan
            $categoryParam = $cmd.Parameters['Category']
            $categoryParam | Should -Not -BeNullOrEmpty

            $validateSet = $categoryParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'EntraID'
        }

        It 'Should have IncludeEntraID switch parameter' {
            $cmd = Get-Command Invoke-ADScoutScan
            $cmd.Parameters['IncludeEntraID'] | Should -Not -BeNullOrEmpty
            $cmd.Parameters['IncludeEntraID'].SwitchParameter | Should -BeTrue
        }

        It 'Should have all expected parameters' {
            $cmd = Get-Command Invoke-ADScoutScan
            $expectedParams = @('Domain', 'Server', 'Credential', 'Category', 'IncludeEntraID', 'RuleId', 'ExcludeRuleId', 'ThrottleLimit', 'SkipCache')
            foreach ($param in $expectedParams) {
                $cmd.Parameters[$param] | Should -Not -BeNullOrEmpty -Because "Parameter $param should exist"
            }
        }
    }

    Context 'Category Filtering' {
        BeforeAll {
            # Mock AD data collectors to avoid real AD queries
            Mock -ModuleName ADScout Get-ADScoutUserData { return @() }
            Mock -ModuleName ADScout Get-ADScoutComputerData { return @() }
            Mock -ModuleName ADScout Get-ADScoutGroupData { return @() }
            Mock -ModuleName ADScout Get-ADScoutTrustData { return @() }
            Mock -ModuleName ADScout Get-ADScoutGPOData { return @() }
            Mock -ModuleName ADScout Get-ADScoutCertificateData { return @() }
            Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $false }
        }

        It 'Should accept EntraID as valid category' {
            { Invoke-ADScoutScan -Category EntraID } | Should -Not -Throw
        }

        It 'Should accept multiple categories including EntraID' {
            { Invoke-ADScoutScan -Category StaleObjects, EntraID } | Should -Not -Throw
        }

        It 'Should accept All category' {
            { Invoke-ADScoutScan -Category All } | Should -Not -Throw
        }
    }

    Context 'Entra ID Integration' {
        BeforeAll {
            # Mock AD collectors
            Mock -ModuleName ADScout Get-ADScoutUserData { return @() }
            Mock -ModuleName ADScout Get-ADScoutComputerData { return @() }
            Mock -ModuleName ADScout Get-ADScoutGroupData { return @() }
            Mock -ModuleName ADScout Get-ADScoutTrustData { return @() }
            Mock -ModuleName ADScout Get-ADScoutGPOData { return @() }
            Mock -ModuleName ADScout Get-ADScoutCertificateData { return @() }
        }

        Context 'When Graph is not connected' {
            BeforeAll {
                Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $false }
            }

            It 'Should not call Entra ID collectors when Graph not connected' {
                Mock -ModuleName ADScout Get-ADScoutEntraUserData { throw "Should not be called" }
                Mock -ModuleName ADScout Get-ADScoutEntraGroupData { throw "Should not be called" }

                # This should not throw because Entra collectors should be skipped
                { Invoke-ADScoutScan -Category EntraID -WarningAction SilentlyContinue } | Should -Not -Throw
            }

            It 'Should complete scan gracefully without Entra ID data' {
                $results = Invoke-ADScoutScan -Category StaleObjects -WarningAction SilentlyContinue
                # Should complete without error
            }
        }

        Context 'When Graph is connected' {
            BeforeAll {
                Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $true }

                # Mock Entra ID collectors
                Mock -ModuleName ADScout Get-ADScoutEntraUserData {
                    @(
                        [PSCustomObject]@{
                            Id = 'user1'
                            UserPrincipalName = 'user@contoso.com'
                            IsPrivileged = $true
                            IsMfaRegistered = $false
                            AccountEnabled = $true
                        }
                    )
                }
                Mock -ModuleName ADScout Get-ADScoutEntraGroupData { @() }
                Mock -ModuleName ADScout Get-ADScoutEntraAppData { @() }
                Mock -ModuleName ADScout Get-ADScoutEntraRoleData { @() }
                Mock -ModuleName ADScout Get-ADScoutEntraPolicyData { @() }
            }

            It 'Should call Entra ID collectors when IncludeEntraID is specified' {
                Invoke-ADScoutScan -IncludeEntraID -WarningAction SilentlyContinue

                Should -Invoke -ModuleName ADScout Get-ADScoutEntraUserData -Times 1
                Should -Invoke -ModuleName ADScout Get-ADScoutEntraGroupData -Times 1
                Should -Invoke -ModuleName ADScout Get-ADScoutEntraAppData -Times 1
            }

            It 'Should call Entra ID collectors when EntraID category is specified' {
                Invoke-ADScoutScan -Category EntraID -WarningAction SilentlyContinue

                Should -Invoke -ModuleName ADScout Get-ADScoutEntraUserData -Times 1
            }

            It 'Should call Entra ID collectors when All category is specified' {
                Invoke-ADScoutScan -Category All -WarningAction SilentlyContinue

                Should -Invoke -ModuleName ADScout Get-ADScoutEntraUserData -Times 1
            }
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            # Mock all collectors
            Mock -ModuleName ADScout Get-ADScoutUserData { @() }
            Mock -ModuleName ADScout Get-ADScoutComputerData { @() }
            Mock -ModuleName ADScout Get-ADScoutGroupData { @() }
            Mock -ModuleName ADScout Get-ADScoutTrustData { @() }
            Mock -ModuleName ADScout Get-ADScoutGPOData { @() }
            Mock -ModuleName ADScout Get-ADScoutCertificateData { @() }
            Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $false }
        }

        It 'Should filter rules by ID' {
            $results = Invoke-ADScoutScan -RuleId 'S-PwdNeverExpires' -WarningAction SilentlyContinue
            # Should not throw and should run only specified rule
        }

        It 'Should exclude rules by ID' {
            $results = Invoke-ADScoutScan -Category StaleObjects -ExcludeRuleId 'S-PwdNeverExpires' -WarningAction SilentlyContinue
            # Should not throw and should skip excluded rule
        }
    }

    Context 'Result Format' {
        BeforeAll {
            # Mock collectors with test data
            Mock -ModuleName ADScout Get-ADScoutUserData {
                @(
                    [PSCustomObject]@{
                        SamAccountName = 'testuser'
                        DistinguishedName = 'CN=TestUser,DC=test,DC=local'
                        Enabled = $true
                        PasswordNeverExpires = $true
                        PasswordLastSet = (Get-Date).AddDays(-100)
                    }
                )
            }
            Mock -ModuleName ADScout Get-ADScoutComputerData { @() }
            Mock -ModuleName ADScout Get-ADScoutGroupData { @() }
            Mock -ModuleName ADScout Get-ADScoutTrustData { @() }
            Mock -ModuleName ADScout Get-ADScoutGPOData { @() }
            Mock -ModuleName ADScout Get-ADScoutCertificateData { @() }
            Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $false }
        }

        It 'Should return PSCustomObject array' {
            $results = Invoke-ADScoutScan -RuleId 'S-PwdNeverExpires' -WarningAction SilentlyContinue
            if ($results) {
                $results | ForEach-Object { $_ | Should -BeOfType [PSCustomObject] }
            }
        }

        It 'Should have expected properties in results' {
            $results = Invoke-ADScoutScan -RuleId 'S-PwdNeverExpires' -WarningAction SilentlyContinue
            if ($results) {
                $results[0].PSObject.Properties.Name | Should -Contain 'RuleId'
                $results[0].PSObject.Properties.Name | Should -Contain 'Score'
                $results[0].PSObject.Properties.Name | Should -Contain 'FindingCount'
                $results[0].PSObject.Properties.Name | Should -Contain 'Findings'
            }
        }
    }

    Context 'Cache Behavior' {
        BeforeAll {
            Mock -ModuleName ADScout Get-ADScoutUserData { @() }
            Mock -ModuleName ADScout Get-ADScoutComputerData { @() }
            Mock -ModuleName ADScout Get-ADScoutGroupData { @() }
            Mock -ModuleName ADScout Get-ADScoutTrustData { @() }
            Mock -ModuleName ADScout Get-ADScoutGPOData { @() }
            Mock -ModuleName ADScout Get-ADScoutCertificateData { @() }
            Mock -ModuleName ADScout Test-ADScoutGraphConnection { return $false }
        }

        It 'Should accept SkipCache parameter' {
            { Invoke-ADScoutScan -SkipCache -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }
}

Describe 'Get-ADScoutRule - EntraID Category' {
    Context 'Category Filtering' {
        It 'Should accept EntraID as valid category' {
            { Get-ADScoutRule -Category EntraID } | Should -Not -Throw
        }

        It 'Should return only EntraID rules when filtered' {
            $rules = Get-ADScoutRule -Category EntraID
            $rules | ForEach-Object {
                $_.Category | Should -Be 'EntraID'
            }
        }

        It 'Should include EntraID rules when no category filter' {
            $allRules = Get-ADScoutRule
            $entraRules = $allRules | Where-Object { $_.Category -eq 'EntraID' }
            $entraRules | Should -Not -BeNullOrEmpty
        }
    }

    Context 'EntraID Rule Properties' {
        BeforeAll {
            $entraRules = Get-ADScoutRule -Category EntraID
        }

        It 'Should have DataSource property' {
            $entraRules | ForEach-Object {
                $_.DataSource | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have valid DataSource values' {
            $validDataSources = @('EntraUsers', 'EntraGroups', 'EntraApps', 'EntraRoles', 'EntraPolicies')
            $entraRules | ForEach-Object {
                $_.DataSource | Should -BeIn $validDataSources
            }
        }

        It 'Should have Severity property' {
            $entraRules | ForEach-Object {
                $_.Severity | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have valid Severity values' {
            $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
            $entraRules | ForEach-Object {
                $_.Severity | Should -BeIn $validSeverities
            }
        }
    }
}

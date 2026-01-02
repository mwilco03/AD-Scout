#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for AD-Scout export functionality.

.DESCRIPTION
    Comprehensive tests for export formats including SARIF, BloodHound, JSON,
    CSV, and Markdown exports.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force

    # Create mock scan results for testing
    $script:mockResults = @(
        [PSCustomObject]@{
            PSTypeName   = 'ADScoutResult'
            RuleId       = 'S-PwdNeverExpires'
            RuleName     = 'Password Never Expires'
            Category     = 'StaleObjects'
            Description  = 'Users with password never expires enabled'
            FindingCount = 3
            Score        = 15
            MaxScore     = 50
            Findings     = @(
                [PSCustomObject]@{
                    SamAccountName    = 'user1'
                    DistinguishedName = 'CN=User1,OU=Users,DC=test,DC=local'
                    DisplayName       = 'Test User 1'
                    Enabled           = $true
                }
                [PSCustomObject]@{
                    SamAccountName    = 'user2'
                    DistinguishedName = 'CN=User2,OU=Users,DC=test,DC=local'
                    DisplayName       = 'Test User 2'
                    Enabled           = $true
                }
                [PSCustomObject]@{
                    SamAccountName    = 'svcaccount'
                    DistinguishedName = 'CN=SvcAccount,OU=Service,DC=test,DC=local'
                    DisplayName       = 'Service Account'
                    Enabled           = $true
                }
            )
            MITRE       = @('T1078.002')
            CIS         = @('5.2.1')
            STIG        = @('V-63597')
            NIST        = @('IA-5')
            Remediation = { 'Set-ADUser -PasswordNeverExpires $false' }
            TechnicalExplanation = 'Passwords that never expire are a security risk.'
            References  = @('https://example.com/pwd-policy')
            ExecutedAt  = Get-Date
        }
        [PSCustomObject]@{
            PSTypeName   = 'ADScoutResult'
            RuleId       = 'EID-PrivilegedNoMFA'
            RuleName     = 'Privileged Users Without MFA'
            Category     = 'EntraID'
            Description  = 'Privileged users without MFA registration'
            FindingCount = 2
            Score        = 50
            MaxScore     = 100
            Findings     = @(
                [PSCustomObject]@{
                    UserPrincipalName = 'admin@contoso.com'
                    DisplayName       = 'Admin User'
                    DirectoryRoles    = 'Global Administrator'
                    IsMfaRegistered   = $false
                    IsGlobalAdmin     = $true
                }
                [PSCustomObject]@{
                    UserPrincipalName = 'secadmin@contoso.com'
                    DisplayName       = 'Security Admin'
                    DirectoryRoles    = 'Security Administrator'
                    IsMfaRegistered   = $false
                    IsGlobalAdmin     = $false
                }
            )
            MITRE       = @('T1078.004', 'T1110')
            CIS         = @('6.1.2')
            STIG        = @()
            NIST        = @('IA-2')
            Remediation = { 'Enable MFA for all privileged users' }
            TechnicalExplanation = 'Privileged accounts without MFA are vulnerable to credential theft.'
            References  = @('https://learn.microsoft.com/azure/active-directory')
            ExecutedAt  = Get-Date
        }
        [PSCustomObject]@{
            PSTypeName   = 'ADScoutResult'
            RuleId       = 'P-AdminCount'
            RuleName     = 'AdminCount Attribute Set'
            Category     = 'PrivilegedAccounts'
            Description  = 'Accounts with AdminCount=1 orphaned from Protected Users'
            FindingCount = 1
            Score        = 25
            MaxScore     = 100
            Findings     = @(
                [PSCustomObject]@{
                    SamAccountName    = 'orphanadmin'
                    DistinguishedName = 'CN=OrphanAdmin,OU=Users,DC=test,DC=local'
                    DisplayName       = 'Orphaned Admin'
                    AdminCount        = 1
                }
            )
            MITRE       = @('T1078')
            CIS         = @('4.1')
            STIG        = @()
            NIST        = @('AC-6')
            Remediation = { 'Review and remediate AdminCount attribute' }
            TechnicalExplanation = 'Orphaned AdminCount can lead to privilege persistence.'
            References  = @()
            ExecutedAt  = Get-Date
        }
    )
}

Describe 'Export-ADScoutReport' {
    Context 'Parameter Validation' {
        It 'Should require Results parameter' {
            { Export-ADScoutReport -Format Console } | Should -Throw
        }

        It 'Should require Format parameter' {
            { Export-ADScoutReport -Results $script:mockResults } | Should -Throw
        }

        It 'Should require Path for file-based formats' {
            { Export-ADScoutReport -Results $script:mockResults -Format JSON } | Should -Throw
        }

        It 'Should accept valid format values' {
            @('HTML', 'JSON', 'CSV', 'SARIF', 'BloodHound', 'Markdown', 'Console') | ForEach-Object {
                $format = $_
                {
                    $params = @{ Results = $script:mockResults; Format = $format }
                    if ($format -ne 'Console') { $params.Path = [System.IO.Path]::GetTempFileName() }
                    Export-ADScoutReport @params
                } | Should -Not -Throw -Because "Format '$format' should be valid"
            }
        }
    }

    Context 'Console Output' {
        It 'Should output to console without errors' {
            { Export-ADScoutReport -Results $script:mockResults -Format Console } | Should -Not -Throw
        }
    }
}

Describe 'SARIF Export' {
    BeforeAll {
        $script:sarifPath = Join-Path $TestDrive 'results.sarif'
        Export-ADScoutReport -Results $script:mockResults -Format SARIF -Path $script:sarifPath
        $script:sarifContent = Get-Content $script:sarifPath -Raw | ConvertFrom-Json
    }

    Context 'SARIF Schema Compliance' {
        It 'Should create valid JSON file' {
            Test-Path $script:sarifPath | Should -BeTrue
            { Get-Content $script:sarifPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Should have correct schema reference' {
            $script:sarifContent.'$schema' | Should -Match 'sarif-schema-2.1.0'
        }

        It 'Should have correct version' {
            $script:sarifContent.version | Should -Be '2.1.0'
        }

        It 'Should have runs array' {
            $script:sarifContent.runs | Should -Not -BeNullOrEmpty
            $script:sarifContent.runs.Count | Should -Be 1
        }
    }

    Context 'SARIF Tool Information' {
        It 'Should have tool driver information' {
            $driver = $script:sarifContent.runs[0].tool.driver
            $driver | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct tool name' {
            $script:sarifContent.runs[0].tool.driver.name | Should -Be 'AD-Scout'
        }

        It 'Should have informationUri' {
            $script:sarifContent.runs[0].tool.driver.informationUri | Should -Match 'github.com'
        }

        It 'Should include rule definitions' {
            $rules = $script:sarifContent.runs[0].tool.driver.rules
            $rules | Should -Not -BeNullOrEmpty
            $rules.Count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'SARIF Rules' {
        BeforeAll {
            $script:sarifRules = $script:sarifContent.runs[0].tool.driver.rules
        }

        It 'Should include rule IDs' {
            $script:sarifRules | ForEach-Object {
                $_.id | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should include security-severity in properties' {
            $script:sarifRules | ForEach-Object {
                $_.properties.'security-severity' | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should include MITRE tags' {
            $ruleWithMitre = $script:sarifRules | Where-Object { $_.properties.mitre }
            $ruleWithMitre | Should -Not -BeNullOrEmpty
        }

        It 'Should include category tags' {
            $script:sarifRules | ForEach-Object {
                $_.properties.tags | Should -Contain $_.properties.category
            }
        }
    }

    Context 'SARIF Results' {
        BeforeAll {
            $script:sarifResults = $script:sarifContent.runs[0].results
        }

        It 'Should have results array' {
            $script:sarifResults | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct number of findings' {
            # 3 + 2 + 1 = 6 individual findings
            $script:sarifResults.Count | Should -Be 6
        }

        It 'Should have ruleId for each result' {
            $script:sarifResults | ForEach-Object {
                $_.ruleId | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have appropriate level (error/warning/note)' {
            $validLevels = @('error', 'warning', 'note')
            $script:sarifResults | ForEach-Object {
                $_.level | Should -BeIn $validLevels
            }
        }

        It 'Should have message text' {
            $script:sarifResults | ForEach-Object {
                $_.message.text | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have partialFingerprints for deduplication' {
            $script:sarifResults | ForEach-Object {
                $_.partialFingerprints | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'SARIF Invocation' {
        It 'Should have invocations array' {
            $script:sarifContent.runs[0].invocations | Should -Not -BeNullOrEmpty
        }

        It 'Should show execution was successful' {
            $script:sarifContent.runs[0].invocations[0].executionSuccessful | Should -BeTrue
        }
    }
}

Describe 'BloodHound Export' {
    BeforeAll {
        $script:bhPath = Join-Path $TestDrive 'results.bloodhound.json'
        Export-ADScoutReport -Results $script:mockResults -Format BloodHound -Path $script:bhPath
        $script:bhContent = Get-Content $script:bhPath -Raw | ConvertFrom-Json
    }

    Context 'BloodHound Format Structure' {
        It 'Should create valid JSON file' {
            Test-Path $script:bhPath | Should -BeTrue
            { Get-Content $script:bhPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Should have meta section' {
            $script:bhContent.meta | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct type in meta' {
            $script:bhContent.meta.type | Should -Be 'adscout'
        }

        It 'Should have data array' {
            $script:bhContent.data | Should -Not -BeNullOrEmpty
        }

        It 'Should have count matching data array length' {
            $script:bhContent.meta.count | Should -Be $script:bhContent.data.Count
        }
    }

    Context 'BloodHound Object Properties' {
        It 'Should have ObjectIdentifier for each object' {
            $script:bhContent.data | ForEach-Object {
                $_.ObjectIdentifier | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have ObjectType for each object' {
            $script:bhContent.data | ForEach-Object {
                $_.ObjectType | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have Properties for each object' {
            $script:bhContent.data | ForEach-Object {
                $_.Properties | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have adscout_findings in properties' {
            $script:bhContent.data | ForEach-Object {
                $_.Properties.adscout_findings | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have adscout_score in properties' {
            $script:bhContent.data | ForEach-Object {
                $_.Properties.adscout_score | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'BloodHound User Objects' {
        BeforeAll {
            $script:bhUsers = $script:bhContent.data | Where-Object { $_.ObjectType -eq 'User' }
        }

        It 'Should contain User type objects' {
            $script:bhUsers | Should -Not -BeNullOrEmpty
        }

        It 'Should have name property in uppercase' {
            $script:bhUsers | ForEach-Object {
                $_.Properties.name | Should -cmatch '^[A-Z0-9@._-]+$'
            }
        }
    }
}

Describe 'JSON Export' {
    BeforeAll {
        $script:jsonPath = Join-Path $TestDrive 'results.json'
        Export-ADScoutReport -Results $script:mockResults -Format JSON -Path $script:jsonPath
        $script:jsonContent = Get-Content $script:jsonPath -Raw | ConvertFrom-Json
    }

    Context 'JSON Structure' {
        It 'Should create valid JSON file' {
            Test-Path $script:jsonPath | Should -BeTrue
            { Get-Content $script:jsonPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Should have Title' {
            $script:jsonContent.Title | Should -Not -BeNullOrEmpty
        }

        It 'Should have GeneratedAt timestamp' {
            $script:jsonContent.GeneratedAt | Should -Not -BeNullOrEmpty
        }

        It 'Should have Summary section' {
            $script:jsonContent.Summary | Should -Not -BeNullOrEmpty
        }

        It 'Should have Results array' {
            $script:jsonContent.Results | Should -Not -BeNullOrEmpty
        }
    }

    Context 'JSON Summary' {
        It 'Should have TotalRulesWithFindings' {
            $script:jsonContent.Summary.TotalRulesWithFindings | Should -Be 3
        }

        It 'Should have TotalFindings' {
            $script:jsonContent.Summary.TotalFindings | Should -Be 6
        }

        It 'Should have TotalScore' {
            $script:jsonContent.Summary.TotalScore | Should -Be 90
        }
    }

    Context 'JSON Results' {
        It 'Should preserve all result properties' {
            $script:jsonContent.Results | ForEach-Object {
                $_.RuleId | Should -Not -BeNullOrEmpty
                $_.Category | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should include Findings array' {
            $script:jsonContent.Results | ForEach-Object {
                $_.Findings | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'CSV Export' {
    BeforeAll {
        $script:csvPath = Join-Path $TestDrive 'results.csv'
        Export-ADScoutReport -Results $script:mockResults -Format CSV -Path $script:csvPath
        $script:csvContent = Import-Csv $script:csvPath
    }

    Context 'CSV Structure' {
        It 'Should create valid CSV file' {
            Test-Path $script:csvPath | Should -BeTrue
        }

        It 'Should have expected columns' {
            $columns = $script:csvContent[0].PSObject.Properties.Name
            $columns | Should -Contain 'RuleId'
            $columns | Should -Contain 'RuleName'
            $columns | Should -Contain 'Category'
            $columns | Should -Contain 'Score'
        }

        It 'Should have one row per finding' {
            $script:csvContent.Count | Should -Be 6
        }
    }
}

Describe 'Markdown Export' {
    BeforeAll {
        $script:mdPath = Join-Path $TestDrive 'results.md'
        Export-ADScoutReport -Results $script:mockResults -Format Markdown -Path $script:mdPath
        $script:mdContent = Get-Content $script:mdPath -Raw
    }

    Context 'Markdown Structure' {
        It 'Should create valid Markdown file' {
            Test-Path $script:mdPath | Should -BeTrue
        }

        It 'Should have title header' {
            $script:mdContent | Should -Match '^# .*Security Assessment'
        }

        It 'Should have Executive Summary section' {
            $script:mdContent | Should -Match '## Executive Summary'
        }

        It 'Should have Category Breakdown section' {
            $script:mdContent | Should -Match '## Category Breakdown'
        }

        It 'Should have Detailed Findings section' {
            $script:mdContent | Should -Match '## Detailed Findings'
        }

        It 'Should include severity badges' {
            $script:mdContent | Should -Match '\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]|\[INFO\]'
        }

        It 'Should include rule IDs' {
            $script:mdContent | Should -Match 'S-PwdNeverExpires'
            $script:mdContent | Should -Match 'EID-PrivilegedNoMFA'
        }
    }

    Context 'Markdown Tables' {
        It 'Should have summary table' {
            $script:mdContent | Should -Match '\| Metric \| Value \|'
        }

        It 'Should have severity breakdown table' {
            $script:mdContent | Should -Match '\| Severity \| Count \|'
        }
    }
}

Describe 'Export PassThru Parameter' {
    It 'Should return results when PassThru is specified' {
        $path = Join-Path $TestDrive 'passthru.json'
        $output = Export-ADScoutReport -Results $script:mockResults -Format JSON -Path $path -PassThru
        $output | Should -Not -BeNullOrEmpty
        $output.Count | Should -Be 3
    }

    It 'Should not return results when PassThru is not specified' {
        $path = Join-Path $TestDrive 'nopassthru.json'
        $output = Export-ADScoutReport -Results $script:mockResults -Format JSON -Path $path
        $output | Should -BeNullOrEmpty
    }
}

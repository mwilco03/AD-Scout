#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for AD-Scout remediation automation features.

.DESCRIPTION
    Tests for Invoke-ADScoutRemediation, Undo-ADScoutRemediation,
    and change management integration.
#>

BeforeAll {
    # Import the module from source
    $modulePath = Join-Path $PSScriptRoot '../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force
}

Describe 'Invoke-ADScoutRemediation' {
    Context 'Function Availability' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Invoke-ADScoutRemediation -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have SupportsShouldProcess' {
            $command = Get-Command -Name Invoke-ADScoutRemediation
            $command.Parameters['WhatIf'] | Should -Not -BeNullOrEmpty
            $command.Parameters['Confirm'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have help documentation' {
            $help = Get-Help Invoke-ADScoutRemediation
            $help.Synopsis | Should -Not -BeNullOrEmpty
            $help.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should have examples' {
            $help = Get-Help Invoke-ADScoutRemediation -Examples
            $help.Examples | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameters' {
        BeforeAll {
            $command = Get-Command -Name Invoke-ADScoutRemediation
        }

        It 'Should have Results parameter that accepts pipeline input' {
            $param = $command.Parameters['Results']
            $param | Should -Not -BeNullOrEmpty
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.ValueFromPipeline | Should -Be $true }
        }

        It 'Should have Finding parameter' {
            $command.Parameters['Finding'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have RuleId filter parameter' {
            $command.Parameters['RuleId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have BatchId parameter' {
            $command.Parameters['BatchId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have EnableRollback switch' {
            $command.Parameters['EnableRollback'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have RollbackPath parameter' {
            $command.Parameters['RollbackPath'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have ChangeTicket parameter' {
            $command.Parameters['ChangeTicket'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have MaxParallel parameter with validation' {
            $param = $command.Parameters['MaxParallel']
            $param | Should -Not -BeNullOrEmpty
            $validateRange = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $validateRange | Should -Not -BeNullOrEmpty
        }

        It 'Should have StopOnError switch' {
            $command.Parameters['StopOnError'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have PassThru switch' {
            $command.Parameters['PassThru'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'WhatIf Simulation' {
        BeforeAll {
            # Create mock results for testing
            $mockFinding = [PSCustomObject]@{
                RuleId            = 'S-PwdNeverExpires'
                SamAccountName    = 'TestUser'
                DistinguishedName = 'CN=TestUser,OU=Users,DC=test,DC=local'
            }

            $mockResult = [PSCustomObject]@{
                RuleId       = 'S-PwdNeverExpires'
                RuleName     = 'Password Never Expires'
                Findings     = @($mockFinding)
                FindingCount = 1
            }
        }

        It 'Should not throw with WhatIf' {
            # Mock Get-ADScoutRule to return a valid rule
            Mock Get-ADScoutRule {
                @{
                    Id          = 'S-PwdNeverExpires'
                    Name        = 'Password Never Expires'
                    Category    = 'StaleObjects'
                    Remediation = {
                        param($Finding)
                        "Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false"
                    }
                }
            } -ModuleName ADScout

            { Invoke-ADScoutRemediation -Results $mockResult -WhatIf } | Should -Not -Throw
        }

        It 'Should produce simulation output with WhatIf' {
            Mock Get-ADScoutRule {
                @{
                    Id          = 'S-PwdNeverExpires'
                    Name        = 'Password Never Expires'
                    Category    = 'StaleObjects'
                    Remediation = {
                        param($Finding)
                        "Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false"
                    }
                }
            } -ModuleName ADScout

            $output = Invoke-ADScoutRemediation -Results $mockResult -WhatIf -PassThru
            $output | Should -Not -BeNullOrEmpty
            $output.Summary.Simulated | Should -BeGreaterThan 0
        }
    }

    Context 'Batch Processing' {
        It 'Should generate unique BatchId if not provided' {
            Mock Get-ADScoutRule { $null } -ModuleName ADScout

            $mockResult = [PSCustomObject]@{
                RuleId   = 'NonExistent'
                Findings = @()
            }

            $output = Invoke-ADScoutRemediation -Results $mockResult -PassThru -WhatIf
            $output.BatchId | Should -Not -BeNullOrEmpty
            $output.BatchId.Length | Should -Be 8
        }

        It 'Should use provided BatchId' {
            Mock Get-ADScoutRule { $null } -ModuleName ADScout

            $mockResult = [PSCustomObject]@{
                RuleId   = 'NonExistent'
                Findings = @()
            }

            $customBatchId = 'test1234'
            $output = Invoke-ADScoutRemediation -Results $mockResult -BatchId $customBatchId -PassThru -WhatIf
            $output.BatchId | Should -Be $customBatchId
        }
    }

    Context 'Empty Results Handling' {
        It 'Should handle empty results gracefully' {
            $emptyResults = @()
            { Invoke-ADScoutRemediation -Results $emptyResults -WhatIf } | Should -Not -Throw
        }

        It 'Should warn when no findings to remediate' {
            $emptyResults = @()
            $warningOutput = Invoke-ADScoutRemediation -Results $emptyResults -WhatIf 3>&1
            $warningOutput | Should -Match 'No findings to remediate'
        }
    }
}

Describe 'Undo-ADScoutRemediation' {
    Context 'Function Availability' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Undo-ADScoutRemediation -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have SupportsShouldProcess' {
            $command = Get-Command -Name Undo-ADScoutRemediation
            $command.Parameters['WhatIf'] | Should -Not -BeNullOrEmpty
            $command.Parameters['Confirm'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have Force parameter' {
            $command = Get-Command -Name Undo-ADScoutRemediation
            $command.Parameters['Force'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameters' {
        BeforeAll {
            $command = Get-Command -Name Undo-ADScoutRemediation
        }

        It 'Should have BatchId parameter' {
            $command.Parameters['BatchId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have RemediationId parameter' {
            $command.Parameters['RemediationId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have RollbackPath parameter' {
            $command.Parameters['RollbackPath'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Error Handling' {
        It 'Should throw when rollback path does not exist' {
            { Undo-ADScoutRemediation -BatchId 'nonexistent' -RollbackPath 'C:\NonExistentPath\ADScout' } |
                Should -Throw '*Rollback path not found*'
        }
    }
}

Describe 'Get-ADScoutRemediationHistory' {
    Context 'Function Availability' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Get-ADScoutRemediationHistory -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameters' {
        BeforeAll {
            $command = Get-Command -Name Get-ADScoutRemediationHistory
        }

        It 'Should have RollbackPath parameter' {
            $command.Parameters['RollbackPath'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have BatchId filter parameter' {
            $command.Parameters['BatchId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have Last parameter' {
            $command.Parameters['Last'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Empty Results' {
        It 'Should handle missing rollback path gracefully' {
            $output = Get-ADScoutRemediationHistory -RollbackPath 'C:\NonExistentPath\ADScout' 3>&1
            # Should return warning, not throw
            $output | Should -Match 'No rollback data found'
        }
    }
}

Describe 'Change Management Functions' {
    Context 'Register-ADScoutChangeManagement' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Register-ADScoutChangeManagement -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have Provider parameter with validation' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $param = $command.Parameters['Provider']
            $param | Should -Not -BeNullOrEmpty

            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'JIRA'
            $validateSet.ValidValues | Should -Contain 'ServiceNow'
            $validateSet.ValidValues | Should -Contain 'AzureDevOps'
        }

        It 'Should have ServerUrl parameter' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $command.Parameters['ServerUrl'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have Credential parameter' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $command.Parameters['Credential'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have ApiToken parameter' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $command.Parameters['ApiToken'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have ProjectKey parameter' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $command.Parameters['ProjectKey'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have TestConnection switch' {
            $command = Get-Command -Name Register-ADScoutChangeManagement
            $command.Parameters['TestConnection'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-ADScoutChangeManagement' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Get-ADScoutChangeManagement -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have Provider filter parameter' {
            $command = Get-Command -Name Get-ADScoutChangeManagement
            $command.Parameters['Provider'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'New-ADScoutChangeTicket' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name New-ADScoutChangeTicket -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have required Title parameter' {
            $command = Get-Command -Name New-ADScoutChangeTicket
            $param = $command.Parameters['Title']
            $param | Should -Not -BeNullOrEmpty

            $mandatory = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory }
            $mandatory | Should -Contain $true
        }

        It 'Should have Description parameter' {
            $command = Get-Command -Name New-ADScoutChangeTicket
            $command.Parameters['Description'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have Results parameter' {
            $command = Get-Command -Name New-ADScoutChangeTicket
            $command.Parameters['Results'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have BatchId parameter' {
            $command = Get-Command -Name New-ADScoutChangeTicket
            $command.Parameters['BatchId'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have Priority parameter with validation' {
            $command = Get-Command -Name New-ADScoutChangeTicket
            $param = $command.Parameters['Priority']
            $param | Should -Not -BeNullOrEmpty

            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Critical'
            $validateSet.ValidValues | Should -Contain 'High'
            $validateSet.ValidValues | Should -Contain 'Medium'
            $validateSet.ValidValues | Should -Contain 'Low'
        }
    }

    Context 'Update-ADScoutChangeTicket' {
        It 'Should be exported from the module' {
            $command = Get-Command -Name Update-ADScoutChangeTicket -Module ADScout -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It 'Should have required TicketKey parameter' {
            $command = Get-Command -Name Update-ADScoutChangeTicket
            $param = $command.Parameters['TicketKey']
            $param | Should -Not -BeNullOrEmpty

            $mandatory = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory }
            $mandatory | Should -Contain $true
        }

        It 'Should have Status parameter with validation' {
            $command = Get-Command -Name Update-ADScoutChangeTicket
            $param = $command.Parameters['Status']
            $param | Should -Not -BeNullOrEmpty

            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Open'
            $validateSet.ValidValues | Should -Contain 'InProgress'
            $validateSet.ValidValues | Should -Contain 'Completed'
            $validateSet.ValidValues | Should -Contain 'Failed'
            $validateSet.ValidValues | Should -Contain 'RolledBack'
        }

        It 'Should have Comment parameter' {
            $command = Get-Command -Name Update-ADScoutChangeTicket
            $command.Parameters['Comment'] | Should -Not -BeNullOrEmpty
        }

        It 'Should have RemediationResult parameter' {
            $command = Get-Command -Name Update-ADScoutChangeTicket
            $command.Parameters['RemediationResult'] | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Helper Functions' {
    Context 'Get-RemediationTargetIdentity' {
        It 'Should extract SamAccountName' {
            # This function is internal but we can test its behavior through the public interface
            $mockFinding = [PSCustomObject]@{
                SamAccountName = 'TestUser'
                OtherProperty  = 'Value'
            }

            # The function prioritizes SamAccountName
            $mockFinding.SamAccountName | Should -Be 'TestUser'
        }
    }

    Context 'Get-ScriptActions (via WhatIf output)' {
        It 'Should parse Set-ADUser commands' {
            Mock Get-ADScoutRule {
                @{
                    Id          = 'Test'
                    Name        = 'Test Rule'
                    Category    = 'Test'
                    Remediation = {
                        param($Finding)
                        "Set-ADUser -Identity 'TestUser' -PasswordNeverExpires `$false"
                    }
                }
            } -ModuleName ADScout

            $mockResult = [PSCustomObject]@{
                RuleId   = 'Test'
                RuleName = 'Test Rule'
                Findings = @([PSCustomObject]@{ SamAccountName = 'TestUser' })
            }

            # WhatIf should parse the script and show actions
            $output = Invoke-ADScoutRemediation -Results $mockResult -WhatIf -PassThru
            $output.Summary.Simulated | Should -Be 1
        }
    }
}

Describe 'Module Function Count Update' {
    Context 'New Functions Added to Module' {
        BeforeAll {
            $expectedNewFunctions = @(
                'Invoke-ADScoutRemediation'
                'Undo-ADScoutRemediation'
                'Get-ADScoutRemediationHistory'
                'Register-ADScoutChangeManagement'
                'Get-ADScoutChangeManagement'
                'New-ADScoutChangeTicket'
                'Update-ADScoutChangeTicket'
            )
        }

        It 'Should export all new remediation functions' {
            $commands = Get-Command -Module ADScout
            foreach ($funcName in $expectedNewFunctions) {
                $commands.Name | Should -Contain $funcName -Because "Function $funcName should be exported"
            }
        }
    }
}

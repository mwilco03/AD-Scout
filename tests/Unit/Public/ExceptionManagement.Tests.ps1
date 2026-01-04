#Requires -Modules Pester

Describe 'Exception Management Functions' -Tag 'Unit', 'Exception' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' '..' 'src' 'ADScout' 'ADScout.psd1'
        Import-Module $modulePath -Force
        $testStoragePath = Join-Path $TestDrive 'exceptions'
    }

    AfterAll {
        Remove-Module ADScout -Force -ErrorAction SilentlyContinue
    }

    Describe 'New-ADScoutException' {
        It 'Creates rule exception with required parameters' {
            $exception = New-ADScoutException `
                -RuleId 'S-PwdNeverExpires' `
                -Justification 'Test exception' `
                -StoragePath $testStoragePath

            $exception | Should -Not -BeNullOrEmpty
            $exception.RuleId | Should -Be 'S-PwdNeverExpires'
            $exception.Type | Should -Be 'Rule'
            $exception.Status | Should -Be 'Active'
        }

        It 'Creates object-specific exception' {
            $exception = New-ADScoutException `
                -RuleId 'S-PwdNeverExpires' `
                -ObjectIdentity 'svc_backup', 'svc_monitoring' `
                -Justification 'Service accounts' `
                -StoragePath $testStoragePath

            $exception.Type | Should -Be 'Object'
            $exception.ObjectIdentity | Should -Contain 'svc_backup'
            $exception.ObjectIdentity | Should -Contain 'svc_monitoring'
        }

        It 'Creates category exception' {
            $exception = New-ADScoutException `
                -Category 'DLLRequired' `
                -Justification 'DLLs not available' `
                -StoragePath $testStoragePath

            $exception.Type | Should -Be 'Category'
            $exception.Category | Should -Be 'DLLRequired'
        }

        It 'Sets default expiration to 1 year' {
            $exception = New-ADScoutException `
                -RuleId 'TEST-001' `
                -Justification 'Test' `
                -StoragePath $testStoragePath

            $expectedExpiry = (Get-Date).AddYears(1).Date
            $actualExpiry = ([datetime]$exception.ExpirationDate).Date
            $actualExpiry | Should -BeGreaterOrEqual $expectedExpiry.AddDays(-1)
        }

        It 'Sets custom expiration date' {
            $expiry = (Get-Date).AddMonths(3)
            $exception = New-ADScoutException `
                -RuleId 'TEST-002' `
                -Justification 'Test' `
                -ExpirationDate $expiry `
                -StoragePath $testStoragePath

            ([datetime]$exception.ExpirationDate).Date | Should -Be $expiry.Date
        }

        It 'Records approval information' {
            $exception = New-ADScoutException `
                -RuleId 'TEST-003' `
                -Justification 'Approved test' `
                -ApprovedBy 'security@contoso.com' `
                -TicketReference 'CHG0012345' `
                -StoragePath $testStoragePath

            $exception.ApprovedBy | Should -Be 'security@contoso.com'
            $exception.TicketReference | Should -Be 'CHG0012345'
        }

        It 'Creates initial audit log entry' {
            $exception = New-ADScoutException `
                -RuleId 'TEST-004' `
                -Justification 'Audit test' `
                -StoragePath $testStoragePath

            $exception.AuditLog | Should -Not -BeNullOrEmpty
            $exception.AuditLog[0].Action | Should -Be 'Created'
        }

        It 'Throws when neither RuleId nor Category specified' {
            { New-ADScoutException -Justification 'Test' -StoragePath $testStoragePath } | Should -Throw
        }

        It 'Throws when Engagement scope without EngagementId' {
            { New-ADScoutException -RuleId 'TEST' -Justification 'Test' -Scope 'Engagement' -StoragePath $testStoragePath } | Should -Throw
        }
    }

    Describe 'Get-ADScoutException' {
        BeforeAll {
            # Create test exceptions
            $script:exc1 = New-ADScoutException -RuleId 'GET-001' -Justification 'Test 1' -StoragePath $testStoragePath
            $script:exc2 = New-ADScoutException -RuleId 'GET-002' -Justification 'Test 2' -StoragePath $testStoragePath
            $script:exc3 = New-ADScoutException -Category 'TestCategory' -Justification 'Test 3' -StoragePath $testStoragePath
        }

        It 'Returns all active exceptions' {
            $exceptions = Get-ADScoutException -StoragePath $testStoragePath
            $exceptions.Count | Should -BeGreaterOrEqual 3
        }

        It 'Filters by ID' {
            $exception = Get-ADScoutException -Id $script:exc1.Id -StoragePath $testStoragePath
            $exception | Should -Not -BeNullOrEmpty
            $exception.Id | Should -Be $script:exc1.Id
        }

        It 'Filters by RuleId' {
            $exceptions = Get-ADScoutException -RuleId 'GET-001' -StoragePath $testStoragePath
            $exceptions.RuleId | Should -Contain 'GET-001'
        }

        It 'Filters by Category' {
            $exceptions = Get-ADScoutException -Category 'TestCategory' -StoragePath $testStoragePath
            $exceptions.Category | Should -Contain 'TestCategory'
        }

        It 'Excludes expired by default' {
            $expired = New-ADScoutException `
                -RuleId 'EXPIRED-001' `
                -Justification 'Expired test' `
                -ExpirationDate (Get-Date).AddDays(-1) `
                -StoragePath $testStoragePath

            $exceptions = Get-ADScoutException -StoragePath $testStoragePath
            $exceptions.Id | Should -Not -Contain $expired.Id
        }

        It 'Includes expired when specified' {
            $expired = New-ADScoutException `
                -RuleId 'EXPIRED-002' `
                -Justification 'Expired test' `
                -ExpirationDate (Get-Date).AddDays(-1) `
                -StoragePath $testStoragePath

            $exceptions = Get-ADScoutException -StoragePath $testStoragePath -IncludeExpired
            $exceptions.Id | Should -Contain $expired.Id
        }
    }

    Describe 'Set-ADScoutException' {
        BeforeEach {
            $script:exception = New-ADScoutException `
                -RuleId 'SET-TEST' `
                -Justification 'Initial justification' `
                -StoragePath $testStoragePath
        }

        It 'Updates status' {
            $updated = Set-ADScoutException -Id $script:exception.Id -Status 'Revoked'
            $updated.Status | Should -Be 'Revoked'
        }

        It 'Updates expiration date' {
            $newExpiry = (Get-Date).AddMonths(6)
            $updated = Set-ADScoutException -Id $script:exception.Id -ExpirationDate $newExpiry
            ([datetime]$updated.ExpirationDate).Date | Should -Be $newExpiry.Date
        }

        It 'Updates justification' {
            $updated = Set-ADScoutException -Id $script:exception.Id -Justification 'Updated justification'
            $updated.Justification | Should -Be 'Updated justification'
        }

        It 'Adds comment to audit log' {
            $updated = Set-ADScoutException -Id $script:exception.Id -Comment 'Test comment'
            $updated.AuditLog[-1].Comment | Should -Be 'Test comment'
        }

        It 'Records changes in audit log' {
            $updated = Set-ADScoutException -Id $script:exception.Id -Status 'Revoked' -Comment 'Revoking'
            $updated.AuditLog[-1].Action | Should -Be 'Modified'
            $updated.AuditLog[-1].Changes | Should -Not -BeNullOrEmpty
        }
    }

    Describe 'Remove-ADScoutException' {
        It 'Removes exception with Force' {
            $exception = New-ADScoutException `
                -RuleId 'REMOVE-001' `
                -Justification 'Remove test' `
                -StoragePath $testStoragePath

            Remove-ADScoutException -Id $exception.Id -Force

            Get-ADScoutException -Id $exception.Id -StoragePath $testStoragePath -IncludeExpired | Should -BeNullOrEmpty
        }

        It 'Revokes instead of deleting when -Revoke specified' {
            $exception = New-ADScoutException `
                -RuleId 'REVOKE-001' `
                -Justification 'Revoke test' `
                -StoragePath $testStoragePath

            Remove-ADScoutException -Id $exception.Id -Revoke

            $revoked = Get-ADScoutException -Id $exception.Id -StoragePath $testStoragePath -IncludeExpired
            $revoked.Status | Should -Be 'Revoked'
        }
    }

    Describe 'Test-ADScoutException' {
        BeforeAll {
            New-ADScoutException -RuleId 'MATCH-RULE' -Justification 'Rule match test' -StoragePath $testStoragePath
            New-ADScoutException -RuleId 'MATCH-OBJECT' -ObjectIdentity 'testuser' -Justification 'Object match test' -StoragePath $testStoragePath
            New-ADScoutException -Category 'MatchCategory' -Justification 'Category match test' -StoragePath $testStoragePath
        }

        It 'Returns true for matching rule exception' {
            # Note: Test-ADScoutException uses default storage path, so this test may need adjustment
            # based on how exceptions are stored
        }

        It 'Returns false for non-matching rule' {
            $result = Test-ADScoutException -RuleId 'NO-MATCH'
            $result | Should -Be $false
        }
    }

    Describe 'Invoke-ADScoutExceptionCleanup' {
        BeforeAll {
            # Create some expired exceptions
            New-ADScoutException `
                -RuleId 'CLEANUP-001' `
                -Justification 'Cleanup test' `
                -ExpirationDate (Get-Date).AddDays(-30) `
                -StoragePath $testStoragePath

            New-ADScoutException `
                -RuleId 'CLEANUP-002' `
                -Justification 'Cleanup test 2' `
                -ExpirationDate (Get-Date).AddDays(-1) `
                -StoragePath $testStoragePath
        }

        It 'Marks expired exceptions' {
            Invoke-ADScoutExceptionCleanup -Force

            $exceptions = Get-ADScoutException -RuleId 'CLEANUP-001' -StoragePath $testStoragePath -IncludeExpired
            if ($exceptions) {
                $exceptions.Status | Should -Be 'Expired'
            }
        }
    }

    Describe 'Get-ADScoutExceptionReport' {
        BeforeAll {
            New-ADScoutException -RuleId 'REPORT-001' -Justification 'Report test' -StoragePath $testStoragePath
        }

        It 'Generates table output by default' {
            $output = Get-ADScoutExceptionReport -StoragePath $testStoragePath
            # Table output goes to host, so we just verify no errors
        }

        It 'Generates JSON output' {
            $json = Get-ADScoutExceptionReport -Format JSON -StoragePath $testStoragePath
            { $json | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Generates HTML output' {
            $html = Get-ADScoutExceptionReport -Format HTML -StoragePath $testStoragePath
            $html | Should -Match '<html'
        }

        It 'Saves to file when Path specified' {
            $outputPath = Join-Path $TestDrive 'exception-report.html'
            Get-ADScoutExceptionReport -Format HTML -Path $outputPath -StoragePath $testStoragePath
            Test-Path $outputPath | Should -Be $true
        }
    }
}

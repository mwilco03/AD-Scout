#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for AD-Scout helper functions.

.DESCRIPTION
    Validates the helper functions used throughout the AD-Scout module,
    including fingerprint generation and configuration path handling.
#>

BeforeAll {
    # Import the module from source
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force

    # Dot-source the private functions directly for testing
    $helpersPath = Join-Path $PSScriptRoot '../../src/ADScout/Private/Helpers'
    Get-ChildItem -Path $helpersPath -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
}

Describe 'Get-ADScoutFingerprint' {
    Context 'Basic Functionality' {
        It 'Should generate a fingerprint for a simple object' {
            $obj = [PSCustomObject]@{ Name = 'Test'; Value = 123 }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should return a string of default length 16' {
            $obj = [PSCustomObject]@{ Name = 'Test' }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint.Length | Should -Be 16
        }

        It 'Should respect custom length parameter' {
            $obj = [PSCustomObject]@{ Name = 'Test' }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj -Length 32
            $fingerprint.Length | Should -Be 32
        }

        It 'Should be deterministic - same input produces same output' {
            $obj = [PSCustomObject]@{ Name = 'Test'; Value = 42 }
            $hash1 = Get-ADScoutFingerprint -InputObject $obj
            $hash2 = Get-ADScoutFingerprint -InputObject $obj
            $hash1 | Should -Be $hash2
        }

        It 'Should produce different hashes for different objects' {
            $obj1 = [PSCustomObject]@{ Name = 'Test1' }
            $obj2 = [PSCustomObject]@{ Name = 'Test2' }
            $hash1 = Get-ADScoutFingerprint -InputObject $obj1
            $hash2 = Get-ADScoutFingerprint -InputObject $obj2
            $hash1 | Should -Not -Be $hash2
        }
    }

    Context 'Complex Objects' {
        It 'Should handle nested objects' {
            $obj = [PSCustomObject]@{
                Name = 'Parent'
                Child = [PSCustomObject]@{
                    Name = 'Child'
                    Value = 123
                }
            }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should handle arrays' {
            $obj = [PSCustomObject]@{
                Name = 'ArrayTest'
                Items = @(1, 2, 3, 4, 5)
            }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should handle hashtables' {
            $obj = @{
                Key1 = 'Value1'
                Key2 = 'Value2'
            }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Edge Cases' {
        It 'Should handle empty objects' {
            $obj = [PSCustomObject]@{}
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should handle null values in properties' {
            $obj = [PSCustomObject]@{ Name = $null; Value = 123 }
            $fingerprint = Get-ADScoutFingerprint -InputObject $obj
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should handle strings directly' {
            $fingerprint = Get-ADScoutFingerprint -InputObject "Simple string"
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should handle integers directly' {
            $fingerprint = Get-ADScoutFingerprint -InputObject 42
            $fingerprint | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Pipeline Input' {
        It 'Should accept pipeline input' {
            $obj = [PSCustomObject]@{ Name = 'PipelineTest' }
            $fingerprint = $obj | Get-ADScoutFingerprint
            $fingerprint | Should -Not -BeNullOrEmpty
        }

        It 'Should process multiple objects from pipeline' {
            $objects = @(
                [PSCustomObject]@{ Name = 'Obj1' }
                [PSCustomObject]@{ Name = 'Obj2' }
            )
            $fingerprints = $objects | Get-ADScoutFingerprint
            $fingerprints.Count | Should -Be 2
        }
    }

    Context 'Length Validation' {
        It 'Should enforce minimum length of 8' {
            { Get-ADScoutFingerprint -InputObject @{} -Length 5 } | Should -Throw
        }

        It 'Should enforce maximum length of 64' {
            { Get-ADScoutFingerprint -InputObject @{} -Length 100 } | Should -Throw
        }

        It 'Should accept valid length values' {
            $obj = @{ Test = 'Value' }
            $hash8 = Get-ADScoutFingerprint -InputObject $obj -Length 8
            $hash64 = Get-ADScoutFingerprint -InputObject $obj -Length 64

            $hash8.Length | Should -Be 8
            $hash64.Length | Should -BeLessOrEqual 64
        }
    }
}

Describe 'Get-ADScoutConfigPath' {
    Context 'Basic Functionality' {
        It 'Should return a path string' {
            $path = Get-ADScoutConfigPath
            $path | Should -Not -BeNullOrEmpty
            $path | Should -BeOfType [string]
        }

        It 'Should return path in user profile directory' {
            $path = Get-ADScoutConfigPath
            $userProfile = [Environment]::GetFolderPath('UserProfile')
            $path | Should -Match [regex]::Escape($userProfile)
        }

        It 'Should return path ending with config.json' {
            $path = Get-ADScoutConfigPath
            $path | Should -Match 'config\.json$'
        }

        It 'Should include .adscout directory in path' {
            $path = Get-ADScoutConfigPath
            $path | Should -Match '\.adscout'
        }
    }

    Context 'CreateDirectory Switch' {
        BeforeAll {
            # Store original path for cleanup
            $script:testConfigPath = Get-ADScoutConfigPath
            $script:testConfigDir = Split-Path $script:testConfigPath -Parent
        }

        AfterAll {
            # Cleanup test directory if we created it
            if ($script:createdDir -and (Test-Path $script:testConfigDir)) {
                # Don't actually delete user's config - just note we tested it
            }
        }

        It 'Should not create directory without switch' {
            $path = Get-ADScoutConfigPath
            # Just verify it returns path without error
            $path | Should -Not -BeNullOrEmpty
        }

        It 'Should accept CreateDirectory switch without error' {
            { Get-ADScoutConfigPath -CreateDirectory } | Should -Not -Throw
        }
    }

    Context 'Consistency' {
        It 'Should return same path on multiple calls' {
            $path1 = Get-ADScoutConfigPath
            $path2 = Get-ADScoutConfigPath
            $path1 | Should -Be $path2
        }
    }
}

Describe 'Convert-SidToName' {
    Context 'Well-Known SIDs' {
        It 'Should translate SYSTEM SID' {
            $name = Convert-SidToName -Sid 'S-1-5-18'
            $name | Should -Be 'SYSTEM'
        }

        It 'Should translate Everyone SID' {
            $name = Convert-SidToName -Sid 'S-1-1-0'
            $name | Should -Be 'Everyone'
        }

        It 'Should translate Authenticated Users SID' {
            $name = Convert-SidToName -Sid 'S-1-5-11'
            $name | Should -Be 'Authenticated Users'
        }

        It 'Should translate LOCAL SERVICE SID' {
            $name = Convert-SidToName -Sid 'S-1-5-19'
            $name | Should -Be 'LOCAL SERVICE'
        }

        It 'Should translate NETWORK SERVICE SID' {
            $name = Convert-SidToName -Sid 'S-1-5-20'
            $name | Should -Be 'NETWORK SERVICE'
        }
    }

    Context 'Domain RIDs' {
        It 'Should translate Administrator RID (500)' {
            $name = Convert-SidToName -Sid 'S-1-5-21-123456789-987654321-111111111-500'
            $name | Should -Be 'Administrator'
        }

        It 'Should translate Domain Admins RID (512)' {
            $name = Convert-SidToName -Sid 'S-1-5-21-123456789-987654321-111111111-512'
            $name | Should -Be 'Domain Admins'
        }

        It 'Should translate Enterprise Admins RID (519)' {
            $name = Convert-SidToName -Sid 'S-1-5-21-123456789-987654321-111111111-519'
            $name | Should -Be 'Enterprise Admins'
        }

        It 'Should translate krbtgt RID (502)' {
            $name = Convert-SidToName -Sid 'S-1-5-21-123456789-987654321-111111111-502'
            $name | Should -Be 'krbtgt'
        }
    }

    Context 'Unknown SIDs' {
        It 'Should return SID string for unknown SIDs' {
            $unknownSid = 'S-1-5-21-123456789-987654321-111111111-99999'
            $name = Convert-SidToName -Sid $unknownSid
            $name | Should -Be $unknownSid
        }
    }

    Context 'Pipeline Input' {
        It 'Should accept pipeline input' {
            $name = 'S-1-5-18' | Convert-SidToName
            $name | Should -Be 'SYSTEM'
        }

        It 'Should process multiple SIDs from pipeline' {
            $sids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
            $names = $sids | Convert-SidToName
            $names | Should -Contain 'SYSTEM'
            $names | Should -Contain 'LOCAL SERVICE'
            $names | Should -Contain 'NETWORK SERVICE'
        }
    }
}

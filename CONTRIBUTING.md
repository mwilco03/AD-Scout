# Contributing to AD-Scout

Thank you for your interest in contributing to AD-Scout! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include PowerShell version (`$PSVersionTable`)
4. Include AD-Scout version
5. Provide steps to reproduce
6. Include error messages and stack traces

### Suggesting Features

1. Check existing feature requests
2. Use the feature request template
3. Explain the use case and benefit
4. Consider backward compatibility

### Contributing Rules

We especially welcome new security rules! See [Creating Rules](#creating-rules) below.

1. Use the new rule template
2. Include MITRE ATT&CK mappings where applicable
3. Provide remediation guidance
4. Add unit tests

### Submitting Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`Invoke-Pester`)
5. Run linting (`Invoke-ScriptAnalyzer`)
6. Commit with clear messages
7. Push to your fork
8. Create a Pull Request

## Development Setup

```powershell
# Clone the repository
git clone https://github.com/mwilco03/AD-Scout.git
cd AD-Scout

# Install development dependencies
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser

# Import the module for development
Import-Module ./src/ADScout/ADScout.psd1 -Force

# Run tests
Invoke-Pester ./tests

# Run linting
Invoke-ScriptAnalyzer ./src -Recurse -Settings ./.psscriptanalyzerrc
```

## Creating Rules

Rules are the heart of AD-Scout. Each rule checks for a specific security condition.

### Rule Template

```powershell
# Create a new rule from template
New-ADScoutRule -Name "MyRule" -Category Anomalies -Path ./src/ADScout/Rules/Anomalies
```

### Rule Structure

```powershell
@{
    # Identity
    Id          = "A-MyRule"
    Name        = "Descriptive Rule Name"
    Category    = "Anomalies"
    Version     = "1.0.0"

    # Scoring
    Computation = "PerDiscover"
    Points      = 5
    MaxPoints   = 50

    # Framework Mappings
    MITRE       = @("T1078.002")
    CIS         = @()
    STIG        = @()

    # The Check
    ScriptBlock = {
        param([hashtable]$ADData)
        # Return findings
    }

    # Documentation
    Description = "Brief description"
    TechnicalExplanation = "Detailed explanation"

    # Remediation
    Remediation = {
        param($Finding)
        "# Remediation script"
    }
}
```

### Testing Rules

```powershell
# Run rule-specific tests
Invoke-Pester ./tests/Rules/A-MyRule.Tests.ps1

# Test rule execution
$rule = Get-ADScoutRule -Id A-MyRule
& $rule.ScriptBlock -ADData $mockData
```

## Coding Standards

### PowerShell Style

- Use `PascalCase` for functions and parameters
- Use `$camelCase` for variables
- Use approved verbs (Get, Set, New, Remove, etc.)
- Include comment-based help for all public functions
- Maximum line length: 120 characters

### Function Template

```powershell
function Verb-ADScoutNoun {
    <#
    .SYNOPSIS
        Brief description.

    .DESCRIPTION
        Detailed description.

    .PARAMETER Name
        Parameter description.

    .EXAMPLE
        Verb-ADScoutNoun -Name "Value"
        Example description.

    .OUTPUTS
        Output type description.

    .NOTES
        Author: Your Name
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Name
    )

    begin {
        Write-Verbose "Starting $($MyInvocation.MyCommand)"
    }

    process {
        # Implementation
    }

    end {
        Write-Verbose "Completed $($MyInvocation.MyCommand)"
    }
}
```

### Testing Requirements

- Unit tests for all public functions
- Mock AD dependencies (no live AD required for tests)
- 80% code coverage target
- Use descriptive test names

```powershell
Describe "Get-ADScoutRule" {
    Context "When called without parameters" {
        It "Should return all rules" {
            $rules = Get-ADScoutRule
            $rules | Should -Not -BeNullOrEmpty
        }
    }

    Context "When called with -Id" {
        It "Should return the specific rule" {
            $rule = Get-ADScoutRule -Id "S-PwdNeverExpires"
            $rule.Id | Should -Be "S-PwdNeverExpires"
        }
    }
}
```

## Commit Messages

Use clear, descriptive commit messages:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(rules): add Kerberos delegation detection rule

Adds S-UnconstrainedDelegation rule to detect computer accounts
with unconstrained delegation enabled.

Closes #42
```

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Ensure PSScriptAnalyzer passes
5. Update CHANGELOG.md
6. Request review from maintainers

## Questions?

- Open a Discussion for questions
- Join our community chat (coming soon)
- Email: security@example.com

Thank you for contributing to AD-Scout!

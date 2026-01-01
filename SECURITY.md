# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in AD-Scout, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by emailing the maintainers directly or using GitHub's private vulnerability reporting feature.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 1 week
- **Resolution Target**: Within 30 days for critical issues

### Safe Harbor

We support safe harbor for security researchers who:

- Act in good faith
- Avoid privacy violations
- Avoid data destruction
- Provide reasonable time for remediation
- Do not exploit vulnerabilities beyond proof-of-concept

## Security Best Practices for Users

### Running AD-Scout

1. **Least Privilege**: Use accounts with minimum required permissions
2. **Secure Output**: Reports may contain sensitive information - store securely
3. **Network Security**: Run from trusted networks
4. **Credential Handling**: Use secure credential methods (`Get-Credential`, not plaintext)

### Protecting Reports

AD-Scout reports may contain:
- User account names and properties
- Group membership information
- Computer account details
- Trust relationship data
- Configuration vulnerabilities

**Treat all reports as sensitive** and:
- Store in encrypted locations
- Limit access to authorized personnel
- Delete when no longer needed
- Never commit to public repositories

## Dependencies

We minimize dependencies and vet all external code. The module primarily uses:
- Built-in PowerShell cmdlets
- .NET Framework / .NET Core classes
- Windows Active Directory APIs

## Code Signing

Future releases will be code-signed with the project's certificate.

## Audit Log

AD-Scout operations can be logged. Enable verbose logging for audit trails:

```powershell
Invoke-ADScoutScan -Verbose *>&1 | Tee-Object -FilePath ./scan.log
```

## Contact

For security concerns, contact the maintainers through GitHub's security advisory feature or the repository's contact information.

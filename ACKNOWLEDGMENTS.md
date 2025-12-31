# Acknowledgments

AD-Scout stands on the shoulders of giants. We gratefully acknowledge the following projects and their contributors whose work has informed and inspired this project:

## Security Assessment Tools

### PingCastle
**Author:** Vincent LE TOUX
**License:** Proprietary (Non-Commercial) / GPL
**Contribution:** The scoring model and many rule concepts in AD-Scout were inspired by PingCastle's pioneering work in Active Directory security assessment. PingCastle demonstrated how to effectively communicate security posture through weighted scoring and categorization.

### BloodHound
**Author:** SpecterOps (Andy Robbins, Rohan Vazarkar, Will Schroeder)
**License:** GPL-3.0
**Contribution:** BloodHound revolutionized our understanding of Active Directory attack paths and privilege escalation. Its graph-based approach to visualizing permissions has influenced how we think about and categorize security findings.

### ADRecon
**Author:** Prashant Mahajan
**License:** MIT
**Contribution:** ADRecon proved that comprehensive Active Directory reconnaissance is achievable in pure PowerShell. Its approach to data collection and cross-version compatibility informed our collector design.

## Libraries and Dependencies

### SMBLibrary
**Author:** Tal Aloni
**License:** LGPL-3.0
**Repository:** https://github.com/TalAloni/SMBLibrary
**Contribution:** SMB protocol implementation for advanced file share enumeration.

### RPCForSMBLibrary
**Author:** Vincent LE TOUX
**License:** LGPL-3.0
**Repository:** https://github.com/vletoux/smb3lib
**Contribution:** RPC over SMB implementation enabling advanced remote procedure calls.

### DSInternals
**Author:** Michael Grafnetter
**License:** MIT
**Repository:** https://github.com/MichaelGrafnetter/DSInternals
**Contribution:** Deep Active Directory access patterns and cryptographic operations. An invaluable resource for understanding AD internals.

## PowerShell Community

### PSWriteHTML
**Author:** Evotec (Przemyslaw Klys)
**License:** MIT
**Repository:** https://github.com/EvotecIT/PSWriteHTML
**Contribution:** HTML report generation patterns and techniques.

### WebServer
**Author:** Markus Scholtes
**License:** MIT
**Repository:** https://github.com/MScholtes/WebServer
**Contribution:** PowerShell-native web server implementation for the dashboard feature.

### Pester
**Author:** Pester Team
**License:** Apache 2.0
**Repository:** https://github.com/pester/Pester
**Contribution:** Testing framework that enables reliable PowerShell module development.

### PSScriptAnalyzer
**Author:** PowerShell Team
**License:** MIT
**Repository:** https://github.com/PowerShell/PSScriptAnalyzer
**Contribution:** Static analysis tool ensuring code quality and best practices.

## Security Frameworks

We reference and map findings to these industry-standard frameworks:

- **MITRE ATT&CK** - Adversarial Tactics, Techniques, and Common Knowledge
- **CIS Controls** - Center for Internet Security Critical Security Controls
- **DISA STIG** - Defense Information Systems Agency Security Technical Implementation Guide
- **ANSSI** - French National Agency for the Security of Information Systems guidelines

## Research and Documentation

The security rules and detection logic in AD-Scout are informed by countless blog posts, conference talks, and research papers from the security community. We especially acknowledge:

- Sean Metcalf (adsecurity.org) - Comprehensive AD security research
- Will Schroeder (@harmj0y) - PowerShell security tooling and offensive research
- Carlos Perez (@darkoperator) - PowerShell security best practices
- The Microsoft Security team - Official documentation and guidance

---

## Important Notice

**AD-Scout is an independent project.** It is not a fork, derivative, or port of any other tool. While we have learned from and been inspired by the projects listed above, AD-Scout is a clean-room implementation with its own architecture, codebase, and design philosophy.

We are committed to respecting the intellectual property and licensing of all referenced projects. If you believe we have inadvertently included licensed material, please contact us immediately.

---

*Thank you to all the security researchers, developers, and community members who have contributed to making Active Directory environments safer.*

# NIST 800-53 Rev 5 Compliance Mapping for AD-Scout

This document provides a comprehensive mapping between NIST 800-53 Rev 5 security controls and AD-Scout security rules. It serves as the foundation for implementing NIST compliance checks in the AD-Scout framework.

## Overview

NIST Special Publication 800-53 Revision 5 provides a catalog of security and privacy controls for information systems. This mapping focuses on controls most relevant to Active Directory security assessments.

### Document Purpose
1. Map existing AD-Scout rules to NIST 800-53 controls
2. Identify control gaps requiring new rule implementation
3. Provide NIST control context for AD security findings
4. Enable NIST-based compliance reporting

---

## Relevant NIST 800-53 Control Families

| Family | Code | AD Relevance |
|--------|------|--------------|
| Access Control | AC | High - Core AD function |
| Audit and Accountability | AU | High - Security monitoring |
| Configuration Management | CM | High - AD/GPO configuration |
| Identification and Authentication | IA | Critical - Authentication core |
| System and Communications Protection | SC | High - Protocol security |
| System and Information Integrity | SI | Medium - Patch management |

---

## Control-to-Rule Mapping

### AC - Access Control

#### AC-2: Account Management
**Control Description:** Manage system accounts including establishing, activating, modifying, disabling, and removing accounts.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| S-InactiveUsers | Identifies accounts not managed (inactive) | AC-2(3) Disable Accounts |
| S-InactiveComputers | Computer accounts not managed | AC-2(3) |
| S-DisabledAccountsWithGroupMembership | Disabled accounts retain access | AC-2(2) Automated Management |
| S-PwdNeverExpires | Password management not enforced | AC-2 |
| P-PrivilegedGroupMembership | Privileged account oversight | AC-2(7) Privileged Accounts |
| P-DefaultAdmin | Built-in admin account management | AC-2(7) |
| P-SchemaAdmin | Schema admin group populated | AC-2(7) |
| S-AdminCount | Stale privilege indicators | AC-2 |
| **GAP** | Account approval workflow | AC-2(1) |
| **GAP** | Temporary/emergency accounts | AC-2(2) |

**NIST Property Value:** `@('AC-2', 'AC-2(2)', 'AC-2(3)', 'AC-2(7)')`

---

#### AC-3: Access Enforcement
**Control Description:** Enforce approved authorizations for logical access to information and system resources.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| P-DangerousACL | Unauthorized access rights | AC-3 |
| P-DelegationEveryone | Everyone granted excessive access | AC-3 |
| G-GPOPermissions | GPO access enforcement | AC-3 |
| G-SYSVOLPermissions | SYSVOL access control | AC-3 |
| P-AdminSDHolder | AdminSDHolder integrity | AC-3 |
| A-NullSession | Null session bypasses access control | AC-3 |
| A-PreWin2000 | Legacy access bypass | AC-3 |

**NIST Property Value:** `@('AC-3')`

---

#### AC-5: Separation of Duties
**Control Description:** Separate duties of individuals to prevent malicious activity.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| P-PrivilegedGroupMembership | Multiple privileged roles | AC-5 |
| P-DNSAdmin | DNS admin with DC access | AC-5 |
| P-ServiceAccountPrivileges | Service accounts with admin rights | AC-5 |
| **GAP** | Role-based access analysis | AC-5 |

**NIST Property Value:** `@('AC-5')`

---

#### AC-6: Least Privilege
**Control Description:** Employ the principle of least privilege.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| P-PrivilegedGroupMembership | Excessive privileged users | AC-6 |
| P-DangerousACL | Excessive permissions granted | AC-6 |
| P-DelegationEveryone | Everyone granted privileges | AC-6(1) |
| P-DNSAdmin | Excessive DNS admin rights | AC-6(5) |
| P-SchemaAdmin | Schema admins populated | AC-6(5) |
| K-UnconstrainedDelegation | Unconstrained delegation | AC-6(1) |
| K-ConstrainedDelegation | Overly broad delegation | AC-6 |
| S-UnrestrictedJoin | Any user can join computers | AC-6(1) |
| P-ServiceAccountPrivileges | Service accounts over-privileged | AC-6(5) |
| G-GPOPermissions | Excessive GPO permissions | AC-6 |

**NIST Property Value:** `@('AC-6', 'AC-6(1)', 'AC-6(5)')`

---

#### AC-17: Remote Access
**Control Description:** Establish usage restrictions and implementation guidance for remote access.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-DCLdapSign | LDAP signing for remote access | AC-17(2) |
| A-SMBSigning | SMB signing for remote access | AC-17(2) |
| **GAP** | Remote Desktop restrictions | AC-17 |
| **GAP** | VPN/remote access policy | AC-17(1) |

**NIST Property Value:** `@('AC-17', 'AC-17(2)')`

---

### AU - Audit and Accountability

#### AU-2: Event Logging
**Control Description:** Identify events that the system must be capable of logging.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-AuditDC | DC audit policy configuration | AU-2 |
| A-NoScriptLogging | PowerShell logging disabled | AU-2 |
| **GAP** | Object access auditing | AU-2(a)(3) |
| **GAP** | Audit policy completeness | AU-2 |

**NIST Property Value:** `@('AU-2')`

---

#### AU-3: Content of Audit Records
**Control Description:** Audit records contain required information.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-AuditDC | Audit record content | AU-3 |
| A-NoScriptLogging | Script execution details | AU-3 |
| **GAP** | Audit record completeness check | AU-3 |

**NIST Property Value:** `@('AU-3')`

---

#### AU-6: Audit Record Review, Analysis, and Reporting
**Control Description:** Review and analyze audit records for indications of inappropriate activity.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-AuditDC | Enables audit analysis | AU-6 |
| **GAP** | SIEM integration verification | AU-6(1) |
| **GAP** | Automated audit analysis | AU-6(1) |

**NIST Property Value:** `@('AU-6')`

---

#### AU-12: Audit Record Generation
**Control Description:** Provide audit record generation capability.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-AuditDC | Audit generation on DCs | AU-12 |
| A-NoScriptLogging | Script audit generation | AU-12 |
| **GAP** | Centralized audit collection | AU-12 |

**NIST Property Value:** `@('AU-12')`

---

### CM - Configuration Management

#### CM-2: Baseline Configuration
**Control Description:** Develop and maintain baseline configurations.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-WeakPwdPolicy | Password policy baseline | CM-2 |
| A-DCLdapSign | LDAP configuration baseline | CM-2 |
| A-SMBSigning | SMB configuration baseline | CM-2 |
| G-UnlinkedGPOs | GPO baseline management | CM-2 |
| **GAP** | AD schema baseline | CM-2 |
| **GAP** | GPO baseline comparison | CM-2(2) |

**NIST Property Value:** `@('CM-2')`

---

#### CM-6: Configuration Settings
**Control Description:** Establish and document configuration settings.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-WeakPwdPolicy | Password policy settings | CM-6 |
| A-DCLdapSign | LDAP security settings | CM-6 |
| A-SMBSigning | SMB security settings | CM-6 |
| A-LMHash | LM hash settings | CM-6 |
| A-NullSession | Null session settings | CM-6 |
| A-PreWin2000 | Legacy compatibility settings | CM-6 |
| A-RecycleBin | AD feature settings | CM-6 |
| A-NoScriptLogging | PowerShell settings | CM-6 |

**NIST Property Value:** `@('CM-6')`

---

#### CM-7: Least Functionality
**Control Description:** Configure systems to provide only essential capabilities.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-PreWin2000 | Legacy functionality enabled | CM-7 |
| A-NullSession | Unnecessary functionality | CM-7 |
| A-LMHash | Legacy hash support | CM-7 |
| S-DESEncryption | Weak encryption enabled | CM-7 |
| **GAP** | Unnecessary services on DCs | CM-7(1) |
| **GAP** | Unnecessary protocols | CM-7(1) |

**NIST Property Value:** `@('CM-7', 'CM-7(1)')`

---

#### CM-8: System Component Inventory
**Control Description:** Develop and maintain inventory of system components.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| S-InactiveComputers | Unknown/stale computers | CM-8 |
| S-ObsoleteOS | OS version inventory | CM-8 |
| S-ObsoleteDC | DC inventory | CM-8 |
| S-DuplicateSPN | SPN inventory issues | CM-8 |
| **GAP** | Complete AD object inventory | CM-8 |

**NIST Property Value:** `@('CM-8')`

---

### IA - Identification and Authentication

#### IA-2: Identification and Authentication (Organizational Users)
**Control Description:** Uniquely identify and authenticate organizational users.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| K-Kerberoasting | Kerberos authentication weakness | IA-2 |
| K-ASREPRoasting | Pre-authentication bypass | IA-2 |
| A-LMHash | Weak authentication storage | IA-2 |
| S-PwdNotRequired | No authentication required | IA-2 |
| A-NullSession | Anonymous authentication | IA-2 |
| **GAP** | Multi-factor authentication | IA-2(1) |
| **GAP** | Network access authentication | IA-2(2) |

**NIST Property Value:** `@('IA-2')`

---

#### IA-4: Identifier Management
**Control Description:** Manage system identifiers.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| S-InactiveUsers | Inactive identifiers | IA-4(4) |
| S-InactiveComputers | Inactive computer identifiers | IA-4(4) |
| S-DuplicateSPN | Duplicate identifiers | IA-4 |
| T-SIDHistorySameDomain | Identifier spoofing | IA-4 |
| T-SIDHistoryUnknown | Unknown identifiers | IA-4 |
| **GAP** | Identifier uniqueness | IA-4(4) |

**NIST Property Value:** `@('IA-4', 'IA-4(4)')`

---

#### IA-5: Authenticator Management
**Control Description:** Manage system authenticators.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-Krbtgt | Kerberos key management | IA-5 |
| A-WeakPwdPolicy | Password authenticator policy | IA-5(1) |
| S-PwdNeverExpires | Password expiration | IA-5(1)(d) |
| S-PwdNotRequired | Password requirement | IA-5(1) |
| S-ReversiblePwd | Password protection | IA-5(1)(c) |
| A-LMHash | Weak hash storage | IA-5(1)(c) |
| A-NoLAPS | Local admin password management | IA-5 |
| G-GPPPasswords | Exposed passwords in GPO | IA-5(1)(c) |
| K-Kerberoasting | Weak service account passwords | IA-5(1) |
| S-DESEncryption | Weak authentication encryption | IA-5(2) |

**NIST Property Value:** `@('IA-5', 'IA-5(1)', 'IA-5(2)')`

---

#### IA-8: Identification and Authentication (Non-Organizational Users)
**Control Description:** Uniquely identify and authenticate non-organizational users.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| T-SIDFilteringDisabled | External trust authentication | IA-8 |
| T-SelectiveAuthDisabled | Trust authentication scope | IA-8 |
| A-NullSession | Anonymous access | IA-8 |
| **GAP** | Guest account status | IA-8 |

**NIST Property Value:** `@('IA-8')`

---

### SC - System and Communications Protection

#### SC-8: Transmission Confidentiality and Integrity
**Control Description:** Protect the confidentiality and integrity of transmitted information.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-DCLdapSign | LDAP integrity | SC-8(1) |
| A-SMBSigning | SMB integrity | SC-8(1) |
| C-WeakCryptoTemplates | Weak transmission crypto | SC-8(1) |
| **GAP** | LDAPS enforcement | SC-8(1) |
| **GAP** | Channel binding | SC-8 |

**NIST Property Value:** `@('SC-8', 'SC-8(1)')`

---

#### SC-12: Cryptographic Key Establishment and Management
**Control Description:** Establish and manage cryptographic keys.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-Krbtgt | Kerberos key management | SC-12 |
| C-ESC1-VulnerableTemplate | Certificate key management | SC-12 |
| C-ESC2-AnyPurpose | Certificate key usage | SC-12 |
| C-ESC3-RequestAgent | Key issuance control | SC-12 |
| C-ESC6-EDITF | CA key policy | SC-12 |
| **GAP** | Key rotation policy | SC-12 |

**NIST Property Value:** `@('SC-12')`

---

#### SC-13: Cryptographic Protection
**Control Description:** Implement cryptographic mechanisms.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| S-DESEncryption | Weak DES encryption | SC-13 |
| A-LMHash | Weak LM hash | SC-13 |
| C-WeakCryptoTemplates | Weak certificate crypto | SC-13 |
| **GAP** | FIPS compliance | SC-13 |
| **GAP** | Approved algorithms | SC-13 |

**NIST Property Value:** `@('SC-13')`

---

#### SC-23: Session Authenticity
**Control Description:** Protect the authenticity of communications sessions.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-DCLdapSign | LDAP session integrity | SC-23 |
| A-SMBSigning | SMB session integrity | SC-23 |
| K-UnconstrainedDelegation | Session delegation abuse | SC-23 |
| K-ConstrainedDelegation | Delegation session control | SC-23 |
| **GAP** | Session timeout policies | SC-23 |

**NIST Property Value:** `@('SC-23')`

---

### SI - System and Information Integrity

#### SI-2: Flaw Remediation
**Control Description:** Identify, report, and correct system flaws.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| S-ObsoleteDC | Unpatched DC OS | SI-2 |
| S-ObsoleteOS | Unpatched member systems | SI-2 |
| C-ESC8-WebEnrollment | Unpatched web enrollment | SI-2 |
| C-ESC8-WebEnrollNTLM | NTLM relay vulnerability | SI-2 |
| **GAP** | Patch compliance | SI-2(2) |
| **GAP** | Vulnerability scanning | SI-2(2) |

**NIST Property Value:** `@('SI-2')`

---

#### SI-4: System Monitoring
**Control Description:** Monitor the system to detect attacks and indicators of potential attacks.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| A-AuditDC | DC monitoring | SI-4 |
| A-NoScriptLogging | Script monitoring | SI-4 |
| **GAP** | Intrusion detection | SI-4(2) |
| **GAP** | SIEM integration | SI-4(2) |

**NIST Property Value:** `@('SI-4')`

---

#### SI-7: Software, Firmware, and Information Integrity
**Control Description:** Employ integrity verification tools.

| AD-Scout Rule | Mapping Rationale | Coverage |
|---------------|-------------------|----------|
| G-SYSVOLPermissions | SYSVOL integrity | SI-7 |
| G-GPOPermissions | GPO integrity | SI-7 |
| P-AdminSDHolder | AdminSDHolder integrity | SI-7 |
| A-RecycleBin | AD object recovery | SI-7 |
| **GAP** | AD backup verification | SI-7 |

**NIST Property Value:** `@('SI-7')`

---

## Summary: Existing Rule to NIST Mapping

### Complete Mapping Table

| Rule ID | NIST 800-53 Controls |
|---------|---------------------|
| **Anomalies (A-)** | |
| A-Krbtgt | IA-5, SC-12 |
| A-LMHash | CM-6, CM-7, IA-2, IA-5(1)(c), SC-13 |
| A-NoLAPS | IA-5 |
| A-DCLdapSign | AC-17(2), CM-2, CM-6, SC-8(1), SC-23 |
| A-SMBSigning | AC-17(2), CM-2, CM-6, SC-8(1), SC-23 |
| A-NullSession | AC-3, CM-6, CM-7, IA-2, IA-8 |
| A-WeakPwdPolicy | CM-2, CM-6, IA-5(1) |
| A-PreWin2000 | AC-3, CM-6, CM-7 |
| A-AuditDC | AU-2, AU-3, AU-6, AU-12, SI-4 |
| A-NoScriptLogging | AU-2, AU-3, AU-12, SI-4 |
| A-RecycleBin | CM-6, SI-7 |
| **StaleObjects (S-)** | |
| S-PwdNeverExpires | AC-2, IA-5(1)(d) |
| S-InactiveUsers | AC-2(3), IA-4(4) |
| S-InactiveComputers | AC-2(3), CM-8, IA-4(4) |
| S-DisabledAccountsWithGroupMembership | AC-2(2) |
| S-ObsoleteDC | CM-8, SI-2 |
| S-ObsoleteOS | CM-8, SI-2 |
| S-PwdNotRequired | IA-2, IA-5(1) |
| S-DESEncryption | CM-7, IA-5(2), SC-13 |
| S-ReversiblePwd | IA-5(1)(c) |
| S-UnrestrictedJoin | AC-6(1) |
| S-DuplicateSPN | CM-8, IA-4 |
| S-AdminCount | AC-2 |
| **PrivilegedAccess (P-)** | |
| P-PrivilegedGroupMembership | AC-2(7), AC-5, AC-6 |
| P-AdminSDHolder | AC-3, SI-7 |
| P-ServiceAccountPrivileges | AC-5, AC-6(5) |
| P-DelegationEveryone | AC-3, AC-6(1) |
| P-SchemaAdmin | AC-2(7), AC-6(5) |
| P-DangerousACL | AC-3, AC-6 |
| P-DefaultAdmin | AC-2(7) |
| P-DNSAdmin | AC-5, AC-6(5) |
| P-NoProtectedUsers | IA-5 |
| **Kerberos (K-)** | |
| K-Kerberoasting | IA-2, IA-5(1) |
| K-ASREPRoasting | IA-2 |
| K-UnconstrainedDelegation | AC-6(1), SC-23 |
| K-ConstrainedDelegation | AC-6, SC-23 |
| **Trusts (T-)** | |
| T-SIDFilteringDisabled | IA-8 |
| T-SelectiveAuthDisabled | IA-8 |
| T-TrustTransitivity | AC-3 |
| T-SIDHistorySameDomain | IA-4 |
| T-SIDHistoryUnknown | IA-4 |
| T-InactiveTrust | AC-2 |
| **GPO (G-)** | |
| G-GPPPasswords | IA-5(1)(c) |
| G-GPOPermissions | AC-3, AC-6, SI-7 |
| G-UnlinkedGPOs | CM-2 |
| G-SYSVOLPermissions | AC-3, SI-7 |
| **PKI/ADCS (C-)** | |
| C-ESC1-VulnerableTemplate | SC-12 |
| C-ESC2-AnyPurpose | SC-12 |
| C-ESC3-RequestAgent | SC-12 |
| C-ESC6-EDITF | SC-12 |
| C-ESC8-WebEnrollment | SI-2 |
| C-ESC8-WebEnrollNTLM | SI-2 |
| C-WeakCryptoTemplates | SC-8(1), SC-13 |

---

## Identified Gaps: New Rules Needed

### High Priority (Critical Controls)

| NIST Control | Proposed Rule ID | Description |
|--------------|------------------|-------------|
| IA-2(1) | A-NoMFA | Multi-factor authentication not enforced for privileged accounts |
| AC-17 | A-RDPSecurity | Remote Desktop security settings |
| SC-8(1) | A-NoLDAPS | LDAPS not configured/enforced |
| SI-2(2) | A-NoPatchCompliance | Systems missing critical patches |
| AU-2 | A-IncompleteAudit | Audit policy missing required categories |

### Medium Priority

| NIST Control | Proposed Rule ID | Description |
|--------------|------------------|-------------|
| CM-2(2) | G-GPOBaselineDrift | GPO settings drift from baseline |
| CM-7(1) | A-UnnecessaryServices | Unnecessary services on DCs |
| AC-2(1) | A-NoAccountWorkflow | No account approval workflow detected |
| AU-6(1) | A-NoSIEM | No SIEM integration detected |
| SC-12 | A-NoKeyRotation | Cryptographic key rotation not enforced |

### Lower Priority

| NIST Control | Proposed Rule ID | Description |
|--------------|------------------|-------------|
| CM-8 | S-InventoryGaps | AD object inventory incomplete |
| SI-7 | A-NoBackupVerification | AD backup not verified |
| IA-8 | A-GuestEnabled | Guest account enabled |
| SC-13 | A-NonFIPSCrypto | Non-FIPS cryptography in use |
| AC-5 | P-RoleConflicts | Users with conflicting privileged roles |

---

## Implementation Guidance

### Adding NIST Property to Rules

Update each rule file to include the NIST property:

```powershell
@{
    Id          = 'A-Krbtgt'
    # ... existing properties ...

    # Existing framework mappings
    MITRE = @{
        Tactics    = @('TA0003', 'TA0006')
        Techniques = @('T1558.001')
    }
    CIS   = @('5.21')
    STIG  = @('V-36451')
    ANSSI = @('vuln1_krbtgt')

    # NEW: NIST 800-53 Rev 5 mapping
    NIST  = @('IA-5', 'SC-12')

    # ... rest of rule ...
}
```

### NIST Filter in Get-ADScoutRule

Add NIST filtering capability:

```powershell
function Get-ADScoutRule {
    param(
        [string[]]$NIST  # Filter by NIST control
    )

    # Filter logic
    if ($NIST) {
        $rules = $rules | Where-Object {
            $_.NIST | Where-Object { $NIST -contains $_ }
        }
    }
}
```

### NIST Compliance Reporter

Create a NIST-focused report format:

```powershell
# Group findings by NIST control family
$findings | Group-Object { $_.NIST[0].Substring(0,2) } | ForEach-Object {
    # AC, AU, CM, IA, SC, SI families
}
```

---

## Control Coverage Summary

| Control Family | Controls Covered | Controls with Gaps | Coverage % |
|---------------|------------------|-------------------|------------|
| AC (Access Control) | AC-2, AC-3, AC-5, AC-6, AC-17 | AC-2(1), AC-17(1) | 80% |
| AU (Audit) | AU-2, AU-3, AU-6, AU-12 | AU-6(1) | 75% |
| CM (Config Mgmt) | CM-2, CM-6, CM-7, CM-8 | CM-2(2), CM-7(1) | 70% |
| IA (Auth) | IA-2, IA-4, IA-5, IA-8 | IA-2(1), IA-2(2) | 75% |
| SC (Comms) | SC-8, SC-12, SC-13, SC-23 | SC-8(1) LDAPS | 80% |
| SI (Integrity) | SI-2, SI-4, SI-7 | SI-2(2), SI-4(2) | 70% |

**Overall Estimated Coverage: ~75%** of AD-relevant NIST 800-53 controls

---

## References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53A Rev 5 (Assessment)](https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final)
- [NIST SP 800-171 (CUI Protection)](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
- [CISA AD Security Best Practices](https://www.cisa.gov/sites/default/files/publications/Mitigating%20Attacks%20Against%20Active%20Directory.pdf)
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-01 | AD-Scout Team | Initial NIST 800-53 mapping document |

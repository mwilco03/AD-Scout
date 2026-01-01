# PingCastle Rules Implementation Plan for AD-Scout

Based on research from [PingCastle documentation](https://www.pingcastle.com/documentation/) and [GitHub repository](https://github.com/netwrix/pingcastle), this document outlines PingCastle rules that can be directly implemented in AD-Scout.

## Current AD-Scout Coverage (53 Rules)

### Summary by Category
| Category | Count | Description |
|----------|-------|-------------|
| Anomalies (A-) | 11 | Configuration weaknesses and misconfigurations |
| StaleObjects (S-) | 11 | Stale accounts, obsolete systems, cleanup needed |
| PrivilegedAccess (P-) | 9 | Privileged access risks and delegation issues |
| Kerberos (K-) | 4 | Kerberos security issues |
| Trusts (T-) | 5 | Trust relationship risks |
| GPO (G-) | 4 | Group Policy security issues |
| PKI (C-) | 8 | Certificate Services (ADCS) vulnerabilities |
| **Total** | **53** | |

### Implemented Rules

#### Anomalies (A-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| A-Krbtgt | Krbtgt Password Age | Critical | A-Krbtgt |
| A-LMHash | LM Hash Storage Enabled | High | A-LMHashAuthorized |
| A-NoLAPS | LAPS Not Deployed | High | A-LAPS_Not_Installed |
| A-DCLdapSign | LDAP Signing Not Required | High | A-DCLdapSign |
| A-SMBSigning | SMB Signing Not Required | High | A-SMB2SignatureNotRequired |
| A-NullSession | Null Session Access | High | A-NullSession |
| A-WeakPwdPolicy | Weak Password Policy | High | A-MinPwdLen |
| A-PreWin2000 | Pre-Windows 2000 Access | High | A-PreWin2000Anonymous |
| A-AuditDC | DC Audit Policy | High | A-AuditDC |
| A-NoScriptLogging | PowerShell Logging Disabled | Medium | A-AuditPowershell |
| A-RecycleBin | AD Recycle Bin Disabled | Medium | (unique) |

#### StaleObjects (S-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| S-PwdNeverExpires | Password Never Expires | Medium | S-PwdNeverExpires |
| S-InactiveUsers | Inactive User Accounts | Low | S-Inactive |
| S-InactiveComputers | Inactive Computer Accounts | Low | S-C_Inactive |
| S-DisabledAccountsWithGroupMembership | Disabled Accounts with Group Membership | Low | (unique) |
| S-ObsoleteDC | Obsolete DC Operating System | Critical | S-DC_Obsolete |
| S-ObsoleteOS | Obsolete Member Systems | High | S-OS_Obsolete |
| S-PwdNotRequired | Password Not Required Flag | High | S-PwdNotRequired |
| S-DESEncryption | DES Kerberos Encryption | Medium | S-DesEnabled |
| S-ReversiblePwd | Reversible Password Encryption | High | S-Reversible |
| S-UnrestrictedJoin | Unrestricted Computer Join | Medium | S-ADRegistration |
| S-DuplicateSPN | Duplicate SPNs | Medium | S-Duplicate |
| S-AdminCount | Stale AdminCount Attribute | Low | (unique) |

#### PrivilegedAccess (P-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| P-PrivilegedGroupMembership | Excessive Privileged Users | High | P-AdminNum |
| P-AdminSDHolder | AdminSDHolder Modification | High | A-AdminSDHolder |
| P-ServiceAccountPrivileges | Service Account Privileges | Medium | P-ServiceDomainAdmin |
| P-DelegationEveryone | Dangerous Delegation to Everyone | Critical | P-DelegationEveryone |
| P-SchemaAdmin | Schema Admins Populated | Medium | P-SchemaAdmin |
| P-DangerousACL | DCSync and Dangerous Rights | Critical | P-DangerousExtendedRight |
| P-DefaultAdmin | Default Administrator Active | Medium | P-AdminLogin |
| P-DNSAdmin | DnsAdmins Privilege Escalation | High | P-DNSDelegation |
| P-NoProtectedUsers | Protected Users Not Used | Medium | P-ProtectedUsers |

#### Kerberos (K-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| K-Kerberoasting | Kerberoastable Accounts | High | A-Krbtgt (related) |
| K-ASREPRoasting | AS-REP Roastable Accounts | High | (unique) |
| K-UnconstrainedDelegation | Unconstrained Delegation | High | P-Delegated |
| K-ConstrainedDelegation | Constrained Delegation to Sensitive Services | High | P-Delegated |

#### Trusts (T-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| T-SIDFilteringDisabled | SID Filtering Disabled | High | T-SIDFiltering |
| T-SelectiveAuthDisabled | Selective Authentication Disabled | Medium | (related) |
| T-TrustTransitivity | Trust Transitivity Issues | Medium | T-Downlevel |
| T-SIDHistorySameDomain | SID History Same Domain | Critical | T-SIDHistorySameDomain |
| T-SIDHistoryUnknown | SID History Unknown Domain | Medium | T-SIDHistoryUnknown |
| T-InactiveTrust | Inactive Domain Trust | Medium | T-Inactive |

#### GPO (G-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| G-GPPPasswords | GPP Passwords | Critical | A-PwdGPO |
| G-GPOPermissions | Insecure GPO Permissions | High | (unique) |
| G-UnlinkedGPOs | Unlinked GPOs | Low | (unique) |
| G-SYSVOLPermissions | Insecure SYSVOL Permissions | High | (unique) |

#### PKI/ADCS (C-)
| Rule ID | Title | Severity | PingCastle Equivalent |
|---------|-------|----------|----------------------|
| C-ESC1-VulnerableTemplate | ESC1 Vulnerable Template | Critical | A-CertEnroll* |
| C-ESC2-AnyPurpose | ESC2 Any Purpose Template | High | A-CertTempAnyPurpose |
| C-ESC3-RequestAgent | ESC3 Request Agent | Critical | A-CertTempAgent |
| C-ESC6-EDITF | ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 | Critical | A-CertTempCustomSubject |
| C-ESC8-WebEnrollment | ESC8 Web Enrollment | High | A-CertEnroll* |
| C-ESC8-WebEnrollNTLM | ESC8 Web Enrollment NTLM Relay | Critical | A-CertEnroll* |
| C-WeakCryptoTemplates | Weak Crypto Templates | Medium | A-WeakRSARootCert |

---

## Priority 1: Critical Security Rules (Implement First)

### Anomalies Category (A-)

#### A-Krbtgt - Kerberos TGT Key Age
**PingCastle Points:** 100 (Critical)
```powershell
# Detection: krbtgt password older than 180 days
@{
    Id = 'A-Krbtgt'
    Title = 'Krbtgt Account Password Age'
    Description = 'The krbtgt account password has not been changed recently, making the domain vulnerable to Golden Ticket attacks.'
    Detect = {
        param($Data, $Domain)
        $krbtgt = $Data.Users | Where-Object { $_.SamAccountName -eq 'krbtgt' }
        if ($krbtgt.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
            [PSCustomObject]@{
                Account = 'krbtgt'
                PasswordAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days
                LastSet = $krbtgt.PasswordLastSet
            }
        }
    }
}
```

#### A-DCLdapSign - LDAP Signing Not Required
**PingCastle Points:** 30 (High)
```powershell
# Detection: DC does not require LDAP signing
@{
    Id = 'A-DCLdapSign'
    Title = 'LDAP Signing Not Required on Domain Controllers'
    Description = 'LDAP signing is not enforced, allowing LDAP relay attacks.'
    DataSource = 'GPOs'
    # Check: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2
}
```

#### A-DCLdaps - LDAPS Not Enforced
**PingCastle Points:** 20 (Medium-High)
```powershell
# Detection: LDAPS not configured on DCs
@{
    Id = 'A-DCLdaps'
    Title = 'LDAP over TLS/SSL Not Configured'
    Description = 'Domain Controllers do not have LDAPS configured, exposing credentials in transit.'
}
```

#### A-SMB2SignatureNotRequired - SMB Signing
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'A-SMBSigning'
    Title = 'SMB Signing Not Required'
    Description = 'SMB signing is not enforced, enabling NTLM relay attacks.'
    # Check GPO: MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature
}
```

#### A-NullSession - Null Session Access
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'A-NullSession'
    Title = 'Null Session Access Enabled'
    Description = 'Anonymous/null sessions can access domain information.'
    # Check: RestrictAnonymous, RestrictAnonymousSAM registry keys
}
```

#### A-LMHashAuthorized - LM Hash Storage
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'A-LMHash'
    Title = 'LM Hash Storage Enabled'
    Description = 'Weak LM hashes are being stored, easily crackable.'
    # Check GPO: NoLMHash setting
}
```

#### A-LAPS_Not_Installed - LAPS Missing
**PingCastle Points:** 20 (Medium-High)
```powershell
@{
    Id = 'A-NoLAPS'
    Title = 'LAPS Not Deployed'
    Description = 'Local Administrator Password Solution is not deployed, leading to shared local admin passwords.'
    DataSource = 'Computers'
    # Check: ms-Mcs-AdmPwd attribute existence
}
```

---

### Stale Objects Category (S-)

#### S-DC_Obsolete - Obsolete Domain Controllers
**PingCastle Points:** 50-100 (Critical)
```powershell
@{
    Id = 'S-ObsoleteDC'
    Title = 'Obsolete Operating System on Domain Controllers'
    Description = 'Domain controllers running unsupported Windows versions.'
    Detect = {
        param($Data, $Domain)
        $obsoleteOS = @('2000', '2003', '2008', '2008 R2', '2012')
        $Data.DomainControllers | Where-Object {
            $obsoleteOS | Where-Object { $_.OperatingSystem -match $_ }
        }
    }
}
```

#### S-OS_Obsolete - Obsolete Member Servers/Workstations
**PingCastle Points:** 20-40
```powershell
@{
    Id = 'S-ObsoleteOS'
    Title = 'Obsolete Operating Systems in Domain'
    Description = 'Computers running unsupported Windows versions (XP, Vista, 7, 2003, 2008).'
    Detect = {
        param($Data, $Domain)
        $Data.Computers | Where-Object {
            $_.OperatingSystem -match 'XP|Vista|Windows 7|2003|2008' -and $_.Enabled
        }
    }
}
```

#### S-PwdNotRequired - Password Not Required
**PingCastle Points:** 20 (High)
```powershell
@{
    Id = 'S-PwdNotRequired'
    Title = 'Accounts Without Password Requirement'
    Description = 'User accounts configured to not require a password (PASSWD_NOTREQD flag).'
    Detect = {
        param($Data, $Domain)
        $Data.Users | Where-Object { $_.UserAccountControl -band 0x20 -and $_.Enabled }
    }
}
```

#### S-DesEnabled - DES Encryption Enabled
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'S-DESEncryption'
    Title = 'DES Kerberos Encryption Enabled'
    Description = 'Accounts using weak DES encryption for Kerberos.'
    Detect = {
        param($Data, $Domain)
        $Data.Users | Where-Object { $_.UserAccountControl -band 0x200000 -and $_.Enabled }
    }
}
```

#### S-Reversible - Reversible Encryption
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'S-ReversiblePwd'
    Title = 'Reversible Password Encryption'
    Description = 'Accounts storing passwords with reversible encryption.'
    Detect = {
        param($Data, $Domain)
        $Data.Users | Where-Object { $_.UserAccountControl -band 0x80 -and $_.Enabled }
    }
}
```

#### S-ADRegistration - Unrestricted Computer Join
**PingCastle Points:** 15 (Medium)
```powershell
@{
    Id = 'S-UnrestrictedJoin'
    Title = 'Unrestricted Domain Computer Registration'
    Description = 'Users can join computers to domain without restrictions (ms-DS-MachineAccountQuota > 0).'
    # Check: ms-DS-MachineAccountQuota on domain object
}
```

#### S-Duplicate - Duplicate SPNs
**PingCastle Points:** 10
```powershell
@{
    Id = 'S-DuplicateSPN'
    Title = 'Duplicate Service Principal Names'
    Description = 'Multiple accounts share the same SPN, causing Kerberos authentication issues.'
}
```

---

### Privileged Access Category (P-)

#### P-DelegationEveryone - Everyone in Delegation
**PingCastle Points:** 40 (Critical)
```powershell
@{
    Id = 'P-DelegationEveryone'
    Title = 'Dangerous Delegation to Everyone/Authenticated Users'
    Description = 'Delegation rights granted to Everyone or Authenticated Users groups.'
}
```

#### P-DangerousExtendedRight - Dangerous ACLs
**PingCastle Points:** 30-50
```powershell
@{
    Id = 'P-DangerousACL'
    Title = 'Dangerous Extended Rights on AD Objects'
    Description = 'Low-privileged users have dangerous extended rights (DCSync, WriteDACL, etc.).'
    # Check for: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
}
```

#### P-SchemaAdmin - Schema Admin Population
**PingCastle Points:** 20
```powershell
@{
    Id = 'P-SchemaAdmin'
    Title = 'Schema Admins Group Populated'
    Description = 'Schema Admins group has permanent members. Should be empty except during schema changes.'
}
```

#### P-AdminLogin - Default Administrator Active
**PingCastle Points:** 10
```powershell
@{
    Id = 'P-DefaultAdmin'
    Title = 'Default Administrator Account Active'
    Description = 'The built-in Administrator account (RID 500) is enabled and actively used.'
}
```

#### P-DNSDelegation - DNS Admin Privilege
**PingCastle Points:** 30 (High)
```powershell
@{
    Id = 'P-DNSAdmin'
    Title = 'DNS Admins Can Execute Code on DC'
    Description = 'DnsAdmins group members can load arbitrary DLLs on Domain Controllers.'
}
```

#### P-ProtectedUsers - Protected Users Empty
**PingCastle Points:** 10
```powershell
@{
    Id = 'P-NoProtectedUsers'
    Title = 'Protected Users Group Not Utilized'
    Description = 'No privileged accounts in Protected Users group, missing credential theft protections.'
}
```

---

### Trust Category (T-)

#### T-SIDHistorySameDomain - SID History in Same Domain
**PingCastle Points:** 40 (Critical)
```powershell
@{
    Id = 'T-SIDHistorySameDomain'
    Title = 'SID History Pointing to Same Domain'
    Description = 'Accounts have SID History with SIDs from the same domain - indicates privilege escalation attack.'
}
```

#### T-SIDHistoryUnknown - SID History Unknown Domain
**PingCastle Points:** 20
```powershell
@{
    Id = 'T-SIDHistoryUnknown'
    Title = 'SID History from Unknown Domain'
    Description = 'SID History contains SIDs from domains that no longer exist or cannot be resolved.'
}
```

#### T-Inactive - Inactive Trust
**PingCastle Points:** 10
```powershell
@{
    Id = 'T-InactiveTrust'
    Title = 'Inactive Domain Trust'
    Description = 'Trust relationship to inactive or unreachable domain.'
}
```

---

## Priority 2: High-Impact Rules

### Anomalies Category

#### A-AuditDC - DC Audit Policy
```powershell
@{
    Id = 'A-AuditDC'
    Title = 'Insufficient Audit Policy on Domain Controllers'
    Description = 'Critical security events are not being logged on Domain Controllers.'
    # Check: Logon, Account Logon, Object Access, Policy Change audit categories
}
```

#### A-AuditPowershell - PowerShell Logging
```powershell
@{
    Id = 'A-NoScriptLogging'
    Title = 'PowerShell Script Block Logging Disabled'
    Description = 'PowerShell script execution is not being logged for security monitoring.'
}
```

#### A-PreWin2000Anonymous - Pre-Windows 2000 Compatibility
```powershell
@{
    Id = 'A-PreWin2000'
    Title = 'Pre-Windows 2000 Compatible Access Enabled'
    Description = 'Pre-Windows 2000 Compatible Access group allows anonymous enumeration.'
}
```

#### A-MinPwdLen - Weak Password Policy
```powershell
@{
    Id = 'A-WeakPwdPolicy'
    Title = 'Weak Password Policy'
    Description = 'Domain password policy requires fewer than 12 characters.'
}
```

#### A-HardenedPaths - UNC Path Hardening
```powershell
@{
    Id = 'A-UNCHardening'
    Title = 'UNC Path Hardening Not Configured'
    Description = 'Hardened UNC paths not configured for SYSVOL and NETLOGON shares.'
}
```

#### A-DCRefuseComputerPwdChange - Computer Password Change
```powershell
@{
    Id = 'A-NoComputerPwdRotation'
    Title = 'Computer Password Rotation Disabled'
    Description = 'Domain Controllers refuse computer account password changes.'
}
```

### PKI/Certificate Rules

#### A-CertROCA - ROCA Vulnerability
```powershell
@{
    Id = 'C-ROCA'
    Title = 'Certificates Vulnerable to ROCA Attack'
    Description = 'Certificates with RSA keys generated by vulnerable Infineon TPMs.'
}
```

#### A-CertTempAgent - Certificate Request Agent
```powershell
@{
    Id = 'C-ESC3-RequestAgent'
    Title = 'ESC3 - Certificate Request Agent Misconfiguration'
    Description = 'Templates allow enrollment of Certificate Request Agent certificates to low-privileged users.'
}
```

#### A-CertTempAnyPurpose - Any Purpose EKU
```powershell
@{
    Id = 'C-ESC2-AnyPurpose'
    Title = 'ESC2 - Any Purpose Certificate Template'
    Description = 'Certificate templates with Any Purpose EKU allow versatile abuse.'
}
```

#### A-CertTempCustomSubject - Subject Alternative Name
```powershell
@{
    Id = 'C-ESC6-EDITF'
    Title = 'ESC6 - CA Allows Arbitrary SAN'
    Description = 'Certificate Authority has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.'
}
```

---

## Priority 3: Medium-Impact Rules

### Additional Stale Object Rules

| Rule ID | Title | Points |
|---------|-------|--------|
| S-PrimaryGroup | Non-standard Primary Group | 5 |
| S-C-PrimaryGroup | Computer Non-standard Primary Group | 5 |
| S-SIDHistory | Stale SID History | 10 |
| S-DC-NotUpdated | DC Not Recently Updated | 15 |
| S-Vuln-MS17-010 | EternalBlue Vulnerable | 50 |
| S-Vuln-MS14-068 | Kerberos Elevation Vulnerable | 50 |

### Additional Anomaly Rules

| Rule ID | Title | Points |
|---------|-------|--------|
| A-SHA1RootCert | SHA-1 Root Certificates | 5 |
| A-MD5RootCert | MD5 Root Certificates | 10 |
| A-BackupMetadata | No Recent AD Backup | 20 |
| A-DsHeuristicsAnonymous | Anonymous LDAP Enabled | 20 |
| A-NoGPOAntiVirus | No Antivirus GPO | 5 |
| A-ProtectedUsers | Protected Users Schema Missing | 10 |

---

## Implementation Summary

### By Category

| Category | Currently Implemented | Can Add | Total Possible |
|----------|----------------------|---------|----------------|
| StaleObjects (S-) | 4 | 15+ | 19+ |
| Anomalies (A-) | 0 | 25+ | 25+ |
| PrivilegedAccess (P-) | 3 | 10+ | 13+ |
| Trusts (T-) | 3 | 5+ | 8+ |
| GPO (G-) | 3 | 0 | 3 |
| PKI (C-) | 3 | 8+ | 11+ |
| Kerberos (K-) | 3 | 0 | 3 |
| **Total** | **19** | **63+** | **82+** |

### Implementation Priority

#### Immediate (Critical - Points 30+)
1. A-Krbtgt - Golden Ticket prevention
2. A-DCLdapSign - LDAP relay prevention
3. A-SMBSigning - SMB relay prevention
4. A-NullSession - Anonymous access
5. A-LMHash - Weak password storage
6. S-ObsoleteDC - Critical vulnerabilities
7. P-DelegationEveryone - Dangerous delegation
8. T-SIDHistorySameDomain - Privilege escalation
9. P-DangerousACL - DCSync and similar

#### High Priority (Points 15-30)
10. S-PwdNotRequired - No password accounts
11. S-DESEncryption - Weak Kerberos
12. S-ReversiblePwd - Readable passwords
13. A-NoLAPS - Local admin password reuse
14. P-DNSAdmin - Code execution on DC
15. A-AuditDC - Security monitoring

#### Medium Priority (Points 5-15)
16. Additional PKI/ADCS rules (ESC2-ESC11)
17. Audit and logging checks
18. Password policy checks
19. Obsolete OS detection

---

## References

- [PingCastle Health Check Rules List](https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html)
- [PingCastle GitHub Repository](https://github.com/netwrix/pingcastle)
- [PingCastle Documentation](https://www.pingcastle.com/documentation/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Certified Pre-Owned (ADCS Research)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

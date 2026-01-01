# PingCastle Rules Implementation Plan for AD-Scout

Based on research from [PingCastle documentation](https://www.pingcastle.com/documentation/) and [GitHub repository](https://github.com/netwrix/pingcastle), this document outlines PingCastle rules that can be directly implemented in AD-Scout.

## Current AD-Scout Coverage (19 Rules)

| Rule ID | Category | Equivalent PingCastle |
|---------|----------|----------------------|
| S-PwdNeverExpires | StaleObjects | S-PwdNeverExpires |
| S-InactiveUsers | StaleObjects | S-Inactive |
| S-InactiveComputers | StaleObjects | S-C_Inactive |
| S-DisabledAccountsWithGroupMembership | StaleObjects | (unique) |
| K-Kerberoasting | Kerberos | A-Krbtgt (partial) |
| K-ASREPRoasting | Kerberos | S-DesEnabled (related) |
| K-UnconstrainedDelegation | Kerberos | P-Delegated |
| P-PrivilegedGroupMembership | PrivilegedAccess | P-AdminNum |
| P-AdminSDHolder | PrivilegedAccess | A-AdminSDHolder |
| P-ServiceAccountPrivileges | PrivilegedAccess | P-ServiceDomainAdmin |
| T-SIDFilteringDisabled | Trusts | T-SIDFiltering |
| T-SelectiveAuthDisabled | Trusts | (related) |
| T-TrustTransitivity | Trusts | T-Downlevel |
| G-GPPPasswords | GPO | A-PwdGPO |
| G-GPOPermissions | GPO | (unique) |
| G-UnlinkedGPOs | GPO | (unique) |
| C-ESC1-VulnerableTemplate | PKI | A-CertEnroll* |
| C-ESC8-WebEnrollment | PKI | A-CertEnroll* |
| C-WeakCryptoTemplates | PKI | A-WeakRSARootCert |

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

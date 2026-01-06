# AD-Scout Operational Security Guide

This document provides guidance for secure deployment of AD-Scout in customer environments,
including alert profiles, credential management, data handling, and pre-engagement requirements.

## Table of Contents

1. [Rule Alert Profiles](#rule-alert-profiles)
2. [Scan Profiles](#scan-profiles)
3. [Expected Security Alerts](#expected-security-alerts)
4. [Credential Lifecycle Management](#credential-lifecycle-management)
5. [Data Protection & Encryption](#data-protection--encryption)
6. [Audit Trail & Logging](#audit-trail--logging)
7. [Pre-Engagement Checklist](#pre-engagement-checklist)

---

## Rule Alert Profiles

AD-Scout rules are categorized by their operational footprint - the likelihood they will
trigger security monitoring alerts in customer environments.

### Profile Definitions

| Profile | Description | Typical Techniques | Expected Alerts |
|---------|-------------|-------------------|-----------------|
| **Stealth** | Read-only LDAP queries | DirectorySearcher, Get-AD* cmdlets | Minimal - standard admin activity |
| **Moderate** | Enhanced AD queries, local checks | ADSI property reads, GPO parsing | Low - may appear in AD audit logs |
| **Noisy** | Remote execution, privileged ops | Invoke-Command, WMI/CIM queries | High - PSRemoting, RPC, security events |

### Alert Profile Tags

Each rule includes an `AlertProfile` property indicating its operational footprint:

```powershell
@{
    Id           = 'S-PwdNeverExpires'
    AlertProfile = 'Stealth'          # Stealth | Moderate | Noisy
    # ... other properties
}
```

### Rules by Alert Profile

#### Stealth Rules (Low Detection Risk)
These rules use standard LDAP queries that blend with normal administrative activity:

- **User/Computer enumeration**: `S-PwdNeverExpires`, `S-InactiveUsers`, `S-ObsoleteOS`
- **Group membership checks**: `P-AdminNum`, `P-SchemaAdmin`, `P-OperatorsEmpty`
- **Delegation analysis**: `P-UnconstrainedDelegation`, `K-ConstrainedDelegation`
- **Trust enumeration**: `T-SIDFiltering`, `T-SIDHistorySameDomain`
- **Basic GPO reads**: `G-GPODelegation`, `G-GPOLinkAbuse`

#### Moderate Rules (Some Detection Risk)
These rules perform deeper analysis that may generate audit events:

- **ACL enumeration**: `P-WriteDACL`, `P-GenericAll`, `AV-AdminSDHolderBackdoor`
- **Certificate template analysis**: `C-ESC1` through `C-ESC13`
- **Schema/configuration reads**: `A-DsHeuristicsAnonymous`, `I-ForestFunctionalLevel`
- **SYSVOL/GPO content parsing**: `G-SYSVOLPermissions`, `E-GPOScriptEnumeration`

#### Noisy Rules (High Detection Risk)
These rules use remote execution and will likely trigger security alerts:

- **PSRemoting to DCs**: `I-DCTimeSkew`, `A-DCLdapChannelBinding`, `A-PrintSpoolerOnDC`
- **Endpoint data collection**: All `ES-*` (EndpointSecurity) rules
- **Remote registry access**: `AUTH-WDigestEnabled`, `AUTH-LSAProtectionDisabled`
- **Service enumeration**: `PERS-ScheduledTaskPriv`, `LOG-SysmonMissing`
- **EDR status checks**: `EDR-AgentCoverage`, `EDR-DCProtection`

---

## Scan Profiles

AD-Scout supports predefined scan profiles that control which rules execute based on
operational security requirements.

### Available Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `Stealth` | Only Stealth-rated rules | Initial recon, production systems, no pre-authorization |
| `Standard` | Stealth + Moderate rules | Typical assessment with basic authorization |
| `Comprehensive` | All rules including Noisy | Full assessment with explicit authorization |
| `DCOnly` | Rules targeting Domain Controllers | DC-focused hardening review |
| `EndpointAudit` | Endpoint security rules only | Endpoint configuration validation |

### Usage

```powershell
# Stealth scan - minimal footprint
Invoke-ADScoutScan -ScanProfile Stealth

# Standard assessment
Invoke-ADScoutScan -ScanProfile Standard

# Full assessment (requires authorization)
Invoke-ADScoutScan -ScanProfile Comprehensive

# Custom: Specific alert profiles
Invoke-ADScoutScan -AlertProfile Stealth, Moderate
```

---

## Expected Security Alerts

### Customer Whitelist Guidance

Provide customers with this information to create appropriate exceptions during assessment windows.

#### SIEM/Log Sources to Monitor

| Log Source | Events to Expect | Rule Categories |
|------------|------------------|-----------------|
| Windows Security | 4662 (Object Access), 4624 (Logon) | All |
| PowerShell ScriptBlock | 4104 (Script execution) | All |
| Windows Remote Management | 91, 168 (WSMan) | Noisy rules |
| Active Directory | 4662, 4928, 4929 (Replication) | Moderate+ |

#### EDR Detection Signatures

Common EDR alerts that may fire during AD-Scout execution:

| Detection | Trigger | Profile |
|-----------|---------|---------|
| LDAP Reconnaissance | Bulk LDAP queries | All |
| PowerShell Remote Execution | Invoke-Command | Noisy |
| AD Enumeration Tool | Get-AD* cmdlet patterns | All |
| Service Principal Enumeration | SPN queries | Stealth |
| Credential Dumping Recon | DPAPI/LSA queries | Noisy |

#### Sample Whitelist Configuration

**Microsoft Defender for Identity:**
```
Exclude account: YOURDOM\ADScoutSvc
Exclude activities: Account enumeration, LDAP recon
Time window: [Assessment dates]
```

**CrowdStrike Falcon:**
```
Exclusion path: C:\Tools\ADScout\*
User exclusion: ADScoutSvc
Detection exclusions: LDAP enumeration, PowerShell reconnaissance
```

**Splunk ES:**
```
index=wineventlog sourcetype=WinEventLog:Security
| where user="ADScoutSvc"
| eval assessment_activity="true"
```

---

## Credential Lifecycle Management

### Pre-Engagement Account Setup

1. **Create dedicated service account**
   ```powershell
   # Create assessment account
   $password = Read-Host -AsSecureString "Enter password"
   New-ADUser -Name "ADScoutSvc" `
       -SamAccountName "ADScoutSvc" `
       -UserPrincipalName "adscoutsvc@domain.com" `
       -AccountPassword $password `
       -Enabled $true `
       -PasswordNeverExpires $false `
       -Description "AD-Scout Security Assessment - Expires: $(Get-Date).AddDays(7)"
   ```

2. **Grant minimum required permissions**
   ```powershell
   # For Stealth/Moderate profiles - read-only access
   Add-ADGroupMember -Identity "Domain Users" -Members "ADScoutSvc"

   # For Comprehensive profile - requires elevated access
   # Option A: Domain Admins (simplest but highest privilege)
   # Option B: Custom delegation (preferred)
   ```

3. **Set account expiration**
   ```powershell
   # Auto-expire after engagement window
   Set-ADUser -Identity "ADScoutSvc" -AccountExpirationDate (Get-Date).AddDays(7)
   ```

### During Engagement

- Use `PSCredential` objects, never plain-text passwords
- Avoid storing credentials in scripts or config files
- Use Windows Credential Manager for interactive sessions:
  ```powershell
  $cred = Get-Credential -Message "AD-Scout Assessment Account"
  Invoke-ADScoutScan -Credential $cred
  ```

### Post-Engagement Cleanup

```powershell
# 1. Disable account immediately
Disable-ADAccount -Identity "ADScoutSvc"

# 2. Review account activity
Get-ADUser "ADScoutSvc" -Properties LastLogonDate, BadLogonCount, LogonCount

# 3. Remove from any groups
Get-ADPrincipalGroupMembership "ADScoutSvc" |
    Where-Object { $_.Name -ne "Domain Users" } |
    ForEach-Object { Remove-ADGroupMember -Identity $_ -Members "ADScoutSvc" -Confirm:$false }

# 4. Delete account after verification period (7-14 days)
# Remove-ADUser -Identity "ADScoutSvc" -Confirm
```

### Credential Security Checklist

- [ ] Dedicated account created for engagement
- [ ] Account has minimum required privileges
- [ ] Account expiration date set
- [ ] Password meets complexity requirements (20+ chars)
- [ ] Account documented in engagement notes
- [ ] Post-engagement disable date scheduled
- [ ] Customer notified of account creation

---

## Data Protection & Encryption

### Export Encryption

AD-Scout supports encrypted export of scan results to protect sensitive findings.

#### Encryption Methods

| Method | Use Case | Implementation |
|--------|----------|----------------|
| **Password-based** | Simple sharing | AES-256-CBC with PBKDF2 |
| **Certificate-based** | Enterprise/automated | CMS encryption |
| **Customer public key** | Secure delivery | Asymmetric encryption |

#### Usage Examples

```powershell
# Password-protected export
$results = Invoke-ADScoutScan
Export-ADScoutReport -Results $results -Format JSON -Path "findings.json" -Encrypt -Password (Read-Host -AsSecureString)

# Certificate-based encryption
Export-ADScoutReport -Results $results -Format JSON -Path "findings.json" -EncryptTo "CN=SecurityTeam"

# Compress and encrypt
Export-ADScoutReport -Results $results -Format JSON -Path "findings.json.zip" -Compress -Encrypt
```

#### Decryption

```powershell
# Password-based
$findings = Import-ADScoutReport -Path "findings.json" -Password (Read-Host -AsSecureString)

# Certificate-based (requires private key)
$findings = Import-ADScoutReport -Path "findings.json" -Certificate (Get-Item Cert:\CurrentUser\My\THUMBPRINT)
```

### Data Handling Requirements

1. **In-Transit**: Always use encrypted channels (HTTPS, encrypted remoting)
2. **At-Rest**: Encrypt exports containing customer data
3. **Retention**: Define retention period in engagement agreement
4. **Disposal**: Secure delete after retention period:
   ```powershell
   # Secure file deletion
   [System.IO.File]::WriteAllBytes($path, (1..$fileLength | ForEach-Object { Get-Random -Maximum 256 }))
   Remove-Item $path -Force
   ```

---

## Audit Trail & Logging

### Execution Logging

AD-Scout generates comprehensive audit logs for each scan execution.

#### Log Location

```
%LOCALAPPDATA%\ADScout\Logs\
├── ADScout-20240115-093022-Scan.log      # Scan execution log
├── ADScout-20240115-093022-Rules.log     # Rules evaluated
└── ADScout-20240115-093022-Manifest.json # Execution manifest
```

#### Manifest Contents

```json
{
  "ExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "StartTime": "2024-01-15T09:30:22Z",
  "EndTime": "2024-01-15T09:45:18Z",
  "Operator": "YOURDOM\\assessor",
  "TargetDomain": "customer.local",
  "ScanProfile": "Standard",
  "RulesEvaluated": 142,
  "FindingsCount": 47,
  "ToolVersion": "2.1.0",
  "Parameters": {
    "Category": ["All"],
    "ExcludeRuleId": [],
    "AlertProfile": ["Stealth", "Moderate"]
  },
  "Checksum": "SHA256:abc123..."
}
```

#### Centralized Logging

Forward audit logs to customer SIEM for correlation:

```powershell
# Configure Splunk forwarding
Set-ADScoutConfig -AuditLogDestination "Splunk" -SplunkHEC "https://splunk:8088" -SplunkToken $token

# Configure Windows Event Log
Set-ADScoutConfig -AuditLogDestination "EventLog" -EventLogName "ADScout"
```

---

## Pre-Engagement Checklist

### Authorization Requirements

Before conducting any AD-Scout assessment, ensure:

- [ ] **Written authorization** from customer security leadership
- [ ] **Scope definition** - which domains, OUs, systems
- [ ] **Time window** - start/end dates for assessment
- [ ] **Alert notification** - SOC/NOC informed of activity
- [ ] **Emergency contact** - escalation path if issues arise
- [ ] **Data handling agreement** - retention, encryption, disposal

### Technical Preparation

- [ ] Assessment account created and tested
- [ ] Network access verified from assessment system
- [ ] Required PowerShell modules available
- [ ] Customer provided DC/server list
- [ ] Backup/snapshot taken if testing remediation

### Customer Handoffs

Provide to customer before engagement:

1. **Expected Activity Document** - What the tool does, expected logs
2. **Whitelist Recommendations** - EDR/SIEM exclusions for assessment window
3. **Account Requirements** - Privileges needed for each scan profile
4. **Emergency Procedures** - How to halt scan if issues arise

### Sample Authorization Template

```
SECURITY ASSESSMENT AUTHORIZATION

Organization: [Customer Name]
Assessment Type: Active Directory Security Assessment
Tool: AD-Scout v[version]

Scope:
- Domains: [list domains]
- Excluded systems: [any exclusions]

Assessment Window:
- Start: [date/time]
- End: [date/time]

Authorized Activities:
- [x] LDAP enumeration of users, computers, groups
- [x] GPO and SYSVOL content analysis
- [x] ACL enumeration on AD objects
- [ ] Remote PowerShell to domain controllers (if Comprehensive)
- [ ] Endpoint security configuration checks (if EndpointAudit)

Assessment Account: [account name]
Assessor(s): [names]

Authorized By: _________________________ Date: _________
               [Customer Security Lead]
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-15 | Initial operational security guide |

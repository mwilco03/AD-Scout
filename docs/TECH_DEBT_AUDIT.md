# AD-Scout Technical Debt Audit Report

**Audit Date:** 2026-01-03
**Last Updated:** 2026-01-03
**Module Version:** 0.1.0 (alpha)
**Files Analyzed:** 287 PowerShell files

---

## Remediation Status

| Priority | Issue | Status | Commit |
|----------|-------|--------|--------|
| **P0** | Fix function exports | ✅ **DONE** | `38d9980` |
| **P0** | Load persisted config | ✅ **DONE** | `38d9980` |
| **P0** | Add RequiredModules | ✅ **DONE** | `38d9980` |
| **P1** | Extract fingerprint helper | ✅ **DONE** | `38d9980` |
| **P1** | Create config path helper | ✅ **DONE** | `38d9980` |
| **P1** | Add missing Set-ADScoutConfig params | ✅ **DONE** | Pending |
| **P1** | Create tests for new helpers | ✅ **DONE** | Pending |
| **P2** | Externalize SID mappings | ✅ **DONE** | `38d9980` |
| **P2** | Create centralized constants | ✅ **DONE** | `38d9980` |
| **P1** | Extract ACL validation module | ⏳ Pending | - |
| **P1** | Extract DirectorySearcher utility | ⏳ Pending | - |
| **P2** | Split Export-ADScoutReport | ⏳ Pending | - |
| **P2** | Create SMB scanner utilities | ⏳ Pending | - |

**Progress:** 9/13 items completed (69%)

---

## Executive Summary

| Component | Grade | Status | Critical Issues |
|-----------|-------|--------|-----------------|
| **Rules/** | C+ | Needs Work | ACL duplication (400+ LOC), hardcoded principals |
| **Public/** | C+ | Needs Work | Hash duplication, 706-line god function |
| **Private/** | B- | Fair | DirectorySearcher duplication (335 LOC) |
| **Module Structure** | C+ | Needs Work | Export mismatch, no config loading |
| **Overall** | **C+** | **Needs Attention** | **Significant refactoring required** |

---

## Component Assessments

### 1. Rules Directory

**Grade: C+ (2.3/4.0)**

#### Category Breakdown

| Category | Grade | Key Issues |
|----------|-------|------------|
| Anomalies | C+ | Hardcoded thresholds, DN construction duplication |
| AttackVectors | B- | Legitimate principal list duplication (9 files) |
| EphemeralPersistence | B | Date threshold inconsistency |
| Kerberos | C | Duplicate encryption checking with StaleObjects |
| PrivilegedAccess | C- | Massive ACL code duplication (6 files, 400 LOC) |
| StaleObjects | B- | Duplicate DES checks, hardcoded thresholds |
| Trusts | B- | Hardcoded flags, netdom usage |

#### Critical Issues

1. **ACL Checking Code Duplication** - 400+ lines duplicated across 6 files
   - `P-GenericAll.ps1:78-210`
   - `P-WriteDACL.ps1:108-177`
   - `P-DCSync.ps1:90-195`
   - `AV-AdminSDHolderBackdoor.ps1:88-147`

2. **Legitimate Principal Lists Inconsistency** - 9 files with different definitions
   - Some include "SELF", others don't
   - Some have "Account Operators", others miss it

3. **DES Encryption Checked Twice** - Duplicate rules
   - `K-DESEncryption.ps1` (Kerberos category)
   - `S-DESEncryption.ps1` (StaleObjects category)

4. **Empty Catch Blocks** - 74 instances silently discarding errors

5. **Hardcoded Strings** - 77+ instances
   - SIDs, thresholds, registry paths, LDAP filters

#### Recommendations

```
Priority 1: Create shared ACL validation module
  - File: src/ADScout/Private/Helpers/Invoke-ACLValidation.ps1
  - Impact: Eliminates 400+ lines of duplication

Priority 2: Create legitimate principals configuration
  - File: src/ADScout/Config/LegitimateADPrincipals.psd1
  - Impact: Single source of truth for 9 files

Priority 3: Consolidate DES encryption checking
  - Merge S-DESEncryption into K-DESEncryption
  - Remove duplicate from StaleObjects category
```

---

### 2. Public Functions

**Grade: C+ (2.3/4.0)**

#### Function Breakdown

| Function | Grade | Key Issues |
|----------|-------|------------|
| Export-ADScoutReport | C | 706-line god function, score duplication |
| Get-ADScoutRule | C | 93-line schema normalization block |
| Compare-ADScoutBaseline | B- | Duplicated hash calculation |
| Export-ADScoutBaseline | B- | Duplicated hash calculation |
| Invoke-ADScoutScan | B- | Hardcoded Entra ID collection |
| Set-ADScoutConfig | B+ | Duplicated config path |
| Get-ADScoutConfig | B+ | Duplicated config path |
| New-ADScoutRule | B | 85-line hardcoded template |
| Show-ADScoutDashboard | B | Hardcoded color thresholds |
| Connect-ADScoutGraph | B | Hardcoded module names/scopes |

#### Critical Issues

1. **Hash/Fingerprint Calculation Duplicated** - 3 files
   - `Export-ADScoutReport.ps1:296-300`
   - `Export-ADScoutBaseline.ps1:121-122`
   - `Compare-ADScoutBaseline.ps1:81-82`

2. **Configuration Path Hardcoding** - `.adscout/config.json` in 3 places
   - `Set-ADScoutConfig.ps1:94`
   - `Get-ADScoutConfig.ps1:57`
   - `Register-ADScoutRule.ps1:71`

3. **Score Threshold Inconsistency**
   - Critical: >=50 (consistent)
   - High/Warning: >=20 or >=30 (INCONSISTENT)
   - Medium: >=15

4. **Export-ADScoutReport God Function** - 706 lines with 6 format handlers

5. **Category ValidateSet Duplication**
   - `Get-ADScoutRule.ps1:53` - 18 categories
   - `New-ADScoutRule.ps1:49` - Only 7 categories (INCOMPLETE)

#### Recommendations

```
Priority 1: Extract Get-ADScoutFingerprint helper
  - File: src/ADScout/Private/Helpers/Get-ADScoutFingerprint.ps1
  - Impact: Eliminates 3 duplications in security-critical code

Priority 2: Extract Get-ADScoutConfigPath helper
  - File: src/ADScout/Private/Helpers/Get-ADScoutConfigPath.ps1
  - Impact: Single source for config path

Priority 3: Split Export-ADScoutReport
  - Create separate reporter files per format
  - Share common infrastructure

Priority 4: Sync category definitions
  - Define $script:ADScoutCategories in module init
  - Use in ValidateSet dynamically
```

---

### 3. Private Functions

**Grade: B- (2.7/4.0)**

#### Category Breakdown

| Category | Grade | Key Issues |
|----------|-------|------------|
| Helpers | B | Hardcoded SIDs (47 values) |
| Compatibility | B+ | ThreadJob issues, resource leaks |
| Collectors | C+ | 335 LOC duplication, hardcoded values |
| Scanners | B- | Hardcoded ports/timeouts, repeated patterns |
| Statistics | B | Hardcoded thresholds |

#### Critical Issues

1. **DirectorySearcher Fallback Duplication** - 335 lines across 3 files
   - `Get-ADScoutComputerData.ps1:115-218` (104 lines)
   - `Get-ADScoutGroupData.ps1:105-204` (100 lines)
   - `Get-ADScoutUserData.ps1:171-301` (131 lines)

2. **Hardcoded SID Mappings** - 47 values in `Convert-SidToName.ps1:36-77`

3. **SMB Connection Pattern Repeated** - 15+ times across scanner files

4. **Hardcoded Ports/Timeouts** - Scattered across 15+ scanner files
   - SMB Port: 445
   - LDAPS Port: 636
   - Default Timeout: 5000ms

5. **LDAP Path Construction Duplicated** - 3 identical implementations

#### Recommendations

```
Priority 1: Extract DirectorySearcher fallback utility
  - File: src/ADScout/Private/Helpers/Get-ADScoutDirectorySearcher.ps1
  - Impact: Eliminates 335 lines of duplication

Priority 2: Externalize SID mappings
  - File: src/ADScout/Data/SidMappings.json
  - Impact: Easier maintenance, version control

Priority 3: Create SMB scanner utilities module
  - File: src/ADScout/Private/Scanners/Invoke-SMBScannerUtilities.ps1
  - Impact: Eliminates 200+ lines of duplication

Priority 4: Create scanner configuration
  - File: src/ADScout/Config/ScannerDefaults.psd1
  - Define: SMB_PORT, LDAPS_PORT, DEFAULT_TIMEOUT
```

---

### 4. Module Structure

**Grade: C+ (2.3/4.0)**

#### Area Breakdown

| Area | Grade | Key Issues |
|------|-------|------------|
| Function Exports | D | Export-ADScoutNISTReport unreachable |
| Configuration | C | Schema mismatch, no auto-load |
| Dependencies | D+ | Undeclared RequiredModules |
| Test Coverage | D | Under 5% coverage |
| Loading | B | No lazy loading |
| Library Mgmt | B+ | Good DLL handling |

#### Critical Issues

1. **Function Export Mismatch**
   - `Export-ADScoutNISTReport` defined in `Reporters/NISTReporter.ps1`
   - Not exported because loader only exports from `Public/`
   - Users cannot call advertised function

2. **Configuration Not Loaded on Import**
   - `$script:ADScoutConfig` initialized with hardcoded defaults
   - Persisted config in `~/.adscout/config.json` never loaded
   - User settings silently ignored

3. **Missing RequiredModules**
   - `ActiveDirectory` - not declared
   - `GroupPolicy` - not declared
   - `Microsoft.Graph.*` - not declared

4. **Test Coverage Under 5%**
   - ~1,100 lines of tests for 287 source files
   - No coverage enforcement in CI
   - Missing tests for baseline, graph, CSV functions

#### Recommendations

```
Priority 0 (CRITICAL):
  - Fix function exports - move NISTReporter or update loader
  - Load persisted config on module import
  - Add RequiredModules to manifest

Priority 1:
  - Implement minimum coverage check (70% target)
  - Add tests for untested functions

Priority 2:
  - Implement lazy loading for collectors/scanners
  - Add OnRemove handler for cleanup
```

---

## Summary: Top 10 Refactoring Priorities

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| **P0** | Fix function exports | Breaking | 1 hour |
| **P0** | Load persisted config | Breaking | 2 hours |
| **P0** | Add RequiredModules | Breaking | 1 hour |
| **P1** | Extract ACL validation module | 400+ LOC | 4 hours |
| **P1** | Extract DirectorySearcher utility | 335 LOC | 4 hours |
| **P1** | Extract fingerprint helper | Security | 1 hour |
| **P1** | Create config path helper | 3 files | 1 hour |
| **P2** | Split Export-ADScoutReport | 706 LOC | 8 hours |
| **P2** | Externalize SID mappings | 47 values | 2 hours |
| **P2** | Create SMB scanner utilities | 200+ LOC | 4 hours |

**Estimated Total Effort:** 40-60 hours for critical and high-priority items

---

## Hardcoded Values Summary

| Category | Count | Examples |
|----------|-------|----------|
| Legitimate Principal Names | 9 files | Domain Admins, Enterprise Admins, SYSTEM |
| Well-Known SIDs | 12+ files | S-1-5-32-544, S-1-5-18, S-1-5-21-*-512 |
| Score Thresholds | 25+ instances | 50 (critical), 20/30 (warning), 15 (medium) |
| Time Thresholds | 15+ instances | 90 days (inactive), 30 days (cert expiry) |
| Encryption Flags | 3 files | 0x1 (DES_CBC_CRC), 0x4 (RC4) |
| Registry Paths | 8+ files | HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |
| Ports | 15+ files | 445 (SMB), 636 (LDAPS) |

**Total Hardcoded Instances:** 150+

---

## Code Duplication Summary

| Pattern | Lines | Files | Savings |
|---------|-------|-------|---------|
| ACL Validation Logic | 400+ | 6 | 350 LOC |
| DirectorySearcher Fallback | 335 | 3 | 285 LOC |
| SMB Connection | 200+ | 15 | 180 LOC |
| Legitimate Principal Check | 135 | 9 | 120 LOC |
| LDAP Path Construction | 45 | 3 | 35 LOC |
| Hash Calculation | 15 | 3 | 12 LOC |
| Config Path | 9 | 3 | 6 LOC |

**Total Potential Savings:** ~1,000 lines of code

---

## Recommended File Structure Additions

```
src/ADScout/
├── Config/
│   ├── ADScoutDefaults.psd1      # Centralized configuration
│   ├── LegitimateADPrincipals.psd1
│   ├── ScannerDefaults.psd1
│   └── StatisticsDefaults.psd1
├── Data/
│   ├── SidMappings.json          # Well-known SIDs
│   ├── HighPrivilegeScopes.json  # Graph API scopes
│   └── RoleClassifications.json  # Entra ID roles
└── Private/
    └── Helpers/
        ├── Get-ADScoutFingerprint.ps1
        ├── Get-ADScoutConfigPath.ps1
        ├── Get-ADScoutDirectorySearcher.ps1
        ├── Invoke-ACLValidation.ps1
        └── Invoke-SMBScannerUtilities.ps1
```

---

## Conclusion

The AD-Scout codebase demonstrates **solid security logic and comprehensive AD vulnerability coverage**, but suffers from **significant technical debt** that will compound over time. The primary concerns are:

1. **Breaking Issues** (P0): Function exports, config loading, dependencies
2. **Code Duplication** (P1): 1,000+ lines could be consolidated
3. **Hardcoded Values** (P2): 150+ instances need externalization
4. **Test Coverage** (P1): Under 5%, no enforcement

**Target State After Remediation:**
- Overall Grade: B+
- Code reduction: 1,000+ lines
- Single sources of truth for all constants
- 70%+ test coverage
- Clean module loading with proper dependency declaration

---

*Report generated by comprehensive codebase analysis*

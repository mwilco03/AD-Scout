# AD-Scout Security Rules - Comprehensive Validation Guide

This document provides detailed validation, impact assessment, remediation guidance, and exception considerations for each AD-Scout security rule.

---

## Table of Contents

1. [StaleObjects Category](#staleobjects-category)
2. [Kerberos Category](#kerberos-category)
3. [PrivilegedAccess Category](#privilegedaccess-category)
4. [Trusts Category](#trusts-category)
5. [GPO Category](#gpo-category)
6. [PKI Category](#pki-category)

---

## StaleObjects Category

### S-PwdNeverExpires - Password Never Expires

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies enabled user accounts with the `PasswordNeverExpires` flag (UAC 0x10000) set to true.

#### Independent Verification
```powershell
# Using Active Directory module
Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires, PasswordLastSet |
    Select-Object SamAccountName, PasswordNeverExpires, PasswordLastSet

# Using DirectorySearcher (no AD module required)
$searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Passwords remain valid indefinitely, increasing credential theft risk |
| **Compliance** | Violates NIST 800-53, PCI-DSS, HIPAA password rotation requirements |
| **Operational** | Old credentials may exist in breach databases |
| **Attack Surface** | Extended window for brute force, password spraying, and credential stuffing |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1078.002**: Attackers use valid domain accounts for persistence
- Passwords leaked in data breaches remain valid indefinitely
- No forced rotation reduces defense against credential-based attacks
- Users have no incentive to change potentially compromised passwords

#### Remediation Steps
```powershell
# Remove the flag for a single user
Set-ADUser -Identity 'username' -PasswordNeverExpires $false

# Bulk remediation (verify first)
Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} |
    ForEach-Object { Set-ADUser -Identity $_ -PasswordNeverExpires $false }
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **gMSA/MSA** | Automatically rotated passwords | Automatic 30-day rotation |
| **Service Accounts** | Application compatibility | 25+ char password, AES encryption, monitoring |
| **Break-glass Accounts** | Emergency access | Vault storage, extensive logging, MFA |
| **Kiosk Accounts** | Shared device access | Physical security, network isolation |

---

### S-InactiveUsers - Inactive User Accounts

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies enabled user accounts with no login activity for 90+ days (configurable threshold).

#### Independent Verification
```powershell
# Using Active Directory module
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $threshold} -Properties LastLogonDate |
    Select-Object SamAccountName, LastLogonDate

# Using DirectorySearcher
$threshold = (Get-Date).AddDays(-90).ToFileTime()
$searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=$threshold))"
$searcher.FindAll()
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Dormant accounts are targets for takeover |
| **Compliance** | SOX, GDPR require prompt deprovisioning |
| **Licensing** | May consume unnecessary licenses |
| **Attack Surface** | Terminated employees may retain access |

#### Why Remediation is Necessary
- Represents potential unauthorized access from former employees
- Attackers specifically target dormant accounts (harder to detect abuse)
- Indicates gaps in offboarding processes
- May indicate compromised accounts that attackers keep dormant

#### Remediation Steps
```powershell
# Export for HR review first
Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt (Get-Date).AddDays(-90)} -Properties LastLogonDate, Department, Manager |
    Export-Csv "InactiveUsers.csv" -NoTypeInformation

# After HR approval, disable accounts
Disable-ADAccount -Identity 'username'
Move-ADObject -Identity 'userDN' -TargetPath 'OU=Disabled Users,DC=domain,DC=com'
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Seasonal Workers** | Predictable return dates | Document return date, auto-disable |
| **Leave of Absence** | Extended leave | HR tracking, temporary disable |
| **Executive Accounts** | Infrequent but legitimate use | Additional authentication requirements |
| **Shared Accounts** | Department mailboxes | Restrict to specific use, audit logging |

---

### S-InactiveComputers - Inactive Computer Accounts

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies enabled computer accounts with no authentication for 90+ days.

#### Independent Verification
```powershell
# Using Active Directory module
$threshold = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $threshold} -Properties LastLogonDate, OperatingSystem |
    Select-Object Name, LastLogonDate, OperatingSystem

# Check password age (computers change passwords every 30 days)
Get-ADComputer -Filter * -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-60) }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Stale accounts can be reused for persistence |
| **Compliance** | Asset management requirements |
| **Operations** | Cluttered AD, inaccurate inventory |
| **Attack Surface** | Silver ticket attacks using stale computer accounts |

#### Why Remediation is Necessary
- Computer accounts with old passwords are vulnerable to Silver Ticket attacks
- Attackers can hijack stale computer identities
- May indicate decommissioned systems not properly removed
- Compliance frameworks require accurate asset inventories

#### Remediation Steps
```powershell
# Two-stage process recommended
# Stage 1: Disable
Get-ADComputer -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)} |
    ForEach-Object { Disable-ADAccount -Identity $_ }

# Stage 2: Delete after additional 30 days
Get-ADComputer -Filter {Enabled -eq $false} -SearchBase 'OU=Disabled Computers,...' |
    Where-Object { $_.Modified -lt (Get-Date).AddDays(-30) } |
    Remove-ADComputer -Confirm:$false
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **DR Systems** | Standby for disaster recovery | Documented DR plan, periodic testing |
| **Offline Systems** | Air-gapped or rarely connected | Physical security, network isolation |
| **Lab Equipment** | Intermittent use | Separate OU, restricted network |

---

### S-DisabledAccountsWithGroupMembership

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies disabled accounts that retain group memberships (especially privileged groups).

#### Independent Verification
```powershell
Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf |
    Where-Object { $_.MemberOf.Count -gt 1 } |
    Select-Object SamAccountName, @{N='GroupCount';E={$_.MemberOf.Count}}
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Re-enabling restores all previous privileges |
| **Compliance** | Audit findings for incomplete deprovisioning |
| **Risk** | Insider threat if account re-enabled |

#### Why Remediation is Necessary
- If an account is re-enabled (maliciously or accidentally), all permissions are instantly restored
- Represents incomplete offboarding
- Privileged memberships on disabled accounts are high-value targets

#### Remediation Steps
```powershell
# Remove all group memberships from disabled accounts
Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf |
    ForEach-Object {
        $user = $_
        $_.MemberOf | ForEach-Object {
            Remove-ADGroupMember -Identity $_ -Members $user -Confirm:$false
        }
    }
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Pending Deletion** | Awaiting final deletion | Short retention window (7-30 days) |
| **Legal Hold** | Litigation preservation | Document hold, restrict re-enable |

---

## Kerberos Category

### K-Kerberoasting - Kerberoastable Service Accounts

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies user accounts with SPNs that can be targeted for offline password cracking.

#### Independent Verification
```powershell
# Find all accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet

# Check encryption types
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName, 'msDS-SupportedEncryptionTypes'
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Service account credentials can be cracked offline |
| **Lateral Movement** | Compromised service accounts enable domain traversal |
| **Privilege Escalation** | Service accounts often have elevated privileges |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1558.003**: Primary credential access technique
- Any domain user can request TGS tickets for any SPN
- Weak passwords can be cracked in seconds with modern GPUs
- RC4 encryption is trivially crackable

#### Remediation Steps
```powershell
# Priority 1: Enable AES-only encryption
Set-ADUser -Identity 'svc_account' -KerberosEncryptionType 'AES256'

# Priority 2: Set strong password (25+ characters)
$password = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 32 | ForEach-Object {[char]$_})
Set-ADAccountPassword -Identity 'svc_account' -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Reset

# Priority 3: Migrate to gMSA
New-ADServiceAccount -Name 'gMSA_ServiceName' -DNSHostName 'gmsa.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup'
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Legacy Applications** | Cannot support AES | 25+ char password, frequent rotation, monitoring |
| **Third-party Services** | Vendor requirements | Network isolation, privileged access restriction |

---

### K-ASREPRoasting - AS-REP Roastable Accounts

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH flag).

#### Independent Verification
```powershell
# Using Active Directory module
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Using UserAccountControl flag (4194304 = 0x400000)
Get-ADUser -Filter * -Properties UserAccountControl |
    Where-Object { $_.UserAccountControl -band 4194304 }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | No authentication required to obtain crackable hash |
| **Attack Complexity** | Attackers don't need any credentials to attack |
| **Detection** | Attack generates no authentication failures |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1558.004**: AS-REP Roasting
- Unlike Kerberoasting, no valid credentials needed
- Attack is completely offline and undetectable
- No legitimate reason for this setting on most accounts

#### Remediation Steps
```powershell
# Enable pre-authentication
Set-ADAccountControl -Identity 'username' -DoesNotRequirePreAuth $false

# Verify the change
Get-ADUser -Identity 'username' -Properties DoesNotRequirePreAuth | Select-Object Name, DoesNotRequirePreAuth
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Ancient Legacy Systems** | Very old Kerberos implementations | Extremely rare; document and isolate |

**Note:** There are virtually no legitimate reasons for this setting. It was used for compatibility with very old systems that no longer exist.

---

### K-UnconstrainedDelegation - Unconstrained Kerberos Delegation

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies non-DC computers with unconstrained delegation enabled.

#### Independent Verification
```powershell
# Find computers with unconstrained delegation (excluding DCs)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Where-Object { $_.DistinguishedName -notlike "*Domain Controllers*" }

# Using UserAccountControl flag (524288 = 0x80000)
Get-ADComputer -Filter * -Properties UserAccountControl |
    Where-Object { $_.UserAccountControl -band 524288 }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | TGTs cached on server can impersonate ANY user |
| **Privilege Escalation** | Can impersonate Domain Admins |
| **Lateral Movement** | Single compromise enables domain-wide access |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1558.001**: Allows complete domain compromise
- Printer Bug/PetitPotam can coerce DC authentication
- Cached TGTs allow unlimited impersonation
- One of the most critical AD misconfigurations

#### Remediation Steps
```powershell
# Disable unconstrained delegation
Set-ADComputer -Identity 'ServerName' -TrustedForDelegation $false

# Configure constrained delegation instead
Set-ADComputer -Identity 'ServerName' -Add @{'msDS-AllowedToDelegateTo'='HTTP/target.domain.com'}

# Or use Resource-Based Constrained Delegation (RBCD)
$target = Get-ADComputer -Identity 'TargetServer'
Set-ADComputer -Identity $target -PrincipalsAllowedToDelegateToAccount (Get-ADComputer 'SourceServer')

# Protect sensitive accounts
Add-ADGroupMember -Identity 'Protected Users' -Members 'AdminAccount'
Set-ADUser -Identity 'AdminAccount' -AccountNotDelegated $true
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Domain Controllers** | Required for DC operations | Already expected; inherent to DC role |

**Note:** There are essentially no valid exceptions for non-DC computers. Always migrate to constrained or RBCD.

---

## PrivilegedAccess Category

### P-PrivilegedGroupMembership - Excessive Privileged Group Membership

**Rule Status:** ✅ Valid

#### Detection Logic
Counts members in highly privileged groups against defined thresholds.

| Group | Recommended Threshold |
|-------|----------------------|
| Domain Admins | ≤ 5 |
| Enterprise Admins | ≤ 3 |
| Schema Admins | ≤ 2 |
| Administrators | ≤ 10 |

#### Independent Verification
```powershell
# Count members of privileged groups
@('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') | ForEach-Object {
    $count = (Get-ADGroupMember -Identity $_ -Recursive | Measure-Object).Count
    [PSCustomObject]@{ Group = $_; MemberCount = $count }
}
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | More accounts = larger attack surface |
| **Accountability** | Difficult to track who did what |
| **Least Privilege** | Violates fundamental security principle |

#### Why Remediation is Necessary
- Each privileged account is a potential compromise vector
- Reduces accountability for administrative actions
- Increases blast radius of credential theft
- Industry best practice is minimal privileged accounts

#### Remediation Steps
```powershell
# Review membership
Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SamAccountName, ObjectClass

# Remove unnecessary members
Remove-ADGroupMember -Identity 'Domain Admins' -Members 'UserToRemove' -Confirm:$false

# Implement JIT access (Azure AD PIM or third-party)
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Break-glass Accounts** | Emergency access | Vault storage, monitoring, MFA |
| **Large Organizations** | Distributed admin teams | Tiered administration, delegation |

---

### P-AdminSDHolder - AdminSDHolder ACL Modifications

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies non-default permissions on the AdminSDHolder container.

#### Independent Verification
```powershell
# Get AdminSDHolder ACL
$adminSDHolder = Get-ADObject -Filter 'Name -eq "AdminSDHolder"' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)"
$acl = Get-Acl -Path "AD:\$($adminSDHolder.DistinguishedName)"

# Compare against known defaults
$acl.Access | Where-Object { $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM' }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Persistence mechanism for attackers |
| **Detection** | SDProp propagates changes every 60 minutes |
| **Compromise** | Grants permanent access to all protected accounts |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1098**: Account Manipulation
- Changes propagate to all protected accounts automatically
- Provides persistent backdoor access to privileged accounts
- Indicates potential active compromise

#### Remediation Steps
```powershell
# Remove unauthorized ACEs
$adminSDHolder = Get-ADObject -Filter 'Name -eq "AdminSDHolder"' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)"
$acl = Get-Acl -Path "AD:\$($adminSDHolder.DistinguishedName)"
$aceToRemove = $acl.Access | Where-Object { $_.IdentityReference -eq 'DOMAIN\UnauthorizedUser' }
$acl.RemoveAccessRule($aceToRemove)
Set-Acl -Path "AD:\$($adminSDHolder.DistinguishedName)" -AclObject $acl
```

#### Exceptions to Consider
None. There should never be non-default permissions on AdminSDHolder. Any modification is suspicious.

---

### P-ServiceAccountPrivileges - Service Accounts with Excessive Privileges

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies service accounts (by naming convention or SPN) in privileged groups.

#### Independent Verification
```powershell
# Find service accounts in privileged groups
Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
    Where-Object { $_.SamAccountName -match 'svc|service|sql|app' }

# Find accounts with SPNs in privileged groups
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties MemberOf |
    Where-Object { $_.MemberOf -match 'Admins' }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Service account compromise = admin access |
| **Kerberoasting** | Privileged service accounts are high-value targets |
| **Least Privilege** | Services rarely need full admin rights |

#### Why Remediation is Necessary
- Service accounts are often Kerberoastable
- Compromise of admin service account = full domain compromise
- Services rarely need Domain Admin privileges
- Password management is often poor for service accounts

#### Remediation Steps
```powershell
# Migrate to gMSA
New-ADServiceAccount -Name 'gMSA_ServiceName' -DNSHostName 'gmsa.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup'

# Remove from privileged groups
Remove-ADGroupMember -Identity 'Domain Admins' -Members 'svc_account'

# Grant minimum required permissions
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Backup Software** | Requires domain-wide access | Dedicated backup admin account, monitoring |
| **SCCM/SCOM** | Management platform requirements | Tiered service accounts, network isolation |

---

## Trusts Category

### T-SIDFilteringDisabled - SID Filtering Disabled

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies external/forest trusts without SID filtering (quarantine).

#### Independent Verification
```powershell
# Check trust attributes
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes,
    @{N='SIDFiltering';E={($_.TrustAttributes -band 4) -ne 0}}

# Using netdom
netdom trust domain.com /domain:trusted.com /verify
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | SID history injection attacks possible |
| **Cross-Forest** | Compromised forest can attack your domain |
| **Privilege Escalation** | Attackers can forge privileged SIDs |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1134.005**: SID-History Injection
- Compromised trusted domain can inject any SID
- Enables complete domain takeover from external forest
- One of the most dangerous trust misconfigurations

#### Remediation Steps
```powershell
# Enable SID filtering
netdom trust domain.com /domain:trusted.com /quarantine:yes /userD:admin /passwordD:*

# Verify
netdom trust domain.com /domain:trusted.com /verify
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Active Migration** | SID history needed during migration | Time-limited, extensive monitoring |

---

### T-SelectiveAuthDisabled - Selective Authentication Not Enabled

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies forest trusts without selective authentication.

#### Independent Verification
```powershell
Get-ADTrust -Filter {ForestTransitive -eq $true} |
    Select-Object Name, @{N='SelectiveAuth';E={($_.TrustAttributes -band 16) -ne 0}}
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | All trusted forest users can authenticate everywhere |
| **Least Privilege** | Overly permissive access |
| **Lateral Movement** | Easy cross-forest movement |

#### Why Remediation is Necessary
- Without selective auth, any user in trusted forest can access any resource
- Violates principle of least privilege
- Enables broad lateral movement

#### Remediation Steps
```powershell
# Enable selective authentication
netdom trust domain.com /domain:trusted.com /SelectiveAuth:yes

# Then grant 'Allowed to Authenticate' on specific resources
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Merger/Acquisition** | Temporary broad access during integration | Time-limited, audit all access |
| **Shared Services** | Many resources need cross-forest access | Consider per-resource authentication |

---

### T-TrustTransitivity - Transitive External Trusts

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies external trusts that are transitive (unusual configuration).

#### Independent Verification
```powershell
Get-ADTrust -Filter {TrustType -eq 'External'} |
    Where-Object { -not ($_.TrustAttributes -band 1) } |
    Select-Object Name, Direction
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Extended trust chain increases risk |
| **Lateral Movement** | Multi-hop attacks possible |
| **Visibility** | Difficult to track access paths |

#### Why Remediation is Necessary
- External trusts should typically be non-transitive
- Transitivity extends the trust chain unexpectedly
- Increases attack surface through trusted domains

#### Remediation Steps
External trusts must be recreated to change transitivity:
1. Document all resources using the trust
2. Remove existing trust
3. Recreate as non-transitive

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Complex Partnerships** | Multi-domain partner access | Document thoroughly, SID filtering |

---

## GPO Category

### G-GPPPasswords - Group Policy Preferences Passwords

**Rule Status:** ✅ Valid (CRITICAL)

#### Detection Logic
Scans GPO XML files for cpassword attributes containing encrypted passwords.

#### Independent Verification
```powershell
# Search SYSVOL for cpassword
findstr /S /I "cpassword" "\\domain.com\SYSVOL\domain.com\Policies\*.xml"

# Using PowerShell
Get-ChildItem "\\domain.com\SYSVOL\domain.com\Policies" -Recurse -Include *.xml |
    Select-String -Pattern "cpassword" | Select-Object Path
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Passwords trivially decrypted by ANY domain user |
| **Compliance** | Plaintext credential storage violation |
| **Immediate Risk** | Public decryption key since MS14-025 |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1552.006**: The encryption key is publicly known
- Any domain user can decrypt these passwords
- May contain admin passwords, service account credentials
- This is one of the most commonly exploited AD vulnerabilities

#### Remediation Steps
```powershell
# Find and remove GPP passwords
findstr /S /I "cpassword" "\\domain.com\SYSVOL\domain.com\Policies\*.xml"

# After removal, CHANGE ALL EXPOSED PASSWORDS IMMEDIATELY
# Use LAPS for local admin passwords
# Use gMSA for service accounts
```

#### Exceptions to Consider
None. GPP passwords must never be used. There are no valid exceptions.

---

### G-GPOPermissions - Dangerous GPO Permissions

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies GPOs where low-privileged groups (Domain Users, Authenticated Users, Everyone) have write permissions.

#### Independent Verification
```powershell
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $acl = Get-GPPermission -Guid $gpo.Id -All
    $acl | Where-Object { $_.Permission -match 'Edit|Write' -and $_.Trustee.Name -match 'Domain Users|Authenticated Users|Everyone' } |
        ForEach-Object { [PSCustomObject]@{ GPO = $gpo.DisplayName; Trustee = $_.Trustee.Name; Permission = $_.Permission } }
}
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Any user can push malicious settings domain-wide |
| **Privilege Escalation** | Immediate path to Domain Admin |
| **Persistence** | Add logon scripts, scheduled tasks |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1484.001**: Group Policy Modification
- GPO write access = domain compromise
- Can deploy malware via logon scripts
- Can add local admins via Restricted Groups

#### Remediation Steps
```powershell
# Remove dangerous permissions
Set-GPPermission -Guid 'GPO-GUID' -TargetName 'Domain Users' -TargetType Group -PermissionLevel None
```

#### Exceptions to Consider
None for low-privileged groups. Only designated GPO administrators should have edit rights.

---

### G-UnlinkedGPOs - Unlinked Group Policy Objects

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies GPOs not linked to any OU, site, or domain.

#### Independent Verification
```powershell
Get-GPO -All | Where-Object { ([xml](Get-GPOReport -Guid $_.Id -ReportType XML)).GPO.LinksTo -eq $null }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Operations** | AD clutter, management overhead |
| **Compliance** | Poor hygiene indicators |
| **Security** | Minor - unlinked GPOs don't apply |

#### Why Remediation is Necessary
- Represents cleanup opportunity
- May contain outdated or conflicting settings
- Indicates gaps in GPO lifecycle management

#### Remediation Steps
```powershell
# Backup before deletion
Backup-GPO -Guid 'GPO-GUID' -Path 'C:\GPOBackups'

# Delete if not needed
Remove-GPO -Guid 'GPO-GUID'
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Template GPOs** | Used as templates for new GPOs | Clear naming convention |
| **Pending Deployment** | Not yet linked | Document deployment timeline |

---

## PKI Category

### C-ESC1-VulnerableTemplate - ESC1 Vulnerable Certificate Template

**Rule Status:** ✅ Valid (CRITICAL)

#### Detection Logic
Identifies templates where:
1. Low-privileged users can enroll
2. ENROLLEE_SUPPLIES_SUBJECT is enabled
3. Client Authentication EKU is present

#### Independent Verification
```powershell
# Using Certify
.\Certify.exe find /vulnerable

# Manual check
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" -Filter * -Properties *
$templates | Where-Object {
    $_.'msPKI-Certificate-Name-Flag' -band 1 -and  # ENROLLEE_SUPPLIES_SUBJECT
    $_.'pKIExtendedKeyUsage' -contains '1.3.6.1.5.5.7.3.2'  # Client Auth
}
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Any user can impersonate any other user |
| **Privilege Escalation** | Instant Domain Admin |
| **Detection** | Certificate-based attacks hard to detect |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1649**: Authentication Certificate theft
- Any domain user can request certificate as Domain Admin
- Most critical ADCS vulnerability
- Publicly known and actively exploited

#### Remediation Steps
```powershell
# Option 1: Remove ENROLLEE_SUPPLIES_SUBJECT flag
certutil -dstemplate "TemplateName" msPKI-Certificate-Name-Flag -CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

# Option 2: Restrict enrollment
# Remove 'Domain Users' enrollment rights via certtmpl.msc

# Option 3: Enable Manager Approval
certutil -dstemplate "TemplateName" msPKI-Enrollment-Flag +CT_FLAG_PEND_ALL_REQUESTS
```

#### Exceptions to Consider
None for the combination of low-priv enrollment + arbitrary SAN. Always remediate.

---

### C-ESC8-WebEnrollment - NTLM Relay to Web Enrollment

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies CA web enrollment endpoints vulnerable to NTLM relay (no EPA, no HTTPS enforcement).

#### Independent Verification
```powershell
# Check if web enrollment is installed
Get-WindowsFeature -Name ADCS-Web-Enrollment

# Check IIS configuration for EPA
Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name extendedProtection.tokenChecking
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | PetitPotam and similar attacks can obtain certificates |
| **Lateral Movement** | Machine account compromise via relay |
| **Domain Compromise** | DC machine account = domain compromise |

#### Why Remediation is Necessary
- **MITRE ATT&CK T1557.001**: NTLM Relay
- Combined with coercion attacks (PetitPotam), enables domain compromise
- Well-documented attack path with public tools

#### Remediation Steps
```powershell
# Best: Disable web enrollment if not needed
Remove-WindowsFeature ADCS-Web-Enrollment

# If required: Enable EPA and HTTPS
# IIS Manager → CertSrv → Authentication → Windows Auth → Advanced Settings → Extended Protection: Required
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **NDES** | Mobile device enrollment | Require HTTPS + EPA |

---

### C-WeakCryptoTemplates - Weak Cryptography in Templates

**Rule Status:** ✅ Valid

#### Detection Logic
Identifies templates with:
- RSA key size < 2048 bits
- SHA-1 or MD5 hash algorithms
- Deprecated signature algorithms

#### Independent Verification
```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" -Filter * -Properties 'msPKI-Minimal-Key-Size' |
    Where-Object { $_.'msPKI-Minimal-Key-Size' -lt 2048 }
```

#### Organizational Impact
| Impact Area | Description |
|------------|-------------|
| **Security** | Weak keys can be factored |
| **Compliance** | PCI-DSS, NIST require 2048+ bit RSA |
| **Longevity** | SHA-1 deprecated, browsers reject |

#### Why Remediation is Necessary
- SHA-1 collision attacks are practical
- RSA-1024 can be factored with sufficient resources
- Compliance frameworks require modern cryptography
- Browser and OS vendors reject weak certificates

#### Remediation Steps
```powershell
# Set minimum key size
certutil -dstemplate "TemplateName" msPKI-Minimal-Key-Size 2048

# Update hash algorithm via certtmpl.msc GUI
```

#### Exceptions to Consider
| Exception Type | Justification | Compensating Controls |
|---------------|---------------|----------------------|
| **Legacy Devices** | Cannot support modern crypto | Network isolation, short certificate lifetime |

---

## Summary Statistics

| Category | Rules | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| StaleObjects | 4 | 0 | 0 | 2 | 2 |
| Kerberos | 3 | 1 | 2 | 0 | 0 |
| PrivilegedAccess | 3 | 1 | 2 | 0 | 0 |
| Trusts | 3 | 1 | 1 | 1 | 0 |
| GPO | 3 | 2 | 0 | 0 | 1 |
| PKI | 3 | 2 | 0 | 1 | 0 |
| **Total** | **19** | **7** | **5** | **4** | **3** |

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [SpecterOps - Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ADSecurity.org](https://adsecurity.org/)

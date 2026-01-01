# Third-Party Library Notices

## SMBLibrary

**License**: LGPL-3.0-or-later
**Source**: https://github.com/TalAloni/SMBLibrary
**Copyright**: (c) Tal Aloni 2014-2025

SMBLibrary is used for SMB protocol-level security scanning.
It is distributed as a separate DLL in compliance with LGPL requirements.

### Capabilities
- SMB 1.0/2.0/2.1/3.0/3.0.2/3.1.1 dialect negotiation
- SMB signing detection and verification
- SMB encryption capability detection
- Share enumeration (including null session testing)
- Protocol-level security assessment

## RPCForSMBLibrary

**License**: LGPL-3.0
**Source**: https://github.com/vletoux/RPCForSMBLibrary
**Copyright**: (c) Vincent LE TOUX

RPCForSMBLibrary extends SMBLibrary with RPC protocol support.
It is distributed as a separate DLL in compliance with LGPL requirements.

### Capabilities
- SAMR (Security Account Manager Remote) queries
- LSA (Local Security Authority) policy enumeration
- Netlogon service interaction
- EFSRPC accessibility testing (PetitPotam detection)
- DFSNM accessibility testing (DFSCoerce detection)
- Print Spooler service probing (PrinterBug detection)

---

## Installation

These libraries are **optional**. AD-Scout functions without them but with
reduced protocol-level detection capabilities.

To use these libraries:

1. Download from the source repositories above
2. Build or download the release DLLs
3. Place DLLs in this directory:
   - `SMBLibrary.dll`
   - `RPCForSMBLibrary.dll`
4. Restart PowerShell session

AD-Scout will automatically load them when needed for DLL-required rules.

## Feature Comparison

| Feature | Without DLLs | With DLLs |
|---------|--------------|-----------|
| SMB Signing (Registry) | ✓ | ✓ |
| SMB Signing (Protocol) | ✗ | ✓ |
| SMB Version Detection | Limited | Full |
| Null Session Testing | Basic | Protocol-level |
| Coercion Detection | TCP only | Full RPC |
| Zerologon Detection | ✗ | ✓ (safe) |
| LDAP Channel Binding | ✗ | ✓ |

## LGPL Compliance

These libraries are licensed under LGPL-3.0, which allows:
- Using the libraries in proprietary software
- Dynamic linking without source disclosure
- Modification of the library (with source disclosure of modifications)

AD-Scout loads these libraries dynamically at runtime and does not modify them.
Users can replace the DLLs with their own builds or newer versions.

## Building from Source

### SMBLibrary
```bash
git clone https://github.com/TalAloni/SMBLibrary
cd SMBLibrary
dotnet build -c Release
# Copy SMBLibrary/bin/Release/net*/SMBLibrary.dll here
```

### RPCForSMBLibrary
```bash
git clone https://github.com/vletoux/RPCForSMBLibrary
cd RPCForSMBLibrary
dotnet build -c Release
# Copy bin/Release/net*/RPCForSMBLibrary.dll here
```

## Security Notice

These libraries enable protocol-level security testing. Ensure you have
authorization before scanning systems you do not own or administer.
All scanners in AD-Scout are designed for defensive security assessment only.

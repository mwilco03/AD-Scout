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

### Quick Install (Download Releases)

**SMBLibrary** (v1.5.x or later):
- Go to: https://github.com/TalAloni/SMBLibrary/releases
- Download the latest `.nupkg` or build from source
- Extract `SMBLibrary.dll` from `lib/net472/` or `lib/netstandard2.0/`

**RPCForSMBLibrary**:
- Go to: https://github.com/vletoux/RPCForSMBLibrary
- Clone and build (no pre-built releases available)

### Installation Steps

1. Download or build the DLLs (see above)
2. Copy DLLs to the AD-Scout Libraries directory:
   ```powershell
   # Find the Libraries directory
   $libPath = Join-Path (Get-Module ADScout).ModuleBase 'Libraries'

   # Copy the DLLs
   Copy-Item SMBLibrary.dll $libPath
   Copy-Item RPCForSMBLibrary.dll $libPath
   ```
3. Restart your PowerShell session
4. Verify installation:
   ```powershell
   # Should return $true if DLLs are loaded
   Initialize-ADScoutSMBLibrary
   ```

AD-Scout will automatically load them when needed for DLL-required rules.

### Troubleshooting

If DLLs fail to load:
- **"Could not load file or assembly"**: Ensure .NET Framework 4.7.2+ or .NET 6+ is installed
- **"Assembly mismatch"**: DLL version must match - try downloading matching versions
- **PowerShell execution policy**: DLLs must not be blocked - run `Unblock-File *.dll`

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

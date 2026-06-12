# uefi

Pure-Go read/write access to UEFI variable stores in the OVMF/EDK2 NvVar binary format — no root privileges, no external tools, no CGO.

Targets the non-authenticated NvVar store (`OVMF_VARS.fd`, `QEMU_VARS.fd`). Typical use case: enrolling Secure Boot keys offline before starting a virtual machine.

## Support summary

| Feature | Status | Notes |
|---|---:|---|
| Open / Close | ✅ | Parses NvVar variable store header |
| Format / FormatOVMF | ✅ | Create a fresh, empty NvVar store |
| List | ✅ | Returns all valid (non-deleted) variables |
| Get | ✅ | Lookup by name + GUID |
| Set | ✅ | Create or replace; rewrites store atomically |
| Delete | ✅ | Removes a variable; rewrites store atomically |
| Authenticated writes | ✅ | Builds & signs `EFI_VARIABLE_AUTHENTICATION_2` (EFI_TIME + PKCS#7) for time-based authenticated variables (PK/KEK/db/dbx) |

## Module

```text
github.com/go-filesystems/uefi
```

## API

`Open` returns a `Store` interface — callers never hold a concrete struct pointer.

### Open

```go
func Open(path string) (Store, error)
```

`Store` combines `VariableStore` (UEFI operations) and `filesystem.Filesystem` (generic adapter).

### VariableStore interface

```go
type VariableStore interface {
    Close() error
    List() []Variable
    Get(name string, guid GUID) (Variable, error)
    Set(v Variable) error
    Delete(name string, guid GUID) error
}
```

### Types

```go
type Variable struct {
    Name       string
    GUID       GUID
    Attributes Attributes
    Data       []byte
}

type GUID [16]byte
type Attributes uint32

const (
    AttrNonVolatile                       Attributes = 0x00000001
    AttrBootServiceAccess                 Attributes = 0x00000002
    AttrRuntimeAccess                     Attributes = 0x00000004
    AttrHardwareErrorRecord               Attributes = 0x00000008
    AttrTimeBasedAuthenticatedWriteAccess Attributes = 0x00000020
    AttrAppendWrite                       Attributes = 0x00000040
)
```

## Implements `filesystem.Filesystem`

`Store` (the interface returned by `Open`) satisfies `filesystem.Filesystem` defined in
`github.com/go-filesystems/interface`. Variable names are mapped to paths;
`DefaultNamespaceGUID` (EFI global variable GUID) is used as namespace.

| filesystem.Filesystem method | Behaviour |
|---|---|
| `ReadFile(name)` | Returns `Variable.Data` for the variable named `name` |
| `WriteFile(name, data, _)` | Creates or replaces the variable; `perm` is ignored |
| `DeleteFile(name)` | Deletes the variable |
| `ListDir("/")` | Returns all variables as dir entries |
| `Stat(name)` | Returns `Size = len(Variable.Data)`, mode `0600` |
| `Rename(old, new)` | Copies variable data to `new`, then deletes `old` |
| `MkDir`, `DeleteDir`, `ReadLink` | Return "not supported" error |

```go
import (
    filesystem "github.com/go-filesystems/interface"
    fsuefi     "github.com/go-filesystems/uefi"
)

s, _ := fsuefi.Open("OVMF_VARS.fd")
defer s.Close()

var fs filesystem.Filesystem = s
data, _ := fs.ReadFile("BootOrder")
```

## Secure Boot use case

### Variables and GUIDs

Secure Boot variables live in two namespaces. GUIDs are exported directly by the package:

| Variable | Exported GUID constant | Content |
|---|---|---|
| `PK` | `EFIGlobalVariableGUID` | Platform Key — activates User Mode |
| `KEK` | `EFIGlobalVariableGUID` | Key Exchange Keys |
| `db` | `EFIImageSecurityDatabaseGUID` | Allowed certificates / hashes |
| `dbx` | `EFIImageSecurityDatabaseGUID` | Revoked certificates / hashes |

### Certificate format: `EFI_SIGNATURE_LIST`

Each Secure Boot variable's data is an `EFI_SIGNATURE_LIST`: an EDK2 binary structure
that wraps one or more DER-encoded X.509 certificates. The package exposes
`BuildEFISignatureList` to encode one:

```
Offset  Size  Field
     0    16  SignatureType GUID  ← EFICertX509GUID
    16     4  SignatureListSize
    20     4  SignatureHeaderSize ← always 0 for X.509
    24     4  SignatureSize       ← 16 (owner GUID) + len(certDER)
    28    16  SignatureOwner GUID
    44     n  DER certificate bytes
```

```go
sl := fsuefi.BuildEFISignatureList(fsuefi.EFIGlobalVariableGUID, certDER)
```

### Enrolling keys into `OVMF_VARS.fd`

`EnrollSecureBootKeys` enforces the required order (db → KEK → PK) and handles
`EFI_SIGNATURE_LIST` encoding internally:

```go
store, err := fsuefi.Open("my_vm_vars.fd")
if err != nil { log.Fatal(err) }
defer store.Close()

err = fsuefi.EnrollSecureBootKeys(store, fsuefi.SecureBootKeys{
    PK:  pkDER,  // DER-encoded X.509
    KEK: kekDER,
    DB:  dbDER,
})
```

> **Order**: `db` and `KEK` may be written in any order as long as `PK` is written
> **last**. Once `PK` is present, OVMF leaves *Setup Mode* and activates *User Mode*
> (Secure Boot enforced). Any subsequent change to `PK` or `KEK` must be signed with
> the previous key.

For the complete guide (key generation, disk image creation, QEMU command lines for
x86-64 and arm64): [docs/uefi-secure-boot-qemu.md](../../../docs/uefi-secure-boot-qemu.md).

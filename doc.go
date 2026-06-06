// Package filesystem_uefi provides read/write access to UEFI variable stores
// in the OVMF/EDK2 NvVar binary format (non-authenticated variant).
//
// # Overview
//
// UEFI firmware stores runtime configuration variables (boot order, Secure Boot
// keys, timeout, …) in a binary NvVar store on a dedicated pflash chip or in a
// file (e.g. OVMF_VARS.fd, QEMU_VARS.fd). This package lets you open such a
// file, enumerate, read, write, and delete variables without requiring root
// privileges, external binaries, or CGO.
//
// # Getting started
//
//	import fsuefi "github.com/go-filesystems/uefi/src"
//
//	s, err := fsuefi.Open("OVMF_VARS.fd")
//	if err != nil { log.Fatal(err) }
//	defer s.Close()
//
//	// List all variables
//	for _, v := range s.List() {
//	    fmt.Printf("%s  attrs=%#x  size=%d\n", v.Name, v.Attributes, len(v.Data))
//	}
//
//	// Write a variable
//	err = s.Set(fsuefi.Variable{
//	    Name:       "MyVar",
//	    GUID:       fsuefi.DefaultNamespaceGUID,
//	    Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
//	    Data:       []byte{0x01, 0x02},
//	})
//
// # Interfaces
//
// [Open] returns a [Store] interface — callers never hold a concrete struct
// pointer. Store combines two sub-interfaces:
//
//   - [VariableStore]: UEFI-specific operations (List, Get, Set, Delete).
//   - filesystem.Filesystem (from github.com/go-filesystems/interface): generic
//     filesystem operations (ReadFile, WriteFile, ListDir, Stat, …).  Variable
//     names are used as paths; [DefaultNamespaceGUID] is the namespace.
//
// # Binary format
//
// The store starts with a VARIABLE_STORE_HEADER (28 bytes) followed by
// zero or more VARIABLE_HEADERs (32 bytes each). Variable names are encoded
// as null-terminated UTF-16LE; data payloads follow the name with 4-byte
// alignment. Deleted variables are skipped on read; writes reconstruct the
// full file from the surviving variables.
//
// Supported store signatures: [EFIVariableGUID] (non-authenticated) and
// [EFIAuthenticatedVariableGUID] (authenticated). Authenticated write
// validation (time-based signatures) is not performed.
//
// # Secure Boot use case
//
// See docs/uefi-secure-boot-qemu.md in the parent repository for a step-by-step
// guide to enrolling PK / KEK / db keys into OVMF_VARS.fd and launching a
// Secure Boot VM under QEMU on x86-64 and arm64.
package filesystem_uefi

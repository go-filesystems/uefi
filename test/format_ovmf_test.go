package filesystem_uefi_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// FormatOVMF must produce a varstore whose on-disk layout matches what
// real QEMU OVMF prebuilts write back after their first boot — that's
// the contract we depend on so that variables we pre-stage actually
// survive (rather than getting wiped by OVMF re-formatting an
// incompatible store on the next boot).

// TestFormatOVMF_X86_64_LayoutMatchesOVMF verifies the FV header +
// store header bytes for the x86_64 flavor.
func TestFormatOVMF_X86_64_LayoutMatchesOVMF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ovmf_x86.fd")
	size := int64(fsuefi.VarsSizeX86_64) // 512 KiB
	if _, err := fsuefi.FormatOVMF(path, size, fsuefi.OVMFX86_64); err != nil {
		t.Fatalf("FormatOVMF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// FvHeader.FileSystemGuid at offset 0x10 must be
	// gEfiSystemNvDataFvGuid in mixed-endian on-disk form
	// (canonical FFF12B8D-7696-4C8B-A985-2747075B4F50 → bytes
	// 8d 2b f1 ff 96 76 8b 4c a9 85 27 47 07 5b 4f 50).
	wantFvGUID := []byte{
		0x8d, 0x2b, 0xf1, 0xff,
		0x96, 0x76,
		0x8b, 0x4c,
		0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50,
	}
	if !bytes.Equal(data[0x10:0x20], wantFvGUID) {
		t.Errorf("FvHeader.FileSystemGuid mismatch:\n got %x\nwant %x", data[0x10:0x20], wantFvGUID)
	}
	// FvLength at 0x20 == size.
	if got := binary.LittleEndian.Uint64(data[0x20:]); got != uint64(size) {
		t.Errorf("FvLength = %d, want %d", got, size)
	}
	// "_FVH" signature at 0x28.
	if got := binary.LittleEndian.Uint32(data[0x28:]); got != 0x4856465F {
		t.Errorf("FvHeader.Signature = %#x, want 0x4856465F (\"_FVH\")", got)
	}
	// HeaderLength = 0x48.
	if got := binary.LittleEndian.Uint16(data[0x30:]); got != 0x48 {
		t.Errorf("FvHeader.HeaderLength = %#x, want 0x48", got)
	}
	// FvHeader.Checksum: sum of all u16 words in the 72-byte header
	// must be zero (UEFI PI rule).
	var sum uint16
	for i := 0; i < fsuefi.FvHeaderSize; i += 2 {
		sum += binary.LittleEndian.Uint16(data[i:])
	}
	if sum != 0 {
		t.Errorf("FvHeader 16-bit checksum sum = %#x, want 0", sum)
	}

	// VARIABLE_STORE_HEADER at offset FvHeaderSize (0x48).
	storeOff := fsuefi.FvHeaderSize
	if !bytes.Equal(data[storeOff:storeOff+16], fsuefi.EFIAuthenticatedVariableGUID[:]) {
		t.Errorf("store signature GUID mismatch:\n got %x\nwant %x",
			data[storeOff:storeOff+16], fsuefi.EFIAuthenticatedVariableGUID)
	}
	// Store size = file size - FvHeaderSize.
	wantStoreSize := uint32(size - int64(fsuefi.FvHeaderSize))
	if got := binary.LittleEndian.Uint32(data[storeOff+16:]); got != wantStoreSize {
		t.Errorf("store.Size = %d, want %d", got, wantStoreSize)
	}
	if data[storeOff+20] != fsuefi.StoreFormatted {
		t.Errorf("store.Format = %#x, want %#x", data[storeOff+20], fsuefi.StoreFormatted)
	}
	if data[storeOff+21] != fsuefi.StoreHealthy {
		t.Errorf("store.State = %#x, want %#x", data[storeOff+21], fsuefi.StoreHealthy)
	}
}

// TestFormatOVMF_AArch64_FixedGeometry verifies that the arm64 flavor
// uses ArmVirtPkg's hardcoded geometry (FvLength=0xC0000, store=256
// KiB) regardless of the total file size.
func TestFormatOVMF_AArch64_FixedGeometry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ovmf_arm64.fd")
	size := int64(fsuefi.VarsSizeARM64) // 64 MiB
	if _, err := fsuefi.FormatOVMF(path, size, fsuefi.OVMFAArch64); err != nil {
		t.Fatalf("FormatOVMF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// FvLength fixed at 0xC0000 (768 KiB) per ArmVirtPkg defaults —
	// not the file size.
	if got := binary.LittleEndian.Uint64(data[0x20:]); got != 0xC0000 {
		t.Errorf("aarch64 FvLength = %#x, want 0xC0000", got)
	}
	// Store size = 0x40000 - 72 (256 KiB var region minus FV header).
	wantStoreSize := uint32(0x40000 - fsuefi.FvHeaderSize)
	storeOff := fsuefi.FvHeaderSize
	if got := binary.LittleEndian.Uint32(data[storeOff+16:]); got != wantStoreSize {
		t.Errorf("aarch64 store.Size = %#x, want %#x", got, wantStoreSize)
	}
	// FV header checksum must still sum to zero.
	var sum uint16
	for i := 0; i < fsuefi.FvHeaderSize; i += 2 {
		sum += binary.LittleEndian.Uint16(data[i:])
	}
	if sum != 0 {
		t.Errorf("aarch64 FvHeader checksum sum = %#x, want 0", sum)
	}
}

// TestFormatOVMF_RoundTrip writes a variable with an *unaligned* name
// size (so the data lands at nameOff+nameSize without HEADER_ALIGN
// padding — the OVMF-compatible layout) and confirms Open/Get returns
// the same bytes. This locks in the "no inter-field padding" fix.
func TestFormatOVMF_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flavor fsuefi.OVMFFlavor
		size   int64
	}{
		{"x86_64", fsuefi.OVMFX86_64, fsuefi.VarsSizeX86_64},
		{"aarch64", fsuefi.OVMFAArch64, fsuefi.VarsSizeARM64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ovmf.fd")
			s, err := fsuefi.FormatOVMF(path, tc.size, tc.flavor)
			if err != nil {
				t.Fatalf("FormatOVMF: %v", err)
			}
			// "CloudBootCmdline" → 16 chars + NUL = 34 bytes UTF-16,
			// NOT a multiple of 4. This is precisely the case where
			// the wrong inter-field-padding implementation prepends
			// 2 zero bytes to the read-back data.
			data := []byte("ABCDEFGHIJ")
			v := makeVar("CloudBootCmdline", testGUID, data)
			if err := s.Set(v); err != nil {
				t.Fatalf("Set: %v", err)
			}
			s.Close()

			s2, err := fsuefi.Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer s2.Close()
			got, err := s2.Get("CloudBootCmdline", testGUID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got.Data, data) {
				t.Errorf("Data mismatch:\n got %q\nwant %q", got.Data, data)
			}
			if got.Name != "CloudBootCmdline" {
				t.Errorf("Name = %q, want CloudBootCmdline", got.Name)
			}
		})
	}
}

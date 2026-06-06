package filesystem_uefi_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// TestFormat_CreatesValidStore verifies that Format produces a file with a
// correct VARIABLE_STORE_HEADER and that the returned store is usable.
func TestFormat_CreatesValidStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vars.bin")
	s, err := fsuefi.Format(path, 4096)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer s.Close()

	// File must exist and have the right size.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 4096 {
		t.Fatalf("file size = %d, want 4096", fi.Size())
	}

	// Header: signature GUID at offset 0.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var sig fsuefi.GUID
	copy(sig[:], data[0:16])
	if sig != fsuefi.EFIVariableGUID {
		t.Fatalf("signature GUID mismatch: got %x", sig)
	}
	// Header: size field must equal the image size.
	if sz := binary.LittleEndian.Uint32(data[16:]); sz != 4096 {
		t.Fatalf("header size field = %d, want 4096", sz)
	}
	if data[20] != fsuefi.StoreFormatted {
		t.Fatalf("Format byte = %#x, want %#x", data[20], fsuefi.StoreFormatted)
	}
	if data[21] != fsuefi.StoreHealthy {
		t.Fatalf("State byte = %#x, want %#x", data[21], fsuefi.StoreHealthy)
	}

	// The store must start empty.
	if got := s.List(); len(got) != 0 {
		t.Fatalf("expected empty store, got %d variables", len(got))
	}
}

// TestFormat_StoreIsUsable verifies that a formatted store can hold variables.
func TestFormat_StoreIsUsable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vars.bin")
	s, err := fsuefi.Format(path, 4096)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer s.Close()

	v := makeVar("BootOrder", testGUID, []byte{0x01, 0x00})
	if err := s.Set(v); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("BootOrder", testGUID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Data) != 2 {
		t.Fatalf("data len = %d, want 2", len(got.Data))
	}
}

// TestFormat_SizeTooSmall verifies that Format rejects a size below the minimum.
func TestFormat_SizeTooSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vars.bin")
	if _, err := fsuefi.Format(path, 10); err == nil {
		t.Fatal("expected error for size too small")
	}
}

// TestFormat_WriteFail verifies that Format propagates file write errors.
func TestFormat_WriteFail(t *testing.T) {
	// Use a path inside a non-existent directory to trigger a write error.
	if _, err := fsuefi.Format("/nonexistent/path/vars.bin", 4096); err == nil {
		t.Fatal("expected error for bad path")
	}
}

// TestVarsSizeConstants verifies the exported size constants are non-zero and distinct.
func TestVarsSizeConstants(t *testing.T) {
	if fsuefi.VarsSizeX86_64 <= 0 {
		t.Error("VarsSizeX86_64 must be positive")
	}
	if fsuefi.VarsSizeARM64 <= 0 {
		t.Error("VarsSizeARM64 must be positive")
	}
	if fsuefi.VarsSizeX86_64 == fsuefi.VarsSizeARM64 {
		t.Error("VarsSizeX86_64 and VarsSizeARM64 must be different")
	}
}

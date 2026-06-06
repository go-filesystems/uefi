package filesystem_uefi_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// TestBuildEFISignatureList_Layout verifies the binary layout of the output.
func TestBuildEFISignatureList_Layout(t *testing.T) {
	cert := []byte{0x30, 0x82, 0x01, 0x02} // dummy DER prefix
	owner := fsuefi.EFIGlobalVariableGUID

	sl := fsuefi.BuildEFISignatureList(owner, cert)

	// Minimum length: 28 header + 16 owner GUID + len(cert)
	want := 28 + 16 + len(cert)
	if len(sl) != want {
		t.Fatalf("len = %d, want %d", len(sl), want)
	}

	// SignatureType must be EFICertX509GUID
	if !bytes.Equal(sl[0:16], fsuefi.EFICertX509GUID[:]) {
		t.Fatalf("SignatureType GUID mismatch")
	}

	listSize := binary.LittleEndian.Uint32(sl[16:])
	if int(listSize) != want {
		t.Fatalf("SignatureListSize = %d, want %d", listSize, want)
	}

	headerSize := binary.LittleEndian.Uint32(sl[20:])
	if headerSize != 0 {
		t.Fatalf("SignatureHeaderSize = %d, want 0", headerSize)
	}

	sigSize := binary.LittleEndian.Uint32(sl[24:])
	if int(sigSize) != 16+len(cert) {
		t.Fatalf("SignatureSize = %d, want %d", sigSize, 16+len(cert))
	}

	// Owner GUID at offset 28
	if !bytes.Equal(sl[28:44], owner[:]) {
		t.Fatalf("SignatureOwner GUID mismatch")
	}

	// Certificate bytes at offset 44
	if !bytes.Equal(sl[44:], cert) {
		t.Fatalf("cert payload mismatch: got %v, want %v", sl[44:], cert)
	}
}

// TestBuildEFISignatureList_EmptyCert handles a zero-length certificate.
func TestBuildEFISignatureList_EmptyCert(t *testing.T) {
	sl := fsuefi.BuildEFISignatureList(fsuefi.EFIGlobalVariableGUID, nil)
	if len(sl) != 28+16 {
		t.Fatalf("len = %d, want %d", len(sl), 28+16)
	}
}

// TestEnrollSecureBootKeys_Success enrolls all three keys into an in-memory store
// and verifies db, KEK and PK are present with the expected namespace GUIDs.
func TestEnrollSecureBootKeys_Success(t *testing.T) {
	s, _ := openStoreWith(t, 16*1024)

	keys := fsuefi.SecureBootKeys{
		PK:  []byte{0x01},
		KEK: []byte{0x02},
		DB:  []byte{0x03},
	}
	if err := fsuefi.EnrollSecureBootKeys(s, keys); err != nil {
		t.Fatalf("EnrollSecureBootKeys: %v", err)
	}

	// db must be in EFIImageSecurityDatabaseGUID namespace
	db, err := s.Get("db", fsuefi.EFIImageSecurityDatabaseGUID)
	if err != nil {
		t.Fatalf("Get db: %v", err)
	}
	if len(db.Data) == 0 {
		t.Fatal("db data is empty")
	}

	// KEK must be in EFIGlobalVariableGUID namespace
	if _, err := s.Get("KEK", fsuefi.EFIGlobalVariableGUID); err != nil {
		t.Fatalf("Get KEK: %v", err)
	}

	// PK must be in EFIGlobalVariableGUID namespace
	if _, err := s.Get("PK", fsuefi.EFIGlobalVariableGUID); err != nil {
		t.Fatalf("Get PK: %v", err)
	}
}

// TestEnrollSecureBootKeys_StoreError verifies that an error from the store
// during db enrollment is propagated.
func TestEnrollSecureBootKeys_StoreError(t *testing.T) {
	s, path := openStoreWith(t, 16*1024)
	// Make the backing file read-only so Set → flush fails.
	mustChmod(t, path, 0o444)

	err := fsuefi.EnrollSecureBootKeys(s, fsuefi.SecureBootKeys{
		PK: []byte{0x01}, KEK: []byte{0x02}, DB: []byte{0x03},
	})
	if err == nil {
		t.Fatal("expected error with read-only store, got nil")
	}
}

// TestSecureBootGUIDs verifies that the exported Secure Boot GUIDs are non-zero
// and distinct from each other.
func TestSecureBootGUIDs(t *testing.T) {
	var zero fsuefi.GUID
	guids := []struct {
		name string
		g    fsuefi.GUID
	}{
		{"EFIGlobalVariableGUID", fsuefi.EFIGlobalVariableGUID},
		{"EFIImageSecurityDatabaseGUID", fsuefi.EFIImageSecurityDatabaseGUID},
		{"EFICertX509GUID", fsuefi.EFICertX509GUID},
	}
	for _, g := range guids {
		if g.g == zero {
			t.Errorf("%s is zero", g.name)
		}
	}
	if fsuefi.EFIGlobalVariableGUID == fsuefi.EFIImageSecurityDatabaseGUID {
		t.Error("EFIGlobalVariableGUID == EFIImageSecurityDatabaseGUID")
	}
	if fsuefi.EFIGlobalVariableGUID == fsuefi.EFICertX509GUID {
		t.Error("EFIGlobalVariableGUID == EFICertX509GUID")
	}
}

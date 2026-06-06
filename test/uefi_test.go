package filesystem_uefi_test

import (
	"encoding/binary"
	"os"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// TestOpen_ValidStore verifies that a well-formed store opens without error.
func TestOpen_ValidStore(t *testing.T) {
	path := writeTempStore(t, buildEmptyStore(4096))
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
}

// TestOpen_InvalidSignature rejects a store with a wrong GUID.
func TestOpen_InvalidSignature(t *testing.T) {
	data := make([]byte, 4096)
	for i := fsuefi.StoreHeaderSize; i < 4096; i++ {
		data[i] = 0xFF
	}
	binary.LittleEndian.PutUint32(data[16:], 4096)
	data[20] = fsuefi.StoreFormatted
	data[21] = fsuefi.StoreHealthy
	// Signature bytes are all zero — should fail.
	path := writeTempStore(t, data)
	if _, err := fsuefi.Open(path); err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
}

// TestOpen_TooSmall rejects a file smaller than the header.
func TestOpen_TooSmall(t *testing.T) {
	path := writeTempStore(t, []byte{0x00, 0x01, 0x02})
	if _, err := fsuefi.Open(path); err == nil {
		t.Fatal("expected error for too-small file")
	}
}

// TestList returns all valid variables.
func TestList(t *testing.T) {
	v1 := makeVar("BootOrder", testGUID, []byte{0x00})
	v2 := makeVar("Timeout", testGUID, []byte{0x05, 0x00})
	s, _ := openStoreWith(t, 4096, v1, v2)
	if list := s.List(); len(list) != 2 {
		t.Fatalf("List: want 2 vars, got %d", len(list))
	}
}

// TestGet_Found retrieves an existing variable.
func TestGet_Found(t *testing.T) {
	v := makeVar("BootOrder", testGUID, []byte{0xAA, 0xBB})
	s, _ := openStoreWith(t, 4096, v)
	got, err := s.Get("BootOrder", testGUID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "BootOrder" || len(got.Data) != 2 || got.Data[0] != 0xAA {
		t.Fatalf("Get returned unexpected variable: %+v", got)
	}
}

// TestGet_NotFound returns an error for a missing variable.
func TestGet_NotFound(t *testing.T) {
	s, _ := openStoreWith(t, 4096)
	if _, err := s.Get("DoesNotExist", testGUID); err == nil {
		t.Fatal("expected error for missing variable, got nil")
	}
}

// TestSet_NewVariable adds a variable and persists it.
func TestSet_NewVariable(t *testing.T) {
	s, path := openStoreWith(t, 4096)
	v := makeVar("NewVar", testGUID, []byte{0xDE, 0xAD})
	if err := s.Set(v); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Re-open: %v", err)
	}
	got, err := s2.Get("NewVar", testGUID)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if len(got.Data) != 2 || got.Data[0] != 0xDE {
		t.Fatalf("unexpected data: %v", got.Data)
	}
}

// TestSet_UpdateExisting replaces an existing variable.
func TestSet_UpdateExisting(t *testing.T) {
	v := makeVar("BootOrder", testGUID, []byte{0x01})
	s, _ := openStoreWith(t, 4096, v)
	updated := makeVar("BootOrder", testGUID, []byte{0x02, 0x03})
	if err := s.Set(updated); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	got, err := s.Get("BootOrder", testGUID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Data) != 2 || got.Data[0] != 0x02 {
		t.Fatalf("Update did not persist: %v", got.Data)
	}
}

// TestDelete removes a variable and verifies it is gone.
func TestDelete(t *testing.T) {
	v := makeVar("BootOrder", testGUID, []byte{0x01})
	s, _ := openStoreWith(t, 4096, v)
	if err := s.Delete("BootOrder", testGUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("BootOrder", testGUID); err == nil {
		t.Fatal("variable still present after Delete")
	}
}

// TestDelete_NotFound returns error when deleting a non-existent variable.
func TestDelete_NotFound(t *testing.T) {
	s, _ := openStoreWith(t, 4096)
	if err := s.Delete("Ghost", testGUID); err == nil {
		t.Fatal("expected error deleting non-existent variable")
	}
}

// TestEmptyStore opens an empty (no variables) store successfully.
func TestEmptyStore(t *testing.T) {
	s, _ := openStoreWith(t, 4096)
	if list := s.List(); len(list) != 0 {
		t.Fatalf("expected 0 vars in empty store, got %d", len(list))
	}
}

// TestStore_OverflowRejected verifies that setting too many variables returns an error.
func TestStore_OverflowRejected(t *testing.T) {
	path := writeTempStore(t, buildEmptyStore(uint32(fsuefi.StoreHeaderSize+8)))
	s, _ := fsuefi.Open(path)
	bigVar := makeVar("BigVariable", testGUID, make([]byte, 100))
	if err := s.Set(bigVar); err == nil {
		t.Fatal("expected overflow error, got nil")
	}
}

// TestAuthenticatedStoreSignature accepts the authenticated store GUID.
func TestAuthenticatedStoreSignature(t *testing.T) {
	buf := make([]byte, 4096)
	for i := fsuefi.StoreHeaderSize; i < 4096; i++ {
		buf[i] = 0xFF
	}
	copy(buf[0:16], fsuefi.EFIAuthenticatedVariableGUID[:])
	binary.LittleEndian.PutUint32(buf[16:], 4096)
	buf[20] = fsuefi.StoreFormatted
	buf[21] = fsuefi.StoreHealthy
	path := writeTempStore(t, buf)
	if _, err := fsuefi.Open(path); err != nil {
		t.Fatalf("Open authenticated store: %v", err)
	}
}

// TestOpen_NotFormatted rejects a store with Format != 0x5A.
func TestOpen_NotFormatted(t *testing.T) {
	buf := buildEmptyStore(4096)
	buf[20] = 0x00
	path := writeTempStore(t, buf)
	if _, err := fsuefi.Open(path); err == nil {
		t.Fatal("expected error for not-formatted store")
	}
}

// TestOpen_NotHealthy rejects a store with State != 0xFE.
func TestOpen_NotHealthy(t *testing.T) {
	buf := buildEmptyStore(4096)
	buf[21] = 0x00
	path := writeTempStore(t, buf)
	if _, err := fsuefi.Open(path); err == nil {
		t.Fatal("expected error for not-healthy store")
	}
}

// TestDecodeUTF16LE_OddLength rejects an odd-length buffer.
func TestDecodeUTF16LE_OddLength(t *testing.T) {
	if _, err := fsuefi.DecodeUTF16LE([]byte{0x48}); err == nil {
		t.Fatal("expected error for odd-length UTF-16LE buffer")
	}
}

// TestParseVariables_StoreSizeTruncation handles data shorter than storeSize field says.
func TestParseVariables_StoreSizeTruncation(t *testing.T) {
	buf := buildEmptyStore(4096)
	path := writeTempStore(t, buf[:512])
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open with truncated data: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected 0 vars in truncated store")
	}
}

// TestParseOneVariable_ExtendsBeyondStore skips a variable that claims to extend past end.
func TestParseOneVariable_ExtendsBeyondStore(t *testing.T) {
	buf := buildEmptyStore(4096)
	off := fsuefi.StoreHeaderSize
	binary.LittleEndian.PutUint16(buf[off:], fsuefi.VariableData)
	buf[off+2] = fsuefi.VarAdded
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(fsuefi.AttrNonVolatile))
	binary.LittleEndian.PutUint32(buf[off+8:], 9999) // nameSize way too large
	binary.LittleEndian.PutUint32(buf[off+12:], 0)
	copy(buf[off+16:], testGUID[:])
	path := writeTempStore(t, buf)
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected 0 valid vars, got %d", len(s.List()))
	}
}

// TestFlush_ReadError exercises the flush read-original-file error path.
func TestFlush_ReadError(t *testing.T) {
	s, path := openStoreWith(t, 4096)
	os.Remove(path)
	v := makeVar("X", testGUID, []byte{0x01})
	if err := s.Set(v); err == nil {
		t.Fatal("expected error when file is gone")
	}
}

// TestUTF16RoundTrip verifies name encoding/decoding is lossless.
func TestUTF16RoundTrip(t *testing.T) {
	names := []string{"Boot0001", "PlatformLang", "BootOrder", "Timeout", "Hello-世界"}
	for _, name := range names {
		enc := fsuefi.EncodeUTF16LE(name)
		got, err := fsuefi.DecodeUTF16LE(enc)
		if err != nil {
			t.Errorf("decode %q: %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("round-trip %q -> %q", name, got)
		}
	}
}

// TestOpen_FileNotFound exercises the os.ReadFile error path in Open.
func TestOpen_FileNotFound(t *testing.T) {
	if _, err := fsuefi.Open("/no/such/path/vars.bin"); err == nil {
		t.Fatal("expected error opening non-existent file, got nil")
	}
}

// TestSet_PreservesOtherVars verifies that Set keeps unrelated variables.
func TestSet_PreservesOtherVars(t *testing.T) {
	v1 := makeVar("BootOrder", testGUID, []byte{0x01})
	v2 := makeVar("Timeout", testGUID, []byte{0x05, 0x00})
	s, _ := openStoreWith(t, 4096, v1, v2)
	updated := makeVar("BootOrder", testGUID, []byte{0x02})
	if err := s.Set(updated); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := s.Get("Timeout", testGUID); err != nil {
		t.Fatalf("Timeout variable lost after Set: %v", err)
	}
}

// TestDelete_PreservesOtherVars verifies that Delete keeps unrelated variables.
func TestDelete_PreservesOtherVars(t *testing.T) {
	v1 := makeVar("BootOrder", testGUID, []byte{0x01})
	v2 := makeVar("Timeout", testGUID, []byte{0x05, 0x00})
	s, _ := openStoreWith(t, 4096, v1, v2)
	if err := s.Delete("BootOrder", testGUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("Timeout", testGUID); err != nil {
		t.Fatalf("Timeout variable lost after Delete: %v", err)
	}
}

// TestFlush_FileTooSmall exercises the len(orig) < StoreHeaderSize branch in flush.
func TestFlush_FileTooSmall(t *testing.T) {
	s, path := openStoreWith(t, 4096)
	if err := os.WriteFile(path, make([]byte, 10), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	v := makeVar("X", testGUID, []byte{0x01})
	if err := s.Set(v); err == nil {
		t.Fatal("expected error when backing file is too small")
	}
}

// TestParseOneVariable_DeletedState verifies that a deleted variable is skipped.
func TestParseOneVariable_DeletedState(t *testing.T) {
	buf := buildEmptyStore(4096)
	off := fsuefi.StoreHeaderSize
	binary.LittleEndian.PutUint16(buf[off:], fsuefi.VariableData)
	buf[off+2] = fsuefi.VarDeleted
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(fsuefi.AttrNonVolatile))
	nameBuf := fsuefi.EncodeUTF16LE("Ghost")
	binary.LittleEndian.PutUint32(buf[off+8:], uint32(len(nameBuf)))
	binary.LittleEndian.PutUint32(buf[off+12:], 0)
	copy(buf[off+16:], testGUID[:])
	copy(buf[off+fsuefi.VarHeaderSize:], nameBuf)
	path := writeTempStore(t, buf)
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected deleted variable to be skipped, got %d vars", len(s.List()))
	}
}

// TestParseOneVariable_OddLengthName verifies that a variable with an odd-length name is skipped.
func TestParseOneVariable_OddLengthName(t *testing.T) {
	buf := buildEmptyStore(4096)
	off := fsuefi.StoreHeaderSize
	binary.LittleEndian.PutUint16(buf[off:], fsuefi.VariableData)
	buf[off+2] = fsuefi.VarAdded
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(fsuefi.AttrNonVolatile))
	binary.LittleEndian.PutUint32(buf[off+8:], 3) // odd byte count → DecodeUTF16LE fails
	binary.LittleEndian.PutUint32(buf[off+12:], 0)
	copy(buf[off+16:], testGUID[:])
	path := writeTempStore(t, buf)
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected odd-name variable to be skipped, got %d vars", len(s.List()))
	}
}

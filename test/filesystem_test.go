package filesystem_uefi_test

import (
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// TestFilesystem_ReadWriteDelete exercises the filesystem.Filesystem adapter.
func TestFilesystem_ReadWriteDelete(t *testing.T) {
	s, _ := openStoreWith(t, 4096)

	data := []byte{0xAA, 0xBB, 0xCC}
	if err := s.WriteFile("MyVar", data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := s.ReadFile("MyVar")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 3 || got[0] != 0xAA {
		t.Fatalf("ReadFile returned unexpected data: %v", got)
	}

	if err := s.DeleteFile("MyVar"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	if _, err := s.ReadFile("MyVar"); err == nil {
		t.Fatal("ReadFile after delete: expected error, got nil")
	}
}

// TestFilesystem_ReadFile_NotFound verifies the error path.
func TestFilesystem_ReadFile_NotFound(t *testing.T) {
	s, _ := openStoreWith(t, 4096)
	if _, err := s.ReadFile("Ghost"); err == nil {
		t.Fatal("expected error for missing variable")
	}
}

// TestFilesystem_ListDir lists all variables at "/" and errors on sub-paths.
func TestFilesystem_ListDir(t *testing.T) {
	v1 := makeVar("Alpha", testGUID, []byte{0x01})
	v2 := makeVar("Beta", testGUID, []byte{0x02})
	s, _ := openStoreWith(t, 4096, v1, v2)

	entries, err := s.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir /: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ListDir /: want 2 entries, got %d", len(entries))
	}

	entries2, err := s.ListDir("")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries2) != 2 {
		t.Fatalf("ListDir empty: want 2 entries, got %d", len(entries2))
	}

	if _, err := s.ListDir("/some/sub"); err == nil {
		t.Fatal("expected error for sub-path, got nil")
	}
}

// TestFilesystem_Stat returns size of variable data.
func TestFilesystem_Stat(t *testing.T) {
	v := makeVar("SizeTest", testGUID, []byte{0x01, 0x02, 0x03, 0x04})
	s, _ := openStoreWith(t, 4096, v)

	st, err := s.Stat("SizeTest")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Size() != 4 {
		t.Fatalf("Stat: want size 4, got %d", st.Size())
	}
}

// TestFilesystem_Stat_NotFound verifies the error path.
func TestFilesystem_Stat_NotFound(t *testing.T) {
	s, _ := openStoreWith(t, 4096)
	if _, err := s.Stat("Ghost"); err == nil {
		t.Fatal("expected error for missing variable")
	}
}

// TestFilesystem_UnsupportedOps verifies that unsupported methods return errors.
func TestFilesystem_UnsupportedOps(t *testing.T) {
	s, _ := openStoreWith(t, 4096)

	if _, err := s.ReadLink("x"); err == nil {
		t.Fatal("ReadLink: expected error")
	}
	if err := s.MkDir("x", 0o755); err == nil {
		t.Fatal("MkDir: expected error")
	}
	if err := s.DeleteDir("x"); err == nil {
		t.Fatal("DeleteDir: expected error")
	}
	// Rename on a non-existent source must fail.
	if err := s.Rename("a", "b"); err == nil {
		t.Fatal("Rename missing source: expected error")
	}
}

// TestFilesystem_Rename_Success renames a variable and verifies the old name
// is gone and the new name carries identical data.
func TestFilesystem_Rename_Success(t *testing.T) {
	v := makeVar("OldName", testGUID, []byte{0x01, 0x02})
	s, _ := openStoreWith(t, 4096, v)

	if err := s.Rename("OldName", "NewName"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := s.ReadFile("OldName"); err == nil {
		t.Fatal("old name still accessible after rename")
	}
	got, err := s.ReadFile("NewName")
	if err != nil {
		t.Fatalf("ReadFile new name: %v", err)
	}
	if len(got) != 2 || got[0] != 0x01 || got[1] != 0x02 {
		t.Fatalf("unexpected data after rename: %v", got)
	}
}

// TestFilesystem_Rename_WriteFail expects an error when the backing file is
// read-only and the copy step (Set) cannot flush to disk.
func TestFilesystem_Rename_WriteFail(t *testing.T) {
	v := makeVar("OldName", testGUID, []byte{0x01})
	s, path := openStoreWith(t, 4096, v)

	mustChmod(t, path, 0o444)
	if err := s.Rename("OldName", "NewName"); err == nil {
		t.Fatal("expected error when backing file is read-only")
	}
}

// TestFilesystem_DefaultNamespaceGUID verifies DefaultNamespaceGUID is exported.
func TestFilesystem_DefaultNamespaceGUID(t *testing.T) {
	var zero fsuefi.GUID
	if fsuefi.DefaultNamespaceGUID == zero {
		t.Fatal("DefaultNamespaceGUID should not be zero")
	}
}

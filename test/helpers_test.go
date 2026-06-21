package filesystem_uefi_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// buildEmptyStore creates valid UEFI variable store bytes with no variables.
// Used by tests that need to craft raw bytes before writing (e.g. to test
// invalid header fields). For valid stores, prefer openStoreWith or Format.
func buildEmptyStore(storeSize uint32) []byte {
	buf := make([]byte, storeSize)
	for i := fsuefi.StoreHeaderSize; i < int(storeSize); i++ {
		buf[i] = 0xFF
	}
	copy(buf[0:16], fsuefi.EFIVariableGUID[:])
	binary.LittleEndian.PutUint32(buf[16:], storeSize)
	buf[20] = fsuefi.StoreFormatted
	buf[21] = fsuefi.StoreHealthy
	return buf
}

// writeTempStore writes raw bytes to a temp file and returns its path.
func writeTempStore(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vars.bin")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp store: %v", err)
	}
	return path
}

// openStoreWith creates a temp store pre-populated with vars and returns the open store and its path.
func openStoreWith(t *testing.T, storeSize uint32, vars ...fsuefi.Variable) (fsuefi.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vars.bin")
	s, err := fsuefi.Format(path, int64(storeSize))
	if err != nil {
		t.Fatalf("openStoreWith: Format: %v", err)
	}
	for _, v := range vars {
		if err := s.Set(v); err != nil {
			t.Fatalf("openStoreWith: Set %q: %v", v.Name, err)
		}
	}
	return s, path
}

// skipIfRoot skips a test that relies on filesystem permission bits to force an
// I/O failure (e.g. chmod 0o444 then expecting a write to fail). The emulated CI
// jobs run as uid 0 inside docker/QEMU, where permission bits are ignored — root
// writes a 0o444 file regardless — so the expected error never occurs. The
// native (non-root) jobs still exercise these paths.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-failure test: running as root, where chmod 0o444 does not block writes")
	}
}

// mustChmod changes file permissions and registers a cleanup to restore 0o644.
func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o644) }) //nolint:errcheck
}

func makeVar(name string, guid fsuefi.GUID, data []byte) fsuefi.Variable {
	return fsuefi.Variable{
		Name:       name,
		GUID:       guid,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       data,
	}
}

// testGUID equals EFIGlobalVariableGUID / DefaultNamespaceGUID.
var testGUID = fsuefi.GUID{
	0x61, 0xdf, 0xe4, 0x8b,
	0xca, 0x93,
	0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
}

package filesystem_uefi_test

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// failingStore is a VariableStore whose Set always fails. It backs the
// WriteAuthenticatedVariable / AddBootEntry error-branch tests, which need a
// store that rejects writes without touching a real file.
type failingStore struct {
	list []fsuefi.Variable
}

func (f *failingStore) Close() error                     { return nil }
func (f *failingStore) List() []fsuefi.Variable          { return f.list }
func (f *failingStore) Set(fsuefi.Variable) error        { return errors.New("failingStore: Set refused") }
func (f *failingStore) Delete(string, fsuefi.GUID) error { return errors.New("failingStore: Delete refused") }
func (f *failingStore) Get(string, fsuefi.GUID) (fsuefi.Variable, error) {
	return fsuefi.Variable{}, errors.New("failingStore: not found")
}

// ---- ParseAuthentication2 header-field rejections ----

// corruptAuth builds a valid EFI_VARIABLE_AUTHENTICATION_2 descriptor and then
// mutates one byte so ParseAuthentication2 rejects it.
func buildValidAuth(t *testing.T) []byte {
	t.Helper()
	signer := makeTestSigner(t)
	desc, err := fsuefi.BuildAuthentication2("PK", testGUID,
		fsuefi.AttrTimeBasedAuthenticatedWriteAccess, []byte("payload"), fsuefi.EFITime{Year: 2026}, signer)
	if err != nil {
		t.Fatalf("BuildAuthentication2: %v", err)
	}
	return desc
}

func TestParseAuthentication2_BadRevision(t *testing.T) {
	desc := buildValidAuth(t)
	// wRevision lives at efiTimeSize + 4 (16 + 4 = 20); clobber it.
	binary.LittleEndian.PutUint16(desc[16+4:], 0x0100)
	if _, err := fsuefi.ParseAuthentication2(desc); err == nil ||
		!strings.Contains(err.Error(), "wRevision") {
		t.Fatalf("expected wRevision error, got %v", err)
	}
}

func TestParseAuthentication2_BadCertType(t *testing.T) {
	desc := buildValidAuth(t)
	// wCertificateType lives at efiTimeSize + 6 (16 + 6 = 22); clobber it.
	binary.LittleEndian.PutUint16(desc[16+6:], 0x1234)
	if _, err := fsuefi.ParseAuthentication2(desc); err == nil ||
		!strings.Contains(err.Error(), "wCertificateType") {
		t.Fatalf("expected wCertificateType error, got %v", err)
	}
}

func TestParseAuthentication2_BadDwLength(t *testing.T) {
	desc := buildValidAuth(t)
	// dwLength lives at the start of the WIN_CERTIFICATE (offset efiTimeSize+0);
	// set it past the end of the certificate so the length check rejects it,
	// leaving wRevision/wCertificateType valid.
	binary.LittleEndian.PutUint32(desc[16:], 0xFFFFFFFF)
	if _, err := fsuefi.ParseAuthentication2(desc); err == nil ||
		!strings.Contains(err.Error(), "dwLength") {
		t.Fatalf("expected dwLength error, got %v", err)
	}
}

// ---- WriteAuthenticatedVariable branches ----

// TestWriteAuthenticatedVariable_DefaultAttrs exercises the attrs==0 default
// branch (which fills in the standard Secure Boot attribute set).
func TestWriteAuthenticatedVariable_DefaultAttrs(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	signer := makeTestSigner(t)
	if err := fsuefi.WriteAuthenticatedVariable(s, "PK", testGUID, 0,
		[]byte("cert-data"), fsuefi.EFITime{Year: 2026}, signer); err != nil {
		t.Fatalf("WriteAuthenticatedVariable(attrs=0): %v", err)
	}
	got, err := s.Get("PK", testGUID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Attributes&fsuefi.AttrTimeBasedAuthenticatedWriteAccess == 0 {
		t.Fatalf("default attrs missing time-based-auth flag: %#x", got.Attributes)
	}
}

// TestWriteAuthenticatedVariable_BuildError forces BuildAuthentication2 to fail
// (a nil signer key), covering the build-error return.
func TestWriteAuthenticatedVariable_BuildError(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	err := fsuefi.WriteAuthenticatedVariable(s, "PK", testGUID,
		fsuefi.AttrTimeBasedAuthenticatedWriteAccess, []byte("d"), fsuefi.EFITime{}, fsuefi.AuthSigner{})
	if err == nil {
		t.Fatal("expected error from BuildAuthentication2 with empty signer")
	}
}

// TestWriteAuthenticatedVariable_SetError covers the store.Set failure branch.
func TestWriteAuthenticatedVariable_SetError(t *testing.T) {
	signer := makeTestSigner(t)
	err := fsuefi.WriteAuthenticatedVariable(&failingStore{}, "PK", testGUID,
		fsuefi.AttrTimeBasedAuthenticatedWriteAccess, []byte("d"), fsuefi.EFITime{Year: 2026}, signer)
	if err == nil || !strings.Contains(err.Error(), "WriteAuthenticatedVariable") {
		t.Fatalf("expected wrapped Set error, got %v", err)
	}
}

// ---- LoadOption.Marshal device-path overflow ----

// TestLoadOptionMarshal_DevicePathOverflow builds a load option whose marshaled
// device path exceeds the uint16 FilePathListLength ceiling.
func TestLoadOptionMarshal_DevicePathOverflow(t *testing.T) {
	big := make([]byte, 0x8000)
	lo := &fsuefi.LoadOption{
		Description: "big",
		DevicePath: []fsuefi.DevicePathNode{
			{Type: 0x01, SubType: 0x01, Data: big},
			{Type: 0x01, SubType: 0x01, Data: big},
			{Type: 0x01, SubType: 0x01, Data: big},
		},
	}
	if _, err := lo.Marshal(); err == nil || !strings.Contains(err.Error(), "overflows uint16") {
		t.Fatalf("expected uint16 overflow error, got %v", err)
	}
}

// ---- AddBootEntry / lowestFreeBootNum exhaustion ----

// fullBootStore reports every Boot#### slot as taken so lowestFreeBootNum
// returns ok=false and AddBootEntry surfaces "no free Boot#### slot".
type fullBootStore struct{ vars []fsuefi.Variable }

func (f *fullBootStore) Close() error                     { return nil }
func (f *fullBootStore) List() []fsuefi.Variable          { return f.vars }
func (f *fullBootStore) Set(fsuefi.Variable) error        { return nil }
func (f *fullBootStore) Delete(string, fsuefi.GUID) error { return nil }
func (f *fullBootStore) Get(string, fsuefi.GUID) (fsuefi.Variable, error) {
	return fsuefi.Variable{}, errors.New("not found")
}

func TestAddBootEntry_NoFreeSlot(t *testing.T) {
	vars := make([]fsuefi.Variable, 0, 0x10000)
	for i := 0; i < 0x10000; i++ {
		vars = append(vars, fsuefi.Variable{
			Name: bootName(i),
			GUID: fsuefi.EFIGlobalVariableGUID,
		})
	}
	store := &fullBootStore{vars: vars}
	_, err := fsuefi.AddBootEntry(store, &fsuefi.LoadOption{Description: "x"})
	if err == nil || !strings.Contains(err.Error(), "no free Boot#### slot") {
		t.Fatalf("expected no-free-slot error, got %v", err)
	}
}

func bootName(n int) string {
	const hex = "0123456789ABCDEF"
	return "Boot" +
		string([]byte{
			hex[(n>>12)&0xF], hex[(n>>8)&0xF], hex[(n>>4)&0xF], hex[n&0xF],
		})
}

// ---- FormatOVMF error + geometry branches ----

func TestFormatOVMF_TooSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vars.fd")
	if _, err := fsuefi.FormatOVMF(path, 16, fsuefi.OVMFX86_64); err == nil ||
		!strings.Contains(err.Error(), "too small") {
		t.Fatalf("expected too-small error, got %v", err)
	}
}

func TestFormatOVMF_WriteError(t *testing.T) {
	// A path under a non-existent directory makes os.WriteFile fail regardless
	// of uid, so this works under both native and root CI jobs.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "vars.fd")
	if _, err := fsuefi.FormatOVMF(bad, 0x20000, fsuefi.OVMFX86_64); err == nil ||
		!strings.Contains(err.Error(), "FormatOVMF") {
		t.Fatalf("expected write error, got %v", err)
	}
}

// TestOpen_SkipsOddLengthName crafts a raw non-auth store whose single variable
// record carries an odd NameSize. parseOneVariable decodes the name with
// DecodeUTF16LE, which rejects an odd-length buffer, so the record is skipped
// (returned as nil) rather than surfaced. Covers the name-decode skip branch.
func TestOpen_SkipsOddLengthName(t *testing.T) {
	const storeSize = 0x1000
	buf := buildEmptyStore(storeSize)
	// Variable region starts right after the 28-byte store header.
	off := int(fsuefi.StoreHeaderSize)
	rec := make([]byte, fsuefi.VarHeaderSize)
	binary.LittleEndian.PutUint16(rec[0:], fsuefi.VariableData) // StartId
	rec[2] = fsuefi.VarAdded                                    // State
	binary.LittleEndian.PutUint32(rec[4:], 0)                   // Attributes
	binary.LittleEndian.PutUint32(rec[8:], 3)                   // NameSize = odd
	binary.LittleEndian.PutUint32(rec[12:], 0)                  // DataSize = 0
	copy(rec[16:32], testGUID[:])                               // VendorGuid
	copy(buf[off:], rec)
	// 3 name bytes follow the header; leave them as-is (already 0xFF fill).
	path := writeTempStore(t, buf)
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if got := len(s.List()); got != 0 {
		t.Fatalf("expected odd-name variable to be skipped, got %d vars", got)
	}
}

// TestFormatOVMF_NonBlockAlignedSizes exercises the makeEmptyOVMFStore fallback
// where sizeBytes is not a whole multiple of the FV block length (numBlocks=1,
// blockLen=sizeBytes) for both flavors.
func TestFormatOVMF_NonBlockAlignedSizes(t *testing.T) {
	cases := []struct {
		name   string
		flavor fsuefi.OVMFFlavor
		size   int64
	}{
		// X86_64 block length is 0x1000; add 1 to break divisibility.
		{"x86_64", fsuefi.OVMFX86_64, 0x20000 + 1},
		// AArch64 block length is 0x40000; its min FV is 0xC0000, add 1.
		{"aarch64", fsuefi.OVMFAArch64, 0xC0000 + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vars.fd")
			s, err := fsuefi.FormatOVMF(path, tc.size, tc.flavor)
			if err != nil {
				t.Fatalf("FormatOVMF(%s, %d): %v", tc.name, tc.size, err)
			}
			s.Close()
		})
	}
}

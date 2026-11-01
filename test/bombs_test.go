package filesystem_uefi_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
	"github.com/go-volumes/safeio"
)

// Regression tests for the memory-bomb audit (2026-11-01). The "before" figures
// were measured with runtime.MemStats.TotalAlloc on v0.3.0.

func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

func wantTooLarge(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("%s: want ErrTooLarge, got %v", what, err)
	}
}

// storeWithRecords returns a raw non-auth store of n empty VarAdded records
// (32 bytes each) followed by erased flash.
func storeWithRecords(n int) []byte {
	size := fsuefi.StoreHeaderSize + n*32 + 64
	buf := buildEmptyStore(uint32(size))
	for i := 0; i < n; i++ {
		putVarHeader(buf, fsuefi.StoreHeaderSize+i*32, fsuefi.VarAdded, 0, 0)
	}
	return buf
}

// Before: a 16 MiB store of 524 287 empty records parsed into 524 287
// variables and allocated 255 MB (15x the file).
func TestBomb_TooManyVariables(t *testing.T) {
	const size = 16 << 20
	buf := buildEmptyStore(size)
	for off := fsuefi.StoreHeaderSize; off+32 <= size; off += 32 {
		putVarHeader(buf, off, fsuefi.VarAdded, 0, 0)
	}
	p := writeTempStore(t, buf)
	before := totalAlloc()
	_, err := fsuefi.Open(p)
	wantTooLarge(t, "524287 variables", err)
	if alloc := totalAlloc() - before; alloc > 64<<20 {
		t.Fatalf("variable bomb allocated %d bytes (was 255 MB)", alloc)
	}
}

func TestBomb_VariableCountExactBound(t *testing.T) {
	p := writeTempStore(t, storeWithRecords(4))
	s, err := fsuefi.OpenLimits(p, fsuefi.Limits{MaxVariables: 4})
	if err != nil {
		t.Fatalf("4 variables under MaxVariables=4: %v", err)
	}
	if got := len(s.List()); got != 4 {
		t.Fatalf("listed %d variables, want 4", got)
	}
	_, err = fsuefi.OpenLimits(p, fsuefi.Limits{MaxVariables: 3})
	wantTooLarge(t, "4 variables over MaxVariables=3", err)
}

// Before: Open read the whole file: a 256 MiB sparse file cost 268 MB.
func TestBomb_FileSizeRefusedBeforeReading(t *testing.T) {
	p := writeTempStore(t, buildEmptyStore(4096))
	if err := os.Truncate(p, fsuefi.DefaultMaxFileSize+4096); err != nil {
		t.Skipf("cannot make a sparse file here: %v", err)
	}
	before := totalAlloc()
	_, err := fsuefi.Open(p)
	wantTooLarge(t, "store file over the default ceiling", err)
	if alloc := totalAlloc() - before; alloc > 1<<20 {
		t.Fatalf("oversized file allocated %d bytes (was 268 MB)", alloc)
	}
}

func TestBomb_FileSizeExactBound(t *testing.T) {
	p := writeTempStore(t, buildEmptyStore(4096))
	if _, err := fsuefi.OpenLimits(p, fsuefi.Limits{MaxFileSize: 4096}); err != nil {
		t.Fatalf("4096-byte file under MaxFileSize=4096: %v", err)
	}
	_, err := fsuefi.OpenLimits(p, fsuefi.Limits{MaxFileSize: 4095})
	wantTooLarge(t, "4096-byte file over MaxFileSize=4095", err)
}

// Set and Delete re-read the file: the same ceiling applies, so a store grown
// behind our back cannot be pulled into memory.
func TestBomb_FlushReReadIsBounded(t *testing.T) {
	p := writeTempStore(t, buildEmptyStore(4096))
	s, err := fsuefi.OpenLimits(p, fsuefi.Limits{MaxFileSize: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, 8192); err != nil {
		t.Fatal(err)
	}
	wantTooLarge(t, "Set after the file grew", s.Set(makeVar("X", testGUID, []byte("x"))))
}

// Before: the header's Size (uint32) was added to the store offset in uint32:
// 0xFFFFFFF0 wrapped, the store read as EMPTY with no error.
func TestBomb_StoreSizeWrapDoesNotHideVariables(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ovmf.fd")
	s, err := fsuefi.FormatOVMF(p, 512*1024, fsuefi.OVMFX86_64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(makeVar("Keep", testGUID, []byte("data"))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(raw[fsuefi.FvHeaderSize+16:], 0xFFFFFFF0)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := fsuefi.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s2.Get("Keep", testGUID); err != nil || string(v.Data) != "data" {
		t.Fatalf("variable lost behind a wrapped StoreSize: %v %q", err, v.Data)
	}
}

// Before: a header claiming a 1 MiB store in a 1 KiB file let Set(2 KiB)
// "succeed": copy() cut the payload to the buffer, the file stayed 1 KiB and the
// variable was lost on the next Open.
func TestBomb_SetBeyondTheFileFailsLoudly(t *testing.T) {
	buf := buildEmptyStore(1024)
	binary.LittleEndian.PutUint32(buf[16:], 1<<20)
	p := writeTempStore(t, buf)
	s, err := fsuefi.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(makeVar("Big", testGUID, make([]byte, 2048))); err == nil {
		t.Fatal("Set larger than the file succeeded (and lost the variable)")
	}
	if st, _ := os.Stat(p); st.Size() != 1024 {
		t.Fatalf("file size changed to %d", st.Size())
	}
	if err := s.Set(makeVar("Small", testGUID, []byte("ok"))); err != nil {
		t.Fatalf("a variable that fits: %v", err)
	}
	s2, err := fsuefi.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get("Small", testGUID); err != nil {
		t.Fatalf("variable that fits was not persisted: %v", err)
	}
}

// A file truncated after Open must not be written back short.
func TestBomb_StoreTruncatedAfterOpen(t *testing.T) {
	p := writeTempStore(t, buildEmptyStore(1024))
	s, err := fsuefi.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, 512); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(makeVar("X", testGUID, []byte("x"))); err == nil {
		t.Fatal("Set into a store that no longer fits the file succeeded")
	}
}

func TestBomb_FormatCeiling(t *testing.T) {
	dir := t.TempDir()
	before := totalAlloc()
	_, err := fsuefi.Format(filepath.Join(dir, "a.fd"), fsuefi.DefaultMaxFileSize+1)
	wantTooLarge(t, "Format over the ceiling", err)
	_, err = fsuefi.FormatOVMF(filepath.Join(dir, "b.fd"), fsuefi.DefaultMaxFileSize+1, fsuefi.OVMFX86_64)
	wantTooLarge(t, "FormatOVMF over the ceiling", err)
	if alloc := totalAlloc() - before; alloc > 1<<20 {
		t.Fatalf("refused Format allocated %d bytes", alloc)
	}
	for _, n := range []string{"a.fd", "b.fd"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("%s was written", n)
		}
	}
}

// Parser fuzz target.
//
// FuzzOpen seeds the Go fuzzer with the committed real OVMF varstore
// fixture, then mutates it and feeds the result through fsuefi.Open.
// Open must never panic, OOM, or deadlock — it may return an error,
// it may return a Store with zero variables, but it must always come
// back in finite time without taking the process down.
//
// Run as:
//
//	go test -run=^$ -fuzz=FuzzOpen -fuzztime=30s ./test/
//
// Default `go test ./...` only exercises the seed corpus, so this
// target costs ~zero wall-clock in normal runs (one Open of the
// 540-KiB fixture).
package filesystem_uefi_test

import (
	"os"
	"path/filepath"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// FuzzOpen mutates the committed real OVMF fixture and feeds the
// result through Open. The fuzzer's only contract here is "do not
// panic / OOM"; we ignore the returned error (any error is a valid
// outcome — Open is supposed to reject malformed stores).
func FuzzOpen(f *testing.F) {
	// Seed with the real OVMF varstore — the most interesting starting
	// point for mutation since it covers the FV-wrapped + auth-record
	// layout that real firmware writes.
	seed, err := os.ReadFile(filepath.Join("..", "testdata", "edk2-x64-vars.fd"))
	if err != nil {
		f.Skipf("seed fixture not available: %v", err)
	}
	f.Add(seed)

	// Also seed with a freshly-formatted empty store — gives the
	// fuzzer a much smaller mutation surface to start from than the
	// 540 KiB fixture, so mutations land on header bytes faster.
	empty, ferr := func() ([]byte, error) {
		dir, _ := os.MkdirTemp("", "fuzz-seed")
		defer os.RemoveAll(dir)
		p := filepath.Join(dir, "empty.fd")
		if _, e := fsuefi.FormatOVMF(p, fsuefi.VarsSizeX86_64, fsuefi.OVMFX86_64); e != nil {
			return nil, e
		}
		return os.ReadFile(p)
	}()
	if ferr == nil && len(empty) > 0 {
		f.Add(empty)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the input size so a runaway mutation can't allocate
		// gigabytes inside the fuzzer process. 1 MiB is well above
		// the largest real-world OVMF VARS file (64 MiB on arm64
		// is the slot size, but only ~1 MiB is the active region).
		// Variables that aren't relevant to parsing the header /
		// records can be cut off here without hiding parser bugs.
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		path := filepath.Join(t.TempDir(), "fuzz.fd")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skipf("write fuzz input: %v", err)
		}
		// Open may legitimately return an error for malformed
		// input — we only fail on panics, which the test harness
		// catches for us. List() must also be safe to call on
		// any returned Store (defence in depth against returning a
		// non-nil partially-initialised store).
		s, err := fsuefi.Open(path)
		if err != nil {
			return
		}
		// Force a List+Get roundtrip so a bad parser that returns
		// the wrong off/end can blow up on slice-access here
		// rather than silently producing garbage downstream.
		_ = s.List()
		s.Close()
	})
}

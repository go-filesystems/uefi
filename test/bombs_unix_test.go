//go:build unix

package filesystem_uefi_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// A named pipe reports size 0 to Stat but can stream any amount: the capped
// read, not the size check, must stop it.
func TestBomb_StreamLongerThanItsStatSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	payload := buildEmptyStore(4096)
	go func() {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.Write(payload)
	}()
	_, err := fsuefi.OpenLimits(p, fsuefi.Limits{MaxFileSize: 1024})
	wantTooLarge(t, "stream over MaxFileSize", err)
}

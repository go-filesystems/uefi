package filesystem_uefi_test

import (
	"bytes"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// FuzzParseLoadOption feeds malformed / truncated / oversize-length input
// through ParseLoadOption. It must never panic, OOM, or loop forever — only
// return a graceful error or a valid *LoadOption. For any blob that DOES
// parse, Marshal(parsed) must itself round-trip back through ParseLoadOption
// (the marshalled form is canonical and self-consistent).
func FuzzParseLoadOption(f *testing.F) {
	// Seed corpus: a real entry, an empty-path entry, and several malformed
	// shapes (truncated header, unterminated description, oversize fpLen).
	good, _ := realLoadOption().Marshal()
	empty, _ := (&fsuefi.LoadOption{Attributes: 1, Description: "x"}).Marshal()
	f.Add(good)
	f.Add(empty)
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00})                         // truncated header
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF})       // huge fpLen, no desc
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41}) // odd trailing byte, no NUL

	f.Fuzz(func(t *testing.T, data []byte) {
		lo, err := fsuefi.ParseLoadOption(data)
		if err != nil {
			return // graceful rejection is fine
		}
		// A successful parse must re-marshal to a canonical form that
		// round-trips stably (marshal → parse → marshal idempotent).
		b1, err := lo.Marshal()
		if err != nil {
			t.Fatalf("Marshal of parsed load option failed: %v", err)
		}
		lo2, err := fsuefi.ParseLoadOption(b1)
		if err != nil {
			t.Fatalf("re-parse of marshalled load option failed: %v", err)
		}
		b2, err := lo2.Marshal()
		if err != nil {
			t.Fatalf("re-marshal failed: %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("marshal not idempotent:\n %x\n %x", b1, b2)
		}
		// Text rendering must never panic.
		_ = lo.Text()
	})
}

// FuzzParseDevicePath feeds malformed node lists through ParseDevicePath. It
// must never panic; any blob that parses must re-marshal idempotently.
func FuzzParseDevicePath(f *testing.F) {
	good, _ := fsuefi.MarshalDevicePath(realBOOTX64Nodes())
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0x7F, 0xFF, 0x04, 0x00})       // terminator only
	f.Add([]byte{0x01, 0x01, 0x02, 0x00})       // node length below header size
	f.Add([]byte{0x01, 0x01, 0xFF, 0xFF})       // length claims more than buffer
	f.Add([]byte{0x04, 0x01, 0x06, 0x00, 0x01}) // truncated node body

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := fsuefi.ParseDevicePath(data)
		if err != nil {
			return
		}
		b1, err := fsuefi.MarshalDevicePath(nodes)
		if err != nil {
			t.Fatalf("Marshal of parsed device path failed: %v", err)
		}
		nodes2, err := fsuefi.ParseDevicePath(b1)
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		b2, err := fsuefi.MarshalDevicePath(nodes2)
		if err != nil {
			t.Fatalf("re-marshal failed: %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("device-path marshal not idempotent:\n %x\n %x", b1, b2)
		}
		_ = fsuefi.DevicePathText(nodes)
	})
}

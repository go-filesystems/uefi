package filesystem_uefi_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// ---------------------------------------------------------------------------
// Device-path round-trip + text form
// ---------------------------------------------------------------------------

// realBOOTX64Path builds the canonical PciRoot/Pci/HD/File device path for an
// \EFI\BOOT\BOOTX64.EFI entry on GPT partition 1.
func realBOOTX64Nodes() []fsuefi.DevicePathNode {
	// ACPI PciRoot(0x0): HID=0x0A0341D0 (PNP0A03), UID=0.
	acpi := make([]byte, 8)
	binary.LittleEndian.PutUint32(acpi[0:], 0x0A0341D0)
	binary.LittleEndian.PutUint32(acpi[4:], 0)
	acpiNode := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeACPI, SubType: 0x01, Data: acpi}

	// Pci(0x0,0x1): function=0, device=1 → Data = {device, function}.
	pciNode := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeHardware, SubType: 0x01, Data: []byte{0x01, 0x00}}

	var sig [16]byte
	for i := range sig {
		sig[i] = byte(i + 1)
	}
	hd := fsuefi.HardDriveNode{
		PartitionNumber: 1,
		PartitionStart:  0x800,
		PartitionSize:   0x100000,
		Signature:       sig,
		MBRType:         fsuefi.HDMBRTypeGPT,
		SignatureType:   fsuefi.HDSigTypeGUID,
	}

	return []fsuefi.DevicePathNode{
		acpiNode,
		pciNode,
		hd.Node(),
		fsuefi.FilePathNode(`\EFI\BOOT\BOOTX64.EFI`),
	}
}

func TestDevicePathRoundTrip(t *testing.T) {
	nodes := realBOOTX64Nodes()
	b, err := fsuefi.MarshalDevicePath(nodes)
	if err != nil {
		t.Fatalf("MarshalDevicePath: %v", err)
	}
	parsed, err := fsuefi.ParseDevicePath(b)
	if err != nil {
		t.Fatalf("ParseDevicePath: %v", err)
	}
	b2, err := fsuefi.MarshalDevicePath(parsed)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("device-path byte round-trip mismatch:\n %x\n %x", b, b2)
	}
}

func TestDevicePathText(t *testing.T) {
	nodes := realBOOTX64Nodes()
	text := fsuefi.DevicePathText(nodes)
	want := `PciRoot(0x0)/Pci(0x0,0x1)/HD(1,GPT,04030201-0605-0807-090a-0b0c0d0e0f10,0x800,0x100000)/File(\EFI\BOOT\BOOTX64.EFI)`
	if text != want {
		t.Fatalf("device-path text mismatch:\n got  %s\n want %s", text, want)
	}
}

func TestHardDriveTypedRoundTrip(t *testing.T) {
	var sig [16]byte
	copy(sig[:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	hd := fsuefi.HardDriveNode{
		PartitionNumber: 3,
		PartitionStart:  2048,
		PartitionSize:   409600,
		Signature:       sig,
		MBRType:         fsuefi.HDMBRTypePCAT,
		SignatureType:   fsuefi.HDSigTypeMBR,
	}
	n := hd.Node()
	got, ok := n.HardDrive()
	if !ok {
		t.Fatal("HardDrive: not recognised")
	}
	if got != hd {
		t.Fatalf("HD typed round-trip mismatch: %+v != %+v", got, hd)
	}
	// MBR signature text form.
	if txt := fsuefi.DevicePathText([]fsuefi.DevicePathNode{n}); txt != "HD(3,MBR,0xefbeadde,0x800,0x64000)" {
		t.Fatalf("MBR HD text: %s", txt)
	}
}

func TestHardDriveNoSignatureText(t *testing.T) {
	hd := fsuefi.HardDriveNode{
		PartitionNumber: 2,
		PartitionStart:  0x40,
		PartitionSize:   0x80,
		MBRType:         fsuefi.HDMBRTypeGPT,
		SignatureType:   fsuefi.HDSigTypeNone,
	}
	if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{hd.Node()}); got != "HD(2,GPT,0,0x40,0x80)" {
		t.Fatalf("no-signature HD text: %s", got)
	}
}

func TestFilePathNodeAccessor(t *testing.T) {
	n := fsuefi.FilePathNode(`\EFI\Microsoft\Boot\bootmgfw.efi`)
	p, ok := n.FilePath()
	if !ok || p != `\EFI\Microsoft\Boot\bootmgfw.efi` {
		t.Fatalf("FilePath: ok=%v p=%q", ok, p)
	}
	// Non-file node returns ok=false.
	if _, ok := (fsuefi.DevicePathNode{Type: 0x01, SubType: 0x01}).FilePath(); ok {
		t.Fatal("FilePath on non-file node should be false")
	}
	if _, ok := (fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMedia, SubType: 0x01}).FilePath(); ok {
		t.Fatal("FilePath on HD node should be false")
	}
}

func TestUnknownNodePreserved(t *testing.T) {
	// A node type the library has no typed renderer for must round-trip
	// losslessly and render generically.
	unknown := fsuefi.DevicePathNode{Type: 0x6F, SubType: 0x42, Data: []byte{0x01, 0x02, 0x03}}
	b, err := fsuefi.MarshalDevicePath([]fsuefi.DevicePathNode{unknown})
	if err != nil {
		t.Fatalf("Marshal unknown: %v", err)
	}
	parsed, err := fsuefi.ParseDevicePath(b)
	if err != nil {
		t.Fatalf("Parse unknown: %v", err)
	}
	if len(parsed) != 1 || parsed[0].Type != 0x6F || parsed[0].SubType != 0x42 ||
		!bytes.Equal(parsed[0].Data, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("unknown node not preserved: %+v", parsed)
	}
	if txt := fsuefi.DevicePathText(parsed); txt != "Path(0x6f,0x42,010203)" {
		t.Fatalf("generic text: %s", txt)
	}
}

func TestMessagingAndAcpiText(t *testing.T) {
	mac := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x0B, Data: []byte{0xAA, 0xBB, 0xCC}}
	ipv4 := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x0C, Data: []byte{0x01, 0x02}}
	ipv6 := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x0D, Data: []byte{0x03}}
	other := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x05, Data: []byte{0x09}}
	// Non-PciRoot ACPI.
	acpi := make([]byte, 8)
	binary.LittleEndian.PutUint32(acpi[0:], 0x1234)
	binary.LittleEndian.PutUint32(acpi[4:], 0x5)
	acpiNode := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeACPI, SubType: 0x01, Data: acpi}

	cases := map[string]fsuefi.DevicePathNode{
		"MAC(aabbcc)":      mac,
		"IPv4(0102)":       ipv4,
		"IPv6(03)":         ipv6,
		"Msg(0x5,09)":      other,
		"Acpi(0x1234,0x5)": acpiNode,
	}
	for want, node := range cases {
		if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{node}); got != want {
			t.Errorf("text: got %q want %q", got, want)
		}
	}
}

func TestMediaVendorText(t *testing.T) {
	var data [16]byte
	for i := range data {
		data[i] = byte(0x10 + i)
	}
	n := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMedia, SubType: 0x03, Data: data[:]}
	got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{n})
	want := "MediaVendor(13121110-1514-1716-1819-1a1b1c1d1e1f)"
	if got != want {
		t.Fatalf("media vendor text: got %q want %q", got, want)
	}
	// CD-ROM generic hex.
	cd := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMedia, SubType: 0x02, Data: []byte{0xFF}}
	if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{cd}); got != "CDROM(ff)" {
		t.Fatalf("cdrom text: %s", got)
	}
	// PCI node with short data falls through to generic.
	shortPci := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeHardware, SubType: 0x01, Data: []byte{0x00}}
	if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{shortPci}); got != "Path(0x1,0x1,00)" {
		t.Fatalf("short pci text: %s", got)
	}
	// HD node with short data falls through to generic (not a valid HD).
	shortHD := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMedia, SubType: 0x01, Data: []byte{0x00}}
	if _, ok := shortHD.HardDrive(); ok {
		t.Fatal("short HD should not parse")
	}
	if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{shortHD}); got != "Path(0x4,0x1,00)" {
		t.Fatalf("short hd text: %s", got)
	}
}

func TestMarshalDevicePathRejectsEndNode(t *testing.T) {
	end := fsuefi.DevicePathNode{Type: 0x7F, SubType: 0xFF}
	if _, err := fsuefi.MarshalDevicePath([]fsuefi.DevicePathNode{end}); err == nil {
		t.Fatal("expected error marshalling explicit End node")
	}
}

func TestMarshalDevicePathRejectsOversizeNode(t *testing.T) {
	big := fsuefi.DevicePathNode{Type: 0x01, SubType: 0x01, Data: make([]byte, 0x10000)}
	if _, err := fsuefi.MarshalDevicePath([]fsuefi.DevicePathNode{big}); err == nil {
		t.Fatal("expected error marshalling oversize node")
	}
}

func TestEmptyDevicePathMarshalsToTerminator(t *testing.T) {
	b, err := fsuefi.MarshalDevicePath(nil)
	if err != nil {
		t.Fatalf("Marshal nil: %v", err)
	}
	if !bytes.Equal(b, []byte{0x7F, 0xFF, 0x04, 0x00}) {
		t.Fatalf("empty path bytes: %x", b)
	}
	nodes, err := fsuefi.ParseDevicePath(b)
	if err != nil {
		t.Fatalf("Parse terminator-only: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}
}

// ---------------------------------------------------------------------------
// EFI_LOAD_OPTION round-trip
// ---------------------------------------------------------------------------

func realLoadOption() *fsuefi.LoadOption {
	return &fsuefi.LoadOption{
		Attributes:   fsuefi.LoadOptionActive,
		Description:  "UEFI OS",
		DevicePath:   realBOOTX64Nodes(),
		OptionalData: []byte{0x01, 0x02, 0x03, 0x04},
	}
}

func pxeLoadOption() *fsuefi.LoadOption {
	mac := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x0B, Data: []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x00, 0x00}}
	ipv4 := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMessaging, SubType: 0x0C, Data: make([]byte, 23)}
	return &fsuefi.LoadOption{
		Attributes:   fsuefi.LoadOptionActive,
		Description:  "PXE Network Boot",
		DevicePath:   []fsuefi.DevicePathNode{mac, ipv4},
		OptionalData: nil,
	}
}

func TestLoadOptionRoundTrip(t *testing.T) {
	for name, lo := range map[string]*fsuefi.LoadOption{
		"hd-file": realLoadOption(),
		"pxe":     pxeLoadOption(),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := lo.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			parsed, err := fsuefi.ParseLoadOption(b)
			if err != nil {
				t.Fatalf("ParseLoadOption: %v", err)
			}
			b2, err := parsed.Marshal()
			if err != nil {
				t.Fatalf("re-Marshal: %v", err)
			}
			if !bytes.Equal(b, b2) {
				t.Fatalf("load-option byte round-trip mismatch:\n %x\n %x", b, b2)
			}
			if parsed.Description != lo.Description {
				t.Fatalf("description: got %q want %q", parsed.Description, lo.Description)
			}
			if parsed.Attributes != lo.Attributes {
				t.Fatalf("attrs: got %x want %x", parsed.Attributes, lo.Attributes)
			}
		})
	}
}

func TestLoadOptionNoDevicePath(t *testing.T) {
	lo := &fsuefi.LoadOption{Attributes: fsuefi.LoadOptionActive, Description: "empty"}
	b, err := lo.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// FilePathListLength must be 0.
	if binary.LittleEndian.Uint16(b[4:6]) != 0 {
		t.Fatalf("expected fpLen 0, got %d", binary.LittleEndian.Uint16(b[4:6]))
	}
	parsed, err := fsuefi.ParseLoadOption(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b2, _ := parsed.Marshal()
	if !bytes.Equal(b, b2) {
		t.Fatalf("no-path round-trip mismatch: %x vs %x", b, b2)
	}
	if len(parsed.DevicePath) != 0 {
		t.Fatalf("expected empty device path, got %d nodes", len(parsed.DevicePath))
	}
	if txt := parsed.Text(); txt != "" {
		t.Fatalf("expected empty text, got %q", txt)
	}
}

// ---------------------------------------------------------------------------
// Boot manager API on a real minted store
// ---------------------------------------------------------------------------

func TestBootManagerRoundTrip(t *testing.T) {
	s, path := openStoreWith(t, 0x20000)
	defer s.Close()

	// Two realistic boot entries.
	hd := realLoadOption()
	pxe := pxeLoadOption()

	n0, err := fsuefi.AddBootEntry(s, hd)
	if err != nil {
		t.Fatalf("AddBootEntry hd: %v", err)
	}
	if n0 != 0 {
		t.Fatalf("first AddBootEntry should yield Boot0000, got %04X", n0)
	}
	n1, err := fsuefi.AddBootEntry(s, pxe)
	if err != nil {
		t.Fatalf("AddBootEntry pxe: %v", err)
	}
	if n1 != 1 {
		t.Fatalf("second AddBootEntry should yield Boot0001, got %04X", n1)
	}

	// BootOrder should be [0, 1].
	order, err := fsuefi.BootOrder(s)
	if err != nil {
		t.Fatalf("BootOrder: %v", err)
	}
	if len(order) != 2 || order[0] != 0 || order[1] != 1 {
		t.Fatalf("BootOrder: %v", order)
	}

	// Reopen and verify the entries round-trip exactly.
	s.Close()
	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got0, err := fsuefi.BootEntry(s2, 0)
	if err != nil {
		t.Fatalf("BootEntry 0: %v", err)
	}
	want0, _ := hd.Marshal()
	gotB0, _ := got0.Marshal()
	if !bytes.Equal(want0, gotB0) {
		t.Fatalf("Boot0000 round-trip mismatch after reopen")
	}
	if got0.Text() == "" {
		t.Fatal("expected non-empty device path text")
	}

	// Reorder BootOrder to [1, 0] and confirm ListBootEntries honours it.
	if err := fsuefi.SetBootOrder(s2, []uint16{1, 0}); err != nil {
		t.Fatalf("SetBootOrder: %v", err)
	}
	entries, ordered, err := fsuefi.ListBootEntries(s2)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if len(ordered) != 2 || ordered[0] != 1 || ordered[1] != 0 {
		t.Fatalf("ordered: %v", ordered)
	}

	// Delete Boot0000 and verify it is gone.
	if err := fsuefi.DeleteBootEntry(s2, 0); err != nil {
		t.Fatalf("DeleteBootEntry: %v", err)
	}
	if _, err := fsuefi.BootEntry(s2, 0); err == nil {
		t.Fatal("expected error reading deleted Boot0000")
	}
	// New AddBootEntry should reuse the freed 0000 slot.
	n2, err := fsuefi.AddBootEntry(s2, hd)
	if err != nil {
		t.Fatalf("AddBootEntry after delete: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected reused slot Boot0000, got %04X", n2)
	}
}

func TestBootNextTimeoutCurrent(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()

	// BootNext unset → ok=false.
	if _, ok, err := fsuefi.BootNext(s); err != nil || ok {
		t.Fatalf("BootNext unset: ok=%v err=%v", ok, err)
	}
	if err := fsuefi.SetBootNext(s, 0x0003); err != nil {
		t.Fatalf("SetBootNext: %v", err)
	}
	n, ok, err := fsuefi.BootNext(s)
	if err != nil || !ok || n != 3 {
		t.Fatalf("BootNext: n=%d ok=%v err=%v", n, ok, err)
	}
	if err := fsuefi.ClearBootNext(s); err != nil {
		t.Fatalf("ClearBootNext: %v", err)
	}
	if _, ok, _ := fsuefi.BootNext(s); ok {
		t.Fatal("BootNext should be cleared")
	}
	// ClearBootNext is idempotent.
	if err := fsuefi.ClearBootNext(s); err != nil {
		t.Fatalf("ClearBootNext (idempotent): %v", err)
	}

	// Timeout.
	if _, ok, _ := fsuefi.Timeout(s); ok {
		t.Fatal("Timeout should be unset initially")
	}
	if err := fsuefi.SetTimeout(s, 5); err != nil {
		t.Fatalf("SetTimeout: %v", err)
	}
	to, ok, err := fsuefi.Timeout(s)
	if err != nil || !ok || to != 5 {
		t.Fatalf("Timeout: %d ok=%v err=%v", to, ok, err)
	}

	// BootCurrent.
	if _, err := fsuefi.BootCurrent(s); err == nil {
		t.Fatal("BootCurrent should error when unset")
	}
	if err := fsuefi.SetBootCurrent(s, 2); err != nil {
		t.Fatalf("SetBootCurrent: %v", err)
	}
	bc, err := fsuefi.BootCurrent(s)
	if err != nil || bc != 2 {
		t.Fatalf("BootCurrent: %d err=%v", bc, err)
	}
}

func TestBootOrderEmptyAndOddLength(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	// No BootOrder → empty, no error.
	order, err := fsuefi.BootOrder(s)
	if err != nil || len(order) != 0 {
		t.Fatalf("empty BootOrder: %v %v", order, err)
	}
	// Round-trip a multi-entry order.
	if err := fsuefi.SetBootOrder(s, []uint16{0x0007, 0x0003, 0x0001}); err != nil {
		t.Fatalf("SetBootOrder: %v", err)
	}
	order, err = fsuefi.BootOrder(s)
	if err != nil {
		t.Fatalf("BootOrder: %v", err)
	}
	if len(order) != 3 || order[0] != 7 || order[1] != 3 || order[2] != 1 {
		t.Fatalf("BootOrder: %v", order)
	}
	// Craft an odd-length BootOrder via raw Set to hit the error branch.
	if err := s.Set(fsuefi.Variable{
		Name:       "BootOrder",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0x01, 0x02, 0x03},
	}); err != nil {
		t.Fatalf("Set odd BootOrder: %v", err)
	}
	if _, err := fsuefi.BootOrder(s); err == nil {
		t.Fatal("expected error on odd-length BootOrder")
	}
}

func TestBootCurrentTimeoutBadLength(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	set := func(name string, data []byte) {
		if err := s.Set(fsuefi.Variable{
			Name: name, GUID: fsuefi.EFIGlobalVariableGUID,
			Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
			Data:       data,
		}); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	set("BootCurrent", []byte{0x01})
	if _, err := fsuefi.BootCurrent(s); err == nil {
		t.Fatal("BootCurrent bad length should error")
	}
	set("BootNext", []byte{0x01, 0x02, 0x03})
	if _, _, err := fsuefi.BootNext(s); err == nil {
		t.Fatal("BootNext bad length should error")
	}
	set("Timeout", []byte{0x01, 0x02, 0x03})
	if _, _, err := fsuefi.Timeout(s); err == nil {
		t.Fatal("Timeout bad length should error")
	}
}

// ListBootEntries must skip malformed Boot#### entries and entries in other
// namespaces, and append entries not in BootOrder.
func TestListBootEntriesEdgeCases(t *testing.T) {
	s, _ := openStoreWith(t, 0x20000)
	defer s.Close()

	good := realLoadOption()
	if err := fsuefi.SetBootEntry(s, 0x0005, good); err != nil {
		t.Fatalf("SetBootEntry: %v", err)
	}
	// A Boot#### with malformed load-option bytes (no NUL terminator).
	if err := s.Set(fsuefi.Variable{
		Name: "Boot0009", GUID: fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile,
		Data:       []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00}, // unterminated desc
	}); err != nil {
		t.Fatalf("Set malformed: %v", err)
	}
	// A variable in another namespace that happens to be named like a boot var.
	if err := s.Set(fsuefi.Variable{
		Name: "Boot0005", GUID: fsuefi.EFIImageSecurityDatabaseGUID,
		Attributes: fsuefi.AttrNonVolatile, Data: []byte{0xFF},
	}); err != nil {
		t.Fatalf("Set other-ns: %v", err)
	}
	// BootOrder references only 0005; 0009 is malformed so excluded.
	if err := fsuefi.SetBootOrder(s, []uint16{0x0005}); err != nil {
		t.Fatalf("SetBootOrder: %v", err)
	}

	entries, ordered, err := fsuefi.ListBootEntries(s)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
	if _, ok := entries[5]; !ok {
		t.Fatal("Boot0005 missing")
	}
	if len(ordered) != 1 || ordered[0] != 5 {
		t.Fatalf("ordered: %v", ordered)
	}
}

func TestParseBootNameRejectsControlVars(t *testing.T) {
	// BootOrder / BootNext are not Boot#### entries.
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	fsuefi.SetBootOrder(s, []uint16{0}) //nolint:errcheck
	fsuefi.SetBootNext(s, 0)            //nolint:errcheck
	entries, _, err := fsuefi.ListBootEntries(s)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("control vars must not be parsed as entries: %v", entries)
	}
}

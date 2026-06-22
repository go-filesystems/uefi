package filesystem_uefi_test

import (
	"errors"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// faultStore is a programmable in-memory VariableStore used to drive the
// error-propagation branches of the boot-manager helpers (Set/Delete/Get
// faults) that a healthy file-backed store never exercises.
type faultStore struct {
	vars     map[string]fsuefi.Variable // key = name (single namespace assumed)
	failSet  bool
	failDel  bool
	oddOrder bool // when true, Get("BootOrder") returns an odd-length blob
}

func newFaultStore() *faultStore {
	return &faultStore{vars: make(map[string]fsuefi.Variable)}
}

func (f *faultStore) Close() error { return nil }

func (f *faultStore) List() []fsuefi.Variable {
	out := make([]fsuefi.Variable, 0, len(f.vars))
	for _, v := range f.vars {
		out = append(out, v)
	}
	return out
}

func (f *faultStore) Get(name string, guid fsuefi.GUID) (fsuefi.Variable, error) {
	if f.oddOrder && name == "BootOrder" {
		return fsuefi.Variable{Name: name, GUID: guid, Data: []byte{0x01, 0x02, 0x03}}, nil
	}
	v, ok := f.vars[name]
	if !ok {
		return fsuefi.Variable{}, errors.New("not found")
	}
	return v, nil
}

func (f *faultStore) Set(v fsuefi.Variable) error {
	if f.failSet {
		return errors.New("injected set failure")
	}
	f.vars[v.Name] = v
	return nil
}

func (f *faultStore) Delete(name string, guid fsuefi.GUID) error {
	if f.failDel {
		return errors.New("injected delete failure")
	}
	if _, ok := f.vars[name]; !ok {
		return errors.New("not found")
	}
	delete(f.vars, name)
	return nil
}

func TestBootEntryParseFailure(t *testing.T) {
	f := newFaultStore()
	// Store a Boot0001 with malformed load-option bytes (no NUL terminator).
	f.vars["Boot0001"] = fsuefi.Variable{
		Name: "Boot0001", GUID: fsuefi.EFIGlobalVariableGUID,
		Data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00},
	}
	if _, err := fsuefi.BootEntry(f, 1); err == nil {
		t.Fatal("expected parse error from BootEntry")
	}
	// Get failure path.
	if _, err := fsuefi.BootEntry(f, 2); err == nil {
		t.Fatal("expected not-found error from BootEntry")
	}
}

func TestSetBootEntryMarshalFailure(t *testing.T) {
	f := newFaultStore()
	// A device path whose total node bytes exceed uint16 forces Marshal to
	// fail inside SetBootEntry.
	big := fsuefi.DevicePathNode{Type: 0x01, SubType: 0x01, Data: make([]byte, 0x10000)}
	lo := &fsuefi.LoadOption{Description: "x", DevicePath: []fsuefi.DevicePathNode{big}}
	if err := fsuefi.SetBootEntry(f, 0, lo); err == nil {
		t.Fatal("expected marshal failure in SetBootEntry")
	}
}

func TestDeleteBootEntryFailure(t *testing.T) {
	f := newFaultStore()
	f.failDel = true
	if err := fsuefi.DeleteBootEntry(f, 0); err == nil {
		t.Fatal("expected delete failure")
	}
}

func TestClearBootNextDeleteFailure(t *testing.T) {
	f := newFaultStore()
	f.vars["BootNext"] = fsuefi.Variable{Name: "BootNext", GUID: fsuefi.EFIGlobalVariableGUID, Data: []byte{0x00, 0x00}}
	f.failDel = true
	if err := fsuefi.ClearBootNext(f); err == nil {
		t.Fatal("expected delete failure in ClearBootNext")
	}
}

func TestAddBootEntrySetEntryFailure(t *testing.T) {
	f := newFaultStore()
	f.failSet = true
	lo := &fsuefi.LoadOption{Description: "x"}
	if _, err := fsuefi.AddBootEntry(f, lo); err == nil {
		t.Fatal("expected SetBootEntry failure in AddBootEntry")
	}
}

func TestAddBootEntryBootOrderParseFailure(t *testing.T) {
	f := newFaultStore()
	f.oddOrder = true // BootOrder Get yields odd-length → BootOrder() errors
	lo := &fsuefi.LoadOption{Description: "x"}
	// SetBootEntry succeeds; BootOrder() then fails on the odd-length blob.
	if _, err := fsuefi.AddBootEntry(f, lo); err == nil {
		t.Fatal("expected BootOrder parse failure in AddBootEntry")
	}
}

func TestAddBootEntrySetOrderFailure(t *testing.T) {
	// A store that accepts the Boot#### Set but rejects the BootOrder Set.
	f := &setOrderFailStore{faultStore: newFaultStore()}
	lo := &fsuefi.LoadOption{Description: "x"}
	if _, err := fsuefi.AddBootEntry(f, lo); err == nil {
		t.Fatal("expected SetBootOrder failure in AddBootEntry")
	}
}

// setOrderFailStore fails only the BootOrder Set, letting Boot#### through.
type setOrderFailStore struct {
	*faultStore
}

func (s *setOrderFailStore) Set(v fsuefi.Variable) error {
	if v.Name == "BootOrder" {
		return errors.New("injected BootOrder set failure")
	}
	return s.faultStore.Set(v)
}

func TestListBootEntriesBootOrderFailure(t *testing.T) {
	f := newFaultStore()
	f.oddOrder = true
	if _, _, err := fsuefi.ListBootEntries(f); err == nil {
		t.Fatal("expected BootOrder parse failure in ListBootEntries")
	}
}

// TestListBootEntriesAppendsUnordered covers the append-not-in-BootOrder
// branch: an entry present in the store but absent from BootOrder is appended
// in ascending numeric order after the ordered ones.
func TestListBootEntriesAppendsUnordered(t *testing.T) {
	s, _ := openStoreWith(t, 0x20000)
	defer s.Close()
	lo := &fsuefi.LoadOption{Description: "x"}
	if err := fsuefi.SetBootEntry(s, 0x0002, lo); err != nil {
		t.Fatalf("SetBootEntry 2: %v", err)
	}
	if err := fsuefi.SetBootEntry(s, 0x0004, lo); err != nil {
		t.Fatalf("SetBootEntry 4: %v", err)
	}
	// BootOrder references only 0004; 0002 must be appended afterwards.
	if err := fsuefi.SetBootOrder(s, []uint16{0x0004}); err != nil {
		t.Fatalf("SetBootOrder: %v", err)
	}
	_, ordered, err := fsuefi.ListBootEntries(s)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if len(ordered) != 2 || ordered[0] != 4 || ordered[1] != 2 {
		t.Fatalf("ordered: %v (want [4 2])", ordered)
	}
}

// TestParseLoadOptionErrors exercises the bounded-parse rejection branches.
func TestParseLoadOptionErrors(t *testing.T) {
	cases := map[string][]byte{
		"truncated header":       {0x01, 0x00, 0x00},
		"unterminated desc":      {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00},
		"fpLen beyond buffer":    {0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
		"odd-length desc region": {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41}, // 7 bytes, no NUL pair
	}
	for name, b := range cases {
		if _, err := fsuefi.ParseLoadOption(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Oversize input.
	if _, err := fsuefi.ParseLoadOption(make([]byte, 70*1024)); err == nil {
		t.Error("oversize: expected error")
	}
	// A bad device path embedded in an otherwise valid load option: fpLen
	// points at a node whose length runs past the device-path region.
	bad := []byte{
		0x01, 0x00, 0x00, 0x00, // attrs
		0x04, 0x00, // fpLen = 4
		0x00, 0x00, // empty UCS-2 desc (NUL terminator)
		0x01, 0x01, 0xFF, 0xFF, // node claims length 0xFFFF > 4
	}
	if _, err := fsuefi.ParseLoadOption(bad); err == nil {
		t.Error("bad embedded device path: expected error")
	}
}

// TestParseDevicePathErrors exercises ParseDevicePath rejection branches.
func TestParseDevicePathErrors(t *testing.T) {
	cases := map[string][]byte{
		"header truncated":     {0x01, 0x01, 0x04}, // only 3 bytes
		"length below header":  {0x01, 0x01, 0x02, 0x00},
		"length beyond buffer": {0x01, 0x01, 0xFF, 0xFF},
	}
	for name, b := range cases {
		if _, err := fsuefi.ParseDevicePath(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := fsuefi.ParseDevicePath(make([]byte, 70*1024)); err == nil {
		t.Error("oversize device path: expected error")
	}
}

// TestMarshalLoadOptionOversizePath covers the fpLen-overflow guard in Marshal.
func TestMarshalLoadOptionOversizePath(t *testing.T) {
	big := fsuefi.DevicePathNode{Type: 0x01, SubType: 0x01, Data: make([]byte, 0x10000)}
	lo := &fsuefi.LoadOption{Description: "x", DevicePath: []fsuefi.DevicePathNode{big}}
	if _, err := lo.Marshal(); err == nil {
		t.Fatal("expected marshal error for oversize device path")
	}
}

// TestFilePathInvalidUTF16 covers FilePath's decode-failure branch (odd-length
// data) and HardDrive on a non-HD node.
func TestFilePathInvalidAndHardDriveWrongType(t *testing.T) {
	n := fsuefi.DevicePathNode{Type: fsuefi.DevPathTypeMedia, SubType: 0x04, Data: []byte{0x41}} // odd length
	if _, ok := n.FilePath(); ok {
		t.Fatal("FilePath on odd-length data should fail")
	}
	if _, ok := (fsuefi.DevicePathNode{Type: 0x01, SubType: 0x01}).HardDrive(); ok {
		t.Fatal("HardDrive on non-media node should be false")
	}
}

// TestBootNameUppercaseHex covers parseBootName's A–F hex branch and confirms
// the #### is rendered uppercase by writing/reading Boot00AB.
func TestBootNameUppercaseHex(t *testing.T) {
	s, _ := openStoreWith(t, 0x20000)
	defer s.Close()
	lo := &fsuefi.LoadOption{Description: "hex entry"}
	if err := fsuefi.SetBootEntry(s, 0x00AB, lo); err != nil {
		t.Fatalf("SetBootEntry: %v", err)
	}
	// The variable must be named Boot00AB (uppercase).
	if _, err := s.Get("Boot00AB", fsuefi.EFIGlobalVariableGUID); err != nil {
		t.Fatalf("expected Boot00AB variable: %v", err)
	}
	// ListBootEntries must parse it back via parseBootName's A–F branch.
	entries, _, err := fsuefi.ListBootEntries(s)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if _, ok := entries[0x00AB]; !ok {
		t.Fatalf("Boot00AB not parsed: %v", entries)
	}
}

// TestAddBootEntrySkipsOtherNamespace covers lowestFreeBootNum's skip of a
// variable in a non-global namespace whose name resembles a boot entry.
func TestAddBootEntrySkipsOtherNamespace(t *testing.T) {
	s, _ := openStoreWith(t, 0x20000)
	defer s.Close()
	// A Boot0000 in the image-security namespace must NOT reserve slot 0.
	if err := s.Set(fsuefi.Variable{
		Name: "Boot0000", GUID: fsuefi.EFIImageSecurityDatabaseGUID,
		Attributes: fsuefi.AttrNonVolatile, Data: []byte{0xFF},
	}); err != nil {
		t.Fatalf("Set other-ns: %v", err)
	}
	n, err := fsuefi.AddBootEntry(s, &fsuefi.LoadOption{Description: "x"})
	if err != nil {
		t.Fatalf("AddBootEntry: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected slot 0 free (other-ns ignored), got %04X", n)
	}
}

// TestHexBytesEmpty covers the empty-slice fast path of the generic renderer.
func TestHexBytesEmpty(t *testing.T) {
	n := fsuefi.DevicePathNode{Type: 0x05, SubType: 0x01, Data: nil}
	if got := fsuefi.DevicePathText([]fsuefi.DevicePathNode{n}); got != "Path(0x5,0x1,)" {
		t.Fatalf("empty-data generic text: %q", got)
	}
}

// TestParseBootNameLowercaseRejected confirms lower-case hex is rejected (the
// #### must be UPPERCASE), exercising the default branch of parseBootName via
// ListBootEntries (a Boot000a entry must be ignored).
func TestParseBootNameLowercaseRejected(t *testing.T) {
	s, _ := openStoreWith(t, 0x10000)
	defer s.Close()
	if err := s.Set(fsuefi.Variable{
		Name: "Boot000a", GUID: fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile, Data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, _, err := fsuefi.ListBootEntries(s)
	if err != nil {
		t.Fatalf("ListBootEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("lowercase Boot000a must be ignored, got %v", entries)
	}
}

package filesystem_uefi

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/go-volumes/safeio"
)

// Load-option attribute flags (EFI_LOAD_OPTION.Attributes, UEFI spec §3.1.3).
const (
	LoadOptionActive         uint32 = 0x00000001 // LOAD_OPTION_ACTIVE
	LoadOptionForceReconnect uint32 = 0x00000002 // LOAD_OPTION_FORCE_RECONNECT
	LoadOptionHidden         uint32 = 0x00000008 // LOAD_OPTION_HIDDEN
	LoadOptionCategoryMask   uint32 = 0x00001F00 // LOAD_OPTION_CATEGORY
	LoadOptionCategoryBoot   uint32 = 0x00000000 // LOAD_OPTION_CATEGORY_BOOT
	LoadOptionCategoryApp    uint32 = 0x00000100 // LOAD_OPTION_CATEGORY_APP
)

// bootVarAttrs are the standard EFI attributes for boot-manager variables
// (BootOrder, Boot####, BootNext, Timeout). These are non-authenticated
// EFI_GLOBAL_VARIABLE entries: non-volatile + boot-service + runtime.
const bootVarAttrs = AttrNonVolatile | AttrBootServiceAccess | AttrRuntimeAccess

// maxLoadOptionBytes bounds an untrusted EFI_LOAD_OPTION blob. Real boot
// entries are well under a kilobyte; 64 KiB is a generous ceiling.
const maxLoadOptionBytes = 64 * 1024

// maxBootEntries bounds the BootOrder array length when iterating, to keep a
// hostile multi-kilobyte BootOrder from causing excessive Get calls.
const maxBootEntries = 0x10000 // 65536 possible Boot#### numbers

// LoadOption is a parsed EFI_LOAD_OPTION — the value of a Boot#### (or
// Driver####/SysPrep####) variable. On-disk layout (UEFI spec §3.1.3, all
// multi-byte fields little-endian):
//
//	0..4              Attributes        (u32 LE)
//	4..6              FilePathListLength (u16 LE) — byte length of DevicePath
//	6..               Description       (UCS-2, NUL-terminated)
//	(after desc)      DevicePath        (FilePathListLength bytes)
//	(remaining)       OptionalData      (everything left over)
type LoadOption struct {
	Attributes   uint32
	Description  string
	DevicePath   []DevicePathNode
	OptionalData []byte
}

// ParseLoadOption decodes an EFI_LOAD_OPTION from untrusted bytes. Every
// length field is validated with safeio so malformed/truncated input yields a
// graceful error rather than a panic or out-of-bounds read.
func ParseLoadOption(b []byte) (*LoadOption, error) {
	if len(b) > maxLoadOptionBytes {
		return nil, fmt.Errorf("uefi: load option: %d bytes exceeds ceiling %d", len(b), maxLoadOptionBytes)
	}
	// Fixed prefix: Attributes(4) + FilePathListLength(2).
	if err := safeio.CheckBounds(0, 6, len(b)); err != nil {
		return nil, fmt.Errorf("uefi: load option: header truncated: %w", err)
	}
	attrs := binary.LittleEndian.Uint32(b[0:4])
	fpLen := int(binary.LittleEndian.Uint16(b[4:6]))

	// Description is a UCS-2 NUL-terminated string starting at offset 6. Scan
	// for the 16-bit NUL terminator within bounds.
	descStart := 6
	descEnd := -1
	// Each step advances by 2 bytes; bound the scan to len(b).
	guard := safeio.NewLoopGuard(len(b) + 1)
	for i := descStart; i+2 <= len(b); i += 2 {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("uefi: load option: %w", err)
		}
		if b[i] == 0x00 && b[i+1] == 0x00 {
			descEnd = i // offset of the terminator
			break
		}
	}
	if descEnd < 0 {
		return nil, errors.New("uefi: load option: unterminated description")
	}
	// Decode description bytes (excluding terminator); DecodeUTF16LE tolerates
	// the trailing NUL but we pass the exact range without it.
	desc, err := DecodeUTF16LE(b[descStart:descEnd])
	if err != nil {
		return nil, fmt.Errorf("uefi: load option: description: %w", err)
	}

	// Device path follows the terminator (descEnd + 2 bytes for the NUL).
	dpStart := descEnd + 2
	if err := safeio.CheckBounds(dpStart, fpLen, len(b)); err != nil {
		return nil, fmt.Errorf("uefi: load option: device path extends beyond buffer: %w", err)
	}
	dpBytes := b[dpStart : dpStart+fpLen]
	var nodes []DevicePathNode
	if fpLen > 0 {
		nodes, err = ParseDevicePath(dpBytes)
		if err != nil {
			return nil, fmt.Errorf("uefi: load option: %w", err)
		}
	}

	// Optional data is everything after the device path.
	optStart := dpStart + fpLen
	opt := make([]byte, len(b)-optStart)
	copy(opt, b[optStart:])

	return &LoadOption{
		Attributes:   attrs,
		Description:  desc,
		DevicePath:   nodes,
		OptionalData: opt,
	}, nil
}

// Marshal encodes the load option to its exact on-disk byte form. It is the
// inverse of ParseLoadOption: Marshal(ParseLoadOption(b)) == b for any
// well-formed b.
func (lo *LoadOption) Marshal() ([]byte, error) {
	dpBytes, err := MarshalDevicePath(lo.DevicePath)
	if err != nil {
		return nil, err
	}
	// An empty node list still marshals to a 4-byte End node; but a load
	// option with no device path at all should have FilePathListLength 0. We
	// treat a nil/empty DevicePath as "no path" (fpLen 0) to round-trip the
	// fpLen==0 case from ParseLoadOption.
	if len(lo.DevicePath) == 0 {
		dpBytes = nil
	}
	if len(dpBytes) > 0xFFFF {
		return nil, fmt.Errorf("uefi: load option: device path length %d overflows uint16", len(dpBytes))
	}
	descBytes := EncodeUTF16LE(lo.Description) // includes NUL terminator

	buf := make([]byte, 0, 6+len(descBytes)+len(dpBytes)+len(lo.OptionalData))
	var hdr [6]byte
	binary.LittleEndian.PutUint32(hdr[0:], lo.Attributes)
	binary.LittleEndian.PutUint16(hdr[4:], uint16(len(dpBytes)))
	buf = append(buf, hdr[:]...)
	buf = append(buf, descBytes...)
	buf = append(buf, dpBytes...)
	buf = append(buf, lo.OptionalData...)
	return buf, nil
}

// Text renders the load option's device path in canonical UEFI text form.
func (lo *LoadOption) Text() string {
	return DevicePathText(lo.DevicePath)
}

// ---------------------------------------------------------------------------
// Boot manager API — thin typed helpers over the Store's Get/Set/Delete in the
// EFIGlobalVariableGUID namespace, mirroring EnrollSecureBootKeys' style.
// ---------------------------------------------------------------------------

// getGlobal fetches a global variable's data, or returns ok=false if absent.
// The underlying Get only fails with a not-found condition, which this helper
// reports as ok=false rather than an error — so callers can treat "missing"
// uniformly without distinguishing it from a real I/O fault.
func getGlobal(store VariableStore, name string) ([]byte, bool) {
	v, err := store.Get(name, EFIGlobalVariableGUID)
	if err != nil {
		return nil, false
	}
	return v.Data, true
}

// setGlobal writes a global boot variable with the standard NV+BS+RT attrs.
func setGlobal(store VariableStore, name string, data []byte) error {
	return store.Set(Variable{
		Name:       name,
		GUID:       EFIGlobalVariableGUID,
		Attributes: bootVarAttrs,
		Data:       data,
	})
}

// BootOrder returns the platform boot order: the packed UINT16 LE array stored
// in the BootOrder variable. A missing BootOrder yields an empty slice.
func BootOrder(store VariableStore) ([]uint16, error) {
	data, ok := getGlobal(store, "BootOrder")
	if !ok {
		return nil, nil
	}
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("uefi: BootOrder: odd length %d", len(data))
	}
	out := make([]uint16, len(data)/2)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return out, nil
}

// SetBootOrder writes the BootOrder variable from a UINT16 slice.
func SetBootOrder(store VariableStore, order []uint16) error {
	data := make([]byte, len(order)*2)
	for i, n := range order {
		binary.LittleEndian.PutUint16(data[i*2:], n)
	}
	return setGlobal(store, "BootOrder", data)
}

// bootName formats a Boot#### variable name (#### = 4-digit uppercase hex).
func bootName(n uint16) string {
	return fmt.Sprintf("Boot%04X", n)
}

// BootEntry returns the parsed EFI_LOAD_OPTION stored in Boot####.
func BootEntry(store VariableStore, n uint16) (*LoadOption, error) {
	v, err := store.Get(bootName(n), EFIGlobalVariableGUID)
	if err != nil {
		return nil, fmt.Errorf("uefi: BootEntry %s: %w", bootName(n), err)
	}
	lo, err := ParseLoadOption(v.Data)
	if err != nil {
		return nil, fmt.Errorf("uefi: BootEntry %s: %w", bootName(n), err)
	}
	return lo, nil
}

// SetBootEntry writes a load option into Boot####.
func SetBootEntry(store VariableStore, n uint16, lo *LoadOption) error {
	data, err := lo.Marshal()
	if err != nil {
		return fmt.Errorf("uefi: SetBootEntry %s: %w", bootName(n), err)
	}
	return setGlobal(store, bootName(n), data)
}

// DeleteBootEntry removes the Boot#### variable. It does NOT touch BootOrder;
// use SetBootOrder to drop the number from the order if desired.
func DeleteBootEntry(store VariableStore, n uint16) error {
	if err := store.Delete(bootName(n), EFIGlobalVariableGUID); err != nil {
		return fmt.Errorf("uefi: DeleteBootEntry %s: %w", bootName(n), err)
	}
	return nil
}

// AddBootEntry writes lo to the lowest free Boot#### number, appends that
// number to the end of BootOrder, and returns the assigned number.
func AddBootEntry(store VariableStore, lo *LoadOption) (uint16, error) {
	n, ok := lowestFreeBootNum(store)
	if !ok {
		return 0, errors.New("uefi: AddBootEntry: no free Boot#### slot")
	}
	if err := SetBootEntry(store, n, lo); err != nil {
		return 0, err
	}
	order, err := BootOrder(store)
	if err != nil {
		return 0, err
	}
	order = append(order, n)
	if err := SetBootOrder(store, order); err != nil {
		return 0, err
	}
	return n, nil
}

// lowestFreeBootNum scans Boot0000..BootFFFF for the first number with no
// existing Boot#### variable. The store's variable list is consulted directly
// so the scan is a single List() rather than 65536 Get calls.
func lowestFreeBootNum(store VariableStore) (uint16, bool) {
	used := make(map[uint16]struct{})
	for _, v := range store.List() {
		if v.GUID != EFIGlobalVariableGUID {
			continue
		}
		if n, ok := parseBootName(v.Name); ok {
			used[n] = struct{}{}
		}
	}
	for i := 0; i < maxBootEntries; i++ {
		if _, taken := used[uint16(i)]; !taken {
			return uint16(i), true
		}
	}
	return 0, false
}

// parseBootName parses "Boot####" (4 uppercase hex digits) → number. Returns
// ok=false for any other name, including the BootOrder/BootNext/BootCurrent
// control variables.
func parseBootName(name string) (uint16, bool) {
	if len(name) != 8 || name[:4] != "Boot" {
		return 0, false
	}
	var n uint16
	for _, c := range name[4:] {
		var d uint16
		switch {
		case c >= '0' && c <= '9':
			d = uint16(c - '0')
		case c >= 'A' && c <= 'F':
			d = uint16(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | d
	}
	return n, true
}

// BootNext returns the one-shot next-boot entry number and ok=true if the
// BootNext variable is set.
func BootNext(store VariableStore) (uint16, bool, error) {
	data, ok := getGlobal(store, "BootNext")
	if !ok {
		return 0, false, nil
	}
	if len(data) != 2 {
		return 0, false, fmt.Errorf("uefi: BootNext: expected 2 bytes, got %d", len(data))
	}
	return binary.LittleEndian.Uint16(data), true, nil
}

// SetBootNext sets the one-shot BootNext entry number.
func SetBootNext(store VariableStore, n uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, n)
	return setGlobal(store, "BootNext", data)
}

// ClearBootNext deletes the BootNext variable. A missing BootNext is not an
// error (the one-shot is simply already clear).
func ClearBootNext(store VariableStore) error {
	if _, ok := getGlobal(store, "BootNext"); !ok {
		return nil
	}
	if err := store.Delete("BootNext", EFIGlobalVariableGUID); err != nil {
		return fmt.Errorf("uefi: ClearBootNext: %w", err)
	}
	return nil
}

// BootCurrent returns the entry number the firmware booted from this session
// (the read-only BootCurrent variable). Returns an error if it is absent.
func BootCurrent(store VariableStore) (uint16, error) {
	data, ok := getGlobal(store, "BootCurrent")
	if !ok {
		return 0, errors.New("uefi: BootCurrent: not set")
	}
	if len(data) != 2 {
		return 0, fmt.Errorf("uefi: BootCurrent: expected 2 bytes, got %d", len(data))
	}
	return binary.LittleEndian.Uint16(data), nil
}

// SetBootCurrent writes the BootCurrent variable. Firmware sets this itself in
// practice; the setter exists for crafting test fixtures and mock stores.
func SetBootCurrent(store VariableStore, n uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, n)
	return setGlobal(store, "BootCurrent", data)
}

// Timeout returns the boot-manager menu timeout in seconds (the Timeout
// variable). Returns ok=false if unset.
func Timeout(store VariableStore) (uint16, bool, error) {
	data, ok := getGlobal(store, "Timeout")
	if !ok {
		return 0, false, nil
	}
	if len(data) != 2 {
		return 0, false, fmt.Errorf("uefi: Timeout: expected 2 bytes, got %d", len(data))
	}
	return binary.LittleEndian.Uint16(data), true, nil
}

// SetTimeout writes the boot-manager menu timeout in seconds.
func SetTimeout(store VariableStore, seconds uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, seconds)
	return setGlobal(store, "Timeout", data)
}

// ListBootEntries returns every parseable Boot#### entry, keyed by number, and
// a slice of numbers in BootOrder sequence (BootOrder entries first, in order;
// any Boot#### present in the store but absent from BootOrder is appended in
// ascending numeric order). Entries whose load option fails to parse are
// skipped rather than aborting the whole listing.
func ListBootEntries(store VariableStore) (map[uint16]*LoadOption, []uint16, error) {
	entries := make(map[uint16]*LoadOption)
	for _, v := range store.List() {
		if v.GUID != EFIGlobalVariableGUID {
			continue
		}
		n, ok := parseBootName(v.Name)
		if !ok {
			continue
		}
		lo, err := ParseLoadOption(v.Data)
		if err != nil {
			continue // skip malformed entries; don't fail the whole listing
		}
		entries[n] = lo
	}

	order, err := BootOrder(store)
	if err != nil {
		return nil, nil, err
	}
	ordered := make([]uint16, 0, len(entries))
	seen := make(map[uint16]struct{})
	for _, n := range order {
		if _, ok := entries[n]; ok {
			if _, dup := seen[n]; !dup {
				ordered = append(ordered, n)
				seen[n] = struct{}{}
			}
		}
	}
	// Append entries not referenced by BootOrder, ascending.
	for i := 0; i < maxBootEntries; i++ {
		n := uint16(i)
		if _, ok := entries[n]; !ok {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		ordered = append(ordered, n)
		seen[n] = struct{}{}
	}
	return entries, ordered, nil
}

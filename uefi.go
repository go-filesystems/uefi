// Package filesystem_uefi provides read/write access to UEFI variable stores
// in the OVMF/EDK2 NvVar binary format (non-authenticated variant).
package filesystem_uefi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unicode/utf16"

	"github.com/go-volumes/safeio"
)

// Binary format constants derived from EDK2 MdeModulePkg/Include/Guid/VariableFormat.h.
const (
	VariableData   = 0x55AA // VARIABLE_DATA start marker
	StoreFormatted = 0x5A   // VARIABLE_STORE_FORMATTED
	StoreHealthy   = 0xFE   // VARIABLE_STORE_HEALTHY

	varInDeletedTransition = 0xFE // header written, data incomplete
	VarAdded               = 0x3F // complete, valid variable
	VarDeleted             = 0xFD // obsolete/deleted
	varHeaderValidOnly     = 0x7F

	StoreHeaderSize   = 28 // sizeof(VARIABLE_STORE_HEADER)
	VarHeaderSize     = 32 // sizeof(VARIABLE_HEADER) — non-auth variant
	AuthVarHeaderSize = 60 // sizeof(AUTHENTICATED_VARIABLE_HEADER) — adds
	//                       MonotonicCount(8) + TimeStamp(16) + PubKeyIndex(4)
	//                       between Attributes and NameSize.
	headerAlignment = 4 // HEADER_ALIGNMENT

	// FvHeaderSize is the on-disk size of an EFI_FIRMWARE_VOLUME_HEADER
	// with exactly one block-map entry plus the (0, 0) terminator. Both
	// QEMU's edk2-i386-vars.fd and the OVMF aarch64 NvVar region use this
	// 72-byte layout (HeaderLength field = 0x48).
	FvHeaderSize = 72

	// fvSignature is the "_FVH" little-endian magic at offset
	// 0x28 of EFI_FIRMWARE_VOLUME_HEADER.
	fvSignature uint32 = 0x4856465F
)

// GUID represents a 16-byte EFI GUID stored in mixed-endian on-disk format.
// Bytes 0-3: Data1 LE, 4-5: Data2 LE, 6-7: Data3 LE, 8-15: Data4 big-endian.
type GUID [16]byte

// Attributes holds EFI variable attribute flags.
type Attributes uint32

const (
	AttrNonVolatile                       Attributes = 0x00000001
	AttrBootServiceAccess                 Attributes = 0x00000002
	AttrRuntimeAccess                     Attributes = 0x00000004
	AttrHardwareErrorRecord               Attributes = 0x00000008
	AttrTimeBasedAuthenticatedWriteAccess Attributes = 0x00000020
	AttrAppendWrite                       Attributes = 0x00000040
)

// EFIVariableGUID is the store signature GUID for non-authenticated NvVar stores.
// {0xddcf3616, 0x3275, 0x4164, {0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d}}
var EFIVariableGUID = GUID{
	0x16, 0x36, 0xcf, 0xdd, // Data1 LE
	0x75, 0x32, // Data2 LE
	0x64, 0x41, // Data3 LE
	0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
}

// EFIAuthenticatedVariableGUID is the store signature GUID for authenticated NvVar stores.
// {0xaaf32c78, 0x947b, 0x439a, {0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92}}
var EFIAuthenticatedVariableGUID = GUID{
	0x78, 0x2c, 0xf3, 0xaa,
	0x7b, 0x94,
	0x9a, 0x43,
	0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
}

// EFISystemNvDataFvGUID is the FvHeader.FileSystemGuid used for the NvVar
// firmware volume in both QEMU x86_64 (edk2-i386-vars.fd) and QEMU aarch64
// (the varstore region of edk2-aarch64-code.fd / QEMU_VARS.fd) prebuilt
// OVMF images. EDK2 calls it `gEfiSystemNvDataFvGuid`.
//
//	{FFF12B8D-7696-4C8B-A985-2747075B4F50}
//
// Wire encoding follows the standard EFI mixed-endian rule:
//
//	Data1 (uint32, LE)   = 0xFFF12B8D  →  bytes 8d 2b f1 ff
//	Data2 (uint16, LE)   = 0x7696      →  bytes 96 76
//	Data3 (uint16, LE)   = 0x4C8B      →  bytes 8b 4c
//	Data4 (8 raw bytes)                 →  a9 85 27 47 07 5b 4f 50
var EFISystemNvDataFvGUID = GUID{
	0x8d, 0x2b, 0xf1, 0xff,
	0x96, 0x76,
	0x8b, 0x4c,
	0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50,
}

// Variable is a single parsed UEFI variable.
type Variable struct {
	Name       string
	GUID       GUID
	Attributes Attributes
	Data       []byte
}

// VariableStore provides read/write access to a UEFI NvVar variable store.
// All write operations (Set, Delete) serialize through the backing file.
type VariableStore interface {
	// Close releases any resources held by the store.
	Close() error
	// List returns a copy of all valid (non-deleted) variables in the store.
	List() []Variable
	// Get retrieves a variable by name and GUID namespace.
	Get(name string, guid GUID) (Variable, error)
	// Set creates or replaces a variable; the backing file is rewritten.
	Set(v Variable) error
	// Delete removes a variable by name and GUID; returns an error if not found.
	Delete(name string, guid GUID) error
}

// store is the internal implementation of VariableStore and filesystem.Filesystem.
//
// The on-disk layout used by real OVMF varstores is:
//
//	[ EFI_FIRMWARE_VOLUME_HEADER       ] ← 72 B at offset 0    (optional)
//	[ VARIABLE_STORE_HEADER            ] ← 28 B at offset storeOff
//	[ variables ...                    ]   ← AUTH or non-AUTH records
//	[ 0xFF padding to end of storeSize ]
//
// Three flavors are observed in the wild:
//
//   - Raw NvVar + non-authenticated variables (what the mock package
//     originally produced; useful for tests).
//   - FV-wrapped + AUTHENTICATED variables (every QEMU OVMF prebuilt
//     since edk2 has shipped NetworkPkg/SecureBoot — both x86_64
//     edk2-i386-vars.fd and aarch64 edk2-aarch64-code.fd's NvVar
//     region use this layout).
//   - FV-wrapped + non-authenticated (rare; mostly older firmwares).
//
// Open auto-detects all three. The fvWrapped + authVars flags are
// carried on the store so flush() preserves the format on rewrite —
// changing flavor mid-flight would corrupt the file for OVMF.
type store struct {
	path      string
	vars      []Variable
	fvWrapped bool   // file begins with a 72-byte FV header
	authVars  bool   // variable records use AUTHENTICATED_VARIABLE_HEADER (60 B)
	storeOff  uint32 // byte offset of the NvVar store header
	storeSize uint32 // total bytes covered by the NvVar store header's Size field
}

// Open opens a UEFI variable store file and parses its contents.
// It returns a Store, which combines VariableStore and filesystem.Filesystem.
//
// Auto-detects the on-disk format: raw NvVar vs FV-wrapped, and
// authenticated vs non-authenticated variable records. The detection
// is sticky — flush() preserves whatever flavor was found at Open
// time so the file stays compatible with the firmware that owns it.
func Open(path string) (Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("uefi: read file: %w", err)
	}
	s := &store{path: path}
	s.fvWrapped = detectFvWrap(data)
	if s.fvWrapped {
		s.storeOff = FvHeaderSize
	}
	if int(s.storeOff)+StoreHeaderSize > len(data) {
		return nil, fmt.Errorf("uefi: parse: file too small for store header")
	}
	// Read the NvVar store header at storeOff.
	var sig GUID
	copy(sig[:], data[s.storeOff:s.storeOff+16])
	switch sig {
	case EFIAuthenticatedVariableGUID:
		s.authVars = true
	case EFIVariableGUID:
		s.authVars = false
	default:
		return nil, fmt.Errorf("uefi: parse: unrecognised store signature GUID")
	}
	if data[s.storeOff+20] != StoreFormatted {
		return nil, fmt.Errorf("uefi: parse: store not formatted")
	}
	if data[s.storeOff+21] != StoreHealthy {
		return nil, fmt.Errorf("uefi: parse: store not healthy")
	}
	s.storeSize = binary.LittleEndian.Uint32(data[s.storeOff+16 : s.storeOff+20])

	vars, err := parseVariables(data, s.storeOff, s.storeSize, s.authVars)
	if err != nil {
		return nil, fmt.Errorf("uefi: parse: %w", err)
	}
	s.vars = vars
	return s, nil
}

// detectFvWrap returns true if the first 0x30 bytes of data look like
// an EDK2 Firmware Volume header — specifically: gEfiSystemNvDataFvGuid
// at offset 0x10 and "_FVH" at offset 0x28.
func detectFvWrap(data []byte) bool {
	if len(data) < FvHeaderSize {
		return false
	}
	var fvGUID GUID
	copy(fvGUID[:], data[16:32])
	if fvGUID != EFISystemNvDataFvGUID {
		return false
	}
	return binary.LittleEndian.Uint32(data[40:44]) == fvSignature
}

// Close is a no-op for file-backed stores (reads are done eagerly).
func (s *store) Close() error {
	return nil
}

// List returns a copy of all valid variables in the store.
func (s *store) List() []Variable {
	out := make([]Variable, len(s.vars))
	copy(out, s.vars)
	return out
}

// Get retrieves a variable by name and GUID. Returns an error if not found.
func (s *store) Get(name string, guid GUID) (Variable, error) {
	for _, v := range s.vars {
		if v.Name == name && v.GUID == guid {
			return v, nil
		}
	}
	return Variable{}, fmt.Errorf("uefi: variable %q not found", name)
}

// Set creates or replaces a variable. The store file is rewritten atomically.
func (s *store) Set(v Variable) error {
	newVars := make([]Variable, 0, len(s.vars)+1)
	for _, existing := range s.vars {
		if existing.Name == v.Name && existing.GUID == v.GUID {
			continue
		}
		newVars = append(newVars, existing)
	}
	newVars = append(newVars, v)
	return s.flush(newVars)
}

// Delete removes a variable by name and GUID. Returns an error if not found.
func (s *store) Delete(name string, guid GUID) error {
	newVars := make([]Variable, 0, len(s.vars))
	found := false
	for _, existing := range s.vars {
		if existing.Name == name && existing.GUID == guid {
			found = true
			continue
		}
		newVars = append(newVars, existing)
	}
	if !found {
		return fmt.Errorf("uefi: variable %q not found", name)
	}
	return s.flush(newVars)
}

// flush serializes vars and writes the store back to disk.
//
// Preserves whatever flavor the store was opened with (raw vs FV-
// wrapped, auth vs non-auth). The FV header and store header are
// taken verbatim from the original file bytes — we don't recompute
// the FV checksum because no fields inside the header change here.
func (s *store) flush(vars []Variable) error {
	orig, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("uefi: read original: %w", err)
	}
	if len(orig) < int(s.storeOff)+StoreHeaderSize {
		return errors.New("uefi: file too small")
	}
	payload := serializeVars(vars, s.authVars)
	buf, err := buildStore(orig, s.storeOff, s.storeSize, payload)
	if err != nil {
		return err
	}
	s.vars = vars
	return os.WriteFile(s.path, buf, 0o644)
}

// buildStore constructs the full file bytes: original prefix (FV
// header + store header) + serialized vars + 0xFF padding to fill the
// rest of storeSize bytes. Anything past storeOff+storeSize is left
// untouched — that region holds FTW state on real OVMF varstores.
func buildStore(orig []byte, storeOff, storeSize uint32, payload []byte) ([]byte, error) {
	headerEnd := storeOff + StoreHeaderSize
	if headerEnd+uint32(len(payload)) > storeOff+storeSize {
		return nil, errors.New("uefi: variables exceed store size")
	}
	buf := make([]byte, len(orig))
	copy(buf, orig)
	// Erase the variable region (everything inside the NvVar store
	// after the 28-byte header).
	end := int(storeOff + storeSize)
	if end > len(buf) {
		end = len(buf)
	}
	for i := int(headerEnd); i < end; i++ {
		buf[i] = 0xFF
	}
	copy(buf[headerEnd:], payload)
	return buf, nil
}

// parseVariables walks the variable region of the NvVar store from
// storeOff..storeOff+storeSize and returns every VarAdded record.
// authVars selects the 60-byte AUTHENTICATED_VARIABLE_HEADER layout
// over the 32-byte non-auth one — auth records carry an extra
// MonotonicCount(8) + TimeStamp(16) + PubKeyIndex(4) prefix between
// the Attributes field and NameSize.
func parseVariables(data []byte, storeOff, storeSize uint32, authVars bool) ([]Variable, error) {
	end := storeOff + storeSize
	if uint32(len(data)) < end {
		end = uint32(len(data))
	}
	var vars []Variable
	off := storeOff + uint32(StoreHeaderSize)
	// LoopGuard backstop: every record advances `off` by at least one
	// alignment unit, and the region is at most `end` bytes, so the walk
	// can make at most `end` forward steps. Sizing the guard to `end`+1 (a
	// strict over-estimate) guarantees termination even if a future change
	// regresses the forward-progress check below.
	guard := safeio.NewLoopGuard(int(end) + 1)
	// Loop while at least the 2-byte StartId fits. parseOneVariable is the
	// single bounds authority: it re-checks StartId, then that the full
	// (auth or non-auth) header fits within `end`, surfacing a truncated
	// header as an error rather than relying on this outer guard. Keeping
	// the outer condition minimal avoids a uint32 wrap on `off+hdrSize`
	// and keeps the truncation checks reachable.
	for off+2 <= end {
		if err := guard.Next(); err != nil {
			break
		}
		v, next, err := parseOneVariable(data, off, end, authVars)
		if err != nil {
			break
		}
		// SECURITY: require strict forward progress. parseOneVariable
		// computes `next` from attacker-controlled sizes; if a wrap (or a
		// zero-length record) ever yielded next <= off, this loop would
		// re-parse the same offset forever. Bounding 0 < off < next <= end
		// makes the walk strictly monotonic and finite.
		if next <= off || next > end {
			break
		}
		if v != nil {
			vars = append(vars, *v)
		}
		off = next
	}
	return vars, nil
}

// parseOneVariable reads a single variable header at off and returns the variable
// (nil if deleted/invalid) and the offset of the next header.
//
// Non-authenticated layout (32 bytes):
//
//	0..2   StartId (=VariableData)
//	2      State
//	3      Reserved
//	4..8   Attributes
//	8..12  NameSize
//	12..16 DataSize
//	16..32 VendorGuid
//
// Authenticated layout (60 bytes) inserts after byte 8:
//
//	8..16   MonotonicCount
//	16..32  TimeStamp (EFI_TIME)
//	32..36  PubKeyIndex
//	36..40  NameSize
//	40..44  DataSize
//	44..60  VendorGuid
func parseOneVariable(data []byte, off, end uint32, authVars bool) (*Variable, uint32, error) {
	if off+2 > end || binary.LittleEndian.Uint16(data[off:off+2]) != VariableData {
		return nil, end, errors.New("end of variable region")
	}
	// The fields common to both layouts span the first 8 bytes:
	// StartId(2) State(1) Reserved(1) Attributes(4). Verify that prefix
	// fits within `end` (which is <= len(data)) BEFORE reading State or
	// Attributes — otherwise a record that begins valid but is cut off
	// after the StartId would index data[off+2] / data[off+4:] past the
	// end of the slice and panic. This guard subsumes the StartId check
	// above for the body reads.
	if err := safeio.CheckBounds(int(off), 8, int(end)); err != nil {
		return nil, end, fmt.Errorf("variable header prefix truncated: %w", err)
	}
	state := data[off+2]
	attrs := binary.LittleEndian.Uint32(data[off+4:])

	var nameSize, dataSize uint32
	var guid GUID
	var hdrSize uint32

	if authVars {
		hdrSize = uint32(AuthVarHeaderSize)
		if off+hdrSize > end {
			return nil, end, errors.New("auth header truncated")
		}
		nameSize = binary.LittleEndian.Uint32(data[off+36:])
		dataSize = binary.LittleEndian.Uint32(data[off+40:])
		copy(guid[:], data[off+44:off+60])
	} else {
		hdrSize = uint32(VarHeaderSize)
		if off+hdrSize > end {
			return nil, end, errors.New("header truncated")
		}
		nameSize = binary.LittleEndian.Uint32(data[off+8:])
		dataSize = binary.LittleEndian.Uint32(data[off+12:])
		copy(guid[:], data[off+16:off+32])
	}

	// DataOffset = nameOff + nameSize. No HEADER_ALIGN padding between
	// name and data — that's an EDK2 invariant we got wrong in the
	// first cut. The alignment is applied only between records (so
	// `next` is rounded up to HEADER_ALIGNMENT below).
	//
	// SECURITY: nameSize and dataSize are attacker-controlled uint32
	// fields. Computing dataOff/next with uint32 arithmetic WRAPS when
	// nameOff+nameSize or dataOff+dataSize overflow 2^32, which would
	// bypass a naive `next > end` guard and let the slice/alloc below
	// index ~4 GiB out of bounds. Validate every field independently in
	// 64-bit BEFORE indexing or allocating: the name range and the data
	// range must each lie fully within [0, end), and the rounded-up next
	// offset must not exceed end. All comparisons are done against `end`
	// (which is itself <= len(data)), so the int conversions below are
	// safe once the bounds hold.
	nameOff64 := int64(off) + int64(hdrSize)
	dataOff64 := nameOff64 + int64(nameSize)
	dataEnd64 := dataOff64 + int64(dataSize)
	next64 := (dataEnd64 + headerAlignment - 1) &^ (headerAlignment - 1)

	// CheckBounds rejects any range that runs past `end` (or wraps), so
	// the [nameOff:nameOff+nameSize] and [dataOff:dataOff+dataSize]
	// accesses below cannot panic.
	if err := safeio.CheckBounds(int(nameOff64), int(nameSize), int(end)); err != nil {
		return nil, end, fmt.Errorf("variable name extends beyond store: %w", err)
	}
	if err := safeio.CheckBounds(int(dataOff64), int(dataSize), int(end)); err != nil {
		return nil, end, fmt.Errorf("variable data extends beyond store: %w", err)
	}
	if next64 > int64(end) {
		return nil, end, errors.New("variable extends beyond store")
	}
	next := uint32(next64)
	nameOff := uint32(nameOff64)
	dataOff := uint32(dataOff64)

	if state != VarAdded {
		return nil, next, nil // skip deleted/transitional
	}
	name, err := DecodeUTF16LE(data[nameOff : nameOff+nameSize])
	if err != nil {
		return nil, next, nil
	}
	// Bound the allocation by the store size: dataSize already passed
	// CheckBounds against end, so this can only fail if end is itself
	// nonsensical — in which case we surface an error rather than alloc.
	payload, err := safeio.MakeBytes(int64(dataSize), int64(end))
	if err != nil {
		return nil, next, nil
	}
	copy(payload, data[dataOff:dataOff+dataSize])
	return &Variable{Name: name, GUID: guid, Attributes: Attributes(attrs), Data: payload}, next, nil
}

// serializeVars encodes a slice of variables as a contiguous byte sequence.
func serializeVars(vars []Variable, authVars bool) []byte {
	var buf []byte
	for _, v := range vars {
		buf = append(buf, encodeVariable(v, authVars)...)
	}
	return buf
}

// encodeVariable encodes a single variable to its on-disk binary form.
// authVars selects the 60-byte AUTHENTICATED_VARIABLE_HEADER layout;
// MonotonicCount / TimeStamp / PubKeyIndex are written as zeros, which
// is the same shape OVMF itself writes for non-authenticated SetVariable
// calls inside an auth-format store.
//
// On-disk record layout (both flavors):
//
//	[ header ] [ name ] [ data ] [ pad to align next record ]
//
// Critically there is NO padding between `name` and `data`, even when
// `len(header)+len(name)` isn't a multiple of HEADER_ALIGNMENT — real
// OVMF (verified empirically on Homebrew QEMU arm64 prebuilts, May
// 2026, edk2-stable202408) computes DataOffset as nameOff+nameSize and
// applies HEADER_ALIGN only when walking to the NEXT variable header,
// not between fields of the same record. Inserting padding here causes
// GetVariable to return the pad bytes prepended to the data — visible
// as a 2-byte zero prefix on names whose size isn't already aligned.
func encodeVariable(v Variable, authVars bool) []byte {
	nameBuf := EncodeUTF16LE(v.Name)
	nameSize := uint32(len(nameBuf))
	dataSize := uint32(len(v.Data))

	var hdr []byte
	if authVars {
		hdr = make([]byte, AuthVarHeaderSize)
		binary.LittleEndian.PutUint16(hdr[0:], VariableData)
		hdr[2] = VarAdded
		hdr[3] = 0
		binary.LittleEndian.PutUint32(hdr[4:], uint32(v.Attributes))
		// MonotonicCount(8) @ 8, TimeStamp(16) @ 16, PubKeyIndex(4) @ 32
		// are all left as zero — see comment above.
		binary.LittleEndian.PutUint32(hdr[36:], nameSize)
		binary.LittleEndian.PutUint32(hdr[40:], dataSize)
		copy(hdr[44:], v.GUID[:])
	} else {
		hdr = make([]byte, VarHeaderSize)
		binary.LittleEndian.PutUint16(hdr[0:], VariableData)
		hdr[2] = VarAdded
		hdr[3] = 0
		binary.LittleEndian.PutUint32(hdr[4:], uint32(v.Attributes))
		binary.LittleEndian.PutUint32(hdr[8:], nameSize)
		binary.LittleEndian.PutUint32(hdr[12:], dataSize)
		copy(hdr[16:], v.GUID[:])
	}

	// Pad only at the END of the record so the next record starts
	// HEADER_ALIGNMENT-aligned.
	recordPad := padBytes(uint32(len(hdr)) + nameSize + dataSize)

	var buf []byte
	buf = append(buf, hdr...)
	buf = append(buf, nameBuf...)
	buf = append(buf, v.Data...)
	buf = append(buf, recordPad...)
	return buf
}

// alignUp aligns n to the next headerAlignment boundary.
func alignUp(n uint32) uint32 {
	return (n + headerAlignment - 1) &^ (headerAlignment - 1)
}

// padBytes returns the padding needed to align the end of a field of size n.
func padBytes(n uint32) []byte {
	pad := alignUp(n) - n
	return make([]byte, pad)
}

// DecodeUTF16LE converts a UTF-16LE byte slice (may include null terminator) to a Go string.
func DecodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("odd-length UTF-16LE buffer")
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16)), nil
}

// EncodeUTF16LE converts a Go string to UTF-16LE bytes with null terminator.
func EncodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	u16 = append(u16, 0) // null terminator
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

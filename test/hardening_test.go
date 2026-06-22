// Security-hardening tests for the UEFI variable-store parser.
//
// THREAT MODEL: an untrusted varstore must NEVER panic the host,
// OOB-read, integer-overflow into a bad alloc/slice, loop forever, or
// OOM. Every malformed input below must come back from Open + List in
// finite time as a graceful error or an empty/partial variable set —
// never a panic.
//
// The headline vector is the uint32-wrap in parseOneVariable: a record
// whose NameSize/DataSize sum overflows 2^32 used to bypass the
// `next > end` guard and then slice / make([]byte, ~4 GiB) out of
// bounds. We craft that exact record here and assert Open survives.
package filesystem_uefi_test

import (
	"encoding/binary"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// putVarHeader writes a 32-byte non-authenticated VARIABLE_HEADER into
// buf at off with the given state, name size and data size. The vendor
// GUID is left zero (irrelevant to the bounds logic under test).
func putVarHeader(buf []byte, off int, state byte, nameSize, dataSize uint32) {
	binary.LittleEndian.PutUint16(buf[off:], fsuefi.VariableData) // StartId
	buf[off+2] = state
	buf[off+3] = 0
	binary.LittleEndian.PutUint32(buf[off+4:], 0) // Attributes
	binary.LittleEndian.PutUint32(buf[off+8:], nameSize)
	binary.LittleEndian.PutUint32(buf[off+12:], dataSize)
	// GUID at off+16..off+32 stays zero.
}

// overflowStore returns a raw (non-FV) non-auth store whose single
// record at the start of the variable region has NameSize/DataSize
// chosen so that dataOff+dataSize wraps below `end` in uint32 math.
//
//	nameOff  = 28 (store header) + 32 (var header) = 60  (≈100 region)
//	NameSize = 0xFFFFFF00
//	DataSize = 0x100
//
// In wrapping uint32 arithmetic dataOff+dataSize collapses to a small
// value, so a naive `next > end` guard passes and the parser would then
// index data[nameOff:nameOff+NameSize] (~4 GiB) → slice-OOB panic.
func overflowStore() []byte {
	const storeSize = 4096
	buf := buildEmptyStore(storeSize)
	putVarHeader(buf, fsuefi.StoreHeaderSize, fsuefi.VarAdded, 0xFFFFFF00, 0x100)
	return buf
}

// truncatedHeaderStore returns a store that ends in the middle of a
// variable header — the region claims a record but not enough bytes
// follow it.
func truncatedHeaderStore() []byte {
	// storeSize large enough for the header; we then cut the slice so the
	// declared store size exceeds the actual file length, and the record
	// header itself is short.
	buf := buildEmptyStore(4096)
	// Plant a StartId so the parser enters parseOneVariable, then chop the
	// buffer mid-header (only 8 bytes of the 32-byte header remain).
	binary.LittleEndian.PutUint16(buf[fsuefi.StoreHeaderSize:], fsuefi.VariableData)
	return buf[:fsuefi.StoreHeaderSize+8]
}

// startIdOnlyStore returns a store cut so the 2-byte StartId of the
// first record is present but the 8-byte common header prefix (through
// Attributes) runs past the end of the file. Exercises the prefix-
// truncation guard that protects the State / Attributes reads.
func startIdOnlyStore() []byte {
	buf := buildEmptyStore(4096)
	binary.LittleEndian.PutUint16(buf[fsuefi.StoreHeaderSize:], fsuefi.VariableData)
	// Keep StartId (off+2) but drop the rest of the 8-byte prefix:
	// file ends 4 bytes into the record, so off+8 > end.
	return buf[:fsuefi.StoreHeaderSize+4]
}

// nextRegressStore returns a store whose record declares NameSize and
// DataSize that, with a partial wrap, could make `next` land at or
// before `off` — the infinite-loop vector for parseVariables. We pick
// sizes whose 64-bit dataEnd rounds to exactly off (zero forward
// progress) absent the strict `next > off` guard.
func nextRegressStore() []byte {
	const storeSize = 4096
	buf := buildEmptyStore(storeSize)
	// NameSize chosen so nameOff+NameSize wraps uint32 back to a value
	// <= off. off = 28, header end = 60. Want dataEnd (60 + NameSize +
	// DataSize) mod 2^32 to round down to <= 28.
	//   NameSize = 2^32 - 60  → nameOff+NameSize wraps to 0
	//   DataSize = 0          → dataEnd wraps to 0, next rounds to 0 <= off
	putVarHeader(buf, fsuefi.StoreHeaderSize, fsuefi.VarAdded, uint32(0xFFFFFFFF-60+1), 0)
	return buf
}

// nextPastEndStore returns a store whose name+data ranges both fit
// within `end`, but whose alignment-rounded `next` offset lands just
// past `end`. end is deliberately not 4-byte aligned so alignUp pushes
// `next` over the edge — exercising the `next64 > end` rejection that
// sits after the two CheckBounds guards.
//
//	end       = 62 (store size, not 4-aligned)
//	nameOff   = 60, NameSize = 2  → name range [60,62) ⊆ [0,62) OK
//	DataSize  = 0                 → data range [62,62) OK
//	dataEnd   = 62, next = alignUp(62) = 64 > 62 → rejected
func nextPastEndStore() []byte {
	const storeSize = 62
	buf := buildEmptyStore(storeSize)
	putVarHeader(buf, fsuefi.StoreHeaderSize, fsuefi.VarAdded, 2, 0)
	return buf
}

// hugeDataStore declares a plausible-looking but enormous DataSize that
// fits in uint32 without wrapping but vastly exceeds the file — the
// OOM / OOB-read vector that MakeBytes + CheckBounds must reject.
func hugeDataStore() []byte {
	const storeSize = 4096
	buf := buildEmptyStore(storeSize)
	putVarHeader(buf, fsuefi.StoreHeaderSize, fsuefi.VarAdded, 4, 0x7FFFFFF0)
	return buf
}

// truncatedAuthHeaderStore returns an FV-wrapped AUTHENTICATED store
// whose first record carries a StartId but is cut off before the full
// 60-byte AUTHENTICATED_VARIABLE_HEADER fits — exercising the auth-side
// "header truncated" rejection.
func truncatedAuthHeaderStore() []byte {
	const fileLen = fsuefi.FvHeaderSize + fsuefi.StoreHeaderSize + 8 // StartId + a few bytes
	buf := make([]byte, fileLen)
	// FV header: GUID at [16:32], "_FVH" signature uint32 at [40:44].
	copy(buf[16:32], fsuefi.EFISystemNvDataFvGUID[:])
	binary.LittleEndian.PutUint32(buf[40:], 0x4856465F) // fvSignature "_FVH"
	// Authenticated store header at FvHeaderSize.
	off := fsuefi.FvHeaderSize
	copy(buf[off:off+16], fsuefi.EFIAuthenticatedVariableGUID[:])
	binary.LittleEndian.PutUint32(buf[off+16:], 1<<20) // store Size (over file len → truncated)
	buf[off+20] = fsuefi.StoreFormatted
	buf[off+21] = fsuefi.StoreHealthy
	// Record StartId right after the store header; the 60-byte auth header
	// cannot fit in the remaining 8 bytes.
	binary.LittleEndian.PutUint16(buf[off+fsuefi.StoreHeaderSize:], fsuefi.VariableData)
	return buf
}

// validRawStore returns a well-formed raw non-auth store containing a
// single complete variable, so the parser's happy path stays covered
// alongside the malformed vectors.
func validRawStore() []byte {
	const storeSize = 4096
	buf := buildEmptyStore(storeSize)
	name := fsuefi.EncodeUTF16LE("Boot")
	data := []byte{1, 2, 3, 4}
	off := fsuefi.StoreHeaderSize
	putVarHeader(buf, off, fsuefi.VarAdded, uint32(len(name)), uint32(len(data)))
	copy(buf[off+32:], name)
	copy(buf[off+32+len(name):], data)
	return buf
}

// openBytes writes raw store bytes to a temp file and runs the full
// Open + List + Close roundtrip, returning Open's error. It MUST NOT
// panic for any input; a panic fails the test via the harness.
func openBytes(t *testing.T, data []byte) error {
	t.Helper()
	path := writeTempStore(t, data)
	s, err := fsuefi.Open(path)
	if err != nil {
		return err
	}
	_ = s.List()
	return s.Close()
}

// TestHarden_OverflowVector is the headline regression: the uint32-wrap
// record must be rejected as a parse-time bounds error, not panic.
func TestHarden_OverflowVector(t *testing.T) {
	// parseVariables breaks (returns no error, zero vars) when a record
	// fails bounds — so Open succeeds with an empty store. The contract
	// is simply: no panic, finite time.
	if err := openBytes(t, overflowStore()); err != nil {
		t.Logf("overflow store rejected at Open: %v", err)
	}
}

// TestHarden_TruncatedHeader: a store cut mid-header must not OOB-read.
func TestHarden_TruncatedHeader(t *testing.T) {
	if err := openBytes(t, truncatedHeaderStore()); err != nil {
		t.Logf("truncated store rejected at Open: %v", err)
	}
}

// TestHarden_StartIdOnly: a record with only its StartId present (the
// 8-byte common prefix runs off the end) must not OOB-read State/Attrs.
func TestHarden_StartIdOnly(t *testing.T) {
	if err := openBytes(t, startIdOnlyStore()); err != nil {
		t.Logf("start-id-only store rejected at Open: %v", err)
	}
}

// TestHarden_NextNoForwardProgress: a record whose `next` would not
// advance past `off` must terminate the walk, not loop forever.
func TestHarden_NextNoForwardProgress(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = openBytes(t, nextRegressStore())
	}()
	// If the forward-progress guard regresses this Open never returns;
	// the test's own deadline (go test -timeout) is the ultimate
	// backstop, but the goroutine makes the intent explicit.
	<-done
}

// TestHarden_HugeData: an enormous DataSize must be rejected by
// CheckBounds / MakeBytes instead of OOMing.
func TestHarden_HugeData(t *testing.T) {
	if err := openBytes(t, hugeDataStore()); err != nil {
		t.Logf("huge-data store rejected at Open: %v", err)
	}
}

// TestHarden_TruncatedAuthHeader: an FV-wrapped auth store cut mid auth
// header must reject cleanly, not OOB-read the 60-byte header.
func TestHarden_TruncatedAuthHeader(t *testing.T) {
	if err := openBytes(t, truncatedAuthHeaderStore()); err != nil {
		t.Logf("truncated auth store rejected at Open: %v", err)
	}
}

// TestHarden_NextPastEnd: a record whose aligned `next` exceeds `end`
// (even though name/data fit) must be rejected, not parsed.
func TestHarden_NextPastEnd(t *testing.T) {
	if err := openBytes(t, nextPastEndStore()); err != nil {
		t.Logf("next-past-end store rejected at Open: %v", err)
	}
}

// TestHarden_ValidRawRoundtrip keeps the happy path covered: the valid
// store parses to exactly one variable with the expected name/data.
func TestHarden_ValidRawRoundtrip(t *testing.T) {
	path := writeTempStore(t, validRawStore())
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open valid raw store: %v", err)
	}
	defer s.Close()
	vars := s.List()
	if len(vars) != 1 {
		t.Fatalf("want 1 variable, got %d", len(vars))
	}
	if vars[0].Name != "Boot" {
		t.Fatalf("want name %q, got %q", "Boot", vars[0].Name)
	}
	if string(vars[0].Data) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("want data 01020304, got %x", vars[0].Data)
	}
}

// FuzzParseVariables feeds malformed and valid stores through Open. The
// seed corpus includes every hand-crafted vector above (incl. the exact
// uint32-overflow record), so the seeds alone — which run under plain
// `go test` — assert "no panic, finite time" without needing -fuzz.
func FuzzParseVariables(f *testing.F) {
	f.Add(overflowStore())
	f.Add(startIdOnlyStore())
	f.Add(truncatedHeaderStore())
	f.Add(truncatedAuthHeaderStore())
	f.Add(nextRegressStore())
	f.Add(nextPastEndStore())
	f.Add(hugeDataStore())
	f.Add(validRawStore())
	f.Add(buildEmptyStore(4096))
	f.Add([]byte{})                             // empty file
	f.Add(make([]byte, fsuefi.StoreHeaderSize)) // header-only, all zero

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound input size so a runaway mutation cannot allocate
		// gigabytes inside the fuzzer process.
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		// openBytes performs Open + List + Close. Any error is a valid
		// outcome; the only failure mode is a panic, which the harness
		// turns into a test failure.
		_ = openBytes(t, data)
	})
}

// FuzzList is an alias-style target that drives List() specifically over
// mutated valid stores, ensuring a parser that returns a bad off/end
// blows up here rather than silently downstream.
func FuzzList(f *testing.F) {
	f.Add(validRawStore())
	f.Add(overflowStore())
	f.Add(buildEmptyStore(2048))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		path := writeTempStore(t, data)
		s, err := fsuefi.Open(path)
		if err != nil {
			return
		}
		// List + Get roundtrip over whatever survived parsing.
		for _, v := range s.List() {
			_, _ = s.Get(v.Name, v.GUID)
		}
		s.Close()
	})
}

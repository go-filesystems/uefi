package filesystem_uefi

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Standard UEFI variable store sizes used by QEMU firmware images.
const (
	// VarsSizeX86_64 is the standard OVMF_VARS.fd size for x86-64 (512 KiB).
	VarsSizeX86_64 = int64(512 * 1024)
	// VarsSizeARM64 is the standard QEMU_VARS.fd size for arm64 (64 MiB).
	VarsSizeARM64 = int64(64 * 1024 * 1024)
)

// Format creates a new empty UEFI NvVar variable store file at path with the
// given total size, in the legacy *raw non-auth* format: signature GUID
// at offset 0, no FV wrapper, non-authenticated variable records.
//
// Use FormatOVMF instead when targeting a real QEMU OVMF varstore on
// either x86_64 or aarch64 — both prebuilts (edk2-i386-vars.fd and the
// NvVar region of edk2-aarch64-code.fd) use the FV-wrapped + auth
// layout, and OVMF will reformat any other layout on first boot.
//
// The returned Store is open and ready for use; call Close when done.
// sizeBytes must be at least StoreHeaderSize + 4 bytes.
func Format(path string, sizeBytes int64) (Store, error) {
	if sizeBytes < int64(StoreHeaderSize)+4 {
		return nil, fmt.Errorf("uefi: Format: size %d is too small (minimum %d)", sizeBytes, int64(StoreHeaderSize)+4)
	}

	buf := makeEmptyStore(sizeBytes)

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("uefi: Format: write %s: %w", path, err)
	}

	return Open(path)
}

// OVMFFlavor selects between the two observed OVMF varstore layouts.
type OVMFFlavor int

const (
	// OVMFX86_64 — the layout used by QEMU's edk2-i386-vars.fd. FvLength
	// equals the file size; BlockMap is a single span covering the same
	// range; the NvVar store fills the FV minus the 72-byte header.
	// Typical file size: 512 KiB.
	OVMFX86_64 OVMFFlavor = iota

	// OVMFAArch64 — the layout used by QEMU's ArmVirt prebuilt. The
	// pflash slot is large (64 MiB on Homebrew QEMU) but the firmware
	// only uses 768 KiB at offset 0 as the NvVar FV, split as
	// 256 KiB (Variable region) + 256 KiB (FTW working) + 256 KiB (FTW
	// spare). FvLength is fixed at 0xC0000, BlockMap covers the entire
	// pflash slot, and the NvVar VARIABLE_STORE_HEADER.Size is
	// 0x3FFB8 (256 KiB − the 72-byte FV header).
	OVMFAArch64
)

// ArmVirt-specific sizes — same constants edk2 ArmVirtPkg/ArmVirtQemu.fdf
// uses. These are firmware-side hard-coded values that OVMF aarch64
// expects; passing a different FvLength or store Size causes OVMF to
// detect a mismatch on first boot and reformat, wiping our variables.
const (
	armVirtNvVarFvSize    = int64(0xC0000) // 768 KiB total FV
	armVirtNvVarStoreSize = int64(0x40000) // 256 KiB for the variable region
)

// FormatOVMF creates a new empty UEFI NvVar variable store file at path
// in the format real QEMU OVMF prebuilts use: a 72-byte EFI_FIRMWARE_VOLUME
// header at offset 0, a VARIABLE_STORE_HEADER with the
// EFIAuthenticatedVariableGUID signature at offset 72, and 0xFF padding
// (erased flash) for the rest of the FV.
//
// flavor picks the FV layout — see OVMFFlavor constants. Use OVMFX86_64
// for OVMF_VARS.fd and OVMFAArch64 for QEMU_VARS.fd (ArmVirt).
//
// sizeBytes is the full file size to produce — for x86_64 this equals the
// FV size; for aarch64 it's typically 64 MiB (the pflash slot) and only
// the first 768 KiB is the FV.
//
// Variables created via Set on the returned Store are written with the
// 60-byte AUTHENTICATED_VARIABLE_HEADER (MonotonicCount + TimeStamp +
// PubKeyIndex zeros), matching how OVMF itself stores
// non-authenticated SetVariable calls inside an auth-format store.
func FormatOVMF(path string, sizeBytes int64, flavor OVMFFlavor) (Store, error) {
	minSize := int64(FvHeaderSize) + int64(StoreHeaderSize) + 4
	if flavor == OVMFAArch64 {
		// arm64 needs room for the full ArmVirt FV.
		minSize = armVirtNvVarFvSize
	}
	if sizeBytes < minSize {
		return nil, fmt.Errorf("uefi: FormatOVMF: size %d is too small (minimum %d for flavor %d)", sizeBytes, minSize, flavor)
	}

	buf := makeEmptyOVMFStore(sizeBytes, flavor)

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("uefi: FormatOVMF: write %s: %w", path, err)
	}

	return Open(path)
}

// makeEmptyStore returns the raw bytes for an empty NvVar variable store of
// the given size: a valid VARIABLE_STORE_HEADER followed by 0xFF (erased
// flash). Exported for use in tests.
func makeEmptyStore(sizeBytes int64) []byte {
	buf := make([]byte, sizeBytes)

	// Variable region (after the 28-byte header) is erased flash = 0xFF.
	for i := StoreHeaderSize; i < len(buf); i++ {
		buf[i] = 0xFF
	}

	// VARIABLE_STORE_HEADER (28 bytes):
	//  0-15  Signature GUID  (EFIVariableGUID)
	// 16-19  Size            (uint32 LE)
	// 20     Format          (0x5A = formatted)
	// 21     State           (0xFE = healthy)
	// 22-23  Reserved        (0x0000)
	// 24-27  Reserved1       (0x00000000)
	copy(buf[0:16], EFIVariableGUID[:])
	binary.LittleEndian.PutUint32(buf[16:], uint32(sizeBytes))
	buf[20] = StoreFormatted
	buf[21] = StoreHealthy

	return buf
}

// makeEmptyOVMFStore returns the raw bytes for an empty FV-wrapped
// authenticated NvVar store, formatted for the given OVMF flavor.
//
// X86_64 layout — FvLength = sizeBytes, BlockMap spans the same:
//
//	0x00..0x10  ZeroVector
//	0x10..0x20  FvHeader.FileSystemGuid = gEfiSystemNvDataFvGuid
//	0x20..0x28  FvHeader.FvLength = sizeBytes (LE u64)
//	0x28..0x2C  FvHeader.Signature = "_FVH"
//	0x2C..0x30  FvHeader.Attributes
//	0x30..0x32  FvHeader.HeaderLength = 0x48
//	0x32..0x34  FvHeader.Checksum (16-bit; sum of all u16 words = 0)
//	0x34..0x38  Reserved + Revision = 0x02
//	0x38..0x48  BlockMap[0] + terminator
//	0x48..0x64  VARIABLE_STORE_HEADER (sizeBytes - 72)
//	0x64..end   0xFF
//
// AArch64 layout — fixed ArmVirtPkg geometry, BlockMap covers the
// entire pflash slot but the NvVar FV only the first 768 KiB:
//
//	FvHeader.FvLength       = 0xC0000  (768 KiB)
//	BlockMap[0]             = sizeBytes / 0x40000 blocks × 256 KiB
//	StoreHeader.Size        = 0x3FFB8  (256 KiB − FvHeaderSize)
//
// The trailing 0xFF padding is the FTW work + spare area; OVMF
// initialises both itself on first boot when it sees them erased.
func makeEmptyOVMFStore(sizeBytes int64, flavor OVMFFlavor) []byte {
	buf := make([]byte, sizeBytes)

	// Pick layout-specific sizes.
	var fvLength, storeSize int64
	var blockLen, numBlocks uint32
	switch flavor {
	case OVMFAArch64:
		fvLength = armVirtNvVarFvSize
		storeSize = armVirtNvVarStoreSize - int64(FvHeaderSize)
		// BlockMap covers the whole pflash slot. ArmVirt uses
		// 256-KiB blocks; if sizeBytes isn't a multiple of that we
		// fall back to a single span (still legal per UEFI PI spec).
		blockLen = 0x40000
		if sizeBytes%int64(blockLen) == 0 {
			numBlocks = uint32(sizeBytes / int64(blockLen))
		} else {
			numBlocks = 1
			blockLen = uint32(sizeBytes)
		}
	default: // OVMFX86_64
		fvLength = sizeBytes
		storeSize = sizeBytes - int64(FvHeaderSize)
		blockLen = 0x1000
		if sizeBytes%int64(blockLen) == 0 {
			numBlocks = uint32(sizeBytes / int64(blockLen))
		} else {
			numBlocks = 1
			blockLen = uint32(sizeBytes)
		}
	}

	// Erased-flash fill from end of NvVar store header to end of file.
	storeOff := uint32(FvHeaderSize)
	headerEnd := int(storeOff) + StoreHeaderSize
	for i := headerEnd; i < len(buf); i++ {
		buf[i] = 0xFF
	}

	// ----- FV header bytes 0x00..0x48 (72 B) -----
	//   ZeroVector @ 0x00..0x10 (already zero).
	copy(buf[0x10:0x20], EFISystemNvDataFvGUID[:])
	binary.LittleEndian.PutUint64(buf[0x20:], uint64(fvLength))
	binary.LittleEndian.PutUint32(buf[0x28:], fvSignature) // "_FVH"
	// Attributes value observed in both x86_64 (0x0004feff) and aarch64
	// (0x00000e36) prebuilt varstores after first boot. Use the
	// stricter arm64 value for both — x86_64 firmware accepts it
	// because every required-cap flag in 0x0004feff is also set there.
	binary.LittleEndian.PutUint32(buf[0x2c:], 0x00000e36)
	binary.LittleEndian.PutUint16(buf[0x30:], 0x0048) // HeaderLength
	// Checksum @ 0x32 — filled in below.
	binary.LittleEndian.PutUint16(buf[0x34:], 0x0000) // ExtHeaderOffset
	buf[0x36] = 0x00                                  // Reserved
	buf[0x37] = 0x02                                  // Revision

	binary.LittleEndian.PutUint32(buf[0x38:], numBlocks)
	binary.LittleEndian.PutUint32(buf[0x3c:], blockLen)
	// BlockMap terminator @ 0x40..0x48 — already zero.

	// FvHeader.Checksum — 16-bit one's-complement of the sum of all
	// u16 words in the header.
	var sum uint16
	for i := 0; i < FvHeaderSize; i += 2 {
		sum += binary.LittleEndian.Uint16(buf[i:])
	}
	binary.LittleEndian.PutUint16(buf[0x32:], uint16(0)-sum)

	// ----- VARIABLE_STORE_HEADER @ 0x48 (28 B, auth signature) -----
	copy(buf[storeOff:storeOff+16], EFIAuthenticatedVariableGUID[:])
	binary.LittleEndian.PutUint32(buf[storeOff+16:], uint32(storeSize))
	buf[storeOff+20] = StoreFormatted
	buf[storeOff+21] = StoreHealthy

	return buf
}

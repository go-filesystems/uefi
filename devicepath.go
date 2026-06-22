package filesystem_uefi

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/go-volumes/safeio"
)

// EFI_DEVICE_PATH_PROTOCOL node Type values (UEFI spec §10.3).
const (
	DevPathTypeHardware  uint8 = 0x01
	DevPathTypeACPI      uint8 = 0x02
	DevPathTypeMessaging uint8 = 0x03
	DevPathTypeMedia     uint8 = 0x04
	DevPathTypeBIOS      uint8 = 0x05
	DevPathTypeEnd       uint8 = 0x7F
)

// SubType values for the End-of-path node (Type 0x7F).
const (
	DevPathEndInstance uint8 = 0x01 // end of one path instance, more follow
	DevPathEndEntire   uint8 = 0xFF // end of the entire device path
)

// Common SubType values used for typed text rendering.
const (
	devPathHWSubPCI       uint8 = 0x01 // Hardware/PCI
	devPathACPISubACPI    uint8 = 0x01 // ACPI/ACPI (_HID + _UID)
	devPathMsgSubMAC      uint8 = 0x0B // Messaging/MAC address
	devPathMsgSubIPv4     uint8 = 0x0C // Messaging/IPv4
	devPathMsgSubIPv6     uint8 = 0x0D // Messaging/IPv6
	devPathMsgSubUSB      uint8 = 0x05 // Messaging/USB
	devPathMsgSubSATA     uint8 = 0x12 // Messaging/SATA
	devPathMediaSubHD     uint8 = 0x01 // Media/Hard Drive
	devPathMediaSubCDROM  uint8 = 0x02 // Media/CD-ROM
	devPathMediaSubVendor uint8 = 0x03 // Media/Vendor
	devPathMediaSubFile   uint8 = 0x04 // Media/File Path
	devPathMediaSubFvFile uint8 = 0x06 // Media/PIWG Firmware File
	devPathMediaSubFv     uint8 = 0x07 // Media/PIWG Firmware Volume
)

// MBRType values for a Hard Drive (HD) media node.
const (
	HDMBRTypePCAT uint8 = 0x01 // legacy MBR partition table
	HDMBRTypeGPT  uint8 = 0x02 // GUID partition table
)

// SignatureType values for a Hard Drive (HD) media node.
const (
	HDSigTypeNone uint8 = 0x00 // no disk signature
	HDSigTypeMBR  uint8 = 0x01 // 4-byte MBR (NT) disk signature
	HDSigTypeGUID uint8 = 0x02 // 16-byte GPT disk GUID
)

// devPathHeaderSize is the fixed EFI_DEVICE_PATH_PROTOCOL header: Type(1) +
// SubType(1) + Length(2, little-endian, includes the header itself).
const devPathHeaderSize = 4

// maxDevicePathBytes bounds an untrusted device-path blob. Real EFI device
// paths are at most a few hundred bytes; 64 KiB is a generous ceiling that
// still rejects a hostile length field claiming gigabytes.
const maxDevicePathBytes = 64 * 1024

// DevicePathNode is a single EFI_DEVICE_PATH_PROTOCOL node. Data holds the
// node-specific bytes that follow the 4-byte header (i.e. everything after
// Type/SubType/Length). Unknown node types are preserved losslessly via this
// generic representation.
type DevicePathNode struct {
	Type    uint8
	SubType uint8
	Data    []byte
}

// Length returns the on-disk node length (header + Data), as written into the
// 2-byte Length field.
func (n DevicePathNode) Length() int {
	return devPathHeaderSize + len(n.Data)
}

// isEnd reports whether n is the entire-device-path End node (0x7F/0xFF).
func (n DevicePathNode) isEnd() bool {
	return n.Type == DevPathTypeEnd && n.SubType == DevPathEndEntire
}

// ParseDevicePath decodes a complete EFI_DEVICE_PATH_PROTOCOL node list from
// b. Parsing stops after the entire-path End node (Type 0x7F, SubType 0xFF);
// the returned slice does NOT include that terminator (MarshalDevicePath
// re-appends it). The input is treated as untrusted: every length field is
// bounds-checked via safeio so malformed or truncated data yields an error
// rather than a panic or out-of-bounds read.
func ParseDevicePath(b []byte) ([]DevicePathNode, error) {
	if len(b) > maxDevicePathBytes {
		return nil, fmt.Errorf("uefi: device path: %d bytes exceeds ceiling %d", len(b), maxDevicePathBytes)
	}
	var nodes []DevicePathNode
	off := 0
	// Each node advances off by at least devPathHeaderSize (4) bytes, so the
	// walk makes at most len(b) forward steps. Size the guard to len(b)+1 as a
	// strict over-estimate.
	guard := safeio.NewLoopGuard(len(b) + 1)
	for {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("uefi: device path: %w", err)
		}
		if err := safeio.CheckBounds(off, devPathHeaderSize, len(b)); err != nil {
			return nil, fmt.Errorf("uefi: device path: header truncated at %d: %w", off, err)
		}
		typ := b[off]
		sub := b[off+1]
		nodeLen := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		if nodeLen < devPathHeaderSize {
			return nil, fmt.Errorf("uefi: device path: node length %d at %d below header size", nodeLen, off)
		}
		if err := safeio.CheckBounds(off, nodeLen, len(b)); err != nil {
			return nil, fmt.Errorf("uefi: device path: node at %d extends beyond buffer: %w", off, err)
		}
		dataLen := nodeLen - devPathHeaderSize
		data := make([]byte, dataLen)
		copy(data, b[off+devPathHeaderSize:off+nodeLen])
		node := DevicePathNode{Type: typ, SubType: sub, Data: data}
		off += nodeLen
		if node.isEnd() {
			return nodes, nil
		}
		nodes = append(nodes, node)
	}
}

// MarshalDevicePath encodes a node list back to its on-disk byte form,
// appending the entire-path End node (0x7F/0xFF, length 4). It is the exact
// inverse of ParseDevicePath: MarshalDevicePath(ParseDevicePath(b)) == b for
// any well-formed b that ends in a single entire-path terminator.
func MarshalDevicePath(nodes []DevicePathNode) ([]byte, error) {
	var buf []byte
	for i, n := range nodes {
		if n.isEnd() {
			return nil, fmt.Errorf("uefi: device path: node %d is an End node; the terminator is implicit", i)
		}
		nodeLen := n.Length()
		if nodeLen > 0xFFFF {
			return nil, fmt.Errorf("uefi: device path: node %d length %d overflows uint16", i, nodeLen)
		}
		hdr := make([]byte, devPathHeaderSize)
		hdr[0] = n.Type
		hdr[1] = n.SubType
		binary.LittleEndian.PutUint16(hdr[2:], uint16(nodeLen))
		buf = append(buf, hdr...)
		buf = append(buf, n.Data...)
	}
	// Append the entire-path End node.
	end := []byte{DevPathTypeEnd, DevPathEndEntire, devPathHeaderSize, 0x00}
	buf = append(buf, end...)
	return buf, nil
}

// FilePathNode builds a Media/File Path node (Type 0x04, SubType 0x04) whose
// Data is the UCS-2 (UTF-16LE) NUL-terminated path, e.g. \EFI\BOOT\BOOTX64.EFI.
func FilePathNode(path string) DevicePathNode {
	return DevicePathNode{
		Type:    DevPathTypeMedia,
		SubType: devPathMediaSubFile,
		Data:    EncodeUTF16LE(path),
	}
}

// FilePath returns the UCS-2 path of a Media/File Path node, or false if n is
// not a file-path node (or its data is malformed).
func (n DevicePathNode) FilePath() (string, bool) {
	if n.Type != DevPathTypeMedia || n.SubType != devPathMediaSubFile {
		return "", false
	}
	s, err := DecodeUTF16LE(n.Data)
	if err != nil {
		return "", false
	}
	return s, true
}

// HardDriveNode describes a Media/Hard Drive (HD) device-path node — the
// typed view of the partition that a load option boots from.
type HardDriveNode struct {
	PartitionNumber uint32
	PartitionStart  uint64 // starting LBA
	PartitionSize   uint64 // size in LBAs
	Signature       [16]byte
	MBRType         uint8 // HDMBRTypePCAT or HDMBRTypeGPT
	SignatureType   uint8 // HDSigTypeNone / HDSigTypeMBR / HDSigTypeGUID
}

// HardDriveNodeFrom builds the on-disk Media/HD node for hd. The fixed
// 42-byte layout (UEFI spec Table 10.x) is:
//
//	 0..4   PartitionNumber (u32 LE)
//	 4..12  PartitionStart  (u64 LE)
//	12..20  PartitionSize   (u64 LE)
//	20..36  Signature       (16 raw bytes)
//	36      MBRType
//	37      SignatureType
func (hd HardDriveNode) Node() DevicePathNode {
	data := make([]byte, 38)
	binary.LittleEndian.PutUint32(data[0:], hd.PartitionNumber)
	binary.LittleEndian.PutUint64(data[4:], hd.PartitionStart)
	binary.LittleEndian.PutUint64(data[12:], hd.PartitionSize)
	copy(data[20:36], hd.Signature[:])
	data[36] = hd.MBRType
	data[37] = hd.SignatureType
	return DevicePathNode{Type: DevPathTypeMedia, SubType: devPathMediaSubHD, Data: data}
}

// HardDrive returns the typed HD view of n, or false if n is not a
// well-formed Media/Hard Drive node.
func (n DevicePathNode) HardDrive() (HardDriveNode, bool) {
	if n.Type != DevPathTypeMedia || n.SubType != devPathMediaSubHD {
		return HardDriveNode{}, false
	}
	if len(n.Data) < 38 {
		return HardDriveNode{}, false
	}
	var hd HardDriveNode
	hd.PartitionNumber = binary.LittleEndian.Uint32(n.Data[0:])
	hd.PartitionStart = binary.LittleEndian.Uint64(n.Data[4:])
	hd.PartitionSize = binary.LittleEndian.Uint64(n.Data[12:])
	copy(hd.Signature[:], n.Data[20:36])
	hd.MBRType = n.Data[36]
	hd.SignatureType = n.Data[37]
	return hd, true
}

// guidFromBytes interprets 16 raw bytes as a mixed-endian EFI GUID for text
// rendering (Data1 LE u32, Data2/Data3 LE u16, Data4 8 raw bytes).
func guidText(b [16]byte) string {
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// DevicePathText renders a node list in the canonical UEFI text form, e.g.:
//
//	PciRoot(0x0)/Pci(0x1,0x0)/HD(1,GPT,<guid>,0x800,0x100000)/File(\EFI\BOOT\BOOTX64.EFI)
//
// Typed renderers are emitted for the common production nodes (Hardware/PCI,
// ACPI, Messaging MAC/IPv4/IPv6, Media HD/File/CD-ROM); any other node is
// rendered generically as Path(<type>,<subtype>,<hexdata>) so the text form is
// always total and never loses information about node identity.
func DevicePathText(nodes []DevicePathNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		parts = append(parts, n.text())
	}
	return strings.Join(parts, "/")
}

// text renders a single node.
func (n DevicePathNode) text() string {
	switch n.Type {
	case DevPathTypeHardware:
		if n.SubType == devPathHWSubPCI && len(n.Data) >= 2 {
			// PCI: Function(1), Device(1).
			return fmt.Sprintf("Pci(0x%x,0x%x)", n.Data[1], n.Data[0])
		}
	case DevPathTypeACPI:
		if n.SubType == devPathACPISubACPI && len(n.Data) >= 8 {
			hid := binary.LittleEndian.Uint32(n.Data[0:4])
			uid := binary.LittleEndian.Uint32(n.Data[4:8])
			// EISA PNP HID 0x0A03 = PciRoot.
			if hid == 0x0A0341D0 {
				return fmt.Sprintf("PciRoot(0x%x)", uid)
			}
			return fmt.Sprintf("Acpi(0x%x,0x%x)", hid, uid)
		}
	case DevPathTypeMessaging:
		switch n.SubType {
		case devPathMsgSubMAC:
			return "MAC(" + hexBytes(n.Data) + ")"
		case devPathMsgSubIPv4:
			return "IPv4(" + hexBytes(n.Data) + ")"
		case devPathMsgSubIPv6:
			return "IPv6(" + hexBytes(n.Data) + ")"
		}
		return fmt.Sprintf("Msg(0x%x,%s)", n.SubType, hexBytes(n.Data))
	case DevPathTypeMedia:
		switch n.SubType {
		case devPathMediaSubHD:
			if hd, ok := n.HardDrive(); ok {
				return hd.text()
			}
		case devPathMediaSubFile:
			if p, ok := n.FilePath(); ok {
				return "File(" + p + ")"
			}
		case devPathMediaSubCDROM:
			return "CDROM(" + hexBytes(n.Data) + ")"
		case devPathMediaSubVendor, devPathMediaSubFvFile, devPathMediaSubFv:
			if len(n.Data) >= 16 {
				var g [16]byte
				copy(g[:], n.Data[:16])
				return fmt.Sprintf("MediaVendor(%s)", guidText(g))
			}
		}
	}
	return fmt.Sprintf("Path(0x%x,0x%x,%s)", n.Type, n.SubType, hexBytes(n.Data))
}

// text renders a Hard Drive node, e.g. HD(1,GPT,<guid>,0x800,0x100000).
func (hd HardDriveNode) text() string {
	mbr := "MBR"
	if hd.MBRType == HDMBRTypeGPT {
		mbr = "GPT"
	}
	var sig string
	switch hd.SignatureType {
	case HDSigTypeGUID:
		sig = guidText(hd.Signature)
	case HDSigTypeMBR:
		sig = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(hd.Signature[:4]))
	default:
		sig = "0"
	}
	return fmt.Sprintf("HD(%d,%s,%s,0x%x,0x%x)",
		hd.PartitionNumber, mbr, sig, hd.PartitionStart, hd.PartitionSize)
}

// hexBytes renders a byte slice as lower-case hex with no separator (used for
// the generic / messaging text renderers).
func hexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	const hexdigits = "0123456789abcdef"
	for _, c := range b {
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0x0f])
	}
	return sb.String()
}

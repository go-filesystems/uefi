package filesystem_uefi

import (
	"encoding/binary"
	"fmt"
)

// Well-known GUIDs for Secure Boot variable management.
var (
	// EFIGlobalVariableGUID is the namespace for PK and KEK variables.
	// {8be4df61-93ca-11d2-aa0d-00e098032b8c}
	EFIGlobalVariableGUID = GUID{
		0x61, 0xdf, 0xe4, 0x8b,
		0xca, 0x93,
		0xd2, 0x11,
		0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
	}

	// EFIImageSecurityDatabaseGUID is the namespace for db and dbx variables.
	// {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
	EFIImageSecurityDatabaseGUID = GUID{
		0xcb, 0xb2, 0x19, 0xd7,
		0x3a, 0x3d,
		0x96, 0x45,
		0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
	}

	// EFICertX509GUID is the SignatureType GUID for X.509 certificates in an
	// EFI_SIGNATURE_LIST. {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
	EFICertX509GUID = GUID{
		0xa1, 0x59, 0xc0, 0xa5,
		0xe4, 0x94,
		0xa7, 0x4a,
		0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
	}
)

// secureBootAttrs are the standard EFI attributes for Secure Boot variables.
const secureBootAttrs = AttrNonVolatile | AttrBootServiceAccess | AttrRuntimeAccess

// BuildEFISignatureList encodes a single DER-encoded X.509 certificate into an
// EFI_SIGNATURE_LIST binary blob suitable for writing into PK, KEK, db or dbx.
//
// ownerGUID identifies the entity that owns the certificate (e.g.
// EFIGlobalVariableGUID for vendor keys). certDER must be a valid DER-encoded
// X.509 certificate; no structural validation is performed.
//
// Layout (all little-endian):
//
//	 0-15  SignatureType GUID (EFICertX509GUID)
//	16-19  SignatureListSize
//	20-23  SignatureHeaderSize (always 0 for X.509)
//	24-27  SignatureSize = 16 + len(certDER)
//	28-43  SignatureOwner GUID
//	44-…   certDER bytes
func BuildEFISignatureList(ownerGUID GUID, certDER []byte) []byte {
	sigSize := uint32(16 + len(certDER))
	listSize := uint32(28) + sigSize
	buf := make([]byte, listSize)
	copy(buf[0:16], EFICertX509GUID[:])
	binary.LittleEndian.PutUint32(buf[16:], listSize)
	binary.LittleEndian.PutUint32(buf[20:], 0)
	binary.LittleEndian.PutUint32(buf[24:], sigSize)
	copy(buf[28:44], ownerGUID[:])
	copy(buf[44:], certDER)
	return buf
}

// SecureBootKeys holds the three certificates required to activate Secure Boot.
// All certificates must be DER-encoded X.509.
type SecureBootKeys struct {
	// PK is the Platform Key certificate. Writing PK last activates User Mode.
	PK []byte
	// KEK is the Key Exchange Key certificate.
	KEK []byte
	// DB is the allowed-signatures database certificate.
	DB []byte
}

// EnrollSecureBootKeys writes PK, KEK and db into the variable store at store.
// Variables are enrolled in the order db → KEK → PK: writing PK last causes
// OVMF to leave Setup Mode and activate Secure Boot (User Mode). After that,
// any PK or KEK change must be signed with the previous key.
func EnrollSecureBootKeys(store VariableStore, keys SecureBootKeys) error {
	type entry struct {
		name string
		ns   GUID
		cert []byte
	}
	for _, e := range []entry{
		{"db", EFIImageSecurityDatabaseGUID, keys.DB},
		{"KEK", EFIGlobalVariableGUID, keys.KEK},
		{"PK", EFIGlobalVariableGUID, keys.PK},
	} {
		if err := enrollOne(store, e.name, e.ns, e.cert); err != nil {
			return err
		}
	}
	return nil
}

// enrollOne writes a single Secure Boot variable into the store.
func enrollOne(store VariableStore, name string, ns GUID, certDER []byte) error {
	sl := BuildEFISignatureList(EFIGlobalVariableGUID, certDER)
	if err := store.Set(Variable{
		Name:       name,
		GUID:       ns,
		Attributes: secureBootAttrs,
		Data:       sl,
	}); err != nil {
		return fmt.Errorf("uefi: enroll %s: %w", name, err)
	}
	return nil
}

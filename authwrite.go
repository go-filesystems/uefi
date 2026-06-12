package filesystem_uefi

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Time-based authenticated variable support (EFI_VARIABLE_AUTHENTICATION_2).
//
// UEFI Secure Boot variables (PK, KEK, db, dbx) carry the
// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute. A write to
// such a variable must be prefixed with an EFI_VARIABLE_AUTHENTICATION_2
// descriptor: an EFI_TIME timestamp followed by a WIN_CERTIFICATE_UEFI_GUID
// that wraps a detached PKCS#7 SignedData. The signature is computed over the
// digest of
//
//	VariableName || VendorGuid || Attributes || TimeStamp || Data
//
// where VariableName is the UTF-16LE name *without* its trailing NUL, and the
// fields are concatenated in their on-the-wire byte order (UEFI 2.10 §8.2.2).
//
// This file implements building, signing and parsing that descriptor. Signing
// uses the Go standard library only (crypto/x509 + a minimal PKCS#7
// SignedData encoder), so the module pulls in no third-party dependency.

// winCertRevision is WIN_CERTIFICATE.wRevision for UEFI authenticated writes.
const winCertRevision = 0x0200

// winCertTypeEFIGUID is WIN_CERTIFICATE.wCertificateType for a
// WIN_CERTIFICATE_UEFI_GUID (WIN_CERT_TYPE_EFI_GUID).
const winCertTypeEFIGUID = 0x0EF1

// winCertHeaderSize is sizeof(WIN_CERTIFICATE): dwLength(4) + wRevision(2) +
// wCertificateType(2).
const winCertHeaderSize = 8

// efiTimeSize is sizeof(EFI_TIME) on the wire.
const efiTimeSize = 16

// EFICertTypePKCS7GUID is EFI_CERT_TYPE_PKCS7_GUID, the WIN_CERTIFICATE_UEFI_GUID
// CertType for a PKCS#7 SignedData payload.
// {4aafd29d-68df-49ee-8aa9-347d375665a7}
var EFICertTypePKCS7GUID = GUID{
	0x9d, 0xd2, 0xaf, 0x4a,
	0xdf, 0x68,
	0xee, 0x49,
	0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
}

// EFITime mirrors EFI_TIME. Only the fields UEFI authenticated writes care
// about are populated; Nanosecond/TimeZone/Daylight are written as zero, which
// is what edk2 SetVariable produces for an authenticated payload.
type EFITime struct {
	Year       uint16
	Month      uint8
	Day        uint8
	Hour       uint8
	Minute     uint8
	Second     uint8
	Nanosecond uint32
	TimeZone   int16
	Daylight   uint8
}

// EFITimeFromGoTime converts a Go time (interpreted in UTC) into the EFI_TIME
// fields UEFI authenticated writes use. Sub-second precision and time-zone
// offsets are dropped to zero, matching edk2's authenticated SetVariable.
func EFITimeFromGoTime(t time.Time) EFITime {
	t = t.UTC()
	return EFITime{
		Year:   uint16(t.Year()),
		Month:  uint8(t.Month()),
		Day:    uint8(t.Day()),
		Hour:   uint8(t.Hour()),
		Minute: uint8(t.Minute()),
		Second: uint8(t.Second()),
	}
}

// Marshal encodes EFI_TIME into its 16-byte on-disk layout (little-endian):
//
//	0..2   Year
//	2      Month
//	3      Day
//	4      Hour
//	5      Minute
//	6      Second
//	7      Pad1
//	8..12  Nanosecond
//	12..14 TimeZone (int16)
//	14     Daylight
//	15     Pad2
func (e EFITime) Marshal() []byte {
	b := make([]byte, efiTimeSize)
	binary.LittleEndian.PutUint16(b[0:], e.Year)
	b[2] = e.Month
	b[3] = e.Day
	b[4] = e.Hour
	b[5] = e.Minute
	b[6] = e.Second
	binary.LittleEndian.PutUint32(b[8:], e.Nanosecond)
	binary.LittleEndian.PutUint16(b[12:], uint16(e.TimeZone))
	b[14] = e.Daylight
	return b
}

// parseEFITime decodes the 16-byte EFI_TIME layout produced by Marshal.
func parseEFITime(b []byte) (EFITime, error) {
	if len(b) < efiTimeSize {
		return EFITime{}, errors.New("uefi: EFI_TIME truncated")
	}
	return EFITime{
		Year:       binary.LittleEndian.Uint16(b[0:]),
		Month:      b[2],
		Day:        b[3],
		Hour:       b[4],
		Minute:     b[5],
		Second:     b[6],
		Nanosecond: binary.LittleEndian.Uint32(b[8:]),
		TimeZone:   int16(binary.LittleEndian.Uint16(b[12:])),
		Daylight:   b[14],
	}, nil
}

// AuthSigner holds the private key and certificate used to sign an
// authenticated variable write. The certificate's public key must match the
// private key, and the certificate (or its issuer chain) must be enrolled in
// the relevant key database (PK signs PK/KEK, KEK signs db/dbx, …).
type AuthSigner struct {
	// Key is the signing private key. Only *rsa.PrivateKey is supported,
	// which is what every shipping Secure Boot tool (sbsign, efitools) and
	// edk2's authenticated SetVariable verifier accept.
	Key *rsa.PrivateKey
	// Cert is the signer certificate, included in the PKCS#7 SignedData.
	Cert *x509.Certificate
}

// digestTBS returns the bytes the UEFI authenticated-write signature is
// computed over: VariableName(UTF-16LE, no NUL) || VendorGuid || Attributes ||
// TimeStamp || Data, per UEFI 2.10 §8.2.2.
func digestTBS(name string, guid GUID, attrs Attributes, ts EFITime, data []byte) []byte {
	var buf bytes.Buffer
	// Name as UTF-16LE WITHOUT the trailing NUL terminator.
	nameU16 := EncodeUTF16LE(name)
	if len(nameU16) >= 2 {
		nameU16 = nameU16[:len(nameU16)-2]
	}
	buf.Write(nameU16)
	buf.Write(guid[:])
	var attrBuf [4]byte
	binary.LittleEndian.PutUint32(attrBuf[:], uint32(attrs))
	buf.Write(attrBuf[:])
	buf.Write(ts.Marshal())
	buf.Write(data)
	return buf.Bytes()
}

// BuildAuthentication2 constructs the serialized EFI_VARIABLE_AUTHENTICATION_2
// descriptor for an authenticated write of variable name/guid carrying attrs
// and data, signed by signer at timestamp ts.
//
// The returned bytes are the descriptor only (EFI_TIME +
// WIN_CERTIFICATE_UEFI_GUID); to perform the write, prepend them to data — see
// WriteAuthenticatedVariable.
//
// attrs must include AttrTimeBasedAuthenticatedWriteAccess; the signature is
// bound to the exact attribute value, so the caller must pass the same attrs it
// will write.
func BuildAuthentication2(name string, guid GUID, attrs Attributes, data []byte, ts EFITime, signer AuthSigner) ([]byte, error) {
	if signer.Key == nil || signer.Cert == nil {
		return nil, errors.New("uefi: BuildAuthentication2: signer key and cert are required")
	}
	if attrs&AttrTimeBasedAuthenticatedWriteAccess == 0 {
		return nil, errors.New("uefi: BuildAuthentication2: attrs must set AttrTimeBasedAuthenticatedWriteAccess")
	}

	tbs := digestTBS(name, guid, attrs, ts, data)
	p7, err := signPKCS7Detached(tbs, signer)
	if err != nil {
		return nil, fmt.Errorf("uefi: BuildAuthentication2: %w", err)
	}

	// WIN_CERTIFICATE_UEFI_GUID = WIN_CERTIFICATE Hdr + CertType GUID + CertData.
	certLen := winCertHeaderSize + len(EFICertTypePKCS7GUID) + len(p7)
	out := make([]byte, 0, efiTimeSize+certLen)
	out = append(out, ts.Marshal()...)

	hdr := make([]byte, winCertHeaderSize+len(EFICertTypePKCS7GUID))
	binary.LittleEndian.PutUint32(hdr[0:], uint32(certLen))
	binary.LittleEndian.PutUint16(hdr[4:], winCertRevision)
	binary.LittleEndian.PutUint16(hdr[6:], winCertTypeEFIGUID)
	copy(hdr[8:], EFICertTypePKCS7GUID[:])
	out = append(out, hdr...)
	out = append(out, p7...)
	return out, nil
}

// Authentication2 is a parsed EFI_VARIABLE_AUTHENTICATION_2 descriptor.
type Authentication2 struct {
	// TimeStamp is the EFI_TIME the signature was bound to.
	TimeStamp EFITime
	// CertType is the WIN_CERTIFICATE_UEFI_GUID CertType (PKCS#7 for Secure Boot).
	CertType GUID
	// PKCS7 is the raw DER PKCS#7 SignedData blob (CertData).
	PKCS7 []byte
}

// ParseAuthentication2 decodes a serialized EFI_VARIABLE_AUTHENTICATION_2
// descriptor produced by BuildAuthentication2. It validates the
// WIN_CERTIFICATE header fields and returns the timestamp, cert type and the
// embedded PKCS#7 blob. It does not verify the signature.
func ParseAuthentication2(b []byte) (Authentication2, error) {
	var a Authentication2
	if len(b) < efiTimeSize+winCertHeaderSize+len(EFICertTypePKCS7GUID) {
		return a, errors.New("uefi: ParseAuthentication2: buffer too small")
	}
	ts, err := parseEFITime(b[:efiTimeSize])
	if err != nil {
		return a, err
	}
	a.TimeStamp = ts

	cert := b[efiTimeSize:]
	dwLength := binary.LittleEndian.Uint32(cert[0:])
	wRevision := binary.LittleEndian.Uint16(cert[4:])
	wCertType := binary.LittleEndian.Uint16(cert[6:])
	if wRevision != winCertRevision {
		return a, fmt.Errorf("uefi: ParseAuthentication2: bad wRevision %#x", wRevision)
	}
	if wCertType != winCertTypeEFIGUID {
		return a, fmt.Errorf("uefi: ParseAuthentication2: bad wCertificateType %#x", wCertType)
	}
	if int(dwLength) < winCertHeaderSize+len(EFICertTypePKCS7GUID) || int(dwLength) > len(cert) {
		return a, fmt.Errorf("uefi: ParseAuthentication2: bad dwLength %d", dwLength)
	}
	copy(a.CertType[:], cert[8:8+len(a.CertType)])
	a.PKCS7 = append([]byte(nil), cert[8+len(a.CertType):dwLength]...)
	return a, nil
}

// WriteAuthenticatedVariable performs a time-based authenticated write of a
// Secure Boot variable into store. It builds the EFI_VARIABLE_AUTHENTICATION_2
// descriptor, signs the time-to-be-signed payload with signer, prepends the
// descriptor to data and writes the result with the
// AttrTimeBasedAuthenticatedWriteAccess attribute set.
//
// The resulting on-disk variable Data is exactly what edk2's
// VariableServicesSmm expects from a SetVariable() call with an
// EFI_VARIABLE_AUTHENTICATION_2 prefix: [descriptor || data].
//
// This constructs and signs the payload only; the store backend does not
// itself verify the signature (firmware does that at runtime). attrs, if zero,
// defaults to the standard Secure Boot attribute set plus the time-based-auth
// flag.
func WriteAuthenticatedVariable(s VariableStore, name string, guid GUID, attrs Attributes, data []byte, ts EFITime, signer AuthSigner) error {
	if attrs == 0 {
		attrs = secureBootAttrs | AttrTimeBasedAuthenticatedWriteAccess
	}
	attrs |= AttrTimeBasedAuthenticatedWriteAccess

	desc, err := BuildAuthentication2(name, guid, attrs, data, ts, signer)
	if err != nil {
		return err
	}
	payload := make([]byte, 0, len(desc)+len(data))
	payload = append(payload, desc...)
	payload = append(payload, data...)

	if err := s.Set(Variable{
		Name:       name,
		GUID:       guid,
		Attributes: attrs,
		Data:       payload,
	}); err != nil {
		return fmt.Errorf("uefi: WriteAuthenticatedVariable %q: %w", name, err)
	}
	return nil
}

// --- Minimal PKCS#7 SignedData encoder (RFC 2315 / detached) -------------
//
// The Go standard library has no PKCS#7 *producer*, and this module forbids
// third-party dependencies. We therefore emit the small, fixed SignedData
// shape that UEFI authenticated writes require: a single signer, no
// authenticated attributes, detached content (eContent absent), SHA-256
// digest, RSA (rsaEncryption / PKCS#1 v1.5) signature. This is precisely the
// structure produced by `sbvarsign`/`sign-efi-sig-list` and accepted by edk2's
// Pkcs7Verify.

var (
	oidData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncrypt   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	pkcs7SignerVer  = 1
	pkcs7SignedVer  = 1
	digestAlgorithm = crypto.SHA256
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerial struct {
	IssuerRaw    asn1.RawValue
	SerialNumber *big.Int
}

type contentInfoEmpty struct {
	ContentType asn1.ObjectIdentifier
}

type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           algorithmIdentifier
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfoEmpty
	Certificates     asn1.RawValue       `asn1:"tag:0,optional"`
	SignerInfos      []signerInfo        `asn1:"set"`
}

type outerContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// signPKCS7Detached produces a DER-encoded PKCS#7 SignedData over content,
// detached (the content itself is not embedded), using SHA-256 + RSA.
func signPKCS7Detached(content []byte, signer AuthSigner) ([]byte, error) {
	h := digestAlgorithm.New()
	h.Write(content)
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.Key, digestAlgorithm, digest)
	if err != nil {
		return nil, fmt.Errorf("rsa sign: %w", err)
	}

	si := signerInfo{
		Version: pkcs7SignerVer,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerRaw:    asn1.RawValue{FullBytes: signer.Cert.RawIssuer},
			SerialNumber: signer.Cert.SerialNumber,
		},
		DigestAlgorithm:           algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
		DigestEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncrypt, Parameters: asn1.NullRawValue},
		EncryptedDigest:           sig,
	}

	sd := signedData{
		Version:          pkcs7SignedVer,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}},
		ContentInfo:      contentInfoEmpty{ContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signer.Cert.Raw,
		},
		SignerInfos: []signerInfo{si},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}

	// Wrap the SignedData in a [0] EXPLICIT context tag, as PKCS#7
	// ContentInfo requires. asn1.Marshal of a RawValue with only FullBytes
	// set emits those bytes verbatim and would drop a struct-level explicit
	// tag, so we build the wrapper RawValue ourselves.
	outer := outerContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	out, err := asn1.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("marshal ContentInfo: %w", err)
	}
	return out, nil
}

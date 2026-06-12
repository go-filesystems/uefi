package filesystem_uefi_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	fsuefi "github.com/go-filesystems/uefi"
)

// makeTestSigner builds a throw-away self-signed RSA cert + key for use as an
// authenticated-write signer. No external fixture or tool is needed.
func makeTestSigner(t *testing.T) fsuefi.AuthSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd),
		Subject:      pkix.Name{CommonName: "go-filesystems test PK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return fsuefi.AuthSigner{Key: key, Cert: cert}
}

// TestEFITimeRoundTrip verifies Marshal produces the 16-byte EFI_TIME layout
// and that the populated fields survive a build/parse cycle.
func TestEFITimeRoundTrip(t *testing.T) {
	ts := fsuefi.EFITimeFromGoTime(time.Date(2026, 6, 12, 13, 45, 7, 999, time.UTC))
	b := ts.Marshal()
	if len(b) != 16 {
		t.Fatalf("EFI_TIME marshalled to %d bytes, want 16", len(b))
	}
	if got := binary.LittleEndian.Uint16(b[0:]); got != 2026 {
		t.Fatalf("Year = %d, want 2026", got)
	}
	if b[2] != 6 || b[3] != 12 || b[4] != 13 || b[5] != 45 || b[6] != 7 {
		t.Fatalf("date/time bytes wrong: %v", b[2:7])
	}
	// Sub-second precision must be dropped to zero (edk2 behaviour).
	if binary.LittleEndian.Uint32(b[8:]) != 0 {
		t.Fatalf("Nanosecond should be zero, got %d", binary.LittleEndian.Uint32(b[8:]))
	}
}

// TestBuildAuthentication2_RoundTrip builds an EFI_VARIABLE_AUTHENTICATION_2
// descriptor and parses it back, checking the timestamp, cert type and that
// the embedded PKCS#7 is a well-formed SignedData whose signature verifies
// against the signer's public key over the correct time-to-be-signed bytes.
func TestBuildAuthentication2_RoundTrip(t *testing.T) {
	signer := makeTestSigner(t)
	name := "PK"
	guid := fsuefi.EFIGlobalVariableGUID
	attrs := fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess |
		fsuefi.AttrRuntimeAccess | fsuefi.AttrTimeBasedAuthenticatedWriteAccess
	data := fsuefi.BuildEFISignatureList(fsuefi.EFIGlobalVariableGUID, signer.Cert.Raw)
	ts := fsuefi.EFITimeFromGoTime(time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC))

	desc, err := fsuefi.BuildAuthentication2(name, guid, attrs, data, ts, signer)
	if err != nil {
		t.Fatalf("BuildAuthentication2: %v", err)
	}

	parsed, err := fsuefi.ParseAuthentication2(desc)
	if err != nil {
		t.Fatalf("ParseAuthentication2: %v", err)
	}
	if parsed.TimeStamp != ts {
		t.Fatalf("timestamp mismatch: got %+v want %+v", parsed.TimeStamp, ts)
	}
	if parsed.CertType != fsuefi.EFICertTypePKCS7GUID {
		t.Fatalf("cert type mismatch: got %v", parsed.CertType)
	}
	if len(parsed.PKCS7) == 0 {
		t.Fatal("empty PKCS#7 payload")
	}

	// The WIN_CERTIFICATE header dwLength must cover everything after EFI_TIME.
	dwLength := binary.LittleEndian.Uint32(desc[16:])
	if int(dwLength) != len(desc)-16 {
		t.Fatalf("dwLength = %d, want %d", dwLength, len(desc)-16)
	}

	// Reconstruct the time-to-be-signed bytes the UEFI spec defines and verify
	// the RSA signature embedded in the PKCS#7 over its SHA-256 digest.
	verifyAuthSignature(t, parsed.PKCS7, signer, name, guid, attrs, ts, data)
}

// verifyAuthSignature decodes the minimal PKCS#7 SignedData and checks the
// signer's RSA signature against the recomputed time-to-be-signed digest.
func verifyAuthSignature(t *testing.T, p7 []byte, signer fsuefi.AuthSigner, name string, guid fsuefi.GUID, attrs fsuefi.Attributes, ts fsuefi.EFITime, data []byte) {
	t.Helper()

	// Outer ContentInfo: { contentType OID, [0] EXPLICIT content }.
	var outer struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(p7, &outer); err != nil {
		t.Fatalf("unmarshal outer ContentInfo: %v", err)
	}
	wantSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	if !outer.ContentType.Equal(wantSignedData) {
		t.Fatalf("outer contentType = %v, want signedData", outer.ContentType)
	}

	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type issuerSerial struct {
		IssuerRaw    asn1.RawValue
		SerialNumber *big.Int
	}
	type sInfo struct {
		Version                   int
		IssuerAndSerialNumber     issuerSerial
		DigestAlgorithm           algID
		DigestEncryptionAlgorithm algID
		EncryptedDigest           []byte
	}
	type cInfo struct {
		ContentType asn1.ObjectIdentifier
	}
	type sData struct {
		Version          int
		DigestAlgorithms []algID `asn1:"set"`
		ContentInfo      cInfo
		Certificates     asn1.RawValue `asn1:"tag:0,optional"`
		SignerInfos      []sInfo       `asn1:"set"`
	}
	var sd sData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("got %d signerInfos, want 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]

	// Recompute time-to-be-signed: name(UTF-16LE no NUL) || guid || attrs || ts || data.
	nameU16 := fsuefi.EncodeUTF16LE(name)
	nameU16 = nameU16[:len(nameU16)-2] // strip NUL
	var tbs bytes.Buffer
	tbs.Write(nameU16)
	tbs.Write(guid[:])
	var ab [4]byte
	binary.LittleEndian.PutUint32(ab[:], uint32(attrs))
	tbs.Write(ab[:])
	tbs.Write(ts.Marshal())
	tbs.Write(data)

	digest := sha256.Sum256(tbs.Bytes())
	pub, ok := signer.Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("signer cert public key is not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], si.EncryptedDigest); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Sanity: the embedded certificate matches the signer.
	if !bytes.Equal(sd.Certificates.Bytes, signer.Cert.Raw) {
		t.Fatal("embedded certificate does not match signer cert")
	}
	if si.IssuerAndSerialNumber.SerialNumber.Cmp(signer.Cert.SerialNumber) != 0 {
		t.Fatal("signerInfo serial number mismatch")
	}
}

// TestBuildAuthentication2_RequiresAuthAttr rejects a build that forgets the
// time-based-auth attribute, since the signature is bound to the exact attrs.
func TestBuildAuthentication2_RequiresAuthAttr(t *testing.T) {
	signer := makeTestSigner(t)
	_, err := fsuefi.BuildAuthentication2("PK", fsuefi.EFIGlobalVariableGUID,
		fsuefi.AttrNonVolatile, []byte{0x01}, fsuefi.EFITime{Year: 2026}, signer)
	if err == nil {
		t.Fatal("expected error when AttrTimeBasedAuthenticatedWriteAccess is unset")
	}
}

// TestBuildAuthentication2_MissingSigner rejects an empty signer.
func TestBuildAuthentication2_MissingSigner(t *testing.T) {
	_, err := fsuefi.BuildAuthentication2("PK", fsuefi.EFIGlobalVariableGUID,
		fsuefi.AttrTimeBasedAuthenticatedWriteAccess, nil, fsuefi.EFITime{}, fsuefi.AuthSigner{})
	if err == nil {
		t.Fatal("expected error with nil signer key/cert")
	}
}

// TestParseAuthentication2_Rejects checks that malformed descriptors are
// rejected rather than panicking.
func TestParseAuthentication2_Rejects(t *testing.T) {
	if _, err := fsuefi.ParseAuthentication2([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error for short buffer")
	}
	// Valid EFI_TIME but garbage WIN_CERTIFICATE header.
	bad := make([]byte, 16+8+16)
	binary.LittleEndian.PutUint32(bad[16:], uint32(len(bad)-16))
	// wRevision left as 0 (invalid).
	if _, err := fsuefi.ParseAuthentication2(bad); err == nil {
		t.Fatal("expected error for bad wRevision")
	}
}

// TestWriteAuthenticatedVariable writes a signed PK into an OVMF-format store
// and verifies the stored variable carries the time-based-auth attribute and a
// re-parseable EFI_VARIABLE_AUTHENTICATION_2 prefix in front of the data.
func TestWriteAuthenticatedVariable(t *testing.T) {
	signer := makeTestSigner(t)
	s, _ := openStoreWith(t, 64*1024)

	guid := fsuefi.EFIGlobalVariableGUID
	attrs := fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess |
		fsuefi.AttrRuntimeAccess | fsuefi.AttrTimeBasedAuthenticatedWriteAccess
	data := fsuefi.BuildEFISignatureList(guid, signer.Cert.Raw)
	ts := fsuefi.EFITimeFromGoTime(time.Now())

	if err := fsuefi.WriteAuthenticatedVariable(s, "PK", guid, attrs, data, ts, signer); err != nil {
		t.Fatalf("WriteAuthenticatedVariable: %v", err)
	}

	v, err := s.Get("PK", guid)
	if err != nil {
		t.Fatalf("Get PK: %v", err)
	}
	if v.Attributes&fsuefi.AttrTimeBasedAuthenticatedWriteAccess == 0 {
		t.Fatal("stored PK missing time-based-auth attribute")
	}

	// The stored data must be [descriptor || data]; the descriptor must parse
	// and the trailing bytes must equal the original signature list.
	parsed, err := fsuefi.ParseAuthentication2(v.Data)
	if err != nil {
		t.Fatalf("ParseAuthentication2 on stored data: %v", err)
	}
	if parsed.CertType != fsuefi.EFICertTypePKCS7GUID {
		t.Fatalf("stored cert type mismatch: %v", parsed.CertType)
	}
	descLen := 16 + binary.LittleEndian.Uint32(v.Data[16:])
	if !bytes.Equal(v.Data[descLen:], data) {
		t.Fatal("stored data tail does not match original signature list")
	}
}

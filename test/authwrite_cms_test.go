package filesystem_uefi_test

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	fsuefi "github.com/go-filesystems/uefi"
)

// sha256DigestOID is the DER body of id-sha256, the bytes edk2's
// FindHashAlgorithmIndex (SecurityPkg/Library/AuthVariableLib/AuthService.c)
// compares against at a fixed offset of the PKCS#7 blob.
var sha256DigestOID = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}

func buildAuthForTest(t *testing.T) (p7, tbs []byte, signer fsuefi.AuthSigner) {
	t.Helper()
	signer = makeTestSigner(t)
	name := "db"
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
	return parsed.PKCS7, specTBS(name, guid, attrs, ts, data), signer
}

// TestAuthPKCS7_EDK2Layout pins what edk2 reads positionally before it ever
// calls Pkcs7Verify: AuthService.c FindHashAlgorithmIndex looks for the digest
// OID at byte 32 of a ContentInfo-wrapped blob (13 when unwrapped) and needs
// the two-byte length form (0x82) on the SignedData SEQUENCE (byte 20). The
// digest AlgorithmIdentifier's parameters (NULL or absent) do not move the OID.
func TestAuthPKCS7_EDK2Layout(t *testing.T) {
	p7, _, _ := buildAuthForTest(t)
	if len(p7) < 32+len(sha256DigestOID) {
		t.Fatalf("PKCS#7 only %d bytes", len(p7))
	}
	if p7[1]&0x82 != 0x82 || p7[20]&0x82 != 0x82 {
		t.Fatalf("length bytes %#x, %#x: edk2 needs the 0x82 form", p7[1], p7[20])
	}
	if !bytes.Equal(p7[32:32+len(sha256DigestOID)], sha256DigestOID) {
		t.Fatalf("digest OID not at offset 32: % x", p7[26:48])
	}
}

// TestAuthPKCS7_OpenSSLVerifies is the oracle: the reference implementation
// edk2's Pkcs7Verify wraps (PKCS7_verify, PKCS7_BINARY, partial chain, any
// purpose) must accept the detached signature over the signed bytes, and must
// refuse it over other bytes.
func TestAuthPKCS7_OpenSSLVerifies(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	p7, tbs, signer := buildAuthForTest(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p7f := write("sig.p7", p7)
	certf := write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.Cert.Raw}))
	var tbsPath string
	run := func(content string) error {
		cmd := exec.Command(openssl, "smime", "-verify", "-binary", "-inform", "DER",
			"-in", p7f, "-content", content, "-CAfile", certf, "-purpose", "any",
			"-partial_chain", "-no_check_time", "-out", filepath.Join(dir, "out"))
		cmd.Stdin = nil
		out, err := cmd.CombinedOutput()
		if err != nil && content == tbsPath {
			t.Logf("openssl: %s", out)
		}
		return err
	}
	tbsPath = write("tbs.bin", tbs)
	if err := run(tbsPath); err != nil {
		t.Fatalf("openssl smime -verify rejected the signature: %v", err)
	}
	if err := run(write("other.bin", append(bytes.Clone(tbs), 0))); err == nil {
		t.Fatal("openssl accepted the signature over altered content")
	}
}

// TestBuildAuthentication2_RefusesIncompleteSigner: a nil key reaches cms.Sign
// as a typed-nil crypto.Signer (non-nil interface), so the refusal in
// BuildAuthentication2 is the only thing standing before a nil dereference.
func TestBuildAuthentication2_RefusesIncompleteSigner(t *testing.T) {
	full := makeTestSigner(t)
	attrs := fsuefi.AttrNonVolatile | fsuefi.AttrTimeBasedAuthenticatedWriteAccess
	ts := fsuefi.EFITimeFromGoTime(time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC))
	for name, s := range map[string]fsuefi.AuthSigner{
		"no key":  {Cert: full.Cert},
		"no cert": {Key: full.Key},
		"neither": {},
	} {
		if _, err := fsuefi.BuildAuthentication2("db", fsuefi.EFIGlobalVariableGUID, attrs, []byte{1}, ts, s); err == nil {
			t.Errorf("%s: signer accepted", name)
		}
	}
}

// specTBS is UEFI 2.10 §8.2.2 spelled out independently of the package:
// name (UTF-16LE, no NUL) || GUID || attributes || EFI_TIME || data.
func specTBS(name string, guid fsuefi.GUID, attrs fsuefi.Attributes, ts fsuefi.EFITime, data []byte) []byte {
	var b bytes.Buffer
	for _, r := range name {
		b.Write([]byte{byte(r), byte(r >> 8)})
	}
	b.Write(guid[:])
	var a [4]byte
	binary.LittleEndian.PutUint32(a[:], uint32(attrs))
	b.Write(a[:])
	b.Write(ts.Marshal())
	b.Write(data)
	return b.Bytes()
}

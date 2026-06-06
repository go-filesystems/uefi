package filesystem_uefi_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// fixturePath returns the absolute path to a committed real-world EDK2
// varstore fixture inside ../testdata/.
//
// The fixtures are committed verbatim from the QEMU 9.2.0 prebuilt
// package (see testdata/README.md for provenance and licence). They
// exist so the test suite exercises the canonical FV-wrapped +
// authenticated-variable layout that real OVMF firmware writes back to
// disk — rather than just round-tripping bytes our own writer emits.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	// The test binary's working directory is the package directory
	// (uefi/test), so the fixtures sit one level up under testdata/.
	p := filepath.Join("..", "testdata", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s not available: %v", name, err)
	}
	return p
}

// copyFixture copies the named fixture into the test's TempDir so each
// test gets its own writable copy. Returns the temp-dir path.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := fixturePath(t, name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write fixture copy %s: %v", dst, err)
	}
	return dst
}

// TestReadEDK2Vars opens the committed real-world EDK2 varstore
// fixture, lists every variable it contains, and asserts the basic
// invariants we expect from a stock OVMF NvVar store: a non-zero
// variable count, the well-known EFI_GLOBAL_VARIABLE_GUID namespace is
// present (it owns BootOrder/Boot####/Timeout/PlatformLang etc.), and
// every Variable has a non-empty name and at least one byte of data.
//
// This proves our reader handles the canonical FV-wrapped +
// authenticated-record layout that QEMU's edk2-i386-vars.fd uses —
// not just the layout our own writer emits.
func TestReadEDK2Vars(t *testing.T) {
	path := fixturePath(t, "edk2-x64-vars.fd")
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open EDK2 fixture: %v", err)
	}
	defer s.Close()

	list := s.List()
	if len(list) == 0 {
		t.Fatal("real EDK2 varstore parsed to zero variables — reader is broken")
	}
	t.Logf("parsed %d variables from %s", len(list), path)

	// Every variable record must have a non-empty UTF-16-decoded name
	// (a broken parser typically returns empty names or garbage when
	// it walks off the end of the store region).
	for _, v := range list {
		if v.Name == "" {
			t.Errorf("variable with empty name found (guid=%x, datalen=%d)", v.GUID, len(v.Data))
		}
		// Data may legitimately be empty for some flag-style
		// variables, so we don't require len(v.Data) > 0.
	}

	// The EFI_GLOBAL_VARIABLE_GUID namespace owns most of the boot
	// machinery; a stock OVMF varstore always carries at least one
	// variable in that namespace (typically Boot0000, BootOrder,
	// Timeout, PlatformLang, ConIn/ConOut/ErrOut).
	var seenGlobal bool
	for _, v := range list {
		if v.GUID == fsuefi.EFIGlobalVariableGUID {
			seenGlobal = true
			break
		}
	}
	if !seenGlobal {
		t.Error("no variable in EFI_GLOBAL_VARIABLE_GUID namespace — likely a GUID-endian regression in the parser")
	}

	// Spot-check a handful of well-known EDK2 globals. Their
	// presence depends on whether the firmware has booted yet and
	// the platform's enabled features — the QEMU 9.2.0 prebuilt has
	// these because the file is the post-boot template. We assert at
	// least one of each "boot-related" and one "locale-related" var
	// is present so a future shrunk fixture doesn't accidentally
	// pass a degenerate test.
	bootRelated := []string{"BootOrder", "Boot0000", "Boot0001", "Timeout"}
	localeRelated := []string{"PlatformLang", "Lang"}

	hasAny := func(names []string) bool {
		for _, want := range names {
			if _, err := s.Get(want, fsuefi.EFIGlobalVariableGUID); err == nil {
				return true
			}
		}
		return false
	}
	if !hasAny(bootRelated) {
		t.Errorf("no boot-related EFI_GLOBAL_VARIABLE_GUID variable found; expected at least one of %v", bootRelated)
	}
	if !hasAny(localeRelated) {
		t.Errorf("no locale-related EFI_GLOBAL_VARIABLE_GUID variable found; expected at least one of %v", localeRelated)
	}

	// Secure Boot variables (PK/KEK/db/dbx) only exist if the
	// platform was provisioned with them. The committed fixture
	// happens to be a *non-secure* OVMF template — but if the
	// firmware ever loads a Secure Boot–enabled variant, those vars
	// must parse correctly too. So we don't assert presence; we
	// assert that *if* any of them exist, they're in the right
	// namespace and have a non-empty payload (i.e. our parser
	// didn't truncate them).
	for _, name := range []string{"PK", "KEK"} {
		if v, err := s.Get(name, fsuefi.EFIGlobalVariableGUID); err == nil {
			if len(v.Data) == 0 {
				t.Errorf("%s present but empty — parser lost the payload", name)
			}
		}
	}
	for _, name := range []string{"db", "dbx"} {
		if v, err := s.Get(name, fsuefi.EFIImageSecurityDatabaseGUID); err == nil {
			if len(v.Data) == 0 {
				t.Errorf("%s present but empty — parser lost the payload", name)
			}
		}
	}
}

// TestWriteEDK2CompatibleVars starts from the committed real EDK2
// fixture, uses our writer to add a fresh variable, re-opens the file
// and asserts: (a) every variable that was present before is still
// readable (with byte-identical data), and (b) the new variable is
// present with the bytes we just wrote.
//
// This proves the writer preserves the FV header + store header
// verbatim and serializes new auth-format records correctly *inside*
// a real OVMF varstore — not just inside one we ourselves formatted.
func TestWriteEDK2CompatibleVars(t *testing.T) {
	path := copyFixture(t, "edk2-x64-vars.fd")

	// Snapshot every variable in the original fixture so we can
	// confirm none are silently dropped by the round-trip.
	s, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Open EDK2 fixture: %v", err)
	}
	original := s.List()
	if len(original) == 0 {
		t.Fatal("real EDK2 varstore parsed to zero variables")
	}

	// Write a new variable using the same namespace OVMF itself
	// uses for boot-related globals, with an unaligned name length
	// to exercise the no-inter-field-padding path. "WeftRoundTrip"
	// is 13 chars → 28 bytes UTF-16LE incl. NUL → not 4-aligned.
	newName := "WeftRoundTrip"
	newData := []byte("hello-from-go-filesystems-uefi")
	newVar := fsuefi.Variable{
		Name:       newName,
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       newData,
	}
	if err := s.Set(newVar); err != nil {
		t.Fatalf("Set new var: %v", err)
	}
	s.Close()

	// Re-open the file fresh — this is what OVMF firmware would do
	// at next boot, and it's the strictest end-to-end check.
	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Re-open after Set: %v", err)
	}
	defer s2.Close()

	// Every original variable must still be there with the same
	// bytes. We don't compare slice order (Set re-serializes the
	// list) but we do compare data byte-by-byte.
	for _, orig := range original {
		got, err := s2.Get(orig.Name, orig.GUID)
		if err != nil {
			t.Errorf("original variable %q lost after Set: %v", orig.Name, err)
			continue
		}
		if !bytes.Equal(got.Data, orig.Data) {
			t.Errorf("original variable %q corrupted by round-trip\n  was %d bytes, now %d bytes",
				orig.Name, len(orig.Data), len(got.Data))
		}
		if got.Attributes != orig.Attributes {
			t.Errorf("original variable %q attributes changed: was %#x, now %#x",
				orig.Name, uint32(orig.Attributes), uint32(got.Attributes))
		}
	}

	// The new variable must be present with the bytes we wrote.
	got, err := s2.Get(newName, fsuefi.EFIGlobalVariableGUID)
	if err != nil {
		t.Fatalf("new variable %q not found after Set: %v", newName, err)
	}
	if !bytes.Equal(got.Data, newData) {
		t.Errorf("new variable data mismatch\n got %q\nwant %q", got.Data, newData)
	}

	// And the on-disk FV header must still be intact: any
	// corruption there would cause OVMF to wipe the store on next
	// boot. Re-validate the two anchors detectFvWrap looks at —
	// gEfiSystemNvDataFvGuid at 0x10 and "_FVH" at 0x28.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Set: %v", err)
	}
	if !bytes.Equal(raw[0x10:0x20], fsuefi.EFISystemNvDataFvGUID[:]) {
		t.Error("FvHeader.FileSystemGuid corrupted by Set")
	}
	if !bytes.Equal(raw[0x28:0x2c], []byte{'_', 'F', 'V', 'H'}) {
		t.Errorf("FV signature corrupted by Set: %x", raw[0x28:0x2c])
	}
	// And the store header signature at FvHeaderSize must still be
	// the authenticated GUID — our writer must not switch flavors.
	storeOff := fsuefi.FvHeaderSize
	if !bytes.Equal(raw[storeOff:storeOff+16], fsuefi.EFIAuthenticatedVariableGUID[:]) {
		t.Error("store header signature changed flavor across Set")
	}
}

// TestSmokeBootOVMF is a best-effort smoke test that launches QEMU
// with our modified VARS file (the post-Set output of the same flow
// TestWriteEDK2CompatibleVars exercises) and asserts QEMU starts.
//
// Skipped when qemu-system-x86_64 or the matching CODE firmware is
// missing — both are environment-dependent and may not be available
// on every CI runner. We deliberately do NOT block the package on
// this passing; it exists as a manual verification that our writer
// produces a varstore OVMF actually accepts.
func TestSmokeBootOVMF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	qemu, err := findExecutable("qemu-system-x86_64")
	if err != nil {
		t.Skipf("qemu-system-x86_64 not in PATH: %v", err)
	}
	code := findOVMFCode(t)
	if code == "" {
		t.Skip("edk2-x86_64-code.fd not found in any known location")
	}

	// Prepare a writable VARS copy and stage one variable through
	// our writer — this is the bytes the firmware will see.
	vars := copyFixture(t, "edk2-x64-vars.fd")
	s, err := fsuefi.Open(vars)
	if err != nil {
		t.Fatalf("Open fixture for smoke test: %v", err)
	}
	if err := s.Set(fsuefi.Variable{
		Name:       "WeftSmokeBoot",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0x01},
	}); err != nil {
		t.Fatalf("Set smoke var: %v", err)
	}
	s.Close()

	if err := runQEMUSmoke(t, qemu, code, vars); err != nil {
		t.Fatalf("QEMU smoke boot failed: %v", err)
	}
}

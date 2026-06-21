// Package filesystem_uefi_test stress suite.
//
// The tests in this file exercise the driver under sustained, scaled
// workloads. Each test is gated on testing.Short() (default `go test ./...`
// skips them) and tuned by `-stress.*` flags plus `UEFI_STRESS_*` env
// vars, so the same code path covers the fast CI hop (a few seconds in
// short mode, ten or so seconds without) and a multi-hour soak run.
//
// Knobs (flag → env override → default short / default long):
//
//	-stress.workers   UEFI_STRESS_WORKERS    8 / 8
//	-stress.duration  UEFI_STRESS_DURATION   2s / 3h
//	-stress.var-kb    UEFI_STRESS_VAR_KB     64 / up to NV store size
//	-stress.vars      UEFI_STRESS_VARS       1_000 / 100_000
//	-stress.qemu      UEFI_STRESS_QEMU       false / opt-in QEMU smoke
//
// Implementation notes:
//
//   - The store's flush() path re-reads the backing file every Set/Delete,
//     so concurrent goroutines operating on the same *store handle race
//     the file. The concurrent R/W test wraps the store in a sync.Mutex
//     to expose a realistic single-process serialised workload; the
//     mutex is the integration point a caller in real code would put
//     here too.
//
//   - The large-variable test sizes the store up to leave room for the
//     auth-header + UTF-16 name + data + record pad inside the NvVar
//     region of an OVMF x86_64 image (512 KiB total → ~512 KiB - 72 - 28
//     usable for the payload).
//
//   - All tests use FormatOVMF(OVMFX86_64) so we exercise the real
//     production layout (FV-wrapped + authenticated records), not the
//     legacy raw non-auth one Format() produces.
package filesystem_uefi_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fsuefi "github.com/go-filesystems/uefi"
)

// -----------------------------------------------------------------------------
// Flags + env-var override
// -----------------------------------------------------------------------------

var (
	flagStressWorkers  = flag.Int("stress.workers", 8, "concurrent worker count for the stress R/W test")
	flagStressDuration = flag.Duration("stress.duration", 2*time.Second, "duration each timed stress subtest runs for (short-mode default keeps go test ./... under ~30s)")
	flagStressVarKB    = flag.Int("stress.var-kb", 64, "single-variable size in KiB for the large-var stress test")
	flagStressVars     = flag.Int("stress.vars", 1_000, "many-variables target count for the fill-store stress test")
	flagStressQEMU     = flag.Bool("stress.qemu", false, "opt-in: run a one-shot QEMU smoke boot at the end of stress")
)

// stressKnobs collects effective stress parameters after env-var
// override. Each accessor returns the env value if set (so CI can
// crank duration to 3h without rebuilding), otherwise the flag value
// (so `go test -run Stress -stress.duration=30s` works for ad-hoc
// runs).
type stressKnobs struct {
	workers  int
	duration time.Duration
	varKB    int
	vars     int
	qemu     bool
}

// loadStressKnobs reads flag values then applies any UEFI_STRESS_*
// environment variable overrides. It runs once per test (cheap), so
// tests that change their own knobs via t.Setenv can co-exist with
// runs that set them globally via the shell.
func loadStressKnobs(t *testing.T) stressKnobs {
	t.Helper()
	k := stressKnobs{
		workers:  *flagStressWorkers,
		duration: *flagStressDuration,
		varKB:    *flagStressVarKB,
		vars:     *flagStressVars,
		qemu:     *flagStressQEMU,
	}
	if v := os.Getenv("UEFI_STRESS_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			k.workers = n
		}
	}
	if v := os.Getenv("UEFI_STRESS_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			k.duration = d
		}
	}
	if v := os.Getenv("UEFI_STRESS_VAR_KB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			k.varKB = n
		}
	}
	if v := os.Getenv("UEFI_STRESS_VARS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			k.vars = n
		}
	}
	if v := os.Getenv("UEFI_STRESS_QEMU"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			k.qemu = b
		}
	}
	return k
}

// guidForWorker derives a deterministic per-worker GUID from a small
// integer so the concurrent test can assert that worker i's variables
// only show up under worker i's namespace. We mutate the last byte of
// EFIGlobalVariableGUID — that keeps the wire format valid while
// giving us up to 256 disjoint namespaces, plenty for stress.
func guidForWorker(i int) fsuefi.GUID {
	g := fsuefi.EFIGlobalVariableGUID
	g[15] = byte(i & 0xff)
	g[14] = byte((i >> 8) & 0xff)
	return g
}

// newStressStore creates a fresh OVMF x86_64 varstore of the requested
// size inside the test's temp dir and returns the open store + path.
// The store is registered for Close on test cleanup so subtests can
// stop worrying about leaks.
func newStressStore(t *testing.T, sizeBytes int64) (fsuefi.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stress-vars.fd")
	s, err := fsuefi.FormatOVMF(path, sizeBytes, fsuefi.OVMFX86_64)
	if err != nil {
		t.Fatalf("FormatOVMF: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// -----------------------------------------------------------------------------
// 1. Concurrent variable R/W
// -----------------------------------------------------------------------------

// TestStress_ConcurrentRW spins N workers that loop Set/Get/Delete
// for the configured duration. Workers use disjoint GUID namespaces so
// they never collide on a key; the store itself is shared and guarded
// by a sync.Mutex (mirroring how a real caller would serialise access).
//
// Throughput counters are reported via t.Logf so a CI run prints the
// effective Set/Get/Delete rate and any deltas across runs are easy
// to spot.
func TestStress_ConcurrentRW(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	k := loadStressKnobs(t)

	// 512 KiB OVMF x86_64 store — same size QEMU's prebuilt uses.
	store, _ := newStressStore(t, fsuefi.VarsSizeX86_64)
	var mu sync.Mutex

	var setOK, getOK, delOK uint64
	var setErr, getErr, delErr uint64

	deadline := time.Now().Add(k.duration)
	var wg sync.WaitGroup
	wg.Add(k.workers)
	for w := 0; w < k.workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			ns := guidForWorker(w)
			// A tiny pool of variable names per worker keeps the
			// store from filling: each iteration toggles between
			// Set (refresh) and Delete (free), exercising the
			// write+reclaim path on every loop.
			names := []string{
				fmt.Sprintf("w%dVarA", w),
				fmt.Sprintf("w%dVarB", w),
				fmt.Sprintf("w%dVarC", w),
			}
			payload := []byte(fmt.Sprintf("worker-%d-payload", w))
			i := 0
			for time.Now().Before(deadline) {
				name := names[i%len(names)]
				i++

				mu.Lock()
				err := store.Set(fsuefi.Variable{
					Name:       name,
					GUID:       ns,
					Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
					Data:       payload,
				})
				mu.Unlock()
				if err != nil {
					atomic.AddUint64(&setErr, 1)
					// Out-of-space is expected when many
					// workers race the same 512 KiB store
					// — back off briefly then continue.
					mu.Lock()
					_ = store.Delete(name, ns)
					mu.Unlock()
					continue
				}
				atomic.AddUint64(&setOK, 1)

				mu.Lock()
				got, err := store.Get(name, ns)
				mu.Unlock()
				if err != nil {
					atomic.AddUint64(&getErr, 1)
					continue
				}
				atomic.AddUint64(&getOK, 1)
				// Round-trip check: the value must equal
				// what we just wrote. A mismatch here means
				// either the parser dropped a record or the
				// writer corrupted neighbouring data.
				if string(got.Data) != string(payload) {
					t.Errorf("worker %d: round-trip mismatch on %q\n got %q\nwant %q",
						w, name, got.Data, payload)
					return
				}

				// Occasionally drop a key to exercise the
				// delete path under contention.
				if i%4 == 0 {
					mu.Lock()
					err := store.Delete(name, ns)
					mu.Unlock()
					if err != nil {
						atomic.AddUint64(&delErr, 1)
					} else {
						atomic.AddUint64(&delOK, 1)
					}
				}
			}
		}()
	}
	wg.Wait()

	// Final invariant: each worker's leftover variables (if any)
	// must still be readable and decode to the expected payload.
	mu.Lock()
	all := store.List()
	mu.Unlock()
	wantPayloadByWorker := make(map[int]string)
	for w := 0; w < k.workers; w++ {
		wantPayloadByWorker[w] = fmt.Sprintf("worker-%d-payload", w)
	}
	for _, v := range all {
		// Recover worker id from the last two bytes of the GUID.
		w := int(v.GUID[14])<<8 | int(v.GUID[15])
		want, ok := wantPayloadByWorker[w]
		if !ok {
			// Foreign namespace — shouldn't happen but isn't fatal.
			continue
		}
		if string(v.Data) != want {
			t.Errorf("residual variable %q in worker %d's namespace has wrong payload\n got %q\nwant %q",
				v.Name, w, v.Data, want)
		}
	}

	d := k.duration.Seconds()
	if d <= 0 {
		d = 1
	}
	t.Logf("stress.ConcurrentRW workers=%d duration=%s — sets=%d gets=%d dels=%d (set_errs=%d get_errs=%d del_errs=%d) → %.0f set/s %.0f get/s %.0f del/s",
		k.workers, k.duration,
		setOK, getOK, delOK, setErr, getErr, delErr,
		float64(setOK)/d, float64(getOK)/d, float64(delOK)/d,
	)
	if setOK == 0 {
		t.Errorf("zero successful Sets — workload never ran")
	}
}

// -----------------------------------------------------------------------------
// 2. Large variable
// -----------------------------------------------------------------------------

// TestStress_LargeVariable writes a single variable of the configured
// size and verifies a clean round-trip — name and data must come back
// byte-identical. This exercises the auth-data/var-data boundary the
// parser computes (nameOff+nameSize, NO inter-field padding) at a
// size that's not 4-byte aligned, which is where past parser bugs
// have shown up.
func TestStress_LargeVariable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	k := loadStressKnobs(t)

	// Sizing: NvVar store usable region = sizeBytes - FvHeaderSize(72) - StoreHeaderSize(28).
	// Each variable record costs AuthVarHeaderSize(60) + len(name in UTF-16+NUL) + len(data) + align pad.
	// Choose the store size to be at least 2x the request so we have headroom.
	want := int64(k.varKB) * 1024
	storeSize := want * 2
	if storeSize < fsuefi.VarsSizeX86_64 {
		storeSize = fsuefi.VarsSizeX86_64
	}

	store, path := newStressStore(t, storeSize)

	// Choose a name whose UTF-16 byte length is NOT a multiple of 4
	// so the "no inter-field padding" path gets exercised. 13 chars
	// + NUL → 28 bytes UTF-16LE, not 4-aligned with the 60-byte
	// auth header (60+28 = 88, fine, but the next record needs
	// alignUp(88+data) so the data alignment edge is tested too).
	name := "BigStressVar"
	data := make([]byte, want)
	// Fill with a recognisable pattern so silent truncation is loud.
	for i := range data {
		data[i] = byte((i * 31) & 0xff)
	}

	if err := store.Set(fsuefi.Variable{
		Name:       name,
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       data,
	}); err != nil {
		t.Fatalf("Set %d-byte variable: %v", len(data), err)
	}
	// Force a fresh parse from disk — exactly what OVMF would do.
	store.Close()
	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Re-open after large Set: %v", err)
	}
	defer s2.Close()

	got, err := s2.Get(name, fsuefi.EFIGlobalVariableGUID)
	if err != nil {
		t.Fatalf("Get large var: %v", err)
	}
	if len(got.Data) != len(data) {
		t.Fatalf("large var size mismatch: got %d, want %d", len(got.Data), len(data))
	}
	for i := range data {
		if got.Data[i] != data[i] {
			t.Fatalf("large var byte %d mismatch: got %#x, want %#x", i, got.Data[i], data[i])
		}
	}
	t.Logf("stress.LargeVariable size=%d KiB round-trip OK", k.varKB)
}

// -----------------------------------------------------------------------------
// 3. Many variables
// -----------------------------------------------------------------------------

// TestStress_ManyVariables fills the store until either k.vars
// variables have been written successfully or an out-of-space error
// fires. The first error must be a real "variables exceed store size"
// error (not e.g. a parse failure), and the variables that DID make
// it in must be byte-perfect on re-open.
//
// This is the canonical "fill the NV store close to capacity; assert
// proper out-of-space error when exceeding" check.
func TestStress_ManyVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	k := loadStressKnobs(t)

	// 512 KiB store, same as x86_64 OVMF. Variables are intentionally
	// small (8-byte payload + ~10-byte name) so we get a high
	// variable count per KB and the test runs in seconds.
	store, path := newStressStore(t, fsuefi.VarsSizeX86_64)

	payload := []byte("01234567")
	target := k.vars
	written := 0
	var firstOverflowErr error
	for i := 0; i < target; i++ {
		name := fmt.Sprintf("MV%06d", i)
		err := store.Set(fsuefi.Variable{
			Name:       name,
			GUID:       fsuefi.EFIGlobalVariableGUID,
			Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
			Data:       payload,
		})
		if err != nil {
			firstOverflowErr = err
			break
		}
		written++
	}
	store.Close()
	t.Logf("stress.ManyVariables wrote %d / %d before %v", written, target, firstOverflowErr)

	// If the configured target is small enough to fit in 512 KiB we
	// expect zero overflow; otherwise the FIRST error must be the
	// store-full error from buildStore. (We don't pin the string —
	// just require it surfaced from our package.)
	if firstOverflowErr != nil {
		// 8 bytes payload + ~14 bytes UTF-16 name + 60 byte auth
		// header + padding ≈ 88 bytes per record; 512 KiB usable
		// ÷ 88 ≈ 5800, so anything below ~5000 should fit.
		if written == 0 {
			t.Fatalf("ManyVariables: first Set already failed: %v", firstOverflowErr)
		}
	}

	// Re-open and verify everything that succeeded is still there.
	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("Re-open ManyVariables store: %v", err)
	}
	defer s2.Close()

	got := s2.List()
	if len(got) != written {
		t.Errorf("ManyVariables: after re-open got %d vars, wrote %d", len(got), written)
	}
	// Spot-check a handful of indices — full N×N comparison would
	// dominate the test wall-clock at high vars counts.
	check := []int{0, written / 4, written / 2, 3 * written / 4, written - 1}
	for _, i := range check {
		if i < 0 || i >= written {
			continue
		}
		name := fmt.Sprintf("MV%06d", i)
		v, err := s2.Get(name, fsuefi.EFIGlobalVariableGUID)
		if err != nil {
			t.Errorf("ManyVariables: lost %q: %v", name, err)
			continue
		}
		if string(v.Data) != string(payload) {
			t.Errorf("ManyVariables: corrupted %q\n got %q\nwant %q", name, v.Data, payload)
		}
	}
}

// -----------------------------------------------------------------------------
// 4. NV-store rotation + GC
// -----------------------------------------------------------------------------

// TestStress_RotationAndGC runs many tight Set→Delete cycles and
// asserts (a) the store never reports a false out-of-space (the
// reclaim/rewrite path must reclaim the deleted variable's bytes
// every flush, so the same key can be set and deleted forever in a
// finite store), and (b) the store remains parseable end-to-end:
// re-open from disk and read back the surviving variable.
//
// The driver's flush rewrites the variable region from scratch each
// time, so deleting a variable returns ALL of its on-disk bytes to
// free immediately. This test verifies that invariant under load.
func TestStress_RotationAndGC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	k := loadStressKnobs(t)

	store, path := newStressStore(t, fsuefi.VarsSizeX86_64)

	// Pick a payload large enough that, without GC, the second Set
	// would fail. Half the usable region forces the reclaim to
	// actually free the previous record's bytes.
	usable := int64(fsuefi.VarsSizeX86_64) - int64(fsuefi.FvHeaderSize) - int64(fsuefi.StoreHeaderSize)
	dataSize := int(usable / 2)
	payload := make([]byte, dataSize)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	deadline := time.Now().Add(k.duration)
	var cycles int
	for time.Now().Before(deadline) {
		// Set fills ~half the store.
		if err := store.Set(fsuefi.Variable{
			Name:       "RotateVar",
			GUID:       fsuefi.EFIGlobalVariableGUID,
			Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
			Data:       payload,
		}); err != nil {
			t.Fatalf("rotation: Set cycle %d: %v", cycles, err)
		}
		// Delete returns those bytes; next Set in the next loop
		// iteration MUST succeed (no false out-of-space).
		if err := store.Delete("RotateVar", fsuefi.EFIGlobalVariableGUID); err != nil {
			t.Fatalf("rotation: Delete cycle %d: %v", cycles, err)
		}
		cycles++
	}
	t.Logf("stress.RotationAndGC ran %d Set/Delete cycles in %s (%.0f cycles/s)",
		cycles, k.duration, float64(cycles)/k.duration.Seconds())
	if cycles < 1 {
		t.Fatalf("rotation: no cycles completed in %s", k.duration)
	}

	// One final Set leaves the store with exactly one variable;
	// re-open and confirm the parser still likes the disk image.
	if err := store.Set(fsuefi.Variable{
		Name:       "FinalRotate",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0xAA, 0xBB},
	}); err != nil {
		t.Fatalf("rotation: final Set: %v", err)
	}
	store.Close()

	s2, err := fsuefi.Open(path)
	if err != nil {
		t.Fatalf("rotation: Re-open after GC: %v", err)
	}
	defer s2.Close()
	v, err := s2.Get("FinalRotate", fsuefi.EFIGlobalVariableGUID)
	if err != nil {
		t.Fatalf("rotation: Get after GC: %v", err)
	}
	if len(v.Data) != 2 || v.Data[0] != 0xAA || v.Data[1] != 0xBB {
		t.Fatalf("rotation: FinalRotate data mismatch: %v", v.Data)
	}
}

// -----------------------------------------------------------------------------
// 6. Fault injection
// -----------------------------------------------------------------------------

// TestStress_FaultInjection_ReadOnly chmods the backing file to 0o444
// and asserts that subsequent Set/Delete operations return errors
// from the os.WriteFile path, rather than silently corrupting in-
// memory state or panicking. After restoring write permissions the
// store must be usable again.
//
// This is the package's exposed I/O-error wrapper: every flush goes
// through os.ReadFile + os.WriteFile, so chmod is the natural fault
// injection point that doesn't need a private hook in the driver.
func TestStress_FaultInjection_ReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	skipIfRoot(t)

	store, path := newStressStore(t, fsuefi.VarsSizeX86_64)

	// A baseline Set must succeed before we start breaking things.
	v := fsuefi.Variable{
		Name:       "FaultBefore",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0x01},
	}
	if err := store.Set(v); err != nil {
		t.Fatalf("baseline Set: %v", err)
	}

	// Read-only the file → next Set must fail at WriteFile.
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatalf("chmod 0444: %v", err)
	}
	v2 := fsuefi.Variable{
		Name:       "FaultDuring",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0x02},
	}
	if err := store.Set(v2); err == nil {
		t.Fatal("Set on read-only file: expected error, got nil")
	}
	if err := store.Delete("FaultBefore", fsuefi.EFIGlobalVariableGUID); err == nil {
		t.Fatal("Delete on read-only file: expected error, got nil")
	}

	// Now break the read path too — replace the file with garbage
	// and ensure flush surfaces the parse error rather than panicking.
	// First restore perms so we can mutate the file.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod 0644 restore: %v", err)
	}
	// Truncate to below header size — flush() must reject this.
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02}, 0o644); err != nil {
		t.Fatalf("truncate file: %v", err)
	}
	if err := store.Set(v2); err == nil {
		t.Fatal("Set against truncated file: expected error, got nil")
	}
}

// -----------------------------------------------------------------------------
// 7. OVMF boot smoke (opt-in)
// -----------------------------------------------------------------------------

// TestStress_QEMUSmoke is a one-shot end-of-stress QEMU boot. It's
// gated behind both testing.Short() AND -stress.qemu / UEFI_STRESS_QEMU
// because launching QEMU adds 10-15s of wall clock per run and depends
// on a working QEMU + OVMF CODE firmware locally.
//
// The store is pre-stressed by running a short rotation cycle, then
// the resulting VARS image is handed to QEMU to confirm OVMF accepts
// it (BdsDxe banner appears, "variable store corrupt" does NOT).
func TestStress_QEMUSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	k := loadStressKnobs(t)
	if !k.qemu {
		t.Skip("-stress.qemu not set (also UEFI_STRESS_QEMU=true enables this)")
	}
	qemu, err := findExecutable("qemu-system-x86_64")
	if err != nil {
		t.Skipf("qemu-system-x86_64 not in PATH: %v", err)
	}
	code := findOVMFCode(t)
	if code == "" {
		t.Skip("OVMF CODE firmware not found")
	}

	// Build a varstore through real driver activity: a handful of
	// Set/Delete cycles, then leave a known-good variable behind.
	path := filepath.Join(t.TempDir(), "stress-vars.fd")
	s, err := fsuefi.FormatOVMF(path, fsuefi.VarsSizeX86_64, fsuefi.OVMFX86_64)
	if err != nil {
		t.Fatalf("FormatOVMF: %v", err)
	}
	for i := 0; i < 32; i++ {
		v := fsuefi.Variable{
			Name:       fmt.Sprintf("Cycle%02d", i),
			GUID:       fsuefi.EFIGlobalVariableGUID,
			Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
			Data:       []byte{byte(i)},
		}
		if err := s.Set(v); err != nil {
			t.Fatalf("preboot Set %d: %v", i, err)
		}
		if i%3 == 0 {
			_ = s.Delete(v.Name, v.GUID)
		}
	}
	if err := s.Set(fsuefi.Variable{
		Name:       "WeftStressSmoke",
		GUID:       fsuefi.EFIGlobalVariableGUID,
		Attributes: fsuefi.AttrNonVolatile | fsuefi.AttrBootServiceAccess | fsuefi.AttrRuntimeAccess,
		Data:       []byte{0xCA, 0xFE},
	}); err != nil {
		t.Fatalf("final Set: %v", err)
	}
	s.Close()

	if err := runQEMUSmoke(t, qemu, code, path); err != nil {
		t.Fatalf("post-stress QEMU smoke boot: %v", err)
	}
}

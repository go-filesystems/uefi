package filesystem_uefi_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findExecutable returns the absolute path to name in PATH, or an
// error if it isn't there. Thin wrapper around exec.LookPath so the
// skip-gate code stays readable.
func findExecutable(name string) (string, error) {
	return exec.LookPath(name)
}

// findOVMFCode looks for an x86_64 OVMF CODE firmware in a handful of
// well-known locations (pkgx qemu install, Homebrew, system /usr/share)
// and returns the first one that exists, or "" if none do.
//
// Kept separate from the test so adding a new search path doesn't
// require touching test logic.
func findOVMFCode(t *testing.T) string {
	t.Helper()
	home, _ := os.UserHomeDir()
	candidates := []string{
		// pkgx qemu install on this developer's machine.
		filepath.Join(home, ".pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"),
		// Homebrew (Intel and Apple Silicon defaults).
		"/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
		"/usr/local/share/qemu/edk2-x86_64-code.fd",
		// Debian / Ubuntu / Fedora common paths.
		"/usr/share/OVMF/OVMF_CODE.fd",
		"/usr/share/edk2/x64/OVMF_CODE.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
		"/usr/share/qemu/edk2-x86_64-code.fd",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// runQEMUSmoke launches QEMU with our modified VARS, captures serial
// output for ~10 s, and returns nil if OVMF reaches its BDS phase (i.e.
// boots far enough to print BdsDxe or any other recognisable OVMF
// banner) without dying on a varstore parse error.
//
// We deliberately don't wait for a guest OS to boot — there isn't one
// in this test setup. The success criterion is simply "OVMF didn't
// reformat the varstore and didn't crash inside the variable driver".
func runQEMUSmoke(t *testing.T, qemu, code, vars string) error {
	t.Helper()

	// Use the pflash device pair OVMF expects: read-only CODE, then
	// writable VARS. -no-reboot stops QEMU from looping on the empty
	// boot order, -nographic + -serial stdio captures the firmware
	// log without needing a display.
	args := []string{
		"-machine", "q35,accel=tcg",
		"-cpu", "qemu64",
		"-m", "256",
		"-drive", fmt.Sprintf("if=pflash,format=raw,readonly=on,file=%s", code),
		"-drive", fmt.Sprintf("if=pflash,format=raw,file=%s", vars),
		"-nographic",
		"-no-reboot",
		"-monitor", "none",
		"-serial", "stdio",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, qemu, args...)
	out, err := cmd.CombinedOutput()
	// QEMU returns non-zero when killed by our timeout, so we don't
	// fail on err alone — we look at the captured output for
	// evidence OVMF made it past varstore init.
	logTail := tail(string(out), 4*1024)
	t.Logf("qemu output (last 4 KiB):\n%s", logTail)

	// Markers that OVMF varstore parsing succeeded — at least one
	// must appear in the captured serial log. Real OVMF builds emit
	// these strings during early boot:
	//   - "BdsDxe"          (Boot Device Selection driver started)
	//   - "PlatformBds"     (platform-specific BDS phase entered)
	//   - "EFI stub:"       (rare — only with -kernel, but kept for
	//                        completeness if a future test boots a
	//                        kernel)
	//   - "Press ESC"       (the OVMF boot menu prompt)
	markers := []string{"BdsDxe", "PlatformBds", "Press ESC", "TianoCore", "EDK II"}
	if !containsAny(string(out), markers) {
		// Distinguish "QEMU couldn't even start" from "QEMU started
		// but OVMF never reached BDS". The former means our test
		// environment is broken (skip); the latter means our
		// varstore corrupted boot (fail).
		if err != nil && len(out) == 0 {
			return fmt.Errorf("qemu produced no output (env issue?): %w", err)
		}
		return errors.New("OVMF did not reach BDS phase — varstore may have been rejected")
	}

	// And the classic "varstore corrupt → reformat" message must NOT
	// appear. If OVMF found our store invalid it would log this and
	// wipe the variables — that's the scenario this test catches.
	bad := []string{
		"variable store corrupt",
		"Reclaim",                 // rare
		"Variable Storage is bad", // very rare
	}
	if containsAny(string(out), bad) {
		return fmt.Errorf("OVMF complained about the varstore: %s", tail(string(out), 512))
	}

	// Context-deadline-exceeded means we hit the 15s budget on
	// purpose — that's the happy path for a no-disk boot.
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return nil
	}
	return nil
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// tail returns the last n bytes of s (or all of s if shorter).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

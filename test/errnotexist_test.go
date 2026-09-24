// SPDX-License-Identifier: BSD-3-Clause

package filesystem_uefi_test

import (
	"errors"
	iofs "io/fs"
	"testing"

	fsuefi "github.com/go-filesystems/uefi"
)

// ⛔ The error contract from go-filesystems/interface: a path that is not
// there must satisfy errors.Is(err, fs.ErrNotExist). This driver satisfies
// filesystem.Filesystem -- the compile-time assertion in filesystem.go says so
// -- and was one of four left out of the contract.
//
// It is the easiest of the four, and worth saying why. btrfs and xfs raise one
// sentinel from both a missing name and a broken image, so each needed the
// marking placed by hand at the path boundary. zfs kept them apart already.
// uefi has no such tension at all: "not found" here is a linear scan of a
// slice of variables finding no match, and a store that cannot be PARSED fails
// in Open, before any name is looked up.
//
// The flat namespace does not excuse the driver either. A tool written against
// filesystem.Filesystem does not know it is talking to a variable store; it
// asks for a path and classifies what comes back.
func TestMissingPathsSatisfyErrNotExist(t *testing.T) {
	s, _ := openStoreWith(t, 4096)

	if err := s.WriteFile("Present", []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		what string
		err  error
	}{
		{"ReadFile", func() error { _, e := s.ReadFile("Absent"); return e }()},
		{"Stat", func() error { _, e := s.Stat("Absent"); return e }()},
		{"DeleteFile", s.DeleteFile("Absent")},
		{"Rename", s.Rename("Absent", "Other")},
		{"Get", func() error { _, e := s.Get("Absent", fsuefi.DefaultNamespaceGUID); return e }()},
		{"Delete", s.Delete("Absent", fsuefi.DefaultNamespaceGUID)},
		{"ListDir of a path that is not the root", func() error { _, e := s.ListDir("/nope"); return e }()},
	} {
		if tc.err == nil {
			t.Errorf("%s on a name that is not in the store returned no error at all", tc.what)
			continue
		}
		if !errors.Is(tc.err, iofs.ErrNotExist) {
			t.Errorf("%s: errors.Is(err, fs.ErrNotExist) is false for %q", tc.what, tc.err)
		}
	}

	// The marking must not spread to a name that IS there.
	if _, err := s.ReadFile("Present"); err != nil {
		t.Errorf("a variable that exists must still read: %v", err)
	}
}

// TestAnUnsupportedOperationIsNotA404 guards the edge this driver does have.
// ReadLink, MkDir and DeleteDir are not "not there" -- they are operations a
// flat variable namespace has no meaning for. A caller that retried on
// fs.ErrNotExist, or reported 404, would be describing the wrong problem.
func TestAnUnsupportedOperationIsNotA404(t *testing.T) {
	s, _ := openStoreWith(t, 4096)

	for _, tc := range []struct {
		what string
		err  error
	}{
		{"ReadLink", func() error { _, e := s.ReadLink("Anything"); return e }()},
		{"MkDir", s.MkDir("/dir", 0o755)},
		{"DeleteDir", s.DeleteDir("/dir")},
	} {
		if tc.err == nil {
			t.Fatalf("%s reported success on a store that cannot do it", tc.what)
		}
		if errors.Is(tc.err, iofs.ErrNotExist) {
			t.Errorf("%s reads as fs.ErrNotExist (%v): an operation this store does not "+
				"support is not a missing file", tc.what, tc.err)
		}
	}
}

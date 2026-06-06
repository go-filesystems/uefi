package filesystem_uefi

import (
	"errors"
	"fmt"
	"os"

	filesystem "github.com/go-filesystems/interface"
)

// Store is the full interface returned by Open.
// It combines UEFI variable operations (VariableStore) with the generic
// filesystem.Filesystem surface, allowing the store to be used by tooling
// that operates on any filesystem driver in this repository.
type Store interface {
	VariableStore
	filesystem.Filesystem
}

// Compile-time assertion that *store satisfies the combined Store interface.
var _ Store = (*store)(nil)

// DefaultNamespaceGUID is used by the filesystem.Filesystem adapter when no
// GUID is embedded in the path. It equals EFI_GLOBAL_VARIABLE_GUID.
//
//	{8be4df61-93ca-11d2-aa0d-00e098032b8c}
var DefaultNamespaceGUID = GUID{
	0x61, 0xdf, 0xe4, 0x8b,
	0xca, 0x93,
	0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
}

// ReadFile returns the data of the UEFI variable whose name equals path.
// The DefaultNamespaceGUID is used as namespace.
func (s *store) ReadFile(path string) ([]byte, error) {
	v, err := s.Get(path, DefaultNamespaceGUID)
	if err != nil {
		return nil, fmt.Errorf("uefi: ReadFile %q: %w", path, err)
	}
	out := make([]byte, len(v.Data))
	copy(out, v.Data)
	return out, nil
}

// WriteFile creates or replaces the UEFI variable whose name equals path.
// perm is ignored (UEFI variables carry their own attribute flags).
func (s *store) WriteFile(path string, data []byte, _ os.FileMode) error {
	return s.Set(Variable{
		Name:       path,
		GUID:       DefaultNamespaceGUID,
		Attributes: AttrNonVolatile | AttrBootServiceAccess | AttrRuntimeAccess,
		Data:       data,
	})
}

// DeleteFile removes the UEFI variable whose name equals path.
func (s *store) DeleteFile(path string) error {
	return s.Delete(path, DefaultNamespaceGUID)
}

// ListDir lists all variables when path is "/" or "", and returns an error
// for any other path (UEFI variables have no directory hierarchy).
func (s *store) ListDir(path string) ([]filesystem.DirEntry, error) {
	if path != "/" && path != "" {
		return nil, fmt.Errorf("uefi: ListDir: no such directory %q", path)
	}
	vars := s.List()
	entries := make([]filesystem.DirEntry, len(vars))
	for i, v := range vars {
		entries[i] = filesystem.NewDirEntry(0, v.Name, 8) // DT_REG = 8
	}
	return entries, nil
}

// Stat returns the size of the UEFI variable whose name equals path.
func (s *store) Stat(path string) (filesystem.Stat, error) {
	v, err := s.Get(path, DefaultNamespaceGUID)
	if err != nil {
		return nil, fmt.Errorf("uefi: Stat %q: %w", path, err)
	}
	return filesystem.NewStat(0o600, uint64(len(v.Data)), 0), nil
}

// ReadLink is not supported by UEFI variable stores.
func (s *store) ReadLink(_ string) (string, error) {
	return "", errors.New("uefi: ReadLink: not supported")
}

// MkDir is not supported by UEFI variable stores.
func (s *store) MkDir(_ string, _ os.FileMode) error {
	return errors.New("uefi: MkDir: not supported")
}

// DeleteDir is not supported by UEFI variable stores.
func (s *store) DeleteDir(_ string) error {
	return errors.New("uefi: DeleteDir: not supported")
}

// Rename copies the variable at oldPath to newPath (preserving attributes and
// data) then deletes the original. MkDir/ReadLink semantics are not meaningful
// for UEFI variables, so both paths must refer to variables in the flat
// namespace (DefaultNamespaceGUID).
func (s *store) Rename(oldPath, newPath string) error {
	v, err := s.Get(oldPath, DefaultNamespaceGUID)
	if err != nil {
		return fmt.Errorf("uefi: Rename %q: %w", oldPath, err)
	}
	v.Name = newPath
	if err := s.Set(v); err != nil {
		return fmt.Errorf("uefi: Rename %q → %q: %w", oldPath, newPath, err)
	}
	// Delete cannot fail here: oldPath was confirmed present above and the
	// store has not been modified under our feet (no concurrent access).
	_ = s.Delete(oldPath, DefaultNamespaceGUID)
	return nil
}

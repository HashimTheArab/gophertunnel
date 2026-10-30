package minecraft

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace atomically renames oldpath to newpath, failing with EEXIST if newpath exists.
// Kernels before 3.15 and filesystems without RENAME_NOREPLACE fail with ENOSYS or EINVAL.
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "renameat2", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

package minecraft

import (
	"os"
	"syscall"
)

// renameNoReplace atomically renames oldpath to newpath, failing with ERROR_ALREADY_EXISTS if
// newpath exists: unlike os.Rename, MoveFile never replaces its target.
func renameNoReplace(oldpath, newpath string) error {
	from, err := syscall.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	if err := syscall.MoveFile(from, to); err != nil {
		return &os.LinkError{Op: "movefile", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

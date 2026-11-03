package minecraft

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile blocks until it holds an exclusive lock on the first byte of f. The lock is released by
// unlockFile, or by Windows once f is closed or the process dies.
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

// unlockFile releases the lock taken by lockFile.
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// syncDir does nothing: Windows cannot flush a directory, and NTFS journals renames.
func syncDir(string) error { return nil }

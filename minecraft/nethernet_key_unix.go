//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package minecraft

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile blocks until it holds an exclusive flock on f. The lock is released by unlockFile, by
// closing f, or when the process dies.
func lockFile(f *os.File) error {
	return flock(f, unix.LOCK_EX)
}

// unlockFile releases the lock taken by lockFile.
func unlockFile(f *os.File) error {
	return flock(f, unix.LOCK_UN)
}

// flock applies how to f, retrying when a signal interrupts the wait.
func flock(f *os.File, how int) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		for {
			if lockErr = unix.Flock(int(fd), how); !errors.Is(lockErr, unix.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	return lockErr
}

// syncDir flushes dir, making a rename into it durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

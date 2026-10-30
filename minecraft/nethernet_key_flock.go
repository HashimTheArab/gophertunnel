//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package minecraft

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLock takes a non-blocking exclusive flock on f, reporting false if another open file holds it. The
// lock lasts until f is closed or its process dies, so a held lock means its holder is still running.
func tryLock(f *os.File) (bool, error) {
	conn, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		lockErr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
	}); err != nil {
		return false, err
	}
	if errors.Is(lockErr, unix.EWOULDBLOCK) {
		return false, nil
	}
	return lockErr == nil, lockErr
}

//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || windows)

package minecraft

import (
	"fmt"
	"os"
	"runtime"
)

// lockFile fails: without file locks, concurrent creators could each save a different key.
func lockFile(*os.File) error {
	return fmt.Errorf("file locks are not supported on %s", runtime.GOOS)
}

// unlockFile is never reached, since lockFile always fails.
func unlockFile(*os.File) error { return nil }

// syncDir is never reached, since lockFile always fails.
func syncDir(string) error { return nil }

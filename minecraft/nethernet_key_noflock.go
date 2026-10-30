//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd)

package minecraft

import "os"

// tryLock is nil here: without file locks a live claim cannot be told from a dead one, so publishing
// never claims and an empty key file is an error.
var tryLock func(f *os.File) (bool, error)

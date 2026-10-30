//go:build !linux && !windows

package minecraft

import "errors"

// renameNoReplace is unavailable here, so publishing falls back to an exclusive claim.
func renameNoReplace(string, string) error {
	return errors.ErrUnsupported
}

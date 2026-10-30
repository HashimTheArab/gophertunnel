//go:build !linux && !windows

package minecraft

import "errors"

// renameNoReplace is unavailable here, so publishing falls back to a locked claim.
func renameNoReplace(string, string) error {
	return errors.ErrUnsupported
}

package marketplace

import "errors"

func errMissing(what string) error { return errors.New("service/marketplace: " + what) }

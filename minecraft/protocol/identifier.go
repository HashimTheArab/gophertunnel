package protocol

import "regexp"

var namespacedIdentifierPattern = regexp.MustCompile(`^[a-z0-9_.-]+:[a-z0-9/._-]+$`)

// ValidNamespacedIdentifier reports whether identifier uses Bedrock's
// namespace:path identifier syntax.
func ValidNamespacedIdentifier(identifier string) bool {
	return namespacedIdentifierPattern.MatchString(identifier)
}

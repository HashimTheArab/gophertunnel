package resource

import (
	"strconv"

	"github.com/google/uuid"
)

// CanonicalVersion returns the major.minor.patch form of a pack version string. The vanilla client parses
// the versions in ResourcePacksInfo, ResourcePackStack and manifests into numbers before comparing them,
// so "1", "1.0" and "1.0.0" name the same version. Strings that do not parse are returned unchanged and so
// only match themselves.
func CanonicalVersion(version string) string {
	v, ok := parseVersion(version)
	if !ok {
		return version
	}
	return strconv.Itoa(v[0]) + "." + strconv.Itoa(v[1]) + "." + strconv.Itoa(v[2])
}

// SameVersion reports whether two pack version strings name the same numeric version.
func SameVersion(a, b string) bool {
	return CanonicalVersion(a) == CanonicalVersion(b)
}

// CanonicalUUID returns the lowercase form of a pack UUID string, as the vanilla client compares parsed
// UUIDs rather than their text. Strings that do not parse are returned unchanged.
func CanonicalUUID(id string) string {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return id
	}
	return parsed.String()
}

// SameIdentity reports whether a pack has the UUID and numeric version a server named.
func (pack *Pack) SameIdentity(id, version string) bool {
	return pack.UUID().String() == CanonicalUUID(id) && SameVersion(pack.Version(), version)
}

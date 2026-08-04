package minecraft

import (
	"context"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackCacheKey identifies a resource pack advertised by a server during login. It holds the UUID,
// version and size of the pack as found in the ResourcePacksInfo packet. Like the vanilla client's own
// pack cache, pack content is assumed not to change without a version bump; the advertised size is
// included as an extra guard.
type ResourcePackCacheKey struct {
	// UUID and Version identify the resource pack advertised by the server.
	UUID    uuid.UUID
	Version string
	// Size is the total size in bytes of the resource pack.
	Size uint64
}

// Matches reports whether a resource pack has the identity the key holds: its UUID, version and size.
func (key ResourcePackCacheKey) Matches(pack *resource.Pack) bool {
	return pack.UUID() == key.UUID && pack.Version() == key.Version && uint64(pack.Size()) == key.Size
}

// ResourcePackCache allows a Dialer to reuse resource packs previously downloaded from a server. Cache
// failures are non-fatal: If Load returns a nil pack or an error, the pack is downloaded from the server as
// usual, and an error returned by Store is only logged.
type ResourcePackCache interface {
	// Load returns the resource pack stored under key. A nil pack with a nil error indicates a cache miss
	// and makes the connection fall back to the normal download path.
	Load(ctx context.Context, key ResourcePackCacheKey) (*resource.Pack, error)
	// Store stores a resource pack downloaded from a server under key, so that it may be returned by a
	// future call to Load.
	Store(ctx context.Context, key ResourcePackCacheKey, pack *resource.Pack) error
}

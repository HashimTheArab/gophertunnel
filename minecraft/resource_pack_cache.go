package minecraft

import (
	"context"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackCacheKey identifies a resource pack advertised during login.
// Implementations should include all fields when deciding whether a cached
// pack matches an advertisement.
type ResourcePackCacheKey struct {
	UUID        uuid.UUID
	Version     string
	Size        uint64
	ContentKey  string
	DownloadURL string
}

// ResourcePackCache allows a Dialer to reuse resource packs downloaded from a
// server. A cache miss is represented by a nil pack with hit set to false.
// Cache failures are non-fatal: gophertunnel falls back to the normal network
// download path.
type ResourcePackCache interface {
	LoadResourcePack(context.Context, ResourcePackCacheKey) (*resource.Pack, bool, error)
	StoreResourcePack(context.Context, ResourcePackCacheKey, *resource.Pack) error
}

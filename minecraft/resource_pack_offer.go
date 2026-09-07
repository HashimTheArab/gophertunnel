package minecraft

import (
	"slices"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackOfferEntry is one entry advertised in ResourcePacksInfo. Info returns its exact wire metadata,
// while Pack returns nil when the entry was not downloaded and a fresh copy otherwise.
type ResourcePackOfferEntry struct {
	info protocol.TexturePackInfo
	pack *resource.Pack
}

// Info returns the exact metadata advertised for the entry.
func (entry ResourcePackOfferEntry) Info() protocol.TexturePackInfo {
	return entry.info
}

// Pack returns an independently owned copy of the downloaded resource pack, or nil if it is unavailable.
func (entry ResourcePackOfferEntry) Pack() *resource.Pack {
	if entry.pack == nil {
		return nil
	}
	return entry.pack.Clone()
}

// ResourcePackOfferSnapshot is an immutable snapshot of a ResourcePacksInfo advertisement and any downloaded
// pack content associated with its entries.
type ResourcePackOfferSnapshot struct {
	texturePackRequired        bool
	hasAddons                  bool
	hasScripts                 bool
	forceDisableVibrantVisuals bool
	worldTemplateUUID          uuid.UUID
	worldTemplateVersion       string
	texturePacks               []ResourcePackOfferEntry
}

func newResourcePackOfferSnapshot(pk *packet.ResourcePacksInfo, packs []*resource.Pack) ResourcePackOfferSnapshot {
	snapshot := ResourcePackOfferSnapshot{
		texturePackRequired:        pk.TexturePackRequired,
		hasAddons:                  pk.HasAddons,
		hasScripts:                 pk.HasScripts,
		forceDisableVibrantVisuals: pk.ForceDisableVibrantVisuals,
		worldTemplateUUID:          pk.WorldTemplateUUID,
		worldTemplateVersion:       pk.WorldTemplateVersion,
		texturePacks:               make([]ResourcePackOfferEntry, len(pk.TexturePacks)),
	}
	for i, info := range pk.TexturePacks {
		snapshot.texturePacks[i] = ResourcePackOfferEntry{info: info, pack: matchingResourcePack(info, packs)}
	}
	return snapshot
}

func matchingResourcePack(info protocol.TexturePackInfo, packs []*resource.Pack) *resource.Pack {
	for _, pack := range packs {
		if pack != nil && pack.UUID() == info.UUID && pack.Version() == info.Version {
			return pack.Clone()
		}
	}
	return nil
}

func (snapshot ResourcePackOfferSnapshot) clone() ResourcePackOfferSnapshot {
	cloned := snapshot
	cloned.texturePacks = make([]ResourcePackOfferEntry, len(snapshot.texturePacks))
	for i, entry := range snapshot.texturePacks {
		cloned.texturePacks[i] = entry
		if entry.pack != nil {
			cloned.texturePacks[i].pack = entry.pack.Clone()
		}
	}
	return cloned
}

func (snapshot ResourcePackOfferSnapshot) withPacks(packs []*resource.Pack) ResourcePackOfferSnapshot {
	cloned := snapshot
	cloned.texturePacks = make([]ResourcePackOfferEntry, len(snapshot.texturePacks))
	for i, entry := range snapshot.texturePacks {
		cloned.texturePacks[i] = ResourcePackOfferEntry{info: entry.info, pack: matchingResourcePack(entry.info, packs)}
	}
	return cloned
}

func (snapshot ResourcePackOfferSnapshot) packet() *packet.ResourcePacksInfo {
	pk := &packet.ResourcePacksInfo{
		TexturePackRequired:        snapshot.texturePackRequired,
		HasAddons:                  snapshot.hasAddons,
		HasScripts:                 snapshot.hasScripts,
		ForceDisableVibrantVisuals: snapshot.forceDisableVibrantVisuals,
		WorldTemplateUUID:          snapshot.worldTemplateUUID,
		WorldTemplateVersion:       snapshot.worldTemplateVersion,
		TexturePacks:               make([]protocol.TexturePackInfo, len(snapshot.texturePacks)),
	}
	for i, entry := range snapshot.texturePacks {
		pk.TexturePacks[i] = entry.info
	}
	return pk
}

// TexturePackRequired reports the exact required bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) TexturePackRequired() bool {
	return snapshot.texturePackRequired
}

// HasAddons reports the exact addon capability bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) HasAddons() bool {
	return snapshot.hasAddons
}

// HasScripts reports the exact script capability bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) HasScripts() bool {
	return snapshot.hasScripts
}

// ForceDisableVibrantVisuals reports the exact vibrant-visuals policy bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) ForceDisableVibrantVisuals() bool {
	return snapshot.forceDisableVibrantVisuals
}

// WorldTemplateUUID returns the exact world-template UUID in the advertisement.
func (snapshot ResourcePackOfferSnapshot) WorldTemplateUUID() uuid.UUID {
	return snapshot.worldTemplateUUID
}

// WorldTemplateVersion returns the exact world-template version in the advertisement.
func (snapshot ResourcePackOfferSnapshot) WorldTemplateVersion() string {
	return snapshot.worldTemplateVersion
}

// TexturePacks returns independently owned entries in advertisement order.
func (snapshot ResourcePackOfferSnapshot) TexturePacks() []ResourcePackOfferEntry {
	return slices.Clone(snapshot.texturePacks)
}

// Packs returns independently owned copies of downloaded packs in advertisement order. Entries without
// downloaded content are omitted.
func (snapshot ResourcePackOfferSnapshot) Packs() []*resource.Pack {
	packs := make([]*resource.Pack, 0, len(snapshot.texturePacks))
	for _, entry := range snapshot.texturePacks {
		if pack := entry.Pack(); pack != nil {
			packs = append(packs, pack)
		}
	}
	return packs
}

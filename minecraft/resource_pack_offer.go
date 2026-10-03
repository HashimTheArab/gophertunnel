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
	info  packet.ResourcePacksInfo
	packs resourcePackContent
}

type resourcePackID struct{ uuid, version string }
type resourcePackContent map[resourcePackID]*resource.Pack

// snapshotResourcePacks copies pack metadata so snapshots never expose mutable connection state.
func snapshotResourcePacks(packs []*resource.Pack) resourcePackContent {
	content := make(resourcePackContent, len(packs))
	for _, pack := range packs {
		if pack != nil {
			id := resourcePackID{pack.UUID().String(), pack.Version()}
			if content[id] == nil {
				content[id] = pack.Clone()
			}
		}
	}
	return content
}

// newResourcePackOfferSnapshot retains the wire packet and independent downloaded content.
func newResourcePackOfferSnapshot(pk *packet.ResourcePacksInfo, packs []*resource.Pack) ResourcePackOfferSnapshot {
	snapshot := ResourcePackOfferSnapshot{info: *pk, packs: snapshotResourcePacks(packs)}
	snapshot.info.TexturePacks = slices.Clone(pk.TexturePacks)
	return snapshot
}

// withPacks associates independent content with the immutable offer metadata.
func (snapshot ResourcePackOfferSnapshot) withPacks(packs []*resource.Pack) ResourcePackOfferSnapshot {
	snapshot.packs = snapshotResourcePacks(packs)
	return snapshot
}

// packet returns the advertised offer without exposing its entry slice.
func (snapshot ResourcePackOfferSnapshot) packet() *packet.ResourcePacksInfo {
	pk := snapshot.info
	pk.TexturePacks = slices.Clone(pk.TexturePacks)
	return &pk
}

// TexturePackRequired reports the exact required bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) TexturePackRequired() bool {
	return snapshot.info.TexturePackRequired
}

// HasAddons reports the exact addon capability bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) HasAddons() bool {
	return snapshot.info.HasAddons
}

// HasScripts reports the exact script capability bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) HasScripts() bool {
	return snapshot.info.HasScripts
}

// ForceDisableVibrantVisuals reports the exact vibrant-visuals policy bit in the advertisement.
func (snapshot ResourcePackOfferSnapshot) ForceDisableVibrantVisuals() bool {
	return snapshot.info.ForceDisableVibrantVisuals
}

// WorldTemplateUUID returns the exact world-template UUID in the advertisement.
func (snapshot ResourcePackOfferSnapshot) WorldTemplateUUID() uuid.UUID {
	return snapshot.info.WorldTemplateUUID
}

// WorldTemplateVersion returns the exact world-template version in the advertisement.
func (snapshot ResourcePackOfferSnapshot) WorldTemplateVersion() string {
	return snapshot.info.WorldTemplateVersion
}

// TexturePacks returns independently owned entries in advertisement order.
func (snapshot ResourcePackOfferSnapshot) TexturePacks() []ResourcePackOfferEntry {
	entries := make([]ResourcePackOfferEntry, len(snapshot.info.TexturePacks))
	for i, info := range snapshot.info.TexturePacks {
		entries[i] = ResourcePackOfferEntry{info: info, pack: snapshot.packs[resourcePackID{info.UUID.String(), info.Version}]}
	}
	return entries
}

// Packs returns independently owned copies of downloaded packs in advertisement order. Entries without
// downloaded content are omitted.
func (snapshot ResourcePackOfferSnapshot) Packs() []*resource.Pack {
	packs := make([]*resource.Pack, 0, len(snapshot.info.TexturePacks))
	for _, entry := range snapshot.TexturePacks() {
		if pack := entry.Pack(); pack != nil {
			packs = append(packs, pack)
		}
	}
	return packs
}

// ProjectResourcePacks restricts a proxied offer and stack to the downloaded packs keep accepts, in their
// original order. Offer entries without kept content are dropped and a kept entry advertises the size of the
// content that will be served; stack entries naming a dropped offer entry are dropped, while entries the offer
// never named (built-in packs) remain.
func ProjectResourcePacks(offer ResourcePackOfferSnapshot, stack ResourcePackStackSnapshot, keep func(*resource.Pack) bool) (ResourcePackOfferSnapshot, ResourcePackStackSnapshot) {
	offered, kept := map[resourcePackID]bool{}, resourcePackContent{}
	projectedOffer := offer
	projectedOffer.info.TexturePacks = nil
	projectedOffer.packs = kept
	for _, entry := range offer.TexturePacks() {
		id := resourcePackID{entry.info.UUID.String(), entry.info.Version}
		offered[id] = true
		if entry.pack == nil || !keep(entry.Pack()) {
			continue
		}
		kept[id] = entry.pack
		entry.info.Size = uint64(max(entry.pack.Size(), 0))
		projectedOffer.info.TexturePacks = append(projectedOffer.info.TexturePacks, entry.info)
	}
	projectedStack := stack
	projectedStack.stack.TexturePacks = nil
	projectedStack.packs = resourcePackContent{}
	for _, entry := range stack.stack.TexturePacks {
		id := resourcePackID{entry.UUID, entry.Version}
		if offered[id] && kept[id] == nil {
			continue
		}
		projectedStack.stack.TexturePacks = append(projectedStack.stack.TexturePacks, entry)
		projectedStack.packs[id] = stack.packs[id]
	}
	return projectedOffer, projectedStack
}

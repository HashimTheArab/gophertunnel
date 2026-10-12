package minecraft

import (
	"slices"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackStackEntry is one resource pack selected by a server, together with the exact identity and
// sub-pack name sent for it. Pack returns nil for client-builtin or deliberately ignored entries, and a fresh
// copy for downloaded entries.
type ResourcePackStackEntry struct {
	info protocol.StackResourcePack
	pack *resource.Pack
}

// Pack returns an independently owned copy of the selected resource pack.
func (entry ResourcePackStackEntry) Pack() *resource.Pack {
	if entry.pack == nil {
		return nil
	}
	return entry.pack.Clone()
}

// UUID returns the exact resource-pack UUID sent by the server.
func (entry ResourcePackStackEntry) UUID() string {
	return entry.info.UUID
}

// Version returns the exact resource-pack version sent by the server.
func (entry ResourcePackStackEntry) Version() string {
	return entry.info.Version
}

// SubPackName returns the exact sub-pack name selected by the server. An empty name is a valid selection.
func (entry ResourcePackStackEntry) SubPackName() string {
	return entry.info.SubPackName
}

// ResourcePackStackSnapshot is an immutable snapshot of the server resource-pack stack in the exact order in
// which it was sent. Entries without downloaded content are retained with a nil Pack.
type ResourcePackStackSnapshot struct {
	stack packet.ResourcePackStack
	packs resourcePackContent
}

// newResourcePackStackSnapshot retains the complete wire stack and independent content.
func newResourcePackStackSnapshot(pk *packet.ResourcePackStack, packs []*resource.Pack) ResourcePackStackSnapshot {
	snapshot := ResourcePackStackSnapshot{stack: *pk, packs: snapshotResourcePacks(packs)}
	snapshot.stack = *snapshot.packet()
	return snapshot
}

// packet copies the stack's slices so callers cannot change the snapshot.
func (snapshot ResourcePackStackSnapshot) packet() *packet.ResourcePackStack {
	pk := snapshot.stack
	pk.TexturePacks = slices.Clone(pk.TexturePacks)
	pk.Experiments = slices.Clone(pk.Experiments)
	return &pk
}

// Entries returns independently owned entries in application order.
func (snapshot ResourcePackStackSnapshot) Entries() []ResourcePackStackEntry {
	entries := make([]ResourcePackStackEntry, len(snapshot.stack.TexturePacks))
	for i, info := range snapshot.stack.TexturePacks {
		entries[i] = ResourcePackStackEntry{info: info, pack: snapshot.packs[resourcePackID{info.UUID, info.Version}]}
	}
	return entries
}

// Packs returns independently owned copies of the downloaded packs in application order. Entries without
// downloaded content are omitted. Use Entries to retain exact identities, positions, and sub-pack selections.
func (snapshot ResourcePackStackSnapshot) Packs() []*resource.Pack {
	packs := make([]*resource.Pack, 0, len(snapshot.stack.TexturePacks))
	for _, entry := range snapshot.Entries() {
		if pack := entry.Pack(); pack != nil {
			packs = append(packs, pack)
		}
	}
	return packs
}

// Required reports the exact required bit sent in ResourcePackStack.
func (snapshot ResourcePackStackSnapshot) Required() bool {
	return snapshot.stack.TexturePackRequired
}

// BaseGameVersion returns the exact base game version sent by the server.
func (snapshot ResourcePackStackSnapshot) BaseGameVersion() string {
	return snapshot.stack.BaseGameVersion
}

// Experiments returns an independently owned copy of the experiments sent with the stack.
func (snapshot ResourcePackStackSnapshot) Experiments() []protocol.ExperimentData {
	return slices.Clone(snapshot.stack.Experiments)
}

// ExperimentsPreviouslyToggled reports the exact state sent by the server.
func (snapshot ResourcePackStackSnapshot) ExperimentsPreviouslyToggled() bool {
	return snapshot.stack.ExperimentsPreviouslyToggled
}

// IncludeEditorPacks reports whether the server requested vanilla editor packs in the stack.
func (snapshot ResourcePackStackSnapshot) IncludeEditorPacks() bool {
	return snapshot.stack.IncludeEditorPacks
}

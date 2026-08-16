package minecraft

import (
	"slices"

	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackStackEntry is one downloaded resource pack selected by a server, together with the exact
// sub-pack name selected for it. Its contents are immutable: Pack returns a fresh copy on every call.
type ResourcePackStackEntry struct {
	pack        *resource.Pack
	subPackName string
}

// Pack returns an independently owned copy of the selected resource pack.
func (entry ResourcePackStackEntry) Pack() *resource.Pack {
	if entry.pack == nil {
		return nil
	}
	return entry.pack.Clone()
}

// SubPackName returns the exact sub-pack name selected by the server. An empty name is a valid selection.
func (entry ResourcePackStackEntry) SubPackName() string {
	return entry.subPackName
}

// ResourcePackStackSnapshot is an immutable snapshot of the downloaded server resource packs in the exact
// order in which the server requested that they be applied. Client-builtin and deliberately ignored packs are
// not included because they have no downloaded pack content to hand off.
type ResourcePackStackSnapshot struct {
	entries  []ResourcePackStackEntry
	required bool
}

func newResourcePackStackSnapshot(entries []ResourcePackStackEntry, required bool) ResourcePackStackSnapshot {
	cloned := make([]ResourcePackStackEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = ResourcePackStackEntry{pack: entry.pack.Clone(), subPackName: entry.subPackName}
	}
	return ResourcePackStackSnapshot{entries: cloned, required: required}
}

// Entries returns independently owned entries in application order.
func (snapshot ResourcePackStackSnapshot) Entries() []ResourcePackStackEntry {
	return slices.Clone(snapshot.entries)
}

// Packs returns independently owned copies of the downloaded packs in application order. Use Entries when
// sub-pack selections must also be retained.
func (snapshot ResourcePackStackSnapshot) Packs() []*resource.Pack {
	packs := make([]*resource.Pack, len(snapshot.entries))
	for i, entry := range snapshot.entries {
		packs[i] = entry.Pack()
	}
	return packs
}

// Required reports whether either ResourcePacksInfo or ResourcePackStack required the server packs.
func (snapshot ResourcePackStackSnapshot) Required() bool {
	return snapshot.required
}

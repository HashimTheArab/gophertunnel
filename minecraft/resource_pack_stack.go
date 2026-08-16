package minecraft

import (
	"slices"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackStackEntry is one resource pack selected by a server, together with the exact identity and
// sub-pack name sent for it. Pack returns nil for client-builtin or deliberately ignored entries, and a fresh
// copy for downloaded entries.
type ResourcePackStackEntry struct {
	pack        *resource.Pack
	uuid        string
	version     string
	subPackName string
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
	return entry.uuid
}

// Version returns the exact resource-pack version sent by the server.
func (entry ResourcePackStackEntry) Version() string {
	return entry.version
}

// SubPackName returns the exact sub-pack name selected by the server. An empty name is a valid selection.
func (entry ResourcePackStackEntry) SubPackName() string {
	return entry.subPackName
}

// ResourcePackStackSnapshot is an immutable snapshot of the server resource-pack stack in the exact order in
// which it was sent. Entries without downloaded content are retained with a nil Pack.
type ResourcePackStackSnapshot struct {
	entries                      []ResourcePackStackEntry
	required                     bool
	baseGameVersion              string
	experiments                  []protocol.ExperimentData
	experimentsPreviouslyToggled bool
	includeEditorPacks           bool
}

func newResourcePackStackSnapshot(
	entries []ResourcePackStackEntry,
	required bool,
	baseGameVersion string,
	experiments []protocol.ExperimentData,
	experimentsPreviouslyToggled bool,
	includeEditorPacks bool,
) ResourcePackStackSnapshot {
	cloned := make([]ResourcePackStackEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = entry
		if entry.pack != nil {
			cloned[i].pack = entry.pack.Clone()
		}
	}
	return ResourcePackStackSnapshot{
		entries:                      cloned,
		required:                     required,
		baseGameVersion:              baseGameVersion,
		experiments:                  slices.Clone(experiments),
		experimentsPreviouslyToggled: experimentsPreviouslyToggled,
		includeEditorPacks:           includeEditorPacks,
	}
}

// Entries returns independently owned entries in application order.
func (snapshot ResourcePackStackSnapshot) Entries() []ResourcePackStackEntry {
	return slices.Clone(snapshot.entries)
}

// Packs returns independently owned copies of the downloaded packs in application order. Entries without
// downloaded content are omitted. Use Entries to retain exact identities, positions, and sub-pack selections.
func (snapshot ResourcePackStackSnapshot) Packs() []*resource.Pack {
	packs := make([]*resource.Pack, 0, len(snapshot.entries))
	for _, entry := range snapshot.entries {
		if pack := entry.Pack(); pack != nil {
			packs = append(packs, pack)
		}
	}
	return packs
}

// Required reports whether either ResourcePacksInfo or ResourcePackStack required the server packs.
func (snapshot ResourcePackStackSnapshot) Required() bool {
	return snapshot.required
}

// BaseGameVersion returns the exact base game version sent by the server.
func (snapshot ResourcePackStackSnapshot) BaseGameVersion() string {
	return snapshot.baseGameVersion
}

// Experiments returns an independently owned copy of the experiments sent with the stack.
func (snapshot ResourcePackStackSnapshot) Experiments() []protocol.ExperimentData {
	return slices.Clone(snapshot.experiments)
}

// ExperimentsPreviouslyToggled reports the exact state sent by the server.
func (snapshot ResourcePackStackSnapshot) ExperimentsPreviouslyToggled() bool {
	return snapshot.experimentsPreviouslyToggled
}

// IncludeEditorPacks reports whether the server requested vanilla editor packs in the stack.
func (snapshot ResourcePackStackSnapshot) IncludeEditorPacks() bool {
	return snapshot.includeEditorPacks
}

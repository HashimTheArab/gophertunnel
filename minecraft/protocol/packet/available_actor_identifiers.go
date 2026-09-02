package packet

import (
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/nbt"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AvailableActorIdentifiers is sent by the server at the start of the game to let the client know all
// entities that are available on the server.
type AvailableActorIdentifiers struct {
	// SerialisedEntityIdentifiers is a network NBT serialised compound of all entity identifiers that are
	// available in the server.
	SerialisedEntityIdentifiers []byte
}

// ID ...
func (*AvailableActorIdentifiers) ID() uint32 {
	return IDAvailableActorIdentifiers
}

func (pk *AvailableActorIdentifiers) Marshal(io protocol.IO) {
	io.Bytes(&pk.SerialisedEntityIdentifiers)
}

// AddIdentifier appends one namespaced actor identifier unless it is already advertised.
func (pk *AvailableActorIdentifiers) AddIdentifier(identifier string) error {
	if !protocol.ValidNamespacedIdentifier(identifier) {
		return fmt.Errorf("add actor identifier: %q is not a valid namespaced identifier", identifier)
	}
	var root map[string]any
	if err := nbt.Unmarshal(pk.SerialisedEntityIdentifiers, &root); err != nil {
		return fmt.Errorf("decode actor identifiers: %w", err)
	}
	identifiers, ok := root["idlist"].([]any)
	if !ok {
		return fmt.Errorf("decode actor identifiers: idlist is %T", root["idlist"])
	}
	for _, raw := range identifiers {
		entry, ok := raw.(map[string]any)
		if ok && entry["id"] == identifier {
			return nil
		}
	}
	root["idlist"] = append(identifiers, map[string]any{"id": identifier})
	data, err := nbt.Marshal(root)
	if err != nil {
		return fmt.Errorf("encode actor identifiers: %w", err)
	}
	pk.SerialisedEntityIdentifiers = data
	return nil
}

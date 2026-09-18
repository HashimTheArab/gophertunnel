package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type PlayerStartItemCooldown struct {
	ItemCategory  string
	DurationTicks int32
}

// ID ...
func (*PlayerStartItemCooldown) ID() uint32 {
	return IDPlayerStartItemCooldown
}

func (pk *PlayerStartItemCooldown) Marshal(io protocol.IO) {
	io.String(&pk.ItemCategory)
	io.Varint32(&pk.DurationTicks)
}

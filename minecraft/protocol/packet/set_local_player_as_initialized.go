package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type SetLocalPlayerAsInitialized struct {
	PlayerID uint64
}

// ID ...
func (*SetLocalPlayerAsInitialized) ID() uint32 {
	return IDSetLocalPlayerAsInitialized
}

func (pk *SetLocalPlayerAsInitialized) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.PlayerID)
}

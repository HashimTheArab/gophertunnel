package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type SetLocalPlayerAsInitialized struct {
	PlayerID uint64
}

// ID returns the protocol ID for SetLocalPlayerAsInitialized.
func (*SetLocalPlayerAsInitialized) ID() uint32 { return IDSetLocalPlayerAsInitialized }

// Marshal reads or writes SetLocalPlayerAsInitialized using its canonical wire layout.
func (pk *SetLocalPlayerAsInitialized) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.PlayerID)
}

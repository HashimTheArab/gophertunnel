package packet

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// PlayerSkin is sent by the client to the server when it updates its own skin using the in-game
// skin picker. It is relayed by the server, or sent if the server changes the skin of a player on
// its own accord. Note that the packet can only be sent for players that are in the player list at
// the time of sending.
type PlayerSkin struct {
	// UUID is the UUID of the player as sent in the Login packet when the client joined the server. It
	// must match this UUID exactly for the skin to show up on the player.
	UUID        uuid.UUID
	Skin        protocol.SerializedSkinRef
	NewSkinName string
	OldSkinName string
}

// Marshal reads or writes PlayerSkin using its canonical wire layout.
func (x *PlayerSkin) Marshal(io protocol.IO) {
	io.UUID(&x.UUID)
	x.Skin.Marshal(io)
	io.String(&x.NewSkinName)
	io.String(&x.OldSkinName)
}

// ID returns the protocol ID for PlayerSkin.
func (*PlayerSkin) ID() uint32 { return IDPlayerSkin }

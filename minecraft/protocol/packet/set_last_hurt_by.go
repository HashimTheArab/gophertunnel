package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SetLastHurtBy is sent by the server to let the client know what entity type it was last hurt by. At this
// moment, the packet is useless and should not be used. There is no behaviour that depends on if this packet
// is sent or not.
type SetLastHurtBy struct {
	// EntityType is the numerical type of the entity that the player was last hurt by.
	EntityType protocol.ActorType
}

// ID returns the protocol ID for SetLastHurtBy.
func (*SetLastHurtBy) ID() uint32 { return IDSetLastHurtBy }

// Marshal reads or writes SetLastHurtBy using its canonical wire layout.
func (pk *SetLastHurtBy) Marshal(io protocol.IO) {
	pk.EntityType.Marshal(io)
}

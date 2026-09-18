package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SetActorLink is sent by the server to initiate an entity link client-side, meaning one entity
// will start riding another.
type SetActorLink struct {
	// Link is the link to be set client-side. It links two entities together, so that one entity rides
	// another. Note that players that see those entities later will not see the link, unless it is also
	// sent in the AddActor and AddPlayer packets.
	EntityLink protocol.EntityLink
}

// Marshal reads or writes SetActorLink using its canonical wire layout.
func (x *SetActorLink) Marshal(io protocol.IO) {
	x.EntityLink.Marshal(io)
}

// ID returns the protocol ID for SetActorLink.
func (*SetActorLink) ID() uint32 { return IDSetActorLink }

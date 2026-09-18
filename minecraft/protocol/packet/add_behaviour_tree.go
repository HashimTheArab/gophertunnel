package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AddBehaviorTree is sent by the server to the client. The packet is currently unused by both client and
// server.
type AddBehaviorTree struct {
	// BehaviourTree is an unused string.
	BehaviourTree string
}

// ID ...
func (*AddBehaviorTree) ID() uint32 {
	return IDAddBehaviorTree
}

func (pk *AddBehaviorTree) Marshal(io protocol.IO) {
	io.String(&pk.BehaviourTree)
}

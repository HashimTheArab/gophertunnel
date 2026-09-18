// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type AddBehaviorTree struct {
	BehaviourTree string
}

// Marshal reads or writes AddBehaviorTree using its canonical wire layout.
func (x *AddBehaviorTree) Marshal(io protocol.IO) {
	io.String(&x.BehaviourTree)
}

// ID returns the protocol ID for AddBehaviorTree.
func (*AddBehaviorTree) ID() uint32 { return IDAddBehaviorTree }

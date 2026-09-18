package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// CurrentStructureFeature is sent by the server to let the client know the name of the structure feature that
// the player is currently occupying.
type CurrentStructureFeature struct {
	// CurrentStructureFeature is the identifier of the structure feature that the player is currently occupying.
	// If the player is not occupying any structure feature, this field is empty.
	CurrentFeature string
}

// ID returns the protocol ID for CurrentStructureFeature.
func (*CurrentStructureFeature) ID() uint32 { return IDCurrentStructureFeature }

// Marshal reads or writes CurrentStructureFeature using its canonical wire layout.
func (pk *CurrentStructureFeature) Marshal(io protocol.IO) {
	io.String(&pk.CurrentFeature)
}

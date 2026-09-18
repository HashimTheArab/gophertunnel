package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	SimulationTypeGame    protocol.SimulationTypeEnum = 0
	SimulationTypeEditor  protocol.SimulationTypeEnum = 1
	SimulationTypeTest    protocol.SimulationTypeEnum = 2
	SimulationTypeInvalid protocol.SimulationTypeEnum = 3
)

// SimulationType is an in-progress packet. We currently do not know the use case.
type SimulationType struct {
	// SimType is the simulation type selected.
	SimulationType protocol.SimulationTypeEnum
}

// ID ...
func (*SimulationType) ID() uint32 {
	return IDSimulationType
}

func (pk *SimulationType) Marshal(io protocol.IO) {
	pk.SimulationType.Marshal(io)
}

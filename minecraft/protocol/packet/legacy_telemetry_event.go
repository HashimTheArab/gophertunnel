package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type LegacyTelemetryEvent struct {
	TargetEntityUniqueID int64
	EventType            protocol.LegacyTelemetryType
	UsePlayerID          bool
	EventData            protocol.EventData
}

// ID ...
func (*LegacyTelemetryEvent) ID() uint32 {
	return IDLegacyTelemetryEvent
}

func (pk *LegacyTelemetryEvent) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.TargetEntityUniqueID)
	pk.EventType.Marshal(io)
	io.Bool(&pk.UsePlayerID)
	protocol.MarshalEventData(io, &pk.EventData)
}

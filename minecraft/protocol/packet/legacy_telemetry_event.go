package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type LegacyTelemetryEvent struct {
	TargetActorID int64
	EventType     protocol.LegacyTelemetryType
	UsePlayerID   bool
	EventData     protocol.EventData
}

// Marshal reads or writes LegacyTelemetryEvent using its canonical wire layout.
func (x *LegacyTelemetryEvent) Marshal(io protocol.IO) {
	io.ActorUniqueID(&x.TargetActorID)
	x.EventType.Marshal(io)
	io.Bool(&x.UsePlayerID)
	protocol.MarshalEventData(io, &x.EventData)
}

// ID returns the protocol ID for LegacyTelemetryEvent.
func (*LegacyTelemetryEvent) ID() uint32 { return IDLegacyTelemetryEvent }

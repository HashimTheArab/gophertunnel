package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	ParticleTypeUndefined        protocol.LabTableReactionType = 0
	ParticleTypeBubble           protocol.LabTableReactionType = 1
	ParticleTypeBubbleManual     protocol.LabTableReactionType = 2
	ParticleTypeCrit             protocol.LabTableReactionType = 3
	ParticleTypeBlockForceField  protocol.LabTableReactionType = 4
	ParticleTypeSmoke            protocol.LabTableReactionType = 5
	ParticleTypeExplode          protocol.LabTableReactionType = 6
	ParticleTypeEvaporation      protocol.LabTableReactionType = 7
	ParticleTypeFlame            protocol.LabTableReactionType = 8
	ParticleTypeLava             protocol.LabTableReactionType = 9
	ParticleTypeLargeSmoke       protocol.LabTableReactionType = 10
	ParticleTypeRedDust          protocol.LabTableReactionType = 11
	ParticleTypeRisingBorderDust protocol.LabTableReactionType = 12
)

// LevelEvent is sent by the server to make a certain event in the level occur. It ranges from particles, to
// sounds, and other events such as starting rain and block breaking.
type LevelEvent struct {
	// EventID is the ID of the event that is being 'called'. It is one of the events found in the constants
	// above.
	EventType int32
	// Position is the position of the level event. Practically every event requires this Vec3 set for it, as
	// particles, sounds and block editing relies on it.
	Position mgl32.Vec3
	// Data is an integer holding additional data of the event. The type of data held depends on the EventType.
	EventData int32
}

// ID returns the protocol ID for LevelEvent.
func (*LevelEvent) ID() uint32 { return IDLevelEvent }

// Marshal reads or writes LevelEvent using its canonical wire layout.
func (pk *LevelEvent) Marshal(io protocol.IO) {
	io.Varint32(&pk.EventType)
	io.Vec3(&pk.Position)
	io.Varint32(&pk.EventData)
}

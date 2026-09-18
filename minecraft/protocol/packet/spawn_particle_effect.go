package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SpawnParticleEffect is sent by the server to spawn a particle effect client-side. Unlike other packets that
// result in the appearing of particles, this packet can show particles that are not hardcoded in the client.
// They can be added and changed through behaviour packs to implement custom particles.
type SpawnParticleEffect struct {
	DimensionID uint8
	EntityID    int64
	// Position is the position that the particle should be spawned at. If the position is too far away from the
	// player, it will not show up. If EntityUniqueID is not -1, the position will be relative to the position of
	// the entity.
	Position   mgl32.Vec3
	EffectName string
	// MoLangVariables is an encoded JSON map of MoLang variables that may be applicable to the particle spawn.
	// This can just be left empty in most cases.
	MoLangVariables protocol.Optional[string]
}

// ID ...
func (*SpawnParticleEffect) ID() uint32 {
	return IDSpawnParticleEffect
}

func (pk *SpawnParticleEffect) Marshal(io protocol.IO) {
	io.Uint8(&pk.DimensionID)
	io.ActorUniqueID(&pk.EntityID)
	io.Vec3(&pk.Position)
	io.String(&pk.EffectName)
	protocol.OptionalFunc(io, &pk.MoLangVariables, io.String)
}

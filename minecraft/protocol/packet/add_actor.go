package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AddActor is sent by the server to the client to spawn an entity to the player. It is used for every entity
// except other players, for which the AddPlayer packet is used.
type AddActor struct {
	// EntityUniqueID is the unique ID of the entity. The unique ID is a value that remains consistent across
	// different sessions of the same world, but most servers simply fill the runtime ID of the entity out for
	// this field.
	EntityUniqueID int64
	// EntityRuntimeID is the runtime ID of the entity. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	// EntityType is the string entity type of the entity, for example 'minecraft:skeleton'. A list of these
	// entities may be found online.
	EntityType string
	// Position is the position to spawn the entity on. If the entity is on a distance that the player cannot see
	// it, the entity will still show up if the player moves closer.
	Position mgl32.Vec3
	// Velocity is the initial velocity the entity spawns with. This velocity will initiate client side movement
	// of the entity.
	Velocity      mgl32.Vec3
	Rotation      mgl32.Vec2
	YHeadRotation float32
	YBodyRotation float32
	// Attributes is a slice of attributes that the entity has. It includes attributes such as its health,
	// movement speed, etc.
	Attributes        []protocol.SyncedAttribute
	EntityData        protocol.SynchedActorDataCopyableDataList
	SynchedProperties protocol.PropertySyncData
	// EntityLinks is a list of entity links that are currently active on the entity. These links alter the way
	// the entity shows up when first spawned in terms of it shown as riding an entity. Setting these links is
	// important for new viewers to see the entity is riding another entity.
	EntityLinks []protocol.EntityLink
}

// ID ...
func (*AddActor) ID() uint32 {
	return IDAddActor
}

func (pk *AddActor) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.EntityUniqueID)
	io.ActorRuntimeID(&pk.EntityRuntimeID)
	io.String(&pk.EntityType)
	io.Vec3(&pk.Position)
	io.Vec3(&pk.Velocity)
	io.Vec2(&pk.Rotation)
	io.Float32(&pk.YHeadRotation)
	io.Float32(&pk.YBodyRotation)
	protocol.Slice(io, &pk.Attributes)
	pk.EntityData.Marshal(io)
	pk.SynchedProperties.Marshal(io)
	protocol.Slice(io, &pk.EntityLinks)
}

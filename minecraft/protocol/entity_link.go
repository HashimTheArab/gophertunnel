package protocol

type ActorLinkType uint8

const (
	EntityLinkRemove    ActorLinkType = 0
	EntityLinkRider     ActorLinkType = 1
	EntityLinkPassenger ActorLinkType = 2
)

// Marshal reads or writes ActorLinkType through its uint8 wire encoding.
func (x *ActorLinkType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// EntityLink is a link between two entities, typically being one entity riding another.
type EntityLink struct {
	TargetA int64
	TargetB int64
	// Type is one of the types above. It specifies the way the entity is linked to another entity.
	Type ActorLinkType
	// Immediate is set to immediately dismount an entity from another. This should be set when the mount of an
	// entity is killed.
	Immediate bool
	// RiderInitiated specifies if the link was created by the rider, for example the player starting to ride a
	// horse by itself. This is generally true in vanilla environment for players.
	RiderInitiated bool
	// VehicleAngularVelocity is the angular velocity of the vehicle that the rider is riding.
	VehicleAngularVelocity float32
}

// Marshal reads or writes EntityLink using its canonical wire layout.
func (x *EntityLink) Marshal(io IO) {
	io.ActorUniqueID(&x.TargetA)
	io.ActorUniqueID(&x.TargetB)
	x.Type.Marshal(io)
	io.Bool(&x.Immediate)
	io.Bool(&x.RiderInitiated)
	io.Float32(&x.VehicleAngularVelocity)
}

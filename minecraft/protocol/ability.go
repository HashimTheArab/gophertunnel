package protocol

// SerializedAbilitiesData represents various data about the abilities of a player, such as ability layers or
// permissions.
type AbilityData struct {
	// EntityUniqueID is a unique identifier of the player. It appears it is not required to fill this field out
	// with a correct value. Simply writing 0 seems to work.
	EntityUniqueID int64
	// PlayerPermissions is the permission level of the player as it shows up in the player list built up using
	// the PlayerList packet.
	PlayerPermissions PlayerPermissionLevel
	// CommandPermissions is a set of permissions that specify what commands a player is allowed to execute.
	CommandPermissions CommandPermissionLevel
	// Layers contains all ability layers and their potential values. This should at least have one entry, being
	// the base layer.
	Layers []SerializedAbilitiesDataSerializedLayer
}

// Marshal reads or writes AbilityData using its canonical wire layout.
func (x *AbilityData) Marshal(io IO) {
	io.Int64(&x.EntityUniqueID)
	x.PlayerPermissions.Marshal(io)
	x.CommandPermissions.Marshal(io)
	Slice(io, &x.Layers)
}

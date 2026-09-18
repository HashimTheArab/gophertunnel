package protocol

type SerializedAbilitiesData struct {
	EntityUniqueID     int64
	PlayerPermissions  PlayerPermissionLevel
	CommandPermissions CommandPermissionLevel
	Layers             []SerializedAbilitiesDataSerializedLayer
}

// Marshal reads or writes SerializedAbilitiesData using its canonical wire layout.
func (x *SerializedAbilitiesData) Marshal(io IO) {
	io.Int64(&x.EntityUniqueID)
	x.PlayerPermissions.Marshal(io)
	x.CommandPermissions.Marshal(io)
	Slice(io, &x.Layers)
}

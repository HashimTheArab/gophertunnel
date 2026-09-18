package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// RequestPermissions is a packet sent from the client to the server to request permissions that the client
// does not currently have. It can only be sent by operators and host in vanilla Minecraft.
type RequestPermissions struct {
	// TargetPlayerIDSRawID is the unique ID of the player. The unique ID is unique for the entire world and is
	// often used in packets. Most servers send an EntityUniqueID equal to the EntityRuntimeID.
	EntityUniqueID int64
	// PlayerPermissionLevel is the current permission level of the player. This is one of the constants that may
	// be found in the AdventureSettings packet.
	PermissionLevel int32
	// CustomPermissionFlags contains the requested permission flags.
	RequestedPermissions uint16
}

// ID returns the protocol ID for RequestPermissions.
func (*RequestPermissions) ID() uint32 { return IDRequestPermissions }

// Marshal reads or writes RequestPermissions using its canonical wire layout.
func (pk *RequestPermissions) Marshal(io protocol.IO) {
	io.Int64(&pk.EntityUniqueID)
	io.Varint32(&pk.PermissionLevel)
	io.Uint16(&pk.RequestedPermissions)
}

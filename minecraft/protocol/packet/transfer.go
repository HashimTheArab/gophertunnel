package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// Transfer is sent by the server to transfer a player from the current server to another. Doing so
// will fully disconnect the client, bring it back to the main menu and make it connect to the next
// server.
type Transfer struct {
	// ServerAddress is the address of the new server, which might be either a hostname or an actual IP
	// address.
	Address string
	// ServerPort is the UDP port of the new server.
	Port uint16
	// ReloadWorld currently has an unknown usage.
	ReloadWorld bool
	// GatheringsConfiguration optionally identifies the gathering being joined on the target server.
	GatheringJoinInfo protocol.Optional[protocol.ServerConfigurationGatheringsConfigurationJoinInfo]
}

// Marshal reads or writes Transfer using its canonical wire layout.
func (x *Transfer) Marshal(io protocol.IO) {
	io.String(&x.Address)
	io.Uint16(&x.Port)
	io.Bool(&x.ReloadWorld)
	protocol.OptionalMarshaler(io, &x.GatheringJoinInfo)
}

// ID returns the protocol ID for Transfer.
func (*Transfer) ID() uint32 { return IDTransfer }

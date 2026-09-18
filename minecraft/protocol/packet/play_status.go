package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// PlayStatus is sent by the server to update a player on the play status. This includes failed
// statuses due to a mismatched version, but also success statuses.
type PlayStatus struct {
	// Status is the status of the packet. It is one of the constants found above.
	Status protocol.PlayStatusType
}

// Marshal reads or writes PlayStatus using its canonical wire layout.
func (x *PlayStatus) Marshal(io protocol.IO) {
	x.Status.Marshal(io)
}

// ID returns the protocol ID for PlayStatus.
func (*PlayStatus) ID() uint32 { return IDPlayStatus }

const (
	PlayStatusLoginSuccess             protocol.PlayStatusType = 0
	PlayStatusLoginFailedClient        protocol.PlayStatusType = 1
	PlayStatusLoginFailedServer        protocol.PlayStatusType = 2
	PlayStatusPlayerSpawn              protocol.PlayStatusType = 3
	PlayStatusLoginFailedInvalidTenant protocol.PlayStatusType = 4
	PlayStatusLoginFailedVanillaEdu    protocol.PlayStatusType = 5
	PlayStatusLoginFailedEduVanilla    protocol.PlayStatusType = 6
	PlayStatusLoginFailedServerFull    protocol.PlayStatusType = 7
	PlayStatusLoginFailedEditorVanilla protocol.PlayStatusType = 8
	PlayStatusLoginFailedVanillaEditor protocol.PlayStatusType = 9
)

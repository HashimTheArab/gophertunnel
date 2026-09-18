// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SetScore is sent by the server to send the contents of a scoreboard to the player. It may be used
// to either add, remove or edit entries on the scoreboard.
type SetScore struct {
	// ScoreInfo is a list of all entries that the client should operate on. Each entry's IdentityType
	// specifies whether it is added, modified or removed.
	Entries []protocol.SetScoreEntriesItem
}

// Marshal reads or writes SetScore using its canonical wire layout.
func (x *SetScore) Marshal(io protocol.IO) {
	protocol.FuncSlice(io, &x.Entries, io.Varuint32, func(value *protocol.SetScoreEntriesItem) {
		protocol.MarshalSetScoreEntriesItem(io, value)
	})
}

// ID returns the protocol ID for SetScore.
func (*SetScore) ID() uint32 { return IDSetScore }

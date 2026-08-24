package minecraft

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// protocol2168 is reported by Minecraft 1.26.40 through 1.26.44 alike, so a
// listener cannot tell those versions apart by ID and selects on the login
// game version instead.
const protocol2168 = 2168

// SupportedLegacyProtocols returns the older Minecraft protocols for which
// this package provides compatibility adapters. The returned slice is newly
// allocated and may be modified by the caller.
func SupportedLegacyProtocols() []Protocol {
	return []Protocol{Protocol12640(), Protocol12644()}
}

// Protocol12640 returns the protocol used by Minecraft 1.26.40 through 1.26.43.
func Protocol12640() Protocol {
	return BasicProtocol{Protocol: protocol2168, Version: "1.26.40"}
}

// Protocol12644 returns the protocol used by Minecraft 1.26.44, which changed
// the scoreboard entry encoding without changing the protocol ID.
func Protocol12644() Protocol {
	return protocol12644{BasicProtocol: BasicProtocol{Protocol: protocol2168, Version: "1.26.44"}}
}

type protocol12644 struct {
	BasicProtocol
}

func (p protocol12644) Packets(listener bool) packet.Pool {
	pool := p.BasicProtocol.Packets(listener)
	if !listener {
		pool[packet.IDSetScore] = func() packet.Packet { return &setScore12644{} }
	}
	return pool
}

func (p protocol12644) ConvertToLatest(pk packet.Packet, conn *Conn) []packet.Packet {
	if score, ok := pk.(*setScore12644); ok {
		return []packet.Packet{&packet.SetScore{Entries: score.Entries}}
	}
	return p.BasicProtocol.ConvertToLatest(pk, conn)
}

func (p protocol12644) ConvertFromLatest(pk packet.Packet, conn *Conn) []packet.Packet {
	if score, ok := pk.(*packet.SetScore); ok {
		return []packet.Packet{&setScore12644{Entries: score.Entries}}
	}
	return p.BasicProtocol.ConvertFromLatest(pk, conn)
}

type setScore12644 struct {
	Entries []protocol.ScoreboardEntry
}

func (*setScore12644) ID() uint32 {
	return packet.IDSetScore
}

func (pk *setScore12644) Marshal(io protocol.IO) {
	protocol.FuncIOSlice(io, &pk.Entries, marshalScoreboardEntry12644)
}

// marshalScoreboardEntry12644 encodes the one-patch nested objective optional used by Minecraft 1.26.44.
func marshalScoreboardEntry12644(io protocol.IO, entry *protocol.ScoreboardEntry) {
	variant := uint32(entry.IdentityType)
	io.Varuint32(&variant)
	entry.IdentityType = byte(variant)

	typeNames := [...]string{"remove", "changeplayer", "changeentity", "changefakeplayer"}
	if variant >= uint32(len(typeNames)) {
		io.UnknownEnumOption(variant, "scoreboard entry variant")
		return
	}
	typeName := typeNames[variant]
	io.String(&typeName)
	io.Varint64(&entry.EntryID)
	switch entry.IdentityType {
	case protocol.ScoreboardIdentityRemove:
		objective := protocol.Optional[string]{}
		if entry.ObjectiveName != "" {
			objective = protocol.Option(entry.ObjectiveName)
		}
		protocol.DoubleOptionalFunc(io, &objective, io.String)
		entry.ObjectiveName, _ = objective.Value()
	case protocol.ScoreboardIdentityEntity, protocol.ScoreboardIdentityPlayer:
		io.String(&entry.ObjectiveName)
		io.Int32(&entry.Score)
		io.ActorUniqueID(&entry.EntityUniqueID)
	case protocol.ScoreboardIdentityFakePlayer:
		io.String(&entry.ObjectiveName)
		io.Int32(&entry.Score)
		io.String(&entry.DisplayName)
	}
}

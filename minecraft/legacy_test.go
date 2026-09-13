package minecraft

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// TestLegacyProtocolsShareCurrentID guards the reason these adapters exist: a
// listener selects them on game version because the ID cannot distinguish them.
func TestLegacyProtocolsShareCurrentID(t *testing.T) {
	for _, proto := range []Protocol{Protocol12640(), Protocol12644()} {
		if got := proto.ID(); got != protocol2168 {
			t.Fatalf("%s: ID = %d, want %d", proto.Ver(), got, protocol2168)
		}
		if proto.ID() == protocol.CurrentProtocol && proto.Ver() == protocol.CurrentVersion {
			t.Fatalf("%s: adapter must not shadow the current protocol", proto.Ver())
		}
	}
}

// TestProtocol12644RoundTripsSetScore covers the one packet whose encoding
// changed in 1.26.44 without a protocol ID bump.
func TestProtocol12644RoundTripsSetScore(t *testing.T) {
	proto := Protocol12644()
	if _, ok := proto.Packets(false)[packet.IDSetScore]().(*setScore12644); !ok {
		t.Fatal("server pool must decode SetScore with the 1.26.44 shape")
	}
	// SetScore travels server to client, so a listener pool has no entry for it.
	if _, ok := proto.Packets(true)[packet.IDSetScore]; ok {
		t.Fatal("client pool must not carry a SetScore entry")
	}

	entries := []protocol.ScoreboardEntry{{IdentityType: protocol.ScoreboardIdentityFakePlayer, ObjectiveName: "obj"}}
	out := proto.ConvertFromLatest(&packet.SetScore{Entries: entries}, nil)
	if len(out) != 1 {
		t.Fatalf("ConvertFromLatest returned %d packets, want 1", len(out))
	}
	legacy, ok := out[0].(*setScore12644)
	if !ok {
		t.Fatalf("ConvertFromLatest returned %T, want *setScore12644", out[0])
	}
	back := proto.ConvertToLatest(legacy, nil)
	if len(back) != 1 {
		t.Fatalf("ConvertToLatest returned %d packets, want 1", len(back))
	}
	if _, ok := back[0].(*packet.SetScore); !ok {
		t.Fatalf("ConvertToLatest returned %T, want *packet.SetScore", back[0])
	}
}

// TestProtocol12640PassesPacketsThrough covers 1.26.40 needing no translation.
func TestProtocol12640PassesPacketsThrough(t *testing.T) {
	proto := Protocol12640()
	pk := &packet.SetScore{}
	if out := proto.ConvertToLatest(pk, nil); len(out) != 1 || out[0] != pk {
		t.Fatal("ConvertToLatest must pass the packet through unchanged")
	}
	if out := proto.ConvertFromLatest(pk, nil); len(out) != 1 || out[0] != pk {
		t.Fatal("ConvertFromLatest must pass the packet through unchanged")
	}
}

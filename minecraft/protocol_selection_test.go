package minecraft

import (
	"testing"
)

func selectionConn(clientVersion string, negotiated Protocol, accepted ...Protocol) *Conn {
	conn := &Conn{proto: negotiated, acceptedProto: accepted}
	conn.clientData.GameVersion = clientVersion
	return conn
}

// TestSelectProtocolPicksNewestVersionTheClientReaches covers the case the
// selector exists for: several accepted protocols sharing one ID, told apart
// only by the game version the client sends in Login.
func TestSelectProtocolPicksNewestVersionTheClientReaches(t *testing.T) {
	older, newer := BasicProtocol{Protocol: 900, Version: "1.26.40"}, BasicProtocol{Protocol: 900, Version: "1.26.44"}
	for _, test := range []struct {
		clientVersion string
		want          string
	}{
		{clientVersion: "1.26.40", want: "1.26.40"},
		{clientVersion: "1.26.43", want: "1.26.40"},
		{clientVersion: "1.26.44", want: "1.26.44"},
		{clientVersion: "1.26.44.02", want: "1.26.44"},
		{clientVersion: "1.26.49", want: "1.26.44"},
	} {
		conn := selectionConn(test.clientVersion, older, older, newer)
		if err := conn.selectProtocolByGameVersion(); err != nil {
			t.Fatalf("client %s: %v", test.clientVersion, err)
		}
		if got := conn.proto.Ver(); got != test.want {
			t.Fatalf("client %s: selected %s, want %s", test.clientVersion, got, test.want)
		}
	}
}

// TestSelectProtocolNeedsNoChangeForAFutureVersion guards the reason this is
// generic: a further same-ID split must work by registering an adapter alone.
func TestSelectProtocolNeedsNoChangeForAFutureVersion(t *testing.T) {
	accepted := []Protocol{
		BasicProtocol{Protocol: 900, Version: "1.26.40"},
		BasicProtocol{Protocol: 900, Version: "1.26.44"},
		BasicProtocol{Protocol: 900, Version: "1.27.10"},
	}
	for clientVersion, want := range map[string]string{
		"1.26.44": "1.26.44",
		"1.27.9":  "1.26.44",
		"1.27.10": "1.27.10",
		"1.28.0":  "1.27.10",
	} {
		conn := selectionConn(clientVersion, accepted[0], accepted...)
		if err := conn.selectProtocolByGameVersion(); err != nil {
			t.Fatalf("client %s: %v", clientVersion, err)
		}
		if got := conn.proto.Ver(); got != want {
			t.Fatalf("client %s: selected %s, want %s", clientVersion, got, want)
		}
	}
}

// TestSelectProtocolLeavesUnambiguousNegotiationAlone covers the common case of
// one protocol per ID, where there is nothing to disambiguate.
func TestSelectProtocolLeavesUnambiguousNegotiationAlone(t *testing.T) {
	negotiated := BasicProtocol{Protocol: 900, Version: "1.26.40"}
	other := BasicProtocol{Protocol: 901, Version: "1.26.45"}
	conn := selectionConn("1.26.40", negotiated, negotiated, other)
	if err := conn.selectProtocolByGameVersion(); err != nil {
		t.Fatal(err)
	}
	if conn.pool != nil {
		t.Fatal("an unambiguous negotiation must not rebuild the packet pool")
	}
	if got := conn.proto.Ver(); got != "1.26.40" {
		t.Fatalf("selected %s, want 1.26.40", got)
	}
}

// TestSelectProtocolKeepsNegotiationOnUnparseableVersion covers a client-controlled
// GameVersion: a value we cannot read must not reject an otherwise valid login.
func TestSelectProtocolKeepsNegotiationOnUnparseableVersion(t *testing.T) {
	older, newer := BasicProtocol{Protocol: 900, Version: "1.26.40"}, BasicProtocol{Protocol: 900, Version: "1.26.44"}
	for _, clientVersion := range []string{"", "1.26", "nonsense", "1.x.4"} {
		conn := selectionConn(clientVersion, newer, older, newer)
		if err := conn.selectProtocolByGameVersion(); err != nil {
			t.Fatalf("client %q: %v", clientVersion, err)
		}
		if got := conn.proto.Ver(); got != "1.26.44" {
			t.Fatalf("client %q: selected %s, want the negotiated 1.26.44", clientVersion, got)
		}
	}
}

// TestSelectProtocolRejectsVersionBelowEveryCandidate covers a client claiming
// the shared ID with a version no accepted wire format covers.
func TestSelectProtocolRejectsVersionBelowEveryCandidate(t *testing.T) {
	older, newer := BasicProtocol{Protocol: 900, Version: "1.26.40"}, BasicProtocol{Protocol: 900, Version: "1.26.44"}
	conn := selectionConn("1.26.30", older, older, newer)
	if err := conn.selectProtocolByGameVersion(); err == nil {
		t.Fatal("expected a version below every candidate to be rejected")
	}
}

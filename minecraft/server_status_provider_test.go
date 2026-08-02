package minecraft

import (
	"fmt"
	"testing"
)

// TestParsePongDataReadsVersion covers the fields a Listener writes into the pong. A parser that
// drops what the writer emits silently reports every server as protocol 0.
func TestParsePongDataReadsVersion(t *testing.T) {
	t.Parallel()

	pong := fmt.Appendf(nil, "MCPE;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;",
		"Lunar Proxy", 1002, "1.27.0", 3, 10, 1234, "Lunar Proxy", "Creative", 1, 19132, 19133, 0)

	status := ParsePongData(pong)
	if status.Protocol != 1002 || status.Version != "1.27.0" {
		t.Fatalf("parsed version = %d/%q, want 1002/1.27.0", status.Protocol, status.Version)
	}
	if status.ServerName != "Lunar Proxy" || status.PlayerCount != 3 || status.MaxPlayers != 10 {
		t.Fatalf("parsed status = %+v, want the values written above", status)
	}

	// Third-party servers put arbitrary data in the protocol field; that must not blank the
	// status a ForeignStatusProvider mirrors.
	junk := []byte("MCPE;Some Server;abc;whatever;3;10;1234;Sub;Creative;1;19132;19133;0;")
	if status := ParsePongData(junk); status.ServerName != "Some Server" || status.Protocol != 0 {
		t.Fatalf("junk protocol parsed to %+v, want name kept and protocol 0", status)
	}
}

// TestForeignStatusProviderDropsTargetVersion verifies a mirroring Listener keeps advertising its own
// protocol. Copying the target's would advertise a version the Listener cannot actually speak.
func TestForeignStatusProviderDropsTargetVersion(t *testing.T) {
	t.Parallel()

	f := &ForeignStatusProvider{status: ServerStatus{
		ServerName: "Target", PlayerCount: 2, MaxPlayers: 20, Protocol: 776, Version: "1.21.60",
	}}

	status := f.ServerStatus(0, 0)
	if status.Protocol != 0 || status.Version != "" {
		t.Fatalf("mirrored version = %d/%q, want the Listener's own", status.Protocol, status.Version)
	}
	if status.ServerName != "Target" || status.PlayerCount != 2 || status.MaxPlayers != 20 {
		t.Fatalf("presentation = %+v, want the target's name and counts copied", status)
	}
}

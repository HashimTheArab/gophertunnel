package minecraft

import "testing"

// ParsePong reports malformed pongs as errors; ParsePongData keeps its in-band names.
func TestParsePongReportsMalformedData(t *testing.T) {
	status, err := ParsePong([]byte("MCPE;A Server;900;1.26.30;12;100;123;sub;Creative;1;19132;19133;"))
	if err != nil || status.ServerName != "A Server" || status.PlayerCount != 12 || status.MaxPlayers != 100 || status.ServerSubName != "sub" {
		t.Fatalf("status = %+v err = %v", status, err)
	}
	for _, pong := range []string{"MCPE;short", "MCPE;A;900;1;x;100;1;sub", "MCPE;A;900;1;1;x;1;sub"} {
		if _, err := ParsePong([]byte(pong)); err == nil {
			t.Fatalf("%q parsed", pong)
		}
	}
	if got := ParsePongData([]byte("MCPE;short")).ServerName; got != "Invalid pong data" {
		t.Fatalf("ParsePongData name = %q", got)
	}
}

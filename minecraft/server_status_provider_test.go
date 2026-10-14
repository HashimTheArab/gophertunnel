package minecraft

import (
	"errors"
	"reflect"
	"testing"
)

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

func TestParsePongAdvertisement_AllFields(t *testing.T) {
	got, err := ParsePongAdvertisement([]byte("MCPE;A Server;900;1.26.30;12;100;18446744073709551615;sub;Creative;1;25565;25566;extra;"))
	want := PongAdvertisement{
		Edition: "MCPE", MOTD: "A Server", ProtocolVersion: 900, VersionName: "1.26.30",
		PlayerCount: 12, MaxPlayerCount: 100, ServerID: "18446744073709551615", MOTDLine2: "sub",
		GameMode: "Creative", GameModeNumeric: 1, PortIPv4: 25565, PortIPv6: 25566,
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("advertisement = %#v err = %v; want %#v", got, err, want)
	}
}

func TestParsePongAdvertisement_LegacyAndMalformedNumerics(t *testing.T) {
	for _, pong := range []string{
		"MCPE;Legacy;bad;version;x;y",
		"MCPE;Legacy;bad;version;x;y;;sub;unknown;bad;bad;bad;",
	} {
		got, err := ParsePongAdvertisement([]byte(pong))
		if err != nil || got.MOTD != "Legacy" || got.ProtocolVersion != 0 || got.PlayerCount != 0 ||
			got.MaxPlayerCount != 0 || got.GameModeNumeric != 0 || got.PortIPv4 != 0 || got.PortIPv6 != 0 {
			t.Fatalf("%q advertisement = %#v err = %v", pong, got, err)
		}
	}
	_, err := ParsePongAdvertisement([]byte("MCPE;short"))
	var fieldError PongFieldCountError
	if !errors.As(err, &fieldError) || fieldError.Fields != 2 {
		t.Fatalf("field error = %#v", err)
	}
}

func TestParsePong_PreservesStrictContract(t *testing.T) {
	for _, test := range []struct {
		pong string
		want string
	}{
		{"MCPE;Legacy;900;version;1;10", "invalid pong data"},
		{"MCPE;A;900;version;x;10;1;sub", "invalid player count"},
		{"MCPE;A;900;version;1;x;1;sub", "invalid max player count"},
	} {
		_, err := ParsePong([]byte(test.pong))
		if err == nil || err.Error() != test.want {
			t.Fatalf("%q error = %v; want %q", test.pong, err, test.want)
		}
	}
	got, err := ParsePong([]byte("MCPE;A;invalid;version;1;10;1;sub"))
	if err != nil || got.ServerName != "A" || got.ServerSubName != "sub" || got.PlayerCount != 1 || got.MaxPlayers != 10 {
		t.Fatalf("eight-field status = %#v err = %v", got, err)
	}
}

func TestPongParsers_PreserveBackslashContracts(t *testing.T) {
	pong := []byte(`MCPE;A\B;900;version;1;10;1;sub\name;Survival;0;19132;19133;`)
	advertisement, err := ParsePongAdvertisement(pong)
	if err != nil || advertisement.MOTD != `A\B` || advertisement.MOTDLine2 != `sub\name` {
		t.Fatalf("literal advertisement = %#v err = %v", advertisement, err)
	}
	status, err := ParsePong(pong)
	if err != nil || status.ServerName != "AB" || status.ServerSubName != "subname" {
		t.Fatalf("legacy status = %#v err = %v", status, err)
	}
}

func TestParsePongAdvertisement_PreservesNumericOverflow(t *testing.T) {
	const number = "999999999999999999999999999999999999999999"
	pong := []byte("MCPE;overflow;" + number + ";version;" + number + ";-" + number + ";1;sub;Survival;" + number + ";" + number + ";-" + number)
	got, err := ParsePongAdvertisement(pong)
	maximum := int(^uint(0) >> 1)
	minimum := -maximum - 1
	if err != nil || got.ProtocolVersion != maximum || got.PlayerCount != maximum ||
		got.MaxPlayerCount != minimum || got.GameModeNumeric != maximum || got.PortIPv4 != maximum || got.PortIPv6 != minimum {
		t.Fatalf("overflow advertisement = %#v err = %v", got, err)
	}
	if _, err := ParsePong(pong); err == nil || err.Error() != "invalid player count" {
		t.Fatalf("strict overflow error = %v", err)
	}
}

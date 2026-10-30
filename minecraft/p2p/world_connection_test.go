package p2p

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNetherNetIDMarshalJSONPreservesVanillaNumberShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   NetherNetID
		want []byte
	}{
		{name: "decimal", id: "6503399194777609304", want: []byte(`6503399194777609304`)},
		{name: "opaque", id: "11111111-2222-3333-4444-555555555555", want: []byte(`"11111111-2222-3333-4444-555555555555"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.id)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNetherNetIDRejectsInvalidDecimalForms(t *testing.T) {
	t.Parallel()

	for _, id := range []NetherNetID{"0", "01"} {
		id := id
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			if err := id.Validate(); err == nil {
				t.Fatalf("Validate(%q) succeeded", id)
			}
			if _, err := json.Marshal(id); err == nil {
				t.Fatalf("MarshalJSON(%q) succeeded", id)
			}
		})
	}
}

// A world is joined only through JSON-RPC signaling: a legacy WebSocket-signaling entry is skipped,
// and a world that advertises nothing else is refused before any signaling is dialed.
func TestWorldConnectionSelectsOnlyJSONRPC(t *testing.T) {
	t.Parallel()

	const legacy = `{"ConnectionType":3,"HostIpAddress":"","HostPort":0,"RakNetGUID":"6503399194777609304"}`
	const jsonrpc = `{"ConnectionType":7,"HostIpAddress":"","HostPort":0,"NetherNetId":6503399194777609304,"PmsgId":"11111111-2222-3333-4444-555555555555"}`
	decode := func(connections ...string) World {
		t.Helper()
		var world World
		if err := json.Unmarshal([]byte(`{"TransportLayer":2,"SupportedConnections":[`+strings.Join(connections, ",")+`]}`), &world); err != nil {
			t.Fatal(err)
		}
		return world
	}

	if _, err := decode(legacy).Connection(); err == nil || !strings.Contains(err.Error(), "no supported signaling connection") {
		t.Fatalf("Connection() of a WebSocket-only world error = %v, want no supported signaling connection", err)
	}
	connection, err := decode(legacy, jsonrpc).Connection()
	if err != nil {
		t.Fatalf("Connection(): %v", err)
	}
	if connection.Type != ConnectionTypeSignalingOverJSONRPC || connection.Address() != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("Connection() = %+v, want the JSON-RPC entry", connection)
	}
}

// The friends list keeps worlds with members whose broadcast admits the player, and the player's
// own sessions only for Realms; an experience session follows join-with-friends.
func TestWorldListedFollowsTheFriendsListRule(t *testing.T) {
	friend := func(xuid string) bool { return xuid == "friend" }
	base := World{HostName: "Host", OwnerID: "friend", MemberCount: 1, BroadcastSetting: BroadcastSettingFriendsOfFriends}
	cases := map[string]struct {
		edit func(*World)
		want bool
	}{
		"friends of friends":          {func(*World) {}, true},
		"setting four":                {func(w *World) { w.BroadcastSetting = 4 }, true},
		"friends only, friend host":   {func(w *World) { w.BroadcastSetting = BroadcastSettingFriendsOnly }, true},
		"friends only, stranger host": {func(w *World) { w.BroadcastSetting, w.OwnerID = BroadcastSettingFriendsOnly, "stranger" }, false},
		"invite only":                 {func(w *World) { w.BroadcastSetting = BroadcastSettingInviteOnly }, false},
		"no members":                  {func(w *World) { w.MemberCount = 0 }, false},
		"no host":                     {func(w *World) { w.HostName = "" }, false},
		"own world":                   {func(w *World) { w.OwnerID = "self" }, false},
		"own realm session":           {func(w *World) { w.OwnerID, w.RealmID = "self", 7 }, true},
		"experience":                  {func(w *World) { w.ExperienceID = uuid.New() }, false},
	}
	for name, tc := range cases {
		world := base
		tc.edit(&world)
		if got := world.Listed("self", false, friend); got != tc.want {
			t.Errorf("%s: Listed = %v, want %v", name, got, tc.want)
		}
	}
	experience := base
	experience.ExperienceID = uuid.New()
	if !experience.Listed("self", true, friend) {
		t.Error("an experience session is listed while join-with-friends is enabled")
	}
}

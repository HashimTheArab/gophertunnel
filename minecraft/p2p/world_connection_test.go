package p2p

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
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

func TestConnectionUnmarshalWebSocketUsesRakNetGUID(t *testing.T) {
	t.Parallel()

	var connection Connection
	err := json.Unmarshal([]byte(`{
		"ConnectionType": 3,
		"HostIpAddress": "",
		"HostPort": 0,
		"RakNetGUID": "6503399194777609304"
	}`), &connection)
	if err != nil {
		t.Fatal(err)
	}
	if got := connection.NetherNetID; got != "6503399194777609304" {
		t.Fatalf("NetherNetID = %q, want the RakNetGUID network ID", got)
	}
	if err := connection.Validate(); err != nil {
		t.Fatalf("validate WebSocket connection: %v", err)
	}
	if got := connection.Address(); got != "6503399194777609304" {
		t.Fatalf("Address = %q, want the WebSocket network ID", got)
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

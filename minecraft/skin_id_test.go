package minecraft

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// TestDefaultClientDataSkinID keeps skin-pack IDs independent of authentication and device IDs.
func TestDefaultClientDataSkinID(t *testing.T) {
	for _, test := range []struct {
		name, arm, skin, want string
		persona               bool
	}{
		{name: "default", want: "c18e65aa-7b21-4637-9b63-8ad63622ef01.Custom"},
		{name: "wide", arm: "wide", want: "c18e65aa-7b21-4637-9b63-8ad63622ef01.Custom"},
		{name: "slim", arm: "slim", want: "c18e65aa-7b21-4637-9b63-8ad63622ef01.CustomSlim"},
		{name: "classic", skin: "fixture-pack.Classic", want: "fixture-pack.Classic"},
		{name: "persona", skin: "fixture-persona", want: "fixture-persona", persona: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, id := range []int64{-7, 1} {
				data := login.ClientData{ClientRandomID: id, DeviceID: "fixture-device", SkinID: test.skin, ArmSize: test.arm, PersonaSkin: test.persona}
				for range 2 {
					defaultClientData("example.test:19132", "Fixture", &data)
					if data.SkinID != test.want {
						t.Fatalf("SkinID = %q, want %q", data.SkinID, test.want)
					}
				}
			}
		})
	}
}

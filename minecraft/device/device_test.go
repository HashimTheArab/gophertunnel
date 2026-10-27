package device

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Apply claims the profile's device and its platform's default input mode, leaving other fields alone.
func TestApplyClaimsTheDevice(t *testing.T) {
	profile := Profile{OS: protocol.DeviceAndroid, Model: "Actual hardware model", ID: "00112233445566778899aabbccddeeff"}
	data := login.ClientData{DeviceOS: protocol.DeviceWin32, DeviceModel: "JolyneClient", CurrentInputMode: packet.InputModeMouse, LanguageCode: "de_DE"}
	profile.Apply(&data)
	if data.DeviceOS != protocol.DeviceAndroid || data.DeviceModel != profile.Model || data.DeviceID != profile.ID ||
		data.DefaultInputMode != packet.InputModeTouch || data.CurrentInputMode != packet.InputModeMouse || data.LanguageCode != "de_DE" {
		t.Fatalf("applied client data = %+v", data)
	}
}

// Applying a device to decoded client data that lacked the device claims serializes them, in the
// vanilla claim order.
func TestApplyDeviceToDecodedClientDataSerializesTheClaims(t *testing.T) {
	var data login.ClientData
	if err := json.Unmarshal([]byte(`{"CurrentInputMode":1,"GameVersion":"1.26.50","ThirdPartyName":"Steve"}`), &data); err != nil {
		t.Fatal(err)
	}
	profile := Profile{OS: protocol.DeviceAndroid, Model: "Actual hardware model", ID: "00112233445566778899aabbccddeeff"}
	profile.Apply(&data)
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &claims); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DefaultInputMode", "DeviceId", "DeviceModel", "DeviceOS"} {
		if _, ok := claims[name]; !ok {
			t.Fatalf("serialized login lacks %s: %s", name, encoded)
		}
	}
	text := string(encoded)
	if !(strings.Index(text, `"CurrentInputMode"`) < strings.Index(text, `"DefaultInputMode"`) &&
		strings.Index(text, `"DeviceOS"`) < strings.Index(text, `"GameVersion"`)) {
		t.Fatalf("device claims are out of vanilla order: %s", encoded)
	}
}

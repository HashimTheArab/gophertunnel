package device

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Every OS with models gets a valid profile whose device ID uses that OS's format.
func TestNewProfilesAreValidForTheirOS(t *testing.T) {
	for os := range models {
		profile := New(os)
		if !profile.Valid() || profile.OS != os || profile.Model == "" {
			t.Fatalf("New(%v) = %+v", os, profile)
		}
	}
	android := New(protocol.DeviceAndroid)
	if android.ID.Format() != login.DeviceIDFormatLowerHexString {
		t.Fatalf("Android device ID %q is not lowercase hex", android.ID)
	}
}

// A profile whose model or device ID another OS reports is not valid.
func TestValidRejectsMismatchedModelsAndIDs(t *testing.T) {
	profile := New(protocol.DeviceAndroid)
	wrongModel := profile
	wrongModel.Model = "XboxSeriesX"
	wrongID := profile
	wrongID.ID = login.DeviceIDFormatUpperHexString.Generate()
	for name, candidate := range map[string]Profile{"model": wrongModel, "id": wrongID} {
		if candidate.Valid() {
			t.Fatalf("a mismatched %s was valid: %+v", name, candidate)
		}
	}
}

// Apply claims the profile's device and its platform's default input mode, leaving other fields alone.
func TestApplyClaimsTheDevice(t *testing.T) {
	profile := New(protocol.DeviceAndroid)
	data := login.ClientData{DeviceOS: protocol.DeviceWin32, DeviceModel: "JolyneClient", CurrentInputMode: packet.InputModeMouse, LanguageCode: "de_DE"}
	profile.Apply(&data)
	if data.DeviceOS != protocol.DeviceAndroid || data.DeviceModel != profile.Model || data.DeviceID != profile.ID ||
		data.DefaultInputMode != packet.InputModeTouch || data.CurrentInputMode != packet.InputModeMouse || data.LanguageCode != "de_DE" {
		t.Fatalf("applied client data = %+v", data)
	}
}

// Android signs in as the Android title; an OS without a supported sign-in reports none.
func TestAuthConfigMatchesTheTitle(t *testing.T) {
	config, ok := AuthConfig(protocol.DeviceAndroid)
	if !ok || config.TitleID != auth.AndroidConfig.TitleID {
		t.Fatalf("Android auth config = %v, %t", config.TitleID, ok)
	}
	if _, ok := AuthConfig(protocol.DeviceXBOX); ok {
		t.Fatal("an unsupported sign-in reported a config")
	}
}

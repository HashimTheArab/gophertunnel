package device

import (
	"encoding/json"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// Applying an Android profile supplies its platform type without replacing an explicit nonzero claim.
func TestApplySerializesPlatformType(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		os       protocol.DeviceOS
		platform int
		want     int
	}{
		{name: "android default", os: protocol.DeviceAndroid, want: login.PlatformTypeMobile},
		{name: "android explicit mobile", os: protocol.DeviceAndroid, platform: login.PlatformTypeMobile, want: login.PlatformTypeMobile},
		{name: "android unknown nonzero", os: protocol.DeviceAndroid, platform: 7, want: 7},
		{name: "windows desktop", os: protocol.DeviceWin10, want: login.PlatformTypeDesktop},
		{name: "other os unchanged", os: protocol.DeviceIOS, want: login.PlatformTypeDesktop},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := Profile{OS: test.os, Model: "Actual hardware model", ID: "00112233445566778899aabbccddeeff"}
			data := login.ClientData{PlatformType: test.platform, SkinData: "fixture skin", LanguageCode: "de_DE"}
			profile.Apply(&data)
			claims := serializedPlatformClaims(t, data)
			if got := claims["PlatformType"]; got != float64(test.want) {
				t.Errorf("serialized PlatformType = %v, want %d", got, test.want)
			}
			if data.DeviceOS != profile.OS || data.DeviceID != profile.ID || data.DeviceModel != profile.Model {
				t.Error("applied device differs from the profile")
			}
			if data.SkinData != "fixture skin" || data.LanguageCode != "de_DE" {
				t.Error("applying a profile changed unrelated claims")
			}
		})
	}
}

// Platform defaults must survive serialization when decoded claims omit the field or contain zero.
func TestApplySerializesDecodedAndroidPlatformType(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input string
		want  int
	}{
		{name: "absent platform", input: `{"CurrentInputMode":1,"SkinData":"fixture skin","FixtureClaim":"kept"}`, want: login.PlatformTypeMobile},
		{name: "zero platform", input: `{"CurrentInputMode":1,"PlatformType":0,"SkinData":"fixture skin","FixtureClaim":"kept"}`, want: login.PlatformTypeMobile},
		{name: "unknown nonzero platform", input: `{"CurrentInputMode":1,"PlatformType":7,"SkinData":"fixture skin","FixtureClaim":"kept"}`, want: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data login.ClientData
			if err := json.Unmarshal([]byte(test.input), &data); err != nil {
				t.Fatal(err)
			}
			profile := Profile{OS: protocol.DeviceAndroid, Model: "Actual hardware model", ID: "00112233445566778899aabbccddeeff"}
			profile.Apply(&data)
			claims := serializedPlatformClaims(t, data)
			if got := claims["PlatformType"]; got != float64(test.want) {
				t.Errorf("serialized PlatformType = %v, want %d", got, test.want)
			}
			if claims["DeviceOS"] != float64(profile.OS) || claims["DeviceId"] != string(profile.ID) ||
				claims["DeviceModel"] != profile.Model {
				t.Error("serialized device differs from the profile")
			}
			if claims["CurrentInputMode"] != float64(1) || claims["SkinData"] != "fixture skin" ||
				claims["FixtureClaim"] != "kept" {
				t.Error("applying a profile changed unrelated decoded claims")
			}
		})
	}
}

// serializedPlatformClaims returns the claims a server receives after ClientData's JSON encoding.
func serializedPlatformClaims(t *testing.T, data login.ClientData) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(encoded, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

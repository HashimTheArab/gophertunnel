package minecraft

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// Dial defaults supply the Android platform claim and preserve other OS and explicit nonzero values.
func TestDefaultClientDataSerializesPlatformType(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		data    login.ClientData
		decoded string
		want    int
	}{
		{name: "default android", want: login.PlatformTypeMobile},
		{name: "explicit android", data: login.ClientData{DeviceOS: protocol.DeviceAndroid}, want: login.PlatformTypeMobile},
		{name: "windows desktop", data: login.ClientData{DeviceOS: protocol.DeviceWin10}, want: login.PlatformTypeDesktop},
		{name: "android unknown nonzero", data: login.ClientData{DeviceOS: protocol.DeviceAndroid, PlatformType: 7}, want: 7},
		{name: "decoded absent platform", decoded: `{"DeviceOS":1,"ClientRandomId":-7,"DeviceId":"0123456789abcdef","SkinId":"fixture"}`, want: login.PlatformTypeMobile},
		{name: "decoded zero platform", decoded: `{"DeviceOS":1,"PlatformType":0,"ClientRandomId":-7,"DeviceId":"0123456789abcdef","SkinId":"fixture"}`, want: login.PlatformTypeMobile},
		{name: "decoded unknown nonzero", decoded: `{"DeviceOS":1,"PlatformType":7,"ClientRandomId":-7,"DeviceId":"0123456789abcdef","SkinId":"fixture"}`, want: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.data
			if test.decoded != "" {
				if err := json.Unmarshal([]byte(test.decoded), &data); err != nil {
					t.Fatal(err)
				}
			}
			defaultClientData("example.invalid:19132", "Player", &data)
			encoded, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]any{}
			if err := json.Unmarshal(encoded, &claims); err != nil {
				t.Fatal(err)
			}
			if got := claims["PlatformType"]; got != float64(test.want) {
				t.Errorf("serialized PlatformType = %v, want %d", got, test.want)
			}
			if test.data.DeviceOS != 0 && data.DeviceOS != test.data.DeviceOS {
				t.Error("defaulting changed the supplied device OS")
			}
			if test.decoded != "" {
				if claims["ClientRandomId"] != float64(-7) || claims["DeviceId"] != "0123456789abcdef" ||
					claims["SkinId"] != "fixture" {
					t.Error("defaulting changed supplied identity or skin claims")
				}
			}
		})
	}
}

// Reusing caller-owned decoded data must retain the same supplied skin on each login.
func TestDefaultPlatformTypePreservesReusedClientData(t *testing.T) {
	t.Parallel()
	var original login.ClientData
	input := []byte(`{"DeviceOS":1,"ClientRandomId":-7,"SkinId":"fixture"}`)
	if err := json.Unmarshal(input, &original); err != nil {
		t.Fatal(err)
	}
	original.ClaimOrder = slices.Grow(original.ClaimOrder, 1)
	for range 2 {
		data := original
		defaultClientData("example.invalid:19132", "Player", &data)
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		claims := map[string]any{}
		if err := json.Unmarshal(encoded, &claims); err != nil {
			t.Fatal(err)
		}
		if claims["SkinId"] != "fixture" || claims["PlatformType"] != float64(login.PlatformTypeMobile) {
			t.Errorf("reused login lost supplied skin or platform claim: %s", encoded)
		}
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(input) {
		t.Errorf("defaulting changed caller-owned login claims: got %s, want %s", encoded, input)
	}
}

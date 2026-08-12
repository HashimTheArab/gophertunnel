package login

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestClientDataEditorConnectionFieldsDecode(t *testing.T) {
	var data ClientData
	if err := json.Unmarshal([]byte(`{"ClientIsEditorCapable":true,"ClientEditorConnectionIntent":2}`), &data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !data.ClientIsEditorCapable {
		t.Fatal("ClientIsEditorCapable = false, want true")
	}
	if got := data.ClientEditorConnectionIntent; got != 2 {
		t.Fatalf("ClientEditorConnectionIntent = %d, want 2", got)
	}
}

func TestClientDataOmitsEmptyPartyClaims(t *testing.T) {
	encoded, err := json.Marshal(ClientData{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal fields: %v", err)
	}
	for _, field := range []string{"PartyId", "IsPartyLeader"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("empty client data includes %s", field)
		}
	}
}

func TestClientDataClaimOrderMatchesVanilla(t *testing.T) {
	encoded, err := json.Marshal(ClientData{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := jsonObjectKeys(t, encoded)
	want := []string{
		"AnimatedImageData",
		"ArmSize",
		"CapeData",
		"CapeId",
		"CapeImageHeight",
		"CapeImageWidth",
		"CapeOnClassicSkin",
		"ClientEditorConnectionIntent",
		"ClientIsEditorCapable",
		"ClientRandomId",
		"CompatibleWithClientSideChunkGen",
		"CurrentInputMode",
		"DefaultInputMode",
		"DeviceId",
		"DeviceModel",
		"DeviceOS",
		"FilterProfanity",
		"GameVersion",
		"GraphicsMode",
		"GuiScale",
		"LanguageCode",
		"MaxViewDistance",
		"MemoryTier",
		"OverrideSkin",
		"PersonaPieces",
		"PersonaSkin",
		"PieceTintColors",
		"PlatformOfflineId",
		"PlatformOnlineId",
		"PlatformType",
		"PremiumSkin",
		"SelfSignedId",
		"ServerAddress",
		"SkinAnimationData",
		"SkinColor",
		"SkinData",
		"SkinGeometryData",
		"SkinGeometryDataEngineVersion",
		"SkinId",
		"SkinImageHeight",
		"SkinImageWidth",
		"SkinResourcePatch",
		"ThirdPartyName",
		"TrustedSkin",
		"UIProfile",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("client data claim order:\n got %v\nwant %v", got, want)
	}
}

func TestClientDataPreservesDecodedClaimPresenceOrderAndUnknownFields(t *testing.T) {
	input := []byte(`{"GameVersion":"1.26.33","FutureClientClaim":{"enabled":true},"DeviceOS":1}`)
	var data ClientData
	if err := json.Unmarshal(input, &data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("re-encoded client data:\n got %s\nwant %s", encoded, input)
	}
}

func TestClientDataAppendsNewOptionalClaimAfterDecodedClaims(t *testing.T) {
	var data ClientData
	if err := json.Unmarshal([]byte(`{"GameVersion":"1.26.33"}`), &data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	data.Nonce = "friend-world-nonce"
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(encoded), `{"GameVersion":"1.26.33","Nonce":"friend-world-nonce"}`; got != want {
		t.Fatalf("re-encoded client data = %s, want %s", got, want)
	}
}

func jsonObjectKeys(t *testing.T, data []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		t.Fatalf("read object start: %v", err)
	}
	if token != json.Delim('{') {
		t.Fatalf("first token = %v, want object start", token)
	}
	var keys []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("read object key: %v", err)
		}
		keys = append(keys, token.(string))
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("read %s value: %v", keys[len(keys)-1], err)
		}
	}
	return keys
}

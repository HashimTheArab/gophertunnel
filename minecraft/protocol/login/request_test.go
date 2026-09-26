package login

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	testIdentity     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testSelfSignedID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testXUID         = "2533274790395900"
	testXboxIdentity = "1a730d98-cc7c-3590-8cab-cd4e6472a378"
)

// TestParseIdentity checks identity selection through signed login requests.
func TestParseIdentity(t *testing.T) {
	f := newLoginFixture(t)
	for _, tt := range []struct {
		name                            string
		authType                        uint8
		claims                          tokenClaims
		clientName, selfSignedID, keyID string
		disableVerification             bool
		wantID, wantName, wantXUID      string
		wantAuthenticated, wantError    bool
	}{
		{name: "offline missing UUID", authType: 2, clientName: "Steve", selfSignedID: testSelfSignedID, wantID: testSelfSignedID, wantName: "Steve"},
		{name: "offline malformed UUID", authType: 2, claims: tokenClaims{Identity: "broken"}, clientName: "Steve", selfSignedID: testSelfSignedID, wantID: testSelfSignedID, wantName: "Steve"},
		{name: "offline zero UUID", authType: 2, claims: tokenClaims{Identity: uuid.Nil.String()}, clientName: "Steve", selfSignedID: testSelfSignedID, wantID: testSelfSignedID, wantName: "Steve"},
		{name: "offline valid UUID", authType: 2, claims: tokenClaims{Identity: testIdentity, DisplayName: "TokenName"}, clientName: "ClientName", selfSignedID: testSelfSignedID, wantID: testIdentity, wantName: "ClientName"},
		{name: "offline compact UUID", authType: 2, claims: tokenClaims{Identity: strings.ToUpper(strings.ReplaceAll(testIdentity, "-", ""))}, clientName: "Steve", wantID: testIdentity, wantName: "Steve"},
		{name: "offline URN uses fallback", authType: 2, claims: tokenClaims{Identity: "urn:uuid:" + testIdentity}, clientName: "Steve", selfSignedID: testSelfSignedID, wantID: testSelfSignedID, wantName: "Steve"},
		{name: "offline absent fallback", authType: 2, clientName: "Steve", wantID: uuid.Nil.String(), wantName: "Steve"},
		{name: "offline invalid fallback", authType: 2, clientName: "Steve", selfSignedID: "broken", wantID: uuid.Nil.String(), wantName: "Steve"},
		{name: "offline cannot claim account", authType: 2, claims: tokenClaims{XUID: testXUID, DisplayName: "XboxName", NintendoID: "123", PlayStationID: "456", PlayFabID: "abc", Identity: testIdentity}, clientName: "Steve", wantID: testIdentity, wantName: "Steve"},
		{name: "offline numeric name", authType: 2, clientName: "1234", wantID: uuid.Nil.String(), wantName: "1234"},
		{name: "offline punctuation name", authType: 2, clientName: "____", wantID: uuid.Nil.String(), wantName: "____"},
		{name: "offline Unicode name", authType: 2, clientName: strings.Repeat("é", 16), wantID: uuid.Nil.String(), wantName: strings.Repeat("é", 16)},
		{name: "offline blank name", authType: 2, clientName: "   ", wantError: true},
		{name: "offline forbidden character", authType: 2, clientName: "A@B", wantError: true},
		{name: "offline newline", authType: 2, clientName: "A\nB", wantError: true},
		{name: "offline host key ID is untrusted", authType: 2, keyID: "host", clientName: "A@B", wantError: true},
		{name: "online ignores unused fields", claims: tokenClaims{XUID: testXUID, DisplayName: "XboxName"}, selfSignedID: "broken", wantID: testXboxIdentity, wantName: "XboxName", wantXUID: testXUID, wantAuthenticated: true},
		{name: "online ignores unused long name", claims: tokenClaims{XUID: testXUID, DisplayName: "XboxName"}, clientName: strings.Repeat("a", 17), wantID: testXboxIdentity, wantName: "XboxName", wantXUID: testXUID, wantAuthenticated: true},
		{name: "online UUID precedence", claims: tokenClaims{XUID: testXUID, DisplayName: "XboxName", Identity: testIdentity}, clientName: "Steve", wantID: testXboxIdentity, wantName: "XboxName", wantXUID: testXUID, wantAuthenticated: true},
		{name: "online trusted name", claims: tokenClaims{XUID: testXUID, DisplayName: "1Xbox  名前#123456789"}, wantID: testXboxIdentity, wantName: "1Xbox  名前#123456789", wantXUID: testXUID, wantAuthenticated: true},
		{name: "online missing name uses fallback", claims: tokenClaims{XUID: testXUID}, clientName: "1234", wantID: testXboxIdentity, wantName: "1234", wantXUID: testXUID, wantAuthenticated: true},
		{name: "disabled verification retains platform name", claims: tokenClaims{XUID: testXUID, DisplayName: "XboxName"}, clientName: "ClientName", disableVerification: true, wantID: testXboxIdentity, wantName: "XboxName", wantXUID: testXUID},
		{name: "service token does not use SelfSignedId", claims: tokenClaims{}, clientName: "Steve", selfSignedID: testSelfSignedID, wantID: uuid.Nil.String(), wantName: "Steve"},
		{name: "trusted host sanitizes name", keyID: "host", clientName: "@§A\"B", wantID: uuid.Nil.String(), wantName: "@AB"},
		{name: "unverified host cannot select sanitizer", keyID: "host", clientName: "A@B", disableVerification: true, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := testClientData()
			data.ThirdPartyName, data.SelfSignedID = tt.clientName, tt.selfSignedID
			verifier := f.verifier
			if tt.disableVerification {
				verifier = nil
			}
			req := f.request(t, tt.claims, data, tt.authType, tt.keyID)
			got, _, auth, err := Parse(req, verifier)
			if (err != nil) != tt.wantError {
				t.Fatalf("Parse error = %v, want error %v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if got.Identity != tt.wantID || got.DisplayName != tt.wantName || got.XUID != tt.wantXUID {
				t.Errorf("identity = %+v, want UUID %q, name %q, XUID %q", got, tt.wantID, tt.wantName, tt.wantXUID)
			}
			if auth.XBOXLiveAuthenticated != tt.wantAuthenticated {
				t.Errorf("authenticated = %v, want %v", auth.XBOXLiveAuthenticated, tt.wantAuthenticated)
			}
			if tt.authType == 2 && got.PlayFabID != "" {
				t.Errorf("self-signed login retained PlayFab ID %q", got.PlayFabID)
			}
			if !auth.PublicKey.Equal(&f.clientKey.PublicKey) {
				t.Error("wrong encryption public key")
			}
		})
	}
}

// TestParsePlatformIdentity checks that UUID and name precedence are independent.
func TestParsePlatformIdentity(t *testing.T) {
	f := newLoginFixture(t)
	for _, tt := range []struct {
		name             string
		device           protocol.DeviceOS
		claims           tokenClaims
		wantID, wantName string
	}{
		{"Nintendo", protocol.DeviceNX, tokenClaims{NintendoID: "nintendo-account", NintendoName: "NintendoName", Identity: testIdentity}, "59f8c2e0-6dc2-3047-a1cb-2a2eb617579c", "NintendoName"},
		{"PlayStation", protocol.DeviceOrbis, tokenClaims{PlayStationID: "psn-account", PlayStationName: "PlayStationName", Identity: testIdentity}, "41ad36db-b3bf-3db4-af7e-4316c5e0f622", "PlayStationName"},
		{"Xbox before consoles", protocol.DeviceNX, tokenClaims{XUID: testXUID, DisplayName: "XboxName", NintendoID: "nintendo-account", NintendoName: "NintendoName", PlayStationID: "psn-account", PlayStationName: "PlayStationName"}, testXboxIdentity, "XboxName"},
		{"PlayStation UUID Nintendo name", protocol.DeviceNX, tokenClaims{NintendoID: "nintendo-account", NintendoName: "NintendoName", PlayStationID: "psn-account", PlayStationName: "PlayStationName"}, "41ad36db-b3bf-3db4-af7e-4316c5e0f622", "NintendoName"},
		{"console name on wrong device", protocol.DeviceAndroid, tokenClaims{NintendoID: "nintendo-account", NintendoName: "NintendoName"}, "59f8c2e0-6dc2-3047-a1cb-2a2eb617579c", "Steve"},
		{"console name without account", protocol.DeviceNX, tokenClaims{NintendoName: "NintendoName", Identity: testIdentity}, testIdentity, "Steve"},
		{"Nintendo fallback", protocol.DeviceNX, tokenClaims{Identity: testIdentity}, testIdentity, "Steve"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := testClientData()
			data.DeviceOS = tt.device
			got, _, auth, err := Parse(f.request(t, tt.claims, data, 0, ""), f.verifier)
			if err != nil {
				t.Fatal(err)
			}
			if got.Identity != tt.wantID || got.DisplayName != tt.wantName {
				t.Errorf("identity = %+v, want UUID %q, name %q", got, tt.wantID, tt.wantName)
			}
			if auth.XBOXLiveAuthenticated != (tt.claims.XUID != "") {
				t.Errorf("unexpected Xbox authentication: %v", auth.XBOXLiveAuthenticated)
			}
		})
	}
}

// TestClientDataCannotReplacePublicKey checks that chain-only claims do not rotate the encryption key.
func TestClientDataCannotReplacePublicKey(t *testing.T) {
	f := newLoginFixture(t)
	for _, authType := range []uint8{0, 2} {
		req, err := parseLoginRequest(f.request(t, tokenClaims{Identity: testIdentity}, testClientData(), authType, ""))
		if err != nil {
			t.Fatal(err)
		}
		req.RawToken = signLoginClaims(t, f.clientKey, "", struct {
			ClientData
			IdentityPublicKey string `json:"identityPublicKey"`
		}{testClientData(), MarshalPublicKey(&f.serviceKey.PublicKey)})
		_, _, auth, err := Parse(encodeRequest(req), f.verifier)
		if err != nil {
			t.Fatal(err)
		}
		if !auth.PublicKey.Equal(&f.clientKey.PublicKey) {
			t.Error("client data replaced the encryption key")
		}
	}
}

// TestParseRejectsInvalidSignatures checks both signed parts of a login request.
func TestParseRejectsInvalidSignatures(t *testing.T) {
	f := newLoginFixture(t)
	other := newLoginFixture(t)
	for _, authType := range []uint8{0, 2} {
		for _, part := range []string{"identity", "client"} {
			t.Run(string(rune('0'+authType))+"/"+part, func(t *testing.T) {
				req, err := parseLoginRequest(f.request(t, tokenClaims{}, testClientData(), authType, ""))
				if err != nil {
					t.Fatal(err)
				}
				if part == "identity" {
					var claims tokenClaims
					tok, err := jwt.ParseSigned(req.Token, []jose.SignatureAlgorithm{jose.ES384})
					if err != nil {
						t.Fatal(err)
					}
					if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
						t.Fatal(err)
					}
					req.Token = signLoginClaims(t, other.clientKey, "", claims)
				} else {
					req.RawToken = signLoginClaims(t, other.clientKey, "", testClientData())
				}
				if _, _, _, err := Parse(encodeRequest(req), f.verifier); err == nil {
					t.Fatal("accepted mismatched signature")
				}
			})
		}
	}
}

// TestSelfSignedTokenExpiry checks the expiry boundary without depending on the wall clock.
func TestSelfSignedTokenExpiry(t *testing.T) {
	f := newLoginFixture(t)
	now := time.Unix(1000, 0)
	for _, seconds := range []int64{-1, 999, 1000, 1001} {
		claims := tokenClaims{ClientPublicKey: MarshalPublicKey(&f.clientKey.PublicKey)}
		if seconds >= 0 {
			claims.Expiry = jwt.NewNumericDate(time.Unix(seconds, 0))
		}
		raw := signLoginClaims(t, f.clientKey, "", claims)
		_, _, _, err := parseMultiplayerToken(raw, f.verifier, true, now)
		if (err != nil) != (seconds < 1000) {
			t.Errorf("expiry %d: error %v", seconds, err)
		}
	}
}

// TestEncodeOfflineIdentity checks both offline wire formats with different token and client names.
func TestEncodeOfflineIdentity(t *testing.T) {
	f := newLoginFixture(t)
	for _, legacy := range []bool{false, true} {
		data := testClientData()
		data.ThirdPartyName = "ClientName"
		identity := IdentityData{Identity: testIdentity, DisplayName: "TokenName"}
		got, _, auth, err := Parse(EncodeOffline(identity, data, f.clientKey, legacy), nil)
		if err != nil {
			t.Fatal(err)
		}
		want := "ClientName"
		if legacy {
			want = "TokenName"
		}
		if got.Identity != testIdentity || got.DisplayName != want || auth.XBOXLiveAuthenticated {
			t.Errorf("legacy %v: identity %+v, auth %v", legacy, got, auth)
		}
	}
}

// loginFixture holds independent service and client keys for login verification tests.
type loginFixture struct {
	clientKey, serviceKey *ecdsa.PrivateKey
	verifier              *oidc.IDTokenVerifier
}

// newLoginFixture creates local keys and a verifier without making network requests.
func newLoginFixture(t *testing.T) loginFixture {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oidc.NewVerifier("test", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&serviceKey.PublicKey}}, &oidc.Config{ClientID: "test", SupportedSigningAlgs: []string{"ES384"}})
	return loginFixture{clientKey: clientKey, serviceKey: serviceKey, verifier: verifier}
}

// request signs the multiplayer token and client data with the appropriate independent keys.
func (f loginFixture) request(t *testing.T, claims tokenClaims, data ClientData, authType uint8, keyID string) []byte {
	t.Helper()
	claims.Claims = jwt.Claims{Issuer: "test", Audience: jwt.Audience{"test"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	claims.ClientPublicKey = MarshalPublicKey(&f.clientKey.PublicKey)
	key := f.serviceKey
	if authType == 2 {
		key = f.clientKey
	}
	return encodeRequest(&request{
		AuthenticationType: authType,
		Token:              signLoginClaims(t, key, keyID, claims),
		RawToken:           signLoginClaims(t, f.clientKey, "", data),
	})
}

// signLoginClaims signs a test token with a chosen header key ID.
func signLoginClaims(t *testing.T, key *ecdsa.PrivateKey, keyID string, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", keyID))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testClientData returns unrelated client fields that pass login validation.
func testClientData() ClientData {
	return ClientData{DeviceOS: protocol.DeviceAndroid, GameVersion: "1.26.30", LanguageCode: "en_US", SelfSignedID: testSelfSignedID, ServerAddress: "127.0.0.1:19132", SkinResourcePatch: base64.StdEncoding.EncodeToString([]byte(`{}`)), SkinID: "test", ThirdPartyName: "Steve"}
}

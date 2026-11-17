package mcservices

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const (
	msAccess   = "ms-access-secret"
	userToken  = "user-token-secret"
	xstsToken  = "xsts-token-secret"
	mcAccess   = "mc-access-secret"
	userHash   = "uhs123"
	issuedUnix = 1765293358
)

var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// signJWT returns a compact JWT with claims; it panics on signer misuse, which only a test bug causes.
func signJWT(alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "1"))
	if err != nil {
		panic(err)
	}
	s, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return s
}

func entitlementClaims(names ...string) map[string]any {
	ents := make([]map[string]string, len(names))
	for i, n := range names {
		ents[i] = map[string]string{"name": n}
	}
	return map[string]any{"entitlements": ents, "signerId": "1", "iat": issuedUnix, "nbf": issuedUnix, "exp": issuedUnix + 172800}
}

// licenseBody returns a license response echoing requestID, with items signed in the top-level JWT.
func licenseBody(requestID string, items ...Item) string {
	names := make([]string, len(items))
	wire := make([]map[string]string, len(items))
	for i, it := range items {
		names[i] = it.Name
		wire[i] = map[string]string{"name": it.Name, "source": it.Source, "signature": "item-jwt"}
	}
	b, _ := json.Marshal(map[string]any{
		"items":     wire,
		"signature": signJWT(jose.RS256, testKey(), entitlementClaims(names...)),
		"keyId":     "1",
		"requestId": requestID,
	})
	return string(b)
}

func xboxTokenBody(token string) string {
	return fmt.Sprintf(`{"IssueInstant":"2026-01-01T00:00:00Z","NotAfter":%q,"Token":%q,"DisplayClaims":{"xui":[{"uhs":%q}]}}`,
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339), token, userHash)
}

// server fakes every endpoint; overrides replace the default handler for a path.
func server(t *testing.T, overrides map[string]http.HandlerFunc) (endpoints, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	decode := func(r *http.Request) map[string]any {
		var m map[string]any
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "PC_LAUNCHER") || strings.Contains(strings.ToLower(string(b)), "platform") {
			t.Errorf("%s: request names a platform: %s", r.URL.Path, b)
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("%s: request body: %v", r.URL.Path, err)
		}
		return m
	}
	defaults := map[string]http.HandlerFunc{
		"/user/authenticate": func(w http.ResponseWriter, r *http.Request) {
			m := decode(r)
			p, _ := m["Properties"].(map[string]any)
			if p["RpsTicket"] != "d="+msAccess || p["AuthMethod"] != "RPS" || m["RelyingParty"] != "http://auth.xboxlive.com" {
				t.Errorf("user auth request: %v", m)
			}
			_, _ = io.WriteString(w, xboxTokenBody(userToken))
		},
		"/xsts/authorize": func(w http.ResponseWriter, r *http.Request) {
			m := decode(r)
			p, _ := m["Properties"].(map[string]any)
			if m["RelyingParty"] != "rp://api.minecraftservices.com/" || p["SandboxId"] != "RETAIL" || fmt.Sprint(p["UserTokens"]) != "["+userToken+"]" {
				t.Errorf("xsts request: %v", m)
			}
			_, _ = io.WriteString(w, xboxTokenBody(xstsToken))
		},
		"/authentication/login_with_xbox": func(w http.ResponseWriter, r *http.Request) {
			if m := decode(r); m["identityToken"] != "XBL3.0 x="+userHash+";"+xstsToken {
				t.Errorf("login request: %v", m)
			}
			_, _ = fmt.Fprintf(w, `{"username":"u","roles":[],"access_token":%q,"token_type":"Bearer","expires_in":86400}`, mcAccess)
		},
		"/entitlements/license": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, licenseBody(r.URL.Query().Get("requestId"), Item{Name: "game_minecraft_bedrock", Source: "PURCHASE"}))
		},
	}
	mux := http.NewServeMux()
	for path, h := range defaults {
		if o, ok := overrides[path]; ok {
			h = o
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if path == "/entitlements/license" && r.Header.Get("Authorization") != "Bearer "+mcAccess {
				t.Errorf("license auth header: %q", r.Header.Get("Authorization"))
			}
			h(w, r)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return endpoints{
		userAuth: srv.URL + "/user/authenticate",
		xsts:     srv.URL + "/xsts/authorize",
		login:    srv.URL + "/authentication/login_with_xbox",
		license:  srv.URL + "/entitlements/license",
	}, &hits
}

func msToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: msAccess, Expiry: time.Now().Add(time.Hour)}
}

func run(t *testing.T, overrides map[string]http.HandlerFunc) (*Entitlements, error) {
	t.Helper()
	ep, _ := server(t, overrides)
	e, err := fetch(t.Context(), nil, msToken(), ep)
	if err != nil {
		for _, secret := range []string{msAccess, userToken, xstsToken, mcAccess} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks a token: %v", err)
			}
		}
	}
	return e, err
}

func licenseItems(items ...Item) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{"/entitlements/license": func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, licenseBody(r.URL.Query().Get("requestId"), items...))
	}}
}

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// Ownership comes only from a 200 license answer; the cached JWT parses back to the same names.
func TestFetchOwnership(t *testing.T) {
	for _, tc := range []struct {
		name  string
		items []Item
		plays bool
	}{
		{"bedrock", []Item{{"game_minecraft_bedrock", "PURCHASE"}, {"product_minecraft_bedrock", "PURCHASE"}}, true},
		{"java only", []Item{{"game_minecraft", "PURCHASE"}, {"product_minecraft", "PURCHASE"}}, true},
		{"game pass", []Item{{"product_game_pass_ultimate", "GAMEPASS"}, {"game_minecraft_bedrock", "GAMEPASS"}}, true},
		{"other games", []Item{{"product_dungeons", "PURCHASE"}}, false},
		{"empty items", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := run(t, licenseItems(tc.items...))
			if err != nil {
				t.Fatal(err)
			}
			if e.PlaysMinecraft() != tc.plays {
				t.Fatalf("PlaysMinecraft = %v, want %v", e.PlaysMinecraft(), tc.plays)
			}
			if len(e.Items) != len(tc.items) || e.RequestID == "" || !e.IssuedAt.Equal(time.Unix(issuedUnix, 0)) {
				t.Fatalf("entitlements = %+v", e)
			}
			cached, err := Parse(e.Signed)
			if err != nil {
				t.Fatal(err)
			}
			if cached.PlaysMinecraft() != tc.plays || !cached.IssuedAt.Equal(e.IssuedAt) || !cached.ExpiresAt.Equal(e.ExpiresAt) {
				t.Fatalf("cached = %+v", cached)
			}
		})
	}
}

// An unsigned empty answer still means "not owned", not an error.
func TestFetchUnsignedEmpty(t *testing.T) {
	e, err := run(t, map[string]http.HandlerFunc{"/entitlements/license": func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"items":[],"requestId":%q}`, r.URL.Query().Get("requestId"))
	}})
	if err != nil {
		t.Fatal(err)
	}
	if e.PlaysMinecraft() || e.Signed != nil {
		t.Fatalf("entitlements = %+v", e)
	}
}

// Every failure surfaces as a typed error, never as "not owned".
func TestFetchErrors(t *testing.T) {
	sameID := func(f func(id string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, f(r.URL.Query().Get("requestId")))
		}
	}
	for _, tc := range []struct {
		name      string
		overrides map[string]http.HandlerFunc
		is        error
		status    int
	}{
		{"app not approved", map[string]http.HandlerFunc{"/authentication/login_with_xbox": respond(403,
			`{"path":"/authentication/login_with_xbox","errorMessage":"Invalid app registration, see https://aka.ms/AppRegInfo for more information"}`)}, ErrAppNotApproved, 0},
		{"suspended", map[string]http.HandlerFunc{"/authentication/login_with_xbox": respond(403,
			`{"details":{"reason":"ACCOUNT_SUSPENDED"},"errorMessage":"Your account has been suspended."}`)}, nil, 403},
		{"user auth 401", map[string]http.HandlerFunc{"/user/authenticate": respond(401, ``)}, ErrUnauthorized, 0},
		{"license 401", map[string]http.HandlerFunc{"/entitlements/license": respond(401, ``)}, ErrUnauthorized, 0},
		{"license 5xx", map[string]http.HandlerFunc{"/entitlements/license": respond(503, `oops`)}, nil, 503},
		{"xsts 5xx", map[string]http.HandlerFunc{"/xsts/authorize": respond(500, `{}`)}, nil, 500},
		{"license not json", map[string]http.HandlerFunc{"/entitlements/license": respond(200, `<html>`)}, ErrMalformedResponse, 0},
		{"login without token", map[string]http.HandlerFunc{"/authentication/login_with_xbox": respond(200, `{}`)}, ErrMalformedResponse, 0},
		{"xsts without user", map[string]http.HandlerFunc{"/xsts/authorize": respond(200, `{"Token":"x","NotAfter":"2999-01-01T00:00:00Z"}`)}, ErrMalformedResponse, 0},
		{"garbage signature", map[string]http.HandlerFunc{"/entitlements/license": sameID(func(id string) string {
			return fmt.Sprintf(`{"items":[{"name":"game_minecraft"}],"signature":"a.b","requestId":%q}`, id)
		})}, ErrMalformedResponse, 0},
		{"unsigned items", map[string]http.HandlerFunc{"/entitlements/license": sameID(func(id string) string {
			return fmt.Sprintf(`{"items":[{"name":"game_minecraft"}],"requestId":%q}`, id)
		})}, ErrMalformedResponse, 0},
		{"signed items differ", map[string]http.HandlerFunc{"/entitlements/license": sameID(func(id string) string {
			b, _ := json.Marshal(map[string]any{
				"items":     []map[string]string{{"name": "game_minecraft_bedrock"}},
				"signature": signJWT(jose.RS256, testKey(), entitlementClaims()),
				"requestId": id,
			})
			return string(b)
		})}, ErrMalformedResponse, 0},
		{"requestId mismatch", map[string]http.HandlerFunc{"/entitlements/license": sameID(func(string) string {
			return licenseBody("00000000-0000-4000-8000-000000000000", Item{Name: "game_minecraft"})
		})}, ErrRequestIDMismatch, 0},
		{"requestId missing", map[string]http.HandlerFunc{"/entitlements/license": sameID(func(string) string {
			return licenseBody("", Item{Name: "game_minecraft"})
		})}, ErrRequestIDMismatch, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := run(t, tc.overrides)
			if err == nil {
				t.Fatalf("got %+v, want error", e)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
			var status *xal.StatusError
			if tc.status != 0 && (!errors.As(err, &status) || status.StatusCode != tc.status) {
				t.Fatalf("err = %v, want status %d", err, tc.status)
			}
		})
	}
}

// XSTS refusals carry their XErr code.
func TestFetchXErr(t *testing.T) {
	for _, code := range []uint32{XErrNoProfile, XErrRegionUnavailable, XErrAdultVerification, XErrAdultVerificationAlt, XErrChildAccount} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			_, err := run(t, map[string]http.HandlerFunc{"/xsts/authorize": respond(401,
				fmt.Sprintf(`{"Identity":"0","XErr":%d,"Message":"","Redirect":"https://start.ui.xboxlive.com/"}`, code))})
			var xerr *XboxError
			if !errors.As(err, &xerr) || xerr.XErr != code {
				t.Fatalf("err = %v, want XErr %d", err, code)
			}
		})
	}
}

// An expired Microsoft token fails before any request is sent.
func TestFetchExpiredToken(t *testing.T) {
	ep, hits := server(t, nil)
	_, err := fetch(t.Context(), nil, &oauth2.Token{AccessToken: msAccess, Expiry: time.Now().Add(-time.Hour)}, ep)
	if !errors.Is(err, ErrUnauthorized) || hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d", err, hits.Load())
	}
}

// Parse accepts only RS256 documents with entitlements and iat.
func TestParseRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"hs256":           signJWT(jose.HS256, []byte("0123456789abcdef0123456789abcdef"), entitlementClaims("game_minecraft")),
		"no iat":          signJWT(jose.RS256, testKey(), map[string]any{"entitlements": []any{}}),
		"no entitlements": signJWT(jose.RS256, testKey(), map[string]any{"iat": issuedUnix}),
		"not a jwt":       "nope",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestOAuthConfig(t *testing.T) {
	c := OAuthConfig("client")
	if c.ClientID != "client" || c.Endpoint.DeviceAuthURL != "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode" ||
		strings.Join(c.Scopes, " ") != "XboxLive.signin offline_access" {
		t.Fatalf("config = %+v", c)
	}
}

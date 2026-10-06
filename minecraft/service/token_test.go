package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestDecodeClaimsAllowsSmallIssuedAtSkew(t *testing.T) {
	t.Parallel()

	token := &Token{AuthorizationHeader: testAuthorizationHeader(t, time.Now().Add(2*time.Minute))}
	if err := decodeClaims(token, time.Time{}); err != nil {
		t.Fatalf("decodeClaims: %v", err)
	}
	if token.Claims.PlayerMessagingID == uuid.Nil {
		t.Fatal("PlayerMessagingID was not decoded")
	}
}

func TestDecodeClaimsRejectsLargeIssuedAtSkewWithoutServiceTime(t *testing.T) {
	t.Parallel()

	token := &Token{AuthorizationHeader: testAuthorizationHeader(t, time.Now().Add(10*time.Minute))}
	err := decodeClaims(token, time.Time{})
	if !errors.Is(err, jwt.ErrIssuedInTheFuture) {
		t.Fatalf("decodeClaims error = %v, want ErrIssuedInTheFuture", err)
	}
}

func TestDecodeClaimsUsesServiceTime(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().Add(90 * time.Minute)
	token := &Token{AuthorizationHeader: testAuthorizationHeaderWithTimes(t, serviceNow, serviceNow.Add(time.Hour))}
	if err := decodeClaims(token, serviceNow); err != nil {
		t.Fatalf("decodeClaims: %v", err)
	}
}

func TestDecodeClaimsStillRejectsExpiredTokenWithServiceTime(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().Add(90 * time.Minute)
	token := &Token{AuthorizationHeader: testAuthorizationHeaderWithTimes(t, serviceNow.Add(-time.Hour), serviceNow.Add(-10*time.Minute))}
	err := decodeClaims(token, serviceNow)
	if !errors.Is(err, jwt.ErrExpired) {
		t.Fatalf("decodeClaims error = %v, want ErrExpired", err)
	}
}

func TestAuthorizationEnvironmentTokenRetainsResponseDateForValidity(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().UTC().Add(-90 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", serviceNow.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": &Token{
				AuthorizationHeader: testAuthorizationHeaderWithTimes(t, serviceNow, serviceNow.Add(time.Hour)),
				ValidUntil:          serviceNow.Add(time.Hour),
			},
		})
	}))
	defer server.Close()

	serviceURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	token, err := env.Token(context.Background(), TokenConfig{User: UserConfig{Token: "playfab-token"}})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !token.Valid() {
		t.Fatal("Valid() = false, want true using retained response Date")
	}
}

func TestAuthorizationEnvironmentTokenUsesResponseDateForIssuedAt(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().UTC().Add(90 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", serviceNow.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": &Token{
				AuthorizationHeader: testAuthorizationHeaderWithTimes(t, serviceNow, serviceNow.Add(time.Hour)),
				ValidUntil:          serviceNow.Add(time.Hour),
			},
		})
	}))
	defer server.Close()

	serviceURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	if _, err := env.Token(context.Background(), TokenConfig{User: UserConfig{Token: "playfab-token"}}); err != nil {
		t.Fatalf("Token: %v", err)
	}
}

func TestAuthorizationEnvironmentMultiplayerTokenUsesResponseDateForValidation(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().UTC().Add(-90 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", serviceNow.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": &multiplayerToken{
				IssuedAt:    serviceNow,
				SignedToken: "multiplayer-token",
				ValidUntil:  serviceNow.Add(time.Hour),
			},
		})
	}))
	defer server.Close()

	serviceURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	token, err := env.MultiplayerToken(context.Background(), staticTokenSource{
		token: &Token{AuthorizationHeader: "service-token"},
	}, &key.PublicKey)
	if err != nil {
		t.Fatalf("MultiplayerToken: %v", err)
	}
	if token != "multiplayer-token" {
		t.Fatalf("MultiplayerToken = %q, want multiplayer-token", token)
	}
}

type staticTokenSource struct {
	token *Token
}

func (s staticTokenSource) ServiceToken(context.Context) (*Token, error) {
	return s.token, nil
}

func testAuthorizationHeader(t *testing.T, issuedAt time.Time) string {
	return testAuthorizationHeaderWithTimes(t, issuedAt, time.Now().Add(time.Hour))
}

func testAuthorizationHeaderWithTimes(t *testing.T, issuedAt, expiry time.Time) string {
	t.Helper()

	payload, err := json.Marshal(struct {
		PlayerMessagingID uuid.UUID `json:"pmid"`
		IssuedAt          int64     `json:"iat"`
		Expiry            int64     `json:"exp"`
	}{
		PlayerMessagingID: uuid.New(),
		IssuedAt:          issuedAt.Unix(),
		Expiry:            expiry.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return "MCToken header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

type fixedTickets struct{}

func (fixedTickets) SessionTicket(context.Context) (string, error) { return "ticket", nil }

// newSessionServer serves session/start and multiplayer/session/start and returns, per call,
// the Session-Id it received and the session/start device.networkProtocolVersion.
func newSessionServer(t *testing.T) (*AuthorizationEnvironment, func() ([]string, any)) {
	var (
		mu              sync.Mutex
		sessions        []string
		protocolVersion any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sessions = append(sessions, r.Header.Get("Session-Id"))
		mu.Unlock()
		now := time.Now().UTC().Truncate(time.Second)
		if r.URL.Path == "/api/v1.0/multiplayer/session/start" {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": &multiplayerToken{
				IssuedAt: now, SignedToken: "multiplayer-token", ValidUntil: now.Add(time.Hour),
			}})
			return
		}
		var body struct {
			Device map[string]any `json:"device"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		protocolVersion = body.Device["networkProtocolVersion"]
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"result": &Token{
			AuthorizationHeader: testAuthorizationHeaderWithTimes(t, now, now.Add(time.Hour)),
			ValidUntil:          now.Add(time.Hour),
		}})
	}))
	t.Cleanup(server.Close)
	serviceURL, _ := url.Parse(server.URL)
	env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	return env, func() ([]string, any) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sessions...), protocolVersion
	}
}

// startAndMint issues a service token and a multiplayer token through src.
func startAndMint(t *testing.T, env *AuthorizationEnvironment, src TokenSource) {
	t.Helper()
	if _, err := src.ServiceToken(context.Background()); err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := env.MultiplayerToken(context.Background(), src, &key.PublicKey); err != nil {
		t.Fatalf("MultiplayerToken: %v", err)
	}
}

// Accounts sharing one process and environment must not share a Session-Id.
func TestTokenSourcesNameTheirOwnSession(t *testing.T) {
	t.Parallel()

	env, recorded := newSessionServer(t)
	startAndMint(t, env, env.ResumeTokenSource(fixedTickets{}, TokenConfig{}, nil))
	startAndMint(t, env, env.ResumeTokenSource(fixedTickets{}, TokenConfig{}, nil))
	sessions, protocolVersion := recorded()
	if len(sessions) != 4 || sessions[0] != sessions[1] || sessions[2] != sessions[3] || sessions[0] == sessions[2] {
		t.Fatalf("Session-Ids = %q, want one per source shared by its start and mint", sessions)
	}
	for _, id := range sessions {
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("Session-Id %q is not a UUID", id)
		}
	}
	if protocolVersion != float64(protocol.CurrentProtocol) {
		t.Fatalf("device.networkProtocolVersion = %v, want %d", protocolVersion, protocol.CurrentProtocol)
	}
}

// A source keeps its session when it replaces its token, as the game does within one launch.
func TestTokenSourceKeepsSessionAcrossRefreshes(t *testing.T) {
	t.Parallel()

	env, recorded := newSessionServer(t)
	src := env.ResumeTokenSource(fixedTickets{}, TokenConfig{}, nil)
	first, err := src.ServiceToken(context.Background())
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	src.(TokenInvalidator).InvalidateServiceToken(first)
	startAndMint(t, env, src)
	sessions, _ := recorded()
	if len(sessions) != 3 || sessions[0] == "" || sessions[0] != sessions[1] || sessions[1] != sessions[2] {
		t.Fatalf("Session-Ids = %q, want one across both starts and the mint", sessions)
	}
}

// A caller-supplied session, such as a proxy's per-login ID, is sent as given.
func TestTokenSourceHonoursCallerSessionID(t *testing.T) {
	t.Parallel()

	env, recorded := newSessionServer(t)
	src := &ManagedTokenSource{TokenSource: env.ResumeTokenSource(fixedTickets{}, TokenConfig{SessionID: "caller-session"}, nil)}
	startAndMint(t, env, src)
	if sessions, _ := recorded(); len(sessions) != 2 || sessions[0] != "caller-session" || sessions[1] != "caller-session" {
		t.Fatalf("Session-Ids = %q, want caller-session on start and mint", sessions)
	}
}

func TestTokenRemainingUsesTheRetainedServiceClock(t *testing.T) {
	t.Parallel()

	serviceNow := time.Now().Add(-90 * time.Minute)
	token := &Token{AuthorizationHeader: "MCToken test", ValidUntil: serviceNow.Add(time.Hour)}
	if token.Remaining() > 0 || token.Valid() {
		t.Fatal("token without a service clock should be expired on the local clock")
	}
	token.setServerTime(serviceNow)
	if remaining := token.Remaining(); remaining < 58*time.Minute || remaining > time.Hour || !token.Valid() {
		t.Fatalf("Remaining() = %v, want about 59m on the service clock", remaining)
	}
}

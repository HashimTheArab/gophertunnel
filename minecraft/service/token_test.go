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

// Both authorization calls name one launch session and report the network protocol, as the game does.
func TestAuthorizationRequestsCarrySessionIDAndProtocol(t *testing.T) {
	t.Parallel()

	sessions := map[string]string{}
	var protocolVersion any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions[r.URL.Path] = r.Header.Get("Session-Id")
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
		protocolVersion = body.Device["networkProtocolVersion"]
		_ = json.NewEncoder(w).Encode(map[string]any{"result": &Token{
			AuthorizationHeader: testAuthorizationHeaderWithTimes(t, now, now.Add(time.Hour)),
			ValidUntil:          now.Add(time.Hour),
		}})
	}))
	defer server.Close()

	serviceURL, _ := url.Parse(server.URL)
	env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	token, err := env.Token(context.Background(), TokenConfig{User: UserConfig{Token: "playfab-token"}})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := env.MultiplayerToken(context.Background(), staticTokenSource{token: token}, &key.PublicKey); err != nil {
		t.Fatalf("MultiplayerToken: %v", err)
	}
	start, mint := sessions["/api/v1.0/session/start"], sessions["/api/v1.0/multiplayer/session/start"]
	if _, err := uuid.Parse(start); err != nil || start != mint {
		t.Fatalf("Session-Id start=%q mint=%q, want one UUID on both", start, mint)
	}
	if protocolVersion != float64(protocol.CurrentProtocol) {
		t.Fatalf("device.networkProtocolVersion = %v, want %d", protocolVersion, protocol.CurrentProtocol)
	}
}

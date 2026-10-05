package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type countingTickets struct{ calls atomic.Int32 }

func (c *countingTickets) SessionTicket(context.Context) (string, error) {
	c.calls.Add(1)
	return "", errors.New("no playfab session in this test")
}

// A resumed valid token is served without asking for a session ticket.
func TestResumeTokenSourceReusesTheRestoredToken(t *testing.T) {
	t.Parallel()

	tickets := new(countingTickets)
	restored := &Token{AuthorizationHeader: testAuthorizationHeader(t, time.Now()), ValidUntil: time.Now().Add(time.Hour)}
	if err := decodeClaims(restored, time.Now()); err != nil {
		t.Fatal(err)
	}
	env := &AuthorizationEnvironment{PlayFabTitleID: "20CA2"}
	src := env.ResumeTokenSource(tickets, TokenConfig{}, restored)
	token, err := src.ServiceToken(context.Background())
	if err != nil || token != restored || tickets.calls.Load() != 0 {
		t.Fatalf("token = %v err = %v tickets = %d", token, err, tickets.calls.Load())
	}
	src.(TokenInvalidator).InvalidateServiceToken(restored)
	if _, err := src.ServiceToken(context.Background()); err == nil || tickets.calls.Load() != 1 {
		t.Fatalf("invalidated token was reused: err = %v tickets = %d", err, tickets.calls.Load())
	}
}

// JSON persistence omits claims, so resuming must recover the signaling identity from the JWT.
func TestResumeTokenSourceRestoresPersistedClaims(t *testing.T) {
	t.Parallel()

	issued := &Token{AuthorizationHeader: testAuthorizationHeader(t, time.Now()), ValidUntil: time.Now().Add(time.Hour)}
	if err := decodeClaims(issued, time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	var restored Token
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	tickets := new(countingTickets)
	env := &AuthorizationEnvironment{PlayFabTitleID: "20CA2"}
	token, err := env.ResumeTokenSource(tickets, TokenConfig{}, &restored).ServiceToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token.Claims.PlayerMessagingID != issued.Claims.PlayerMessagingID || token.AuthorizationHeader != issued.AuthorizationHeader || tickets.calls.Load() != 0 {
		t.Fatalf("claims were not restored without renewing: pmid = %v tickets = %d", token.Claims.PlayerMessagingID, tickets.calls.Load())
	}
	if restored.Claims.PlayerMessagingID != uuid.Nil {
		t.Fatal("resuming mutated the caller's token")
	}
}

// An unusable persisted JWT must be replaced, even when its separate expiry field looks valid.
func TestResumeTokenSourceReplacesInvalidPersistedClaims(t *testing.T) {
	t.Parallel()

	for name, header := range map[string]string{
		"malformed":        "MCToken malformed",
		"missing identity": "MCToken header.e30.signature",
		"expired":          testAuthorizationHeaderWithTimes(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			tickets := new(countingTickets)
			env := &AuthorizationEnvironment{PlayFabTitleID: "20CA2"}
			restored := &Token{AuthorizationHeader: header, ValidUntil: time.Now().Add(time.Hour)}
			if _, err := env.ResumeTokenSource(tickets, TokenConfig{}, restored).ServiceToken(context.Background()); err == nil || tickets.calls.Load() != 1 {
				t.Fatalf("invalid token was reused: err = %v tickets = %d", err, tickets.calls.Load())
			}
		})
	}
}

type rotatingTokenSource struct {
	issued      atomic.Int32
	invalidated atomic.Int32
}

func (s *rotatingTokenSource) ServiceToken(context.Context) (*Token, error) {
	if s.invalidated.Load() == 0 {
		return &Token{AuthorizationHeader: "MCToken revoked"}, nil
	}
	s.issued.Add(1)
	return &Token{AuthorizationHeader: "MCToken fresh"}, nil
}

func (s *rotatingTokenSource) InvalidateServiceToken(rejected *Token) {
	if rejected.AuthorizationHeader == "MCToken revoked" {
		s.invalidated.Add(1)
	}
}

// An unauthorized multiplayer start invalidates the service token and retries once.
func TestMultiplayerTokenRetriesOnceAfterInvalidatingARejectedToken(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"direct", "managed"} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "MCToken fresh" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"result": &multiplayerToken{
					IssuedAt: time.Now(), SignedToken: "multiplayer-token", ValidUntil: time.Now().Add(time.Hour),
				}})
			}))
			defer server.Close()
			serviceURL, _ := url.Parse(server.URL)
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			env := &AuthorizationEnvironment{ServiceURI: serviceURL, HTTPClient: server.Client()}
			src := new(rotatingTokenSource)
			var source TokenSource = src
			if name == "managed" {
				source = &ManagedTokenSource{TokenSource: src}
			}
			token, err := env.MultiplayerToken(context.Background(), source, &key.PublicKey)
			if err != nil || token != "multiplayer-token" {
				t.Fatalf("MultiplayerToken = %q, %v", token, err)
			}
			if src.invalidated.Load() != 1 || src.issued.Load() != 1 || requests.Load() != 2 {
				t.Fatalf("invalidated=%d issued=%d requests=%d", src.invalidated.Load(), src.issued.Load(), requests.Load())
			}
		})
	}
}

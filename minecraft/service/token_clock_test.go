package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthorizationEnvironmentTokenRetainsResponseClock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serviceNow time.Time
		afterIssue func(*Token, time.Time)
		wantValid  bool
	}{
		{
			name:       "local clock ahead",
			serviceNow: time.Now().UTC().Add(-90 * time.Minute).Truncate(time.Second),
			wantValid:  true,
		},
		{
			name:       "local clock behind",
			serviceNow: time.Now().UTC().Add(90 * time.Minute).Truncate(time.Second),
			afterIssue: func(token *Token, serviceNow time.Time) {
				token.ValidUntil = serviceNow.Add(-time.Minute)
			},
			wantValid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Date", tt.serviceNow.Format(http.TimeFormat))
				_ = json.NewEncoder(w).Encode(map[string]any{
					"result": &Token{
						AuthorizationHeader: testClockAuthorizationHeader(t, tt.serviceNow, tt.serviceNow.Add(time.Hour)),
						ValidUntil:          tt.serviceNow.Add(time.Hour),
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
			if tt.afterIssue != nil {
				tt.afterIssue(token, tt.serviceNow)
			}
			if got := token.Valid(); got != tt.wantValid {
				t.Fatalf("Valid() = %v, want %v", got, tt.wantValid)
			}
			if got := tokenRenewable(token); got != tt.wantValid {
				t.Fatalf("tokenRenewable() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

func testClockAuthorizationHeader(t *testing.T, issuedAt, expiry time.Time) string {
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

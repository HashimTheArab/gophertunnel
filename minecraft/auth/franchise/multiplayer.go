package franchise

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/auth/franchise/internal"
)

type MultiplayerToken struct {
	SignedToken string    `json:"signedToken"`
	ValidUntil  time.Time `json:"validUntil"`
	IssuedAt    time.Time `json:"issuedAt"`
}

// RequestMultiplayerToken requests a token for use with multiplayer servers
func RequestMultiplayerToken(ctx context.Context, c *authclient.AuthClient, env AuthorizationEnvironment, mcToken *Token, key *ecdsa.PrivateKey) (tok *MultiplayerToken, err error) {
	u, err := url.Parse(env.ServiceURI)
	if err != nil {
		return nil, fmt.Errorf("parse service URI: %w", err)
	}
	u = u.JoinPath("/api/v1.0/multiplayer/session/start")

	encodedKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	body := `{"publicKey":"` + base64.StdEncoding.EncodeToString(encodedKey) + `"}`

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("Authorization", mcToken.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request multiplayer token: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Best-effort read of the error body to make debugging authorization failures possible.
		// Keep it small to avoid logging huge payloads.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if len(b) > 0 {
			return nil, fmt.Errorf("POST %v: %v: %s", u, resp.Status, strings.TrimSpace(string(b)))
		}
		return nil, fmt.Errorf("POST %v: %v", u, resp.Status)
	}

	var result internal.Result[*MultiplayerToken]
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("decode multiplayer token: %w", err)
	}

	return result.Data, nil
}

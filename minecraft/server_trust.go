package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ServerTrust decides whether to join a NetherNet server reached by address. It is asked while the
// server's answer is negotiated, with the URL that answered the probe and the public key the server
// proved it holds; a server that presents no identity is refused without asking.
type ServerTrust interface {
	TrustServer(ctx context.Context, url string, key *ecdsa.PublicKey) (bool, error)
}

// ErrServerNotTrusted is returned by a dial whose ServerTrust declined the server.
var ErrServerNotTrusted = errors.New("minecraft: server identity not trusted")

// TrustStore persists the public keys of trusted servers, oldest first, each encoded as standard
// base64 of its PKIX DER form.
type TrustStore interface {
	LoadTrustedKeys() ([]string, error)
	SaveTrustedKeys(keys []string) error
}

// maxTrustedKeys is how many keys vanilla keeps; the least recently used is dropped beyond it.
const maxTrustedKeys = 100

// FirstUseTrust trusts servers on first use as the vanilla client does. A known key is trusted and
// becomes the most recently used. An unknown key is trusted silently when the URL is https, and
// otherwise only if Confirm agrees; a trusted unknown key is stored. Keys are not bound to a URL, so
// a server whose key changed is asked about again.
type FirstUseTrust struct {
	Store   TrustStore
	Confirm func(ctx context.Context, url string) (bool, error)
	// Log reports keys that could not be loaded or saved; persistence failures never refuse a join.
	Log *slog.Logger

	mu sync.Mutex
}

// TrustServer ...
func (t *FirstUseTrust) TrustServer(ctx context.Context, url string, key *ecdsa.PublicKey) (bool, error) {
	encoded, err := EncodeTrustedKey(key)
	if err != nil {
		return false, err
	}
	t.mu.Lock()
	keys, _ := t.load()
	for i, known := range keys {
		if known == encoded {
			keys = append(append(keys[:i:i], keys[i+1:]...), encoded)
			t.save(keys)
			t.mu.Unlock()
			return true, nil
		}
	}
	t.mu.Unlock()

	if !strings.HasPrefix(url, "https://") {
		if t.Confirm == nil {
			return false, nil
		}
		trusted, err := t.Confirm(ctx, url)
		if err != nil || !trusted {
			return false, err
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	keys, loaded := t.load()
	if !loaded {
		return true, nil // saving now would replace keys that could not be read
	}
	for _, known := range keys {
		if known == encoded {
			return true, nil
		}
	}
	keys = append(keys, encoded)
	if len(keys) > maxTrustedKeys {
		keys = keys[len(keys)-maxTrustedKeys:]
	}
	t.save(keys)
	return true, nil
}

// load reports false when the stored keys could not be read.
func (t *FirstUseTrust) load() ([]string, bool) {
	if t.Store == nil {
		return nil, false
	}
	keys, err := t.Store.LoadTrustedKeys()
	if err != nil {
		t.logger().Warn("load trusted server keys", "error", err)
		return nil, false
	}
	return keys, true
}

func (t *FirstUseTrust) save(keys []string) {
	if t.Store == nil {
		return
	}
	if err := t.Store.SaveTrustedKeys(keys); err != nil {
		t.logger().Warn("save trusted server keys", "error", err)
	}
}

func (t *FirstUseTrust) logger() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.Default()
}

// EncodeTrustedKey returns the TrustStore encoding of key.
func EncodeTrustedKey(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", errors.New("minecraft: nil server key")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encode server key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// serverTokenKey returns the public key in a server identity token's cpk claim, which may be a JWK
// or base64 PKIX DER, after checking the token is signed by that key.
func serverTokenKey(token string) (*ecdsa.PublicKey, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return nil, fmt.Errorf("parse server identity token: %w", err)
	}
	var claims struct {
		PublicKey json.RawMessage `json:"cpk"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("read server identity token: %w", err)
	}
	key, err := parseClaimedKey(claims.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := parsed.Claims(key, new(map[string]any)); err != nil {
		return nil, fmt.Errorf("verify server identity token: %w", err)
	}
	return key, nil
}

func parseClaimedKey(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	raw = bytes.TrimSpace(raw)
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode cpk: %w", err)
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse cpk: %w", err)
		}
		if ecKey, ok := key.(*ecdsa.PublicKey); ok {
			return ecKey, nil
		}
		return nil, errors.New("cpk is not an ECDSA key")
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse cpk: %w", err)
	}
	if ecKey, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		return ecKey, nil
	}
	return nil, errors.New("cpk is not an ECDSA key")
}

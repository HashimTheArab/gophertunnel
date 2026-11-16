package minecraft

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

// The authorization environment is compared with discovery after authEnvTTL: kept while discovery names
// the same service and issuer, replaced when the issuer changes, and kept when discovery fails.
func TestAuthEnvFollowsDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		issuer := "https://auth.example"
		var discoverErr error
		calls := 0
		oldDiscover := authEnvDiscover
		authEnvDiscover = func(context.Context) (*service.AuthorizationEnvironment, error) {
			calls++
			if discoverErr != nil {
				return nil, discoverErr
			}
			u, _ := url.Parse(issuer)
			return &service.AuthorizationEnvironment{ServiceURI: u, Issuer: u}, nil
		}
		authEnvCacheMu.Lock()
		authEnvCache = nil
		authEnvCacheMu.Unlock()
		t.Cleanup(func() {
			authEnvDiscover = oldDiscover
			authEnvCacheMu.Lock()
			authEnvCache = nil
			authEnvCacheMu.Unlock()
		})

		first, err := authEnv(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if e, _ := authEnv(context.Background()); e != first || calls != 1 {
			t.Fatalf("within the TTL: discovered %d times, same environment = %v", calls, e == first)
		}
		time.Sleep(authEnvTTL)
		if e, _ := authEnv(context.Background()); e != first || calls != 2 {
			t.Fatalf("unchanged discovery: discovered %d times, kept environment = %v", calls, e == first)
		}
		issuer = "https://moved.example"
		time.Sleep(authEnvTTL)
		moved, _ := authEnv(context.Background())
		if moved == first || moved.Issuer.String() != issuer {
			t.Fatalf("changed issuer: environment issuer = %v, want %s", moved.Issuer, issuer)
		}
		discoverErr = errors.New("discovery unavailable")
		time.Sleep(authEnvTTL)
		if e, err := authEnv(context.Background()); err != nil || e != moved {
			t.Fatalf("failed discovery: error = %v, kept environment = %v", err, e == moved)
		}
	})
}

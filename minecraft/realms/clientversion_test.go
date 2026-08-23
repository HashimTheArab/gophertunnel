package realms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal/xasu"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// stubRealms serves a realms api that accepts only acceptedVersion, recording the
// Client-Version of every request it receives.
func stubRealms(t *testing.T, acceptedVersion string) (*Client, *[]string) {
	t.Helper()

	var mu sync.Mutex
	var versions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get("Client-Version")
		mu.Lock()
		versions = append(versions, r.URL.Path+" "+version)
		mu.Unlock()

		if r.URL.Path == compatiblePath {
			if version == acceptedVersion {
				_, _ = w.Write([]byte(compatibleResponse))
			} else {
				_, _ = w.Write([]byte("OUTDATED"))
			}
			return
		}
		if version != acceptedVersion {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errorCode":6020,"errorMsg":"Unknown client version","reason":"unknown_client_version"}`))
			return
		}
		_, _ = w.Write([]byte(`{"address":"127.0.0.1:19132","networkProtocol":"DEFAULT"}`))
	}))
	t.Cleanup(server.Close)

	previous := realmsBaseURL
	realmsBaseURL = server.URL
	t.Cleanup(func() { realmsBaseURL = previous })

	return &Client{
		httpClient: server.Client(),
		xblToken: &auth.XBLToken{AuthorizationToken: &xsts.Token{
			Token:         "stub",
			NotAfter:      time.Now().Add(time.Hour),
			DisplayClaims: xsts.DisplayClaims{UserInfo: []xsts.UserInfo{{UserInfo: xasu.UserInfo{UserHash: "stub"}}}},
		}},
	}, &versions
}

// TestClientRetriesRejectedClientVersion covers the Realms allowlist rejecting the
// compiled-in version: the client must find an accepted one and replay the request.
func TestClientRetriesRejectedClientVersion(t *testing.T) {
	c, versions := stubRealms(t, "1.26.44")
	c.SetClientVersion("1.26.46")

	if _, err := c.RealmAddress(context.Background(), 1); err != nil {
		t.Fatalf("realm address: %v", err)
	}
	if _, err := c.RealmAddress(context.Background(), 2); err != nil {
		t.Fatalf("realm address after negotiation: %v", err)
	}

	want := []string{
		"/worlds/1/join 1.26.46",
		compatiblePath + " 1.26.45",
		compatiblePath + " 1.26.44",
		"/worlds/1/join 1.26.44",
		"/worlds/2/join 1.26.44",
	}
	if got := *versions; !reflect.DeepEqual(got, want) {
		t.Fatalf("request versions: got %v, want %v", got, want)
	}
}

// TestClientKeepsErrorWhenNoVersionAccepted covers exhausting the search: the
// original rejection must survive rather than becoming a compatibility error.
func TestClientKeepsErrorWhenNoVersionAccepted(t *testing.T) {
	c, _ := stubRealms(t, "1.30.0")
	c.SetClientVersion("1.26.2")

	if _, err := c.RealmAddress(context.Background(), 1); err == nil {
		t.Fatal("expected the rejection to be returned")
	}
	if got := c.clientVersion(); got != "1.26.2" {
		t.Fatalf("client version: got %q, want %q", got, "1.26.2")
	}
}

// TestClientKeepsSearchingAfterCooldown covers the hold-off: a second rejection
// inside the cooldown must not repeat the whole walk.
func TestClientHoldsOffRepeatedSearches(t *testing.T) {
	c, versions := stubRealms(t, "1.30.0")
	c.SetClientVersion("1.26.2")

	for range 2 {
		if _, err := c.RealmAddress(context.Background(), 1); err == nil {
			t.Fatal("expected the rejection to be returned")
		}
	}

	var probes int
	for _, v := range *versions {
		if strings.HasPrefix(v, compatiblePath) {
			probes++
		}
	}
	if probes != 2 {
		t.Fatalf("compatibility probes: got %d, want %d", probes, 2)
	}
}

func TestClientVersionDefaultsToCurrentVersion(t *testing.T) {
	c := &Client{}
	if got := c.clientVersion(); got != protocol.CurrentVersion {
		t.Fatalf("client version: got %q, want %q", got, protocol.CurrentVersion)
	}
	c.SetClientVersion("1.26.44")
	if got := c.clientVersion(); got != "1.26.44" {
		t.Fatalf("client version: got %q, want %q", got, "1.26.44")
	}
	c.SetClientVersion("nonsense")
	if got := c.clientVersion(); got != "1.26.44" {
		t.Fatalf("unparseable version must be ignored: got %q", got)
	}
	c.SetClientVersion("")
	if got := c.clientVersion(); got != protocol.CurrentVersion {
		t.Fatalf("client version after reset: got %q, want %q", got, protocol.CurrentVersion)
	}
}

func TestVersionCandidates(t *testing.T) {
	for _, test := range []struct {
		version string
		want    []string
	}{
		{version: "1.26.45", want: []string{"1.26.45", "1.26.44", "1.26.43"}},
		{version: "1.26.2.9", want: []string{"1.26.2", "1.26.1", "1.26.0"}},
		{version: "1.26", want: []string{"1.26"}},
		{version: "not.a.version", want: []string{"not.a.version"}},
	} {
		got := versionCandidates(test.version)
		if len(got) > len(test.want) {
			got = got[:len(test.want)]
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("candidates for %q: got %v, want %v", test.version, got, test.want)
		}
	}
	if got := len(versionCandidates("1.26.999")); got != maxVersionFallback+1 {
		t.Fatalf("candidate count: got %d, want %d", got, maxVersionFallback+1)
	}
}

func TestUnknownClientVersion(t *testing.T) {
	rejection := []byte(`{"errorCode":6020,"errorMsg":"Unknown client version","reason":"unknown_client_version"}`)
	if !unknownClientVersion(http.StatusBadRequest, rejection) {
		t.Fatal("expected the version rejection to be recognised")
	}
	if unknownClientVersion(http.StatusForbidden, rejection) {
		t.Fatal("only 400 rejects the version")
	}
	if unknownClientVersion(http.StatusBadRequest, []byte(`{"errorCode":400,"errorMsg":"Bad request"}`)) {
		t.Fatal("an unrelated 400 must not trigger negotiation")
	}
	if unknownClientVersion(http.StatusBadRequest, []byte("not json")) {
		t.Fatal("a non-JSON 400 must not trigger negotiation")
	}
}

package gatherings

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

type fixedTokens struct{}

func (fixedTokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

// Authored from the 26.30 client's GatheringManager parser, not a captured payload.
const publicConfigFixture = `{"result":[{"gatheringId":"g-1","startTimeUtc":"2026-10-01T18:00:00Z","endTimeUtc":"2026-10-03T18:00:00Z",
"title":"Live","description":"An event","shouldRouteToServerTab":true,
"externalVenue":{"netherNetId":"","serverIpAddress":"2001:db8::1","serverPort":19132},
"segments":[{"segmentType":"Stream","startTimeUtc":"2026-10-01T18:00:00Z","endTimeUtc":"","ui":{"startScreenButtonText":"Join","captionIncludesCountdown":true,"badgeImage":"https://cdn.example.test/b.png"}}]}]}`

// The public config decodes typed, builds a bracketed host:port, and rejects a malformed answer.
func TestPublicConfigDecodesTheReferenceSchema(t *testing.T) {
	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		if r.URL.Path == "/api/v1.0/config/public" {
			_, _ = w.Write([]byte(publicConfigFixture))
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"gatheringId":"g","startTimeUtc":"yesterday"}]}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := (&Environment{ServiceURI: base, HTTPClient: server.Client()}).New(fixedTokens{})
	configs, err := client.PublicConfig(context.Background(), ConfigQuery{ClientVersion: "1.26.30", ClientPlatform: "Android", ClientSubPlatform: "Google"})
	if err != nil || len(configs) != 1 {
		t.Fatalf("configs = %v err = %v", configs, err)
	}
	config := configs[0]
	if query.Get("clientVersion") != "1.26.30" || query.Get("clientSubPlatform") != "Google" {
		t.Fatalf("query = %v", query)
	}
	if address, ok := config.Venue.RakNetAddress(); !ok || address != "[2001:db8::1]:19132" {
		t.Fatalf("venue address = %q %v", address, ok)
	}
	if !config.RouteToServersTab || config.End.Sub(config.Start.Time) != 48*time.Hour || !config.Segments[0].End.IsZero() {
		t.Fatalf("config = %+v", config)
	}
	if ui := config.Segments[0].UI; ui.StartScreenButtonText != "Join" || !ui.CaptionCountdown {
		t.Fatalf("segment ui = %+v", ui)
	}
	bad := (&Environment{ServiceURI: base.JoinPath("other"), HTTPClient: server.Client()}).New(fixedTokens{})
	if _, err := bad.PublicConfig(context.Background(), ConfigQuery{}); err == nil {
		t.Fatal("a malformed timestamp decoded")
	}
}

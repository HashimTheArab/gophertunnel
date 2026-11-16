package signaling

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// configurationServer answers signaling-afd configuration requests with the given statuses and bodies, one per
// request, repeating the last.
func configurationServer(t *testing.T, statuses []int, bodies []string) (*AFDEnvironment, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := min(int(calls.Add(1))-1, len(statuses)-1)
		if r.URL.Path != "/api/v1.0/configuration" || r.Header.Get("Authorization") != "test-token" {
			t.Errorf("request = %s with Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.WriteHeader(statuses[i])
		_, _ = w.Write([]byte(bodies[i]))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &AFDEnvironment{ServiceEnvironment: internal.ServiceEnvironment{ServiceURI: u}}, calls
}

var testTokenSource = staticTokenSource{token: &service.Token{AuthorizationHeader: "test-token"}}

const validConfiguration = `{"result":{"signalingUri":"wss://signaling.example","pingFrequency":"00:00:30"}}`

// Like vanilla, a configuration request is retried after a transient failure, and a request that fails
// for good falls back to the discovered signaling service with the default ping interval.
func TestDiscoveredConfiguration(t *testing.T) {
	fallback, err := url.Parse("wss://fallback.example")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		statuses  []int
		bodies    []string
		fallback  *url.URL
		wantURI   string
		wantPing  time.Duration
		wantCalls int32
		wantErr   bool
	}{
		{name: "transient failure then success", statuses: []int{503, 200}, bodies: []string{"", validConfiguration},
			fallback: fallback, wantURI: "wss://signaling.example", wantPing: 30 * time.Second, wantCalls: 2},
		{name: "rejected", statuses: []int{404}, bodies: []string{""},
			fallback: fallback, wantURI: "wss://fallback.example", wantPing: DefaultPingFrequency, wantCalls: 1},
		{name: "unusable answer", statuses: []int{200}, bodies: []string{`{"result":{"signalingUri":""}}`},
			fallback: fallback, wantURI: "wss://fallback.example", wantPing: DefaultPingFrequency, wantCalls: 1},
		{name: "rejected without fallback", statuses: []int{404}, bodies: []string{""}, wantCalls: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			afd, calls := configurationServer(t, tt.statuses, tt.bodies)
			p := discoveredConfiguration{afd: afd, fallback: tt.fallback, log: slog.New(slog.DiscardHandler)}
			cfg, err := p.Configuration(context.Background(), http.DefaultClient, testTokenSource)
			if got := calls.Load(); got != tt.wantCalls {
				t.Errorf("configuration requests = %d, want %d", got, tt.wantCalls)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("Configuration() succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Configuration() error = %v", err)
			}
			if cfg.ServiceURI.String() != tt.wantURI || cfg.PingFrequency != tt.wantPing {
				t.Fatalf("configuration = %s every %v, want %s every %v", cfg.ServiceURI, cfg.PingFrequency, tt.wantURI, tt.wantPing)
			}
		})
	}
}

// An interval in any TimeSpan form is read; one that is missing or does not parse keeps the default
// instead of failing the dial.
func TestConfigurationPingFrequency(t *testing.T) {
	tests := map[string]time.Duration{
		`"00:00:15"`:         15 * time.Second,
		`"00:00:15.5000000"`: 15500 * time.Millisecond,
		`"1.00:00:00"`:       24 * time.Hour,
		`"PT15S"`:            DefaultPingFrequency,
		`"00:00:00"`:         DefaultPingFrequency,
		`""`:                 DefaultPingFrequency,
	}
	for value, want := range tests {
		var cfg Configuration
		if err := json.Unmarshal([]byte(`{"signalingUri":"wss://signaling.example","pingFrequency":`+value+`}`), &cfg); err != nil {
			t.Fatalf("decode pingFrequency %s: %v", value, err)
		}
		if cfg.PingFrequency != want {
			t.Errorf("pingFrequency %s = %v, want %v", value, cfg.PingFrequency, want)
		}
	}
}

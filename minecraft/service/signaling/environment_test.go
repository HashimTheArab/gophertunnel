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

// configurationServer answers configuration requests with statuses[i] and bodies[i], repeating the last.
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

var testTokenSource = fixedTokenSource{token: &service.Token{AuthorizationHeader: "test-token"}}

const validConfiguration = `{"result":{"signalingUri":"wss://signaling.example","pingFrequency":"00:00:30"}}`

// A transient failure is retried, and one that persists falls back to the discovered signaling service.
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
		{name: "endpoint without a host", statuses: []int{200}, bodies: []string{`{"result":{"signalingUri":"/"}}`},
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

// pingFrequency is read in TimeSpan form, and any other value keeps the default instead of failing the dial.
func TestConfigurationPingFrequency(t *testing.T) {
	tests := map[string]time.Duration{
		`"00:00:15"`:         15 * time.Second,
		`"00:00:15.5000000"`: 15500 * time.Millisecond,
		`"1.00:00:00"`:       24 * time.Hour,
		`"PT15S"`:            DefaultPingFrequency,
		`"00:00:00"`:         DefaultPingFrequency,
		`""`:                 DefaultPingFrequency,
		`15000`:              DefaultPingFrequency,
		`null`:               DefaultPingFrequency,
		`"-00:00:15"`:        DefaultPingFrequency,
		`"00:00:Inf"`:        DefaultPingFrequency,
		`"00:00:1e12"`:       DefaultPingFrequency,
		`"00:00:00.5000000"`: DefaultPingFrequency,
		`"00:00:75"`:         DefaultPingFrequency,
		`"24:00:00"`:         DefaultPingFrequency,
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

// A configuration request that hangs leaves the fallback time to connect within the dial's deadline.
func TestDiscoveredConfigurationFallsBackWhenTheRequestHangs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := url.Parse("wss://fallback.example")
	if err != nil {
		t.Fatal(err)
	}
	p := discoveredConfiguration{
		afd:      &AFDEnvironment{ServiceEnvironment: internal.ServiceEnvironment{ServiceURI: u}},
		fallback: fallback,
		log:      slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cfg, err := p.Configuration(ctx, http.DefaultClient, testTokenSource)
	if err != nil {
		t.Fatalf("Configuration() error = %v, want the fallback", err)
	}
	if cfg.ServiceURI != fallback || ctx.Err() != nil {
		t.Fatalf("configuration = %s, dial context error = %v, want the fallback with time left", cfg.ServiceURI, ctx.Err())
	}
}

// Discovery that lists only the signaling service connects to it directly.
func TestDiscoveredConfigurationWithoutAFD(t *testing.T) {
	fallback, err := url.Parse("wss://fallback.example")
	if err != nil {
		t.Fatal(err)
	}
	p := discoveredConfiguration{fallback: fallback, log: slog.New(slog.DiscardHandler)}
	cfg, err := p.Configuration(context.Background(), http.DefaultClient, testTokenSource)
	if err != nil || cfg.ServiceURI != fallback || cfg.PingFrequency != DefaultPingFrequency {
		t.Fatalf("Configuration() = %+v, %v, want the signaling service every %v", cfg, err, DefaultPingFrequency)
	}
}

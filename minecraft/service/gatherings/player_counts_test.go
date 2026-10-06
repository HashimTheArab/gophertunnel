package gatherings

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

func TestPlayerCountsRequestAndCache(t *testing.T) {
	fixture, err := os.ReadFile("testdata/player_counts.json")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized, err := os.ReadFile("testdata/player_counts_unauthorized.json")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/api/v2.0/dataquery/playercounts" {
			t.Error("unexpected count request")
		}
		if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
			t.Error("GET included a body")
		}
		if r.Header.Get("Authorization") != "MCToken synthetic" {
			t.Error("missing service authorization")
		}
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "libhttpclient/1.0.0.0" {
			t.Error("unexpected request headers")
		}
		if requests.Add(1) == 2 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(unauthorized)
			return
		}
		_, _ = w.Write(fixture)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := (&Environment{ServiceURI: base, HTTPClient: server.Client()}).New(fixedTokens{})
	now := time.Unix(1, 0)
	client.countsNow = func() time.Time { return now }
	counts, err := client.PlayerCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 3 || *counts[0].PlayerCount != 14252 || *counts[1].PlayerCount != 0 || counts[2].PlayerCount != nil {
		t.Fatalf("counts = %#v", counts)
	}
	*counts[0].PlayerCount = 1
	for range 10 {
		counts, err = client.PlayerCounts(context.Background())
		if err != nil || *counts[0].PlayerCount != 14252 {
			t.Fatal("caller changed cached values")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("cache hits issued requests")
	}
	now = now.Add(PlayerCountsRefreshInterval)
	counts, err = client.PlayerCounts(context.Background())
	var responseErr *service.ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh error = %v", err)
	}
	if len(counts) != 3 || *counts[0].PlayerCount != 14252 {
		t.Fatal("failed refresh discarded cached counts")
	}
	counts, err = client.PlayerCounts(context.Background())
	if err != nil || len(counts) != 3 || requests.Load() != 2 {
		t.Fatal("failure retry was not throttled")
	}
	now = now.Add(PlayerCountsRefreshInterval)
	if _, err := client.PlayerCounts(context.Background()); err != nil || requests.Load() != 3 {
		t.Fatal("next refresh was not issued")
	}
}

func TestPlayerCountsRejectsMalformedEnvelopeAndSanitizesErrors(t *testing.T) {
	for _, fixture := range []string{`{}`, `{"result":null}`, `{"result":{}}`, `{"result":[]`, `{"result":[]} trailing`} {
		t.Run(fixture, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(fixture)) }))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			client := (&Environment{ServiceURI: base, HTTPClient: server.Client()}).New(fixedTokens{})
			if _, err := client.PlayerCounts(context.Background()); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("sensitive-error-content"))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := (&Environment{ServiceURI: base, HTTPClient: server.Client()}).New(fixedTokens{})
	if _, err := client.PlayerCounts(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive-error-content") {
		t.Fatal("unsafe response error")
	}
}

func TestPlayerCountsCoalescesConcurrentCallsAndCancels(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		close(started)
		<-release
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := (&Environment{ServiceURI: base, HTTPClient: server.Client()}).New(fixedTokens{})
	done := make(chan error, 1)
	go func() { _, err := client.PlayerCounts(context.Background()); done <- err }()
	<-started
	if counts, err := client.PlayerCounts(context.Background()); err != nil || counts != nil {
		t.Fatal("in-flight request did not reuse absent cache")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.PlayerCounts(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller was accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("concurrent calls issued duplicate requests")
	}
	if counts, err := client.PlayerCounts(context.Background()); err != nil || counts == nil || len(counts) != 0 {
		t.Fatal("empty success was not preserved")
	}
}

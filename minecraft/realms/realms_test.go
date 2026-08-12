package realms

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestRealmAddressRequestsImmediately(t *testing.T) {
	requests := make(chan string, 1)
	c := &Client{
		requestFunc: func(_ context.Context, method, path string, _ []byte) ([]byte, int, error) {
			requests <- method + " " + path
			return []byte(`{"address":"127.0.0.1:19132","networkProtocol":"DEFAULT"}`), http.StatusOK, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	addr, err := c.RealmAddress(ctx, 42)
	if err != nil {
		t.Fatalf("RealmAddress: %v", err)
	}
	if addr.Address != "127.0.0.1:19132" || addr.NetworkProtocol != NetworkProtocolDefault {
		t.Fatalf("RealmAddress = %+v", addr)
	}
	select {
	case got := <-requests:
		if got != "GET /worlds/42/join" {
			t.Fatalf("request = %q", got)
		}
	default:
		t.Fatal("RealmAddress did not request before waiting for the poll ticker")
	}
}

func TestRealmAddressPollsAfterServiceUnavailable(t *testing.T) {
	attempts := 0
	c := &Client{
		requestFunc: func(_ context.Context, _, _ string, _ []byte) ([]byte, int, error) {
			attempts++
			return nil, http.StatusServiceUnavailable, errors.New("starting")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := c.RealmAddress(ctx, 42); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RealmAddress error = %v, want context deadline", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want exactly one immediate attempt before poll wait", attempts)
	}
}

func TestClientStorySettings(t *testing.T) {
	c := &Client{
		requestFunc: func(_ context.Context, method, path string, _ []byte) ([]byte, int, error) {
			if method != http.MethodGet || path != "/worlds/42/stories/settings" {
				t.Fatalf("request = %s %s", method, path)
			}
			return []byte(`{"autostories":true,"coordinates":false,"notifications":true,"playerOptIn":"NONE","realmOptIn":"OPT_IN","timeline":true}`), http.StatusOK, nil
		},
	}

	settings, err := c.StorySettings(context.Background(), 42)
	if err != nil {
		t.Fatalf("StorySettings: %v", err)
	}
	if settings.PlayerOptIn != StoryOptInNone || settings.RealmOptIn != StoryOptInOptIn {
		t.Fatalf("StorySettings = %+v", settings)
	}
}

func TestClientUpdateStorySettings(t *testing.T) {
	want := StorySettings{
		AutoStories:   true,
		Coordinates:   false,
		Notifications: true,
		PlayerOptIn:   StoryOptInOptIn,
		RealmOptIn:    StoryOptInOptOut,
		Timeline:      true,
	}
	c := &Client{
		requestFunc: func(_ context.Context, method, path string, body []byte) ([]byte, int, error) {
			if method != http.MethodPost || path != "/worlds/42/stories/settings" {
				t.Fatalf("request = %s %s", method, path)
			}
			var got StorySettings
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body = %+v, want %+v", got, want)
			}
			return nil, http.StatusNoContent, nil
		},
	}

	if err := c.UpdateStorySettings(context.Background(), 42, want); err != nil {
		t.Fatalf("UpdateStorySettings: %v", err)
	}
}

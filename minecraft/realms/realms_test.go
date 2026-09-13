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
	type recordedRequest struct {
		method string
		path   string
		body   []byte
	}
	requests := make(chan recordedRequest, 1)
	c := &Client{
		requestFunc: func(_ context.Context, method, path string, body []byte) ([]byte, int, error) {
			requests <- recordedRequest{method: method, path: path, body: body}
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
		if got.method != http.MethodPost || got.path != "/worlds/42/join" {
			t.Fatalf("request = %s %s", got.method, got.path)
		}
		var body struct {
			JoinIntention string            `json:"joinIntention"`
			PingRegions   []json.RawMessage `json:"pingRegions"`
		}
		if err := json.Unmarshal(got.body, &body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.JoinIntention != "VANILLA" || body.PingRegions == nil || len(body.PingRegions) != 0 {
			t.Fatalf("request body = %+v", body)
		}
	default:
		t.Fatal("RealmAddress did not request before waiting for a retry delay")
	}
}

func TestRealmAddressDoesNotRetryServiceUnavailableWithoutRetryAfter(t *testing.T) {
	attempts := 0
	wantErr := errors.New("starting")
	c := &Client{
		requestFunc: func(_ context.Context, _, _ string, _ []byte) ([]byte, int, error) {
			attempts++
			return nil, http.StatusServiceUnavailable, wantErr
		},
	}

	if _, err := c.RealmAddress(context.Background(), 42); !errors.Is(err, wantErr) {
		t.Fatalf("RealmAddress error = %v, want %v", err, wantErr)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
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

func TestClientOptInToStoryTimelinePreservesSettings(t *testing.T) {
	want := StorySettings{
		AutoStories:   true,
		Coordinates:   true,
		Notifications: false,
		PlayerOptIn:   StoryOptInOptIn,
		RealmOptIn:    StoryOptInOptOut,
		Timeline:      false,
	}
	requests := 0
	c := &Client{
		requestFunc: func(_ context.Context, method, path string, body []byte) ([]byte, int, error) {
			requests++
			if path != "/worlds/42/stories/settings" {
				t.Fatalf("path = %q", path)
			}
			switch method {
			case http.MethodGet:
				return []byte(`{"autostories":true,"coordinates":true,"notifications":false,"playerOptIn":"NONE","realmOptIn":"OPT_OUT","timeline":false}`), http.StatusOK, nil
			case http.MethodPost:
				var got StorySettings
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("body = %+v, want %+v", got, want)
				}
				return nil, http.StatusNoContent, nil
			default:
				t.Fatalf("method = %q", method)
				return nil, 0, nil
			}
		},
	}

	if err := c.OptInToStoryTimeline(context.Background(), 42); err != nil {
		t.Fatalf("OptInToStoryTimeline: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

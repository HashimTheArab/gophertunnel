package userstats

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip routes a test request without opening a network connection.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// response returns an HTTP response for a fixture payload.
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestBatchSDKFixtureAndRequest(t *testing.T) {
	fixture, err := os.ReadFile("testdata/batch_response.json")
	if err != nil {
		t.Fatal(err)
	}
	xuids := []string{"2533274792693551", "2533274792693552"}
	scid := uuid.MustParse("7492baca-c1b4-440d-a391-b7ef364a8d40")
	requested := []RequestedStatistics{{scid, []string{"OverallReputation", "FairplayReputation"}}, {uuid.New(), []string{"Other"}}}
	calls := 0
	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/batch" || r.URL.RawQuery != "operation=read" {
			t.Error("unexpected batch URL or method")
		}
		for name, value := range map[string]string{"Accept-Language": "en-US", "Content-Type": "application/json; charset=utf-8", "x-xbl-contract-version": "1", "User-Agent": userAgent} {
			if r.Header.Get(name) != value {
				t.Errorf("unexpected %s", name)
			}
		}
		var body struct {
			Users      []string              `json:"requestedusers"`
			Statistics []RequestedStatistics `json:"requestedscids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(body.Users, xuids) || !reflect.DeepEqual(body.Statistics, requested) {
			t.Error("batch request changed selections")
		}
		return response(http.StatusOK, string(fixture)), nil
	})})
	users, err := client.Batch(context.Background(), xuids, requested)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(users) != 2 || users[1].XUID != xuids[1] {
		t.Fatalf("calls=%d users=%v", calls, users)
	}
	stats := users[0].ServiceConfigurations[0]
	if stats.ServiceConfigID != scid || len(stats.Statistics) != 2 {
		t.Fatalf("stats=%v", stats)
	}
	value, ok := stats.Statistics[0].NonNegativeNumber()
	if !ok || value != "66" {
		t.Fatalf("value=%q valid=%v", value, ok)
	}
}

func TestBatchRejectsMalformedAndRedactsHTTPError(t *testing.T) {
	requested := []RequestedStatistics{{uuid.New(), []string{"stat"}}}
	// Bedrock's statistics client accepts only string or null user IDs and rejects the whole response otherwise.
	for _, body := range []string{`{}`, `{"users":null}`, `{"users":{}}`, `{"users":[]} trailing`, `{"users":[{"xuid":2533274792693551,"scids":[]}]}`} {
		client := NewClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusOK, body), nil })})
		if _, err := client.Batch(context.Background(), []string{"1"}, requested); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	client := NewClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, "sensitive-error-content"), nil
	})})
	_, err := client.Batch(context.Background(), []string{"1"}, requested)
	var responseErr *service.ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusForbidden || strings.Contains(err.Error(), "sensitive-error-content") {
		t.Fatal("HTTP error was not safely typed")
	}
}

func TestBatchRejectsEmptyRequestsWithoutDispatch(t *testing.T) {
	client := NewClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid request was dispatched")
		return response(http.StatusOK, `{"users":[]}`), nil
	})})
	for _, xuid := range []string{"", "x", "-1", "18446744073709551616"} {
		if _, err := client.Batch(context.Background(), []string{xuid}, []RequestedStatistics{{uuid.New(), []string{"stat"}}}); err == nil {
			t.Errorf("accepted %q", xuid)
		}
	}
	if _, err := client.Batch(context.Background(), nil, nil); err == nil {
		t.Fatal("accepted empty batch")
	}
}

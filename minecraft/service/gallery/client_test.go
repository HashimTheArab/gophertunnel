package gallery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
	serviceinternal "github.com/sandertv/gophertunnel/minecraft/service/internal"
)

func TestClientImages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1.0/gallery/xuid/2533274790000000" {
			t.Errorf("path = %s", r.URL.Path)
		}
		assertRequestHeaders(t, r)
		_, _ = io.WriteString(w, `{"result":{"showcasedImages":[{"id":"image-id","isFeatured":true,"lastModified":"2026-08-12T09:10:11Z","takenTime":"2026-08-11T08:09:10Z","url":"https://cdn.example.test/image.png"}]}}`)
	}))
	defer server.Close()

	client := testClient(t, server)
	images, err := client.Images(context.Background(), "2533274790000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 {
		t.Fatalf("len(images) = %d, want 1", len(images))
	}
	image := images[0]
	if image.ID != "image-id" || !image.Featured || image.URL != "https://cdn.example.test/image.png" {
		t.Fatalf("unexpected image: %#v", image)
	}
	if got, want := image.LastModified, time.Date(2026, 8, 12, 9, 10, 11, 0, time.UTC); !got.Equal(want) {
		t.Errorf("LastModified = %v, want %v", got, want)
	}
	if got, want := image.TakenAt, time.Date(2026, 8, 11, 8, 9, 10, 0, time.UTC); !got.Equal(want) {
		t.Errorf("TakenAt = %v, want %v", got, want)
	}
}

func TestClientUpload(t *testing.T) {
	takenAt := time.Date(2026, 8, 12, 9, 10, 11, 123456789, time.FixedZone("test", 3*60*60))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1.0/gallery" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		assertRequestHeaders(t, r)
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := r.Header.Get("X-Ms-Showcased-Featured"); got != "true" {
			t.Errorf("X-Ms-Showcased-Featured = %q", got)
		}
		if got := r.Header.Get("X-Ms-Showcased-Timetaken"); got != "2026-08-12T06:10:11.123Z" {
			t.Errorf("X-Ms-Showcased-Timetaken = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "image bytes" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"result":{"id":"uploaded","isFeatured":true,"lastModified":"2026-08-12T06:10:12Z","takenTime":"2026-08-12T06:10:11.123Z","url":"https://cdn.example.test/uploaded.png"}}`)
	}))
	defer server.Close()

	image, err := testClient(t, server).Upload(context.Background(), strings.NewReader("image bytes"), UploadOptions{
		Featured: true,
		TakenAt:  takenAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if image.ID != "uploaded" || image.URL != "https://cdn.example.test/uploaded.png" {
		t.Fatalf("unexpected image: %#v", image)
	}
}

func TestClientFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/image.png" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		assertRequestHeaders(t, r)
		_, _ = io.WriteString(w, "image bytes")
	}))
	defer server.Close()

	client := testClient(t, server)
	contents, err := client.Fetch(context.Background(), Image{ID: "image-id", URL: server.URL + "/image.png"})
	if err != nil {
		t.Fatal(err)
	}
	defer contents.Close()
	got, err := io.ReadAll(contents)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "image bytes" {
		t.Fatalf("contents = %q", got)
	}
}

func TestClientDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1.0/gallery/image-id" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		assertRequestHeaders(t, r)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := testClient(t, server).Delete(context.Background(), "image-id"); err != nil {
		t.Fatal(err)
	}
}

func TestClientReturnsServiceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"namespace":"persona","code":"TooManyRequests","message":"slow down","customData":{"retryAfter":30}}`)
	}))
	defer server.Close()

	_, err := testClient(t, server).Images(context.Background(), "1")
	var serviceErr *serviceinternal.Error
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error = %v, want Minecraft service error", err)
	}
	if serviceErr.Code != "TooManyRequests" || serviceErr.Namespace != "persona" {
		t.Fatalf("unexpected service error: %#v", serviceErr)
	}
}

func TestClientReturnsTokenErrorWithoutSendingRequest(t *testing.T) {
	tokenErr := errors.New("token unavailable")
	client := &Client{
		src: tokenSourceFunc(func(context.Context) (*service.Token, error) {
			return nil, tokenErr
		}),
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("request was sent")
			return nil, nil
		})},
		env: DefaultEnvironment,
	}

	_, err := client.Images(context.Background(), "1")
	if !errors.Is(err, tokenErr) {
		t.Fatalf("error = %v, want %v", err, tokenErr)
	}
}

func testClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	serviceURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	env := &Environment{ServiceURI: serviceURL, HTTPClient: server.Client()}
	return env.New(tokenSourceFunc(func(context.Context) (*service.Token, error) {
		return &service.Token{AuthorizationHeader: "MCToken test-token"}, nil
	}))
}

func assertRequestHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "MCToken test-token" {
		t.Errorf("Authorization = %q", got)
	}
	if got := r.Header.Get("User-Agent"); got != serviceinternal.UserAgent {
		t.Errorf("User-Agent = %q", got)
	}
}

type tokenSourceFunc func(context.Context) (*service.Token, error)

func (f tokenSourceFunc) ServiceToken(ctx context.Context) (*service.Token, error) {
	return f(ctx)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

package minecraft

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// blockedPackTransport holds each request until the test releases the batch.
type blockedPackTransport struct {
	started  atomic.Int32
	release  chan struct{}
	archives map[string][]byte
}

// RoundTrip records a download and returns its fixture after release or cancellation.
func (transport *blockedPackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.started.Add(1)
	select {
	case <-transport.release:
	case <-request.Context().Done():
		return nil, request.Context().Err()
	}
	archive := transport.archives[request.URL.Path]
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), ContentLength: int64(len(archive)), Header: make(http.Header)}, nil
}

// recordedURLPackCache records completed archives without storing partial downloads.
type recordedURLPackCache struct {
	memoryPackCache
	stored []*resource.Pack
}

// Store records only archives which passed the advertised identity and size checks.
func (cache *recordedURLPackCache) Store(_ context.Context, _ ResourcePackCacheKey, pack *resource.Pack) error {
	cache.stored = append(cache.stored, pack)
	return nil
}

func TestResourcePackURLDownloadsOverlap(t *testing.T) {
	for _, test := range []struct {
		name   string
		count  int
		cancel bool
	}{
		{name: "two packs", count: 2},
		{name: "bounded batch", count: maxConcurrentResourcePackURLs + 2},
		{name: "cancel active and queued", count: maxConcurrentResourcePackURLs + 2, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				defer client.Close()
				defer peer.Close()
				go func() { _, _ = io.Copy(io.Discard, peer) }()
				conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
				defer conn.Abort()
				transport := &blockedPackTransport{release: make(chan struct{}), archives: make(map[string][]byte)}
				conn.httpClient = &http.Client{Transport: transport}
				cache := &recordedURLPackCache{}
				conn.resourcePackCache = cache
				info := &packet.ResourcePacksInfo{}
				for index := range test.count {
					id := uuid.New()
					path := fmt.Sprintf("/pack-%d", index)
					archive := testResourcePackArchive(t, id)
					transport.archives[path] = archive
					info.TexturePacks = append(info.TexturePacks, protocol.TexturePackInfo{UUID: id, Version: "1.0.0", Size: uint64(len(archive)), DownloadURL: "https://packs.test" + path})
				}
				done := make(chan error, 1)
				go func() { done <- conn.handleResourcePacksInfo(info) }()
				synctest.Wait()
				started := transport.started.Load()
				if test.cancel {
					conn.Abort()
				} else {
					close(transport.release)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if want := int32(min(test.count, maxConcurrentResourcePackURLs)); started != want {
					t.Fatalf("started downloads = %d, want bounded batch %d before any completes", started, want)
				}
				if test.cancel {
					if transport.started.Load() != started || len(conn.resourcePacks) != 0 || len(cache.stored) != 0 {
						t.Fatal("cancelled download started queued work or exposed a partial archive")
					}
					return
				}
				if len(conn.resourcePacks) != test.count {
					t.Fatalf("downloaded packs = %d, want %d", len(conn.resourcePacks), test.count)
				}
				if len(cache.stored) != test.count {
					t.Fatal("completed archives were not cached")
				}
				for index, pack := range conn.resourcePacks {
					if pack.UUID() != info.TexturePacks[index].UUID {
						t.Fatal("download completion changed offer order")
					}
				}
			})
		})
	}
}

func TestResourcePackURLValidationFallsBackWithoutCaching(t *testing.T) {
	for _, reason := range []string{"identity", "size"} {
		t.Run(reason, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			go func() { _, _ = io.Copy(io.Discard, peer) }()
			conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
			defer conn.Abort()
			id := uuid.New()
			archive := testResourcePackArchive(t, id)
			info := protocol.TexturePackInfo{UUID: id, Version: "1.0.0", Size: uint64(len(archive)), DownloadURL: "https://packs.test/pack"}
			if reason == "identity" {
				info.UUID = uuid.New()
			} else {
				info.Size--
			}
			transport := &blockedPackTransport{release: make(chan struct{}), archives: map[string][]byte{"/pack": archive}}
			close(transport.release)
			conn.httpClient = &http.Client{Transport: transport}
			cache := &recordedURLPackCache{}
			conn.resourcePackCache = cache
			if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{info}}); err != nil {
				t.Fatal(err)
			}
			if len(conn.resourcePacks) != 0 || len(cache.stored) != 0 {
				t.Fatal("invalid URL archive was published or cached")
			}
			if _, ok := conn.packQueue.downloadingPacks[info.UUID.String()]; !ok {
				t.Fatal("invalid URL archive did not retain chunk fallback")
			}
		})
	}
}

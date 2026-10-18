package minecraft

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// orderedURLPackCache records cache callbacks in the same trace as admission and progress.
type orderedURLPackCache struct {
	memoryPackCache
	record func(string, uuid.UUID)
}

// Load records the lookup and returns the configured cache entry.
func (cache *orderedURLPackCache) Load(ctx context.Context, key ResourcePackCacheKey) (*resource.Pack, error) {
	cache.record("load", key.UUID)
	return cache.memoryPackCache.Load(ctx, key)
}

// Store records completed archives without changing later cache hits.
func (cache *orderedURLPackCache) Store(_ context.Context, key ResourcePackCacheKey, _ *resource.Pack) error {
	cache.record("store", key.UUID)
	return nil
}

func TestResourcePackURLsDefaultPreservesCallbackOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()
		go func() { _, _ = io.Copy(io.Discard, peer) }()
		conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
		defer conn.Abort()
		ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
		var trace []string
		record := func(step string, id uuid.UUID) {
			trace = append(trace, fmt.Sprintf("%s:%d", step, slices.Index(ids, id)))
		}
		cached, err := resource.ReadBytes(testResourcePackArchive(t, ids[2]))
		if err != nil {
			t.Fatal(err)
		}
		conn.resourcePackCache = &orderedURLPackCache{memoryPackCache: memoryPackCache{ids[2]: cached}, record: record}
		conn.downloadResourcePack = func(id uuid.UUID, _ string, _, _ int) bool { record("admit", id); return id != ids[3] }
		conn.resourcePackProgress = func(event ResourcePackEvent) {
			switch event.Kind {
			case ResourcePackStarted:
				record("start", event.UUID)
			case ResourcePackFinished:
				record("finish", event.UUID)
			}
		}
		transport := &blockedPackTransport{release: make(chan struct{}), archives: make(map[string][]byte)}
		conn.httpClient = &http.Client{Transport: transport}
		info := &packet.ResourcePacksInfo{}
		for index, id := range ids {
			archive := testResourcePackArchive(t, id)
			path := fmt.Sprintf("/pack-%d", index)
			transport.archives[path] = archive
			info.TexturePacks = append(info.TexturePacks, protocol.TexturePackInfo{UUID: id, Version: "1.0.0", Size: uint64(len(archive)), DownloadURL: "https://packs.test" + path})
		}
		done := make(chan error, 1)
		go func() { done <- conn.handleResourcePacksInfo(info) }()
		synctest.Wait()
		before, started := slices.Clone(trace), transport.started.Load()
		close(transport.release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if want := []string{"admit:0", "load:0", "start:0"}; !slices.Equal(before, want) {
			t.Fatalf("callbacks before first completion = %v, want %v", before, want)
		}
		if started != 1 {
			t.Fatal("default started overlapping URL requests")
		}
		want := []string{"admit:0", "load:0", "start:0", "store:0", "finish:0", "admit:1", "load:1", "start:1", "store:1", "finish:1", "admit:2", "load:2", "finish:2", "admit:3"}
		if !slices.Equal(trace, want) {
			t.Fatalf("callbacks = %v, want %v", trace, want)
		}
		if transport.started.Load() != 2 || len(conn.resourcePacks) != 3 || len(conn.ignoredResourcePacks) != 1 {
			t.Fatal("default acquisition changed admission or cache results")
		}
	})
}

func TestResourcePackURLsDefaultPreservesRepeatedOffers(t *testing.T) {
	for _, source := range []string{"URL", "cache", "chunks"} {
		t.Run(source, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			go func() { _, _ = io.Copy(io.Discard, peer) }()
			conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
			defer conn.Abort()
			id := uuid.New()
			archive := testResourcePackArchive(t, id)
			transport := &blockedPackTransport{release: make(chan struct{}), archives: map[string][]byte{"/pack": archive}}
			close(transport.release)
			conn.httpClient = &http.Client{Transport: transport}
			first := protocol.TexturePackInfo{UUID: id, Version: "1.0.0", Size: uint64(len(archive))}
			if source == "URL" {
				first.DownloadURL = "https://packs.test/pack"
			}
			if source == "cache" {
				pack, err := resource.ReadBytes(archive)
				if err != nil {
					t.Fatal(err)
				}
				conn.resourcePackCache = memoryPackCache{id: pack}
			}
			urlDuplicate, chunkDuplicate := first, first
			urlDuplicate.DownloadURL, chunkDuplicate.DownloadURL = "https://packs.test/pack", ""
			if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{first, urlDuplicate, chunkDuplicate}}); err != nil {
				t.Fatal(err)
			}
			wantRequests, wantPacks, wantQueued := int32(0), 3, 0
			if source == "URL" {
				wantRequests, wantPacks, wantQueued = 2, 2, 1
			}
			if source == "chunks" {
				wantPacks, wantQueued = 0, 1
			}
			if transport.started.Load() != wantRequests || len(conn.resourcePacks) != wantPacks || len(conn.packQueue.downloadingPacks) != wantQueued || conn.packQueue.packAmount != wantQueued {
				t.Fatal("default repeated-offer behavior changed")
			}
		})
	}
}

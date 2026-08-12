package minecraft

// Local-only tests for the resource pack cache and delivery configuration. Not committed: kept out of the
// branch on purpose so the upstream PR stays test-free per repo policy.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

type memoryResourcePackCache struct {
	mu     sync.Mutex
	packs  map[ResourcePackCacheKey]*resource.Pack
	loads  []ResourcePackCacheKey
	stores []ResourcePackCacheKey
}

func (c *memoryResourcePackCache) Load(_ context.Context, key ResourcePackCacheKey) (*resource.Pack, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads = append(c.loads, key)
	return c.packs[key], nil
}

func (c *memoryResourcePackCache) Store(_ context.Context, key ResourcePackCacheKey, pack *resource.Pack) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packs == nil {
		c.packs = make(map[ResourcePackCacheKey]*resource.Pack)
	}
	c.packs[key] = pack
	c.stores = append(c.stores, key)
	return nil
}

func TestResourcePackDeliveryConfigNormalized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   ResourcePackDeliveryConfig
		want ResourcePackDeliveryConfig
	}{
		{name: "zero value keeps defaults", in: ResourcePackDeliveryConfig{}, want: ResourcePackDeliveryConfig{ChunkSize: DefaultResourcePackChunkSize, ChunkSendDelay: DefaultResourcePackChunkSendDelay}},
		{name: "chunk size only keeps default delay", in: ResourcePackDeliveryConfig{ChunkSize: 1024 * 1024}, want: ResourcePackDeliveryConfig{ChunkSize: 1024 * 1024, ChunkSendDelay: DefaultResourcePackChunkSendDelay}},
		{name: "negative delay disables pacing", in: ResourcePackDeliveryConfig{ChunkSendDelay: -1}, want: ResourcePackDeliveryConfig{ChunkSize: DefaultResourcePackChunkSize, ChunkSendDelay: 0}},
		{name: "explicit values kept", in: ResourcePackDeliveryConfig{ChunkSize: 512, ChunkSendDelay: time.Millisecond}, want: ResourcePackDeliveryConfig{ChunkSize: 512, ChunkSendDelay: time.Millisecond}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.normalized(); got != tt.want {
				t.Fatalf("normalized() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestResourcePackCacheRoundTrip downloads a pack from a URL with one connection and verifies that a second
// connection sharing the same cache serves it without touching the network. This pins the store/load key
// symmetry: a pack must be stored under the same key a later login looks it up with.
func TestResourcePackCacheRoundTrip(t *testing.T) {
	t.Parallel()

	packID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	archive := testResourcePackArchive(t, packID)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	cache := &memoryResourcePackCache{}
	info := &packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{
		UUID:        packID,
		Version:     "1.0.0",
		Size:        uint64(len(archive)),
		DownloadURL: server.URL,
	}}}

	handle := func() *Conn {
		client, serverConn := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = serverConn.Close() })
		go func() {
			_, _ = io.Copy(io.Discard, serverConn)
		}()
		conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
		t.Cleanup(func() { _ = conn.Close() })
		conn.resourcePackCache = cache
		if err := conn.handleResourcePacksInfo(info); err != nil {
			t.Fatalf("handleResourcePacksInfo: %v", err)
		}
		return conn
	}

	first := handle()
	if requests != 1 {
		t.Fatalf("requests after first login = %d, want 1", requests)
	}
	if len(first.resourcePacks) != 1 || first.packQueue.packAmount != 0 {
		t.Fatalf("first login: resourcePacks = %d, packAmount = %d", len(first.resourcePacks), first.packQueue.packAmount)
	}
	if len(cache.stores) != 1 {
		t.Fatalf("stores after first login = %d, want 1", len(cache.stores))
	}

	second := handle()
	if requests != 1 {
		t.Fatalf("requests after second login = %d, want 1 (cache should have been hit)", requests)
	}
	if len(second.resourcePacks) != 1 || second.packQueue.packAmount != 0 {
		t.Fatalf("second login: resourcePacks = %d, packAmount = %d", len(second.resourcePacks), second.packQueue.packAmount)
	}
	if cache.stores[0] != cache.loads[0] {
		t.Fatalf("store key %+v does not match load key %+v", cache.stores[0], cache.loads[0])
	}
	if got := second.resourcePacks[0].UUID(); got != packID {
		t.Fatalf("cached pack UUID = %v, want %v", got, packID)
	}
}

// TestResourcePackCacheMismatchFallsBack verifies that a cached pack whose identity does not match the
// advertisement is ignored and the pack is downloaded from the server instead.
func TestResourcePackCacheMismatchFallsBack(t *testing.T) {
	t.Parallel()

	packID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	otherID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	archive := testResourcePackArchive(t, packID)
	stale, err := resource.Read(bytes.NewReader(testResourcePackArchive(t, otherID)))
	if err != nil {
		t.Fatalf("read stale pack: %v", err)
	}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	key := ResourcePackCacheKey{UUID: packID, Version: "1.0.0", Size: uint64(len(archive))}
	cache := &memoryResourcePackCache{packs: map[ResourcePackCacheKey]*resource.Pack{key: stale}}

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
	defer conn.Close()
	conn.resourcePackCache = cache

	err = conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{
		UUID:        packID,
		Version:     "1.0.0",
		Size:        uint64(len(archive)),
		DownloadURL: server.URL,
	}}})
	if err != nil {
		t.Fatalf("handleResourcePacksInfo: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (mismatched cache entry must fall back to download)", requests)
	}
	if len(conn.resourcePacks) != 1 || conn.resourcePacks[0].UUID() != packID {
		t.Fatalf("resourcePacks = %d, want the downloaded pack", len(conn.resourcePacks))
	}
}

func TestDirResourcePackCache(t *testing.T) {
	t.Parallel()

	packID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	archive := testResourcePackArchive(t, packID)
	pack, err := resource.Read(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}
	cache := DirResourcePackCache{Dir: t.TempDir() + "/packs"}
	key := ResourcePackCacheKey{UUID: packID, Version: "1.0.0", Size: uint64(pack.Size())}

	if got, err := cache.Load(context.Background(), key); err != nil || got != nil {
		t.Fatalf("Load before store = %v, %v; want nil, nil", got, err)
	}
	if err := cache.Store(context.Background(), key, pack); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := cache.Load(context.Background(), key)
	if err != nil || got == nil {
		t.Fatalf("Load after store = %v, %v; want pack, nil", got, err)
	}
	if !key.Matches(got) {
		t.Fatalf("loaded pack does not match key: UUID=%v version=%v size=%v", got.UUID(), got.Version(), got.Size())
	}
	if key2 := (ResourcePackCacheKey{UUID: packID, Version: "../../evil", Size: 1}); filepath.Dir(cache.path(key2)) != filepath.Clean(cache.Dir) {
		t.Fatalf("path escaped the cache dir: %v", cache.path(key2))
	}
	leftovers, _ := filepath.Glob(cache.Dir + "/pack-*.tmp")
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

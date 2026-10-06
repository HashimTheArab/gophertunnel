package minecraft

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/resource"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestResourcePackDownloadConfigNormalized(t *testing.T) {
	for _, test := range []struct {
		name   string
		config ResourcePackDownloadConfig
		want   int
	}{
		{name: "zero", want: DefaultResourcePackMaxInFlightChunks},
		{name: "negative", config: ResourcePackDownloadConfig{MaxInFlightChunks: -1}, want: DefaultResourcePackMaxInFlightChunks},
		{name: "custom", config: ResourcePackDownloadConfig{MaxInFlightChunks: 7}, want: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.config.normalized().MaxInFlightChunks; got != test.want {
				t.Fatalf("MaxInFlightChunks = %d, want %d", got, test.want)
			}
		})
	}
}

func TestResourcePackDownloadReplenishesAfterOutOfOrderChunk(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()

	const id = "550e8400-e29b-41d4-a716-446655440000"
	pack := &downloadingPack{buf: new(bytes.Buffer), size: 200}
	conn.packQueue = &resourcePackQueue{
		downloadingPacks: map[string]*downloadingPack{id: pack},
		awaitingPacks:    make(map[string]*downloadingPack),
	}
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{
		UUID:          id + "_1.0.0",
		DataChunkSize: 1,
		Size:          200,
	}); err != nil {
		t.Fatalf("handleResourcePackDataInfo: %v", err)
	}

	if !waitForResourcePackRequest(t, pack, 99) {
		t.Fatal("vanilla request window was not filled")
	}
	pack.mu.Lock()
	_, requestedEarly := pack.requested[100]
	requestCount := len(pack.requested)
	pack.mu.Unlock()
	if requestedEarly {
		t.Fatal("request window exceeded before a chunk was received")
	}
	if requestCount != DefaultResourcePackMaxInFlightChunks {
		t.Fatalf("initial request count = %d, want %d", requestCount, DefaultResourcePackMaxInFlightChunks)
	}
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{
		UUID:       id + "_1.0.0",
		ChunkIndex: 50,
		Data:       []byte{50},
	}); err != nil {
		t.Fatalf("handleResourcePackChunkData: %v", err)
	}
	if !waitForResourcePackRequest(t, pack, 100) {
		t.Fatal("out-of-order response did not replenish the request window")
	}
}

func waitForResourcePackRequest(t *testing.T, pack *downloadingPack, index uint32) bool {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pack.mu.Lock()
		_, ok := pack.requested[index]
		pack.mu.Unlock()
		if ok {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

type recordedPackEvents struct {
	mu     sync.Mutex
	events []ResourcePackEvent
}

func (r *recordedPackEvents) record(event ResourcePackEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

// steps compresses events to kind/source pairs with Received runs summed into one entry.
func (r *recordedPackEvents) steps() []ResourcePackEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var steps []ResourcePackEvent
	for _, event := range r.events {
		event.Err = nil
		if n := len(steps); n > 0 && event.Kind == ResourcePackReceived && steps[n-1].Kind == ResourcePackReceived && steps[n-1].UUID == event.UUID {
			steps[n-1].Size += event.Size
			continue
		}
		steps = append(steps, event)
	}
	return steps
}

type memoryPackCache map[uuid.UUID]*resource.Pack

func (c memoryPackCache) Load(_ context.Context, key ResourcePackCacheKey) (*resource.Pack, error) {
	return c[key.UUID], nil
}
func (memoryPackCache) Store(context.Context, ResourcePackCacheKey, *resource.Pack) error { return nil }

// Cache hits, URL downloads with their byte counts, and a failed URL falling back to chunks are all reported.
func TestResourcePacksInfoReportsCacheURLAndFallbackEvents(t *testing.T) {
	cachedID, urlID, brokenID := uuid.New(), uuid.New(), uuid.New()
	cachedPack, err := resource.ReadBytes(testResourcePackArchive(t, cachedID))
	if err != nil {
		t.Fatal(err)
	}
	urlArchive := testResourcePackArchive(t, urlID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(urlArchive)
	}))
	defer server.Close()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()
	var events recordedPackEvents
	conn.resourcePackProgress = events.record
	conn.resourcePackCache = memoryPackCache{cachedID: cachedPack}
	if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{UUID: cachedID, Version: "1.0.0", Size: uint64(cachedPack.Size())},
		{UUID: urlID, Version: "1.0.0", Size: uint64(len(urlArchive)), DownloadURL: server.URL + "/pack"},
		{UUID: brokenID, Version: "1.0.0", Size: 10, DownloadURL: server.URL + "/broken"},
	}}); err != nil {
		t.Fatal(err)
	}
	cache, url := ResourcePackSourceCache, ResourcePackSourceURL
	want := []ResourcePackEvent{
		{Kind: ResourcePackFinished, Source: cache, UUID: cachedID, Version: "1.0.0", Size: uint64(cachedPack.Size())},
		{Kind: ResourcePackStarted, Source: url, UUID: urlID, Version: "1.0.0", Size: uint64(len(urlArchive))},
		{Kind: ResourcePackReceived, Source: url, UUID: urlID, Version: "1.0.0", Size: uint64(len(urlArchive))},
		{Kind: ResourcePackFinished, Source: url, UUID: urlID, Version: "1.0.0"},
		{Kind: ResourcePackStarted, Source: url, UUID: brokenID, Version: "1.0.0", Size: 10},
		{Kind: ResourcePackFailed, Source: url, UUID: brokenID, Version: "1.0.0"},
	}
	if got := events.steps(); !slices.Equal(got, want) {
		t.Fatalf("events = %+v\nwant %+v", got, want)
	}
	if _, queued := conn.packQueue.downloadingPacks[brokenID.String()]; !queued {
		t.Fatal("the failed URL pack did not fall back to chunks")
	}
}

// Chunk transfers report their start, bytes and completion; a cancelled connection fails an open transfer.
func TestChunkDownloadReportsProgressAndCancellation(t *testing.T) {
	archive := testResourcePackArchive(t, uuid.New())
	for _, cancel := range []bool{false, true} {
		client, peer := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, peer) }()
		conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
		var events recordedPackEvents
		conn.resourcePackProgress = events.record
		id := uuid.New()
		key := ResourcePackCacheKey{UUID: id, Version: "1.0.0", Size: uint64(len(archive))}
		pack := &downloadingPack{buf: new(bytes.Buffer), size: uint64(len(archive)), cacheKey: key}
		conn.packQueue = &resourcePackQueue{
			packAmount:       1,
			downloadingPacks: map[string]*downloadingPack{id.String(): pack},
			awaitingPacks:    make(map[string]*downloadingPack),
		}
		if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: id.String() + "_1.0.0", DataChunkSize: uint32(len(archive)), Size: uint64(len(archive))}); err != nil {
			t.Fatal(err)
		}
		waitForResourcePackRequest(t, pack, 0)
		chunks := ResourcePackSourceChunks
		want := []ResourcePackEvent{{Kind: ResourcePackStarted, Source: chunks, UUID: id, Version: "1.0.0", Size: uint64(len(archive))}}
		if cancel {
			_ = conn.Abort()
			want = append(want, ResourcePackEvent{Kind: ResourcePackFailed, Source: chunks, UUID: id, Version: "1.0.0"})
		} else {
			if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: id.String() + "_1.0.0", Data: archive}); err != nil {
				t.Fatal(err)
			}
			want = append(want,
				ResourcePackEvent{Kind: ResourcePackReceived, Source: chunks, UUID: id, Version: "1.0.0", Size: uint64(len(archive))},
				ResourcePackEvent{Kind: ResourcePackFinished, Source: chunks, UUID: id, Version: "1.0.0"})
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(events.steps()) < len(want) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := events.steps(); !slices.Equal(got, want) {
			t.Fatalf("cancel=%t events = %+v\nwant %+v", cancel, got, want)
		}
		_ = conn.Abort()
		_ = peer.Close()
	}
}

type recordingPackCache struct {
	mu     sync.Mutex
	stored []ResourcePackCacheKey
}

func (*recordingPackCache) Load(context.Context, ResourcePackCacheKey) (*resource.Pack, error) {
	return nil, nil
}
func (c *recordingPackCache) Store(_ context.Context, key ResourcePackCacheKey, _ *resource.Pack) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stored = append(c.stored, key)
	return nil
}

// A chunk-downloaded pack is in the cache before Dial hands out the Conn, so an immediate Close cannot cancel its store.
func TestChunkDownloadStoresBeforeDialReturns(t *testing.T) {
	id := uuid.New()
	archive := testResourcePackArchive(t, id)
	client, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()
	cache := &recordingPackCache{}
	conn.resourcePackCache = cache
	key := ResourcePackCacheKey{UUID: id, Version: "1.0.0", Size: uint64(len(archive))}
	pack := &downloadingPack{buf: new(bytes.Buffer), size: key.Size, cacheKey: key}
	conn.packQueue = &resourcePackQueue{
		packAmount:       1,
		downloadingPacks: map[string]*downloadingPack{id.String(): pack},
		awaitingPacks:    make(map[string]*downloadingPack),
	}
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: id.String() + "_1.0.0", DataChunkSize: uint32(len(archive)), Size: key.Size}); err != nil {
		t.Fatal(err)
	}
	waitForResourcePackRequest(t, pack, 0)
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: id.String() + "_1.0.0", Data: archive}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.awaitPackStores(ctx); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !slices.Equal(cache.stored, []ResourcePackCacheKey{key}) {
		t.Fatalf("stored %v before Dial returned, want %v", cache.stored, key)
	}
}

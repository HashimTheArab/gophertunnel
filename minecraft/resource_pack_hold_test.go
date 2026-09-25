package minecraft

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// TestHoldResourcePackCompletion parks Completed until the caller releases it and keeps the server's packets.
func TestHoldResourcePackCompletion(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()
	conn.disablePacketHandling = true
	conn.holdResourcePackCompletion = true
	conn.packsReady = make(chan struct{})

	if err := conn.CompleteResourcePacks(); err == nil {
		t.Fatal("completed before the stack arrived")
	}
	info := &packet.ResourcePacksInfo{TexturePackRequired: true}
	if err := conn.handleResourcePacksInfo(info); err != nil {
		t.Fatal(err)
	}
	stack := &packet.ResourcePackStack{BaseGameVersion: "1.26.0"}
	if err := conn.handleResourcePackStack(stack); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.ResourcePacksReady():
	default:
		t.Fatal("packs not reported ready after the stack")
	}
	if conn.packPhaseDone.Load() || conn.loggedIn {
		t.Fatal("completion was not held")
	}
	if got := conn.ResourcePacksInfo(); got == info || !got.TexturePackRequired {
		t.Fatal("retained info is not an independent copy of the server's packet")
	}
	if conn.ResourcePackStack().BaseGameVersion != "1.26.0" {
		t.Fatal("retained stack lost")
	}
	if err := conn.handleResourcePackStack(&packet.ResourcePackStack{BaseGameVersion: "dup"}); err != nil {
		t.Fatal(err)
	}
	if conn.ResourcePackStack().BaseGameVersion != "1.26.0" {
		t.Fatal("a resent stack replaced the retained one")
	}
	if err := conn.CompleteResourcePacks(); err != nil || !conn.packPhaseDone.Load() {
		t.Fatalf("CompleteResourcePacks = %v, done=%v", err, conn.packPhaseDone.Load())
	}
}

// TestPackFilesRemovedOnAbort leaves no download files behind when a connection ends.
func TestPackFilesRemovedOnAbort(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	cache := DirResourcePackCache{Dir: t.TempDir()}
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.resourcePackCache = cache
	info := &packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: uuid.New(), Version: "1.0.0", Size: 64}}}
	if err := conn.handleResourcePacksInfo(info); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cache.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("download file not created in the cache dir: %v, %v", entries, err)
	}
	conn.Abort()
	if entries, _ := os.ReadDir(cache.Dir); len(entries) != 0 {
		t.Fatalf("download file left behind: %v", entries)
	}
}

// TestDirResourcePackCache_EvictsLeastRecentlyUsed keeps the directory under MaxBytes, dropping the entry
// that was loaded least recently.
func TestDirResourcePackCache_EvictsLeastRecentlyUsed(t *testing.T) {
	cache := DirResourcePackCache{Dir: t.TempDir()}
	store := func(name string) ResourcePackCacheKey {
		t.Helper()
		pack, err := resource.ReadBytes(testPackArchive(t, name))
		if err != nil {
			t.Fatal(err)
		}
		key := ResourcePackCacheKey{UUID: pack.UUID(), Version: pack.Version(), Size: uint64(pack.Size())}
		if err := cache.Store(t.Context(), key, pack); err != nil {
			t.Fatal(err)
		}
		return key
	}
	first := store("first")
	second := store("second")
	time.Sleep(20 * time.Millisecond)
	old, err := cache.Load(t.Context(), first) // touches first, so second is now least recent
	if err != nil || old == nil {
		t.Fatal("first entry missing before eviction")
	}
	_ = old.Close()
	cache.MaxBytes = 2*int64(first.Size) + 1
	third := store("third")
	if pack, _ := cache.Load(t.Context(), second); pack != nil {
		t.Fatal("least recently used entry survived eviction")
	}
	for _, key := range []ResourcePackCacheKey{first, third} {
		pack, err := cache.Load(t.Context(), key)
		if err != nil || pack == nil {
			t.Fatalf("entry %s evicted", key.UUID)
		}
		_ = pack.Close()
	}
}

func testPackArchive(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for file, content := range map[string]string{
		"manifest.json": fmt.Sprintf(`{"format_version": 2, "header": {"name": %q, "uuid": %q, "version": [1, 0, 0]}, "modules": [{"type": "resources", "uuid": %q, "version": [1, 0, 0]}]}`, name, uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)), uuid.New()),
		"pad.txt":       strings.Repeat(name, 64),
	} {
		f, err := w.Create(file)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

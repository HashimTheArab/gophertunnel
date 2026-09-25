package minecraft

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// TestDialHoldsResourcePackCompletion downloads a server's pack into the cache, parks Completed until
// released, and then passes StartGame through.
func TestDialHoldsResourcePackCompletion(t *testing.T) {
	log := slog.New(internal.DiscardHandler{})
	pack, err := resource.ReadBytes(testPackArchive(t, "held"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenConfig{ErrorLog: log, AuthenticationDisabled: true, ResourcePacks: []*resource.Pack{pack}}.Listen("raknet", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started := make(chan error, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			started <- err
			return
		}
		// StartGame blocks on a spawn reply a passthrough dialer never sends; write the packet itself.
		if err := server.(*Conn).WritePacket(&packet.StartGame{WorldName: "held"}); err != nil {
			started <- err
			return
		}
		started <- server.(*Conn).Flush()
	}()

	cache := DirResourcePackCache{Dir: t.TempDir()}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	dialer := Dialer{ErrorLog: log, DisablePacketHandling: true, EnableBatchReading: true, HoldResourcePackCompletion: true, ResourcePackCache: cache, FlushRate: -1}
	conn, err := dialer.DialContext(ctx, "raknet", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case <-conn.ResourcePacksReady():
	case <-ctx.Done():
		t.Fatal("pack phase never reported ready")
	}
	if packs := conn.ResourcePacks(); len(packs) != 1 || packs[0].UUID() != pack.UUID() {
		t.Fatalf("downloaded packs = %v", packs)
	}
	if info := conn.ResourcePacksInfo(); info == nil || len(info.TexturePacks) != 1 || info.TexturePacks[0].UUID != pack.UUID() {
		t.Fatalf("retained info = %+v", info)
	}
	stack := conn.ResourcePackStack()
	if stack == nil || !slices.ContainsFunc(stack.TexturePacks, func(entry protocol.StackResourcePack) bool { return entry.UUID == pack.UUID().String() }) {
		t.Fatalf("retained stack lacks the server pack: %+v", stack)
	}
	select {
	case err := <-started:
		t.Fatalf("server finished login before completion was released: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := conn.CompleteResourcePacks(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("StartGame never passed through after completion")
		}
		batch, err := conn.ReadBatch()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, pk := range batch {
			if _, ok := pk.(*packet.StartGame); ok {
				found = true
			}
		}
		if found {
			break
		}
	}
	entries, _ := os.ReadDir(cache.Dir)
	var cached, temp int
	for _, entry := range entries {
		switch {
		case strings.HasSuffix(entry.Name(), ".mcpack"):
			cached++
		case strings.HasSuffix(entry.Name(), ".tmp"):
			temp++
		}
	}
	if cached != 1 {
		t.Fatalf("cache holds %d packs, want 1: %v", cached, entries)
	}
	_ = conn.Close()
	if entries, _ := os.ReadDir(cache.Dir); len(entries) != 1 {
		t.Fatalf("download files left after close: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(cache.Dir, cache.path(ResourcePackCacheKey{UUID: pack.UUID(), Version: pack.Version(), Size: uint64(pack.Size())})[len(cache.Dir)+1:])); err != nil {
		t.Fatalf("cache entry missing: %v", err)
	}
	_ = temp
}

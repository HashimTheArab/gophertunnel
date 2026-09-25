package minecraft

import (
	"io"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
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
	if conn.packPhaseDone || conn.loggedIn {
		t.Fatal("completion was not held")
	}
	if got := conn.ResourcePacksInfo(); got == info || !got.TexturePackRequired {
		t.Fatal("retained info is not an independent copy of the server's packet")
	}
	if conn.ResourcePackStack().BaseGameVersion != "1.26.0" {
		t.Fatal("retained stack lost")
	}
	if err := conn.CompleteResourcePacks(); err != nil || !conn.packPhaseDone {
		t.Fatalf("CompleteResourcePacks = %v, done=%v", err, conn.packPhaseDone)
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

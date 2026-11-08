package minecraft

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// A server may offer one pack UUID at several versions and require all of them. Every version is requested,
// transferred under its own "uuid_version" pack ID and kept.
func TestChunkDownloadKeepsEveryVersionOfOnePackUUID(t *testing.T) {
	id := uuid.New()
	versions := []string{"2.7.0", "2.18.0"}
	archives := map[string][]byte{
		"2.7.0":  testVersionedResourcePackArchive(t, id, [3]int{2, 7, 0}),
		"2.18.0": testVersionedResourcePackArchive(t, id, [3]int{2, 18, 0}),
	}
	client, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()

	offers := make([]protocol.TexturePackInfo, len(versions))
	names := make([]string, len(versions))
	for i, version := range versions {
		offers[i] = protocol.TexturePackInfo{UUID: id, Version: version, Size: uint64(len(archives[version]))}
		names[i] = id.String() + "_" + version
	}
	if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePackRequired: true, TexturePacks: offers}); err != nil {
		t.Fatal(err)
	}
	if got := sentPacksToDownload(t, conn); !slices.Equal(got, names) {
		t.Fatalf("requested %v, want %v", got, names)
	}

	for _, version := range versions {
		name := id.String() + "_" + version
		archive := archives[version]
		if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: name, DataChunkSize: uint32(len(archive)), Size: uint64(len(archive))}); err != nil {
			t.Fatalf("ResourcePackDataInfo %s: %v", name, err)
		}
		conn.packMu.Lock()
		pack := conn.packQueue.awaitingPacks[name]
		conn.packMu.Unlock()
		if pack == nil || !waitForResourcePackRequest(t, pack, 0) {
			t.Fatalf("transfer %s did not request its chunk", name)
		}
		if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: name, Data: archive}); err != nil {
			t.Fatalf("ResourcePackChunkData %s: %v", name, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.packMu.Lock()
		remaining := conn.packQueue.packAmount
		var got []string
		for _, pack := range conn.resourcePacks {
			if pack.UUID() == id {
				got = append(got, pack.Version())
			}
		}
		conn.packMu.Unlock()
		slices.Sort(got)
		if remaining == 0 && slices.Equal(got, []string{"2.18.0", "2.7.0"}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("downloaded versions %v with %d remaining, want both versions and none remaining", got, remaining)
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.handleResourcePackStack(&packet.ResourcePackStack{TexturePackRequired: true, TexturePacks: []protocol.StackResourcePack{
		{UUID: id.String(), Version: "2.7.0"},
		{UUID: id.String(), Version: "2.18.0"},
	}}); err != nil {
		t.Fatalf("required stack naming both versions: %v", err)
	}
}

// A DataInfo or ChunkData that names a pack by UUID alone, or by a version other than the offered one, still
// matches the single pending transfer with that UUID.
func TestChunkDownloadMatchesUnversionedPackIDByUUID(t *testing.T) {
	id := uuid.New()
	archive := testVersionedResourcePackArchive(t, id, [3]int{1, 0, 0})
	client, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()
	if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: id, Version: "1.0.0", Size: uint64(len(archive))}}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: id.String(), DataChunkSize: uint32(len(archive)), Size: uint64(len(archive))}); err != nil {
		t.Fatalf("ResourcePackDataInfo by UUID: %v", err)
	}
	conn.packMu.Lock()
	pack := conn.packQueue.awaitingPacks[id.String()+"_1.0.0"]
	conn.packMu.Unlock()
	if pack == nil || !waitForResourcePackRequest(t, pack, 0) {
		t.Fatal("transfer named by UUID did not request its chunk")
	}
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: id.String() + "_1.0", Data: archive}); err != nil {
		t.Fatalf("ResourcePackChunkData with another version spelling: %v", err)
	}
}

// A Listener serves every version a client requests, even when they share a UUID, and only serves chunks of
// the version it is currently sending.
func TestResourcePackQueueServesEveryVersionOfOnePackUUID(t *testing.T) {
	id := uuid.New()
	var packs []*resource.Pack
	var names []string
	for _, version := range [][3]int{{2, 7, 0}, {2, 18, 0}} {
		pack, err := resource.ReadBytes(testVersionedResourcePackArchive(t, id, version))
		if err != nil {
			t.Fatal(err)
		}
		packs = append(packs, pack)
		names = append(names, id.String()+"_"+pack.Version())
	}
	raw := &recordingConn{writes: make(chan []byte, 16)}
	conn := newConn(raw, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.packQueue = &resourcePackQueue{packs: packs, chunkSize: 1 << 20}
	if err := conn.packQueue.Request(names); err != nil {
		t.Fatal(err)
	}

	if err := conn.nextResourcePackDownload(); err != nil {
		t.Fatal(err)
	}
	var served []string
	for range names {
		current := resourcePackDownloadID(id.String(), conn.packQueue.currentPack.Version())
		served = append(served, current)
		for _, name := range names {
			if name == current {
				continue
			}
			if err := conn.handleResourcePackChunkRequest(&packet.ResourcePackChunkRequest{UUID: name}); err == nil {
				t.Fatalf("chunk request for %s was served while sending %s", name, current)
			}
		}
		// The pack fits one chunk, so serving it moves the queue on to the next requested pack.
		if err := conn.handleResourcePackChunkRequest(&packet.ResourcePackChunkRequest{UUID: current}); err != nil {
			t.Fatalf("chunk request for %s: %v", current, err)
		}
	}
	if !conn.packQueue.AllDownloaded() {
		t.Fatal("packs remain queued after every requested pack was served")
	}
	slices.Sort(served)
	slices.Sort(names)
	if !slices.Equal(served, names) {
		t.Fatalf("served %v, want %v", served, names)
	}
}

// sentPacksToDownload decodes the ResourcePackClientResponse buffered by handleResourcePacksInfo.
func sentPacksToDownload(t *testing.T, conn *Conn) []string {
	t.Helper()
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	for _, data := range conn.bufferedSend {
		buf := bytes.NewBuffer(data)
		var header packet.Header
		if err := header.Read(buf); err != nil || header.PacketID != packet.IDResourcePackClientResponse {
			continue
		}
		var response packet.ResourcePackClientResponse
		response.Marshal(protocol.NewReader(buf, 0, true))
		return response.PacksToDownload
	}
	t.Fatal("no ResourcePackClientResponse was buffered")
	return nil
}

// testVersionedResourcePackArchive returns a minimal resource pack archive with the UUID and manifest
// version passed.
func testVersionedResourcePackArchive(t *testing.T, id uuid.UUID, version [3]int) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	v := fmt.Sprintf("[%d, %d, %d]", version[0], version[1], version[2])
	_, _ = fmt.Fprintf(w, `{
		"format_version": 2,
		"header": {"name": "test pack", "description": "test pack", "uuid": %q, "version": %s, "min_engine_version": [1, 20, 0]},
		"modules": [{"description": "test pack", "type": "resources", "uuid": %q, "version": %s}]
	}`, id.String(), v, uuid.NewString(), v)
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// versionOfferConn offers one UUID at each version passed and returns the conn and each version's archive.
func versionOfferConn(t *testing.T, versions ...[3]int) (*Conn, uuid.UUID, map[string][]byte) {
	t.Helper()
	id := uuid.New()
	archives := make(map[string][]byte)
	var offers []protocol.TexturePackInfo
	for _, v := range versions {
		name := fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
		archives[name] = testVersionedResourcePackArchive(t, id, v)
		offers = append(offers, protocol.TexturePackInfo{UUID: id, Version: name, Size: uint64(len(archives[name]))})
	}
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	t.Cleanup(func() { _ = conn.Abort() })
	if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePackRequired: true, TexturePacks: offers}); err != nil {
		t.Fatal(err)
	}
	return conn, id, archives
}

// startTransfer sends DataInfo for name and waits for its first chunk request.
func startTransfer(t *testing.T, conn *Conn, name string, data []byte) *downloadingPack {
	t.Helper()
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: name, DataChunkSize: uint32(len(data)), Size: uint64(len(data))}); err != nil {
		t.Fatal(err)
	}
	conn.packMu.Lock()
	_, pack, _ := lookupTransfer(conn.packQueue.awaitingPacks, name)
	conn.packMu.Unlock()
	if pack == nil || !waitForResourcePackRequest(t, pack, 0) {
		t.Fatal("no chunk request")
	}
	return pack
}

// TestDataInfoForFinishedVersionKeepsOtherVersionPending refuses a repeated DataInfo for a finished version
// rather than letting it take over the other version's pending transfer.
func TestDataInfoForFinishedVersionKeepsOtherVersionPending(t *testing.T) {
	conn, id, archives := versionOfferConn(t, [3]int{2, 7, 0}, [3]int{2, 18, 0})
	first, data := id.String()+"_2.7.0", archives["2.7.0"]
	startTransfer(t, conn, first, data)
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: first, Data: data}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		conn.packMu.Lock()
		_, inFlight := conn.packQueue.awaitingPacks[first]
		conn.packMu.Unlock()
		if !inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first transfer did not finish")
		}
	}
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: first, DataChunkSize: uint32(len(data)), Size: uint64(len(data))}); err == nil {
		t.Fatalf("DataInfo for finished %s was accepted", first)
	}
	if _, pending := conn.packQueue.downloadingPacks[id.String()+"_2.18.0"]; !pending {
		t.Fatal("2.18.0 transfer was consumed by the repeated 2.7.0 DataInfo")
	}
}

// TestChunkDataForUnstartedVersionIsNotMisrouted refuses chunk data naming a version that has not started
// instead of writing it into another version's transfer.
func TestChunkDataForUnstartedVersionIsNotMisrouted(t *testing.T) {
	conn, id, archives := versionOfferConn(t, [3]int{2, 7, 0}, [3]int{2, 18, 0})
	data := archives["2.7.0"]
	startTransfer(t, conn, id.String()+"_2.7.0", data)
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: id.String() + "_2.18.0", Data: data}); err == nil {
		t.Fatal("chunk data for the unstarted 2.18.0 transfer was written into the 2.7.0 transfer")
	}
}

// TestChunkDataUsesRequestedIDAfterAliasDataInfo accepts chunk data naming the requested ID for a transfer
// the server started under its bare UUID.
func TestChunkDataUsesRequestedIDAfterAliasDataInfo(t *testing.T) {
	conn, id, archives := versionOfferConn(t, [3]int{2, 7, 0})
	data := archives["2.7.0"]
	startTransfer(t, conn, id.String(), data)
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: id.String() + "_2.7.0", Data: data}); err != nil {
		t.Fatalf("ChunkData naming the requested ID: %v", err)
	}
}

// TestResourcePacksInfoRequestsParsedVersion requests an offer of "1.0" as "1.0.0", and offers of "1.0" and
// "1.0.0" for one UUID only once, as the vanilla client does.
func TestResourcePacksInfoRequestsParsedVersion(t *testing.T) {
	id := uuid.New()
	client, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Abort()
	if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{UUID: id, Version: "1.0", Size: 1},
		{UUID: id, Version: "1.0.0", Size: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	if got, want := sentPacksToDownload(t, conn), []string{id.String() + "_1.0.0"}; !slices.Equal(got, want) {
		t.Fatalf("requested %v, want %v", got, want)
	}
}

// TestShortVersionIDsReachTheirOwnTransfer resolves "1.0" to the 1.0.0 transfer while 2.0.0 is pending, and
// never routes it into the 2.0.0 transfer.
func TestShortVersionIDsReachTheirOwnTransfer(t *testing.T) {
	conn, id, archives := versionOfferConn(t, [3]int{1, 0, 0}, [3]int{2, 0, 0})
	short := id.String() + "_1.0"
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: short, Data: archives["1.0.0"]}); err == nil {
		t.Fatal("chunk data for the unstarted 1.0.0 transfer was accepted")
	}
	startTransfer(t, conn, id.String()+"_2.0.0", archives["2.0.0"])
	if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{UUID: short, Data: archives["1.0.0"]}); err == nil {
		t.Fatal("chunk data naming 1.0 was routed into the 2.0.0 transfer")
	}
	startTransfer(t, conn, short, archives["1.0.0"])
	conn.packMu.Lock()
	_, started := conn.packQueue.awaitingPacks[id.String()+"_1.0.0"]
	conn.packMu.Unlock()
	if !started {
		t.Fatal("DataInfo naming 1.0 did not start the 1.0.0 transfer")
	}
}

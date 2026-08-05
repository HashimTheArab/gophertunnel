package minecraft

import (
	"archive/zip"
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

func TestResourcePackChunkRequestFlushesBeforeDelay(t *testing.T) {
	const delay = 200 * time.Millisecond

	raw := &recordingConn{writes: make(chan []byte, 1)}
	conn := newConn(raw, nil, slog.Default(), DefaultProtocol, -1, false)
	conn.resourcePackDelivery.ChunkSendDelay = delay
	pack := testResourcePack(t)
	conn.packQueue = &resourcePackQueue{
		currentPack:     pack,
		chunkSize:       uint32(pack.Size()),
		packsToDownload: map[string]*resource.Pack{},
	}

	done := make(chan error, 1)
	started := time.Now()
	go func() {
		done <- conn.handlePacket(&packet.ResourcePackChunkRequest{
			UUID:       pack.UUID().String(),
			ChunkIndex: 0,
		})
	}()

	select {
	case <-raw.writes:
		if elapsed := time.Since(started); elapsed >= delay {
			t.Fatalf("chunk was flushed after the pacing delay: %v", elapsed)
		}
	case <-time.After(delay / 2):
		t.Fatal("chunk was not flushed before the pacing delay")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handle resource pack chunk request: %v", err)
		}
	case <-time.After(delay * 2):
		t.Fatal("resource pack chunk request did not finish")
	}
}

func testResourcePack(t *testing.T) *resource.Pack {
	t.Helper()

	const packUUID = "2f8f5f7e-09c4-4d5d-b3b2-8d39a8a1b1a7"
	const moduleUUID = "4c0bc8e1-7e51-4d6e-8c49-3e7e3857c3a8"
	manifest := []byte(`{"format_version":2,"header":{"name":"test","description":"test","uuid":"` + packUUID + `","version":[1,0,0],"min_engine_version":[1,20,0]},"modules":[{"type":"resources","uuid":"` + moduleUUID + `","version":[1,0,0]}]}`)

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	if _, err := file.Write(manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	pack, err := resource.ReadBytes(archive.Bytes())
	if err != nil {
		t.Fatalf("read test resource pack: %v", err)
	}
	return pack
}

type recordingConn struct {
	writes chan []byte
}

func (conn *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }

func (conn *recordingConn) Write(data []byte) (int, error) {
	conn.writes <- bytes.Clone(data)
	return len(data), nil
}

func (conn *recordingConn) Close() error { return nil }

func (conn *recordingConn) LocalAddr() net.Addr { return testAddr("local") }

func (conn *recordingConn) RemoteAddr() net.Addr { return testAddr("remote") }

func (conn *recordingConn) SetDeadline(time.Time) error { return nil }

func (conn *recordingConn) SetReadDeadline(time.Time) error { return nil }

func (conn *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (addr testAddr) Network() string { return "test" }

func (addr testAddr) String() string { return string(addr) }

var _ net.Conn = (*recordingConn)(nil)

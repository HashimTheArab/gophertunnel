package minecraft

import (
	"archive/zip"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestHandleResourcePacksInfoCountsURLDownloadedPacks(t *testing.T) {
	t.Parallel()

	urlPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	chunkPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	urlPack := testResourcePackArchive(t, urlPackID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(urlPack)
	}))
	defer server.Close()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
	defer conn.Close()

	err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{
			UUID:        urlPackID,
			Version:     "1.0.0",
			DownloadURL: server.URL,
		},
		{
			UUID:    chunkPackID,
			Version: "1.0.0",
			Size:    1,
		},
	}})
	if err != nil {
		t.Fatalf("handleResourcePacksInfo: %v", err)
	}
	if conn.packQueue.packAmount != 1 {
		t.Fatalf("packAmount = %d, want 1", conn.packQueue.packAmount)
	}
	if _, ok := conn.packQueue.downloadingPacks[chunkPackID.String()]; !ok {
		t.Fatalf("chunk pack was not queued for chunk download")
	}
	if len(conn.resourcePacks) != 1 {
		t.Fatalf("resourcePacks length = %d, want 1", len(conn.resourcePacks))
	}
}

func testResourcePackArchive(t *testing.T, id uuid.UUID) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	_, _ = w.Write([]byte(`{
		"format_version": 2,
		"header": {
			"name": "test pack",
			"description": "test pack",
			"uuid": "` + id.String() + `",
			"version": [1, 0, 0],
			"min_engine_version": [1, 20, 0]
		},
		"modules": [{
			"description": "test pack",
			"type": "resources",
			"uuid": "550e8400-e29b-41d4-a716-446655440001",
			"version": [1, 0, 0]
		}]
	}`))
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

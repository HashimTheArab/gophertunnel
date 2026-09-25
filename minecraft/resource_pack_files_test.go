package minecraft

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// newPackFileTestConn provides an isolated connection with a caller-selected shared download budget.
func newPackFileTestConn(t *testing.T, budget *ResourcePackDownloadBudget) *Conn {
	t.Helper()
	client, peer := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.resourcePackCache = DirResourcePackCache{Dir: t.TempDir()}
	conn.resourcePackDownload = (ResourcePackDownloadConfig{Budget: budget}).normalized()
	t.Cleanup(func() { _ = conn.Abort(); _ = peer.Close() })
	return conn
}

// TestResourcePackFilesShareBudget reserves before writing and returns space only when a file is removed.
func TestResourcePackFilesShareBudget(t *testing.T) {
	budget := NewResourcePackDownloadBudget(100)
	first, second := newPackFileTestConn(t, budget), newPackFileTestConn(t, budget)
	f, err := first.newPackFile(60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.newPackFile(41); err == nil {
		t.Fatal("concurrent downloads exceeded their shared budget")
	}
	if err := first.resizePackFile(f, 101); err == nil {
		t.Fatal("revised size exceeded shared budget")
	}
	if err := first.resizePackFile(f, 100); err != nil {
		t.Fatal(err)
	}
	_ = first.Abort()
	if _, err := os.Stat(f.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("aborted download remains on disk: %v", err)
	}
	if _, err := second.newPackFile(100); err != nil {
		t.Fatalf("aborted connection retained its reservation: %v", err)
	}
}

// TestResourcePackFilesConcurrentBudget ensures simultaneous connections cannot oversubscribe a budget.
func TestResourcePackFilesConcurrentBudget(t *testing.T) {
	budget := NewResourcePackDownloadBudget(1)
	const count = 16
	conns := make([]*Conn, count)
	for i := range conns {
		conns[i] = newPackFileTestConn(t, budget)
	}
	start := make(chan struct{})
	results := make(chan error, count)
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Go(func() {
			<-start
			_, err := conn.newPackFile(1)
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful reservations = %d, want 1", successes)
	}
}

// TestResourcePackSizeLimits applies limits both to initial metadata and to the later chunk metadata.
func TestResourcePackSizeLimits(t *testing.T) {
	conn := newPackFileTestConn(t, NewResourcePackDownloadBudget(1000))
	conn.resourcePackDownload.MaxPackBytes = 100
	id := uuid.New()
	info := &packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: id, Version: "1.0.0", Size: 101}}}
	if err := conn.handleResourcePacksInfo(info); err == nil {
		t.Fatal("oversized advertisement accepted")
	}
	if len(conn.packFiles) != 0 {
		t.Fatal("oversized advertisement created a file")
	}
	info.TexturePacks[0].Size = 100
	if err := conn.handleResourcePacksInfo(info); err != nil {
		t.Fatal(err)
	}
	if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{UUID: id.String(), Size: 101, DataChunkSize: 1}); err == nil {
		t.Fatal("size changed beyond limit after advertisement")
	}
}

// delayedPackFileCache lets a resource finish opening after the owning connection has already closed.
type delayedPackFileCache struct {
	DirResourcePackCache
	entered chan struct{}
	resume  chan struct{}
	loaded  *resource.Pack
}

// TempFile opens a download file after the test allows the pending operation to resume.
func (cache delayedPackFileCache) TempFile() (*os.File, error) {
	close(cache.entered)
	<-cache.resume
	return cache.DirResourcePackCache.TempFile()
}

// Load returns an open archive after the test allows the pending operation to resume.
func (cache delayedPackFileCache) Load(context.Context, ResourcePackCacheKey) (*resource.Pack, error) {
	close(cache.entered)
	<-cache.resume
	return cache.loaded, nil
}

// TestResourcePackOpenAfterAbort checks both late download creation and late cache loads.
func TestResourcePackOpenAfterAbort(t *testing.T) {
	for _, load := range []bool{false, true} {
		name := "download"
		if load {
			name = "cache"
		}
		t.Run(name, func(t *testing.T) {
			budget := NewResourcePackDownloadBudget(4096)
			conn := newPackFileTestConn(t, budget)
			cache := delayedPackFileCache{DirResourcePackCache: DirResourcePackCache{Dir: t.TempDir()}, entered: make(chan struct{}), resume: make(chan struct{})}
			archive := testPackArchive(t, "late")
			f, err := os.CreateTemp(t.TempDir(), "loaded-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if _, err := f.Write(archive); err != nil {
				t.Fatal(err)
			}
			cache.loaded, err = resource.ReadFile(f, int64(len(archive)))
			if err != nil {
				t.Fatal(err)
			}
			conn.resourcePackCache = cache
			result := make(chan error, 1)
			go func() {
				if load {
					result <- conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: cache.loaded.UUID(), Version: cache.loaded.Version(), Size: uint64(len(archive))}}})
				} else {
					_, err := conn.newPackFile(4096)
					result <- err
				}
			}()
			<-cache.entered
			_ = conn.Abort()
			close(cache.resume)
			if err := <-result; err == nil {
				t.Fatal("resource registered after abort")
			}
			if load {
				if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("late cache handle remains open: %v", err)
				}
			} else if entries, err := os.ReadDir(cache.Dir); err != nil || len(entries) != 0 {
				t.Fatalf("late download left files: %v, %v", entries, err)
			}
			if _, err := newPackFileTestConn(t, budget).newPackFile(4096); err != nil {
				t.Fatalf("late open retained its reservation: %v", err)
			}
		})
	}
}

// TestResourcePackHTTPFallbackReleasesFile keeps failed CDN responses from consuming fallback space.
func TestResourcePackHTTPFallbackReleasesFile(t *testing.T) {
	for _, validArchive := range []bool{false, true} {
		name := "invalid_archive"
		if validArchive {
			name = "wrong_identity"
		}
		t.Run(name, func(t *testing.T) {
			data := []byte("invalid archive")
			if validArchive {
				data = testPackArchive(t, "wrong")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
			defer server.Close()
			conn := newPackFileTestConn(t, NewResourcePackDownloadBudget(uint64(len(data))))
			info := &packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: uuid.New(), Version: "1.0.0", Size: uint64(len(data)), DownloadURL: server.URL}}}
			if err := conn.handleResourcePacksInfo(info); err != nil {
				t.Fatalf("fallback could not reserve the failed HTTP download's space: %v", err)
			}
			if len(conn.packFiles) != 1 || len(conn.packQueue.downloadingPacks) != 1 {
				t.Fatalf("fallback retained failed download: files=%d, pending=%d", len(conn.packFiles), len(conn.packQueue.downloadingPacks))
			}
		})
	}
}

// TestResourcePackNestedFile streams one nested archive to disk and applies limits before extracting it.
func TestResourcePackNestedFile(t *testing.T) {
	inner := testPackArchive(t, "nested")
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	entry, err := zw.Create("pack.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		name := "budget_rejected"
		limit := uint64(outer.Len())
		if allow {
			name = "extracted"
			limit += uint64(len(inner))
		}
		t.Run(name, func(t *testing.T) {
			conn := newPackFileTestConn(t, NewResourcePackDownloadBudget(limit))
			f, err := conn.newPackFile(uint64(outer.Len()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(outer.Bytes()); err != nil {
				t.Fatal(err)
			}
			pack, err := conn.readDownloadedPack(f, uint64(outer.Len()))
			if !allow {
				if err == nil {
					t.Fatal("nested archive exceeded shared budget")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, pack.Size())
			if _, err := pack.ReadAt(got, 0); err != nil || !bytes.Equal(got, inner) {
				t.Fatalf("extracted archive differs: %v", err)
			}
			if _, err := os.Stat(f.Name()); !errors.Is(err, os.ErrNotExist) || len(conn.packFiles) != 1 {
				t.Fatalf("outer archive not released: %v, files=%d", err, len(conn.packFiles))
			}
		})
	}
}

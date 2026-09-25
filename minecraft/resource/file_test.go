package resource

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestReadFile_MatchesReadBytes keeps a file-backed pack identical to its in-memory reading.
func TestReadFile_MatchesReadBytes(t *testing.T) {
	data := packArchive(t, map[string]string{"pack/manifest.json": testManifest, "pack/entity/a.json": "{}"})
	path := filepath.Join(t.TempDir(), "a.mcpack")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	mem, err := ReadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := ReadPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if disk.Checksum() != mem.Checksum() || disk.Size() != mem.Size() || disk.UUID() != mem.UUID() {
		t.Fatal("file-backed pack differs from the in-memory pack")
	}
	files, err := disk.ResourceFiles("entity")
	if err != nil || !slices.Equal(files, []string{"entity/a.json"}) {
		t.Fatalf("ResourceFiles = %v, %v", files, err)
	}
	chunk := make([]byte, 16)
	if n, err := disk.ReadAt(chunk, 4); err != nil || n != 16 || !slices.Equal(chunk, data[4:20]) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}

// TestReadURLToFile_StreamsIntoFile downloads without holding the archive in memory.
func TestReadURLToFile_StreamsIntoFile(t *testing.T) {
	data := packArchive(t, map[string]string{"manifest.json": testManifest})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	f, err := os.CreateTemp(t.TempDir(), "dl-*")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := ReadURLToFile(t.Context(), server.Client(), server.URL+"/p.mcpack", uint64(len(data)), f)
	if err != nil {
		t.Fatal(err)
	}
	defer pack.Close()
	if pack.Size() != len(data) || pack.DownloadURL() != server.URL+"/p.mcpack" {
		t.Fatalf("size=%d url=%q", pack.Size(), pack.DownloadURL())
	}
	if _, err := ReadURLToFile(t.Context(), server.Client(), server.URL, uint64(len(data))-1, f); err == nil {
		t.Fatal("oversized download accepted")
	}
}

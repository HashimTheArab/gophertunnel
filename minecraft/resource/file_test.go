package resource

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	disk, err := OpenPath(path)
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
		t.Fatal("nonempty destination accepted")
	}
}

// TestReadPath_Snapshot remains readable after the source file changes or Close is called.
func TestReadPath_Snapshot(t *testing.T) {
	data := packArchive(t, map[string]string{"manifest.json": testManifest})
	path := filepath.Join(t.TempDir(), "pack.mcpack")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := ReadPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := pack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := pack.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("ReadPath snapshot changed: err=%v", err)
	}
}

// TestOpenPath_SharedArchiveOwnership closes the file once for all pack metadata copies.
func TestOpenPath_SharedArchiveOwnership(t *testing.T) {
	data := packArchive(t, map[string]string{"manifest.json": testManifest})
	path := filepath.Join(t.TempDir(), "pack.mcpack")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := OpenPath(path)
	if err != nil {
		t.Fatal(err)
	}
	alias := pack.WithContentKey("key").WithDownloadURL("https://example.invalid/pack")
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadAt after alias Close = %v, want closed file", err)
	}
}

// TestReadFile_ErrorKeepsOwnership leaves the caller responsible for an invalid archive.
func TestReadFile_ErrorKeepsOwnership(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "invalid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ReadFile(f, 0); err == nil {
		t.Fatal("empty archive accepted")
	}
	if _, err := f.Stat(); err != nil {
		t.Fatalf("ReadFile closed caller's file on error: %v", err)
	}
	if _, err := ReadFile(nil, 0); err == nil {
		t.Fatal("nil archive accepted")
	}
}

// TestReadURLToFile_ValidatesDestination fails before sending a request for an unusable file.
func TestReadURLToFile_ValidatesDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("requested pack with an invalid destination")
	}))
	defer server.Close()
	if _, err := ReadURLToFile(t.Context(), server.Client(), server.URL, 1024, nil); err == nil {
		t.Fatal("nil destination accepted")
	}
	f, err := os.CreateTemp(t.TempDir(), "nonempty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("existing")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadURLToFile(t.Context(), server.Client(), server.URL, 1024, f); err == nil {
		t.Fatal("nonempty destination accepted")
	}
}

// TestReadURLToFile_BoundsUnknownLength keeps streamed responses within the disk allowance.
func TestReadURLToFile_BoundsUnknownLength(t *testing.T) {
	data := packArchive(t, map[string]string{"manifest.json": testManifest})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write(data)
	}))
	defer server.Close()
	for _, test := range []struct {
		name  string
		limit uint64
		valid bool
	}{
		{name: "exact", limit: uint64(len(data)), valid: true},
		{name: "oversized", limit: uint64(len(data) - 1)},
		{name: "maximum int64", limit: math.MaxInt64, valid: true},
		{name: "unsupported size", limit: math.MaxInt64 + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "bounded-*")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Seek(10, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			pack, err := ReadURLToFile(t.Context(), server.Client(), server.URL, test.limit, f)
			if (err == nil) != test.valid {
				t.Fatalf("ReadURLToFile error = %v, want valid=%v", err, test.valid)
			}
			if pack != nil {
				defer pack.Close()
				if pack.Size() != len(data) {
					t.Fatalf("download size = %d, want %d", pack.Size(), len(data))
				}
			}
			info, statErr := f.Stat()
			if statErr != nil {
				t.Fatal(statErr)
			}
			if uint64(info.Size()) > test.limit {
				t.Fatalf("download wrote %d bytes with limit %d", info.Size(), test.limit)
			}
		})
	}
}

// TestReadURLToFile_RejectsNestedArchive preserves the HTTP archive format restriction.
func TestReadURLToFile_RejectsNestedArchive(t *testing.T) {
	data := packArchive(t, map[string]string{"pack.zip": string(testPackArchive(t))})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()
	f, err := os.CreateTemp(t.TempDir(), "nested-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ReadURLToFile(t.Context(), server.Client(), server.URL, uint64(len(data)), f); err == nil {
		t.Fatal("nested HTTP archive accepted")
	}
}

// TestReadFile_RejectsOversizedManifest bounds decompressed metadata for memory and file archives.
func TestReadFile_RejectsOversizedManifest(t *testing.T) {
	data := packArchive(t, map[string]string{"manifest.json": testManifest + strings.Repeat(" ", maxManifestSize)})
	if len(data) >= maxManifestSize {
		t.Fatal("fixture is not a small compressed archive")
	}
	if _, err := ReadBytes(data); err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
		t.Fatalf("ReadBytes oversized manifest error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "oversized.mcpack")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPath(path); err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
		t.Fatalf("OpenPath oversized manifest error = %v", err)
	}
}

// TestNestedArchive_MatchesReadBytes exposes precisely the one level that memory readers unwrap.
func TestNestedArchive_MatchesReadBytes(t *testing.T) {
	inner := testPackArchive(t)
	outer := packArchive(t, map[string]string{"pack.ZIP": string(inner)})
	nested, err := NestedArchive(bytes.NewReader(outer), int64(len(outer)))
	if err != nil || nested == nil {
		t.Fatalf("NestedArchive = %v, %v", nested, err)
	}
	r, err := nested.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, inner) {
		t.Fatalf("nested content differs: %v", err)
	}
	pack, err := ReadBytes(outer)
	if err != nil || pack.Size() != len(inner) {
		t.Fatalf("ReadBytes did not unwrap one level: pack=%v, err=%v", pack, err)
	}
	if nested, err := NestedArchive(bytes.NewReader(inner), int64(len(inner))); err != nil || nested != nil {
		t.Fatalf("direct NestedArchive = %v, %v", nested, err)
	}
	double := packArchive(t, map[string]string{"outer.zip": string(outer)})
	if _, err := ReadBytes(double); err == nil {
		t.Fatal("ReadBytes unwrapped more than one level")
	}
}

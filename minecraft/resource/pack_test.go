package resource

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadURLContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadURLContext(ctx, "http://127.0.0.1/resource.mcpack"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadURLContext error = %v, want context canceled", err)
	}
}

func TestReadURLContextLimitRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	defer server.Close()

	if _, err := ReadURLContextLimit(context.Background(), server.URL, 4); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("ReadURLContextLimit error = %v, want exceeds limit", err)
	}
}

func TestReadURLContextLimitDoesNotUnwrapNestedURLArchive(t *testing.T) {
	t.Parallel()

	inner := testPackArchive(t)
	outer := new(bytes.Buffer)
	zw := zip.NewWriter(outer)
	w, err := zw.Create("pack.zip")
	if err != nil {
		t.Fatalf("create nested zip entry: %v", err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatalf("write nested zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close outer zip: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(outer.Bytes())
	}))
	defer server.Close()

	if _, err := ReadURLContextLimit(context.Background(), server.URL, uint64(outer.Len())); err == nil {
		t.Fatal("ReadURLContextLimit succeeded for nested URL archive, want error")
	}
}

func testPackArchive(t *testing.T) []byte {
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
			"uuid": "550e8400-e29b-41d4-a716-446655440000",
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

func TestPack_HasResourceFileBelowManifestRoot(t *testing.T) {
	archive := testPackArchive(t)
	root, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := root.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := io.ReadAll(manifest)
	_ = manifest.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"", "MyPack/"} {
		t.Run(prefix, func(t *testing.T) {
			buf := new(bytes.Buffer)
			zw := zip.NewWriter(buf)
			for name, data := range map[string][]byte{
				prefix + "manifest.json":             manifestData,
				prefix + "entity/player.entity.json": []byte(`{}`),
			} {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			pack, err := ReadBytes(buf.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if !pack.HasResourceFile("entity/player.entity.json") || pack.HasResourceFile("entity/missing.json") {
				t.Fatal("resource files were not resolved relative to the manifest")
			}
			data, err := pack.ReadFile("entity/player.entity.json")
			if err != nil || string(data) != "{}" {
				t.Fatalf("ReadFile from manifest root = %q, %v", data, err)
			}
			zipPath := filepath.Join(t.TempDir(), "pack.mcpack")
			if err := os.WriteFile(zipPath, buf.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			fromPath, err := ReadPath(zipPath)
			if err != nil {
				t.Fatal(err)
			}
			if !fromPath.HasResourceFile("entity/player.entity.json") {
				t.Fatal("ReadPath lost the manifest directory")
			}
			if prefix == "" {
				directory := t.TempDir()
				if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifestData, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(directory, "entity"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "entity", "player.entity.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
				fromDir, err := ReadPath(directory)
				if err != nil || !fromDir.HasResourceFile("entity/player.entity.json") {
					t.Fatalf("directory pack lookup = %v, %v", fromDir, err)
				}
			}
		})
	}
}

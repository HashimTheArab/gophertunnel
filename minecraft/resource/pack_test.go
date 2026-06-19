package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPathFindsManifestInNestedDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	nested := filepath.Join(dir, "wrapped")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "manifest.json"), []byte(`{
		"format_version": 2,
		"header": {
			"name": "nested",
			"description": "nested",
			"uuid": "550e8400-e29b-41d4-a716-446655440000",
			"version": [1, 0, 0],
			"min_engine_version": [1, 20, 0]
		},
		"modules": [{
			"description": "nested",
			"type": "resources",
			"uuid": "550e8400-e29b-41d4-a716-446655440001",
			"version": [1, 0, 0]
		}]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	pack, err := ReadPath(dir)
	if err != nil {
		t.Fatalf("ReadPath: %v", err)
	}
	if pack.Name() != "nested" {
		t.Fatalf("pack name = %q, want nested", pack.Name())
	}
}

func TestReadURLContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadURLContext(ctx, "http://127.0.0.1/resource.mcpack"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadURLContext error = %v, want context canceled", err)
	}
}

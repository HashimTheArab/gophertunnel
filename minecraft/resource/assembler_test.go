package resource

import (
	"archive/zip"
	"bytes"
	"slices"
	"testing"
)

func TestChunkCount(t *testing.T) {
	for _, test := range []struct {
		name      string
		size      uint64
		chunkSize uint32
		want      uint32
		wantOK    bool
	}{
		{name: "empty", chunkSize: 16, wantOK: true},
		{name: "exact", size: 32, chunkSize: 16, want: 2, wantOK: true},
		{name: "partial", size: 33, chunkSize: 16, want: 3, wantOK: true},
		{name: "zero chunk size", size: 32},
		{name: "max index", size: 1 << 31, chunkSize: 1, want: 1 << 31, wantOK: true},
		{name: "index overflows int32", size: 1<<31 + 1, chunkSize: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ChunkCount(test.size, test.chunkSize)
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}
			if got != test.want {
				t.Fatalf("count = %d, want %d", got, test.want)
			}
		})
	}
}

// packArchive builds a pack whose manifest sits in a subdirectory, as servers ship them.
func packArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const testManifest = `{"format_version": 2, "header": {"name": "t", "uuid": "0b5b8f8e-5c5e-4c43-8f3e-0d2f6f5a1b01", "version": [1, 0, 0]},
"modules": [{"type": "resources", "uuid": "0b5b8f8e-5c5e-4c43-8f3e-0d2f6f5a1b02", "version": [1, 0, 0]}]}`

// TestAssembler_OutOfOrderChunks rebuilds a pack from chunks seen in any order, ignoring repeats.
func TestAssembler_OutOfOrderChunks(t *testing.T) {
	data := packArchive(t, map[string]string{"pack/manifest.json": testManifest, "pack/entity/a.json": "{}"})
	const chunkSize = 64
	a, err := NewAssembler(uint64(len(data)), chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	count, _ := ChunkCount(uint64(len(data)), chunkSize)
	for i := int(count) - 1; i >= 0; i-- {
		chunk := data[i*chunkSize : min((i+1)*chunkSize, len(data))]
		if _, err := a.Pack(); err == nil {
			t.Fatal("pack parsed before every chunk arrived")
		}
		done, err := a.Add(uint32(i), chunk)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := a.Add(uint32(i), chunk); err != nil || again != done {
			t.Fatalf("repeated chunk changed state: done=%v again=%v err=%v", done, again, err)
		}
		if done != (i == 0) {
			t.Fatalf("chunk %d: done = %v", i, done)
		}
	}
	pack, err := a.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if files, err := pack.ResourceFiles("entity"); err != nil || !slices.Equal(files, []string{"entity/a.json"}) {
		t.Fatalf("ResourceFiles = %v, %v", files, err)
	}
}

// TestAssembler_RejectsMalformedChunks keeps a hostile stream from writing outside the pack.
func TestAssembler_RejectsMalformedChunks(t *testing.T) {
	a, err := NewAssembler(10, 4)
	if err != nil {
		t.Fatal(err)
	}
	for name, add := range map[string]func() (bool, error){
		"index past end": func() (bool, error) { return a.Add(3, []byte{1, 2}) },
		"short chunk":    func() (bool, error) { return a.Add(0, []byte{1}) },
		"long tail":      func() (bool, error) { return a.Add(2, []byte{1, 2, 3}) },
	} {
		if _, err := add(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewAssembler(8, 0); err == nil {
		t.Error("zero chunk size accepted")
	}
}

// TestResourceFiles_RootAndCaseFolding lists from the manifest root and folds directory case by segment.
func TestResourceFiles_RootAndCaseFolding(t *testing.T) {
	root, err := ReadBytes(packArchive(t, map[string]string{"manifest.json": testManifest, "Entity/a.json": "{}"}))
	if err != nil {
		t.Fatal(err)
	}
	if files, err := root.ResourceFiles("."); err != nil || !slices.Contains(files, "Entity/a.json") || !slices.Contains(files, "manifest.json") {
		t.Fatalf("root ResourceFiles = %v, %v", files, err)
	}
	// U+212A KELVIN SIGN folds to 'k' but is three bytes long.
	nested, err := ReadBytes(packArchive(t, map[string]string{"\u212apack/manifest.json": testManifest, "kpack/entity/b.json": "{}"}))
	if err != nil {
		t.Fatal(err)
	}
	if files, err := nested.ResourceFiles("entity"); err != nil || !slices.Equal(files, []string{"entity/b.json"}) {
		t.Fatalf("nested ResourceFiles = %v, %v", files, err)
	}
}

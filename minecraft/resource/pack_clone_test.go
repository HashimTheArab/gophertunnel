package resource

import (
	"bytes"
	"reflect"
	"testing"
)

// Every mutable manifest field needs both an isolation test and explicit copying in Pack.Clone.
func TestPackCloneManifestIsolation(t *testing.T) {
	mutations := map[string]func(*Manifest){
		"Manifest.Modules":          func(m *Manifest) { m.Modules[0].Type = "changed" },
		"Manifest.Dependencies":     func(m *Manifest) { m.Dependencies[0].UUID = "changed" },
		"Manifest.Capabilities":     func(m *Manifest) { m.Capabilities[0] = "changed" },
		"Manifest.Metadata":         func(m *Manifest) { m.Metadata.License = "changed" },
		"Manifest.Metadata.Authors": func(m *Manifest) { m.Metadata.Authors[0] = "changed" },
	}
	checkManifestCloneCoverage(t, reflect.TypeFor[Manifest](), "Manifest", mutations)
	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			original := Pack{manifest: testCloneManifest(), content: bytes.NewReader([]byte("archive"))}
			want := testCloneManifest()
			clone := original.Clone()
			if !reflect.DeepEqual(clone.manifest, want) {
				t.Fatal("clone changed manifest values")
			}
			if clone.content != original.content {
				t.Fatal("clone copied the read-only archive")
			}
			mutate(clone.manifest)
			if reflect.DeepEqual(clone.manifest, want) {
				t.Fatal("test did not change the cloned manifest")
			}
			if !reflect.DeepEqual(original.manifest, want) {
				t.Fatal("changing the clone changed the original manifest")
			}
		})
	}
}

// Nil optional manifest fields remain valid when a pack is cloned.
func TestPackCloneEmptyManifest(t *testing.T) {
	for _, manifest := range []*Manifest{{}, {Metadata: &Metadata{}}} {
		clone := (Pack{manifest: manifest}).Clone()
		if !reflect.DeepEqual(clone.manifest, manifest) {
			t.Fatal("clone changed empty manifest values")
		}
		clone.manifest.Header.Name = "changed"
		if manifest.Header.Name != "" {
			t.Fatal("clone shares the original manifest")
		}
	}
}

// checkManifestCloneCoverage finds references even inside value structs, arrays, and slice elements.
// New reference fields fail until their ownership is covered by a mutation test.
func checkManifestCloneCoverage(t *testing.T, typ reflect.Type, path string, mutations map[string]func(*Manifest)) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			checkManifestCloneCoverage(t, field.Type, path+"."+field.Name, mutations)
		}
	case reflect.Array:
		checkManifestCloneCoverage(t, typ.Elem(), path+"[]", mutations)
	case reflect.Slice, reflect.Pointer:
		if mutations[path] == nil {
			t.Errorf("%s (%s) needs a Pack.Clone isolation test", path, typ)
			return
		}
		if typ.Kind() == reflect.Slice {
			path += "[]"
		}
		checkManifestCloneCoverage(t, typ.Elem(), path, mutations)
	case reflect.Map, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		t.Errorf("%s (%s) needs explicit Pack.Clone ownership coverage", path, typ)
	}
}

// testCloneManifest creates independent, populated metadata for comparing clones after mutation.
func testCloneManifest() *Manifest {
	return &Manifest{
		FormatVersion: 2,
		Header: Header{
			Name: "test pack", Description: "description", UUID: [16]byte{1},
			Version: Version{1, 2, 3}, MinimumGameVersion: Version{1, 21, 0},
		},
		Modules: []Module{{
			UUID: "module", Description: "module description", Type: "resources", Version: Version{1, 0, 0},
		}},
		Dependencies:  []Dependency{{UUID: "dependency", Version: Version{2, 0, 0}}},
		Capabilities:  []Capability{"chemistry"},
		Metadata:      &Metadata{Authors: []string{"author"}, License: "MIT", URL: "https://example.test"},
		worldTemplate: true,
	}
}

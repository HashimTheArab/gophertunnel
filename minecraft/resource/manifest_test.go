package resource

import (
	"encoding/json"
	"testing"
)

// Format versions written as strings or arrays must not fail the whole manifest.
func TestManifestFormatVersionRepresentations(t *testing.T) {
	for text, want := range map[string]FormatVersion{
		`2`: 2, `2.0`: 2, `1.5`: 1.5, `"2"`: 2, `"2.0"`: 2, `"2.0.0"`: 2, `[2, 0, 0]`: 2, `"3.1.0"`: 3.1,
		`"x"`: 0, `{}`: 0, `null`: 0,
	} {
		var m Manifest
		if err := json.Unmarshal([]byte(`{"format_version": `+text+`, "header": {"version": [1, 0, 0]}}`), &m); err != nil {
			t.Fatalf("format_version %s: %v", text, err)
		}
		if m.FormatVersion != want {
			t.Fatalf("format_version %s = %v, want %v", text, m.FormatVersion, want)
		}
	}
}

// Version strings follow vanilla's grammar, so partial versions name the same version as their full form.
func TestManifestVersionStrings(t *testing.T) {
	for text, want := range map[string]Version{
		"1": {1, 0, 0}, "1.2": {1, 2, 0}, "1.2.3": {1, 2, 3}, " 1.2.3 ": {1, 2, 3},
		"1.2.3-beta.1": {1, 2, 3}, "1.2.3+build": {1, 2, 3}, "01.0.11": {1, 0, 11},
	} {
		if got, ok := parseVersion(text); !ok || got != want {
			t.Fatalf("parseVersion(%q) = %v, %t, want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "x", "1.x", "1.2-beta", "1.2.3.4", "-1.0.0"} {
		if _, ok := parseVersion(text); ok {
			t.Fatalf("parseVersion(%q) accepted", text)
		}
	}
	var m Manifest
	if err := json.Unmarshal([]byte(`{"header": {"version": "1.0"}, "modules": [{"version": "2"}]}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Header.Version != (Version{1, 0, 0}) || m.Modules[0].Version != (Version{2, 0, 0}) {
		t.Fatalf("partial versions = %v, %v", m.Header.Version, m.Modules[0].Version)
	}
}

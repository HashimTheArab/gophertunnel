package resource

import "testing"

// Pack versions compare as numbers: short forms name the same version, and different numbers never match.
func TestSameVersionComparesNumbers(t *testing.T) {
	for _, pair := range [][2]string{{"1", "1.0.0"}, {"1.0", "1.0.0"}, {"1.2.3", "1.2.3"}, {"01.0.0", "1.0.0"}} {
		if !SameVersion(pair[0], pair[1]) {
			t.Fatalf("SameVersion(%q, %q) = false", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"1.0.0", "1.0.1"}, {"2.0.0", "1.0.0"}, {"x", "1.0.0"}, {"x", "y"}} {
		if SameVersion(pair[0], pair[1]) {
			t.Fatalf("SameVersion(%q, %q) = true", pair[0], pair[1])
		}
	}
	if !SameVersion("x", "x") {
		t.Fatal("an unparsed version does not match itself")
	}
	if got := CanonicalUUID("6F733B6B-33F7-46A1-A246-588F130F51C2"); got != "6f733b6b-33f7-46a1-a246-588f130f51c2" {
		t.Fatalf("CanonicalUUID = %q", got)
	}
}

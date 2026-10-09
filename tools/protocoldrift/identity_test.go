package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInspectSourceUsesInspectedTarget prevents host constants from labelling another checkout.
func TestInspectSourceUsesInspectedTarget(t *testing.T) {
	root := t.TempDir()
	writeIdentityFixture(t, root, `package protocol
const CurrentVersion = "9.8.7"
const CurrentProtocol = 12345
`)
	identity, err := inspectSource(root)
	if err != nil {
		t.Fatal(err)
	}
	if identity.MinecraftVersion != "9.8.7" || identity.ProtocolVersion != 12345 || identity.Source != "gophertunnel@unversioned" {
		t.Fatalf("unexpected inspected identity: %+v", identity)
	}
}

// TestInspectSourceRejectsUnknownTarget keeps incomplete metadata from passing as a default.
func TestInspectSourceRejectsUnknownTarget(t *testing.T) {
	for name, declaration := range map[string]string{
		"missing":     `const CurrentVersion = "9.8.7"`,
		"empty":       `const CurrentVersion = ""; const CurrentProtocol = 1`,
		"wrong type":  `const CurrentVersion = "9.8.7"; const CurrentProtocol = "1"`,
		"zero":        `const CurrentVersion = "9.8.7"; const CurrentProtocol = 0`,
		"expression":  `const CurrentVersion = "9.8.7"; const CurrentProtocol = 1 + 2`,
		"duplicate":   `const CurrentVersion = "9.8.7"; const CurrentProtocol = 1; const CurrentProtocol = 2`,
		"not a const": `const CurrentVersion = "9.8.7"; var CurrentProtocol = 1`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeIdentityFixture(t, root, "package protocol\n"+declaration)
			if _, err := inspectSource(root); err == nil {
				t.Fatal("accepted invalid source identity")
			}
		})
	}
	if _, err := inspectSource(t.TempDir()); err == nil {
		t.Fatal("accepted missing info.go")
	}
}

// TestSourceRevision follows the inspected Git root and distinguishes local changes and archives.
func TestSourceRevision(t *testing.T) {
	root := t.TempDir()
	writeIdentityFixture(t, root, `package protocol; const CurrentVersion = "9.8.7"; const CurrentProtocol = 12345`)
	runIdentityGit(t, root, "init", "--quiet")
	runIdentityGit(t, root, "add", ".")
	runIdentityGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
	want := "gophertunnel@" + runIdentityGit(t, root, "rev-parse", "HEAD")
	got, err := sourceRevision(root)
	if err != nil || got != want {
		t.Fatalf("clean source = %q, %v; want %q", got, err, want)
	}
	writeIdentityFixture(t, root, `package protocol; const CurrentVersion = "9.8.6"; const CurrentProtocol = 12344`)
	got, err = sourceRevision(root)
	if err != nil || got != want+"-dirty" {
		t.Fatalf("modified source = %q, %v", got, err)
	}
	runIdentityGit(t, root, "checkout", "--", "minecraft/protocol/info.go")
	if err := os.WriteFile(filepath.Join(root, "minecraft/protocol/extra.go"), []byte("package protocol"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err = sourceRevision(root)
	if err != nil || got != want+"-dirty" {
		t.Fatalf("untracked source = %q, %v", got, err)
	}
	archive := filepath.Join(root, "archive")
	writeIdentityFixture(t, archive, `package protocol; const CurrentVersion = "9.8.7"; const CurrentProtocol = 12345`)
	got, err = sourceRevision(archive)
	if err != nil || got != "gophertunnel@unversioned" {
		t.Fatalf("nested archive = %q, %v", got, err)
	}
}

// writeIdentityFixture creates only the inspected version file for each test.
func writeIdentityFixture(t *testing.T, root, source string) {
	t.Helper()
	dir := filepath.Join(root, "minecraft", "protocol")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "info.go"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
}

// runIdentityGit runs an isolated fixture repository command and reports failures.
func runIdentityGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

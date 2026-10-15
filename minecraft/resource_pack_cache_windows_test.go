//go:build windows

package minecraft

import (
	"os"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// TestDirResourcePackCacheSkipsOpenEntries keeps an active Windows file from blocking cache eviction.
func TestDirResourcePackCacheSkipsOpenEntries(t *testing.T) {
	cache := DirResourcePackCache{Dir: t.TempDir()}
	pack, err := resource.ReadBytes(testPackArchive(t, "pinned"))
	if err != nil {
		t.Fatal(err)
	}
	key := ResourcePackCacheKey{UUID: pack.UUID(), Version: pack.Version(), Size: uint64(pack.Size())}
	if err := cache.Store(t.Context(), key, pack); err != nil {
		t.Fatal(err)
	}
	active, err := cache.Load(t.Context(), key)
	if err != nil || active == nil {
		t.Fatalf("Load = %v, %v", active, err)
	}
	defer active.Close()
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(cache.path(key), old, old); err != nil {
		t.Fatal(err)
	}
	cache.MaxBytes = int64(pack.Size())
	second, err := resource.ReadBytes(testPackArchive(t, "newer"))
	if err != nil {
		t.Fatal(err)
	}
	secondKey := ResourcePackCacheKey{UUID: second.UUID(), Version: second.Version(), Size: uint64(second.Size())}
	if err := cache.Store(t.Context(), secondKey, second); err != nil {
		t.Fatalf("a busy oldest entry blocked eviction: %v", err)
	}
	if entries, err := os.ReadDir(cache.Dir); err != nil || len(entries) != 1 || entries[0].Name() != key.UUID.String()+"_"+key.Version+".mcpack" {
		t.Fatalf("cache kept entries beyond its budget: %v, %v", entries, err)
	}
}

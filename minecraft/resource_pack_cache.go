package minecraft

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackCacheKey identifies a resource pack advertised in the ResourcePacksInfo packet. Like the
// vanilla client's own pack cache, pack content is assumed not to change without a version bump; the
// advertised size is included as an extra guard.
type ResourcePackCacheKey struct {
	UUID    uuid.UUID
	Version string
	Size    uint64
}

// Matches reports whether pack has the UUID, version and size the key holds.
func (key ResourcePackCacheKey) Matches(pack *resource.Pack) bool {
	return pack.UUID() == key.UUID && pack.Version() == key.Version && uint64(pack.Size()) == key.Size
}

// ResourcePackCache allows a Dialer to reuse resource packs downloaded earlier. Cache failures are
// non-fatal: a nil pack or an error from Load falls back to a normal download, and errors from Store are
// only logged.
type ResourcePackCache interface {
	// Load returns the pack stored under key, or nil if it is not cached. The caller owns the returned
	// pack and closes it, so a file-backed cache opens a fresh handle per call rather than sharing one.
	Load(ctx context.Context, key ResourcePackCacheKey) (*resource.Pack, error)
	// Store stores a pack under key for a later Load. The pack is only valid during the call: its
	// archive belongs to the connection and is removed with it, so an implementation copies the content.
	Store(ctx context.Context, key ResourcePackCacheKey, pack *resource.Pack) error
}

// DirResourcePackCache is a ResourcePackCache that stores resource packs as files in a directory.
type DirResourcePackCache struct {
	// Dir is the directory packs are stored in. It is created when the first pack is stored.
	Dir string
	// MaxBytes, when positive, bounds the directory: after a store, the least recently used entries are
	// removed until the total fits. Zero keeps every entry; the caller then owns the directory's lifecycle.
	MaxBytes int64
}

// Load returns the pack stored under key, or nil if no file exists for it.
func (cache DirResourcePackCache) Load(_ context.Context, key ResourcePackCacheKey) (*resource.Pack, error) {
	path := cache.path(key)
	pack, err := resource.ReadPath(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err == nil {
		// Mark the entry recently used for eviction; mtime is portable where atime is not.
		now := time.Now()
		_ = os.Chtimes(path, now, now)
	}
	return pack, err
}

// Store writes the pack to a file under key, replacing any previous entry.
func (cache DirResourcePackCache) Store(_ context.Context, key ResourcePackCacheKey, pack *resource.Pack) error {
	if err := os.MkdirAll(cache.Dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(cache.Dir, "pack-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := io.Copy(temp, io.NewSectionReader(pack, 0, int64(pack.Size()))); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp.Name(), cache.path(key)); err != nil {
		return err
	}
	return cache.evict()
}

// evict removes the least recently used entries until the directory fits MaxBytes. A Load touches its
// entry, so recently served packs survive.
func (cache DirResourcePackCache) evict() error {
	if cache.MaxBytes <= 0 {
		return nil
	}
	entries, err := os.ReadDir(cache.Dir)
	if err != nil {
		return err
	}
	type packFile struct {
		name  string
		size  int64
		atime time.Time
	}
	var files []packFile
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".mcpack") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, packFile{name: entry.Name(), size: info.Size(), atime: info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].atime.Before(files[j].atime) })
	for _, file := range files {
		if total <= cache.MaxBytes {
			break
		}
		if err := os.Remove(filepath.Join(cache.Dir, file.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		total -= file.size
	}
	return nil
}

// TempFile creates a download file beside the cache entries, so Store stays on one filesystem.
func (cache DirResourcePackCache) TempFile() (*os.File, error) {
	if err := os.MkdirAll(cache.Dir, 0o755); err != nil {
		return nil, err
	}
	return os.CreateTemp(cache.Dir, "download-*.tmp")
}

// path returns the file a pack with key is stored at. The version is escaped as it comes from the server.
func (cache DirResourcePackCache) path(key ResourcePackCacheKey) string {
	return filepath.Join(cache.Dir, key.UUID.String()+"_"+url.PathEscape(key.Version)+".mcpack")
}
